import dpkt
import csv
import struct
from dataclasses import dataclass
from typing import Dict, Tuple, Optional
import logging
from pathlib import Path
import zipfile
import zstandard as zstd
import io
import os

@dataclass
class MDPMessage:
    template_id: int
    fields: Dict

class MDPParser:
    def __init__(self, debug: bool = False, logging_enabled: bool = True):
        """
        Initialize parser with configurable logging.
        
        Args:
            debug: Enable debug level logging
            logging_enabled: Master switch to enable/disable all logging
        """
        self.setup_logging(debug, logging_enabled)
        self.initialize_template_sizes()

    def setup_logging(self, debug: bool, logging_enabled: bool) -> None:
        """Configure logging with master enable/disable switch."""
            
        level = logging.DEBUG if debug else logging.INFO
        logging.basicConfig(
            level=level,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        # if logging_enabled:
        if not logging_enabled:
            logging.getLogger().setLevel(logging.CRITICAL + 1)
        self.logger = logging.getLogger(__name__)

    def initialize_template_sizes(self):
        """Initialize known template message sizes and structures."""
        self.templates = {
            47: {
                'header_format': '!QBh',  # TransactTime (uint64), MatchEventIndicator (uint8), NoMDEntries (int16)
                'header_fields': [
                    'transact_time',
                    'match_event_indicator',
                    'no_md_entries',
                ],
                'group_format': '!QQqiiBc',  # Corrected format
                'group_fields': [
                    'order_id',
                    'md_order_priority',
                    'md_entry_px',
                    'md_display_qty',
                    'security_id',
                    'md_update_action',
                    'md_entry_type'
                ]
            }
        }

        # Field mappings based on CME documentation
        self.md_update_action_map = {
            0: 'New',
            1: 'Change',
            2: 'Delete'
        }
        
        self.md_entry_type_map = {
            ord('0'): 'Bid',
            ord('1'): 'Offer'
        }

        self.match_event_indicator_map = {
            0x01: 'LastTrade',
            0x02: 'LastVolume',
            0x04: 'LastQuote',
            0x08: 'LastStats',
            0x10: 'LastImplied',
            0x20: 'Recovery',
            0x40: 'Reserved',
            0x80: 'EndOfEvent'
        }

    def validate_message_length(self, data: bytes, offset: int, template_id: int) -> bool:
        """Validate if enough bytes remain for the template."""
        if template_id not in self.templates:
            # self.logger.warning(f"Unknown template ID: {template_id}")
            return False
            
        expected_length = self.templates[template_id]['size']
        remaining_bytes = len(data) - offset
        
        if remaining_bytes < expected_length:
            self.logger.debug(f"Insufficient bytes for template {template_id}: needed {expected_length}, got {remaining_bytes}")
            return False
        return True

    def parse_mdp_header(self, data: bytes, offset: int) -> Tuple[Optional[int], int]:
        """Parse MDP message header."""
        try:
            header_format = '>HH'  # template_id, block_length
            header_size = struct.calcsize(header_format)
            
            if len(data) - offset < header_size:
                return None, offset
                
            template_id, block_length = struct.unpack_from(header_format, data, offset)
            return template_id, offset + header_size
            
        except struct.error as e:
            self.logger.error(f"Failed to parse MDP header: {e}")
            return None, offset
        
    # def process_security_definition(self, message):
    #     """Process security definition message and update security map."""
    #     if message and 'fields' in message:
    #         security_id = message['fields']['security_id']
    #         symbol = message['fields'].get('symbol', '').strip(b'\x00').decode('utf-8')
    #         self.security_map[security_id] = symbol
    def parse_mdp_message(self, data: bytes, offset: int) -> Tuple[Optional[Dict], int]:
        """Parse a single MDP message with repeating groups."""
        template_id, new_offset = self.parse_mdp_header(data, offset)
        if template_id is None:
            return None, len(data)

        try:
            template = self.templates.get(template_id)
            if not template:
                return None, new_offset

            # Parse header fields
            header_size = struct.calcsize(template['header_format'])
            if len(data) - new_offset < header_size:
                return None, len(data)

            header_values = struct.unpack_from(template['header_format'], data, new_offset)
            self.logger.debug(f"Header values: {header_values}")
            
            message = {
                'template_id': template_id,
                'fields': dict(zip(template['header_fields'], header_values))
            }

            # Process header fields
            message['fields']['transact_time'] = int(message['fields']['transact_time'])
            
            mei = message['fields']['match_event_indicator']
            mei_flags = []
            for bitmask, flag_name in self.match_event_indicator_map.items():
                if mei & bitmask:
                    mei_flags.append(flag_name)
            message['fields']['match_event_indicator'] = '|'.join(mei_flags) if mei_flags else 'None'

            no_md_entries = message['fields']['no_md_entries']

            # Move offset past header
            new_offset += header_size

            # Parse repeating group entries
            group_size = struct.calcsize(template['group_format'])

            entries = []
            for i in range(no_md_entries):
                if len(data) - new_offset < group_size:
                    self.logger.error(f"Not enough data for group entry {i+1}")
                    break

                group_values = struct.unpack_from(template['group_format'], data, new_offset)
                group_data = dict(zip(template['group_fields'], group_values))
                
                # Process group fields
                md_entry_px = group_data['md_entry_px']
                if md_entry_px == 9223372036854775807:  # Null value for PRICENULL9
                    group_data['md_entry_px'] = None
                else:
                    group_data['md_entry_px'] = md_entry_px / 1e9  # Adjust scale

                md_display_qty = group_data['md_display_qty']
                if md_display_qty == 2147483647:  # Null value for Int32NULL
                    group_data['md_display_qty'] = None

                md_update_action = group_data['md_update_action']
                group_data['md_update_action'] = self.md_update_action_map.get(
                    md_update_action, f"Unknown_{md_update_action}")

                entry_type = group_data['md_entry_type']
                if isinstance(entry_type, bytes):
                    entry_type = ord(entry_type)
                group_data['md_entry_type'] = self.md_entry_type_map.get(
                    entry_type, f"Unknown_0x{entry_type:02x}")

                entries.append(group_data)

                # Move offset to next group entry
                new_offset += group_size

            message['entries'] = entries

            return message, new_offset

        except struct.error as e:
            self.logger.error(f"Failed to parse message body: {e}")
            self.logger.error(f"Raw bytes at error: {data[new_offset:new_offset+40].hex()}")
            return None, len(data)


    def decode_pcap(self, input_file: str, output_file: str, packet_limit: int = 10000000000) -> None:
        """Decode MDP messages from PCAP file and write to CSV."""
        messages = []
        packet_count = 0

        try:
            with open(input_file, 'rb') as f:
                pcap = dpkt.pcap.Reader(f)
                
                for timestamp, buf in pcap:
                    if packet_limit and packet_count >= packet_limit:
                        break
                        
                    packet_count += 1
                    try:
                        eth = dpkt.ethernet.Ethernet(buf)
                        if not isinstance(eth.data, dpkt.ip.IP):
                            continue

                        ip = eth.data
                        if not isinstance(ip.data, dpkt.udp.UDP):
                            continue

                        udp = ip.data
                        offset = 0
                        
                        while offset < len(udp.data):
                            message, offset = self.parse_mdp_message(udp.data, offset)
                            if message:
                                message['fields']['timestamp'] = timestamp
                                messages.append(message)
                            else:
                                break

                    except Exception as e:
                        self.logger.error(f"Error processing packet {packet_count}: {e}")
                        continue

        except Exception as e:
            self.logger.error(f"Error reading PCAP file: {e}")
            raise

        self.write_to_csv(messages, output_file)

    def write_to_csv(self, messages: list, output_file: str) -> None:
        """Write parsed messages to CSV file."""
        if not messages:
            self.logger.warning("No messages to write to CSV")
            return

        try:
            # Get all unique fields from all messages
            fields = set()
            for msg in messages:
                fields.update(msg['fields'].keys())
            fields = sorted(fields)

            with open(output_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['template_id'] + fields)

                for msg in messages:
                    row = [msg['template_id']]
                    row.extend(msg['fields'].get(field, '') for field in fields)
                    writer.writerow(row)

            self.logger.info(f"Successfully wrote {len(messages)} messages to {output_file}")

        except Exception as e:
            self.logger.error(f"Error writing to CSV: {e}")
            raise

        
    def process_pcap_data(self, pcap_data: bytes, message_limit: Optional[int] = None) -> list:
        """Process raw PCAP data and return parsed messages."""
        messages = []
        packet_count = 0
        message_count = 0
        
        try:
            pcap = dpkt.pcap.Reader(io.BytesIO(pcap_data))
            
            for timestamp, buf in pcap:
                packet_count += 1
                
                if message_limit and message_count >= message_limit:
                    self.logger.info(f"Reached message limit of {message_limit}")
                    break
                    
                try:
                    eth = dpkt.ethernet.Ethernet(buf)
                    if not isinstance(eth.data, dpkt.ip.IP):
                        continue

                    ip = eth.data
                    if not isinstance(ip.data, dpkt.udp.UDP):
                        continue

                    udp = ip.data
                    offset = 0
                    
                    while offset < len(udp.data):
                        message, offset = self.parse_mdp_message(udp.data, offset)
                        if message:
                            # For each entry in message['entries'], create a separate message
                            for entry in message['entries']:
                                combined_fields = message['fields'].copy()
                                combined_fields.update(entry)
                                combined_fields['timestamp'] = timestamp
                                combined_fields['packet_number'] = packet_count
                                messages.append({
                                    'template_id': message['template_id'],
                                    'fields': combined_fields
                                })
                                message_count += 1
                                
                                if message_count % 1000 == 0:
                                    self.logger.info(f"Processed {message_count} messages from {packet_count} packets")
                                    
                                if message_limit and message_count >= message_limit:
                                    break
                        else:
                            break

                except Exception as e:
                    self.logger.error(f"Error processing packet {packet_count}: {e}")
                    continue

        except Exception as e:
            self.logger.error(f"Error reading PCAP data at packet {packet_count}: {e}")
            
        self.logger.info(f"Finished processing {packet_count} packets, found {len(messages)} messages")
        return messages

        
        
    def decode_zip_archive(self, zip_path: str, output_file: str, message_limit: Optional[int] = None, batch_size: int = 1000000) -> None:
        """Process a ZIP file containing .zst compressed PCAP files and write to a single CSV in batches."""
        first_batch = True
        current_batch = []
        total_messages = 0
        
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            for filename in zip_ref.namelist():
                if not filename.endswith('.zst'):
                    continue
                    
                self.logger.info(f"Processing {filename}")
                
                # Extract and decompress
                zst_data = zip_ref.read(filename)
                dctx = zstd.ZstdDecompressor()
                pcap_data = dctx.decompress(zst_data)
                
                # Calculate remaining messages to process
                remaining_messages = None if message_limit is None else message_limit - total_messages
                if remaining_messages is not None and remaining_messages <= 0:
                    break
                    
                # Process PCAP data
                messages = self.process_pcap_data(pcap_data, remaining_messages)
                
                # Add source file information
                for msg in messages:
                    msg['fields']['source_file'] = filename
                    current_batch.append(msg)
                    
                    # Write batch if it reaches the size limit
                    if len(current_batch) >= batch_size:
                        self.write_batch_to_csv(current_batch, output_file, write_header=first_batch)
                        first_batch = False
                        current_batch = []
                
                total_messages += len(messages)
                self.logger.info(f"Processed {len(messages)} messages from {filename}")
                
                if message_limit and total_messages >= message_limit:
                    self.logger.info(f"Reached total message limit of {message_limit}")
                    break
        
        # Write any remaining messages
        if current_batch:
            self.write_batch_to_csv(current_batch, output_file, write_header=first_batch)

    def write_batch_to_csv(self, messages: list, output_file: str, write_header: bool = True) -> None:
        """Write a batch of messages to CSV file."""
        if not messages:
            return
            
        # Get all unique fields
        fields = set()
        for msg in messages:
            fields.update(msg['fields'].keys())
        fields = sorted(fields)
        
        # Write to CSV
        mode = 'w' if write_header else 'a'
        with open(output_file, mode, newline='') as f:
            writer = csv.writer(f)
            
            if write_header:
                writer.writerow(['template_id'] + fields)
                
            for msg in messages:
                row = [msg['template_id']]
                row.extend(msg['fields'].get(field, '') for field in fields)
                writer.writerow(row)
        
        self.logger.info(f"Wrote batch of {len(messages)} messages to {output_file}")

def main():
    # import argparse
    # parser = argparse.ArgumentParser(description='Parse CME MDP 3.0 MBOFD PCAP files')
    # parser.add_argument('input_file', help='Input PCAP file path')
    # parser.add_argument('output_file', help='Output CSV file path')
    # parser.add_argument('--packet-limit', type=int, help='Limit number of packets to process')
    # parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    # args = parser.parse_args()

    parser = MDPParser(debug=True, logging_enabled=True)
    # parser.decode_pcap(args.input_file, args.output_file, 10000000)
    parser.decode_zip_archive("C:/data/dev/OneTickPersonal/CMEDecoder/PythonCMEDecoder/data/dc3-glbx-a-20230716.zip",
                              "C:/data/dev/OneTickPersonal/CMEDecoder/PythonCMEDecoder/output/output.csv",
                              message_limit=1000,
                              batch_size=1000000)

if __name__ == '__main__':
    main()
    
'''
python mdp_parser.py input.pcap output.csv --packet-limit 1000 --debug
'''