from sbedecoder import MDPSchema, MDPMessageFactory, SBEParser
import zstandard as zstd
import dpkt
import struct

def decode_mdp_packet(packet_data, message_parser):
    """Decode a single MDP packet"""
    try:
        # Extract UDP payload
        eth = dpkt.ethernet.Ethernet(packet_data)
        if isinstance(eth.data, dpkt.ip.IP):
            ip = eth.data
            if isinstance(ip.data, dpkt.udp.UDP):
                udp = ip.data
                message_data = udp.data
                
                # Skip Ethernet (14) + IP (20) + UDP (8) = 42 bytes
                
                # MDP 3.0 packet structure:
                # Bytes 0-3:   Sequence number (uint32)
                # Bytes 4-11:  Send time (uint64)
                # Followed by messages, each with:
                # - 2 bytes message size
                # - 2 bytes template ID
                # - 4 bytes block length
                # - Message payload
                
                # Skip MDP packet header (12 bytes)
                offset = 12
                
                while offset + 8 <= len(message_data):  # Need at least 8 bytes for message header
                    try:
                        # First 2 bytes: Message Size (uint16, big-endian)
                        # Next 2 bytes: Template ID (uint16, big-endian)
                        # Next 4 bytes: Block Length (uint32, big-endian)
                        message_header = struct.unpack_from('>HHI', message_data, offset)
                        message_size, template_id, block_length = message_header
                        
                        print(f"Message header - Size: {message_size}, Template ID: {template_id}, Block Length: {block_length}")
                        
                        # Validate message size
                        if message_size < 8 or offset + message_size > len(message_data):
                            print(f"Invalid message size: {message_size} at offset {offset}")
                            break
                        
                        # Get the complete message (including header)
                        message_buffer = message_data[offset:offset + message_size]
                        
                        if template_id == 47:  # MBOFD message
                            print(f"Found MBOFD message at offset {offset}")
                            try:
                                # Skip the size field when parsing
                                messages = message_parser.parse(message_buffer[2:], offset=0)
                                if messages:
                                    for message in messages:
                                        process_mbofd_message(message)
                            except Exception as e:
                                print(f"Error parsing MBOFD message: {e}")
                        
                        offset += message_size
                        
                    except struct.error as e:
                        print(f"Error unpacking message header at offset {offset}: {e}")
                        break
                    
    except Exception as e:
        print(f"Error processing packet: {e}")

def process_mbofd_message(message):
    """Process MBOFD message (Template ID 47)"""
    try:
        if not hasattr(message, 'template_id') or message.template_id.value != 47:
            return
        
        # Extract message header information
        transact_time = message.get_field('TransactTime')
        match_event_indicator = message.get_field('MatchEventIndicator')
        
        print(f"""
        Found MBOFD message:
        - Template ID: 47
        - TransactTime: {transact_time}
        - MatchEventIndicator: {match_event_indicator}
        """)
        
        # Process NoOrderIDEntries group
        order_entries = message.get_group('NoOrderIDEntries')
        if order_entries:
            for entry in order_entries:
                order_id = entry.get_field('OrderID')
                md_order_priority = entry.get_field('MDOrderPriority')
                md_display_qty = entry.get_field('MDDisplayQty')
                reference_id = entry.get_field('ReferenceID')
                order_update_action = entry.get_field('OrderUpdateAction')
                
                print(f"""
                Order Entry:
                - Order ID: {order_id}
                - Priority: {md_order_priority}
                - Display Qty: {md_display_qty}
                - Reference ID: {reference_id}
                - Update Action: {order_update_action}
                """)
    except Exception as e:
        print(f"Error processing MBOFD message: {e}")

def decode_mdp_messages(pcap_file, schema_file):
    try:
        # Initialize schema
        mdp_schema = MDPSchema()
        print("Schema initialized")
        
        # Parse the schema file
        mdp_schema.parse(schema_file)
        print("Schema parsed successfully")
        
        # Debug print available templates
        # if hasattr(mdp_schema, 'messages'):
        #     print(f"Available templates: {sorted(mdp_schema.messages.keys())}")
        
        # Create message factory and parser
        message_factory = MDPMessageFactory(mdp_schema)
        message_parser = SBEParser(message_factory)
        
        # Process PCAP file
        packet_count = 0
        with open(pcap_file, 'rb') as f:
            dctx = zstd.ZstdDecompressor()
            with dctx.stream_reader(f) as reader:
                pcap = dpkt.pcap.Reader(reader)
                
                for timestamp, packet in pcap:
                    packet_count += 1
                    if packet_count % 1000 == 0:
                        print(f"Processing packet {packet_count}")
                    decode_mdp_packet(packet, message_parser)
                
        print(f"Processed {packet_count} packets")
                    
    except Exception as e:
        print(f"Error in decode_mdp_messages: {e}")

if __name__ == '__main__':
    schema_file = 'C:/data/dev/OneTickPersonal/CMEDecoder/PythonCMEDecoder/data/templates_FixBinary_v12.xml'
    pcap_file = 'C:/data/dev/OneTickPersonal/CMEDecoder/PythonCMEDecoder/output/dc3-glbx-a-20230716T110000.pcap.zst'
    
    decode_mdp_messages(pcap_file, schema_file)