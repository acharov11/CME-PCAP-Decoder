//
// Created by hruks on 11/17/2024.
//

#include "one_parse_cme_parser.h"



#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <ctime>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <string>
#include "DebugUtil.h"
#include "MKTData/MessageHeader.h"
using namespace std;

class CMEParser {
private:
    string filename;
    ifstream input_file;
    bool advanced_debug = true;

    // Techinical Header
    struct TechnicalHeader {
        uint32_t msgSeqNum;     // UDP
        uint64_t sendingTime;
    };

    struct CMEMessageHeader {
        uint16_t msgSize;
        uint16_t blockLength;
        uint16_t templateID;
        uint16_t schemaID;
        uint16_t version;
    };

    // PCAP Packet Header (16 bytes)
    struct PcapPacketHeader {
        uint32_t ts_sec;         // Timestamp seconds
        uint32_t ts_usec;        // Timestamp microseconds
        uint32_t incl_len;       // Number of octets of packet saved in file
        uint32_t orig_len;       // Actual length of packet
    };

public:
    CMEParser(const string& input_file) : filename(input_file) {}


    /* @TODO
     * implement way to select CSV vs print, logger, put all messages into CSV
     * getting lots of MDInstrumentDefinitionOption template id 55?
     */

    // UTILITY FUNCTIONS

    // Convert hex string to std::vector<uint8_t>
    std::vector<uint8_t> hex_string_to_vector(const std::string& hex_string) {
        std::vector<uint8_t> byte_vector;
        std::istringstream hex_stream(hex_string);
        std::string byte_str;

        while (hex_stream >> byte_str) {
            uint8_t byte = static_cast<uint8_t>(std::stoul(byte_str, nullptr, 16));
            byte_vector.push_back(byte);
        }

        return byte_vector;
    }

    std::string format_timestamp(uint32_t ts_sec, uint32_t ts_usec) {
        // Convert ts_sec to HH:MM:SS using gmtime
        std::time_t raw_time = static_cast<std::time_t>(ts_sec);
        std::tm* timeinfo = std::gmtime(&raw_time);

        // Format as HH:MM:SS.UUUUUU
        std::ostringstream oss;
        oss << std::setfill('0') << std::setw(2) << timeinfo->tm_hour << ":"
            << std::setw(2) << timeinfo->tm_min << ":"
            << std::setw(2) << timeinfo->tm_sec << "."
            << std::setw(6) << ts_usec; // Append microseconds

        return oss.str();
    }

    // Util function to extract a field from a std::vector<uint8_t> at a specific offset and
    // advance offset automatically
    template <typename T>
    T extract_field(const std::vector<uint8_t>& data, size_t& offset) {
        if (offset + sizeof(T) > data.size()) {
            throw std::runtime_error("Not enough data to extract field");
        }

        T field;
        std::memcpy(&field, data.data() + offset, sizeof(T));
        offset += sizeof(T);
        return field;
    }

    // Skip (num_bytes) amount of bytes from a std::vector<uint8_t> and advance offset automatically
    void skip_bytes(size_t num_bytes, const std::vector<uint8_t>& data, size_t& offset) {
        if (offset + num_bytes > data.size()) {
            throw std::runtime_error("Not enough data to skip bytes");
        }
        offset += num_bytes;
    }

    // Extract a custom N-length string field from a std::vector<uint8_t> and automatically advanced offset
    std::string extract_fixed_length_string(size_t length, const std::vector<uint8_t>& data, size_t& offset) {
        if (offset + length > data.size()) {
            throw std::runtime_error("Not enough data to extract string");
        }

        std::string result(reinterpret_cast<const char*>(data.data() + offset), length);
        offset += length;
        return result;
    }

    // Extract a null-terminated string from a std::vector<uint8_t> and automatically advance offset
    std::string extract_null_terminated_string(const std::vector<uint8_t>& data, size_t& offset) {
        size_t start_offset = offset;
        while (offset < data.size() && data[offset] != '\0') {
            ++offset;
        }
        if (offset == data.size()) {
            throw std::runtime_error("Null-terminated string not found");
        }
        std::string result(reinterpret_cast<const char*>(data.data() + start_offset), offset - start_offset);
        ++offset; // Skip the null terminator
        return result;
    }

    // Print out all the bits from a given byte (usually uint8_t interpreted as char)
    void print_bits(uint8_t value) {
        std::cout << "Bits: ";
        for (int i = 7; i >= 0; --i) { // Iterate from MSB to LSB
            std::cout << ((value >> i) & 1);
        }
        std::cout << std::endl;
    }

    // Print DEBUG info for a uint8
    void print_uint8_info(uint8_t value) {
        std::cout << "Decimal: " << static_cast<int>(value)
                  << ", Hex: 0x" << std::hex << static_cast<int>(value)
                  << ", Bits: ";
        for (int i = 7; i >= 0; --i) {
            std::cout << ((value >> i) & 1);
        }
        std::cout << std::dec << std::endl;
    }


    // PARSING

    void parse_template_50_LBM(const std::vector<uint8_t>& packet_data, size_t& offset) {
        std::cout << "Parsing template 50_LBM..." << std::endl;

        struct SBE_LBM {
            uint64_t transactTime;
            uint8_t matchEventIndicator;
            // 2 byte padding
            uint16_t noMDEntries;
            uint8_t numInGroup;
            int64_t highLimitPrice; // (null value as 9223372036854775807 for the mantissa)
            int64_t lowLimitPrice;
            // not part but int8 exponent (-9), constant as -9 for PRICENULL 9, not sent in SBE
            // message on wire, and not part of block length calculation
            int64_t maxPriceVariation;
            // not part but int8 exponent (-9), constant as -9 for PRICENULL 9, not sent in SBE
            // message on wire, and not part of block length calculation
            int32_t securityID;
            uint32_t rptSeq;
            // MDUpateAction uint8 -- 0 -- dfined as 0 constant (not sent in SBE message), not part of block length
            // MDEntryType char -- g -- constant, not part of block length calculation
        };

        SBE_LBM sbe_lbm;
        sbe_lbm.transactTime = extract_field<uint64_t>(packet_data, offset);
        sbe_lbm.matchEventIndicator = extract_field<uint8_t>(packet_data, offset);
        skip_bytes(2, packet_data, offset);
        sbe_lbm.noMDEntries = extract_field<uint16_t>(packet_data, offset);
        sbe_lbm.numInGroup = extract_field<uint8_t>(packet_data, offset);
        sbe_lbm.highLimitPrice = extract_field<int64_t>(packet_data, offset);
        sbe_lbm.lowLimitPrice = extract_field<int64_t>(packet_data, offset);
        sbe_lbm.maxPriceVariation = extract_field<int64_t>(packet_data, offset);
        sbe_lbm.securityID = extract_field<int32_t>(packet_data, offset);
        sbe_lbm.rptSeq = extract_field<uint32_t>(packet_data, offset);

        std::cout << "\n==== SBE_LBM Message ====" << std::endl;
        std::cout << "transactTime: " << sbe_lbm.transactTime << std::endl;
        std::cout << "matchEventIndicator: " << std::hex << static_cast<int>(sbe_lbm.matchEventIndicator) << std::dec << std::endl;
        print_uint8_info(sbe_lbm.matchEventIndicator);
        std::cout << "noMDEntries: " << sbe_lbm.noMDEntries << std::endl;
        std::cout << "numInGroup: " << sbe_lbm.numInGroup << std::endl;
        print_uint8_info(sbe_lbm.numInGroup);
        std::cout << "highLimitPrice: " << sbe_lbm.highLimitPrice << std::endl;
        std::cout << "lowLimitPrice: " << sbe_lbm.lowLimitPrice << std::endl;
        std::cout << "maxPriceVariation: " << sbe_lbm.maxPriceVariation << std::endl;
        std::cout << "securityID: " << sbe_lbm.securityID << std::endl;
        std::cout << "rptSeq: " << sbe_lbm.rptSeq << std::endl;
    }

    // Further parses the rest of the packet payload based on templateID, will switch and choose
    // the correct one
    void parse_by_template_id(uint16_t templateID, const std::vector<uint8_t>& packet_data, size_t& offset) {
        std::cout << "\n<<< Attempting to parse templateID [" << templateID << "] >>>" << std::endl;
        switch (templateID) {
            case 50:
                parse_template_50_LBM(packet_data, offset);
            break;
            case 2:
                // parse_template_2(packet_data, offset);
                std::cout << "parsing case 2" << std::endl;
            break;
            // Add cases for other templateIDs
            default:
                std::cerr << "Unknown templateID: " << templateID << std::endl;
            break;
        }
    }

    void parse_packet(const std::vector<uint8_t>& packet_data) {

        // Ensure enough data for TechnicalHeader -- sanity check
        if(packet_data.size() < sizeof(TechnicalHeader)) {
            throw std::runtime_error("Packet data too small to contain TechnicalHeader");
        }

        // Store offset to advance through packet data
        size_t offset = 0;

        // Parse TechnicalHeader
        TechnicalHeader tech_header;
        // Can't parse whole struct because of padding, so parse struct individually and copy
        // data with memcpy to new struct
        // std::memcpy(&tech_header.msgSeqNum, packet_data.data(), sizeof(tech_header.msgSeqNum));
        // std::memcpy(&tech_header.sendingTime, packet_data.data() + sizeof(tech_header.msgSeqNum), sizeof(tech_header.sendingTime));

        // New method is faster
        tech_header.msgSeqNum = extract_field<uint32_t>(packet_data, offset);
        tech_header.sendingTime = extract_field<uint64_t>(packet_data, offset);

        std::cout << "\n==== PCAP Technical Header ====" << std::endl;
        std::cout << "msgSeqNum: " << tech_header.msgSeqNum << std::endl;
        std::cout << "sendingTime: " << tech_header.sendingTime << std::endl;

        // Ensure enough data for CME Message header
        if (packet_data.size() < offset + sizeof(CMEMessageHeader)) {
            throw std::runtime_error("Packet data too small to contain CMEMessageHeader");
        }

        // Parse CME Message Header
        CMEMessageHeader cme_header;
        cme_header.msgSize = extract_field<uint16_t>(packet_data,offset);
        cme_header.blockLength = extract_field<uint16_t>(packet_data,offset);
        cme_header.templateID = extract_field<uint16_t>(packet_data,offset);
        cme_header.schemaID = extract_field<uint16_t>(packet_data,offset);
        cme_header.version = extract_field<uint16_t>(packet_data,offset);

        std::cout << "\n==== CME Message Header ====" << std::endl;
        std::cout << "msgSize: " << cme_header.msgSize << std::endl;
        std::cout << "blockLength: " << cme_header.blockLength << std::endl;
        std::cout << "templateID: " << cme_header.templateID << std::endl;
        std::cout << "schemaID: " << cme_header.schemaID << std::endl;
        std::cout << "version: " << cme_header.version << std::endl;

        // Dispatch parsing based on templateID
        parse_by_template_id(cme_header.templateID, packet_data, offset);
    }

    void process_nth_packet(size_t packet_number) {
        input_file.open(filename, ios::binary);
        if (!input_file.is_open()) {
            throw runtime_error("Unable to open file: " + filename);
        }

        std::cout << "\n <<<< START: PACKET [" << packet_number << "] START >>>>" << std::endl;

        // Skip the PCAP Global Header (24 bytes)
        input_file.ignore(24);

        // Read the first PCAP Packet Header (16 bytes)
        PcapPacketHeader pcap_header;
        for (size_t i = 1; i < packet_number; ++i) {

            // Read the PCAP Packet Header
            input_file.read(reinterpret_cast<char*>(&pcap_header), sizeof(PcapPacketHeader));

            // Skip the packet data (incl_len bytes)
            input_file.ignore(pcap_header.incl_len);

            if(input_file.eof()) {
                throw std::runtime_error("Reached end of file before finding packet " + std::to_string(packet_number));
            }
        }

        // Read the N-th packet header
        input_file.read(reinterpret_cast<char*>(&pcap_header), sizeof(PcapPacketHeader));
        if (input_file.eof()) {
            throw std::runtime_error("Reached end of file before finding packet " + std::to_string(packet_number));
        }

        // Convert timestamp to human-readable format
        std::string converted_time = format_timestamp(pcap_header.ts_sec, pcap_header.ts_usec);

        std::cout << "\n ==== [" << packet_number << "] Header General Info ====" << std::endl;
        std::cout << "Timestamp: " << pcap_header.ts_sec << "." << pcap_header.ts_usec << std::endl;
        std::cout << "Converted Timestamp: " << converted_time << std::endl;
        std::cout << "Included Length: " << pcap_header.incl_len << " bytes" << std::endl;

        // Read the N-th packet payload (up to incl_len bytes)
        std::vector<uint8_t> packet_data(pcap_header.incl_len);
        input_file.read(reinterpret_cast<char*>(packet_data.data()), pcap_header.incl_len);

        if (packet_data.size() < 42) {
            throw std::runtime_error("Packet too small to contain expected headers (42 bytes).");
        }

        // Parse the packet (we have reached the payload -- at byte 42)
        std::vector<uint8_t> payload_data(packet_data.begin() + 42, packet_data.end());
        parse_packet(payload_data);

        // Print the raw byte stream
        if(advanced_debug) {
            std::cout << "\n ==== [" << packet_number << "] Raw Byte Stream ====" << std::endl;
            const int NUM_ROWS_PRINT = 3;
            int row_printed_count = 0;
            for (size_t i = 0; i < packet_data.size(); ++i) {
                std::cout << std::hex << std::setw(2) << std::setfill('0')
                          << static_cast<int>(packet_data[i]) << " ";
                if ((i + 1) % 16 == 0) {
                    row_printed_count++;
                    if(row_printed_count >= NUM_ROWS_PRINT) break;
                    std::cout << std::endl;
                }
            }
            std::cout << std::dec << std::endl;
        }

        std::cout << "\n <<<< END: PACKET [" << packet_number << "] END >>>>" << std::endl;

        input_file.close();
    }
};

int main() {
    try {
        string input_file = "C:/data/dev/OneTickPersonal/CMEDecoder/PCAPParser/data/dc3-glbx-a-20230716T110000.pcap";
        string output_file = "C:/data/dev/OneTickPersonal/CMEDecoder/PCAPParser/output/result.csv";

        CMEParser parser(input_file);
        parser.process_nth_packet(500473);
        // parser.process_nth_packet(10);
        // parser.process_nth_packet(21);

        /* VALIDATE PACKET PAYLOAD PARSING WITH CME EXAMPLE */
        // std::string hex_stream = "A6 BB 0A 00 5B 19 01 72 1E EF A9 16 38 00 0B 00 32 00 01 00 09 00 4B 52 E8 71 1E EF A9 16 00 00 00 20 00 01 FF FF FF FF FF FF FF 7F 00 90 CD 79 2F 08 00 00 00 E4 0B 54 02 00 00 00 F4 15 00 00 4D 07 00 00";
        // std::vector<uint8_t> packet_data = parser.hex_string_to_vector(hex_stream);
        // try {
        //     parser.parse_packet(packet_data);
        // } catch (const std::exception& e) {
        //     std::cerr << "error: " << e.what() << std::endl;
        // }

    } catch (const exception& e) {
        cerr << "Error: " << e.what() << endl;
        return 1;
    }
    return 0;
}