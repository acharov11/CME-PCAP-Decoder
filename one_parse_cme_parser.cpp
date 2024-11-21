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


    // Convert hext string to std::vector<uint8_t>
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



    void parse_packet(const std::vector<uint8_t>& packet_data) {

        // Ensure enough data for TechnicalHeader
        if(packet_data.size() < sizeof(TechnicalHeader)) {
            throw std::runtime_error("Packet data too small to contain TechnicalHeader");
        }

        // Parse TechnicalHeader
        TechnicalHeader tech_header;
        // Can't parse whole struct because of padding, so parse struct individually and copy
        // data with memcpy to new struct
        std::memcpy(&tech_header.msgSeqNum, packet_data.data(), sizeof(tech_header.msgSeqNum));
        std::memcpy(&tech_header.sendingTime, packet_data.data() + sizeof(tech_header.msgSeqNum), sizeof(tech_header.sendingTime));

        std::cout << "\n==== PCAP Technical Header ====" << std::endl;
        std::cout << "msgSeqNum: " << tech_header.msgSeqNum << std::endl;
        std::cout << "sendingTime: " << tech_header.sendingTime << std::endl;

        // Ensure enough data for CME Message header
        size_t offset = sizeof(TechnicalHeader);
        if (packet_data.size() < offset + sizeof(CMEMessageHeader)) {
            throw std::runtime_error("Packet data too small to contain CMEMessageHeader");
        }

        // Parse CME Message Header
        CMEMessageHeader cme_header;
        // Inlcude offset of tech header
        memcpy(&cme_header.msgSize, packet_data.data() + offset, sizeof(CMEMessageHeader));
        memcpy(&cme_header.blockLength, packet_data.data() + offset, sizeof(CMEMessageHeader));
        memcpy(&cme_header.templateID, packet_data.data() + offset, sizeof(CMEMessageHeader));
        memcpy(&cme_header.schemaID, packet_data.data() + offset, sizeof(CMEMessageHeader));
        memcpy(&cme_header.version, packet_data.data() + offset, sizeof(CMEMessageHeader));

        std::cout << "\n==== CME Message Header ====" << std::endl;
        std::cout << "msgSize: " << cme_header.msgSize << std::endl;
        std::cout << "blockLength: " << cme_header.blockLength << std::endl;
        std::cout << "templateID: " << cme_header.templateID << std::endl;
        std::cout << "schemaID: " << cme_header.schemaID << std::endl;
        std::cout << "version: " << cme_header.version << std::endl;
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

        // Parse the packet (we have reached the payload)
        parse_packet(packet_data);

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
        // parser.process_nth_packet(1);
        // parser.process_nth_packet(10);
        // parser.process_nth_packet(21);

        /* VALIDATE PACKET PAYLOAD PARSING WITH CME EXAMPLE */
        std::string hex_stream = "A6 BB 0A 00 5B 19 01 72 1E EF A9 16 38 00 0B 00 32 00 01 00 09 00 4B 52 E8 71 1E EF A9 16 00 00 00 20 00 01 FF FF FF FF FF FF FF 7F 00 90 CD 79 2F 08 00 00 00 E4 0B 54 02 00 00 00 F4 15 00 00 4D 07 00 00";
        std::vector<uint8_t> packet_data = parser.hex_string_to_vector(hex_stream);
        try {
            parser.parse_packet(packet_data);
        } catch (const std::exception& e) {
            std::cerr << "error: " << e.what() << std::endl;
        }

    } catch (const exception& e) {
        cerr << "Error: " << e.what() << endl;
        return 1;
    }
    return 0;
}