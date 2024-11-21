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

    // // CME Packet Header (16 bytes)
    // struct CMEPacketHeader {
    //     uint64_t sequence_number; // 8 bytes
    //     uint64_t sending_time;    // 8 bytes
    // };
    //
    // // CME Message Header (16 bytes)
    // struct CMEMessageHeader {
    //     uint32_t message_size;    // 4 bytes
    //     uint32_t template_id;     // 4 bytes
    //     uint32_t schema_id;       // 4 bytes
    //     uint32_t version;         // 4 bytes
    // };

public:
    CMEParser(const string& input_file) : filename(input_file) {}

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
        std::memcpy(&tech_header, packet_data.data(), sizeof(TechnicalHeader));

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
        memcpy(&cme_header, packet_data.data() + offset, sizeof(CMEMessageHeader));

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


        // // Read first PCAP packet header -- 12 bytes
        // TechnicalHeader tech_header;
        // // input_file.read(reinterpret_cast<char*>(&pcap_header), sizeof(PcapPacketHeader));
        // input_file.read(reinterpret_cast<char*>(&tech_header), sizeof(TechnicalHeader));
        //
        // DEBUG_PRINT("\n ==== PCAP Technical Header ==== ");
        // DEBUG_PRINT("msgSeqNum: ", tech_header.msgSeqNum,
        //             "\nsendingTime: ", tech_header.sendingTime);
        //
        // CMEMessageHeader cme_header;
        //
        // input_file.read(reinterpret_cast<char*>(&tech_header), sizeof(CMEMessageHeader));
        //
        // DEBUG_PRINT("\n ==== CME Message header ==== ");
        // DEBUG_PRINT("msgSize: ", cme_header.msgSize,
        //             "\nblockLength: ", cme_header.blockLength,
        //             "\ntemplateID: ",cme_header.templateID,
        //             "\nschemaID: ", cme_header.schemaID,
        //             "\nversion: ",cme_header.version
        //             );

        // for()


        // cout << "\nPCAP Packet Header:" << endl;
        // cout << "Timestamp: " << pcap_header.ts_sec << "."
        //      << setfill('0') << setw(6) << pcap_header.ts_usec << endl;
        // cout << "Captured Length: " << pcap_header.incl_len << " bytes" << endl;
        // cout << "Original Length: " << pcap_header.orig_len << " bytes" << endl;
        // cout << "UDP Payload Length: " << (pcap_header.incl_len - 42) << " bytes" << endl;

        // Skip network headers (Ethernet + IP + UDP = 42 bytes)
        // input_file.ignore(42);

        // // Read and display the raw UDP payload bytes
        // vector<uint8_t> payload(pcap_header.incl_len - 42);
        // input_file.read(reinterpret_cast<char*>(payload.data()), pcap_header.incl_len - 42);
        //
        // cout << "\nRaw UDP Payload (hex):" << endl;
        // for(size_t i = 0; i < payload.size(); i++) {
        //     cout << hex << setfill('0') << setw(2)
        //          << static_cast<int>(payload[i]) << " ";
        //     if((i + 1) % 16 == 0) cout << endl;
        // }
        // cout << dec << endl;
        //
        // // Parse CME packet header (first 8 bytes)
        // if (payload.size() >= 8) {
        //     // First 4 bytes: sequence number
        //     uint32_t seq_num = 0;
        //     seq_num |= static_cast<uint32_t>(payload[0]);
        //     seq_num |= static_cast<uint32_t>(payload[1]) << 8;
        //     seq_num |= static_cast<uint32_t>(payload[2]) << 16;
        //     seq_num |= static_cast<uint32_t>(payload[3]) << 24;
        //
        //     // Next 4 bytes: sending time
        //     uint32_t send_time = 0;
        //     send_time |= static_cast<uint32_t>(payload[4]);
        //     send_time |= static_cast<uint32_t>(payload[5]) << 8;
        //     send_time |= static_cast<uint32_t>(payload[6]) << 16;
        //     send_time |= static_cast<uint32_t>(payload[7]) << 24;
        //
        //     cout << "\nCME Packet Header (corrected):" << endl;
        //     cout << "Sequence number: 0x" << hex << setfill('0') << setw(8) << seq_num << dec << endl;
        //     cout << "Sending time: 0x" << hex << setfill('0') << setw(8) << send_time << dec << endl;
        //
        //     // Looking at payload -- my example:
        //     // 85 01 00 00 - Sequence number should be 0x00000185
        //     // c4 04 eb 4b - Sending time should be 0x4beb04c4
        //
        //     // Parse CME message header (next 8 bytes)
        //     if (payload.size() >= 16) {
        //         uint32_t msg_size = 0;
        //         msg_size |= static_cast<uint32_t>(payload[8]);
        //         msg_size |= static_cast<uint32_t>(payload[9]) << 8;
        //         msg_size |= static_cast<uint32_t>(payload[10]) << 16;
        //         msg_size |= static_cast<uint32_t>(payload[11]) << 24;
        //
        //         uint32_t template_id = 0;
        //         template_id |= static_cast<uint32_t>(payload[12]);
        //         template_id |= static_cast<uint32_t>(payload[13]) << 8;
        //         template_id |= static_cast<uint32_t>(payload[14]) << 16;
        //         template_id |= static_cast<uint32_t>(payload[15]) << 24;
        //
        //         cout << "\nCME Message Header:" << endl;
        //         cout << "Message size: " << msg_size << endl;
        //         cout << "Template ID: " << template_id << endl;
        //     }

        // }

        input_file.close();
    }
};

int main() {
    try {
        string input_file = "C:/data/dev/OneTickPersonal/CMEDecoder/PCAPParser/data/dc3-glbx-a-20230716T110000.pcap";
        string output_file = "C:/data/dev/OneTickPersonal/CMEDecoder/PCAPParser/output/result.csv";

        CMEParser parser(input_file);
        // parser.print_raw_bytes(64);
        parser.process_nth_packet(1);
        parser.process_nth_packet(10);
        parser.process_nth_packet(21);
        // parser.parse_first_packet_2();
    } catch (const exception& e) {
        cerr << "Error: " << e.what() << endl;
        return 1;
    }
    return 0;
}