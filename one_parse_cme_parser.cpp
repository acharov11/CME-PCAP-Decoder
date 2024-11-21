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

    void parse_first_packet() {
        input_file.open(filename, ios::binary);
        if (!input_file.is_open()) {
            throw runtime_error("Unable to open file: " + filename);
        }

        // Skip PCAP global header (24 bytes)


        // 12 bytes
        // input_file.ignore(sizeof(TechnicalHeader));

        // Read first PCAP packet header
        TechnicalHeader tech_header;
        // input_file.read(reinterpret_cast<char*>(&pcap_header), sizeof(PcapPacketHeader));
        input_file.read(reinterpret_cast<char*>(&tech_header), sizeof(TechnicalHeader));

        DEBUG_PRINT("\nPCAP Technical Header");
        DEBUG_PRINT("msgSeqNum: ", tech_header.msgSeqNum,
                    "\nsendingTime: ", tech_header.sendingTime);

        CMEMessageHeader cme_header;

        input_file.read(reinterpret_cast<char*>(&tech_header), sizeof(CMEMessageHeader));

        DEBUG_PRINT("\nCME Message header");
        DEBUG_PRINT("msgSize: ", cme_header);


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
        parser.parse_first_packet();
    } catch (const exception& e) {
        cerr << "Error: " << e.what() << endl;
        return 1;
    }
    return 0;
}