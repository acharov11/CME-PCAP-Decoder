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
using namespace std;

class CMEParser {
private:
    string filename;
    ifstream input_file;

    // PCAP Packet Header (16 bytes)
    struct PcapPacketHeader {
        uint32_t ts_sec;         // Timestamp seconds
        uint32_t ts_usec;        // Timestamp microseconds
        uint32_t incl_len;       // Number of octets of packet saved in file
        uint32_t orig_len;       // Actual length of packet
    };

    // CME Packet Header (16 bytes)
    struct CMEPacketHeader {
        uint64_t sequence_number; // 8 bytes
        uint64_t sending_time;    // 8 bytes
    };

    // CME Message Header (16 bytes)
    struct CMEMessageHeader {
        uint32_t message_size;    // 4 bytes
        uint32_t template_id;     // 4 bytes
        uint32_t schema_id;       // 4 bytes
        uint32_t version;         // 4 bytes
    };

public:
    CMEParser(const string& input_file) : filename(input_file) {}

    void parse_first_packet() {
        input_file.open(filename, ios::binary);
        if (!input_file.is_open()) {
            throw runtime_error("Unable to open file: " + filename);
        }

        // Skip PCAP global header (24 bytes)
        input_file.ignore(24);

        // Read first PCAP packet header
        PcapPacketHeader pcap_header;
        input_file.read(reinterpret_cast<char*>(&pcap_header), sizeof(PcapPacketHeader));

        cout << "\nPCAP Packet Header:" << endl;
        cout << "Timestamp: " << pcap_header.ts_sec << "." << setfill('0') << setw(6) << pcap_header.ts_usec << endl;
        cout << "Captured Length: " << pcap_header.incl_len << " bytes" << endl;
        cout << "Original Length: " << pcap_header.orig_len << " bytes" << endl;

        // From Wireshark, we can see UDP payload length is 22 bytes
        // Verify this matches: incl_len - (Ethernet + IP + UDP headers) = 64 - 42 = 22 bytes
        cout << "UDP Payload Length: " << (pcap_header.incl_len - 42) << " bytes" << endl;

        // Skip network headers (Ethernet + IP + UDP = 42 bytes)
        input_file.ignore(42);

        // Read and display the raw UDP payload bytes
        vector<char> payload(pcap_header.incl_len - 42);
        input_file.read(payload.data(), pcap_header.incl_len - 42);

        cout << "\nRaw UDP Payload (hex):" << endl;
        for(size_t i = 0; i < payload.size(); i++) {
            cout << hex << setfill('0') << setw(2)
                 << (static_cast<int>(payload[i]) & 0xFF) << " ";
            if((i + 1) % 16 == 0) cout << endl;
        }
        cout << dec << endl; // Reset to decimal output
        // Skip network headers (Ethernet + IP + UDP = 42 bytes)
        input_file.ignore(42);

        // Read CME packet header
        CMEPacketHeader cme_header;
        input_file.read(reinterpret_cast<char*>(&cme_header), sizeof(CMEPacketHeader));

        cout << "\nCME Packet Header:" << endl;
        cout << "Sequence number: " << cme_header.sequence_number << endl;
        cout << "Sending time: " << cme_header.sending_time << endl;

        // Read first CME message header
        CMEMessageHeader msg_header;
        input_file.read(reinterpret_cast<char*>(&msg_header), sizeof(CMEMessageHeader));

        cout << "\nCME Message Header:" << endl;
        cout << "Message size: " << msg_header.message_size << endl;
        cout << "Template ID: " << msg_header.template_id << endl;
        cout << "Schema ID: " << msg_header.schema_id << endl;
        cout << "Version: " << msg_header.version << endl;



        input_file.close();
    }
};

int main() {
    try {
        string input_file = "C:/data/dev/OneTickPersonal/CMEDecoder/PCAPParser/data/dc3-glbx-a-20230716T110000.pcap";
        CMEParser parser(input_file);
        parser.parse_first_packet();
    } catch (const exception& e) {
        cerr << "Error: " << e.what() << endl;
        return 1;
    }
    return 0;
}