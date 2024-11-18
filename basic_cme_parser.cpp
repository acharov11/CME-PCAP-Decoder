//
// Created by hruks on 11/17/2024.
//

#include "basic_cme_parser.h"

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

using namespace std;

class CMEParser {
private:
    string filename;
    ofstream output_file;
    int messages_processed = 0;
    static const int MAX_MESSAGES = 1000000; // Process in batches of 1 million

    struct PcapPacketHeader {
        uint32_t ts_sec;
        uint32_t ts_usec;
        uint32_t incl_len;
        uint32_t orig_len;
    };

    struct CMEPacketHeader {
        uint32_t sequence_number;
        uint32_t sending_time;
    };

    struct CMEMessageHeader {
        uint32_t message_size;
        uint32_t template_id;
        uint32_t schema_id;
        uint32_t version;
    };

public:
    CMEParser(const string& input_file, const string& output_file)
        : filename(input_file) {
        this->output_file.open(output_file);
        // Write CSV header
        this->output_file << "Timestamp,SequenceNumber,TemplateID,SecurityID,Price,Size,Side,OrderID,Action\n";
    }

    void parse_file() {
        ifstream input_file(filename, ios::binary);
        if (!input_file.is_open()) {
            throw runtime_error("Unable to open file: " + filename);
        }

        // Skip PCAP global header (24 bytes)
        input_file.ignore(24);

        while (parse_next_packet(input_file)) {
            messages_processed++;
            if (messages_processed % 100000 == 0) {
                cout << "Processed " << messages_processed << " messages" << endl;
                output_file.flush(); // Flush to disk periodically
            }
        }

        input_file.close();
        output_file.close();
    }

private:
    bool parse_next_packet(ifstream& input_file) {
        PcapPacketHeader pcap_header;
        input_file.read(reinterpret_cast<char*>(&pcap_header), sizeof(PcapPacketHeader));
        if (input_file.eof()) return false;

        // Skip network headers (Ethernet + IP + UDP = 42 bytes)
        input_file.ignore(42);

        // Read CME packet
        vector<uint8_t> payload(pcap_header.incl_len - 42);
        input_file.read(reinterpret_cast<char*>(payload.data()), pcap_header.incl_len - 42);

        // Parse CME packet header
        uint32_t seq_num = 0;
        uint32_t send_time = 0;

        // First 4 bytes - sequence number
        seq_num |= payload[0];
        seq_num |= payload[1] << 8;
        seq_num |= payload[2] << 16;
        seq_num |= payload[3] << 24;

        // Next 4 bytes - sending time
        send_time |= payload[4];
        send_time |= payload[5] << 8;
        send_time |= payload[6] << 16;
        send_time |= payload[7] << 24;

        // Process message based on template ID
        size_t offset = 8; // Start after CME packet header
        while (offset < payload.size()) {
            CMEMessageHeader msg_header;
            memcpy(&msg_header, payload.data() + offset, sizeof(CMEMessageHeader));
            offset += sizeof(CMEMessageHeader);

            // Process based on template ID

            output_file << send_time << ","
                       << seq_num << ","
                       << msg_header.template_id << ","
                       << "\n";

            switch (msg_header.template_id) {
                case 47: // MDIncrementalRefreshOrderBook
                    parse_order_book_message(payload.data() + offset, msg_header, send_time, seq_num);
                    break;
                // Add other message types as needed
            }

            offset += msg_header.message_size;
        }

        return true;
    }

    void parse_order_book_message(const uint8_t* data, const CMEMessageHeader& header,
                                uint32_t send_time, uint32_t seq_num) {
        // Based on MDIncrementalRefreshOrderBook47 structure
        struct OrderBookEntry {
            uint64_t order_id;
            uint64_t priority;
            int64_t price;
            int32_t quantity;
            int32_t security_id;
            uint8_t update_action;
            uint8_t entry_type;
        };

        OrderBookEntry entry;
        memcpy(&entry, data, sizeof(OrderBookEntry));

        // Convert price (stored as fixed point)
        double price = static_cast<double>(entry.price) / 10000.0;

        // Write to CSV
        // output_file << send_time << ","
        //            << seq_num << ","
        //            << header.template_id << ","
        //            << entry.security_id << ","
        //            << fixed << setprecision(4) << price << ","
        //            << entry.quantity << ","
        //            << static_cast<int>(entry.entry_type) << ","
        //            << entry.order_id << ","
        //            << static_cast<int>(entry.update_action) << "\n";
        // output_file << "hi" << "\n";
    }
};

int main() {
    try {
        string input_file = "C:/data/dev/OneTickPersonal/CMEDecoder/PCAPParser/data/dc3-glbx-a-20230716T110000.pcap";
        string output_file = "C:/data/dev/OneTickPersonal/CMEDecoder/PCAPParser/output/result.csv";

        CMEParser parser(input_file, output_file);
        parser.parse_file();
        cout << "Parsing completed successfully" << endl;
    } catch (const exception& e) {
        cerr << "Error: " << e.what() << endl;
        return 1;
    }
    return 0;
}