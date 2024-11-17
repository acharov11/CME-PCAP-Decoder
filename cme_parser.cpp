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
// #include <zstd.h>

using namespace std;

class CMEParser {
private:
    string filename;
    string output_filename;
    ifstream input_file;
    ofstream output_file;
    int total_messages_processed = 0;
    time_t start_parse_time;
    time_t stop_parse_time;

    // PCAP file format headers - Standard format defined by libpcap
    // Reference: https://wiki.wireshark.org/Development/LibpcapFileFormat
    struct PcapGlobalHeader {
        uint32_t magic_number;   // PCAP file identifier (file format and byte ordering)
        uint16_t version_major;  // Major version
        uint16_t version_minor;  // Minor version
        int32_t thiszone;        // GMT to local correction
        uint32_t sigfigs;        // Accuracy of timestamps
        uint32_t snaplen;        // Max length of captured packets
        uint32_t network;        // Data link type
    };

    struct PcapPacketHeader {
        uint32_t ts_sec;         // Timestamp seconds
        uint32_t ts_usec;        // Timestamp microseconds
        uint32_t incl_len;       // Number of octets of packet saved in file
        uint32_t orig_len;       // Actual length of packet
    };

    // CME MDP 3.0 Binary Packet Header - 16 bytes
    // Reference: CME MDP 3.0 Market Data Protocol Specification
    struct CMEPacketHeader {
        uint64_t sequence_number;  // 8 bytes - Packet sequence number
        uint64_t sending_time;     // 8 bytes - Packet send time in nanoseconds
    };

    // CME MDP 3.0 Message Header - 16 bytes
    struct CMEMessageHeader {
        uint32_t message_size;     // 4 bytes - Size of message body
        uint32_t template_id;      // 4 bytes - Message template identifier
        uint32_t schema_id;        // 4 bytes - Schema version number
        uint32_t version;          // 4 bytes - Template version number
    };

public:
    CMEParser(const string& input_file, const string& output_file)
        : filename(input_file), output_filename(output_file) {
        // Open output file and write CSV header
        this->output_file.open(output_filename);
        this->output_file << "Timestamp,TemplateID,SecurityID,Price,Size,Side,OrderID,Action\n";
    }

    bool check_if_zst() {
        ifstream file(filename, ios::binary);
        if (!file.is_open()) {
            cerr << "Error opening file: " << filename << endl;
            return false;
        }

        char buffer[4];
        file.read(buffer, 4);
        file.close();

        return buffer[0] == '\x28' && buffer[1] == '\xB5' &&
               buffer[2] == '\x2F' && buffer[3] == '\xFD';
    }

    void parse() {
        DEBUG_PRINT("Going into parse!");
        if (check_if_zst()) {
            DEBUG_PRINT("Parsing as ZST");
            parse_zst_file();
        } else {
            DEBUG_PRINT("Parsing normally");
            parse_pcap_file();
        }
    }

private:
    // Parse Zstandard compressed file
    void parse_zst_file() {
        // // Initialize Zstandard decompression
        // ZSTD_DStream* dstream = ZSTD_createDStream();
        // if (dstream == nullptr) {
        //     throw runtime_error("Failed to create ZSTD_DStream");
        // }
        //
        // // Setup buffers for decompression
        // ifstream input(filename, ios::binary);
        // vector<char> in_buffer(ZSTD_DStreamInSize());
        // vector<char> out_buffer(ZSTD_DStreamOutSize());
        //
        // ZSTD_inBuffer input_buf = {in_buffer.data(), 0, 0};
        //
        // // Skip PCAP global header (24 bytes)
        // vector<char> pcap_header(24);
        // size_t bytes_read = decompress_chunk(dstream, input, pcap_header.data(), 24);
        //
        // // Process each packet
        // while (true) {
        //     PcapPacketHeader pkt_header;
        //     bytes_read = decompress_chunk(dstream, input, (char*)&pkt_header, sizeof(PcapPacketHeader));
        //     if (bytes_read == 0) break;
        //
        //     // Skip network headers (Ethernet + IP + UDP = 42 bytes)
        //     vector<char> skip_buffer(42);
        //     decompress_chunk(dstream, input, skip_buffer.data(), 42);
        //
        //     // Read CME headers and payload
        //     process_cme_packet(dstream, input, pkt_header.incl_len - 42);
        // }
        //
        // ZSTD_freeDStream(dstream);
    }

    void parse_pcap_file() {
        input_file.open(filename, ios::binary);
        if (!input_file.is_open()) {
            throw runtime_error("Unable to open file: " + filename);
        }

        DEBUG_PRINT("Skipping global header...");
        // Skip PCAP global header
        input_file.ignore(24);

        start_parse_time = time(nullptr);
        while (read_packet()) {
            total_messages_processed++;
        }
        stop_parse_time = time(nullptr);
    }

    bool read_packet() {
        PcapPacketHeader pkt_header;
        input_file.read((char*)&pkt_header, sizeof(PcapPacketHeader));
        if (input_file.eof()) return false;


        DEBUG_PRINT("Skipping network header...");
        // Skip network headers
        input_file.ignore(42);

        // Read CME packet
        vector<char> packet_data(pkt_header.incl_len - 42);
        input_file.read(packet_data.data(), pkt_header.incl_len - 42);

        process_cme_packet(packet_data);
        return true;
    }

    // Process individual CME packet
    void process_cme_packet(const vector<char>& packet_data) {
        CMEPacketHeader pkt_header;
        memcpy(&pkt_header, packet_data.data(), sizeof(CMEPacketHeader));

        size_t offset = sizeof(CMEPacketHeader);

        // Process all messages in packet
        while (offset < packet_data.size()) {
            CMEMessageHeader msg_header;
            memcpy(&msg_header, packet_data.data() + offset, sizeof(CMEMessageHeader));
            offset += sizeof(CMEMessageHeader);

            // Parse message based on template ID
            parse_message(packet_data.data() + offset, msg_header, pkt_header.sending_time);
            offset += msg_header.message_size;
        }
    }

    // void process_cme_packet(ZSTD_DStream* dstream, ifstream& input, size_t packet_size) {
    //     vector<char> packet_data(packet_size);
    //     size_t bytes_read = decompress_chunk(dstream, input, packet_data.data(), packet_size);
    //     if (bytes_read > 0) {
    //         process_cme_packet(packet_data);
    //     }
    // }

    // Parse message based on template ID
    void parse_message(const char* data, const CMEMessageHeader& header, uint64_t timestamp) {
        switch (header.template_id) {
            case 32: // Market Data Incremental Refresh
                parse_md_increment(data, header, timestamp);
                break;
            case 33: // Market Data Incremental Refresh - Order Book
                parse_md_order_book(data, header, timestamp);
                break;
            // Add other message types as needed
        }
    }

    // Parse Market Data Increment message
    void parse_md_increment(const char* data, const CMEMessageHeader& header, uint64_t timestamp) {
        // CME specific message structure for Market Data Incremental Refresh
        // Based on CME MDP 3.0 Market Data Increment Message Template
        // Based on Template ID 32
        struct MDIncrement {
            uint32_t security_id;   // Unique instrument identifier
            int64_t price;          // Price with implied decimal places
            uint32_t size;          // Order quantity
            char side;              // Side of order (1=Buy, 2=Sell)
            uint64_t order_id;      // Unique order identifier
            char action;            // Add/Modify/Delete (1=Add, 2=Modify, 3=Delete)
        } entry;

        memcpy(&entry, data, sizeof(MDIncrement));

        // Convert price from integer to decimal (price is stored as integer * 10000)
        double price = static_cast<double>(entry.price) / 10000.0;

        std::cout << "parsing market increment" << std::endl;

        // Write to CSV format
        output_file << timestamp << ","
                   << header.template_id << ","
                   << entry.security_id << ","
                   << price << ","
                   << entry.size << ","
                   << entry.side << ","
                   << entry.order_id << ","
                   << entry.action << "\n";
    }

    void parse_md_order_book(const char* data, const CMEMessageHeader& header, uint64_t timestamp) {
        // Similar to parse_md_increment but with order book specific fields
    }

    // size_t decompress_chunk(ZSTD_DStream* dstream, ifstream& input, char* output, size_t output_size) {
    //     vector<char> in_buffer(ZSTD_DStreamInSize());
    //     ZSTD_inBuffer input_buf = {in_buffer.data(), 0, 0};
    //     ZSTD_outBuffer output_buf = {output, output_size, 0};
    //
    //     while (output_buf.pos < output_buf.size) {
    //         if (input_buf.pos == input_buf.size) {
    //             input.read(in_buffer.data(), in_buffer.size());
    //             input_buf.size = input.gcount();
    //             input_buf.pos = 0;
    //             if (input_buf.size == 0) break;
    //         }
    //
    //         size_t ret = ZSTD_decompressStream(dstream, &output_buf, &input_buf);
    //         if (ZSTD_isError(ret)) {
    //             throw runtime_error(string("ZSTD decompression error: ") + ZSTD_getErrorName(ret));
    //         }
    //     }
    //
    //     return output_buf.pos;
    // }
};

int main() {
    try {
        // Use relative path from the executable location
        // C:/data/dev/OneTickPersonal/CMEDecoder/PCAPParser/data/dc3-glbx-a-20230716T110000.pcap
        string input_file = "C:/data/dev/OneTickPersonal/CMEDecoder/PCAPParser/data/dc3-glbx-a-20230716T110000.pcap";
        string output_file = "C:/data/dev/OneTickPersonal/CMEDecoder/PCAPParser/output/result.csv";

        DEBUG_PRINT("HEY!");



        // First check if file exists
        ifstream file_check(input_file, ios::binary);
        if (!file_check.good()) {
            cerr << "Error: Cannot open file: " << input_file << endl;
            cerr << "Current working directory might not be correct." << endl;
            return 1;
        }
        file_check.close();

        cout << "Found input file: " << input_file << endl;

        CMEParser parser(input_file, output_file);
        parser.parse();
        cout << "Parsing completed successfully" << endl;
    } catch (const exception& e) {
        cerr << "Error: " << e.what() << endl;
        return 1;
    }
    return 0;
}