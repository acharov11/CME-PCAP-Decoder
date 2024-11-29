//
// Created by hruks on 11/26/2024.
//


#include "src/tests/TestParser.h"
#include "src/exchanges/cme/CMEParser.h"
#include <vector>
#include <iostream>

#include "src/exchanges/nyse/NYSEParser.h"

int main() {
    try {
        cout << ("C++ PCAP Parser runner starting...\n\n");

        const string& NYSE_FILE_INPUT = "C:/data/dev/OneTickPersonal/CMEDecoder/PCAPParser/data/ny4-xchi-pillar-b-20230822T133000.pcap";
        const string& CME_FILE_INPUT = "C:/data/dev/OneTickPersonal/CMEDecoder/PCAPParser/data/dc3-glbx-a-20230716T110000.pcap";

        const string& NYSE_FILE_OUTPUT = "C:/data/dev/OneTickPersonal/CMEDecoder/PCAPParser/src/exchanges/nyse/output/results.csv";

        // Set I/O
        string input_file = NYSE_FILE_INPUT;
        string output_file = NYSE_FILE_OUTPUT;

        // Specify allowed template IDs
        std::set<uint16_t> allowed_messages = {};

        // Specify custom header (OPTIONAL)
        std::vector<std::string> custom_header = {
            "PacketNumber", "Timestamp", "msgSeqNum", "sendingTime",
            "msgSize", "blockLength", "templateID", "schemaID", "version",
            "transactTime", "matchEventIndicator", "noMDEntries", "numInGroup",
            "highLimitPrice", "lowLimitPrice"
        };

        // ENABLE DEBUG LEVELS IN ParserBase.cpp CONSTRUCTOR
        NYSEParser parser(input_file, output_file, allowed_messages, custom_header);
        // parser.process_nth_packet(5);

        size_t total_packets = 10000000;
        size_t batch_size = 25000;
        size_t start_packet = 1;
        size_t end_packet = 10000000;
        const size_t OPTIMAL_HARDWARE_THREAD_COUNT = std::thread::hardware_concurrency();
        size_t num_threads = OPTIMAL_HARDWARE_THREAD_COUNT; // Adjust based on your system's capabilities

        // Input print
        std::ostringstream user_stream;
        cout << "\nUser has entered the following info: "
        << "\n" << "total_packets: " << total_packets
        << "\n" << "batch_size: " << batch_size
        << "\n" << "start_packet: " << start_packet
        << "\n" << "end_packet: " << end_packet
        << "\n" << "num_threads: " << num_threads
        << "\n" << "Recommended thread count: " << OPTIMAL_HARDWARE_THREAD_COUNT << "\n";

        // Single-threaded processing
        cout << ("\nStarting single-threaded processing...");
        // for NYSE look 589349, looks like a problem packet
        // parser.process_nth_packet(2); // NOTE DEBUG and EXTRACT_DEBUG need to be ENABLED in ParserBase.cpp constructor
        parser.process_packets(total_packets, batch_size, start_packet, end_packet);




        // Multi-threaded processing
        // logger.info("Starting multithreaded processing...");
        // parser.process_packets_multithreaded(total_packets, batch_size, start_packet, end_packet, num_threads);

        // Multi-threaded pool
        // parser.process_packets_with_thread_pool(total_packets, batch_size, start_packet, end_packet, num_threads);

        // parser.process_packets_with_priority_queue(total_packets, batch_size, start_packet, end_packet, num_threads);

        // // parser.process_nth_packet(10);
        // parser.process_nth_packet(21);

        // // Test CME Parser
        // CMEParser cme_parser("cme_output.csv");
        //
        // // Dummy CME packet
        // std::vector<uint8_t> dummy_cme_packet = {
        //     0x10, 0x00, 0x20, 0x00, 0x32, 0x00, // Header (Message Size, Block Length, Template ID)
        //     0x50, 0x06, 0x04, 0x03, 0x02, 0x01 // Payload
        // };
        //
        // cme_parser.parse_packet(dummy_cme_packet);
        // cme_parser.write_to_csv();
        //
        // // Test TestParser
        // TestParser test_parser("test_output.csv");
        //
        // // Dummy test packet
        // std::vector<uint8_t> dummy_test_packet = {
        //     0x01, 0x02, 0x03, 0x04, // Field1
        //     0x05, 0x06,             // Field2
        //     'H', 'e', 'l', 'l', 'o' // Field3
        // };
        //
        // test_parser.parse_packet(dummy_test_packet);
        // test_parser.write_to_csv();

    } catch (const std::exception& e) {
        std::cerr << "[ERROR] Exception: " << e.what() << std::endl;
    }

    return 0;
}
