//
// Created by hruks on 11/26/2024.
//


#include "src/tests/TestParser.h"
#include "src/exchanges/cme/CMEParser.h"
#include <vector>
#include <iostream>

int main() {
    try {

        // Set I/O
        string input_file = "C:/data/dev/OneTickPersonal/CMEDecoder/PCAPParser/data/dc3-glbx-a-20230716T110000.pcap";
        string output_file = "C:/data/dev/OneTickPersonal/CMEDecoder/PCAPParser/output/result.csv";

        // Specify allowed template IDs
        std::set<uint16_t> allowed_templates = {};

        // Specify custom header (OPTIONAL)
        std::vector<std::string> custom_header = {
            "PacketNumber", "Timestamp", "msgSeqNum", "sendingTime",
            "msgSize", "blockLength", "templateID", "schemaID", "version",
            "transactTime", "matchEventIndicator", "noMDEntries", "numInGroup",
            "highLimitPrice", "lowLimitPrice"
        };

        CMEParser parser(input_file, output_file, allowed_templates, custom_header);
        // parser.process_nth_packet(5);
        parser.process_packets(1000000, 10000);

        std::cout << std::endl;

        parser.print_message_statistics();

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
