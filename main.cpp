//
// Created by hruks on 11/26/2024.
//


#include "src/tests/TestParser.h"
#include "src/exchanges/cme/CMEParser.h"
#include <vector>
#include <iostream>

#include "src/exchanges/cboe/CBOEParser.h"
#include "src/exchanges/nasdaq/NASDAQParser.h"
#include "src/exchanges/nyse/NYSEParser.h"

#define INFO Logger::LogLevel::INFO
#define DEBUG Logger::LogLevel::DEBUG
#define WARNING Logger::LogLevel::WARNING
#define ERROR Logger::LogLevel::ERROR
#define FOCUS Logger::LogLevel::FOCUS
#define EXTRACT_DEBUG Logger::LogLevel::EXTRACT_DEBUG

int main() {
    try {
        cout << "C++ PCAP Parser runner starting...\n\n";

        // Set your inputs
        const string& NYSE_FILE_INPUT = "C:/data/dev/OneTickPersonal/CMEDecoder/PCAPParser/data/ny4-xchi-pillar-b-20230822T133000.pcap";
        const string& CME_FILE_INPUT = "C:/data/dev/OneTickPersonal/CMEDecoder/PCAPParser/data/dc3-glbx-a-20230716T110000.pcap";
        const string& NASDAQ_FILE_INPUT = "";
        const string& CBOE_FILE_INPUT = "";
        // Set your outputs
        const string& NYSE_FILE_OUTPUT = "C:/data/dev/OneTickPersonal/CMEDecoder/PCAPParser/src/exchanges/nyse/output/results.csv";
        const string& CME_FILE_OUTPUT = "C:/data/dev/OneTickPersonal/CMEDecoder/PCAPParser/src/exchanges/cme/output/results.csv";
        const string& NASDAQ_FILE_OUTPUT = "";
        const string& CBOE_FILE_OUTPUT = "";

        // Specify allowed template / message IDs -- empty means all enabled
        std::set<uint16_t> allowed_messages = {};

        // Specify custom header (OPTIONAL)
        std::vector<std::string> custom_header = {
            "PacketNumber", "Timestamp", "msgSeqNum", "sendingTime",
            "msgSize", "blockLength", "templateID", "schemaID", "version",
            "transactTime", "matchEventIndicator", "noMDEntries", "numInGroup",
            "highLimitPrice", "lowLimitPrice"
        };


        // Instantiate parser
        NYSEParser nyse_parser(NYSE_FILE_INPUT, NYSE_FILE_OUTPUT, allowed_messages, custom_header);
        nyse_parser.set_log_levels({INFO}); // possible {INFO, DEBUG, WARNING, ERROR, FOCUS, EXTRACT_DEBUG}
        CMEParser cme_parser(CME_FILE_INPUT, CME_FILE_OUTPUT, allowed_messages, custom_header);
        cme_parser.set_log_levels({INFO}); // possible {INFO, DEBUG, WARNING, ERROR, FOCUS, EXTRACT_DEBUG}
        // NASDAQParser nasdaq_parser(NASDAQ_FILE_INPUT, NASDAQ_FILE_OUTPUT, allowed_messages, custom_header);
        // nasdaq_parser.set_log_levels({INFO}); // possible {INFO, DEBUG, WARNING, ERROR, FOCUS, EXTRACT_DEBUG}
        // CBOEParser cboe_parser(CBOE_FILE_INPUT, CBOE_FILE_OUTPUT, allowed_messages, custom_header);
        // cboe_parser.set_log_levels({INFO}); // possible {INFO, DEBUG, WARNING, ERROR, FOCUS, EXTRACT_DEBUG}

        // Initial params
        constexpr size_t total_packets = 10000000;
        constexpr size_t batch_size = 25000;
        constexpr size_t start_packet = 1;
        constexpr size_t end_packet = 0;
        const size_t OPTIMAL_HARDWARE_THREAD_COUNT = std::thread::hardware_concurrency();
        const size_t num_threads = OPTIMAL_HARDWARE_THREAD_COUNT; // Adjust based on your system's capabilities

        // Input print
        cout << "\nUser has entered the following info: "
        << "\n" << "total_packets: " << total_packets
        << "\n" << "batch_size: " << batch_size
        << "\n" << "start_packet: " << start_packet
        << "\n" << "end_packet: " << end_packet
        << "\n" << "num_threads: " << num_threads
        << "\n" << "Recommended thread count: " << OPTIMAL_HARDWARE_THREAD_COUNT << "\n";

        // Single-threaded processing
        cout << "\nStarting single-threaded processing...";

        // RUN YOUR PREFFERED METHODS
        // nyse_parser.process_nth_packet(2);
        nyse_parser.process_packets(total_packets, batch_size, start_packet, end_packet);

        cme_parser.process_packets(total_packets, batch_size, start_packet, end_packet);




        // for NYSE look 589349, looks like a problem packet


        // Multi-threaded processing
        // logger.info("Starting multithreaded processing...");
        // parser.process_packets_multithreaded(total_packets, batch_size, start_packet, end_packet, num_threads);

        // Multi-threaded pool
        // parser.process_packets_with_thread_pool(total_packets, batch_size, start_packet, end_packet, num_threads);

        // parser.process_packets_with_priority_queue(total_packets, batch_size, start_packet, end_packet, num_threads);

        // parser.process_nth_packet(10);
        // parser.process_nth_packet(21);

    } catch (const std::exception& e) {
        std::cerr << "[ERROR] Exception: " << e.what() << std::endl;
    }

    return 0;
}
