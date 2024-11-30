//
// Created by hruks on 11/26/2024.
//

#include "ParserBase.h"

#include <unordered_map>

ParserBase::ParserBase(const std::string& input_file,
                       const std::string& output_file,
                       const std::set<uint16_t>& allowed_messages,
                       const std::vector<std::string>& custom_header,
                       const std::string& log_file)
    : input_file_(input_file),
    output_file_(output_file),
    allowed_message_ids_(allowed_messages),
    csv_builder_(output_file),
    logger_(false, log_file) {

    write_header(custom_header);

    // DEPRECATED: use new set_log_levels method
    // logger_.enable_level(Logger::INFO);
    // logger_.enable_level(Logger::DEBUG);
    // logger_.enable_level(Logger::EXTRACT_DEBUG);
    // logger_.enable_level(Logger::WARNING);
    // logger_.enable_level(Logger::ERROR);

    logger_.info("Logger initialized for ParserBase");
}

void ParserBase::write_header(const std::vector<std::string>& custom_header) {
    if (!custom_header.empty()) {
        csv_builder_.write_row(custom_header);
    } else {
        std::vector<std::string> default_header = CUSTOM_HEADER_;
        csv_builder_.write_row(default_header);
    }
}

void ParserBase::print_message_statistics() {
    ostringstream message_debug_stream;
    message_debug_stream << "Message Statistics\n";
    for (const auto& entry : message_count_) {
        message_debug_stream << "MessageID: " << entry.first << ", Count: " << entry.second << "\n";
    }
    logger_.info(message_debug_stream.str());
}

void ParserBase::process_packets(size_t total_packets, size_t batch_size, size_t start_packet, size_t end_packet) {
    // Start timing
    auto start_time = std::chrono::high_resolution_clock::now();

    cout << endl;
    logger_.info("process_packets: Processing " + std::to_string(total_packets) + " packets from " + std::to_string(start_packet) +
                 " to " + std::to_string(end_packet) + " in batches of " + std::to_string(batch_size));
    cout << endl;

    // Safety checks
    if(batch_size > total_packets) {
        throw std::runtime_error("Batch size of " + std::to_string(batch_size) + " is greater then " + std::to_string(total_packets) + " packets. Your batch size cannot be greater then your total packet count.");
    }
    if(batch_size < 1 || total_packets < 1) {
        throw std::runtime_error("Batch size and total packets cannot be less than 1.");
    }
    if(end_packet != 0 && end_packet < start_packet) {
        throw std::runtime_error("Your end packet number must be greater then your start packet number.");
    }


    std::ifstream input_file(input_file_, std::ios::binary);
    // Does the file even exist?
    if (!input_file.is_open()) {
        throw std::runtime_error("Unable to open input file: " + input_file_);
    }

    input_file.ignore(GLOBAL_HEADER_NUM_BYTES_); // Skip PCAP global header

    size_t current_packet = 1;
    size_t processed_packets = 0;
    size_t batches = 0;

    // Default 'end_packet' to the total number of packets if not specified
    if (end_packet == 0 || end_packet > total_packets) {
        end_packet = total_packets;
        if(end_packet < start_packet) {
            throw std::runtime_error("Your end packet number must be greater then your start packet number. In this case, "
                                     "it's likely that the total packets you set is lower than your end packet. The value"
                                     " of your end packet number must fit within the total packet range (e.g. 1000 -> (0 to 10000)");
        }
    }

    std::vector<std::vector<std::string>> batch_data;

    while (processed_packets < total_packets && current_packet <= end_packet) {
        // Read packet header
        PcapPacketHeader pcap_header;

        input_file.read(reinterpret_cast<char*>(&pcap_header), sizeof(PcapPacketHeader));
        if (input_file.eof()) break;

        // Skip out-of-range packets
        if (current_packet < start_packet) {
            input_file.ignore(pcap_header.incl_len);
            ++current_packet;
            continue;
        }

        // Read the N-th packet payload (up to incl_len bytes)
        std::vector<uint8_t> packet_data(pcap_header.incl_len);
        input_file.read(reinterpret_cast<char*>(packet_data.data()), pcap_header.incl_len);
        if (input_file.eof()) break;

        // Process packet
        try {
            std::vector<std::string> row = parse_payload(packet_data, current_packet, pcap_header);
            // add packet number and timestamp before packet -- packet metadata
            if (!row.empty()) {// Only add rows for allowed templates
                row.insert(row.begin(),{
                    std::to_string(current_packet), // Packet num
                    format_timestamp(pcap_header.ts_sec, pcap_header.ts_usec) // Time stamp
                });
                batch_data.push_back(row);
            }
        } catch (const std::exception& e) {
            logger_.error("Failed to process packet " + std::to_string(current_packet) + ": " + e.what());
        }

        // Write batch to CSV
        if (batch_data.size() >= batch_size) {
            ++batches;
            logger_.info("Finished batch number " + std::to_string(batches) + " and processed " + std::to_string(processed_packets+1) + " packets.");
            csv_builder_.write_rows(batch_data);
            batch_data.clear();
        }

        ++current_packet;
        ++processed_packets;
    }

    // Write remaining rows
    if (!batch_data.empty()) {
        logger_.info("Processing remaining " + std::to_string(batch_data.size()) + " packets.");
        csv_builder_.write_rows(batch_data);
    }

    input_file.close();
    cout << endl;


    // End timing
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = end_time - start_time;

    // Break down duration into hours, minutes, seconds, milliseconds, and nanoseconds
    auto hours = std::chrono::duration_cast<std::chrono::hours>(duration);
    duration -= hours;
    auto minutes = std::chrono::duration_cast<std::chrono::minutes>(duration);
    duration -= minutes;
    auto seconds = std::chrono::duration_cast<std::chrono::seconds>(duration);
    duration -= seconds;
    auto milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(duration);
    duration -= milliseconds;
    auto nanoseconds = std::chrono::duration_cast<std::chrono::nanoseconds>(duration);

    // Format the precise runtime string
    std::ostringstream time_stream;
    time_stream << std::setfill('0') << std::setw(2) << hours.count() << ":"
                << std::setw(2) << minutes.count() << ":"
                << std::setw(2) << seconds.count() << ":"
                << std::setw(3) << milliseconds.count() << "::"
                << std::setw(9) << nanoseconds.count();

    // Log duration
    logger_.info("Finished >>> Processed " + std::to_string(processed_packets) + " packets in " +
                 time_stream.str() + ".\n");

    print_message_statistics();
}


// Multithreaded process_packets method
void ParserBase::process_packets_multithreaded(
    size_t total_packets,
    size_t batch_size,
    size_t start_packet,
    size_t end_packet,
    size_t num_threads)
{
    auto start_time = std::chrono::high_resolution_clock::now();
    logger_.info("Starting multithreaded packet processing with " + std::to_string(num_threads) + " threads.");

    if (end_packet == 0 || end_packet > total_packets) {
        end_packet = total_packets;
    }

    if (batch_size > total_packets || batch_size < 1 || total_packets < 1) {
        throw std::runtime_error("Invalid batch size or total packet count.");
    }
    if (end_packet < start_packet) {
        throw std::runtime_error("End packet must be greater than or equal to start packet.");
    }

    size_t packets_per_thread = (end_packet - start_packet + 1) / num_threads;
    size_t remainder_packets = (end_packet - start_packet + 1) % num_threads;

    std::vector<std::thread> threads;
    std::mutex count_mutex;
    std::mutex csv_mutex;
    std::map<uint16_t, size_t> global_message_count;

    // Create a vector to store results from all threads
    std::vector<std::vector<std::vector<std::string>>> thread_results(num_threads);

    for (size_t i = 0; i < num_threads; ++i) {
        size_t thread_start_packet = start_packet + i * packets_per_thread + std::min(i, remainder_packets);
        size_t thread_end_packet = thread_start_packet + packets_per_thread - 1;
        if (i < remainder_packets) {
            thread_end_packet += 1;
        }

        threads.emplace_back([&, thread_start_packet, thread_end_packet, i]() {
            auto thread_start_time = std::chrono::high_resolution_clock::now();
            std::ifstream local_input_file(input_file_, std::ios::binary);
            if (!local_input_file.is_open()) {
                logger_.error("Thread " + std::to_string(i) + ": Unable to open input file.");
                return;
            }

            local_input_file.ignore(GLOBAL_HEADER_NUM_BYTES_);

            // Seek to starting packet
            size_t current_packet = 1;
            while (current_packet < thread_start_packet) {
                PcapPacketHeader pcap_header;
                local_input_file.read(reinterpret_cast<char*>(&pcap_header), sizeof(PcapPacketHeader));
                local_input_file.ignore(pcap_header.incl_len);
                ++current_packet;
            }

            std::map<uint16_t, size_t> local_message_count;
            size_t packets_processed = 0;

            // Store results in thread-local vector
            std::vector<std::vector<std::string>>& local_results = thread_results[i];

            while (current_packet <= thread_end_packet) {
                PcapPacketHeader pcap_header;
                local_input_file.read(reinterpret_cast<char*>(&pcap_header), sizeof(PcapPacketHeader));
                if (local_input_file.eof()) break;

                std::vector<uint8_t> packet_data(pcap_header.incl_len);
                local_input_file.read(reinterpret_cast<char*>(packet_data.data()), pcap_header.incl_len);
                if (local_input_file.eof()) break;

                try {
                    // Use actual packet number instead of thread-local counter
                    std::vector<std::string> row = parse_payload(packet_data, current_packet, pcap_header);
                    if (!row.empty()) {
                        local_results.push_back(row);
                        uint16_t templateID = std::stoi(row[4]);
                        local_message_count[templateID]++;
                    }
                } catch (const std::exception& e) {
                    logger_.error("Thread " + std::to_string(i) + " failed to process packet " +
                                std::to_string(current_packet) + ": " + e.what());
                }

                ++current_packet;
                ++packets_processed;
            }

            // Merge message counts under lock
            {
                std::lock_guard<std::mutex> lock(count_mutex);
                for (const auto& pair : local_message_count) {
                    global_message_count[pair.first] += pair.second;
                }
            }

            auto thread_end_time = std::chrono::high_resolution_clock::now();
            auto thread_duration = std::chrono::duration_cast<std::chrono::milliseconds>(
                thread_end_time - thread_start_time).count();

            logger_.info("Thread " + std::to_string(i) + " finished processing " +
                        std::to_string(packets_processed) + " packets in " +
                        std::to_string(thread_duration) + " ms.");
        });
    }

    // Wait for all threads to finish
    for (auto& thread : threads) {
        thread.join();
    }

    // Write results in correct order
    {
        std::lock_guard<std::mutex> lock(csv_mutex);
        for (size_t i = 0; i < num_threads; ++i) {
            csv_builder_.write_rows(thread_results[i]);
        }
    }

    // Log message counts
    logger_.info("MULTITHREADED: Global message count:");
    for (const auto& pair : global_message_count) {
        logger_.info("Message ID: " + std::to_string(pair.first) + " Count: " + std::to_string(pair.second));
    }

    // End timing
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = end_time - start_time;

    // Break down duration into hours, minutes, seconds, milliseconds, and nanoseconds
    auto hours = std::chrono::duration_cast<std::chrono::hours>(duration);
    duration -= hours;
    auto minutes = std::chrono::duration_cast<std::chrono::minutes>(duration);
    duration -= minutes;
    auto seconds = std::chrono::duration_cast<std::chrono::seconds>(duration);
    duration -= seconds;
    auto milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(duration);
    duration -= milliseconds;
    auto nanoseconds = std::chrono::duration_cast<std::chrono::nanoseconds>(duration);

    // Format the precise runtime string
    std::ostringstream time_stream;
    time_stream << std::setfill('0') << std::setw(2) << hours.count() << ":"
                << std::setw(2) << minutes.count() << ":"
                << std::setw(2) << seconds.count() << ":"
                << std::setw(3) << milliseconds.count() << "::"
                << std::setw(9) << nanoseconds.count();

    // Log duration
    logger_.info("Finished multithreaded processing >>> Processed " " packets in " +
                 time_stream.str() + ".\n");

    // logger_.info("Finished multithreaded processing in " + std::to_string(duration) + " ms.");
}

void ParserBase::process_packets_with_thread_pool(
    size_t total_packets,
    size_t batch_size,
    size_t start_packet,
    size_t end_packet,
    size_t num_threads)
{
    // Start overall timing
    auto start_time = std::chrono::high_resolution_clock::now();

    logger_.info("Starting thread-pool-based packet processing with " + std::to_string(num_threads) + " threads.");

    if (end_packet == 0 || end_packet > total_packets) {
        end_packet = total_packets;
    }

    // Safety checks
    if (batch_size > total_packets || batch_size < 1 || total_packets < 1) {
        throw std::runtime_error("Invalid batch size or total packet count.");
    }
    if (end_packet < start_packet) {
        throw std::runtime_error("End packet must be greater than or equal to start packet.");
    }

    // Split packet range among threads
    size_t packets_per_thread = (end_packet - start_packet + 1) / num_threads;
    size_t remainder_packets = (end_packet - start_packet + 1) % num_threads;

    // Thread-safe variables
    std::mutex csv_mutex;                               // Mutex for synchronized CSV writes
    std::mutex count_mutex;                             // Mutex for synchronized message counts
    std::map<uint16_t, size_t> global_message_count;    // Global message count
    std::vector<double> thread_times(num_threads);      // Time taken by each thread

    // Initialize thread pool
    ThreadPool pool(num_threads);

    // Enqueue work for each thread
    for (size_t i = 0; i < num_threads; ++i) {
        size_t thread_start_packet = start_packet + i * packets_per_thread + std::min(i, remainder_packets);
        size_t thread_end_packet = thread_start_packet + packets_per_thread - 1;
        if (i < remainder_packets) thread_end_packet += 1; // Distribute remainder packets

        // Enqueue tasks to the thread pool
        pool.enqueue([&, thread_start_packet, thread_end_packet, i]() {
            auto thread_start_time = std::chrono::high_resolution_clock::now();

            std::ifstream local_input_file(input_file_, std::ios::binary);
            if (!local_input_file.is_open()) {
                logger_.error("Thread " + std::to_string(i) + ": Unable to open input file.");
                return;
            }

            local_input_file.ignore(GLOBAL_HEADER_NUM_BYTES_);

            // Seek to the starting packet for this thread
            size_t current_packet = 1;
            while (current_packet < thread_start_packet) {
                PcapPacketHeader pcap_header;
                local_input_file.read(reinterpret_cast<char*>(&pcap_header), sizeof(PcapPacketHeader));
                local_input_file.ignore(pcap_header.incl_len);
                ++current_packet;
            }

            // Local results and message count
            std::vector<std::vector<std::string>> local_results;
            std::map<uint16_t, size_t> local_message_count;
            size_t packets_processed = 0;

            // Process packets for this thread
            while (current_packet <= thread_end_packet) {
                PcapPacketHeader pcap_header;
                local_input_file.read(reinterpret_cast<char*>(&pcap_header), sizeof(PcapPacketHeader));
                if (local_input_file.eof()) break;

                std::vector<uint8_t> packet_data(pcap_header.incl_len);
                local_input_file.read(reinterpret_cast<char*>(packet_data.data()), pcap_header.incl_len);
                if (local_input_file.eof()) break;

                try {
                    std::vector<std::string> row = parse_payload(packet_data, current_packet, pcap_header);
                    if (!row.empty()) {
                        local_results.push_back(row);

                        // Update local message count
                        uint16_t templateID = std::stoi(row[4]); // Assuming templateID is at index 4
                        local_message_count[templateID]++;
                    }
                } catch (const std::exception& e) {
                    logger_.error("Thread " + std::to_string(i) + " failed to process packet " + std::to_string(current_packet) + ": " + e.what());
                }

                ++current_packet;
                ++packets_processed;
            }
            // Write results to CSV (thread-safe)
            {
                std::lock_guard<std::mutex> lock(csv_mutex);
                csv_builder_.write_rows(local_results);
            }
            // Update global message count (thread-safe)
            {
                std::lock_guard<std::mutex> lock(count_mutex);
                for (const auto& pair : local_message_count) {
                    global_message_count[pair.first] += pair.second;
                }
            }

            auto thread_end_time = std::chrono::high_resolution_clock::now();
            thread_times[i] = std::chrono::duration<double>(thread_end_time - thread_start_time).count();

            logger_.info("Thread " + std::to_string(i) + " processed " + std::to_string(local_results.size()) +
                         " packets in " + std::to_string(thread_times[i]) + " seconds.");
        });
    }

    // Wait for all threads to complete (done by ThreadPool destructor)

    // The pool destructor will ensure all tasks complete before proceeding
    logger_.info("All threads completed.");

    // Log global message counts
    logger_.info("MULTITHREADED: Global message count:");
    for (const auto& pair : global_message_count) {
        logger_.info("Message ID: " + std::to_string(pair.first) + " Count: " + std::to_string(pair.second));
    }

    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();
    logger_.info("Finished thread-pool processing in " + std::to_string(duration) + " ms.");
}

void ParserBase::process_packets_with_priority_queue(
    size_t total_packets,
    size_t batch_size,
    size_t start_packet,
    size_t end_packet,
    size_t num_threads)
{
    // Start overall timing
    auto start_time = std::chrono::high_resolution_clock::now();

    logger_.info("Starting thread-pool-based packet processing with " + std::to_string(num_threads) + " threads.");

    if (end_packet == 0 || end_packet > total_packets) {
        end_packet = total_packets;
    }

    // Safety checks
    if (batch_size > total_packets || batch_size < 1 || total_packets < 1) {
        throw std::runtime_error("Invalid batch size or total packet count.");
    }
    if (end_packet < start_packet) {
        throw std::runtime_error("End packet must be greater than or equal to start packet.");
    }

    // Split packet range among threads
    size_t packets_per_thread = (end_packet - start_packet + 1) / num_threads;
    size_t remainder_packets = (end_packet - start_packet + 1) % num_threads;

    ThreadPool pool(num_threads);
    std::priority_queue<std::pair<size_t, std::vector<std::string>>, std::vector<std::pair<size_t, std::vector<std::string>>>, std::greater<>> result_queue;
    std::mutex queue_mutex;
    std::condition_variable queue_cv;
    bool done_parsing = false;

    // Writer thread
    std::thread writer_thread([&]() {
        std::ofstream csv_file(output_file_, std::ios::out | std::ios::trunc);
        if (!csv_file.is_open()) {
            throw std::runtime_error("Failed to open CSV file: " + output_file_);
        }

        while (true) {
            std::unique_lock<std::mutex> lock(queue_mutex);
            queue_cv.wait(lock, [&]() { return !result_queue.empty() || done_parsing; });

            while (!result_queue.empty()) {
                auto [packet_number, row] = result_queue.top();
                result_queue.pop();

                csv_builder_.write_row(csv_file, row);
            }

            if (done_parsing && result_queue.empty()) {
                break;
            }
        }

        csv_file.close();
    });

    // Parsing threads
    for (size_t i = 0; i < num_threads; ++i) {
        size_t thread_start_packet = start_packet + i * packets_per_thread + std::min(i, remainder_packets);
        size_t thread_end_packet = thread_start_packet + packets_per_thread - 1;
        if (i < remainder_packets) thread_end_packet += 1;

        pool.enqueue([&, thread_start_packet, thread_end_packet]() {
            std::ifstream local_input_file(input_file_, std::ios::binary);
            if (!local_input_file.is_open()) {
                logger_.error("Failed to open input file.");
                return;
            }

            local_input_file.ignore(GLOBAL_HEADER_NUM_BYTES_);

            // Seek to the starting packet for this thread
            size_t current_packet = 1;
            while (current_packet < thread_start_packet) {
                PcapPacketHeader pcap_header;
                local_input_file.read(reinterpret_cast<char*>(&pcap_header), sizeof(PcapPacketHeader));
                local_input_file.ignore(pcap_header.incl_len);
                ++current_packet;
            }

            while (current_packet <= thread_end_packet) {
                PcapPacketHeader pcap_header;
                local_input_file.read(reinterpret_cast<char*>(&pcap_header), sizeof(PcapPacketHeader));
                if (local_input_file.eof()) break;

                std::vector<uint8_t> packet_data(pcap_header.incl_len);
                local_input_file.read(reinterpret_cast<char*>(packet_data.data()), pcap_header.incl_len);
                if (local_input_file.eof()) break;

                try {
                    std::vector<std::string> row = parse_payload(packet_data, current_packet, pcap_header);
                    if (!row.empty()) {
                        std::lock_guard<std::mutex> lock(queue_mutex);
                        result_queue.emplace(current_packet, row);
                        queue_cv.notify_one();
                    }
                } catch (const std::exception& e) {
                    logger_.error("Failed to process packet " + std::to_string(current_packet) + ": " + e.what());
                }

                ++current_packet;
            }
        });
    }

    // Wait for parsing threads to finish
    pool.~ThreadPool();

    // Signal writer thread to finish
    {
        std::lock_guard<std::mutex> lock(queue_mutex);
        done_parsing = true;
        queue_cv.notify_one();
    }

    writer_thread.join();

    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();
    logger_.info("Finished thread-pool processing in " + std::to_string(duration) + " ms.");
}



void ParserBase::process_nth_packet(size_t packet_number) {
    cout << endl;
    logger_.info("Processing packet number " + std::to_string(packet_number) + "...");
    cout << endl;

    std::ifstream input_file(input_file_, std::ios::binary);
    // Does the file even exist?
    if (!input_file.is_open()) {
        throw std::runtime_error("Unable to open input file: " + input_file_);
    }

    input_file.ignore(GLOBAL_HEADER_NUM_BYTES_); // Skip PCAP global header

    PcapPacketHeader pcap_header;
    size_t current_packet = 1;
    while (current_packet < packet_number) {
        // Read the PCAP Packet Header
        input_file.read(reinterpret_cast<char*>(&pcap_header), sizeof(PcapPacketHeader));
        // Skip the packet data (incl_len bytes)
        input_file.ignore(pcap_header.incl_len);
        ++current_packet;
    }

    // Read the N-th packet header
    input_file.read(reinterpret_cast<char*>(&pcap_header), sizeof(PcapPacketHeader));
    if (input_file.eof()) {
        throw std::runtime_error("Reached end of file before finding packet " + std::to_string(packet_number));
    }

    // Convert timestamp to human-readable format
    std::string converted_time = format_timestamp(pcap_header.ts_sec, pcap_header.ts_usec);

    std::ostringstream header_debug_stream;
    header_debug_stream << "==== [" + std::to_string(packet_number) + "] Header General Info ====\n";
    header_debug_stream << "Timestamp: " + std::to_string(pcap_header.ts_sec) + "." + std::to_string(pcap_header.ts_usec) << endl;
    header_debug_stream << "Converted Timestamp: " + converted_time << endl;
    header_debug_stream << "Included Length: " + std::to_string(pcap_header.incl_len) + " bytes" << endl;
    logger_.debug(header_debug_stream.str());

    std::vector<uint8_t> packet_data(pcap_header.incl_len);
    input_file.read(reinterpret_cast<char*>(packet_data.data()), pcap_header.incl_len);
    if (input_file.eof()) {
        throw std::runtime_error("Reached end of file while reading packet data.");
    }

    std::vector<std::string> row = parse_payload(packet_data, packet_number, pcap_header);
    if (!row.empty()) {
        csv_builder_.write_row(row);
    }


    // Print the raw byte stream
    cout << endl;
    std::ostringstream debug_stream;
    debug_stream << "==== [" + std::to_string(packet_number) + "] Raw Byte Stream ====\n";
    const int NUM_ROWS_PRINT = NUM_RAW_HEX_ROWS_PRINT_;
    int row_printed_count = 0;

    for (size_t i = 0; i < packet_data.size(); ++i) {
        debug_stream << std::hex << std::setw(2) << std::setfill('0')
                  << static_cast<int>(packet_data[i]) << " ";
        if ((i + 1) % 16 == 0) {
            row_printed_count++;
            if(row_printed_count >= NUM_ROWS_PRINT) break;
            debug_stream << std::endl;
        }
    }
    debug_stream << std::dec << std::endl;
    logger_.debug(debug_stream.str());

    // Print row for debug
    std::ostringstream debug_stream_row;
    debug_stream_row << " ==== ROW PRINT [" << packet_number << "] ====" << std::endl;
    for (size_t i = 0; i < row.size(); ++i) {
        debug_stream_row << row[i];
        if (i < row.size() - 1)
            debug_stream_row << ",";
    }
    debug_stream_row << std::endl;
    logger_.debug(debug_stream_row.str());

    logger_.info("<<<< END: PACKET [" + std::to_string(packet_number) + "] END >>>>");

    input_file.close();
}

std::string ParserBase::format_timestamp(uint32_t ts_sec, uint32_t ts_usec) {
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

std::string ParserBase::format_bytes(const std::vector<uint8_t>& data, size_t offset, size_t length, size_t alignment_column) {
    std::ostringstream bytes_stream;

    const size_t bytes_per_line = 8; // Number of bytes per line before wrapping
    size_t current_line_length = 0;

    bytes_stream << "Bytes: ";
    for (size_t i = 0; i < length; ++i) {
        if (current_line_length == bytes_per_line) {
            // Start a new line and align properly
            bytes_stream << "\n" << std::string(alignment_column, ' ');
            current_line_length = 0;
        }

        bytes_stream << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data[offset + i]) << " ";
        current_line_length++;
    }

    return bytes_stream.str();
}