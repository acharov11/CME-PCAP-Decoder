//
// Created by hruks on 11/26/2024.
//

#include "ParserBase.h"

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

    logger_.enable_level(Logger::INFO);
    // logger_.enable_level(Logger::DEBUG);
    // logger_.enable_level(Logger::EXTRACT_DEBUG);
    logger_.enable_level(Logger::ERROR);

    logger_.info("Logger initialized for ParserBase");
}

void ParserBase::write_header(const std::vector<std::string>& custom_header) {
    if (!custom_header.empty()) {
        csv_builder_.write_row(custom_header);
    } else {
        std::vector<std::string> default_header = { "PacketNumber", "Timestamp", "ExampleField1", "ExampleField2", "ExampleField3" };
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
            row.insert(row.begin(),{
                std::to_string(current_packet), // Packet num
                format_timestamp(pcap_header.ts_sec, pcap_header.ts_usec) // Time stamp
            });
            if (!row.empty()) {// Only add rows for allowed templates
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