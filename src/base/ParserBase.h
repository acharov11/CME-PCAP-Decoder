//
// Created by hruks on 11/26/2024.
//

#ifndef PARSERBASE_H
#define PARSERBASE_H

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
#include <set>
#include <map>
#include <type_traits>
#include <bitset>
#include <chrono>
// #include "tools/DebugUtil.h"
// #include "MKTData/MessageHeader.h"
#include "../utils/Logger.h"
#include "CSVBuilder.h"
#include "../../tools/DebugUtil.h"

using namespace std;

class ParserBase {

    // Go to Run | Edit Configurations.
    // Emulate terminal in the output console checkbox:
private:

    const int GLOBAL_HEADER_NUM_BYTES_ = 24;
    const int NUM_RAW_HEX_ROWS_PRINT_ = 5;
    const int FIELD_NAME_WIDTH_ = 25;  // Width for aligning field names
    const int VALUE_WIDTH_ = 30;      // Width for aligning field values
    const bool SHOW_BYTES_ = true;    // Toggle for showing byte representation
    const bool SPECIAL_FORMATTING_ = true; // Toggle for special formatting of uint8_t and int8_t

    const int EXTRA_BYTE_PADDING_ = 25;

    std::string format_timestamp(uint32_t ts_sec, uint32_t ts_usec);

protected:

    // PCAP Packet Header (16 bytes)
    struct PcapPacketHeader {
        uint32_t ts_sec;         // Timestamp seconds
        uint32_t ts_usec;        // Timestamp microseconds
        uint32_t incl_len;       // Number of octets of packet saved in file
        uint32_t orig_len;       // Actual length of packet
    };

    std::string input_file_;
    std::string output_file_;
    std::set<uint16_t> allowed_message_ids_;   // Allowed Message IDs / Allowed Template IDs
    std::map<uint16_t, size_t> message_count_; // Message ID / Template ID usage count
    CSVBuilder csv_builder_;

    Logger logger_;

    // Utility to extract fields from binary data
    template <typename T>
    T extract_field(const std::vector<uint8_t>& data, size_t& offset, const std::string& field_name) {
        if (offset + sizeof(T) > data.size()) {
            throw std::runtime_error("Not enough data to extract field: " + field_name);
        }

        T field;
        std::memcpy(&field, data.data() + offset, sizeof(T));

        if (logger_.is_level_enabled(Logger::EXTRACT_DEBUG)) {
            std::ostringstream debug_stream;

            // Align field names and values
            debug_stream << std::left << std::setw(FIELD_NAME_WIDTH_) << field_name << ": ";

            // Format the value with special formatting if enabled
            if (SPECIAL_FORMATTING_) {
                if constexpr (std::is_same_v<T, uint8_t> || std::is_same_v<T, int8_t>) {
                    debug_stream << "" << std::setw(VALUE_WIDTH_) << static_cast<int>(field)
                                 << std::setw(1) << "Bits: (" << std::bitset<8>(field) << ") ";
                // } else if constexpr (std::is_same_v<T, int64_t> || std::is_same_v<T, uint64_t>) {
                //     // Example for special formatting for larger integers
                //     debug_stream << std::setw(VALUE_WIDTH_) << field << " (Hex: 0x" << std::hex << field << std::dec << ")";
                } else {
                    debug_stream << std::setw(VALUE_WIDTH_) << field;
                }
            } else {
                debug_stream << std::setw(VALUE_WIDTH_) << field;
            }

            // Append byte representation
            if (SHOW_BYTES_) {
                // Align the overflowed lines with the value column
                const size_t alignment_column = FIELD_NAME_WIDTH_ + VALUE_WIDTH_ + EXTRA_BYTE_PADDING_; // Adjust for field and value width
                debug_stream << format_bytes(data, offset, sizeof(T), alignment_column);
            }

            logger_.extract_debug(debug_stream.str());
        }

        offset += sizeof(T);
        return field;
    }


    // Extract fixed-length strings
    std::string extract_fixed_length_string(size_t length, const std::vector<uint8_t>& data, size_t& offset, const std::string& field_name) {
        if (offset + length > data.size()) {
            throw std::runtime_error("Not enough data to extract string: " + field_name);
        }

        std::string result(reinterpret_cast<const char*>(data.data() + offset), length);

        std::ostringstream debug_stream;
        debug_stream << std::left << std::setw(FIELD_NAME_WIDTH_) << field_name << ": "
                     << std::setw(VALUE_WIDTH_) << result;
        // Append byte representation
        if (SHOW_BYTES_) {
            // Align the overflowed lines with the value column
            const size_t alignment_column = FIELD_NAME_WIDTH_ + VALUE_WIDTH_ + EXTRA_BYTE_PADDING_; // Adjust for field and value width
            debug_stream << format_bytes(data, offset, length, alignment_column);
        }

        logger_.extract_debug(debug_stream.str());
        offset += length;
        return result;
    }

    // Skip bytes
    void skip_bytes(size_t num_bytes, const std::vector<uint8_t>& data, size_t& offset, const std::string& reason = "") {
        if (offset + num_bytes > data.size()) {
            throw std::runtime_error("Not enough data to skip bytes");
        }

        std::ostringstream debug_stream;
        debug_stream << std::left << std::setw(FIELD_NAME_WIDTH_) << "Skip Bytes" << ": "
                     << std::setw(VALUE_WIDTH_) << num_bytes;
        if (!reason.empty()) {
            debug_stream << " Reason: " << reason;
        }

        logger_.extract_debug(debug_stream.str());
        offset += num_bytes;
    }

    std::string format_bytes(const std::vector<uint8_t>& data, size_t offset, size_t length, size_t alignment_column);

    // Helper to write a header to CSV
    void write_header(const std::vector<std::string>& custom_header);

    // Abstract methods for derived classes to implement
    virtual std::vector<std::string> parse_payload(const std::vector<uint8_t>& packet_data,
        size_t packet_number,
        const PcapPacketHeader& pcap_header) = 0;

public:
    ParserBase(const std::string& input_file,
        const std::string& output_file,
        const std::set<uint16_t>& allowed_messages = {},
        const std::vector<std::string>& custom_header = {},
        const std::string& log_file = "parser.log");
    virtual ~ParserBase() = default;

    // Main processing methods
    void process_packets(size_t total_packets, size_t batch_size, size_t start_packet = 1, size_t end_packet = 0);
    void process_nth_packet(size_t packet_number);

    // Information methods
    void print_message_statistics();
};



#endif //PARSERBASE_H
