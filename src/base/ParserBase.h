//
// Created by Anton Charov on 11/26/2024.
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
#include <atomic>
#include <thread>
#include <mutex>
#include "../utils/ThreadPool.h"
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


    const bool SAFE_MODE_PARSE_ = true;         // Should we throw an error if number of parsed bytes doesn't align with data type.
    const bool SAFE_MODE_ENDIAN_CONVERT_ = true;// Should we throw an error if we get a byte type we can't convert
    const int GLOBAL_HEADER_NUM_BYTES_ = 24;    // How many bytes to skip of the global heaader
    const int NUM_RAW_HEX_ROWS_PRINT_ = 5;      // How many rows to print for raw hex debug
    const int FIELD_NAME_WIDTH_ = 25;           // Width for aligning field names
    const int VALUE_WIDTH_ = 30;                // Width for aligning field values
    const bool SHOW_BYTES_ = true;              // Toggle for showing byte representation
    const bool SPECIAL_FORMATTING_ = true;      // Toggle for special formatting of uint8_t and int8_t
    const int EXTRA_BYTE_PADDING_ = 25;         // Width for aligning overflowing bytes

    bool BIG_ENDIAN_ = false;                   // Toggle big endian parsing for this parser class (set per child parser)

    std::string format_timestamp(uint32_t ts_sec, uint32_t ts_usec);


    static constexpr size_t average_packet_size_ = 1500; // Adjust based on your needs
    std::atomic<size_t> total_processed_packets_{0};

    std::vector<Logger::LogLevel> enabled_logging_levels_;

    const std::vector<std::string> PRL_HEADER_ = {
        "Packet Capture Time", "Send Time", "Message ID", "Raw Timestamp",
        "Tick Type", "Symbol", "Price", "Size", "Record Type", "Flag", "ASK"
    };

    const std::vector<std::string> TRD_HEADER_ = {
        "Packet Capture Time", "Send Time", "Message ID", "Raw Timestamp",
        "Tick Type", "Symbol", "Size", "Price", "Trade ID", "Sale Condition"
    };

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
    CSVBuilder prl_csv_builder_;
    CSVBuilder trd_csv_builder_;

    bool enable_full_writer_;
    bool enable_prl_writer_;
    bool enable_trd_writer_;

    // Used as default CSV header for X parser
    std::vector<std::string> CUSTOM_HEADER_ = {
        "PacketNumber", "Timestamp", "msgSeqNum", "sendingTime",
        "msgSize", "blockLength", "templateID", "schemaID", "version",
        "transactTime", "matchEventIndicator", "noMDEntries", "numInGroup",
        "highLimitPrice", "lowLimitPrice"
    };

    // Verify a message fits the PRL style
    bool is_prl_message(const std::string& symbol, uint32_t volume, char side) {
        // This logic could change
        return (symbol == "AAPL" || symbol == "MSFT") && volume > 0 && (side == 'B' || side == 'S');
    }

    // Method to handle PRL row construction and writing
    void add_to_prl(const std::string& packet_capture_time,
                const std::string& send_time,
                uint32_t message_id,
                const std::string& raw_timestamp,
                const std::string& tick_type,
                const std::string& symbol,
                double price,
                uint32_t size,
                const std::string& record_type,
                uint8_t flag,
                bool ask);

    // Method to handle TRD row construction and writing
    void add_to_trd(const std::string& packet_capture_time,
                const std::string& send_time,
                uint32_t message_id,
                const std::string& raw_timestamp,
                const std::string& tick_type,
                const std::string& symbol,
                uint32_t size,
                double price,
                uint32_t trade_id,
                const std::string& sale_condition);

    std::mutex csv_mutex; // Mutex for thread-safe CSV writing

    Logger logger_;

    // Updat endian type
    void setBigEndian(bool value) {
        BIG_ENDIAN_ = value;
    }

    // Endian conversion utility -- handles 2 byte, 4 byte, and 8 byte types
    // Note: strings don't apply since they are treated as a raw byte sequence
    // Supports both integral and floating-point types
    template <typename T>
    inline T convert_endianness(T value) noexcept {
        static_assert(std::is_arithmetic_v<T>, "Endianness conversion requires an arithmetic type");

        if constexpr (std::is_integral_v<T>) {
            // Handle integral types
            if constexpr (sizeof(T) == 1) {
                // No conversion needed for 1-byte types
                return value;
            } else if constexpr (sizeof(T) == 2) {
                return static_cast<T>((value >> 8) | (value << 8));
            } else if constexpr (sizeof(T) == 4) {
                return static_cast<T>(((value >> 24) & 0x000000FF) |
                                      ((value >> 8) & 0x0000FF00) |
                                      ((value << 8) & 0x00FF0000) |
                                      ((value << 24) & 0xFF000000));
            } else if constexpr (sizeof(T) == 8) {
                return static_cast<T>(((value >> 56) & 0x00000000000000FFULL) |
                                      ((value >> 40) & 0x000000000000FF00ULL) |
                                      ((value >> 24) & 0x0000000000FF0000ULL) |
                                      ((value >> 8)  & 0x00000000FF000000ULL) |
                                      ((value << 8)  & 0x000000FF00000000ULL) |
                                      ((value << 24) & 0x0000FF0000000000ULL) |
                                      ((value << 40) & 0x00FF000000000000ULL) |
                                      ((value << 56) & 0xFF00000000000000ULL));
            } else {
                if (SAFE_MODE_ENDIAN_CONVERT_)
                    throw std::runtime_error("Unsupported integral type for endianness conversion");
            }
        } else if constexpr (std::is_floating_point_v<T>) {
            // Handle floating-point types by reinterpreting as an integral type
            static_assert(sizeof(T) == 4 || sizeof(T) == 8, "Unsupported floating-point type size");
            using IntType = std::conditional_t<sizeof(T) == 4, uint32_t, uint64_t>;

            IntType int_value;
            std::memcpy(&int_value, &value, sizeof(T)); // Copy bytes from float/double to integer
            int_value = convert_endianness(int_value); // Swap bytes as an integer
            std::memcpy(&value, &int_value, sizeof(T)); // Copy bytes back to float/double
            return value;
        }
    }


    // Utility to extract fields from binary data
    template <typename T>
    T extract_field(const std::vector<uint8_t>& data, size_t& offset, const std::string& field_name) {
        // Check for enough data
        if (offset + sizeof(T) > data.size()) {
            if(SAFE_MODE_PARSE_)
                throw std::runtime_error("Not enough data to extract field: " + field_name);
        }

        // Directly read the field using pointer arithmetic
        const T* field_ptr = reinterpret_cast<const T*>(&data[offset]);
        T field = *field_ptr; // Dereference to get the value

        // Handle endianness if necessary
        if (BIG_ENDIAN_ && sizeof(T) > 1) { // Only apply to multi-byte fields
            field = convert_endianness(field);
        }

        // Move the offset forward
        offset += sizeof(T);

        // Only log if EXTRACT_DEBUG is enabled
        if (logger_.is_level_enabled(Logger::EXTRACT_DEBUG)) {
            std::ostringstream debug_stream;

            // Align field names and values
            debug_stream << std::left << std::setw(FIELD_NAME_WIDTH_) << field_name << ": ";

            // Format the value with special formatting if enabled
            if (SPECIAL_FORMATTING_) {
                if constexpr (std::is_same_v<T, uint8_t> || std::is_same_v<T, int8_t>) {
                    debug_stream << std::setw(VALUE_WIDTH_) << static_cast<int>(field)
                                 << " (Bits: " << std::bitset<8>(field) << ")";
                } else {
                    debug_stream << std::setw(VALUE_WIDTH_) << field;
                }
            } else {
                debug_stream << std::setw(VALUE_WIDTH_) << field;
            }

            // Append byte representation if enabled
            if (SHOW_BYTES_) {
                const size_t alignment_column = FIELD_NAME_WIDTH_ + VALUE_WIDTH_ + EXTRA_BYTE_PADDING_;
                debug_stream << format_bytes(data, offset - sizeof(T), sizeof(T), alignment_column);
            }

            // Log the debug information
            logger_.extract_debug(debug_stream.str());
        }

        return field;
    }



    // Extract fixed-length strings
    std::string extract_fixed_length_string(size_t length, const std::vector<uint8_t>& data, size_t& offset, const std::string& field_name) {
        // Check for enough data
        if (offset + length > data.size()) {
            throw std::runtime_error("Not enough data to extract string: " + field_name);
        }

        // Directly create the string from the range
        std::string result(reinterpret_cast<const char*>(&data[offset]), length);

        // Move the offset forward
        offset += length;

        // Log if EXTRACT_DEBUG is enabled
        if (logger_.is_level_enabled(Logger::EXTRACT_DEBUG)) {
            std::ostringstream debug_stream;
            debug_stream << std::left << std::setw(FIELD_NAME_WIDTH_) << field_name << ": "
                         << std::setw(VALUE_WIDTH_) << result;

            if (SHOW_BYTES_) {
                const size_t alignment_column = FIELD_NAME_WIDTH_ + VALUE_WIDTH_ + EXTRA_BYTE_PADDING_;
                debug_stream << format_bytes(data, offset - length, length, alignment_column);
            }

            logger_.extract_debug(debug_stream.str());
        }

        return result;
    }

    // Skip bytes
    void skip_bytes(size_t num_bytes, const std::vector<uint8_t>& data, size_t& offset, const std::string& reason = "") {
        // Check for enough data
        if (offset + num_bytes > data.size()) {
            throw std::runtime_error("Not enough data to skip bytes");
        }

        // Log the skip operation if EXTRACT_DEBUG is enabled
        if (logger_.is_level_enabled(Logger::EXTRACT_DEBUG)) {
            std::ostringstream debug_stream;
            debug_stream << std::left << std::setw(FIELD_NAME_WIDTH_) << "Skip Bytes" << ": "
                         << std::setw(VALUE_WIDTH_) << num_bytes;
            if (!reason.empty()) {
                debug_stream << " Reason: " << reason;
            }
            logger_.extract_debug(debug_stream.str());
        }

        // Move the offset forward
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
        bool enable_full_writer = true,
        const std::string& prl_output_file = "results_PRL.csv",
        bool enable_prl_writer = true,
        const std::string& trd_output_file = "results_TRD.csv",
        bool enable_trd_writer = true,
        const std::set<uint16_t>& allowed_messages = {},
        const std::vector<std::string>& custom_header = {},
        const std::string& log_file = "parser.log");
    virtual ~ParserBase() = default;

    // Main processing methods
    void process_packets(size_t total_packets, size_t batch_size, size_t start_packet = 1, size_t end_packet = 0);
    void process_nth_packet(size_t packet_number);

    // Multithreaded-processing
    void process_packets_multithreaded(
    size_t total_packets,
    size_t batch_size,
    size_t start_packet,
    size_t end_packet,
    size_t num_threads);

    // Multithreaded-pool processing
    void process_packets_with_thread_pool(
    size_t total_packets,
    size_t batch_size,
    size_t start_packet,
    size_t end_packet,
    size_t num_threads);

    void process_packets_with_priority_queue(
    size_t total_packets,
    size_t batch_size,
    size_t start_packet,
    size_t end_packet,
    size_t num_threads);

    // Information methods
    void print_message_statistics();

    // Logging methods
    void set_log_levels(const std::vector<Logger::LogLevel>& levels) {
        enabled_logging_levels_ = levels;
        for(const auto& level : enabled_logging_levels_) {
            logger_.enable_level(level);
        }
    }
};



#endif //PARSERBASE_H
