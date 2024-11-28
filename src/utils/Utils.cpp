#include "Utils.h"

namespace Utils {

    std::vector<uint8_t> hex_string_to_vector(const std::string& hex_string) {
        std::vector<uint8_t> byte_vector;
        std::istringstream hex_stream(hex_string);
        std::string byte_str;

        while (hex_stream >> byte_str) {
            uint8_t byte = static_cast<uint8_t>(std::stoul(byte_str, nullptr, 16));
            byte_vector.push_back(byte);
        }

        return byte_vector;
    }

    std::string format_timestamp(uint32_t ts_sec, uint32_t ts_usec) {
        std::time_t raw_time = static_cast<std::time_t>(ts_sec);
        std::tm* timeinfo = std::gmtime(&raw_time);

        std::ostringstream oss;
        oss << std::setfill('0') << std::setw(2) << timeinfo->tm_hour << ":"
            << std::setw(2) << timeinfo->tm_min << ":"
            << std::setw(2) << timeinfo->tm_sec << "."
            << std::setw(6) << ts_usec;

        return oss.str();
    }

    std::string format_bytes(const std::vector<uint8_t>& data, size_t offset, size_t size) {
        std::ostringstream byte_stream;
        for (size_t i = offset; i < offset + size; ++i) {
            byte_stream << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(data[i]) << " ";
        }
        return byte_stream.str();
    }

    void print_bits(uint8_t value) {
        std::cout << "Bits: ";
        for (int i = 7; i >= 0; --i) {
            std::cout << ((value >> i) & 1);
        }
        std::cout << std::endl;
    }

    void print_uint8_info(uint8_t value) {
        std::cout << "Decimal: " << static_cast<int>(value)
                  << ", Hex: 0x" << std::hex << static_cast<int>(value)
                  << ", Bits: ";
        for (int i = 7; i >= 0; --i) {
            std::cout << ((value >> i) & 1);
        }
        std::cout << std::dec << std::endl;
    }

    void print_price_with_exponent(int64_t mantissa, int8_t exponent, const std::string& field_name) {
        if (mantissa == INT64_MAX) {
            std::cout << field_name << ": NULL" << std::endl;
            return;
        }
        double price = mantissa * std::pow(10, exponent);
        std::cout << field_name << ": " << price << std::endl;
    }

    template <typename T>
    void debug_field(const std::string& field_name, const T& value) {
        std::cout << std::left << std::setw(25) << field_name << ": " << value << std::endl;
    }

    void debug_field(const std::string& field_name, uint8_t value) {
        std::cout << std::left << std::setw(25) << field_name << ": "
                  << static_cast<int>(value) << " (0b" << std::bitset<8>(value) << ")" << std::endl;
    }

    void debug_field(const std::string& field_name, int8_t value) {
        std::cout << std::left << std::setw(25) << field_name << ": " << static_cast<int>(value) << std::endl;
    }

    void debug_field(const std::string& field_name, const std::string& value) {
        std::cout << std::left << std::setw(25) << field_name << ": " << value << std::endl;
    }

    void debug_price_with_exponent(const std::string& field_name, int64_t price, int8_t exponent) {
        double real_price = static_cast<double>(price) * std::pow(10, exponent);
        std::cout << std::left << std::setw(25) << field_name << ": " << price
                  << " (Exponent: " << static_cast<int>(exponent) << ", Real: " << real_price << ")" << std::endl;
    }

    void debug_string_with_bytes(const std::string& field_name, const std::string& value) {
        std::ostringstream byte_stream;
        for (unsigned char c : value) {
            byte_stream << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(c) << " ";
        }
        std::cout << std::left << std::setw(25) << field_name << ": " << value
                  << " [Bytes: " << byte_stream.str() << "]" << std::endl;
    }
}
