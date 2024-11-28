#ifndef UTILS_H
#define UTILS_H

#include <vector>
#include <string>
#include <cstdint>
#include <sstream>
#include <iomanip>
#include <iostream>
#include <bitset>
#include <cmath>
#include <ctime>

namespace Utils {

    std::vector<uint8_t> hex_string_to_vector(const std::string& hex_string);

    std::string format_timestamp(uint32_t ts_sec, uint32_t ts_usec);

    std::string format_bytes(const std::vector<uint8_t>& data, size_t offset, size_t size);

    void print_bits(uint8_t value);

    void print_uint8_info(uint8_t value);

    void print_price_with_exponent(int64_t mantissa, int8_t exponent, const std::string& field_name);

    template <typename T>
    void debug_field(const std::string& field_name, const T& value);

    void debug_field(const std::string& field_name, uint8_t value);

    void debug_field(const std::string& field_name, int8_t value);

    void debug_field(const std::string& field_name, const std::string& value);

    void debug_price_with_exponent(const std::string& field_name, int64_t price, int8_t exponent);

    void debug_string_with_bytes(const std::string& field_name, const std::string& value);

}

#endif // UTILS_H
