//
// Created by hruks on 11/26/2024.
//

#ifndef TESTPARSER_H
#define TESTPARSER_H

// #include "../base/ParserBase.h"
// #include "../base/CSVBuilder.h"
// #include <vector>
// #include <iostream>
//
// // Example implementation of ParserBase
// class TestParser : public ParserBase {
// private:
//     CSVBuilder csv_builder_;
//     std::vector<std::string> parsed_data_;
//
// public:
//     explicit TestParser(const std::string& output_file)
//         : csv_builder_(output_file) {
//         csv_builder_.write_header({"Field1", "Field2", "Field3"});
//     }
//
//     // Parse a dummy packet
//     void parse_packet(const std::vector<uint8_t>& data) override {
//         size_t offset = 0;
//         try {
//             uint32_t field1 = extract_field<uint32_t>(data, offset, "Field1");
//             uint16_t field2 = extract_field<uint16_t>(data, offset, "Field2");
//             std::string field3 = extract_fixed_length_string(5, data, offset, "Field3");
//
//             // Store parsed data
//             parsed_data_ = {std::to_string(field1), std::to_string(field2), field3};
//         } catch (const std::exception& e) {
//             std::cerr << "[ERROR] Parsing failed: " << e.what() << std::endl;
//         }
//     }
//
//     // Write parsed data to CSV
//     void write_to_csv() override {
//         if (parsed_data_.empty()) {
//             std::cerr << "[INFO] No data to write." << std::endl;
//             return;
//         }
//
//         csv_builder_.write_row(parsed_data_);
//     }
// };


#endif //TESTPARSER_H
