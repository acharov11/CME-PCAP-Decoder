//
// Created by hruks on 11/26/2024.
//

#ifndef CMEMESSAGES_H
#define CMEMESSAGES_H

// #include <vector>
// #include <cstdint>
// #include <string>
// #include "../cme/CMEParser.h"
//
// // Define the namespace to avoid name collisions
// namespace CMEMessageTemplates {
//
//     // Template 50 parsing
//     std::vector<std::string> parse_template_50(const std::vector<uint8_t>& data, size_t& offset, ParserBase& parser) {
//         uint64_t transactTime = parser.extract_field<uint64_t>(data, offset, "transactTime");
//         uint8_t matchEventIndicator = parser.extract_field<uint8_t>(data, offset, "matchEventIndicator");
//
//         return {
//             std::to_string(transactTime),
//             std::to_string(matchEventIndicator)
//         };
//     }
//
//     // Template 55 parsing
//     std::vector<std::string> parse_template_55(const std::vector<uint8_t>& data, size_t& offset, ParserBase& parser) {
//         uint8_t matchEventIndicator = parser.extract_field<uint8_t>(data, offset, "matchEventIndicator");
//         uint32_t totNumReports = parser.extract_field<uint32_t>(data, offset, "totNumReports");
//         int8_t securityUpdateAction = parser.extract_field<int8_t>(data, offset, "securityUpdateAction");
//         uint64_t lastUpdateTime = parser.extract_field<uint64_t>(data, offset, "lastUpdateTime");
//
//         return {
//             std::to_string(matchEventIndicator),
//             std::to_string(totNumReports),
//             std::to_string(securityUpdateAction),
//             std::to_string(lastUpdateTime)
//         };
//     }
//
//     // Add other template parsers here, e.g., template_2, template_100, etc.
//
// }

#endif //CMEMESSAGES_H
