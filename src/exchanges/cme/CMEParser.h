//
// Created by hruks on 11/26/2024.
//

#ifndef CMEPARSER_H
#define CMEPARSER_H

#include "../../base/ParserBase.h"
#include "../../../src/base/CSVBuilder.h"
#include "CMEMessages.h"
#include <vector>
#include <string>


class CMEParser : public ParserBase {
private:
    struct TechnicalHeader {
        uint32_t msgSeqNum;
        uint64_t sendingTime;
    };

    struct CMEMessageHeader {
        uint16_t msgSize;
        uint16_t blockLength;
        uint16_t templateID;
        uint16_t schemaID;
        uint16_t version;
    };

    // std::set<uint16_t> allowed_template_ids_; // Allowed templates
    // std::map<uint16_t, size_t> template_count_; // Template statistics

public:
    CMEParser(const std::string& input_file, const std::string& output_file,
              const std::set<uint16_t>& allowed_messaeges = {},
              const std::vector<std::string>& custom_header = {});

    ~CMEParser() override = default;

protected:
    // Overrides from ParserBase
    std::vector<std::string> parse_payload(const std::vector<uint8_t>& packet_data,
        size_t packet_number,
        const PcapPacketHeader& pcap_header) override;
    std::vector<std::string> parse_by_template_id(uint16_t templateID, const std::vector<uint8_t>& data, size_t& offset);

    // CME-specific template parsers
    std::vector<std::string> parse_template_50(const std::vector<uint8_t>& data, size_t& offset);
    std::vector<std::string> parse_template_55(const std::vector<uint8_t>& data, size_t& offset);

    // Add any additional templates here
};




#endif //CMEPARSER_H
