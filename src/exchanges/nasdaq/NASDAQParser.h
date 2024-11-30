//
// Created by Anton Charov on 11/30/2024.
//

#ifndef NASDAQPARSER_H
#define NASDAQPARSER_H



#include "../../base/ParserBase.h"
#include "../../../src/base/CSVBuilder.h"
#include "NASDAQMessages.h"
#include <vector>
#include <string>


class NASDAQParser : public ParserBase {
private:

    struct NASDAQPacketHeader {
        // UPDATE WITH NASDAQ SETTINGS
        uint16_t pktSize;
        uint8_t deliveryFlag;
        uint8_t numberMsgs;
        uint32_t seqNum;
        uint32_t sendTime;
        uint32_t sendTimeNS;
    };

    struct NASDAQMessageHeader {
        // UPDATE WITH NASDAQ SETTINGS
        uint16_t msgSize;
        uint16_t msgType;
    };


public:
    NASDAQParser(const std::string& input_file, const std::string& output_file,
              const std::set<uint16_t>& allowed_messaeges = {},
              const std::vector<std::string>& custom_header = {});

    ~NASDAQParser() override = default;

protected:
    // Overrides from ParserBase
    std::vector<std::string> parse_payload(const std::vector<uint8_t>& packet_data,
        size_t packet_number,
        const PcapPacketHeader& pcap_header) override;
    std::vector<std::string> parse_by_message_id(uint16_t messageID, const std::vector<uint8_t>& data, size_t& offset);

    // NASDAQ-specific template parsers
    // Control Message Types
    std::vector<std::string> parse_message_1_sequenceNumberReset(const std::vector<uint8_t>& data, size_t& offset);


    // Add any additional MESSAGES here
};



#endif //NASDAQPARSER_H
