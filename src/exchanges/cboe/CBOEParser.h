//
// Created by hruks on 11/30/2024.
//

#ifndef CBOEPARSER_H
#define CBOEPARSER_H



#include "../../base/ParserBase.h"
#include "../../../src/base/CSVBuilder.h"
#include "CBOEMessages.h"
#include <vector>
#include <string>


class CBOEParser : public ParserBase {
private:

    struct CBOEPacketHeader {
        // UPDATE WITH CBOE SETTINGS
        uint16_t pktSize;
        uint8_t deliveryFlag;
        uint8_t numberMsgs;
        uint32_t seqNum;
        uint32_t sendTime;
        uint32_t sendTimeNS;
    };

    struct CBOEMessageHeader {
        // UPDATE WITH CBOE SETTINGS
        uint16_t msgSize;
        uint16_t msgType;
    };


public:
    CBOEParser(const std::string& input_file, const std::string& output_file,
              const std::set<uint16_t>& allowed_messaeges = {},
              const std::vector<std::string>& custom_header = {});

    ~CBOEParser() override = default;

protected:
    // Overrides from ParserBase
    std::vector<std::string> parse_payload(const std::vector<uint8_t>& packet_data,
        size_t packet_number,
        const PcapPacketHeader& pcap_header) override;
    std::vector<std::string> parse_by_message_id(uint16_t messageID, const std::vector<uint8_t>& data, size_t& offset);

    // CBOE-specific template parsers
    // Control Message Types
    std::vector<std::string> parse_message_1_sequenceNumberReset(const std::vector<uint8_t>& data, size_t& offset);


    // Add any additional MESSAGES here
};



#endif //CBOEPARSER_H
