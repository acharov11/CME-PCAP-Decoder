//
// Created by hruks on 11/29/2024.
//

#ifndef NYSEPARSER_H
#define NYSEPARSER_H



#include "../../base/ParserBase.h"
#include "../../../src/base/CSVBuilder.h"
#include "NYSEMessages.h"
#include <vector>
#include <string>


class NYSEParser : public ParserBase {
private:

    struct NYSEPacketHeader {
        uint16_t pktSize;
        uint8_t deliveryFlag;
        uint8_t numberMsgs;
        uint32_t seqNum;
        uint32_t sendTime;
        uint32_t sendTimeNS;
    };

    struct NYSEMessageHeader {
        uint16_t msgSize;
        uint16_t msgType;
    };


    // std::set<uint16_t> allowed_template_ids_; // Allowed templates
    // std::map<uint16_t, size_t> template_count_; // Template statistics

public:
    NYSEParser(const std::string& input_file, const std::string& output_file,
              const std::set<uint16_t>& allowed_messaeges = {},
              const std::vector<std::string>& custom_header = {});

    ~NYSEParser() override = default;

protected:
    // Overrides from ParserBase
    std::vector<std::string> parse_payload(const std::vector<uint8_t>& packet_data,
        size_t packet_number,
        const PcapPacketHeader& pcap_header) override;
    std::vector<std::string> parse_by_message_id(uint16_t messageID, const std::vector<uint8_t>& data, size_t& offset);

    // NYSE-specific template parsers
    // Control Message Types
    std::vector<std::string> parse_message_1_sequenceNumberReset(const std::vector<uint8_t>& data, size_t& offset);
    std::vector<std::string> parse_message_2_timeReference(const std::vector<uint8_t>& data, size_t& offset);
    std::vector<std::string> parse_message_3_symbolIndexMapping(const std::vector<uint8_t>& data, size_t& offset);
    std::vector<std::string> parse_message_10_retransmissionRequest(const std::vector<uint8_t>& data, size_t& offset);
    std::vector<std::string> parse_message_11_requestResponse(const std::vector<uint8_t>& data, size_t& offset);
    std::vector<std::string> parse_message_12_heartbeatResponse(const std::vector<uint8_t>& data, size_t& offset);
    std::vector<std::string> parse_message_13_symbolIndexMappingRequest(const std::vector<uint8_t>& data, size_t& offset);
    std::vector<std::string> parse_message_15_refreshRequest(const std::vector<uint8_t>& data, size_t& offset);
    std::vector<std::string> parse_message_31_messageUnavailable(const std::vector<uint8_t>& data, size_t& offset);
    std::vector<std::string> parse_message_32_symbolClear(const std::vector<uint8_t>& data, size_t& offset);
    std::vector<std::string> parse_message_34_securityStatusMessage(const std::vector<uint8_t>& data, size_t& offset);
    std::vector<std::string> parse_message_35_refreshHeaderMessage(const std::vector<uint8_t>& data, size_t& offset);

    // Integrated Feed Message Types
    // NYSE Chicago hours: 6:30am - 8:00pm (messages 100,101,104,102,112,111,113,114,106)
    std::vector<std::string> parse_message_100_addOrderMessage(const std::vector<uint8_t>& data, size_t& offset);
    std::vector<std::string> parse_message_101_modifyOrderMessage(const std::vector<uint8_t>& data, size_t& offset);
    std::vector<std::string> parse_message_104_replaceOrderMessage(const std::vector<uint8_t>& data, size_t& offset);
    std::vector<std::string> parse_message_102_deleteOrderMessage(const std::vector<uint8_t>& data, size_t& offset);
    std::vector<std::string> parse_message_112_tradeCancelMessage(const std::vector<uint8_t>& data, size_t& offset);
    std::vector<std::string> parse_message_111_crossTradeMessage(const std::vector<uint8_t>& data, size_t& offset);
    std::vector<std::string> parse_message_113_crossCorrectionMessage(const std::vector<uint8_t>& data, size_t& offset);
    std::vector<std::string> parse_message_114_retailPriceImprovementMsg(const std::vector<uint8_t>& data, size_t& offset);
    std::vector<std::string> parse_message_106_addOrderRefreshMessage(const std::vector<uint8_t>& data, size_t& offset);
    // See Appendix A (105)
    std::vector<std::string> parse_message_105_imbalanceMessage(const std::vector<uint8_t>& data, size_t& offset);
    // NYSE Chicago 7:00am - 8:00pm (messages 103, 110, 223)
    std::vector<std::string> parse_message_103_orderExecutionMessage(const std::vector<uint8_t>& data, size_t& offset);
    std::vector<std::string> parse_message_110_nonDisplayedTradeMessage(const std::vector<uint8_t>& data, size_t& offset);
    std::vector<std::string> parse_message_223_stockSummaryMessage(const std::vector<uint8_t>& data, size_t& offset);

    // Add any additional templates here
};



#endif //NYSEPARSER_H
