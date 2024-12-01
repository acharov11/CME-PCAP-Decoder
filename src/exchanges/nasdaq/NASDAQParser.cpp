//
// Created by Anton Charov on 11/29/2024.
//

#include "NASDAQParser.h"

NASDAQParser::NASDAQParser(const std::string& input_file,
    const std::string& output_file,
    bool enable_full_writer,
    const std::string& prl_output_file,
    bool enable_prl_writer,
    const std::string& trd_output_file,
    bool enable_trd_writer,
    const std::set<uint16_t>& allowed_messages,
    const std::vector<std::string>& custom_header)
: ParserBase(input_file,
    output_file,
    enable_full_writer,
    prl_output_file,
    enable_prl_writer,
    trd_output_file,
    enable_trd_writer,
    allowed_messages,
    {        "PacketNumber", "Timestamp", "pktSize", "deliveryFlag",
    "numberMsgs", "seqNum", "sendTime", "sendTimeNS", "msgSize",
    "msgType", "sourceTimeNS", "symbolIndex", "symbolSeqNum",
    "orderID", "price", "volume","side","firmID","reserved"}
    ) {
    setBigEndian(true);
}

std::vector<std::string> NASDAQParser::parse_payload(const std::vector<uint8_t>& packet_data,
        size_t packet_number,
        const PcapPacketHeader& pcap_header) {

    std::vector<std::string> row;

    // Check for minimum packet size (46 bytes for payload)
    // @TODO; UPDATE WITH NASDAQ UDP SIZE (LOOK AT WIRESHARK, NEED TO SKIP BYTES BEFORE YOU GET TO ACTUAL DATA)
    const size_t UDP_HEADER_SIZE = 46;

    if (packet_data.size() < UDP_HEADER_SIZE) {
        std::cerr << "Packet too small, skipping.\n";
        row.push_back(std::to_string(packet_number)); // Packet number
        // row.push_back(format_timestamp(pcap_header.ts_sec, pcap_header.ts_usec)); // Timestamp
        row.insert(row.end(), 12, ""); // Fill the rest with blanks
        return row;
    }

    // Parse the packet (we have reached the UDP payload -- at byte 46)
    const std::vector<uint8_t>& payload_data = packet_data;


    size_t offset = UDP_HEADER_SIZE; // Start after Ethernet header

    // Parse general NASDAQ packet header
    NASDAQPacketHeader nasdaq_packet_header;
    nasdaq_packet_header.pktSize = extract_field<uint16_t>(payload_data, offset, "pktSize");
    nasdaq_packet_header.deliveryFlag = extract_field<uint8_t>(payload_data, offset, "deliveryFlag");
    nasdaq_packet_header.numberMsgs = extract_field<uint8_t>(payload_data, offset, "numberMsgs");
    nasdaq_packet_header.seqNum = extract_field<uint32_t>(payload_data, offset, "seqNum");
    nasdaq_packet_header.sendTime = extract_field<uint32_t>(payload_data, offset, "sendTime");
    nasdaq_packet_header.sendTimeNS = extract_field<uint32_t>(payload_data, offset, "sendTimeNS");

    // Parse common message specific header
    NASDAQMessageHeader nasdaq_message_header;
    nasdaq_message_header.msgSize = extract_field<uint16_t>(payload_data, offset, "msgSize");
    nasdaq_message_header.msgType = extract_field<uint16_t>(payload_data, offset, "msgType");

    const uint16_t& message_type = nasdaq_message_header.msgType;

    // Count occurrences of templateID / messageID
    message_count_[message_type]++;

    // Filter non-allowed template == message IDs
    if (!allowed_message_ids_.empty() && allowed_message_ids_.find(message_type) == allowed_message_ids_.end()) {
        logger_.debug("Skipping messageID: " + std::to_string(message_type));
        return {}; // Skip this template
    }

    // Build row with core fields
    row = {
        to_string(nasdaq_packet_header.pktSize),
        to_string(nasdaq_packet_header.deliveryFlag),
        to_string(nasdaq_packet_header.numberMsgs),
        to_string(nasdaq_packet_header.seqNum),
        to_string(nasdaq_packet_header.sendTime),
        to_string(nasdaq_packet_header.sendTimeNS),
        to_string(nasdaq_message_header.msgSize),
        to_string(message_type)
    };

    // Parse template-specific fields and append to row
    std::vector<std::string> additional_fields = parse_by_message_id(message_type, payload_data, offset);
    row.insert(row.end(), additional_fields.begin(), additional_fields.end());

    return row;
}

std::vector<std::string> NASDAQParser::parse_by_message_id(uint16_t messageID, const std::vector<uint8_t>& data, size_t& offset) {
    switch (messageID) {
        // Control messages...
        case 1:
            return parse_message_1_sequenceNumberReset(data, offset);
        default:
            return {}; // Unknown message ID
    }
}

// Control Message Types
std::vector<std::string> NASDAQParser::parse_message_1_sequenceNumberReset(const std::vector<uint8_t> &data,
    size_t &offset) {
    // Establish message 1 struct
    struct Message_1 {
        uint32_t sourceTime;
        uint32_t sourceTimeNS;
        uint8_t productID;
        uint8_t channelID;
    };

    // Instantiate struct
    Message_1 message_1;

    // Extract fields with extract_field, specify bytes of the field, pass in the data, offset, and name you would
    // like it to display in the debug
    message_1.sourceTime = extract_field<uint32_t>(data, offset,"sourceTime");
    message_1.sourceTimeNS = extract_field<uint32_t>(data, offset,"sourceTimeNS");
    message_1.productID = extract_field<uint32_t>(data, offset,"productID");
    message_1.channelID = extract_field<uint32_t>(data, offset,"channelID");

    // Maybe after extracing field clean up the struct, e.g. nulls, formatting, mantissa applications

    // Return row (this will be put into the CSV)
    return {
        to_string(message_1.sourceTime),
        to_string(message_1.sourceTimeNS),
        to_string(message_1.productID),
        to_string(message_1.channelID )
    };

}