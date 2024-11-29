//
// Created by hruks on 11/29/2024.
//

#include "NYSEParser.h"

NYSEParser::NYSEParser(const std::string& input_file, const std::string& output_file, const std::set<uint16_t>& allowed_messages, const std::vector<std::string>& custom_header)
: ParserBase(input_file,
    output_file,
    allowed_messages,
    {        "PacketNumber", "Timestamp", "pktSize", "deliveryFlag",
    "numberMsgs", "seqNum", "sendTime", "sendTimeNS", "msgSize",
    "msgType", "sourceTimeNS", "symbolIndex", "symbolSeqNum",
    "orderID", "price", "volume","side","firmID","reserved"}
    ) {
}

std::vector<std::string> NYSEParser::parse_payload(const std::vector<uint8_t>& packet_data,
        size_t packet_number,
        const PcapPacketHeader& pcap_header) {

    std::vector<std::string> row;

    // Check for minimum packet size (46 bytes for payload)
    if (packet_data.size() < 46) {
        std::cerr << "Packet too small, skipping.\n";
        row.push_back(std::to_string(packet_number)); // Packet number
        // row.push_back(format_timestamp(pcap_header.ts_sec, pcap_header.ts_usec)); // Timestamp
        row.insert(row.end(), 12, ""); // Fill the rest with blanks
        return row;
    }

    // Parse the packet (we have reached the UDP payload -- at byte 46)
    const std::vector<uint8_t>& payload_data = packet_data;


    size_t offset = 46; // Start after Ethernet header

    // Parse general NYSE packet header
    NYSEPacketHeader nyse_packet_header;
    nyse_packet_header.pktSize = extract_field<uint16_t>(payload_data, offset, "pktSize");
    nyse_packet_header.deliveryFlag = extract_field<uint8_t>(payload_data, offset, "deliveryFlag");
    nyse_packet_header.numberMsgs = extract_field<uint8_t>(payload_data, offset, "numberMsgs");
    nyse_packet_header.seqNum = extract_field<uint32_t>(payload_data, offset, "seqNum");
    nyse_packet_header.sendTime = extract_field<uint32_t>(payload_data, offset, "sendTime");
    nyse_packet_header.sendTimeNS = extract_field<uint32_t>(payload_data, offset, "sendTimeNS");

    // Parse common message specific header
    NYSEMessageHeader nyse_message_header;
    nyse_message_header.msgSize = extract_field<uint16_t>(payload_data, offset, "msgSize");
    nyse_message_header.msgType = extract_field<uint16_t>(payload_data, offset, "msgType");

    const uint16_t& message_type = nyse_message_header.msgType;

    // Count occurrences of templateID / messageID
    message_count_[message_type]++;

    // Filter non-allowed template == message IDs
    if (!allowed_message_ids_.empty() && allowed_message_ids_.find(message_type) == allowed_message_ids_.end()) {
        logger_.debug("Skipping messageID: " + std::to_string(message_type));
        return {}; // Skip this template
    }

    // Build row with core fields
    row = {
        to_string(nyse_packet_header.pktSize),
        to_string(nyse_packet_header.deliveryFlag),
        to_string(nyse_packet_header.numberMsgs),
        to_string(nyse_packet_header.seqNum),
        to_string(nyse_packet_header.sendTime),
        to_string(nyse_packet_header.sendTimeNS),
        to_string(nyse_message_header.msgSize),
        to_string(message_type)
    };

    // Parse template-specific fields and append to row
    std::vector<std::string> additional_fields = parse_by_message_id(message_type, payload_data, offset);
    row.insert(row.end(), additional_fields.begin(), additional_fields.end());

    return row;
}

std::vector<std::string> NYSEParser::parse_by_message_id(uint16_t messageID, const std::vector<uint8_t>& data, size_t& offset) {
    switch (messageID) {
        // Control messages...
        case 1:
            return parse_message_1_sequenceNumberReset(data, offset);
        case 2:
            return parse_message_2_timeReference(data, offset);
        case 3:
            return parse_message_3_symbolIndexMapping(data, offset);
        case 10:
            return parse_message_10_retransmissionRequest(data, offset);
        case 11:
            return parse_message_11_requestResponse(data, offset);
        case 12:
            return parse_message_12_heartbeatResponse(data, offset);
        case 13:
            return parse_message_13_symbolIndexMappingRequest(data, offset);
        case 15:
            return parse_message_15_refreshRequest(data, offset);
        case 31:
            return parse_message_31_messageUnavailable(data, offset);
        case 32:
            return parse_message_32_symbolClear(data, offset);
        case 34:
            return parse_message_34_securityStatusMessage(data, offset);
        case 35:
            return parse_message_35_refreshHeaderMessage(data, offset);
        // Integrated feed...
        case 100:
            return parse_message_100_addOrderMessage(data, offset);
        case 101:
            return parse_message_101_modifyOrderMessage(data, offset);
        case 104:
            return parse_message_104_replaceOrderMessage(data, offset);
        case 102:
            return parse_message_102_deleteOrderMessage(data, offset);
        case 112:
            return parse_message_112_tradeCancelMessage(data, offset);
        case 111:
            return parse_message_111_crossTradeMessage(data, offset);
        case 113:
            return parse_message_113_crossCorrectionMessage(data, offset);
        case 114:
            return parse_message_114_retailPriceImprovementMsg(data, offset);
        case 106:
            return parse_message_106_addOrderRefreshMessage(data, offset);
        case 105:
            return parse_message_105_imbalanceMessage(data, offset);
        case 103:
            return parse_message_103_orderExecutionMessage(data, offset);
        case 110:
            return parse_message_110_nonDisplayedTradeMessage(data, offset);
        case 223:
            return parse_message_223_stockSummaryMessage(data, offset);
        default:
            return {}; // Unknown template ID
    }
}

// Control Message Types
std::vector<std::string> NYSEParser::parse_message_1_sequenceNumberReset(const std::vector<uint8_t> &data,
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

std::vector<std::string> NYSEParser::parse_message_2_timeReference(const std::vector<uint8_t> &data, size_t &offset) {
    // Define the struct for message 2
    struct Message_2 {
        uint32_t id;             // ID of the originating Matching Engine partition
        uint32_t symbolSeqNum;   // Reserved for future use
        uint32_t sourceTime;     // Time when the message was generated
    };

    // Instantiate the message struct
    Message_2 message_2;

    // Extract fields using extract_field
    message_2.id = extract_field<uint32_t>(data, offset, "id");
    message_2.symbolSeqNum = extract_field<uint32_t>(data, offset, "symbolSeqNum");
    message_2.sourceTime = extract_field<uint32_t>(data, offset, "sourceTime");

    // Prepare the row to be returned
    return {
        std::to_string(message_2.id),
        std::to_string(message_2.symbolSeqNum), // Ignored but logged for consistency
        std::to_string(message_2.sourceTime)
    };
}

std::vector<std::string> NYSEParser::parse_message_3_symbolIndexMapping(const std::vector<uint8_t> &data,
    size_t &offset) {
    // Define the structure for the message
    struct Message_3 {
        uint32_t symbolIndex;      // Unique ID of the symbol
        char symbol[11];           // Null-terminated ASCII symbol
        uint8_t reserved;          // Reserved for future use
        uint16_t marketId;         // Originating Market ID
        uint8_t systemId;          // Matching engine server ID
        char exchangeCode;         // Market where the symbol is listed
        uint8_t priceScaleCode;    // Placement of decimal point in price fields
        char securityType;         // Security type
        uint16_t lotSize;          // Round lot size in shares
        uint32_t prevClosePrice;   // Previous day's closing price
        uint32_t prevCloseVolume;  // Previous day's closing volume
        uint8_t priceResolution;   // Price resolution (e.g., penny/nickel)
        char roundLot;             // 'Y' or 'N' for round lots accepted
        uint16_t mpv;              // Minimum price variation
        uint16_t unitOfTrade;      // Unit of trade in shares
        uint16_t reserved2;        // Reserved for future use
    };

    // Create an instance of the message structure
    Message_3 message;

    // Extract fields using utility functions
    message.symbolIndex = extract_field<uint32_t>(data, offset, "symbolIndex");
    std::string symbol = extract_fixed_length_string(11, data, offset,"symbol"); // Handles null-terminated ASCII
    message.reserved = extract_field<uint8_t>(data, offset, "reserved");
    message.marketId = extract_field<uint16_t>(data, offset, "marketId");
    message.systemId = extract_field<uint8_t>(data, offset, "systemId");
    message.exchangeCode = extract_field<char>(data, offset, "exchangeCode");
    message.priceScaleCode = extract_field<uint8_t>(data, offset, "priceScaleCode");
    message.securityType = extract_field<char>(data, offset, "securityType");
    message.lotSize = extract_field<uint16_t>(data, offset, "lotSize");
    message.prevClosePrice = extract_field<uint32_t>(data, offset, "prevClosePrice");
    message.prevCloseVolume = extract_field<uint32_t>(data, offset, "prevCloseVolume");
    message.priceResolution = extract_field<uint8_t>(data, offset, "priceResolution");
    message.roundLot = extract_field<char>(data, offset, "roundLot");
    message.mpv = extract_field<uint16_t>(data, offset, "mpv");
    message.unitOfTrade = extract_field<uint16_t>(data, offset, "unitOfTrade");
    message.reserved2 = extract_field<uint16_t>(data, offset, "reserved2");

    // Build and return the row to insert into the CSV
    return {
        std::to_string(message.symbolIndex),
        symbol, // Convert char array to string
        std::to_string(message.reserved),
        std::to_string(message.marketId),
        std::to_string(message.systemId),
        std::string(1, message.exchangeCode), // Convert char to string
        std::to_string(message.priceScaleCode),
        std::string(1, message.securityType),
        std::to_string(message.lotSize),
        std::to_string(message.prevClosePrice),
        std::to_string(message.prevCloseVolume),
        std::to_string(message.priceResolution),
        std::string(1, message.roundLot),
        std::to_string(message.mpv),
        std::to_string(message.unitOfTrade),
        std::to_string(message.reserved2)
    };
}

std::vector<std::string> NYSEParser::parse_message_10_retransmissionRequest(const std::vector<uint8_t> &data,
    size_t &offset) {
    // Define the structure for the message
    struct Message_10 {
        uint16_t msgSize;             // Size of the message
        uint16_t msgType;             // Message type (10 for Retransmission Request)
        uint32_t beginSeqNum;         // Beginning sequence number
        uint32_t endSeqNum;           // End sequence number
        char sourceID[10];            // Client requesting retransmission (ASCII, null-padded)
        uint8_t productID;            // Product ID
        uint8_t channelID;            // Channel ID
    };

    // Create an instance of the message structure
    Message_10 message;

    // Extract fields using utility functions
    message.msgSize = extract_field<uint16_t>(data, offset, "msgSize");
    message.msgType = extract_field<uint16_t>(data, offset, "msgType");
    message.beginSeqNum = extract_field<uint32_t>(data, offset, "beginSeqNum");
    message.endSeqNum = extract_field<uint32_t>(data, offset, "endSeqNum");
    std::string sourceID = extract_fixed_length_string(10, data, offset, "sourceID");
    message.productID = extract_field<uint8_t>(data, offset, "productID");
    message.channelID = extract_field<uint8_t>(data, offset, "channelID");

    // Build and return the row to insert into the CSV
    return {
        std::to_string(message.msgSize),
        std::to_string(message.msgType),
        std::to_string(message.beginSeqNum),
        std::to_string(message.endSeqNum),
        sourceID,
        std::to_string(message.productID),
        std::to_string(message.channelID)
    };
}

std::vector<std::string> NYSEParser::
parse_message_11_requestResponse(const std::vector<uint8_t> &data, size_t &offset) {
    // Define the structure for the Request Response Message
    struct Message_11 {
        uint16_t msgSize;          // Size of the message (29 bytes)
        uint16_t msgType;          // The type of message (11)
        uint32_t requestSeqNum;    // Sequence number of the client request
        uint32_t beginSeqNum;      // Beginning sequence number of retransmission range (or 0)
        uint32_t endSeqNum;        // Ending sequence number of retransmission range (or 0)
        char sourceID[10];         // Client ID requesting retransmission (NULL-padded)
        uint8_t productID;         // Feed ID for the request
        uint8_t channelID;         // Multicast channel ID for the request
        char status;               // Status of the response
    };

    // Create an instance of the message structure
    Message_11 message;

    // Extract fields using utility functions
    message.msgSize = extract_field<uint16_t>(data, offset, "msgSize");
    message.msgType = extract_field<uint16_t>(data, offset, "msgType");
    message.requestSeqNum = extract_field<uint32_t>(data, offset, "requestSeqNum");
    message.beginSeqNum = extract_field<uint32_t>(data, offset, "beginSeqNum");
    message.endSeqNum = extract_field<uint32_t>(data, offset, "endSeqNum");
    string sourceID = extract_fixed_length_string(10, data, offset, "sourceID");
    message.productID = extract_field<uint8_t>(data, offset, "productID");
    message.channelID = extract_field<uint8_t>(data, offset, "channelID");
    message.status = extract_field<char>(data, offset, "status");

    // Build and return the row to insert into the CSV
    return {
        std::to_string(message.msgSize),
        std::to_string(message.msgType),
        std::to_string(message.requestSeqNum),
        std::to_string(message.beginSeqNum),
        std::to_string(message.endSeqNum),
        sourceID, // Convert char array to string
        std::to_string(message.productID),
        std::to_string(message.channelID),
        std::to_string(static_cast<int>(message.status)) // Convert char status to int string
    };
}

std::vector<std::string> NYSEParser::parse_message_12_heartbeatResponse(const std::vector<uint8_t> &data,
    size_t &offset) {
    // Define the structure for the Heartbeat Response Message
    struct Message_12 {
        uint16_t msgSize;       // Size of the message (14 bytes)
        uint16_t msgType;       // The type of message (12)
        char sourceID[10];      // Client ID (ASCII, NULL-padded)
    };

    // Create an instance of the message structure
    Message_12 message;

    // Extract fields using utility functions
    message.msgSize = extract_field<uint16_t>(data, offset, "msgSize");
    message.msgType = extract_field<uint16_t>(data, offset, "msgType");
    string sourceID = extract_fixed_length_string(10, data, offset, "sourceID");

    // Build and return the row to insert into the CSV
    return {
        std::to_string(message.msgSize),
        std::to_string(message.msgType),
        sourceID
    };
}

std::vector<std::string> NYSEParser::parse_message_13_symbolIndexMappingRequest(const std::vector<uint8_t> &data,
    size_t &offset) {
    // Define the structure for the message
    struct Message_13 {
        uint16_t msgSize;             // Size of the message
        uint16_t msgType;             // Message type (13 for Symbol Index Mapping Request)
        uint32_t symbolIndex;         // Symbol ID (or 0 for all symbols)
        char sourceID[10];            // Client requesting retransmission (ASCII, null-padded)
        uint8_t productID;            // Product ID
        uint8_t channelID;            // Channel ID
        uint8_t retransmitMethod;     // Delivery method (0 = UDP)
    };

    // Create an instance of the message structure
    Message_13 message;

    // Extract fields using utility functions
    message.msgSize = extract_field<uint16_t>(data, offset, "msgSize");
    message.msgType = extract_field<uint16_t>(data, offset, "msgType");
    message.symbolIndex = extract_field<uint32_t>(data, offset, "symbolIndex");
    std::string sourceID = extract_fixed_length_string(10, data, offset, "sourceID");
    message.productID = extract_field<uint8_t>(data, offset, "productID");
    message.channelID = extract_field<uint8_t>(data, offset, "channelID");
    message.retransmitMethod = extract_field<uint8_t>(data, offset, "retransmitMethod");

    // Build and return the row to insert into the CSV
    return {
        std::to_string(message.msgSize),
        std::to_string(message.msgType),
        std::to_string(message.symbolIndex),
        sourceID,
        std::to_string(message.productID),
        std::to_string(message.channelID),
        std::to_string(message.retransmitMethod)
    };
}

std::vector<std::string> NYSEParser::parse_message_15_refreshRequest(const std::vector<uint8_t> &data, size_t &offset) {
    // Define the structure for the message
    struct Message_15 {
        uint16_t msgSize;          // Size of the message
        uint16_t msgType;          // Message type (15 for Refresh Request)
        uint32_t symbolIndex;      // Symbol Index (0 for all symbols in the channel)
        char sourceID[10];         // Client ID requesting the refresh (ASCII, null-padded)
        uint8_t productID;         // Product ID
        uint8_t channelID;         // Channel ID
    };

    // Create an instance of the message structure
    Message_15 message;

    // Extract fields using utility functions
    message.msgSize = extract_field<uint16_t>(data, offset, "msgSize");
    message.msgType = extract_field<uint16_t>(data, offset, "msgType");
    message.symbolIndex = extract_field<uint32_t>(data, offset, "symbolIndex");
    std::string sourceID = extract_fixed_length_string(10, data, offset, "sourceID");
    message.productID = extract_field<uint8_t>(data, offset, "productID");
    message.channelID = extract_field<uint8_t>(data, offset, "channelID");

    // Build and return the row to insert into the CSV
    return {
        std::to_string(message.msgSize),
        std::to_string(message.msgType),
        std::to_string(message.symbolIndex),
        sourceID,
        std::to_string(message.productID),
        std::to_string(message.channelID)
    };
}

std::vector<std::string> NYSEParser::parse_message_31_messageUnavailable(const std::vector<uint8_t> &data,
    size_t &offset) {
    // Define the structure for the message
    struct Message_31 {
        uint16_t msgSize;       // Size of the message
        uint16_t msgType;       // Message type (31 for Message Unavailable)
        uint32_t beginSeqNum;   // Beginning sequence number of the unavailable range
        uint32_t endSeqNum;     // Ending sequence number of the unavailable range
        uint8_t productID;      // Unique ID of the feed
        uint8_t channelID;      // ID of the multicast channel
    };

    // Create an instance of the message structure
    Message_31 message;

    // Extract fields using utility functions
    message.msgSize = extract_field<uint16_t>(data, offset, "msgSize");
    message.msgType = extract_field<uint16_t>(data, offset, "msgType");
    message.beginSeqNum = extract_field<uint32_t>(data, offset, "beginSeqNum");
    message.endSeqNum = extract_field<uint32_t>(data, offset, "endSeqNum");
    message.productID = extract_field<uint8_t>(data, offset, "productID");
    message.channelID = extract_field<uint8_t>(data, offset, "channelID");

    // Build and return the row to insert into the CSV
    return {
        std::to_string(message.msgSize),
        std::to_string(message.msgType),
        std::to_string(message.beginSeqNum),
        std::to_string(message.endSeqNum),
        std::to_string(message.productID),
        std::to_string(message.channelID)
    };
}

std::vector<std::string> NYSEParser::parse_message_32_symbolClear(const std::vector<uint8_t> &data, size_t &offset) {
    // Define the structure for the message
    struct Message_32 {
        uint32_t sourceTime;         // Time when the message was generated (seconds)
        uint32_t sourceTimeNs;       // Nanosecond offset from sourceTime
        uint32_t symbolIndex;        // Unique ID of the symbol in the Symbol Index
        uint32_t nextSourceSeqNum;   // Sequence number in the next message for this symbol
    };

    // Create an instance of the message structure
    Message_32 message;

    // Extract fields using utility functions
    message.sourceTime = extract_field<uint32_t>(data, offset, "sourceTime");
    message.sourceTimeNs = extract_field<uint32_t>(data, offset, "sourceTimeNs");
    message.symbolIndex = extract_field<uint32_t>(data, offset, "symbolIndex");
    message.nextSourceSeqNum = extract_field<uint32_t>(data, offset, "nextSourceSeqNum");

    // Build and return the row to insert into the CSV
    return {
        std::to_string(message.sourceTime),
        std::to_string(message.sourceTimeNs),
        std::to_string(message.symbolIndex),
        std::to_string(message.nextSourceSeqNum)
    };
}

std::vector<std::string> NYSEParser::parse_message_34_securityStatusMessage(const std::vector<uint8_t> &data,
    size_t &offset) {
    // Define the structure for the message
    struct Message_34 {
        uint32_t sourceTime;           // Time in seconds since Jan 1, 1970 UTC
        uint32_t sourceTimeNS;         // Nanosecond offset
        uint32_t symbolIndex;          // Symbol Index
        uint32_t symbolSeqNum;         // Symbol Sequence Number
        char securityStatus;           // Security Status
        char haltCondition;            // Halt Condition
        uint8_t reserved[4];           // Reserved (4 bytes)
        uint32_t price1;               // Price 1
        uint32_t price2;               // Price 2
        char ssrTriggeringExchangeID;  // SSR Triggering Exchange ID
        uint32_t ssrTriggeringVolume;  // SSR Triggering Volume
        uint32_t time;                 // Time (HHMMSSmmm format)
        char ssrState;                 // SSR State
        char marketState;              // Market State
        char sessionState;             // Session State
    };

    // Create an instance of the message structure
    Message_34 message;

    // Extract fields using utility functions
    message.sourceTime = extract_field<uint32_t>(data, offset, "sourceTime");
    message.sourceTimeNS = extract_field<uint32_t>(data, offset, "sourceTimeNS");
    message.symbolIndex = extract_field<uint32_t>(data, offset, "symbolIndex");
    message.symbolSeqNum = extract_field<uint32_t>(data, offset, "symbolSeqNum");
    message.securityStatus = extract_field<char>(data, offset, "securityStatus");
    message.haltCondition = extract_field<char>(data, offset, "haltCondition");
    for (int i = 0; i < 4; ++i) {
        message.reserved[i] = extract_field<uint8_t>(data, offset, "reserved");
    }
    message.price1 = extract_field<uint32_t>(data, offset, "price1");
    message.price2 = extract_field<uint32_t>(data, offset, "price2");
    message.ssrTriggeringExchangeID = extract_field<char>(data, offset, "ssrTriggeringExchangeID");
    message.ssrTriggeringVolume = extract_field<uint32_t>(data, offset, "ssrTriggeringVolume");
    message.time = extract_field<uint32_t>(data, offset, "time");
    message.ssrState = extract_field<char>(data, offset, "ssrState");
    message.marketState = extract_field<char>(data, offset, "marketState");
    message.sessionState = extract_field<char>(data, offset, "sessionState");

    // Build and return the row to insert into the CSV
    return {
        std::to_string(message.sourceTime),
        std::to_string(message.sourceTimeNS),
        std::to_string(message.symbolIndex),
        std::to_string(message.symbolSeqNum),
        std::string(1, message.securityStatus), // Convert char to string
        std::string(1, message.haltCondition),  // Convert char to string
        std::to_string(message.price1),
        std::to_string(message.price2),
        std::string(1, message.ssrTriggeringExchangeID),
        std::to_string(message.ssrTriggeringVolume),
        std::to_string(message.time),
        std::string(1, message.ssrState),
        std::string(1, message.marketState),
        std::string(1, message.sessionState)
    };
}

std::vector<std::string> NYSEParser::parse_message_35_refreshHeaderMessage(const std::vector<uint8_t> &data,
    size_t &offset) {
    // Define the structure for the Refresh Header Message
    struct Message_35 {
        uint16_t msgSize;            // Size of the message (16 bytes)
        uint16_t msgType;            // The type of message (35)
        uint16_t currentRefreshPkt;  // The current refresh packet in the update
        uint16_t totalRefreshPkts;   // The total number of refresh packets in the update
        uint32_t lastSeqNum;         // The last sequence number sent on the channel
        uint32_t lastSymbolSeqNum;   // The last symbol sequence number sent for this symbol
    };

    // Create an instance of the message structure
    Message_35 message;

    // Extract fields using utility functions
    message.msgSize = extract_field<uint16_t>(data, offset, "msgSize");
    message.msgType = extract_field<uint16_t>(data, offset, "msgType");
    message.currentRefreshPkt = extract_field<uint16_t>(data, offset, "currentRefreshPkt");
    message.totalRefreshPkts = extract_field<uint16_t>(data, offset, "totalRefreshPkts");
    message.lastSeqNum = extract_field<uint32_t>(data, offset, "lastSeqNum");
    message.lastSymbolSeqNum = extract_field<uint32_t>(data, offset, "lastSymbolSeqNum");

    // Build and return the row to insert into the CSV
    return {
        std::to_string(message.msgSize),
        std::to_string(message.msgType),
        std::to_string(message.currentRefreshPkt),
        std::to_string(message.totalRefreshPkts),
        std::to_string(message.lastSeqNum),
        std::to_string(message.lastSymbolSeqNum)
    };
}

// Integrated Feed Message Types
// NYSE Chicago hours: 6:30am - 8:00pm (messages 100,101,104,102,112,111,113,114,106)

std::vector<std::string> NYSEParser::
parse_message_100_addOrderMessage(const std::vector<uint8_t> &data, size_t &offset) {
    struct Message_100 {
        uint32_t sourceTimeNS;  // 4 bytes
        uint32_t symbolIndex;   // 4 bytes
        uint32_t symbolSeqNum;  // 4 bytes
        uint64_t orderID;       // 8 bytes
        uint32_t price;         // 4 bytes
        uint32_t volume;        // 4 bytes
        char side;              // 1 byte (ASCII)
        char firmID[5];         // 5 bytes (ASCII)
        uint8_t reserved;       // 1 byte
    };

    // Instantiate the struct
    Message_100 message_100;

    // Extract fields using the utility functions
    message_100.sourceTimeNS = extract_field<uint32_t>(data, offset, "sourceTimeNS");
    message_100.symbolIndex = extract_field<uint32_t>(data, offset, "symbolIndex");
    message_100.symbolSeqNum = extract_field<uint32_t>(data, offset, "symbolSeqNum");
    message_100.orderID = extract_field<uint64_t>(data, offset, "orderID");
    message_100.price = extract_field<uint32_t>(data, offset, "price");
    message_100.volume = extract_field<uint32_t>(data, offset, "volume");
    message_100.side = extract_field<char>(data, offset, "side");
    std::string firmID = extract_fixed_length_string(5, data, offset, "firmID");
    message_100.reserved = extract_field<uint8_t>(data, offset, "reserved");

    // Build the row for the CSV
    return {
        std::to_string(message_100.sourceTimeNS),
        std::to_string(message_100.symbolIndex),
        std::to_string(message_100.symbolSeqNum),
        std::to_string(message_100.orderID),
        std::to_string(message_100.price),
        std::to_string(message_100.volume),
        std::string(1, message_100.side), // Convert char to string
        firmID,
        std::to_string(message_100.reserved)
    };
}

std::vector<std::string> NYSEParser::parse_message_101_modifyOrderMessage(const std::vector<uint8_t> &data,
    size_t &offset) {
    // Define the struct for the Modify Order Message (Msg Type 101)
    struct Message_101 {
        uint32_t sourceTimeNs;     // 4 bytes
        uint32_t symbolIndex;      // 4 bytes
        uint32_t symbolSeqNum;     // 4 bytes
        uint64_t orderId;          // 8 bytes
        uint32_t price;            // 4 bytes
        uint32_t volume;           // 4 bytes
        uint8_t positionChange;    // 1 byte
        char side;                 // 1 byte (ASCII)
        uint8_t reserved2;         // 1 byte
    };

    // Instantiate the struct
    Message_101 message_101;

    // Extract fields using the utility functions
    message_101.sourceTimeNs = extract_field<uint32_t>(data, offset, "sourceTimeNs");
    message_101.symbolIndex = extract_field<uint32_t>(data, offset, "symbolIndex");
    message_101.symbolSeqNum = extract_field<uint32_t>(data, offset, "symbolSeqNum");
    message_101.orderId = extract_field<uint64_t>(data, offset, "orderId");
    message_101.price = extract_field<uint32_t>(data, offset, "price");
    message_101.volume = extract_field<uint32_t>(data, offset, "volume");
    message_101.positionChange = extract_field<uint8_t>(data, offset, "positionChange");
    message_101.side = extract_field<char>(data, offset, "side");
    message_101.reserved2 = extract_field<uint8_t>(data, offset, "reserved2");

    // Build the row for the CSV
    return {
        std::to_string(message_101.sourceTimeNs),
        std::to_string(message_101.symbolIndex),
        std::to_string(message_101.symbolSeqNum),
        std::to_string(message_101.orderId),
        std::to_string(message_101.price),
        std::to_string(message_101.volume),
        std::to_string(message_101.positionChange),
        std::string(1, message_101.side), // Convert char to string
        std::to_string(message_101.reserved2)
    };
}

std::vector<std::string> NYSEParser::parse_message_104_replaceOrderMessage(const std::vector<uint8_t> &data,
    size_t &offset) {
    // Define the structure for the message
    struct Message_104 {
        uint32_t sourceTimeNs;   // Nanosecond offset
        uint32_t symbolIndex;    // Symbol ID
        uint32_t symbolSeqNum;   // Sequence number
        uint64_t orderId;        // Existing order ID to be replaced
        uint64_t newOrderId;     // New order ID of the replacement
        uint32_t price;          // New order price
        uint32_t volume;         // New order quantity
        char side;               // Side of the order ('B' or 'S')
        uint8_t reserved2;       // Reserved for future use
    };

    // Create an instance of the message structure
    Message_104 message;

    // Extract fields using utility functions
    message.sourceTimeNs = extract_field<uint32_t>(data, offset, "sourceTimeNs");
    message.symbolIndex = extract_field<uint32_t>(data, offset, "symbolIndex");
    message.symbolSeqNum = extract_field<uint32_t>(data, offset, "symbolSeqNum");
    message.orderId = extract_field<uint64_t>(data, offset, "orderId");
    message.newOrderId = extract_field<uint64_t>(data, offset, "newOrderId");
    message.price = extract_field<uint32_t>(data, offset, "price");
    message.volume = extract_field<uint32_t>(data, offset, "volume");
    message.side = extract_field<char>(data, offset, "side");
    message.reserved2 = extract_field<uint8_t>(data, offset, "reserved2");

    // Build and return the row to insert into the CSV
    return {
        std::to_string(message.sourceTimeNs),
        std::to_string(message.symbolIndex),
        std::to_string(message.symbolSeqNum),
        std::to_string(message.orderId),
        std::to_string(message.newOrderId),
        std::to_string(message.price),
        std::to_string(message.volume),
        std::string(1, message.side), // Convert char to string
        std::to_string(message.reserved2)
    };
}

std::vector<std::string> NYSEParser::parse_message_102_deleteOrderMessage(const std::vector<uint8_t> &data,
    size_t &offset) {
    // Define the struct for the Delete Order Message (Msg Type 102)
    struct Message_102 {
        uint32_t sourceTimeNs;     // 4 bytes
        uint32_t symbolIndex;      // 4 bytes
        uint32_t symbolSeqNum;     // 4 bytes
        uint64_t orderId;          // 8 bytes
        uint8_t reserved1;         // 1 byte (Future use)
    };

    // Instantiate the struct
    Message_102 message_102;

    // Extract fields using the utility functions
    message_102.sourceTimeNs = extract_field<uint32_t>(data, offset, "sourceTimeNs");
    message_102.symbolIndex = extract_field<uint32_t>(data, offset, "symbolIndex");
    message_102.symbolSeqNum = extract_field<uint32_t>(data, offset, "symbolSeqNum");
    message_102.orderId = extract_field<uint64_t>(data, offset, "orderId");
    message_102.reserved1 = extract_field<uint8_t>(data, offset, "reserved1");

    // Build the row for the CSV
    return {
        std::to_string(message_102.sourceTimeNs),
        std::to_string(message_102.symbolIndex),
        std::to_string(message_102.symbolSeqNum),
        std::to_string(message_102.orderId),
        std::to_string(message_102.reserved1)
    };
}

std::vector<std::string> NYSEParser::parse_message_112_tradeCancelMessage(const std::vector<uint8_t> &data,
    size_t &offset) {
    // Define the struct for message 112
    struct Message_112 {
        uint32_t sourceTimeNS;      // Nanoseconds offset
        uint32_t symbolIndex;       // Symbol Index
        uint32_t symbolSeqNum;      // Sequence Number
        uint32_t tradeID;           // Trade ID of the trade to be canceled
    };

    // Instantiate the message struct
    Message_112 message_112;

    // Extract fields using extract_field
    message_112.sourceTimeNS = extract_field<uint32_t>(data, offset, "sourceTimeNS");
    message_112.symbolIndex = extract_field<uint32_t>(data, offset, "symbolIndex");
    message_112.symbolSeqNum = extract_field<uint32_t>(data, offset, "symbolSeqNum");
    message_112.tradeID = extract_field<uint32_t>(data, offset, "tradeID");

    // Prepare the row to be returned
    return {
        std::to_string(message_112.sourceTimeNS),
        std::to_string(message_112.symbolIndex),
        std::to_string(message_112.symbolSeqNum),
        std::to_string(message_112.tradeID)
    };
}

std::vector<std::string> NYSEParser::parse_message_111_crossTradeMessage(const std::vector<uint8_t> &data,
    size_t &offset) {
    // Define the struct for message 111
    struct Message_111 {
        uint32_t sourceTimeNS;      // Nanoseconds offset
        uint32_t symbolIndex;       // Symbol Index
        uint32_t symbolSeqNum;      // Sequence Number
        uint32_t crossID;           // Unique Cross Trade ID
        uint32_t price;             // Execution price
        uint32_t volume;            // Executed volume
        char crossType;             // Reason for crossing auction
    };

    // Instantiate the message struct
    Message_111 message_111;

    // Extract fields using extract_field
    message_111.sourceTimeNS = extract_field<uint32_t>(data, offset, "sourceTimeNS");
    message_111.symbolIndex = extract_field<uint32_t>(data, offset, "symbolIndex");
    message_111.symbolSeqNum = extract_field<uint32_t>(data, offset, "symbolSeqNum");
    message_111.crossID = extract_field<uint32_t>(data, offset, "crossID");
    message_111.price = extract_field<uint32_t>(data, offset, "price");
    message_111.volume = extract_field<uint32_t>(data, offset, "volume");
    message_111.crossType = extract_field<char>(data, offset, "crossType");

    // Prepare the row to be returned
    return {
        std::to_string(message_111.sourceTimeNS),
        std::to_string(message_111.symbolIndex),
        std::to_string(message_111.symbolSeqNum),
        std::to_string(message_111.crossID),
        std::to_string(message_111.price),
        std::to_string(message_111.volume),
        std::string(1, message_111.crossType) // Convert char to string
    };
}

std::vector<std::string> NYSEParser::parse_message_113_crossCorrectionMessage(const std::vector<uint8_t> &data,
    size_t &offset) {
    // Define the struct for message 113
    struct Message_113 {
        uint32_t sourceTimeNS;      // Nanoseconds offset
        uint32_t symbolIndex;       // Symbol Index
        uint32_t symbolSeqNum;      // Sequence Number
        uint32_t crossID;           // Cross ID of the original Cross Trade
        uint32_t volume;            // Corrected volume of the Cross Trade
    };

    // Instantiate the message struct
    Message_113 message_113;

    // Extract fields using extract_field
    message_113.sourceTimeNS = extract_field<uint32_t>(data, offset, "sourceTimeNS");
    message_113.symbolIndex = extract_field<uint32_t>(data, offset, "symbolIndex");
    message_113.symbolSeqNum = extract_field<uint32_t>(data, offset, "symbolSeqNum");
    message_113.crossID = extract_field<uint32_t>(data, offset, "crossID");
    message_113.volume = extract_field<uint32_t>(data, offset, "volume");

    // Prepare the row to be returned
    return {
        std::to_string(message_113.sourceTimeNS),
        std::to_string(message_113.symbolIndex),
        std::to_string(message_113.symbolSeqNum),
        std::to_string(message_113.crossID),
        std::to_string(message_113.volume)
    };
}

std::vector<std::string> NYSEParser::parse_message_114_retailPriceImprovementMsg(const std::vector<uint8_t> &data,
    size_t &offset) {
    // Define the struct for message 114
    struct Message_114 {
        uint32_t sourceTimeNS;   // Nanoseconds offset
        uint32_t symbolIndex;    // Symbol Index
        uint32_t symbolSeqNum;   // Sequence Number
        char rpiIndicator;       // RPI Indicator
    };

    // Instantiate the message struct
    Message_114 message_114;

    // Extract fields using extract_field
    message_114.sourceTimeNS = extract_field<uint32_t>(data, offset, "sourceTimeNS");
    message_114.symbolIndex = extract_field<uint32_t>(data, offset, "symbolIndex");
    message_114.symbolSeqNum = extract_field<uint32_t>(data, offset, "symbolSeqNum");
    message_114.rpiIndicator = extract_field<char>(data, offset, "rpiIndicator");

    // Prepare the row to be returned
    return {
        std::to_string(message_114.sourceTimeNS),
        std::to_string(message_114.symbolIndex),
        std::to_string(message_114.symbolSeqNum),
        std::string(1, message_114.rpiIndicator) // Convert char to string
    };
}

std::vector<std::string> NYSEParser::parse_message_106_addOrderRefreshMessage(const std::vector<uint8_t> &data,
    size_t &offset) {
    struct AddOrderRefreshMessage {
        uint32_t sourceTime;
        uint32_t sourceTimeNS;
        uint32_t symbolIndex;
        uint32_t symbolSeqNum;
        uint64_t orderID;
        uint32_t price;
        uint32_t volume;
        char side;
        std::string firmID;
        uint8_t reserved;
    };

    AddOrderRefreshMessage message;

    // Extract fields using `extract_field` and `extract_fixed_length_string`
    message.sourceTime = extract_field<uint32_t>(data, offset, "sourceTime");
    message.sourceTimeNS = extract_field<uint32_t>(data, offset, "sourceTimeNS");
    message.symbolIndex = extract_field<uint32_t>(data, offset, "symbolIndex");
    message.symbolSeqNum = extract_field<uint32_t>(data, offset, "symbolSeqNum");
    message.orderID = extract_field<uint64_t>(data, offset, "orderID");
    message.price = extract_field<uint32_t>(data, offset, "price");
    message.volume = extract_field<uint32_t>(data, offset, "volume");
    message.side = extract_field<char>(data, offset, "side");
    message.firmID = extract_fixed_length_string(5, data, offset, "firmID");
    message.reserved = extract_field<uint8_t>(data, offset, "reserved");

    // Build the row for the CSV
    return {
        std::to_string(message.sourceTime),
        std::to_string(message.sourceTimeNS),
        std::to_string(message.symbolIndex),
        std::to_string(message.symbolSeqNum),
        std::to_string(message.orderID),
        std::to_string(message.price),
        std::to_string(message.volume),
        std::string(1, message.side), // Convert char to string for CSV
        message.firmID,
        std::to_string(message.reserved),
    };
}
// See Appendix A (105)
std::vector<std::string> NYSEParser::parse_message_105_imbalanceMessage(const std::vector<uint8_t> &data,
    size_t &offset) {
    // Define the structure for the message
    struct Message_105 {
        uint32_t sourceTime;
        uint32_t sourceTimeNS;
        uint32_t symbolIndex;
        uint32_t symbolSeqNum;
        uint32_t referencePrice;
        uint32_t pairedQty;
        uint32_t totalImbalanceQty;
        uint32_t marketImbalanceQty;
        uint16_t auctionTime;
        char auctionType;
        char imbalanceSide;
        uint32_t continuousBookClearingPrice;
        uint32_t auctionInterestClearingPrice;
        uint32_t ssrFilingPrice;
        uint32_t indicativeMatchPrice;
        uint32_t upperCollar;
        uint32_t lowerCollar;
        uint8_t auctionStatus;
        uint8_t freezeStatus;
        uint8_t numExtensions;
        uint32_t unpairedQty;
        char unpairedSide;
        char reserved;
    };

    Message_105 message;

    message.sourceTime = extract_field<uint32_t>(data, offset, "sourceTime");
    message.sourceTimeNS = extract_field<uint32_t>(data, offset, "sourceTimeNS");
    message.symbolIndex = extract_field<uint32_t>(data, offset, "symbolIndex");
    message.symbolSeqNum = extract_field<uint32_t>(data, offset, "symbolSeqNum");
    message.referencePrice = extract_field<uint32_t>(data, offset, "referencePrice");
    message.pairedQty = extract_field<uint32_t>(data, offset, "pairedQty");
    message.totalImbalanceQty = extract_field<uint32_t>(data, offset, "totalImbalanceQty");
    message.marketImbalanceQty = extract_field<uint32_t>(data, offset, "marketImbalanceQty");
    message.auctionTime = extract_field<uint16_t>(data, offset, "auctionTime");
    message.auctionType = extract_field<char>(data, offset, "auctionType");
    message.imbalanceSide = extract_field<char>(data, offset, "imbalanceSide");
    message.continuousBookClearingPrice = extract_field<uint32_t>(data, offset, "continuousBookClearingPrice");
    message.auctionInterestClearingPrice = extract_field<uint32_t>(data, offset, "auctionInterestClearingPrice");
    message.ssrFilingPrice = extract_field<uint32_t>(data, offset, "ssrFilingPrice");
    message.indicativeMatchPrice = extract_field<uint32_t>(data, offset, "indicativeMatchPrice");
    message.upperCollar = extract_field<uint32_t>(data, offset, "upperCollar");
    message.lowerCollar = extract_field<uint32_t>(data, offset, "lowerCollar");
    message.auctionStatus = extract_field<uint8_t>(data, offset, "auctionStatus");
    message.freezeStatus = extract_field<uint8_t>(data, offset, "freezeStatus");
    message.numExtensions = extract_field<uint8_t>(data, offset, "numExtensions");
    message.unpairedQty = extract_field<uint32_t>(data, offset, "unpairedQty");
    message.unpairedSide = extract_field<char>(data, offset, "unpairedSide");
    message.reserved = extract_field<char>(data, offset, "reserved");

    // Build the row for the CSV
    return {
        std::to_string(message.sourceTime),
        std::to_string(message.sourceTimeNS),
        std::to_string(message.symbolIndex),
        std::to_string(message.symbolSeqNum),
        std::to_string(message.referencePrice),
        std::to_string(message.pairedQty),
        std::to_string(message.totalImbalanceQty),
        std::to_string(message.marketImbalanceQty),
        std::to_string(message.auctionTime),
        std::string(1, message.auctionType),
        std::string(1, message.imbalanceSide),
        std::to_string(message.continuousBookClearingPrice),
        std::to_string(message.auctionInterestClearingPrice),
        std::to_string(message.ssrFilingPrice),
        std::to_string(message.indicativeMatchPrice),
        std::to_string(message.upperCollar),
        std::to_string(message.lowerCollar),
        std::to_string(message.auctionStatus),
        std::to_string(message.freezeStatus),
        std::to_string(message.numExtensions),
        std::to_string(message.unpairedQty),
        std::string(1, message.unpairedSide),
        std::string(1, message.reserved),
    };
}
// NYSE Chicago 7:00am - 8:00pm (messages 103, 110, 223)
std::vector<std::string> NYSEParser::parse_message_103_orderExecutionMessage(const std::vector<uint8_t> &data,
    size_t &offset) {
    // Define the structure for the message
    struct Message_103 {
        uint32_t sourceTimeNs;   // Nanosecond offset
        uint32_t symbolIndex;    // Symbol ID
        uint32_t symbolSeqNum;   // Sequence number
        uint64_t orderId;        // Unique order ID
        uint32_t tradeId;        // Unique trade ID
        uint32_t price;          // Execution price
        uint32_t volume;         // Executed quantity
        uint8_t printableFlag;   // Printable to SIP
        uint8_t reserved1;       // Reserved for future use
        char tradeCond1;         // Settlement related condition
        char tradeCond2;         // Reason for Trade Through Exemptions
        char tradeCond3;         // Extended hours/sequencing conditions
        char tradeCond4;         // SRO required detail
    };

    // Create an instance of the message structure
    Message_103 message;

    // Extract fields using utility functions
    message.sourceTimeNs = extract_field<uint32_t>(data, offset, "sourceTimeNs");
    message.symbolIndex = extract_field<uint32_t>(data, offset, "symbolIndex");
    message.symbolSeqNum = extract_field<uint32_t>(data, offset, "symbolSeqNum");
    message.orderId = extract_field<uint64_t>(data, offset, "orderId");
    message.tradeId = extract_field<uint32_t>(data, offset, "tradeId");
    message.price = extract_field<uint32_t>(data, offset, "price");
    message.volume = extract_field<uint32_t>(data, offset, "volume");
    message.printableFlag = extract_field<uint8_t>(data, offset, "printableFlag");
    message.reserved1 = extract_field<uint8_t>(data, offset, "reserved1");
    message.tradeCond1 = extract_field<char>(data, offset, "tradeCond1");
    message.tradeCond2 = extract_field<char>(data, offset, "tradeCond2");
    message.tradeCond3 = extract_field<char>(data, offset, "tradeCond3");
    message.tradeCond4 = extract_field<char>(data, offset, "tradeCond4");

    // Build and return the row to insert into the CSV
    return {
        std::to_string(message.sourceTimeNs),
        std::to_string(message.symbolIndex),
        std::to_string(message.symbolSeqNum),
        std::to_string(message.orderId),
        std::to_string(message.tradeId),
        std::to_string(message.price),
        std::to_string(message.volume),
        std::to_string(message.printableFlag),
        std::string(1, message.tradeCond1), // Convert char to string
        std::string(1, message.tradeCond2), // Convert char to string
        std::string(1, message.tradeCond3), // Convert char to string
        std::string(1, message.tradeCond4)  // Convert char to string
    };
}

std::vector<std::string> NYSEParser::parse_message_110_nonDisplayedTradeMessage(const std::vector<uint8_t> &data,
    size_t &offset) {
    struct Message_110 {
        uint32_t sourceTimeNS;
        uint32_t symbolIndex;
        uint32_t symbolSeqNum;
        uint32_t tradeID;
        uint32_t price;
        uint32_t volume;
        uint8_t printableFlag;
        char tradeCond1;
        char tradeCond2;
        char tradeCond3;
        char tradeCond4;
    };

    Message_110 message_110;

    // Extract fields
    message_110.sourceTimeNS = extract_field<uint32_t>(data, offset, "sourceTimeNS");
    message_110.symbolIndex = extract_field<uint32_t>(data, offset, "symbolIndex");
    message_110.symbolSeqNum = extract_field<uint32_t>(data, offset, "symbolSeqNum");
    message_110.tradeID = extract_field<uint32_t>(data, offset, "tradeID");
    message_110.price = extract_field<uint32_t>(data, offset, "price");
    message_110.volume = extract_field<uint32_t>(data, offset, "volume");
    message_110.printableFlag = extract_field<uint8_t>(data, offset, "printableFlag");
    message_110.tradeCond1 = extract_field<char>(data, offset, "tradeCond1");
    message_110.tradeCond2 = extract_field<char>(data, offset, "tradeCond2");
    message_110.tradeCond3 = extract_field<char>(data, offset, "tradeCond3");
    message_110.tradeCond4 = extract_field<char>(data, offset, "tradeCond4");

    // Create a CSV row
    return {
        std::to_string(message_110.sourceTimeNS),
        std::to_string(message_110.symbolIndex),
        std::to_string(message_110.symbolSeqNum),
        std::to_string(message_110.tradeID),
        std::to_string(message_110.price),
        std::to_string(message_110.volume),
        std::to_string(static_cast<int>(message_110.printableFlag)),
        std::string(1, message_110.tradeCond1),
        std::string(1, message_110.tradeCond2),
        std::string(1, message_110.tradeCond3),
        std::string(1, message_110.tradeCond4)
    };
}

std::vector<std::string> NYSEParser::parse_message_223_stockSummaryMessage(const std::vector<uint8_t> &data,
    size_t &offset) {
    // Define the struct for message 223
    struct Message_223 {
        uint32_t sourceTime;      // Time when the message was generated
        uint32_t sourceTimeNS;    // Nanosecond offset from the source time
        uint32_t symbolIndex;     // Symbol index
        uint32_t highPrice;       // High price for the stock
        uint32_t lowPrice;        // Low price for the stock
        uint32_t open;            // Opening price for the stock
        uint32_t close;           // Closing price for the stock
        uint32_t totalVolume;     // Cumulative volume for the stock
    };

    // Instantiate the message struct
    Message_223 message_223;

    // Extract fields using extract_field
    message_223.sourceTime = extract_field<uint32_t>(data, offset, "sourceTime");
    message_223.sourceTimeNS = extract_field<uint32_t>(data, offset, "sourceTimeNS");
    message_223.symbolIndex = extract_field<uint32_t>(data, offset, "symbolIndex");
    message_223.highPrice = extract_field<uint32_t>(data, offset, "highPrice");
    message_223.lowPrice = extract_field<uint32_t>(data, offset, "lowPrice");
    message_223.open = extract_field<uint32_t>(data, offset, "open");
    message_223.close = extract_field<uint32_t>(data, offset, "close");
    message_223.totalVolume = extract_field<uint32_t>(data, offset, "totalVolume");

    // Prepare the row to be returned
    return {
        std::to_string(message_223.sourceTime),
        std::to_string(message_223.sourceTimeNS),
        std::to_string(message_223.symbolIndex),
        std::to_string(message_223.highPrice),
        std::to_string(message_223.lowPrice),
        std::to_string(message_223.open),
        std::to_string(message_223.close),
        std::to_string(message_223.totalVolume)
    };
}