#include "CMEParser.h"

CMEParser::CMEParser(const std::string& input_file, const std::string& output_file, const std::set<uint16_t>& allowed_messages, const std::vector<std::string>& custom_header)
    : ParserBase(input_file, output_file, allowed_messages, custom_header) {}

std::vector<std::string> CMEParser::parse_payload(const std::vector<uint8_t>& packet_data,
        size_t packet_number,
        const PcapPacketHeader& pcap_header) {

    std::vector<std::string> row;

    // Now check whole payload
    if (packet_data.size() < 42) {
        std::cerr << "Packet too small, skipping.\n";
        row.push_back(std::to_string(packet_number)); // Packet number
        // row.push_back(format_timestamp(pcap_header.ts_sec, pcap_header.ts_usec)); // Timestamp
        row.insert(row.end(), 12, ""); // Fill the rest with blanks
        return row;
    }

    // Parse the packet (we have reached the payload -- at byte 42)
    std::vector<uint8_t> payload_data(packet_data.begin() + 42, packet_data.end());

    if (payload_data.size() < sizeof(TechnicalHeader)) {
        throw std::runtime_error("Payload data too small to contain TechnicalHeader");
    }

    size_t offset = 0;

    // Parse Technical Header
    TechnicalHeader tech_header;
    tech_header.msgSeqNum = extract_field<uint32_t>(payload_data, offset, "msgSeqNum");
    tech_header.sendingTime = extract_field<uint64_t>(payload_data, offset, "sendingTime");

    // Ensure sufficient data for CME Message Header
    if (payload_data.size() < offset + sizeof(CMEMessageHeader)) {
        throw std::runtime_error("Payload data too small to contain CMEMessageHeader");
    }

    // Parse CME Message Header
    CMEMessageHeader cme_header;
    cme_header.msgSize = extract_field<uint16_t>(payload_data, offset, "msgSize");
    cme_header.blockLength = extract_field<uint16_t>(payload_data, offset, "blockLength");
    cme_header.templateID = extract_field<uint16_t>(payload_data, offset, "templateID");
    cme_header.schemaID = extract_field<uint16_t>(payload_data, offset, "schemaID");
    cme_header.version = extract_field<uint16_t>(payload_data, offset, "version");

    // Count occurrences of templateID / messageID
    message_count_[cme_header.templateID]++;

    // Filter non-allowed template == message IDs
    if (!allowed_message_ids_.empty() && allowed_message_ids_.find(cme_header.templateID) == allowed_message_ids_.end()) {
        logger_.debug("Skipping templateID: " + std::to_string(cme_header.templateID));
        return {}; // Skip this template
    }

    // Build row with core fields
    row = {
        std::to_string(tech_header.msgSeqNum),
        std::to_string(tech_header.sendingTime),
        std::to_string(cme_header.msgSize),
        std::to_string(cme_header.blockLength),
        std::to_string(cme_header.templateID),
        std::to_string(cme_header.schemaID),
        std::to_string(cme_header.version)
    };

    // Parse template-specific fields and append to row
    std::vector<std::string> additional_fields = parse_by_template_id(cme_header.templateID, payload_data, offset);
    row.insert(row.end(), additional_fields.begin(), additional_fields.end());

    return row;
}

std::vector<std::string> CMEParser::parse_by_template_id(uint16_t templateID, const std::vector<uint8_t>& data, size_t& offset) {
    switch (templateID) {
        case 50:
            return parse_template_50(data, offset);
        case 55:
            return parse_template_55(data, offset);
        default:
            return {}; // Unknown template ID
    }
}

std::vector<std::string> CMEParser::parse_template_50(const std::vector<uint8_t>& data, size_t& offset) {
    uint64_t transactTime = extract_field<uint64_t>(data, offset, "transactTime");
    uint8_t matchEventIndicator = extract_field<uint8_t>(data, offset, "matchEventIndicator");

    return {
        std::to_string(transactTime),
        std::to_string(matchEventIndicator)
    };
}

std::vector<std::string> CMEParser::parse_template_55(const std::vector<uint8_t>& data, size_t& offset) {

    struct SBE_O_55 {
            uint8_t matchEventIndicator;    // Offset 0: Bitmap field reflecting updates for a Globex event.
            uint32_t totNumReports;         // Offset 1: Total instruments in Replay loop.
            int8_t securityUpdateAction;    // Offset 5: Last Security update action ('A', 'D', 'M').
            uint64_t lastUpdateTime;        // Offset 6: Timestamp of last addition/modification/deletion.
            int8_t mDSecurityTradingStatus; // Offset 14: Current state of the instrument.
            int16_t appID;                 // Offset 15: Channel ID from configuration file.
            uint8_t marketSegmentID;        // Offset 17: Market segment identifier.
            uint8_t underlyingProduct;      // Offset 18: Product complex identifier.

            // Fixed-length strings for alphanumeric fields
            string securityExchange;       // Offset 19: Exchange identifier (e.g., "XCME").
            string securityGroup;          // Offset 23: Security group code.
            string asset;                  // Offset 29: Underlying asset code.
            string symbol;                // Offset 35: Instrument name or symbol.

            int32_t securityID;             // Offset 55: Unique instrument ID.
            int8_t securityIDSource;          // Offset 59: Source of security ID (always '8').
            string securityType;           // Offset 60: Security type (e.g., "FUT").
            string cFICode;                // Offset 66: ISO categorization code.
            int8_t putOrCall;               // Offset 72: Option type (0=Put, 1=Call).
            string maturityMonthYear;      // Offset 73: Contract maturity date (YYYYMM format).
            string currency;               // Offset 78: ISO currency code.

            int64_t strikePrice;            // Offset 80: Strike price (null for non-options).
            string strikeCurrency;         // Offset 88: Currency of strike price.
            string settlCurrency;          // Offset 91: Settlement currency.
            int64_t minCabPrice;            // Offset 94: Minimum cabinet price.

            char matchAlgorithm;            // Offset 102: Matching algorithm ('F', 'K', etc.).
            uint32_t minTradeVol;           // Offset 103: Minimum trade volume.
            uint32_t maxTradeVol;           // Offset 107: Maximum trade volume.

            int64_t minPriceIncrement;      // Offset 111: Minimum price tick.
            int64_t minPriceIncrementAmount;// Offset 119: Monetary value of price tick.
            float displayFactor;            // Offset 127: Multiplier for converting price.

            int8_t tickRule;                // Offset 135: Tick table reference.
            uint8_t mainFraction;           // Offset 136: Main price fraction denominator.
            uint8_t subFraction;            // Offset 137: Sub price fraction denominator.
            uint8_t priceDisplayFormat;     // Offset 138: Number of decimals in display price.

            string unitOfMeasure;         // Offset 139: Unit of measure (e.g., megawatts).
            float unitOfMeasureQty;         // Offset 169: Contract size per unit.
            int64_t tradingReferencePrice;  // Offset 177: Reference price (settlement price).

            uint8_t settlPriceType;         // Offset 185: Settlement price type (bitmap).
            int32_t clearedVolume;          // Offset 186: Cleared volume from prior session.
            int32_t openInterestQty;        // Offset 190: Open interest from prior session.

            int64_t lowLimitPrice;          // Offset 194: Lowest allowable price for the day.
            int64_t highLimitPrice;         // Offset 202: Highest allowable price for the day.

            uint8_t userDefinedInstrument;     // Offset 210: User-defined instrument flag ('Y' or 'N').
            uint16_t tradingReferenceDate;  // Offset 211: Session date for settlement price.

            uint64_t instrumentGUID;
    };

    SBE_O_55 sbe_55;

     // Extract fields
        sbe_55.matchEventIndicator = extract_field<uint8_t>(data, offset,"matchEventIndicator");
        sbe_55.totNumReports = extract_field<uint32_t>(data, offset,"totNumReports");
        if (sbe_55.totNumReports == 0xFFFFFFFF) {
            sbe_55.totNumReports = 0; // Handle null value
        }

        sbe_55.securityUpdateAction = extract_field<int8_t>(data, offset,"securityUpdateAction");
        std::string securityUpdateActionStr(1, static_cast<char>(sbe_55.securityUpdateAction));
        if (sbe_55.securityUpdateAction != 'A' && sbe_55.securityUpdateAction != 'D' && sbe_55.securityUpdateAction != 'M') {
            std::cerr << "\n[WARN] Invalid securityUpdateAction: " << static_cast<int>(sbe_55.securityUpdateAction) << std::endl;
        }

        sbe_55.lastUpdateTime = extract_field<uint64_t>(data, offset,"lastUpdateTime");
        // if (sbe_55.lastUpdateTime > 1e18) { // Check for implausible timestamp
        //     std::cerr << "\n[WARN] Invalid lastUpdateTime: " << sbe_55.lastUpdateTime << std::endl;
        //     sbe_55.lastUpdateTime = 0;
        // }

        sbe_55.mDSecurityTradingStatus = extract_field<int8_t>(data, offset,"mDSecurityTradingStatus");
        // if (sbe_55.mDSecurityTradingStatus < 0 || sbe_55.mDSecurityTradingStatus > 103) {
        //     std::cerr << "\n[WARN] Invalid mDSecurityTradingStatus: " << static_cast<int>(sbe_55.mDSecurityTradingStatus) << std::endl;
        // }

        sbe_55.appID = extract_field<int16_t>(data, offset,"appID");
        sbe_55.marketSegmentID = extract_field<uint8_t>(data, offset,"marketSegmentID");
        sbe_55.underlyingProduct = extract_field<uint8_t>(data, offset,"underlyingProduct");
        if (sbe_55.underlyingProduct > 17) {
            std::cerr << "\n[WARN] Invalid underlyingProduct: " << static_cast<int>(sbe_55.underlyingProduct) << std::endl;
        }

        sbe_55.securityExchange = extract_fixed_length_string(4, data, offset,"securityExchange");
        sbe_55.securityGroup = extract_fixed_length_string(6, data, offset,"securityGroup");
        sbe_55.asset = extract_fixed_length_string(6, data, offset,"asset");
        sbe_55.symbol = extract_fixed_length_string(19, data, offset,"symbol");

        sbe_55.securityID = extract_field<int32_t>(data, offset,"securityID");
        sbe_55.securityIDSource = extract_field<int8_t>(data, offset,"securityIDSource");
        // if (sbe_55.securityIDSource != '8') { // '8' is the expected value for CME
        //     std::cerr << "\n[WARN] Invalid securityIDSource: " << static_cast<int>(sbe_55.securityIDSource) << std::endl;
        //     logger_.log(Logger::WARNING,"Invalid securityIDSource: " + static_cast<int>(sbe_55.securityIDSource));
        // }

        sbe_55.securityType = extract_fixed_length_string(6, data, offset,"securityType");
        sbe_55.cFICode = extract_fixed_length_string(6, data, offset,"cFICode");

        sbe_55.putOrCall = extract_field<int8_t>(data, offset,"putOrCall");
        if (sbe_55.putOrCall != 0 && sbe_55.putOrCall != 1) {
            std::cerr << "\n[WARN] Invalid putOrCall: " << static_cast<int>(sbe_55.putOrCall) << std::endl;
        }

        sbe_55.maturityMonthYear = extract_fixed_length_string(5, data, offset,"maturityMonthYear");
        // if (sbe_55.maturityMonthYear.length() < 4 || !std::isdigit(sbe_55.maturityMonthYear[0])) {
        //     std::cerr << "\n[WARN] Invalid maturityMonthYear: " << sbe_55.maturityMonthYear << std::endl;
        // }

        sbe_55.currency = extract_fixed_length_string(3, data, offset,"currency");

        sbe_55.strikePrice = extract_field<int64_t>(data, offset,"strikePrice");
        if (sbe_55.strikePrice == 0x7FFFFFFFFFFFFFFF) {
            sbe_55.strikePrice = 0; // Handle null value
        }
        sbe_55.strikeCurrency = extract_fixed_length_string(3, data, offset,"strikeCurrency");
        sbe_55.settlCurrency = extract_fixed_length_string(3, data, offset,"settlCurrency");

        sbe_55.minCabPrice = extract_field<int64_t>(data, offset,"minCabPrice");
        if (sbe_55.minCabPrice == 0x7FFFFFFFFFFFFFFF) {
            sbe_55.minCabPrice = 0; // Handle null value
        }

        sbe_55.matchAlgorithm = extract_field<char>(data, offset,"matchAlgorithm");
        sbe_55.minTradeVol = extract_field<uint32_t>(data, offset,"minTradeVol");
        sbe_55.maxTradeVol = extract_field<uint32_t>(data, offset,"maxTradeVol");
        sbe_55.minPriceIncrement = extract_field<int64_t>(data, offset,"minPriceIncrement"); // PRICENULL9
        sbe_55.minPriceIncrementAmount = extract_field<int64_t>(data, offset,"minPriceIncrementAmount"); // PRICENULL9
        sbe_55.displayFactor = extract_field<float>(data, offset,"displayFactor"); // Decimal9
        sbe_55.tickRule = extract_field<int8_t>(data, offset,"tickRule"); // Int8NULL
        sbe_55.mainFraction = extract_field<uint8_t>(data, offset,"mainFraction"); // uInt8NULL
        sbe_55.subFraction = extract_field<uint8_t>(data, offset,"subFraction"); // uInt8NULL
        sbe_55.priceDisplayFormat = extract_field<uint8_t>(data, offset,"priceDisplayFormat"); // uInt8NULL
        sbe_55.unitOfMeasure = extract_fixed_length_string(30, data, offset,"unitOfMeasure"); // String (max 30 bytes)
        sbe_55.unitOfMeasureQty = extract_field<float>(data, offset,"unitOfMeasureQty"); // Decimal9NULL
        sbe_55.tradingReferencePrice = extract_field<int64_t>(data, offset,"tradingReferencePrice"); // PRICENULL9
        sbe_55.settlPriceType = extract_field<uint8_t>(data, offset,"settlPriceType"); // MultipleCharValue
        sbe_55.clearedVolume = extract_field<int32_t>(data, offset,"clearedVolume"); // Int32NULL
        sbe_55.openInterestQty = extract_field<int32_t>(data, offset,"openInterestQty"); // Int32NULL
        sbe_55.lowLimitPrice = extract_field<int64_t>(data, offset,"lowLimitPrice"); // PRICENULL9
        sbe_55.highLimitPrice = extract_field<int64_t>(data, offset,"highLimitPrice"); // PRICENULL9
        sbe_55.userDefinedInstrument = extract_field<uint8_t>(data, offset,"userDefinedInstrument"); // char (Y/N)
        sbe_55.tradingReferenceDate = extract_field<uint16_t>(data, offset,"tradingReferenceDate"); // LocalMktDate
        sbe_55.instrumentGUID = extract_field<uint64_t>(data, offset,"instrumentGUID");

    return {
        std::to_string(sbe_55.matchEventIndicator),
        std::to_string(sbe_55.totNumReports),
        std::to_string(sbe_55.securityUpdateAction),
        std::to_string(sbe_55.lastUpdateTime)
    };
}
