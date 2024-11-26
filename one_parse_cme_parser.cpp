//
// Created by Anton Charov on 11/17/2024.
//

#include "one_parse_cme_parser.h"



#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <ctime>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <string>
#include <set>
#include <map>
#include <type_traits>
#include <bitset>
#include "tools/DebugUtil.h"
#include "MKTData/MessageHeader.h"
#include "Logger.h"

using namespace std;

class CMEParser {
private:
    string filename;                                // Input file name
    ifstream input_file;
    ofstream csv_file;

    std::set<uint16_t> allowed_template_ids_;       // Templates to include in CSV
    std::map<uint16_t, size_t> template_count_;     // Counts for each template
    std::vector<std::string> custom_header_;        // Optional custom header


    Logger logger_;                                 // Custom logger instance

    bool advanced_debug = true;

    // Techinical Header
    struct TechnicalHeader {
        uint32_t msgSeqNum;     // UDP
        uint64_t sendingTime;
    };

    struct CMEMessageHeader {
        uint16_t msgSize;
        uint16_t blockLength;
        uint16_t templateID;
        uint16_t schemaID;
        uint16_t version;
    };

    // PCAP Packet Header (16 bytes)
    struct PcapPacketHeader {
        uint32_t ts_sec;         // Timestamp seconds
        uint32_t ts_usec;        // Timestamp microseconds
        uint32_t incl_len;       // Number of octets of packet saved in file
        uint32_t orig_len;       // Actual length of packet
    };

public:
    CMEParser(const string& input_file, const string& output_file,
        const std::set<uint16_t>& allowed_templates = {},
        const std::vector<std::string>& custom_header = {})
    : filename(input_file), allowed_template_ids_(allowed_templates), custom_header_(custom_header) {

        intialize_logger();
        csv_file.open(output_file);
        if(!csv_file.is_open()) {
            logger_.log(Logger::ERROR, "Unable to open CSV file: " + output_file);
            throw std::runtime_error("Unable to open CSV file: " + output_file);
        }
        logger_.log(Logger::INFO, "CSV file opened succesfully: " + output_file);
        // Write to CSV header
        // csv_file << "PacketNumber,Timestamp,msgSeqNum,sendingTime,msgSize,blockLength,templateID,schemaID,version,"
                 // << "transactTime,matchEventIndicator,noMDEntries,numInGroup,highLimitPrice,lowLimitPrice\n";
        write_header(custom_header_);
    }

    ~CMEParser() {
        if (csv_file.is_open()) {
            csv_file.close();
        }
    }

    void intialize_logger() {
        logger_.enable_level(Logger::INFO);
        logger_.enable_level(Logger::FOCUS);
        // logger_.enable_level(Logger::DEBUG);
        logger_.enable_level(Logger::ERROR);
        logger_.enable_level(Logger::WARNING);
    }

    // UTILITY FUNCTIONS

    // Convert hex string to std::vector<uint8_t>
    std::vector<uint8_t> hex_string_to_vector(const std::string& hex_string) {
        std::vector<uint8_t> byte_vector;
        std::istringstream hex_stream(hex_string);
        std::string byte_str;

        while (hex_stream >> byte_str) {
            uint8_t byte = static_cast<uint8_t>(std::stoul(byte_str, nullptr, 16));
            byte_vector.push_back(byte);
        }

        return byte_vector;
    }

    std::string format_timestamp(uint32_t ts_sec, uint32_t ts_usec) {
        // Convert ts_sec to HH:MM:SS using gmtime
        std::time_t raw_time = static_cast<std::time_t>(ts_sec);
        std::tm* timeinfo = std::gmtime(&raw_time);

        // Format as HH:MM:SS.UUUUUU
        std::ostringstream oss;
        oss << std::setfill('0') << std::setw(2) << timeinfo->tm_hour << ":"
            << std::setw(2) << timeinfo->tm_min << ":"
            << std::setw(2) << timeinfo->tm_sec << "."
            << std::setw(6) << ts_usec; // Append microseconds

        return oss.str();
    }

    // Util function to extract a field from a std::vector<uint8_t> at a specific offset and
    // advance offset automatically
    template <typename T>
    T extract_field(const std::vector<uint8_t>& data, size_t& offset) {
        if (offset + sizeof(T) > data.size()) {
            throw std::runtime_error("Not enough data to extract field");
        }

        T field;
        std::memcpy(&field, data.data() + offset, sizeof(T));
        // logger_.log(Logger::FOCUS, "offset: " + offset + " value: " + );
        cout << "[SPECIAL DEBUG] offset: " << offset << " value: " << field << hex << "     " << field << dec << endl;
        offset += sizeof(T);
        return field;
    }

    // Skip (num_bytes) amount of bytes from a std::vector<uint8_t> and advance offset automatically
    void skip_bytes(size_t num_bytes, const std::vector<uint8_t>& data, size_t& offset) {
        if (offset + num_bytes > data.size()) {
            throw std::runtime_error("Not enough data to skip bytes");
        }
        offset += num_bytes;
    }

    // Extract a custom N-length string field from a std::vector<uint8_t> and automatically advanced offset
    std::string extract_fixed_length_string(size_t length, const std::vector<uint8_t>& data, size_t& offset) {
        // exclusive?

        if (offset + length > data.size()) {
            throw std::runtime_error("Not enough data to extract string");
        }



        std::string result(reinterpret_cast<const char*>(data.data() + offset), length);
        cout << "[SPECIAL DEBUG] offset: " << offset << " value: " << result << " ";
        for (size_t i = offset; i < offset + length; ++i) {
            cout << " " << static_cast<int>(data.at(i));
        }
        cout << endl;


        offset += length;
        return result;
    }

    // Extract a null-terminated string from a std::vector<uint8_t> and automatically advance offset
    std::string extract_null_terminated_string(const std::vector<uint8_t>& data, size_t& offset) {
        size_t start_offset = offset;
        while (offset < data.size() && data[offset] != '\0') {
            ++offset;
        }
        if (offset == data.size()) {
            throw std::runtime_error("Null-terminated string not found");
        }
        std::string result(reinterpret_cast<const char*>(data.data() + start_offset), offset - start_offset);
        ++offset; // Skip the null terminator
        return result;
    }

    // Print out all the bits from a given byte (usually uint8_t interpreted as char)
    void print_bits(uint8_t value) {
        std::cout << "Bits: ";
        for (int i = 7; i >= 0; --i) { // Iterate from MSB to LSB
            std::cout << ((value >> i) & 1);
        }
        std::cout << std::endl;
    }

    // Print DEBUG info for a uint8
    void print_uint8_info(uint8_t value) {
        std::cout << "Decimal: " << static_cast<int>(value)
                  << ", Hex: 0x" << std::hex << static_cast<int>(value)
                  << ", Bits: ";
        for (int i = 7; i >= 0; --i) {
            std::cout << ((value >> i) & 1);
        }
        std::cout << std::dec << std::endl;
    }

    // print price with consideration of exponent
    void print_price_with_exponent(int64_t mantissa, int8_t exponent, const std::string& field_name) {
        // Check for null value
        if (mantissa == INT64_MAX) {
            std::cout << field_name << ": NULL" << std::endl;
            return;
        }

        // Compute the value using the exponent
        double price = mantissa * std::pow(10, exponent);

        // Print the result
        std::cout << field_name << ": " << price << std::endl;
    }

    // Generalized debug function
    template <typename T>
    void debug_field(const std::string& field_name, const T& value) {
        std::cout << std::left << std::setw(25) << field_name << ": " << value << std::endl;
    }

    // Specialization for uint8_t to print as integer and binary
    void debug_field(const std::string& field_name, uint8_t value) {
        std::cout << std::left << std::setw(25) << field_name << ": "
                  << static_cast<int>(value) << " (0b" << std::bitset<8>(value) << ")" << std::endl;
    }

    // Specialization for int8_t to print as integer
    void debug_field(const std::string& field_name, int8_t value) {
        std::cout << std::left << std::setw(25) << field_name << ": " << static_cast<int>(value) << std::endl;
    }

    // Specialization for string
    void debug_field(const std::string& field_name, const std::string& value) {
        std::cout << std::left << std::setw(25) << field_name << ": " << value << std::endl;
    }

    // Debug price with exponent
    void debug_price_with_exponent(const std::string& field_name, int64_t price, int8_t exponent) {
        double real_price = static_cast<double>(price) * std::pow(10, exponent);
        std::cout << std::left << std::setw(25) << field_name << ": " << price
                  << " (Exponent: " << static_cast<int>(exponent) << ", Real: " << real_price << ")" << std::endl;
    }

    // Print unique template IDs and their counts
    void print_template_statistics() {
        logger_.log(Logger::INFO, "Template Statistics");
        for (const auto& entry : template_count_) {
            std::cout << "TemplateID: " << entry.first << ", Count: " << entry.second << "\n";
        }
    }


    // PARSING

    std::vector<std::string> parse_template_50_FULL(const std::vector<uint8_t>& packet_data, size_t& offset) {
        logger_.log(Logger::DEBUG, "Parsing template 50_LBM...");

        struct SBE_LBM {
            uint64_t transactTime;
            uint8_t matchEventIndicator;
            // 2 byte padding
            uint16_t noMDEntries;
            uint8_t numInGroup;
            int64_t highLimitPrice; // (null value as 9223372036854775807 for the mantissa)
            int64_t lowLimitPrice;
            // not part but int8 exponent (-9), constant as -9 for PRICENULL 9, not sent in SBE
            // message on wire, and not part of block length calculation
            int64_t maxPriceVariation;
            // not part but int8 exponent (-9), constant as -9 for PRICENULL 9, not sent in SBE
            // message on wire, and not part of block length calculation
            int32_t securityID;
            uint32_t rptSeq;
            // MDUpateAction uint8 -- 0 -- dfined as 0 constant (not sent in SBE message), not part of block length
            // MDEntryType char -- g -- constant, not part of block length calculation
        };

        SBE_LBM sbe_lbm;
        sbe_lbm.transactTime = extract_field<uint64_t>(packet_data, offset);
        sbe_lbm.matchEventIndicator = extract_field<uint8_t>(packet_data, offset);
        skip_bytes(2, packet_data, offset);
        sbe_lbm.noMDEntries = extract_field<uint16_t>(packet_data, offset);
        sbe_lbm.numInGroup = extract_field<uint8_t>(packet_data, offset);
        sbe_lbm.highLimitPrice = extract_field<int64_t>(packet_data, offset);
        sbe_lbm.lowLimitPrice = extract_field<int64_t>(packet_data, offset);
        sbe_lbm.maxPriceVariation = extract_field<int64_t>(packet_data, offset);
        sbe_lbm.securityID = extract_field<int32_t>(packet_data, offset);
        sbe_lbm.rptSeq = extract_field<uint32_t>(packet_data, offset);

        if(logger_.is_level_enabled(Logger::DEBUG)) {
            std::cout << "\n[DEBUG] ==== SBE_LBM Message ==== [DEBUG]" << std::endl;
            std::cout << "transactTime: " << sbe_lbm.transactTime << std::endl;
            std::cout << "matchEventIndicator: " << std::hex << static_cast<int>(sbe_lbm.matchEventIndicator) << std::dec << std::endl;
            print_uint8_info(sbe_lbm.matchEventIndicator);
            std::cout << "noMDEntries: " << sbe_lbm.noMDEntries << std::endl;
            std::cout << "numInGroup: " << sbe_lbm.numInGroup << std::endl;
            print_uint8_info(sbe_lbm.numInGroup);
            std::cout << "highLimitPrice: " << sbe_lbm.highLimitPrice << std::endl;
            std::cout << "lowLimitPrice: " << sbe_lbm.lowLimitPrice << std::endl;
            std::cout << "maxPriceVariation: " << sbe_lbm.maxPriceVariation << std::endl;
            std::cout << "securityID: " << sbe_lbm.securityID << std::endl;
            std::cout << "rptSeq: " << sbe_lbm.rptSeq << std::endl;
        }

        std::vector<std::string> additional_fields(6,"");
        additional_fields[0] = sbe_lbm.transactTime;
        additional_fields[1] = sbe_lbm.matchEventIndicator;
        additional_fields[2] = sbe_lbm.noMDEntries;
        additional_fields[3] = sbe_lbm.numInGroup;
        additional_fields[4] = sbe_lbm.highLimitPrice;
        additional_fields[5] = sbe_lbm.lowLimitPrice;
        return additional_fields;
    }

    std::vector<std::string> parse_template_55_FULL(const std::vector<uint8_t>& packet_data, size_t& offset) {
        logger_.log(Logger::DEBUG, "Parsing template 55_O...");

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

            char userDefinedInstrument;     // Offset 210: User-defined instrument flag ('Y' or 'N').
            uint16_t tradingReferenceDate;  // Offset 211: Session date for settlement price.
        };

        SBE_O_55 sbe_55;

        // Extract fields
        sbe_55.matchEventIndicator = extract_field<uint8_t>(packet_data, offset);
        sbe_55.totNumReports = extract_field<uint32_t>(packet_data, offset);
        if (sbe_55.totNumReports == 0xFFFFFFFF) {
            sbe_55.totNumReports = 0; // Handle null value
        }

        sbe_55.securityUpdateAction = extract_field<int8_t>(packet_data, offset);
        std::string securityUpdateActionStr(1, static_cast<char>(sbe_55.securityUpdateAction));
        if (sbe_55.securityUpdateAction != 'A' && sbe_55.securityUpdateAction != 'D' && sbe_55.securityUpdateAction != 'M') {
            std::cerr << "\n[WARN] Invalid securityUpdateAction: " << static_cast<int>(sbe_55.securityUpdateAction) << std::endl;
        }

        sbe_55.lastUpdateTime = extract_field<uint64_t>(packet_data, offset);
        // if (sbe_55.lastUpdateTime > 1e18) { // Check for implausible timestamp
        //     std::cerr << "\n[WARN] Invalid lastUpdateTime: " << sbe_55.lastUpdateTime << std::endl;
        //     sbe_55.lastUpdateTime = 0;
        // }

        sbe_55.mDSecurityTradingStatus = extract_field<int8_t>(packet_data, offset);
        if (sbe_55.mDSecurityTradingStatus < 0 || sbe_55.mDSecurityTradingStatus > 103) {
            std::cerr << "\n[WARN] Invalid mDSecurityTradingStatus: " << static_cast<int>(sbe_55.mDSecurityTradingStatus) << std::endl;
        }

        sbe_55.appID = extract_field<int16_t>(packet_data, offset);
        sbe_55.marketSegmentID = extract_field<uint8_t>(packet_data, offset);
        sbe_55.underlyingProduct = extract_field<uint8_t>(packet_data, offset);
        if (sbe_55.underlyingProduct > 17) {
            std::cerr << "\n[WARN] Invalid underlyingProduct: " << static_cast<int>(sbe_55.underlyingProduct) << std::endl;
        }

        sbe_55.securityExchange = extract_fixed_length_string(4, packet_data, offset);
        sbe_55.securityGroup = extract_fixed_length_string(6, packet_data, offset);
        sbe_55.asset = extract_fixed_length_string(6, packet_data, offset);
        sbe_55.symbol = extract_fixed_length_string(19, packet_data, offset);

        sbe_55.securityID = extract_field<int32_t>(packet_data, offset);
        sbe_55.securityIDSource = extract_field<int8_t>(packet_data, offset);
        if (sbe_55.securityIDSource != '8') { // '8' is the expected value for CME
            std::cerr << "\n[WARN] Invalid securityIDSource: " << static_cast<int>(sbe_55.securityIDSource) << std::endl;
        }

        sbe_55.securityType = extract_fixed_length_string(6, packet_data, offset);
        sbe_55.cFICode = extract_fixed_length_string(6, packet_data, offset);

        sbe_55.putOrCall = extract_field<int8_t>(packet_data, offset);
        if (sbe_55.putOrCall != 0 && sbe_55.putOrCall != 1) {
            std::cerr << "\n[WARN] Invalid putOrCall: " << static_cast<int>(sbe_55.putOrCall) << std::endl;
        }

        sbe_55.maturityMonthYear = extract_fixed_length_string(5, packet_data, offset);
        if (sbe_55.maturityMonthYear.length() < 4 || !std::isdigit(sbe_55.maturityMonthYear[0])) {
            std::cerr << "\n[WARN] Invalid maturityMonthYear: " << sbe_55.maturityMonthYear << std::endl;
        }

        sbe_55.currency = extract_fixed_length_string(3, packet_data, offset);

        sbe_55.strikePrice = extract_field<int64_t>(packet_data, offset);
        if (sbe_55.strikePrice == 0x7FFFFFFFFFFFFFFF) {
            sbe_55.strikePrice = 0; // Handle null value
        }
        sbe_55.strikeCurrency = extract_fixed_length_string(3, packet_data, offset);
        sbe_55.settlCurrency = extract_fixed_length_string(3, packet_data, offset);

        sbe_55.minCabPrice = extract_field<int64_t>(packet_data, offset);
        if (sbe_55.minCabPrice == 0x7FFFFFFFFFFFFFFF) {
            sbe_55.minCabPrice = 0; // Handle null value
        }

        // DEBUG to INFO
        if(logger_.is_level_enabled(Logger::FOCUS)) {
            std::cout << "\n[DEBUG] ==== 55 Message ==== [DEBUG]" << std::endl;

            debug_field("matchEventIndicator", sbe_55.matchEventIndicator);
            debug_field("totNumReports", sbe_55.totNumReports);
            debug_field("securityUpdateAction", sbe_55.securityUpdateAction);
            debug_field("lastUpdateTime", sbe_55.lastUpdateTime);
            debug_field("mDSecurityTradingStatus", sbe_55.mDSecurityTradingStatus);
            debug_field("appID", sbe_55.appID);
            debug_field("marketSegmentID", sbe_55.marketSegmentID);
            debug_field("underlyingProduct", sbe_55.underlyingProduct);
            debug_field("securityExchange", sbe_55.securityExchange);
            debug_field("securityGroup", sbe_55.securityGroup);
            debug_field("asset", sbe_55.asset);
            debug_field("symbol", sbe_55.symbol);
            debug_field("securityID",sbe_55.securityID);
            debug_field("securityIDSource",sbe_55.securityIDSource);
            debug_field("securityType",sbe_55.securityType);
            debug_field("cFICode",sbe_55.cFICode);
            debug_field("putOrCall",sbe_55.putOrCall);
            debug_field("maturityMonthYear",sbe_55.maturityMonthYear);
            debug_field("currency",sbe_55.currency);
            debug_price_with_exponent("strikePrice", sbe_55.strikePrice, -9);
            debug_field("strikeCurrency",sbe_55.strikeCurrency);
            debug_field("settlCurrency",sbe_55.settlCurrency);
            debug_price_with_exponent("minCabPrice", sbe_55.minCabPrice, -9);
            debug_field()
        }

        std::vector<std::string> row;
        row = {
            std::to_string(sbe_55.matchEventIndicator),
            std::to_string(sbe_55.totNumReports),
            securityUpdateActionStr,
            std::to_string(sbe_55.lastUpdateTime),
            std::to_string(sbe_55.mDSecurityTradingStatus),
            std::to_string(sbe_55.appID),
            std::to_string(sbe_55.marketSegmentID),
            std::to_string(sbe_55.underlyingProduct),
            sbe_55.asset,
            sbe_55.symbol,
            to_string(sbe_55.putOrCall)

        };

        return row;
    }



    // Further parses the rest of the packet payload based on templateID, will switch and choose
    // the correct one
    std::vector<std::string> parse_by_template_id(uint16_t templateID, const std::vector<uint8_t>& packet_data, size_t& offset) {
        if(logger_.is_level_enabled(Logger::DEBUG)) std::cout << "\n<<< Attempting to parse templateID [" << templateID << "] >>>" << std::endl;
        switch (templateID) {
            case 50:
                return parse_template_50_FULL(packet_data, offset);
            break;
            case 55:
                return parse_template_55_FULL(packet_data, offset);
            // case 2:
            //     // parse_template_2(packet_data, offset);
            //     std::cout << "parsing case 2" << std::endl;
            // break;
            // Add cases for other templateIDs
            default:
                if(logger_.is_level_enabled(Logger::DEBUG)) std::cerr << "Unknown templateID: " << templateID << std::endl;
            return vector<std::string>(6,"");
            break;
        }
    }

    std::vector<std::string> process_payload(const std::vector<uint8_t>& payload_data) {
        std::vector<std::string> row;

        if (payload_data.size() < sizeof(TechnicalHeader)) {
            throw std::runtime_error("Payload data too small to contain TechnicalHeader");
        }


        // Store offset to advance through packet data
        size_t offset = 0;

        // Parse TechnicalHeader
        TechnicalHeader tech_header;
        // Can't parse whole struct because of padding, so parse struct individually and copy
        // data with memcpy to new struct
        // std::memcpy(&tech_header.msgSeqNum, packet_data.data(), sizeof(tech_header.msgSeqNum));
        // std::memcpy(&tech_header.sendingTime, packet_data.data() + sizeof(tech_header.msgSeqNum), sizeof(tech_header.sendingTime));

        // New method is faster
        tech_header.msgSeqNum = extract_field<uint32_t>(payload_data, offset);
        tech_header.sendingTime = extract_field<uint64_t>(payload_data, offset);

        if(logger_.is_level_enabled(Logger::DEBUG)) {
            std::cout << "\n==== PCAP Technical Header ====" << std::endl;
            std::cout << "msgSeqNum: " << tech_header.msgSeqNum << std::endl;
            std::cout << "sendingTime: " << tech_header.sendingTime << std::endl;
        }

        // Ensure enough data for CME Message header
        if (payload_data.size() < offset + sizeof(CMEMessageHeader)) {
            throw std::runtime_error("Payload data too small to contain CMEMessageHeader");
        }

        // Parse CME Message Header
        CMEMessageHeader cme_header;
        cme_header.msgSize = extract_field<uint16_t>(payload_data,offset);
        cme_header.blockLength = extract_field<uint16_t>(payload_data,offset);
        cme_header.templateID = extract_field<uint16_t>(payload_data,offset);
        cme_header.schemaID = extract_field<uint16_t>(payload_data,offset);
        cme_header.version = extract_field<uint16_t>(payload_data,offset);

        if(logger_.is_level_enabled(Logger::DEBUG)) {
            std::cout << "\n==== CME Message Header ====" << std::endl;
            std::cout << "msgSize: " << cme_header.msgSize << std::endl;
            std::cout << "blockLength: " << cme_header.blockLength << std::endl;
            std::cout << "templateID: " << cme_header.templateID << std::endl;
            std::cout << "schemaID: " << cme_header.schemaID << std::endl;
            std::cout << "version: " << cme_header.version << std::endl;
        }

        // Count occurences of each template
        template_count_[cme_header.templateID]++;

        // Filter by allowed template IDs (if not ALL)
        if (!allowed_template_ids_.empty() && allowed_template_ids_.find(cme_header.templateID) == allowed_template_ids_.end()) {
            logger_.log(Logger::DEBUG, "Skipping templateID: " + std::to_string(cme_header.templateID));
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

        // Add additional fields from template-specific parsing. Dispatch parsing based on templateID
        std::vector<std::string> additional_fields = parse_by_template_id(cme_header.templateID, payload_data, offset);
        row.insert(row.end(), additional_fields.begin(), additional_fields.end());

        return row;
    }

    std::vector<std::string> process_single_packet(const std::vector<uint8_t>& packet_data, size_t packet_number, const PcapPacketHeader& pcap_header) {
        // vector structure as CSV line
        std::vector<std::string> row;

        // Ensure enough data for TechnicalHeader -- sanity check
        // if(packet_data.size() < sizeof(TechnicalHeader)) {
        //     throw std::runtime_error("Packet data too small to contain TechnicalHeader");
        // }

        // Now check whole payload
        if (packet_data.size() < 42) {
            if (logger_.is_level_enabled(Logger::ERROR)) std::cerr << "Packet too small, skipping.\n";
            row.push_back(std::to_string(packet_number)); // Packet number
            row.push_back(format_timestamp(pcap_header.ts_sec, pcap_header.ts_usec)); // Timestamp
            row.insert(row.end(), 12, ""); // Fill the rest with blanks
            return row;
        }

        // Parse the packet (we have reached the payload -- at byte 42)
        std::vector<uint8_t> payload_data(packet_data.begin() + 42, packet_data.end());

        // Process payload
        row = process_payload(payload_data);

        // Skip if payload is empty (non-allowed template)
        if (row.empty()) return {};

        // Add packet metadata
        row.insert(row.begin(), {
            std::to_string(packet_number), // Packet num
            format_timestamp(pcap_header.ts_sec, pcap_header.ts_usec) // Time stamp
        });

        return row;
    }

    // Convert row vector to CSV
    void write_to_csv(const std::vector<std::vector<std::string>>& rows) {
        for (const auto& row : rows) {
            for (size_t i = 0; i < row.size(); ++i) {
                csv_file << row[i];
                if (i < row.size() - 1) {
                    csv_file << ",";
                }
            }
            csv_file << "\n";
        }
    }

    void write_header(const std::vector<std::string>& row) {
        if (!custom_header_.empty()) {
            for (size_t i = 0; i < custom_header_.size(); ++i) {
                csv_file << custom_header_[i];
                if (i < custom_header_.size() - 1) {
                    csv_file << ",";
                }
            }
        } else {
            for (size_t i = 0; i < row.size(); ++i) {
                csv_file << "Field" << i + 1; // Default header naming
                if (i < row.size() - 1) {
                    csv_file << ",";
                }
            }
        }
        csv_file << "\n";
    }

    // process N amount of packets
    void process_packets(size_t total_packets, size_t batch_size, size_t start_packet = 1, size_t end_packet = 0) {
        logger_.log(Logger::INFO, "Processing " + std::to_string(total_packets) +  " packets from " + std::to_string(start_packet) +
                                 " to " + std::to_string(end_packet) +
                                 " in batches of " + std::to_string(batch_size));

        // Safety checks
        if(batch_size > total_packets) {
            throw std::runtime_error("Batch size of " + std::to_string(batch_size) + " is greater then " + std::to_string(total_packets) + " packets. Your batch size cannot be greater then your total packet count.");
        }

        if(batch_size < 1 || total_packets < 1) {
            throw std::runtime_error("Batch size and total packets cannot be less than 1.");
        }

        if(end_packet != 0 && end_packet < start_packet) {
            throw std::runtime_error("Your end packet number must be greater then your start packet number.");
        }

        // Does the file even exist?
        input_file.open(filename, ios::binary);
        if (!input_file.is_open()) {
            throw std::runtime_error("Unable to open file: " + filename);
        }

        // Skip the PCAP Global Header (24 bytes)
        input_file.ignore(24);

        std::vector<std::vector<std::string>> batch_data;

        size_t current_packet = 1; // Start at the first packet
        size_t processed_packets = 0;
        size_t batches = 0;

        // Default 'end_packet' to the total number of packets if not specified
        if (end_packet == 0 || end_packet > total_packets) {
            end_packet = total_packets;
            if(end_packet < start_packet) {
                throw std::runtime_error("Your end packet number must be greater then your start packet number. In this case, "
                                         "it's likely that the total packets you set is lower than your end packet. The value"
                                         " of your end packet number must fit within the total packet range (e.g. 1000 -> (0 to 10000)");
            }
        }

        while (processed_packets < total_packets && current_packet <= end_packet) {
            PcapPacketHeader pcap_header;
            // Read the PCAP Packet Header
            input_file.read(reinterpret_cast<char*>(&pcap_header), sizeof(PcapPacketHeader));
            if (input_file.eof()) break;

            // Skip packets outside the specified range
            if (current_packet < start_packet) {
                input_file.ignore(pcap_header.incl_len);
                current_packet++;
                continue;
            }

            // Read the N-th packet payload (up to incl_len bytes)
            std::vector<uint8_t> packet_data(pcap_header.incl_len);
            input_file.read(reinterpret_cast<char*>(packet_data.data()), pcap_header.incl_len);
            if (input_file.eof()) break;

            try {
                std::vector<std::string> row = process_single_packet(packet_data, current_packet, pcap_header);
                if (!row.empty()) {     // Only add rows for allowed templates
                    batch_data.push_back(row);
                }
            } catch (const std::exception& e) {
                logger_.log(Logger::ERROR, "Error processing packet " + std::to_string(current_packet) + ": " + e.what());
            }

            // Write in batches
            if (batch_data.size() >= batch_size) {
                ++batches;
                logger_.log(Logger::INFO, "Finished batch number " + std::to_string(batches) + " and processed " + std::to_string(processed_packets+1) + " packets.");
                write_to_csv(batch_data);
                batch_data.clear();
            }

            ++processed_packets;
            ++current_packet;
        }

        // Write remaining data
        if (!batch_data.empty()) {
            logger_.log(Logger::INFO, "Processing remaining " + std::to_string(batch_data.size()) + " packets.");
            write_to_csv(batch_data);
        }

        input_file.close();
        std::cout << "\n";
        logger_.log(Logger::INFO, "Finished >>> Processed " + std::to_string(processed_packets) + " packets.\n");
    }

    void process_nth_packet(size_t packet_number) {
        input_file.open(filename, ios::binary);
        if (!input_file.is_open()) {
            throw runtime_error("Unable to open file: " + filename);
        }

        std::cout << "\n <<<< START: PACKET [" << packet_number << "] START >>>>" << std::endl;

        // Skip the PCAP Global Header (24 bytes)
        input_file.ignore(24);

        // Read the first PCAP Packet Header (16 bytes)
        PcapPacketHeader pcap_header;
        for (size_t i = 1; i < packet_number; ++i) {

            // Read the PCAP Packet Header
            input_file.read(reinterpret_cast<char*>(&pcap_header), sizeof(PcapPacketHeader));

            // Skip the packet data (incl_len bytes)
            input_file.ignore(pcap_header.incl_len);

            if(input_file.eof()) {
                throw std::runtime_error("Reached end of file before finding packet " + std::to_string(packet_number));
            }
        }

        // Read the N-th packet header
        input_file.read(reinterpret_cast<char*>(&pcap_header), sizeof(PcapPacketHeader));
        if (input_file.eof()) {
            throw std::runtime_error("Reached end of file before finding packet " + std::to_string(packet_number));
        }

        // Convert timestamp to human-readable format
        std::string converted_time = format_timestamp(pcap_header.ts_sec, pcap_header.ts_usec);

        std::cout << "\n ==== [" << packet_number << "] Header General Info ====" << std::endl;
        std::cout << "Timestamp: " << pcap_header.ts_sec << "." << pcap_header.ts_usec << std::endl;
        std::cout << "Converted Timestamp: " << converted_time << std::endl;
        std::cout << "Included Length: " << pcap_header.incl_len << " bytes" << std::endl;

        // Read the N-th packet payload (up to incl_len bytes)
        std::vector<uint8_t> packet_data(pcap_header.incl_len);
        input_file.read(reinterpret_cast<char*>(packet_data.data()), pcap_header.incl_len);
        if (input_file.eof()) {
            throw std::runtime_error("Reached end of file while reading packet data.");
        }
        // if (packet_data.size() < 42) {
        //     throw std::runtime_error("Packet too small to contain expected headers (42 bytes).");
        // }

        // Parse the packet (we have reached the payload -- at byte 42)
        // std::vector<uint8_t> payload_data(packet_data.begin() + 42, packet_data.end());
        // parse_packet(payload_data);
        std::vector<std::string> row = process_single_packet(packet_data, packet_number, pcap_header);
        // std::vector<std::vector<std::string>> test_row;
        // test_row.push_back(row);

        // Print the raw byte stream
        if(advanced_debug) {
            std::cout << "\n ==== [" << packet_number << "] Raw Byte Stream ====" << std::endl;
            const int NUM_ROWS_PRINT = 100000000;
            int row_printed_count = 0;
            for (size_t i = 0; i < packet_data.size(); ++i) {
                std::cout << std::hex << std::setw(2) << std::setfill('0')
                          << static_cast<int>(packet_data[i]) << " ";
                if ((i + 1) % 16 == 0) {
                    row_printed_count++;
                    if(row_printed_count >= NUM_ROWS_PRINT) break;
                    std::cout << std::endl;
                }
            }
            std::cout << std::dec << std::endl;
        }

        // Print row for debug
        std::cout << "\n ==== ROW PRINT [" << packet_number << "] DEBUG ====" << std::endl;
        for (size_t i = 0; i < row.size(); ++i) {
            std::cout << row[i];
            if (i < row.size() - 1)
                std::cout << ",";
        }
        std::cout << std::endl;

        std::cout << "\n <<<< END: PACKET [" << packet_number << "] END >>>>" << std::endl;

        input_file.close();
    }
};

int main() {
    try {
        // Logger::LogLevel log_level = Logger::DEBUG;

        // Set I/O
        string input_file = "C:/data/dev/OneTickPersonal/CMEDecoder/PCAPParser/data/dc3-glbx-a-20230716T110000.pcap";
        string output_file = "C:/data/dev/OneTickPersonal/CMEDecoder/PCAPParser/output/result.csv";

        // Specify allowed template IDs
        std::set<uint16_t> allowed_templates = {};

        // Specify custom header (OPTIONAL)
        std::vector<std::string> custom_header = {
            "PacketNumber", "Timestamp", "msgSeqNum", "sendingTime",
            "msgSize", "blockLength", "templateID", "schemaID", "version",
            "transactTime", "matchEventIndicator", "noMDEntries", "numInGroup",
            "highLimitPrice", "lowLimitPrice"
        };

        CMEParser parser(input_file, output_file, allowed_templates, custom_header);
        parser.process_nth_packet(5);
        // parser.process_packets(1000000, 100000);
        // // parser.process_nth_packet(10);
        // parser.process_nth_packet(21);

        // Print template statistics
        parser.print_template_statistics();

        std::cout << "\n[SYSTEM] Processing complete. Have an excellent day user. Results written to " << output_file << std::endl;

        /* VALIDATE PACKET PAYLOAD PARSING WITH CME EXAMPLE */
        // std::string hex_stream = "A6 BB 0A 00 5B 19 01 72 1E EF A9 16 38 00 0B 00 32 00 01 00 09 00 4B 52 E8 71 1E EF A9 16 00 00 00 20 00 01 FF FF FF FF FF FF FF 7F 00 90 CD 79 2F 08 00 00 00 E4 0B 54 02 00 00 00 F4 15 00 00 4D 07 00 00";
        // std::vector<uint8_t> packet_data = parser.hex_string_to_vector(hex_stream);
        // try {
        //     parser.process_payload(packet_data);
        // } catch (const std::exception& e) {
        //     std::cerr << "error: " << e.what() << std::endl;
        // }

    } catch (const exception& e) {
        cerr << "Error: " << e.what() << endl;
        return 1;
    }
    return 0;
}