//
// Created by hruks on 11/17/2024.
//

#include "fast_cme_parser.h"

#include "MDIncrementalRefreshOrderBook47.h"



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

class CMEOrderBookDecoder {
private:
    std::ofstream csv_file;

    // Helper function to convert timestamp to human readable format
    std::string formatTimestamp(uint64_t nanoseconds) {
        time_t seconds = nanoseconds / 1000000000;
        auto ms = (nanoseconds % 1000000000) / 1000000;
        char buffer[30];
        struct tm* timeinfo = localtime(&seconds);
        strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", timeinfo);
        std::stringstream ss;
        ss << buffer << "." << std::setfill('0') << std::setw(3) << ms;
        return ss.str();
    }

public:
    CMEOrderBookDecoder(const std::string& output_file) {
        csv_file.open(output_file);
        writeHeader();
    }

    ~CMEOrderBookDecoder() {
        if (csv_file.is_open()) {
            csv_file.close();
        }
    }

    void writeHeader() {
        csv_file << "Timestamp,SecurityID,OrderID,Price,Quantity,Side,UpdateAction,Priority\n";
    }

    void decode(const char* buffer, size_t length) {
        MDIncrementalRefreshOrderBook47Decoder decoder;
        decoder.wrapForDecode(buffer, 0, decoder.sbeBlockLength(), decoder.sbeSchemaVersion());

        // Get message header information
        uint64_t transactTime = decoder.transactTime();
        std::string formattedTime = formatTimestamp(transactTime);

        // Process all entries in the message
        auto& entries = decoder.noMDEntries();
        while (entries.hasNext()) {
            auto& entry = entries.next();

            // Extract order details
            uint64_t orderId = entry.orderID();
            uint64_t priority = entry.mDOrderPriority();

            // Handle price (using PRICE9 format)
            auto priceData = entry.mDEntryPx();
            double price = priceData.mantissa() * std::pow(10, priceData.exponent());

            int32_t quantity = entry.mDDisplayQty();
            int32_t securityId = entry.securityID();
            auto updateAction = entry.mDUpdateAction();
            auto entryType = entry.mDEntryType();

            // Convert update action to string
            std::string actionStr;
            switch (updateAction) {
                case MDUpdateAction::New: actionStr = "NEW"; break;
                case MDUpdateAction::Change: actionStr = "CHANGE"; break;
                case MDUpdateAction::Delete: actionStr = "DELETE"; break;
                default: actionStr = "UNKNOWN";
            }

            // Convert entry type to side
            std::string side = (entryType == MDEntryTypeBook::Bid) ? "BID" : "ASK";

            // Write to CSV
            csv_file << formattedTime << ","
                    << securityId << ","
                    << orderId << ","
                    << std::fixed << std::setprecision(6) << price << ","
                    << quantity << ","
                    << side << ","
                    << actionStr << ","
                    << priority << "\n";
        }
        csv_file.flush();
    }
};

// Example usage
int main() {
    CMEOrderBookDecoder decoder("orderbook.csv");

    // Read your binary file and process it
    std::ifstream input("CME_Example.pcap", std::ios::binary);
    if (input.is_open()) {
        // Read file in chunks
        // constexpr size_t BUFFER_SIZE = 8192;
        // char buffer[BUFFER_SIZE];

        // while (input.read(buffer, BUFFER_SIZE)) {
        //     size_t bytesRead = input.gcount();
        //     decoder.decode(buffer, bytesRead);
        // }
        cout << "Reading input!" << endl;
        input.close();
    }
    return 0;
}