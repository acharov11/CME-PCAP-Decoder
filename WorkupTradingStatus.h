/* Generated SBE (Simple Binary Encoding) message codec */
#ifndef _MKTDATA_WORKUPTRADINGSTATUS_CXX_H_
#define _MKTDATA_WORKUPTRADINGSTATUS_CXX_H_

#if !defined(__STDC_LIMIT_MACROS)
#  define __STDC_LIMIT_MACROS 1
#endif

#include <cstdint>
#include <iomanip>
#include <limits>
#include <ostream>
#include <stdexcept>
#include <sstream>
#include <string>

#define SBE_NULLVALUE_INT8 (std::numeric_limits<std::int8_t>::min)()
#define SBE_NULLVALUE_INT16 (std::numeric_limits<std::int16_t>::min)()
#define SBE_NULLVALUE_INT32 (std::numeric_limits<std::int32_t>::min)()
#define SBE_NULLVALUE_INT64 (std::numeric_limits<std::int64_t>::min)()
#define SBE_NULLVALUE_UINT8 (std::numeric_limits<std::uint8_t>::max)()
#define SBE_NULLVALUE_UINT16 (std::numeric_limits<std::uint16_t>::max)()
#define SBE_NULLVALUE_UINT32 (std::numeric_limits<std::uint32_t>::max)()
#define SBE_NULLVALUE_UINT64 (std::numeric_limits<std::uint64_t>::max)()

namespace mktdata {

class WorkupTradingStatus
{
public:
    enum Value
    {
        ReadyToTrade = static_cast<std::uint8_t>(17),
        NotAvailableForTrading = static_cast<std::uint8_t>(18),
        PrivateWorkup = static_cast<std::uint8_t>(201),
        PublicWorkup = static_cast<std::uint8_t>(202),
        NULL_VALUE = static_cast<std::uint8_t>(255)
    };

    static WorkupTradingStatus::Value get(const std::uint8_t value)
    {
        switch (value)
        {
            case static_cast<std::uint8_t>(17): return ReadyToTrade;
            case static_cast<std::uint8_t>(18): return NotAvailableForTrading;
            case static_cast<std::uint8_t>(201): return PrivateWorkup;
            case static_cast<std::uint8_t>(202): return PublicWorkup;
            case static_cast<std::uint8_t>(255): return NULL_VALUE;
        }

        throw std::runtime_error("unknown value for enum WorkupTradingStatus [E103]");
    }

    static const char *c_str(const WorkupTradingStatus::Value value)
    {
        switch (value)
        {
            case ReadyToTrade: return "ReadyToTrade";
            case NotAvailableForTrading: return "NotAvailableForTrading";
            case PrivateWorkup: return "PrivateWorkup";
            case PublicWorkup: return "PublicWorkup";
            case NULL_VALUE: return "NULL_VALUE";
        }

        throw std::runtime_error("unknown value for enum WorkupTradingStatus [E103]:");
    }

    template<typename CharT, typename Traits>
    friend std::basic_ostream<CharT, Traits> & operator << (
        std::basic_ostream<CharT, Traits> &os, WorkupTradingStatus::Value m)
    {
        return os << WorkupTradingStatus::c_str(m);
    }
};

}

#endif
