/* Generated SBE (Simple Binary Encoding) message codec */
#ifndef _MKTDATA_MDINSTRUMENTDEFINITIONFUTURE54_CXX_H_
#define _MKTDATA_MDINSTRUMENTDEFINITIONFUTURE54_CXX_H_

#if __cplusplus >= 201103L
#  define SBE_CONSTEXPR constexpr
#  define SBE_NOEXCEPT noexcept
#else
#  define SBE_CONSTEXPR
#  define SBE_NOEXCEPT
#endif

#if __cplusplus >= 201703L
#  include <string_view>
#  define SBE_NODISCARD [[nodiscard]]
#else
#  define SBE_NODISCARD
#endif

#if !defined(__STDC_LIMIT_MACROS)
#  define __STDC_LIMIT_MACROS 1
#endif

#include <cstdint>
#include <limits>
#include <cstring>
#include <iomanip>
#include <ostream>
#include <stdexcept>
#include <sstream>
#include <string>
#include <vector>
#include <tuple>

#if defined(WIN32) || defined(_WIN32)
#  define SBE_BIG_ENDIAN_ENCODE_16(v) _byteswap_ushort(v)
#  define SBE_BIG_ENDIAN_ENCODE_32(v) _byteswap_ulong(v)
#  define SBE_BIG_ENDIAN_ENCODE_64(v) _byteswap_uint64(v)
#  define SBE_LITTLE_ENDIAN_ENCODE_16(v) (v)
#  define SBE_LITTLE_ENDIAN_ENCODE_32(v) (v)
#  define SBE_LITTLE_ENDIAN_ENCODE_64(v) (v)
#elif __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#  define SBE_BIG_ENDIAN_ENCODE_16(v) __builtin_bswap16(v)
#  define SBE_BIG_ENDIAN_ENCODE_32(v) __builtin_bswap32(v)
#  define SBE_BIG_ENDIAN_ENCODE_64(v) __builtin_bswap64(v)
#  define SBE_LITTLE_ENDIAN_ENCODE_16(v) (v)
#  define SBE_LITTLE_ENDIAN_ENCODE_32(v) (v)
#  define SBE_LITTLE_ENDIAN_ENCODE_64(v) (v)
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#  define SBE_LITTLE_ENDIAN_ENCODE_16(v) __builtin_bswap16(v)
#  define SBE_LITTLE_ENDIAN_ENCODE_32(v) __builtin_bswap32(v)
#  define SBE_LITTLE_ENDIAN_ENCODE_64(v) __builtin_bswap64(v)
#  define SBE_BIG_ENDIAN_ENCODE_16(v) (v)
#  define SBE_BIG_ENDIAN_ENCODE_32(v) (v)
#  define SBE_BIG_ENDIAN_ENCODE_64(v) (v)
#else
#  error "Byte Ordering of platform not determined. Set __BYTE_ORDER__ manually before including this file."
#endif

#if !defined(SBE_BOUNDS_CHECK_EXPECT)
#  if defined(SBE_NO_BOUNDS_CHECK)
#    define SBE_BOUNDS_CHECK_EXPECT(exp, c) (false)
#  elif defined(_MSC_VER)
#    define SBE_BOUNDS_CHECK_EXPECT(exp, c) (exp)
#  else 
#    define SBE_BOUNDS_CHECK_EXPECT(exp, c) (__builtin_expect(exp, c))
#  endif

#endif

#define SBE_FLOAT_NAN std::numeric_limits<float>::quiet_NaN()
#define SBE_DOUBLE_NAN std::numeric_limits<double>::quiet_NaN()
#define SBE_NULLVALUE_INT8 (std::numeric_limits<std::int8_t>::min)()
#define SBE_NULLVALUE_INT16 (std::numeric_limits<std::int16_t>::min)()
#define SBE_NULLVALUE_INT32 (std::numeric_limits<std::int32_t>::min)()
#define SBE_NULLVALUE_INT64 (std::numeric_limits<std::int64_t>::min)()
#define SBE_NULLVALUE_UINT8 (std::numeric_limits<std::uint8_t>::max)()
#define SBE_NULLVALUE_UINT16 (std::numeric_limits<std::uint16_t>::max)()
#define SBE_NULLVALUE_UINT32 (std::numeric_limits<std::uint32_t>::max)()
#define SBE_NULLVALUE_UINT64 (std::numeric_limits<std::uint64_t>::max)()


#include "MDEntryTypeBook.h"
#include "OpenCloseSettlFlag.h"
#include "MatchEventIndicator.h"
#include "MaturityMonthYear.h"
#include "MDEntryTypeDailyStatistics.h"
#include "EventType.h"
#include "DecimalQty.h"
#include "MDUpdateAction.h"
#include "PRICENULL9.h"
#include "RepoSubType.h"
#include "Side.h"
#include "GroupSize8Byte.h"
#include "HaltReason.h"
#include "PRICE9.h"
#include "MoneyOrPar.h"
#include "MDEntryType.h"
#include "SecurityTradingStatus.h"
#include "LegSide.h"
#include "MessageHeader.h"
#include "OrderUpdateAction.h"
#include "PutOrCall.h"
#include "SecurityTradingEvent.h"
#include "SecurityUpdateAction.h"
#include "Decimal9.h"
#include "MDEntryTypeStatistics.h"
#include "WorkupTradingStatus.h"
#include "InstAttribValue.h"
#include "AggressorSide.h"
#include "SecurityAltIDSource.h"
#include "AggressorFlag.h"
#include "PriceSource.h"
#include "GroupSize.h"
#include "SettlPriceType.h"
#include "Decimal9NULL.h"

namespace mktdata {

class MDInstrumentDefinitionFuture54
{
private:
    char *m_buffer = nullptr;
    std::uint64_t m_bufferLength = 0;
    std::uint64_t m_offset = 0;
    std::uint64_t m_position = 0;
    std::uint64_t m_actingBlockLength = 0;
    std::uint64_t m_actingVersion = 0;

    inline std::uint64_t *sbePositionPtr() SBE_NOEXCEPT
    {
        return &m_position;
    }

public:
    static constexpr std::uint16_t SBE_BLOCK_LENGTH = static_cast<std::uint16_t>(224);
    static constexpr std::uint16_t SBE_TEMPLATE_ID = static_cast<std::uint16_t>(54);
    static constexpr std::uint16_t SBE_SCHEMA_ID = static_cast<std::uint16_t>(1);
    static constexpr std::uint16_t SBE_SCHEMA_VERSION = static_cast<std::uint16_t>(12);
    static constexpr const char* SBE_SEMANTIC_VERSION = "FIX5SP2";

    enum MetaAttribute
    {
        EPOCH, TIME_UNIT, SEMANTIC_TYPE, PRESENCE
    };

    union sbe_float_as_uint_u
    {
        float fp_value;
        std::uint32_t uint_value;
    };

    union sbe_double_as_uint_u
    {
        double fp_value;
        std::uint64_t uint_value;
    };

    using messageHeader = MessageHeader;

    MDInstrumentDefinitionFuture54() = default;

    MDInstrumentDefinitionFuture54(
        char *buffer,
        const std::uint64_t offset,
        const std::uint64_t bufferLength,
        const std::uint64_t actingBlockLength,
        const std::uint64_t actingVersion) :
        m_buffer(buffer),
        m_bufferLength(bufferLength),
        m_offset(offset),
        m_position(sbeCheckPosition(offset + actingBlockLength)),
        m_actingBlockLength(actingBlockLength),
        m_actingVersion(actingVersion)
    {
    }

    MDInstrumentDefinitionFuture54(char *buffer, const std::uint64_t bufferLength) :
        MDInstrumentDefinitionFuture54(buffer, 0, bufferLength, sbeBlockLength(), sbeSchemaVersion())
    {
    }

    MDInstrumentDefinitionFuture54(
        char *buffer,
        const std::uint64_t bufferLength,
        const std::uint64_t actingBlockLength,
        const std::uint64_t actingVersion) :
        MDInstrumentDefinitionFuture54(buffer, 0, bufferLength, actingBlockLength, actingVersion)
    {
    }

    SBE_NODISCARD static SBE_CONSTEXPR std::uint16_t sbeBlockLength() SBE_NOEXCEPT
    {
        return static_cast<std::uint16_t>(224);
    }

    SBE_NODISCARD static SBE_CONSTEXPR std::uint64_t sbeBlockAndHeaderLength() SBE_NOEXCEPT
    {
        return messageHeader::encodedLength() + sbeBlockLength();
    }

    SBE_NODISCARD static SBE_CONSTEXPR std::uint16_t sbeTemplateId() SBE_NOEXCEPT
    {
        return static_cast<std::uint16_t>(54);
    }

    SBE_NODISCARD static SBE_CONSTEXPR std::uint16_t sbeSchemaId() SBE_NOEXCEPT
    {
        return static_cast<std::uint16_t>(1);
    }

    SBE_NODISCARD static SBE_CONSTEXPR std::uint16_t sbeSchemaVersion() SBE_NOEXCEPT
    {
        return static_cast<std::uint16_t>(12);
    }

    SBE_NODISCARD static const char *sbeSemanticVersion() SBE_NOEXCEPT
    {
        return "FIX5SP2";
    }

    SBE_NODISCARD static SBE_CONSTEXPR const char *sbeSemanticType() SBE_NOEXCEPT
    {
        return "d";
    }

    SBE_NODISCARD std::uint64_t offset() const SBE_NOEXCEPT
    {
        return m_offset;
    }

    MDInstrumentDefinitionFuture54 &wrapForEncode(char *buffer, const std::uint64_t offset, const std::uint64_t bufferLength)
    {
        m_buffer = buffer;
        m_bufferLength = bufferLength;
        m_offset = offset;
        m_actingBlockLength = sbeBlockLength();
        m_actingVersion = sbeSchemaVersion();
        m_position = sbeCheckPosition(m_offset + m_actingBlockLength);
        return *this;
    }

    MDInstrumentDefinitionFuture54 &wrapAndApplyHeader(char *buffer, const std::uint64_t offset, const std::uint64_t bufferLength)
    {
        messageHeader hdr(buffer, offset, bufferLength, sbeSchemaVersion());

        hdr
            .blockLength(sbeBlockLength())
            .templateId(sbeTemplateId())
            .schemaId(sbeSchemaId())
            .version(sbeSchemaVersion());

        m_buffer = buffer;
        m_bufferLength = bufferLength;
        m_offset = offset + messageHeader::encodedLength();
        m_actingBlockLength = sbeBlockLength();
        m_actingVersion = sbeSchemaVersion();
        m_position = sbeCheckPosition(m_offset + m_actingBlockLength);
        return *this;
    }

    MDInstrumentDefinitionFuture54 &wrapForDecode(
        char *buffer,
        const std::uint64_t offset,
        const std::uint64_t actingBlockLength,
        const std::uint64_t actingVersion,
        const std::uint64_t bufferLength)
    {
        m_buffer = buffer;
        m_bufferLength = bufferLength;
        m_offset = offset;
        m_actingBlockLength = actingBlockLength;
        m_actingVersion = actingVersion;
        m_position = sbeCheckPosition(m_offset + m_actingBlockLength);
        return *this;
    }

    MDInstrumentDefinitionFuture54 &sbeRewind()
    {
        return wrapForDecode(m_buffer, m_offset, m_actingBlockLength, m_actingVersion, m_bufferLength);
    }

    SBE_NODISCARD std::uint64_t sbePosition() const SBE_NOEXCEPT
    {
        return m_position;
    }

    // NOLINTNEXTLINE(readability-convert-member-functions-to-static)
    std::uint64_t sbeCheckPosition(const std::uint64_t position)
    {
        if (SBE_BOUNDS_CHECK_EXPECT((position > m_bufferLength), false))
        {
            throw std::runtime_error("buffer too short [E100]");
        }
        return position;
    }

    void sbePosition(const std::uint64_t position)
    {
        m_position = sbeCheckPosition(position);
    }

    SBE_NODISCARD std::uint64_t encodedLength() const SBE_NOEXCEPT
    {
        return sbePosition() - m_offset;
    }

    SBE_NODISCARD std::uint64_t decodeLength() const
    {
        MDInstrumentDefinitionFuture54 skipper(m_buffer, m_offset, m_bufferLength, sbeBlockLength(), m_actingVersion);
        skipper.skip();
        return skipper.encodedLength();
    }

    SBE_NODISCARD const char *buffer() const SBE_NOEXCEPT
    {
        return m_buffer;
    }

    SBE_NODISCARD char *buffer() SBE_NOEXCEPT
    {
        return m_buffer;
    }

    SBE_NODISCARD std::uint64_t bufferLength() const SBE_NOEXCEPT
    {
        return m_bufferLength;
    }

    SBE_NODISCARD std::uint64_t actingVersion() const SBE_NOEXCEPT
    {
        return m_actingVersion;
    }

    SBE_NODISCARD static const char *MatchEventIndicatorMetaAttribute(const MetaAttribute metaAttribute) SBE_NOEXCEPT
    {
        switch (metaAttribute)
        {
            case MetaAttribute::SEMANTIC_TYPE: return "MultipleCharValue";
            case MetaAttribute::PRESENCE: return "required";
            default: return "";
        }
    }

    static SBE_CONSTEXPR std::uint16_t matchEventIndicatorId() SBE_NOEXCEPT
    {
        return 5799;
    }

    SBE_NODISCARD static SBE_CONSTEXPR std::uint64_t matchEventIndicatorSinceVersion() SBE_NOEXCEPT
    {
        return 0;
    }

    SBE_NODISCARD bool matchEventIndicatorInActingVersion() SBE_NOEXCEPT
    {
        return true;
    }

    SBE_NODISCARD static SBE_CONSTEXPR std::size_t matchEventIndicatorEncodingOffset() SBE_NOEXCEPT
    {
        return 0;
    }

private:
    MatchEventIndicator m_matchEventIndicator;

public:
    SBE_NODISCARD MatchEventIndicator &matchEventIndicator()
    {
        m_matchEventIndicator.wrap(m_buffer, m_offset + 0, m_actingVersion, m_bufferLength);
        return m_matchEventIndicator;
    }

    static SBE_CONSTEXPR std::size_t matchEventIndicatorEncodingLength() SBE_NOEXCEPT
    {
        return 1;
    }

    SBE_NODISCARD static const char *TotNumReportsMetaAttribute(const MetaAttribute metaAttribute) SBE_NOEXCEPT
    {
        switch (metaAttribute)
        {
            case MetaAttribute::SEMANTIC_TYPE: return "int";
            case MetaAttribute::PRESENCE: return "optional";
            default: return "";
        }
    }

    static SBE_CONSTEXPR std::uint16_t totNumReportsId() SBE_NOEXCEPT
    {
        return 911;
    }

    SBE_NODISCARD static SBE_CONSTEXPR std::uint64_t totNumReportsSinceVersion() SBE_NOEXCEPT
    {
        return 0;
    }

    SBE_NODISCARD bool totNumReportsInActingVersion() SBE_NOEXCEPT
    {
        return true;
    }

    SBE_NODISCARD static SBE_CONSTEXPR std::size_t totNumReportsEncodingOffset() SBE_NOEXCEPT
    {
        return 1;
    }

    static SBE_CONSTEXPR std::uint32_t totNumReportsNullValue() SBE_NOEXCEPT
    {
        return UINT32_C(0xffffffff);
    }

    static SBE_CONSTEXPR std::uint32_t totNumReportsMinValue() SBE_NOEXCEPT
    {
        return UINT32_C(0x0);
    }

    static SBE_CONSTEXPR std::uint32_t totNumReportsMaxValue() SBE_NOEXCEPT
    {
        return UINT32_C(0xfffffffe);
    }

    static SBE_CONSTEXPR std::size_t totNumReportsEncodingLength() SBE_NOEXCEPT
    {
        return 4;
    }

    SBE_NODISCARD std::uint32_t totNumReports() const SBE_NOEXCEPT
    {
        std::uint32_t val;
        std::memcpy(&val, m_buffer + m_offset + 1, sizeof(std::uint32_t));
        return SBE_LITTLE_ENDIAN_ENCODE_32(val);
    }

    MDInstrumentDefinitionFuture54 &totNumReports(const std::uint32_t value) SBE_NOEXCEPT
    {
        std::uint32_t val = SBE_LITTLE_ENDIAN_ENCODE_32(value);
        std::memcpy(m_buffer + m_offset + 1, &val, sizeof(std::uint32_t));
        return *this;
    }

    SBE_NODISCARD static const char *SecurityUpdateActionMetaAttribute(const MetaAttribute metaAttribute) SBE_NOEXCEPT
    {
        switch (metaAttribute)
        {
            case MetaAttribute::SEMANTIC_TYPE: return "char";
            case MetaAttribute::PRESENCE: return "required";
            default: return "";
        }
    }

    static SBE_CONSTEXPR std::uint16_t securityUpdateActionId() SBE_NOEXCEPT
    {
        return 980;
    }

    SBE_NODISCARD static SBE_CONSTEXPR std::uint64_t securityUpdateActionSinceVersion() SBE_NOEXCEPT
    {
        return 0;
    }

    SBE_NODISCARD bool securityUpdateActionInActingVersion() SBE_NOEXCEPT
    {
        return true;
    }

    SBE_NODISCARD static SBE_CONSTEXPR std::size_t securityUpdateActionEncodingOffset() SBE_NOEXCEPT
    {
        return 5;
    }

    SBE_NODISCARD static SBE_CONSTEXPR std::size_t securityUpdateActionEncodingLength() SBE_NOEXCEPT
    {
        return 1;
    }

    SBE_NODISCARD char securityUpdateActionRaw() const SBE_NOEXCEPT
    {
        char val;
        std::memcpy(&val, m_buffer + m_offset + 5, sizeof(char));
        return (val);
    }

    SBE_NODISCARD SecurityUpdateAction::Value securityUpdateAction() const
    {
        char val;
        std::memcpy(&val, m_buffer + m_offset + 5, sizeof(char));
        return SecurityUpdateAction::get((val));
    }

    MDInstrumentDefinitionFuture54 &securityUpdateAction(const SecurityUpdateAction::Value value) SBE_NOEXCEPT
    {
        char val = (value);
        std::memcpy(m_buffer + m_offset + 5, &val, sizeof(char));
        return *this;
    }

    SBE_NODISCARD static const char *LastUpdateTimeMetaAttribute(const MetaAttribute metaAttribute) SBE_NOEXCEPT
    {
        switch (metaAttribute)
        {
            case MetaAttribute::SEMANTIC_TYPE: return "UTCTimestamp";
            case MetaAttribute::PRESENCE: return "required";
            default: return "";
        }
    }

    static SBE_CONSTEXPR std::uint16_t lastUpdateTimeId() SBE_NOEXCEPT
    {
        return 779;
    }

    SBE_NODISCARD static SBE_CONSTEXPR std::uint64_t lastUpdateTimeSinceVersion() SBE_NOEXCEPT
    {
        return 0;
    }

    SBE_NODISCARD bool lastUpdateTimeInActingVersion() SBE_NOEXCEPT
    {
        return true;
    }

    SBE_NODISCARD static SBE_CONSTEXPR std::size_t lastUpdateTimeEncodingOffset() SBE_NOEXCEPT
    {
        return 6;
    }

    static SBE_CONSTEXPR std::uint64_t lastUpdateTimeNullValue() SBE_NOEXCEPT
    {
        return SBE_NULLVALUE_UINT64;
    }

    static SBE_CONSTEXPR std::uint64_t lastUpdateTimeMinValue() SBE_NOEXCEPT
    {
        return UINT64_C(0x0);
    }

    static SBE_CONSTEXPR std::uint64_t lastUpdateTimeMaxValue() SBE_NOEXCEPT
    {
        return UINT64_C(0xfffffffffffffffe);
    }

    static SBE_CONSTEXPR std::size_t lastUpdateTimeEncodingLength() SBE_NOEXCEPT
    {
        return 8;
    }

    SBE_NODISCARD std::uint64_t lastUpdateTime() const SBE_NOEXCEPT
    {
        std::uint64_t val;
        std::memcpy(&val, m_buffer + m_offset + 6, sizeof(std::uint64_t));
        return SBE_LITTLE_ENDIAN_ENCODE_64(val);
    }

    MDInstrumentDefinitionFuture54 &lastUpdateTime(const std::uint64_t value) SBE_NOEXCEPT
    {
        std::uint64_t val = SBE_LITTLE_ENDIAN_ENCODE_64(value);
        std::memcpy(m_buffer + m_offset + 6, &val, sizeof(std::uint64_t));
        return *this;
    }

    SBE_NODISCARD static const char *MDSecurityTradingStatusMetaAttribute(const MetaAttribute metaAttribute) SBE_NOEXCEPT
    {
        switch (metaAttribute)
        {
            case MetaAttribute::SEMANTIC_TYPE: return "int";
            case MetaAttribute::PRESENCE: return "required";
            default: return "";
        }
    }

    static SBE_CONSTEXPR std::uint16_t mDSecurityTradingStatusId() SBE_NOEXCEPT
    {
        return 1682;
    }

    SBE_NODISCARD static SBE_CONSTEXPR std::uint64_t mDSecurityTradingStatusSinceVersion() SBE_NOEXCEPT
    {
        return 0;
    }

    SBE_NODISCARD bool mDSecurityTradingStatusInActingVersion() SBE_NOEXCEPT
    {
        return true;
    }

    SBE_NODISCARD static SBE_CONSTEXPR std::size_t mDSecurityTradingStatusEncodingOffset() SBE_NOEXCEPT
    {
        return 14;
    }

    SBE_NODISCARD static SBE_CONSTEXPR std::size_t mDSecurityTradingStatusEncodingLength() SBE_NOEXCEPT
    {
        return 1;
    }

    SBE_NODISCARD std::uint8_t mDSecurityTradingStatusRaw() const SBE_NOEXCEPT
    {
        std::uint8_t val;
        std::memcpy(&val, m_buffer + m_offset + 14, sizeof(std::uint8_t));
        return (val);
    }

    SBE_NODISCARD SecurityTradingStatus::Value mDSecurityTradingStatus() const
    {
        std::uint8_t val;
        std::memcpy(&val, m_buffer + m_offset + 14, sizeof(std::uint8_t));
        return SecurityTradingStatus::get((val));
    }

    MDInstrumentDefinitionFuture54 &mDSecurityTradingStatus(const SecurityTradingStatus::Value value) SBE_NOEXCEPT
    {
        std::uint8_t val = (value);
        std::memcpy(m_buffer + m_offset + 14, &val, sizeof(std::uint8_t));
        return *this;
    }

    SBE_NODISCARD static const char *ApplIDMetaAttribute(const MetaAttribute metaAttribute) SBE_NOEXCEPT
    {
        switch (metaAttribute)
        {
            case MetaAttribute::SEMANTIC_TYPE: return "int";
            case MetaAttribute::PRESENCE: return "required";
            default: return "";
        }
    }

    static SBE_CONSTEXPR std::uint16_t applIDId() SBE_NOEXCEPT
    {
        return 1180;
    }

    SBE_NODISCARD static SBE_CONSTEXPR std::uint64_t applIDSinceVersion() SBE_NOEXCEPT
    {
        return 0;
    }

    SBE_NODISCARD bool applIDInActingVersion() SBE_NOEXCEPT
    {
        return true;
    }

    SBE_NODISCARD static SBE_CONSTEXPR std::size_t applIDEncodingOffset() SBE_NOEXCEPT
    {
        return 15;
    }

    static SBE_CONSTEXPR std::int16_t applIDNullValue() SBE_NOEXCEPT
    {
        return SBE_NULLVALUE_INT16;
    }

    static SBE_CONSTEXPR std::int16_t applIDMinValue() SBE_NOEXCEPT
    {
        return static_cast<std::int16_t>(-32767);
    }

    static SBE_CONSTEXPR std::int16_t applIDMaxValue() SBE_NOEXCEPT
    {
        return static_cast<std::int16_t>(32767);
    }

    static SBE_CONSTEXPR std::size_t applIDEncodingLength() SBE_NOEXCEPT
    {
        return 2;
    }

    SBE_NODISCARD std::int16_t applID() const SBE_NOEXCEPT
    {
        std::int16_t val;
        std::memcpy(&val, m_buffer + m_offset + 15, sizeof(std::int16_t));
        return SBE_LITTLE_ENDIAN_ENCODE_16(val);
    }

    MDInstrumentDefinitionFuture54 &applID(const std::int16_t value) SBE_NOEXCEPT
    {
        std::int16_t val = SBE_LITTLE_ENDIAN_ENCODE_16(value);
        std::memcpy(m_buffer + m_offset + 15, &val, sizeof(std::int16_t));
        return *this;
    }

    SBE_NODISCARD static const char *MarketSegmentIDMetaAttribute(const MetaAttribute metaAttribute) SBE_NOEXCEPT
    {
        switch (metaAttribute)
        {
            case MetaAttribute::SEMANTIC_TYPE: return "int";
            case MetaAttribute::PRESENCE: return "required";
            default: return "";
        }
    }

    static SBE_CONSTEXPR std::uint16_t marketSegmentIDId() SBE_NOEXCEPT
    {
        return 1300;
    }

    SBE_NODISCARD static SBE_CONSTEXPR std::uint64_t marketSegmentIDSinceVersion() SBE_NOEXCEPT
    {
        return 0;
    }

    SBE_NODISCARD bool marketSegmentIDInActingVersion() SBE_NOEXCEPT
    {
        return true;
    }

    SBE_NODISCARD static SBE_CONSTEXPR std::size_t marketSegmentIDEncodingOffset() SBE_NOEXCEPT
    {
        return 17;
    }

    static SBE_CONSTEXPR std::uint8_t marketSegmentIDNullValue() SBE_NOEXCEPT
    {
        return SBE_NULLVALUE_UINT8;
    }

    static SBE_CONSTEXPR std::uint8_t marketSegmentIDMinValue() SBE_NOEXCEPT
    {
        return static_cast<std::uint8_t>(0);
    }

    static SBE_CONSTEXPR std::uint8_t marketSegmentIDMaxValue() SBE_NOEXCEPT
    {
        return static_cast<std::uint8_t>(254);
    }

    static SBE_CONSTEXPR std::size_t marketSegmentIDEncodingLength() SBE_NOEXCEPT
    {
        return 1;
    }

    SBE_NODISCARD std::uint8_t marketSegmentID() const SBE_NOEXCEPT
    {
        std::uint8_t val;
        std::memcpy(&val, m_buffer + m_offset + 17, sizeof(std::uint8_t));
        return (val);
    }

    MDInstrumentDefinitionFuture54 &marketSegmentID(const std::uint8_t value) SBE_NOEXCEPT
    {
        std::uint8_t val = (value);
        std::memcpy(m_buffer + m_offset + 17, &val, sizeof(std::uint8_t));
        return *this;
    }

    SBE_NODISCARD static const char *UnderlyingProductMetaAttribute(const MetaAttribute metaAttribute) SBE_NOEXCEPT
    {
        switch (metaAttribute)
        {
            case MetaAttribute::SEMANTIC_TYPE: return "int";
            case MetaAttribute::PRESENCE: return "required";
            default: return "";
        }
    }

    static SBE_CONSTEXPR std::uint16_t underlyingProductId() SBE_NOEXCEPT
    {
        return 462;
    }

    SBE_NODISCARD static SBE_CONSTEXPR std::uint64_t underlyingProductSinceVersion() SBE_NOEXCEPT
    {
        return 0;
    }

    SBE_NODISCARD bool underlyingProductInActingVersion() SBE_NOEXCEPT
    {
        return true;
    }

    SBE_NODISCARD static SBE_CONSTEXPR std::size_t underlyingProductEncodingOffset() SBE_NOEXCEPT
    {
        return 18;
    }

    static SBE_CONSTEXPR std::uint8_t underlyingProductNullValue() SBE_NOEXCEPT
    {
        return SBE_NULLVALUE_UINT8;
    }

    static SBE_CONSTEXPR std::uint8_t underlyingProductMinValue() SBE_NOEXCEPT
    {
        return static_cast<std::uint8_t>(0);
    }

    static SBE_CONSTEXPR std::uint8_t underlyingProductMaxValue() SBE_NOEXCEPT
    {
        return static_cast<std::uint8_t>(254);
    }

    static SBE_CONSTEXPR std::size_t underlyingProductEncodingLength() SBE_NOEXCEPT
    {
        return 1;
    }

    SBE_NODISCARD std::uint8_t underlyingProduct() const SBE_NOEXCEPT
    {
        std::uint8_t val;
        std::memcpy(&val, m_buffer + m_offset + 18, sizeof(std::uint8_t));
        return (val);
    }

    MDInstrumentDefinitionFuture54 &underlyingProduct(const std::uint8_t value) SBE_NOEXCEPT
    {
        std::uint8_t val = (value);
        std::memcpy(m_buffer + m_offset + 18, &val, sizeof(std::uint8_t));
        return *this;
    }

    SBE_NODISCARD static const char *SecurityExchangeMetaAttribute(const MetaAttribute metaAttribute) SBE_NOEXCEPT
    {
        switch (metaAttribute)
        {
            case MetaAttribute::SEMANTIC_TYPE: return "Exchange";
            case MetaAttribute::PRESENCE: return "required";
            default: return "";
        }
    }

    static SBE_CONSTEXPR std::uint16_t securityExchangeId() SBE_NOEXCEPT
    {
        return 207;
    }

    SBE_NODISCARD static SBE_CONSTEXPR std::uint64_t securityExchangeSinceVersion() SBE_NOEXCEPT
    {
        return 0;
    }

    SBE_NODISCARD bool securityExchangeInActingVersion() SBE_NOEXCEPT
    {
        return true;
    }

    SBE_NODISCARD static SBE_CONSTEXPR std::size_t securityExchangeEncodingOffset() SBE_NOEXCEPT
    {
        return 19;
    }

    static SBE_CONSTEXPR char securityExchangeNullValue() SBE_NOEXCEPT
    {
        return static_cast<char>(0);
    }

    static SBE_CONSTEXPR char securityExchangeMinValue() SBE_NOEXCEPT
    {
        return static_cast<char>(32);
    }

    static SBE_CONSTEXPR char securityExchangeMaxValue() SBE_NOEXCEPT
    {
        return static_cast<char>(126);
    }

    static SBE_CONSTEXPR std::size_t securityExchangeEncodingLength() SBE_NOEXCEPT
    {
        return 4;
    }

    static SBE_CONSTEXPR std::uint64_t securityExchangeLength() SBE_NOEXCEPT
    {
        return 4;
    }

    SBE_NODISCARD const char *securityExchange() const SBE_NOEXCEPT
    {
        return m_buffer + m_offset + 19;
    }

    SBE_NODISCARD char *securityExchange() SBE_NOEXCEPT
    {
        return m_buffer + m_offset + 19;
    }

    SBE_NODISCARD char securityExchange(const std::uint64_t index) const
    {
        if (index >= 4)
        {
            throw std::runtime_error("index out of range for securityExchange [E104]");
        }

        char val;
        std::memcpy(&val, m_buffer + m_offset + 19 + (index * 1), sizeof(char));
        return (val);
    }

    MDInstrumentDefinitionFuture54 &securityExchange(const std::uint64_t index, const char value)
    {
        if (index >= 4)
        {
            throw std::runtime_error("index out of range for securityExchange [E105]");
        }

        char val = (value);
        std::memcpy(m_buffer + m_offset + 19 + (index * 1), &val, sizeof(char));
        return *this;
    }

    std::uint64_t getSecurityExchange(char *const dst, const std::uint64_t length) const
    {
        if (length > 4)
        {
            throw std::runtime_error("length too large for getSecurityExchange [E106]");
        }

        std::memcpy(dst, m_buffer + m_offset + 19, sizeof(char) * static_cast<std::size_t>(length));
        return length;
    }

    MDInstrumentDefinitionFuture54 &putSecurityExchange(const char *const src) SBE_NOEXCEPT
    {
        std::memcpy(m_buffer + m_offset + 19, src, sizeof(char) * 4);
        return *this;
    }

    MDInstrumentDefinitionFuture54 &putSecurityExchange(
        const char value0,
        const char value1,
        const char value2,
        const char value3) SBE_NOEXCEPT
    {
        char val0 = (value0);
        std::memcpy(m_buffer + m_offset + 19, &val0, sizeof(char));
        char val1 = (value1);
        std::memcpy(m_buffer + m_offset + 20, &val1, sizeof(char));
        char val2 = (value2);
        std::memcpy(m_buffer + m_offset + 21, &val2, sizeof(char));
        char val3 = (value3);
        std::memcpy(m_buffer + m_offset + 22, &val3, sizeof(char));

        return *this;
    }

    SBE_NODISCARD std::string getSecurityExchangeAsString() const
    {
        const char *buffer = m_buffer + m_offset + 19;
        std::size_t length = 0;

        for (; length < 4 && *(buffer + length) != '\0'; ++length);
        std::string result(buffer, length);

        return result;
    }

    std::string getSecurityExchangeAsJsonEscapedString()
    {
        std::ostringstream oss;
        std::string s = getSecurityExchangeAsString();

        for (const auto c : s)
        {
            switch (c)
            {
                case '"': oss << "\\\""; break;
                case '\\': oss << "\\\\"; break;
                case '\b': oss << "\\b"; break;
                case '\f': oss << "\\f"; break;
                case '\n': oss << "\\n"; break;
                case '\r': oss << "\\r"; break;
                case '\t': oss << "\\t"; break;

                default:
                    if ('\x00' <= c && c <= '\x1f')
                    {
                        oss << "\\u" << std::hex << std::setw(4)
                            << std::setfill('0') << (int)(c);
                    }
                    else
                    {
                        oss << c;
                    }
            }
        }

        return oss.str();
    }

    #if __cplusplus >= 201703L
    SBE_NODISCARD std::string_view getSecurityExchangeAsStringView() const SBE_NOEXCEPT
    {
        const char *buffer = m_buffer + m_offset + 19;
        std::size_t length = 0;

        for (; length < 4 && *(buffer + length) != '\0'; ++length);
        std::string_view result(buffer, length);

        return result;
    }
    #endif

    #if __cplusplus >= 201703L
    MDInstrumentDefinitionFuture54 &putSecurityExchange(const std::string_view str)
    {
        const std::size_t srcLength = str.length();
        if (srcLength > 4)
        {
            throw std::runtime_error("string too large for putSecurityExchange [E106]");
        }

        std::memcpy(m_buffer + m_offset + 19, str.data(), srcLength);
        for (std::size_t start = srcLength; start < 4; ++start)
        {
            m_buffer[m_offset + 19 + start] = 0;
        }

        return *this;
    }
    #else
    MDInstrumentDefinitionFuture54 &putSecurityExchange(const std::string &str)
    {
        const std::size_t srcLength = str.length();
        if (srcLength > 4)
        {
            throw std::runtime_error("string too large for putSecurityExchange [E106]");
        }

        std::memcpy(m_buffer + m_offset + 19, str.c_str(), srcLength);
        for (std::size_t start = srcLength; start < 4; ++start)
        {
            m_buffer[m_offset + 19 + start] = 0;
        }

        return *this;
    }
    #endif

    SBE_NODISCARD static const char *SecurityGroupMetaAttribute(const MetaAttribute metaAttribute) SBE_NOEXCEPT
    {
        switch (metaAttribute)
        {
            case MetaAttribute::SEMANTIC_TYPE: return "String";
            case MetaAttribute::PRESENCE: return "required";
            default: return "";
        }
    }

    static SBE_CONSTEXPR std::uint16_t securityGroupId() SBE_NOEXCEPT
    {
        return 1151;
    }

    SBE_NODISCARD static SBE_CONSTEXPR std::uint64_t securityGroupSinceVersion() SBE_NOEXCEPT
    {
        return 0;
    }

    SBE_NODISCARD bool securityGroupInActingVersion() SBE_NOEXCEPT
    {
        return true;
    }

    SBE_NODISCARD static SBE_CONSTEXPR std::size_t securityGroupEncodingOffset() SBE_NOEXCEPT
    {
        return 23;
    }

    static SBE_CONSTEXPR char securityGroupNullValue() SBE_NOEXCEPT
    {
        return static_cast<char>(0);
    }

    static SBE_CONSTEXPR char securityGroupMinValue() SBE_NOEXCEPT
    {
        return static_cast<char>(32);
    }

    static SBE_CONSTEXPR char securityGroupMaxValue() SBE_NOEXCEPT
    {
        return static_cast<char>(126);
    }

    static SBE_CONSTEXPR std::size_t securityGroupEncodingLength() SBE_NOEXCEPT
    {
        return 6;
    }

    static SBE_CONSTEXPR std::uint64_t securityGroupLength() SBE_NOEXCEPT
    {
        return 6;
    }

    SBE_NODISCARD const char *securityGroup() const SBE_NOEXCEPT
    {
        return m_buffer + m_offset + 23;
    }

    SBE_NODISCARD char *securityGroup() SBE_NOEXCEPT
    {
        return m_buffer + m_offset + 23;
    }

    SBE_NODISCARD char securityGroup(const std::uint64_t index) const
    {
        if (index >= 6)
        {
            throw std::runtime_error("index out of range for securityGroup [E104]");
        }

        char val;
        std::memcpy(&val, m_buffer + m_offset + 23 + (index * 1), sizeof(char));
        return (val);
    }

    MDInstrumentDefinitionFuture54 &securityGroup(const std::uint64_t index, const char value)
    {
        if (index >= 6)
        {
            throw std::runtime_error("index out of range for securityGroup [E105]");
        }

        char val = (value);
        std::memcpy(m_buffer + m_offset + 23 + (index * 1), &val, sizeof(char));
        return *this;
    }

    std::uint64_t getSecurityGroup(char *const dst, const std::uint64_t length) const
    {
        if (length > 6)
        {
            throw std::runtime_error("length too large for getSecurityGroup [E106]");
        }

        std::memcpy(dst, m_buffer + m_offset + 23, sizeof(char) * static_cast<std::size_t>(length));
        return length;
    }

    MDInstrumentDefinitionFuture54 &putSecurityGroup(const char *const src) SBE_NOEXCEPT
    {
        std::memcpy(m_buffer + m_offset + 23, src, sizeof(char) * 6);
        return *this;
    }

    SBE_NODISCARD std::string getSecurityGroupAsString() const
    {
        const char *buffer = m_buffer + m_offset + 23;
        std::size_t length = 0;

        for (; length < 6 && *(buffer + length) != '\0'; ++length);
        std::string result(buffer, length);

        return result;
    }

    std::string getSecurityGroupAsJsonEscapedString()
    {
        std::ostringstream oss;
        std::string s = getSecurityGroupAsString();

        for (const auto c : s)
        {
            switch (c)
            {
                case '"': oss << "\\\""; break;
                case '\\': oss << "\\\\"; break;
                case '\b': oss << "\\b"; break;
                case '\f': oss << "\\f"; break;
                case '\n': oss << "\\n"; break;
                case '\r': oss << "\\r"; break;
                case '\t': oss << "\\t"; break;

                default:
                    if ('\x00' <= c && c <= '\x1f')
                    {
                        oss << "\\u" << std::hex << std::setw(4)
                            << std::setfill('0') << (int)(c);
                    }
                    else
                    {
                        oss << c;
                    }
            }
        }

        return oss.str();
    }

    #if __cplusplus >= 201703L
    SBE_NODISCARD std::string_view getSecurityGroupAsStringView() const SBE_NOEXCEPT
    {
        const char *buffer = m_buffer + m_offset + 23;
        std::size_t length = 0;

        for (; length < 6 && *(buffer + length) != '\0'; ++length);
        std::string_view result(buffer, length);

        return result;
    }
    #endif

    #if __cplusplus >= 201703L
    MDInstrumentDefinitionFuture54 &putSecurityGroup(const std::string_view str)
    {
        const std::size_t srcLength = str.length();
        if (srcLength > 6)
        {
            throw std::runtime_error("string too large for putSecurityGroup [E106]");
        }

        std::memcpy(m_buffer + m_offset + 23, str.data(), srcLength);
        for (std::size_t start = srcLength; start < 6; ++start)
        {
            m_buffer[m_offset + 23 + start] = 0;
        }

        return *this;
    }
    #else
    MDInstrumentDefinitionFuture54 &putSecurityGroup(const std::string &str)
    {
        const std::size_t srcLength = str.length();
        if (srcLength > 6)
        {
            throw std::runtime_error("string too large for putSecurityGroup [E106]");
        }

        std::memcpy(m_buffer + m_offset + 23, str.c_str(), srcLength);
        for (std::size_t start = srcLength; start < 6; ++start)
        {
            m_buffer[m_offset + 23 + start] = 0;
        }

        return *this;
    }
    #endif

    SBE_NODISCARD static const char *AssetMetaAttribute(const MetaAttribute metaAttribute) SBE_NOEXCEPT
    {
        switch (metaAttribute)
        {
            case MetaAttribute::SEMANTIC_TYPE: return "String";
            case MetaAttribute::PRESENCE: return "required";
            default: return "";
        }
    }

    static SBE_CONSTEXPR std::uint16_t assetId() SBE_NOEXCEPT
    {
        return 6937;
    }

    SBE_NODISCARD static SBE_CONSTEXPR std::uint64_t assetSinceVersion() SBE_NOEXCEPT
    {
        return 0;
    }

    SBE_NODISCARD bool assetInActingVersion() SBE_NOEXCEPT
    {
        return true;
    }

    SBE_NODISCARD static SBE_CONSTEXPR std::size_t assetEncodingOffset() SBE_NOEXCEPT
    {
        return 29;
    }

    static SBE_CONSTEXPR char assetNullValue() SBE_NOEXCEPT
    {
        return static_cast<char>(0);
    }

    static SBE_CONSTEXPR char assetMinValue() SBE_NOEXCEPT
    {
        return static_cast<char>(32);
    }

    static SBE_CONSTEXPR char assetMaxValue() SBE_NOEXCEPT
    {
        return static_cast<char>(126);
    }

    static SBE_CONSTEXPR std::size_t assetEncodingLength() SBE_NOEXCEPT
    {
        return 6;
    }

    static SBE_CONSTEXPR std::uint64_t assetLength() SBE_NOEXCEPT
    {
        return 6;
    }

    SBE_NODISCARD const char *asset() const SBE_NOEXCEPT
    {
        return m_buffer + m_offset + 29;
    }

    SBE_NODISCARD char *asset() SBE_NOEXCEPT
    {
        return m_buffer + m_offset + 29;
    }

    SBE_NODISCARD char asset(const std::uint64_t index) const
    {
        if (index >= 6)
        {
            throw std::runtime_error("index out of range for asset [E104]");
        }

        char val;
        std::memcpy(&val, m_buffer + m_offset + 29 + (index * 1), sizeof(char));
        return (val);
    }

    MDInstrumentDefinitionFuture54 &asset(const std::uint64_t index, const char value)
    {
        if (index >= 6)
        {
            throw std::runtime_error("index out of range for asset [E105]");
        }

        char val = (value);
        std::memcpy(m_buffer + m_offset + 29 + (index * 1), &val, sizeof(char));
        return *this;
    }

    std::uint64_t getAsset(char *const dst, const std::uint64_t length) const
    {
        if (length > 6)
        {
            throw std::runtime_error("length too large for getAsset [E106]");
        }

        std::memcpy(dst, m_buffer + m_offset + 29, sizeof(char) * static_cast<std::size_t>(length));
        return length;
    }

    MDInstrumentDefinitionFuture54 &putAsset(const char *const src) SBE_NOEXCEPT
    {
        std::memcpy(m_buffer + m_offset + 29, src, sizeof(char) * 6);
        return *this;
    }

    SBE_NODISCARD std::string getAssetAsString() const
    {
        const char *buffer = m_buffer + m_offset + 29;
        std::size_t length = 0;

        for (; length < 6 && *(buffer + length) != '\0'; ++length);
        std::string result(buffer, length);

        return result;
    }

    std::string getAssetAsJsonEscapedString()
    {
        std::ostringstream oss;
        std::string s = getAssetAsString();

        for (const auto c : s)
        {
            switch (c)
            {
                case '"': oss << "\\\""; break;
                case '\\': oss << "\\\\"; break;
                case '\b': oss << "\\b"; break;
                case '\f': oss << "\\f"; break;
                case '\n': oss << "\\n"; break;
                case '\r': oss << "\\r"; break;
                case '\t': oss << "\\t"; break;

                default:
                    if ('\x00' <= c && c <= '\x1f')
                    {
                        oss << "\\u" << std::hex << std::setw(4)
                            << std::setfill('0') << (int)(c);
                    }
                    else
                    {
                        oss << c;
                    }
            }
        }

        return oss.str();
    }

    #if __cplusplus >= 201703L
    SBE_NODISCARD std::string_view getAssetAsStringView() const SBE_NOEXCEPT
    {
        const char *buffer = m_buffer + m_offset + 29;
        std::size_t length = 0;

        for (; length < 6 && *(buffer + length) != '\0'; ++length);
        std::string_view result(buffer, length);

        return result;
    }
    #endif

    #if __cplusplus >= 201703L
    MDInstrumentDefinitionFuture54 &putAsset(const std::string_view str)
    {
        const std::size_t srcLength = str.length();
        if (srcLength > 6)
        {
            throw std::runtime_error("string too large for putAsset [E106]");
        }

        std::memcpy(m_buffer + m_offset + 29, str.data(), srcLength);
        for (std::size_t start = srcLength; start < 6; ++start)
        {
            m_buffer[m_offset + 29 + start] = 0;
        }

        return *this;
    }
    #else
    MDInstrumentDefinitionFuture54 &putAsset(const std::string &str)
    {
        const std::size_t srcLength = str.length();
        if (srcLength > 6)
        {
            throw std::runtime_error("string too large for putAsset [E106]");
        }

        std::memcpy(m_buffer + m_offset + 29, str.c_str(), srcLength);
        for (std::size_t start = srcLength; start < 6; ++start)
        {
            m_buffer[m_offset + 29 + start] = 0;
        }

        return *this;
    }
    #endif

    SBE_NODISCARD static const char *SymbolMetaAttribute(const MetaAttribute metaAttribute) SBE_NOEXCEPT
    {
        switch (metaAttribute)
        {
            case MetaAttribute::SEMANTIC_TYPE: return "String";
            case MetaAttribute::PRESENCE: return "required";
            default: return "";
        }
    }

    static SBE_CONSTEXPR std::uint16_t symbolId() SBE_NOEXCEPT
    {
        return 55;
    }

    SBE_NODISCARD static SBE_CONSTEXPR std::uint64_t symbolSinceVersion() SBE_NOEXCEPT
    {
        return 0;
    }

    SBE_NODISCARD bool symbolInActingVersion() SBE_NOEXCEPT
    {
        return true;
    }

    SBE_NODISCARD static SBE_CONSTEXPR std::size_t symbolEncodingOffset() SBE_NOEXCEPT
    {
        return 35;
    }

    static SBE_CONSTEXPR char symbolNullValue() SBE_NOEXCEPT
    {
        return static_cast<char>(0);
    }

    static SBE_CONSTEXPR char symbolMinValue() SBE_NOEXCEPT
    {
        return static_cast<char>(32);
    }

    static SBE_CONSTEXPR char symbolMaxValue() SBE_NOEXCEPT
    {
        return static_cast<char>(126);
    }

    static SBE_CONSTEXPR std::size_t symbolEncodingLength() SBE_NOEXCEPT
    {
        return 20;
    }

    static SBE_CONSTEXPR std::uint64_t symbolLength() SBE_NOEXCEPT
    {
        return 20;
    }

    SBE_NODISCARD const char *symbol() const SBE_NOEXCEPT
    {
        return m_buffer + m_offset + 35;
    }

    SBE_NODISCARD char *symbol() SBE_NOEXCEPT
    {
        return m_buffer + m_offset + 35;
    }

    SBE_NODISCARD char symbol(const std::uint64_t index) const
    {
        if (index >= 20)
        {
            throw std::runtime_error("index out of range for symbol [E104]");
        }

        char val;
        std::memcpy(&val, m_buffer + m_offset + 35 + (index * 1), sizeof(char));
        return (val);
    }

    MDInstrumentDefinitionFuture54 &symbol(const std::uint64_t index, const char value)
    {
        if (index >= 20)
        {
            throw std::runtime_error("index out of range for symbol [E105]");
        }

        char val = (value);
        std::memcpy(m_buffer + m_offset + 35 + (index * 1), &val, sizeof(char));
        return *this;
    }

    std::uint64_t getSymbol(char *const dst, const std::uint64_t length) const
    {
        if (length > 20)
        {
            throw std::runtime_error("length too large for getSymbol [E106]");
        }

        std::memcpy(dst, m_buffer + m_offset + 35, sizeof(char) * static_cast<std::size_t>(length));
        return length;
    }

    MDInstrumentDefinitionFuture54 &putSymbol(const char *const src) SBE_NOEXCEPT
    {
        std::memcpy(m_buffer + m_offset + 35, src, sizeof(char) * 20);
        return *this;
    }

    SBE_NODISCARD std::string getSymbolAsString() const
    {
        const char *buffer = m_buffer + m_offset + 35;
        std::size_t length = 0;

        for (; length < 20 && *(buffer + length) != '\0'; ++length);
        std::string result(buffer, length);

        return result;
    }

    std::string getSymbolAsJsonEscapedString()
    {
        std::ostringstream oss;
        std::string s = getSymbolAsString();

        for (const auto c : s)
        {
            switch (c)
            {
                case '"': oss << "\\\""; break;
                case '\\': oss << "\\\\"; break;
                case '\b': oss << "\\b"; break;
                case '\f': oss << "\\f"; break;
                case '\n': oss << "\\n"; break;
                case '\r': oss << "\\r"; break;
                case '\t': oss << "\\t"; break;

                default:
                    if ('\x00' <= c && c <= '\x1f')
                    {
                        oss << "\\u" << std::hex << std::setw(4)
                            << std::setfill('0') << (int)(c);
                    }
                    else
                    {
                        oss << c;
                    }
            }
        }

        return oss.str();
    }

    #if __cplusplus >= 201703L
    SBE_NODISCARD std::string_view getSymbolAsStringView() const SBE_NOEXCEPT
    {
        const char *buffer = m_buffer + m_offset + 35;
        std::size_t length = 0;

        for (; length < 20 && *(buffer + length) != '\0'; ++length);
        std::string_view result(buffer, length);

        return result;
    }
    #endif

    #if __cplusplus >= 201703L
    MDInstrumentDefinitionFuture54 &putSymbol(const std::string_view str)
    {
        const std::size_t srcLength = str.length();
        if (srcLength > 20)
        {
            throw std::runtime_error("string too large for putSymbol [E106]");
        }

        std::memcpy(m_buffer + m_offset + 35, str.data(), srcLength);
        for (std::size_t start = srcLength; start < 20; ++start)
        {
            m_buffer[m_offset + 35 + start] = 0;
        }

        return *this;
    }
    #else
    MDInstrumentDefinitionFuture54 &putSymbol(const std::string &str)
    {
        const std::size_t srcLength = str.length();
        if (srcLength > 20)
        {
            throw std::runtime_error("string too large for putSymbol [E106]");
        }

        std::memcpy(m_buffer + m_offset + 35, str.c_str(), srcLength);
        for (std::size_t start = srcLength; start < 20; ++start)
        {
            m_buffer[m_offset + 35 + start] = 0;
        }

        return *this;
    }
    #endif

    SBE_NODISCARD static const char *SecurityIDMetaAttribute(const MetaAttribute metaAttribute) SBE_NOEXCEPT
    {
        switch (metaAttribute)
        {
            case MetaAttribute::SEMANTIC_TYPE: return "int";
            case MetaAttribute::PRESENCE: return "required";
            default: return "";
        }
    }

    static SBE_CONSTEXPR std::uint16_t securityIDId() SBE_NOEXCEPT
    {
        return 48;
    }

    SBE_NODISCARD static SBE_CONSTEXPR std::uint64_t securityIDSinceVersion() SBE_NOEXCEPT
    {
        return 0;
    }

    SBE_NODISCARD bool securityIDInActingVersion() SBE_NOEXCEPT
    {
        return true;
    }

    SBE_NODISCARD static SBE_CONSTEXPR std::size_t securityIDEncodingOffset() SBE_NOEXCEPT
    {
        return 55;
    }

    static SBE_CONSTEXPR std::int32_t securityIDNullValue() SBE_NOEXCEPT
    {
        return SBE_NULLVALUE_INT32;
    }

    static SBE_CONSTEXPR std::int32_t securityIDMinValue() SBE_NOEXCEPT
    {
        return INT32_C(-2147483647);
    }

    static SBE_CONSTEXPR std::int32_t securityIDMaxValue() SBE_NOEXCEPT
    {
        return INT32_C(2147483647);
    }

    static SBE_CONSTEXPR std::size_t securityIDEncodingLength() SBE_NOEXCEPT
    {
        return 4;
    }

    SBE_NODISCARD std::int32_t securityID() const SBE_NOEXCEPT
    {
        std::int32_t val;
        std::memcpy(&val, m_buffer + m_offset + 55, sizeof(std::int32_t));
        return SBE_LITTLE_ENDIAN_ENCODE_32(val);
    }

    MDInstrumentDefinitionFuture54 &securityID(const std::int32_t value) SBE_NOEXCEPT
    {
        std::int32_t val = SBE_LITTLE_ENDIAN_ENCODE_32(value);
        std::memcpy(m_buffer + m_offset + 55, &val, sizeof(std::int32_t));
        return *this;
    }

    SBE_NODISCARD static const char *SecurityIDSourceMetaAttribute(const MetaAttribute metaAttribute) SBE_NOEXCEPT
    {
        switch (metaAttribute)
        {
            case MetaAttribute::SEMANTIC_TYPE: return "char";
            case MetaAttribute::PRESENCE: return "constant";
            default: return "";
        }
    }

    static SBE_CONSTEXPR std::uint16_t securityIDSourceId() SBE_NOEXCEPT
    {
        return 22;
    }

    SBE_NODISCARD static SBE_CONSTEXPR std::uint64_t securityIDSourceSinceVersion() SBE_NOEXCEPT
    {
        return 0;
    }

    SBE_NODISCARD bool securityIDSourceInActingVersion() SBE_NOEXCEPT
    {
        return true;
    }

    SBE_NODISCARD static SBE_CONSTEXPR std::size_t securityIDSourceEncodingOffset() SBE_NOEXCEPT
    {
        return 59;
    }

    static SBE_CONSTEXPR char securityIDSourceNullValue() SBE_NOEXCEPT
    {
        return static_cast<char>(0);
    }

    static SBE_CONSTEXPR char securityIDSourceMinValue() SBE_NOEXCEPT
    {
        return static_cast<char>(32);
    }

    static SBE_CONSTEXPR char securityIDSourceMaxValue() SBE_NOEXCEPT
    {
        return static_cast<char>(126);
    }

    static SBE_CONSTEXPR std::size_t securityIDSourceEncodingLength() SBE_NOEXCEPT
    {
        return 0;
    }

    static SBE_CONSTEXPR std::uint64_t securityIDSourceLength() SBE_NOEXCEPT
    {
        return 1;
    }

    SBE_NODISCARD const char *securityIDSource() const
    {
        static const std::uint8_t securityIDSourceValues[] = { 56, 0 };

        return (const char *)securityIDSourceValues;
    }

    SBE_NODISCARD char securityIDSource(const std::uint64_t index) const
    {
        static const std::uint8_t securityIDSourceValues[] = { 56, 0 };

        return (char)securityIDSourceValues[index];
    }

    std::uint64_t getSecurityIDSource(char *dst, const std::uint64_t length) const
    {
        static std::uint8_t securityIDSourceValues[] = { 56 };
        std::uint64_t bytesToCopy = length < sizeof(securityIDSourceValues) ? length : sizeof(securityIDSourceValues);

        std::memcpy(dst, securityIDSourceValues, static_cast<std::size_t>(bytesToCopy));
        return bytesToCopy;
    }

    std::string getSecurityIDSourceAsString() const
    {
        static const std::uint8_t SecurityIDSourceValues[] = { 56 };

        return std::string((const char *)SecurityIDSourceValues, 1);
    }

    std::string getSecurityIDSourceAsJsonEscapedString()
    {
        std::ostringstream oss;
        std::string s = getSecurityIDSourceAsString();

        for (const auto c : s)
        {
            switch (c)
            {
                case '"': oss << "\\\""; break;
                case '\\': oss << "\\\\"; break;
                case '\b': oss << "\\b"; break;
                case '\f': oss << "\\f"; break;
                case '\n': oss << "\\n"; break;
                case '\r': oss << "\\r"; break;
                case '\t': oss << "\\t"; break;

                default:
                    if ('\x00' <= c && c <= '\x1f')
                    {
                        oss << "\\u" << std::hex << std::setw(4)
                            << std::setfill('0') << (int)(c);
                    }
                    else
                    {
                        oss << c;
                    }
            }
        }

        return oss.str();
    }

    SBE_NODISCARD static const char *SecurityTypeMetaAttribute(const MetaAttribute metaAttribute) SBE_NOEXCEPT
    {
        switch (metaAttribute)
        {
            case MetaAttribute::SEMANTIC_TYPE: return "String";
            case MetaAttribute::PRESENCE: return "required";
            default: return "";
        }
    }

    static SBE_CONSTEXPR std::uint16_t securityTypeId() SBE_NOEXCEPT
    {
        return 167;
    }

    SBE_NODISCARD static SBE_CONSTEXPR std::uint64_t securityTypeSinceVersion() SBE_NOEXCEPT
    {
        return 0;
    }

    SBE_NODISCARD bool securityTypeInActingVersion() SBE_NOEXCEPT
    {
        return true;
    }

    SBE_NODISCARD static SBE_CONSTEXPR std::size_t securityTypeEncodingOffset() SBE_NOEXCEPT
    {
        return 59;
    }

    static SBE_CONSTEXPR char securityTypeNullValue() SBE_NOEXCEPT
    {
        return static_cast<char>(0);
    }

    static SBE_CONSTEXPR char securityTypeMinValue() SBE_NOEXCEPT
    {
        return static_cast<char>(32);
    }

    static SBE_CONSTEXPR char securityTypeMaxValue() SBE_NOEXCEPT
    {
        return static_cast<char>(126);
    }

    static SBE_CONSTEXPR std::size_t securityTypeEncodingLength() SBE_NOEXCEPT
    {
        return 6;
    }

    static SBE_CONSTEXPR std::uint64_t securityTypeLength() SBE_NOEXCEPT
    {
        return 6;
    }

    SBE_NODISCARD const char *securityType() const SBE_NOEXCEPT
    {
        return m_buffer + m_offset + 59;
    }

    SBE_NODISCARD char *securityType() SBE_NOEXCEPT
    {
        return m_buffer + m_offset + 59;
    }

    SBE_NODISCARD char securityType(const std::uint64_t index) const
    {
        if (index >= 6)
        {
            throw std::runtime_error("index out of range for securityType [E104]");
        }

        char val;
        std::memcpy(&val, m_buffer + m_offset + 59 + (index * 1), sizeof(char));
        return (val);
    }

    MDInstrumentDefinitionFuture54 &securityType(const std::uint64_t index, const char value)
    {
        if (index >= 6)
        {
            throw std::runtime_error("index out of range for securityType [E105]");
        }

        char val = (value);
        std::memcpy(m_buffer + m_offset + 59 + (index * 1), &val, sizeof(char));
        return *this;
    }

    std::uint64_t getSecurityType(char *const dst, const std::uint64_t length) const
    {
        if (length > 6)
        {
            throw std::runtime_error("length too large for getSecurityType [E106]");
        }

        std::memcpy(dst, m_buffer + m_offset + 59, sizeof(char) * static_cast<std::size_t>(length));
        return length;
    }

    MDInstrumentDefinitionFuture54 &putSecurityType(const char *const src) SBE_NOEXCEPT
    {
        std::memcpy(m_buffer + m_offset + 59, src, sizeof(char) * 6);
        return *this;
    }

    SBE_NODISCARD std::string getSecurityTypeAsString() const
    {
        const char *buffer = m_buffer + m_offset + 59;
        std::size_t length = 0;

        for (; length < 6 && *(buffer + length) != '\0'; ++length);
        std::string result(buffer, length);

        return result;
    }

    std::string getSecurityTypeAsJsonEscapedString()
    {
        std::ostringstream oss;
        std::string s = getSecurityTypeAsString();

        for (const auto c : s)
        {
            switch (c)
            {
                case '"': oss << "\\\""; break;
                case '\\': oss << "\\\\"; break;
                case '\b': oss << "\\b"; break;
                case '\f': oss << "\\f"; break;
                case '\n': oss << "\\n"; break;
                case '\r': oss << "\\r"; break;
                case '\t': oss << "\\t"; break;

                default:
                    if ('\x00' <= c && c <= '\x1f')
                    {
                        oss << "\\u" << std::hex << std::setw(4)
                            << std::setfill('0') << (int)(c);
                    }
                    else
                    {
                        oss << c;
                    }
            }
        }

        return oss.str();
    }

    #if __cplusplus >= 201703L
    SBE_NODISCARD std::string_view getSecurityTypeAsStringView() const SBE_NOEXCEPT
    {
        const char *buffer = m_buffer + m_offset + 59;
        std::size_t length = 0;

        for (; length < 6 && *(buffer + length) != '\0'; ++length);
        std::string_view result(buffer, length);

        return result;
    }
    #endif

    #if __cplusplus >= 201703L
    MDInstrumentDefinitionFuture54 &putSecurityType(const std::string_view str)
    {
        const std::size_t srcLength = str.length();
        if (srcLength > 6)
        {
            throw std::runtime_error("string too large for putSecurityType [E106]");
        }

        std::memcpy(m_buffer + m_offset + 59, str.data(), srcLength);
        for (std::size_t start = srcLength; start < 6; ++start)
        {
            m_buffer[m_offset + 59 + start] = 0;
        }

        return *this;
    }
    #else
    MDInstrumentDefinitionFuture54 &putSecurityType(const std::string &str)
    {
        const std::size_t srcLength = str.length();
        if (srcLength > 6)
        {
            throw std::runtime_error("string too large for putSecurityType [E106]");
        }

        std::memcpy(m_buffer + m_offset + 59, str.c_str(), srcLength);
        for (std::size_t start = srcLength; start < 6; ++start)
        {
            m_buffer[m_offset + 59 + start] = 0;
        }

        return *this;
    }
    #endif

    SBE_NODISCARD static const char *CFICodeMetaAttribute(const MetaAttribute metaAttribute) SBE_NOEXCEPT
    {
        switch (metaAttribute)
        {
            case MetaAttribute::SEMANTIC_TYPE: return "String";
            case MetaAttribute::PRESENCE: return "required";
            default: return "";
        }
    }

    static SBE_CONSTEXPR std::uint16_t cFICodeId() SBE_NOEXCEPT
    {
        return 461;
    }

    SBE_NODISCARD static SBE_CONSTEXPR std::uint64_t cFICodeSinceVersion() SBE_NOEXCEPT
    {
        return 0;
    }

    SBE_NODISCARD bool cFICodeInActingVersion() SBE_NOEXCEPT
    {
        return true;
    }

    SBE_NODISCARD static SBE_CONSTEXPR std::size_t cFICodeEncodingOffset() SBE_NOEXCEPT
    {
        return 65;
    }

    static SBE_CONSTEXPR char cFICodeNullValue() SBE_NOEXCEPT
    {
        return static_cast<char>(0);
    }

    static SBE_CONSTEXPR char cFICodeMinValue() SBE_NOEXCEPT
    {
        return static_cast<char>(32);
    }

    static SBE_CONSTEXPR char cFICodeMaxValue() SBE_NOEXCEPT
    {
        return static_cast<char>(126);
    }

    static SBE_CONSTEXPR std::size_t cFICodeEncodingLength() SBE_NOEXCEPT
    {
        return 6;
    }

    static SBE_CONSTEXPR std::uint64_t cFICodeLength() SBE_NOEXCEPT
    {
        return 6;
    }

    SBE_NODISCARD const char *cFICode() const SBE_NOEXCEPT
    {
        return m_buffer + m_offset + 65;
    }

    SBE_NODISCARD char *cFICode() SBE_NOEXCEPT
    {
        return m_buffer + m_offset + 65;
    }

    SBE_NODISCARD char cFICode(const std::uint64_t index) const
    {
        if (index >= 6)
        {
            throw std::runtime_error("index out of range for cFICode [E104]");
        }

        char val;
        std::memcpy(&val, m_buffer + m_offset + 65 + (index * 1), sizeof(char));
        return (val);
    }

    MDInstrumentDefinitionFuture54 &cFICode(const std::uint64_t index, const char value)
    {
        if (index >= 6)
        {
            throw std::runtime_error("index out of range for cFICode [E105]");
        }

        char val = (value);
        std::memcpy(m_buffer + m_offset + 65 + (index * 1), &val, sizeof(char));
        return *this;
    }

    std::uint64_t getCFICode(char *const dst, const std::uint64_t length) const
    {
        if (length > 6)
        {
            throw std::runtime_error("length too large for getCFICode [E106]");
        }

        std::memcpy(dst, m_buffer + m_offset + 65, sizeof(char) * static_cast<std::size_t>(length));
        return length;
    }

    MDInstrumentDefinitionFuture54 &putCFICode(const char *const src) SBE_NOEXCEPT
    {
        std::memcpy(m_buffer + m_offset + 65, src, sizeof(char) * 6);
        return *this;
    }

    SBE_NODISCARD std::string getCFICodeAsString() const
    {
        const char *buffer = m_buffer + m_offset + 65;
        std::size_t length = 0;

        for (; length < 6 && *(buffer + length) != '\0'; ++length);
        std::string result(buffer, length);

        return result;
    }

    std::string getCFICodeAsJsonEscapedString()
    {
        std::ostringstream oss;
        std::string s = getCFICodeAsString();

        for (const auto c : s)
        {
            switch (c)
            {
                case '"': oss << "\\\""; break;
                case '\\': oss << "\\\\"; break;
                case '\b': oss << "\\b"; break;
                case '\f': oss << "\\f"; break;
                case '\n': oss << "\\n"; break;
                case '\r': oss << "\\r"; break;
                case '\t': oss << "\\t"; break;

                default:
                    if ('\x00' <= c && c <= '\x1f')
                    {
                        oss << "\\u" << std::hex << std::setw(4)
                            << std::setfill('0') << (int)(c);
                    }
                    else
                    {
                        oss << c;
                    }
            }
        }

        return oss.str();
    }

    #if __cplusplus >= 201703L
    SBE_NODISCARD std::string_view getCFICodeAsStringView() const SBE_NOEXCEPT
    {
        const char *buffer = m_buffer + m_offset + 65;
        std::size_t length = 0;

        for (; length < 6 && *(buffer + length) != '\0'; ++length);
        std::string_view result(buffer, length);

        return result;
    }
    #endif

    #if __cplusplus >= 201703L
    MDInstrumentDefinitionFuture54 &putCFICode(const std::string_view str)
    {
        const std::size_t srcLength = str.length();
        if (srcLength > 6)
        {
            throw std::runtime_error("string too large for putCFICode [E106]");
        }

        std::memcpy(m_buffer + m_offset + 65, str.data(), srcLength);
        for (std::size_t start = srcLength; start < 6; ++start)
        {
            m_buffer[m_offset + 65 + start] = 0;
        }

        return *this;
    }
    #else
    MDInstrumentDefinitionFuture54 &putCFICode(const std::string &str)
    {
        const std::size_t srcLength = str.length();
        if (srcLength > 6)
        {
            throw std::runtime_error("string too large for putCFICode [E106]");
        }

        std::memcpy(m_buffer + m_offset + 65, str.c_str(), srcLength);
        for (std::size_t start = srcLength; start < 6; ++start)
        {
            m_buffer[m_offset + 65 + start] = 0;
        }

        return *this;
    }
    #endif

    SBE_NODISCARD static const char *MaturityMonthYearMetaAttribute(const MetaAttribute metaAttribute) SBE_NOEXCEPT
    {
        switch (metaAttribute)
        {
            case MetaAttribute::SEMANTIC_TYPE: return "MonthYear";
            case MetaAttribute::PRESENCE: return "required";
            default: return "";
        }
    }

    static SBE_CONSTEXPR std::uint16_t maturityMonthYearId() SBE_NOEXCEPT
    {
        return 200;
    }

    SBE_NODISCARD static SBE_CONSTEXPR std::uint64_t maturityMonthYearSinceVersion() SBE_NOEXCEPT
    {
        return 0;
    }

    SBE_NODISCARD bool maturityMonthYearInActingVersion() SBE_NOEXCEPT
    {
        return true;
    }

    SBE_NODISCARD static SBE_CONSTEXPR std::size_t maturityMonthYearEncodingOffset() SBE_NOEXCEPT
    {
        return 71;
    }

private:
    MaturityMonthYear m_maturityMonthYear;

public:
    SBE_NODISCARD MaturityMonthYear &maturityMonthYear()
    {
        m_maturityMonthYear.wrap(m_buffer, m_offset + 71, m_actingVersion, m_bufferLength);
        return m_maturityMonthYear;
    }

    SBE_NODISCARD static const char *CurrencyMetaAttribute(const MetaAttribute metaAttribute) SBE_NOEXCEPT
    {
        switch (metaAttribute)
        {
            case MetaAttribute::SEMANTIC_TYPE: return "Currency";
            case MetaAttribute::PRESENCE: return "required";
            default: return "";
        }
    }

    static SBE_CONSTEXPR std::uint16_t currencyId() SBE_NOEXCEPT
    {
        return 15;
    }

    SBE_NODISCARD static SBE_CONSTEXPR std::uint64_t currencySinceVersion() SBE_NOEXCEPT
    {
        return 0;
    }

    SBE_NODISCARD bool currencyInActingVersion() SBE_NOEXCEPT
    {
        return true;
    }

    SBE_NODISCARD static SBE_CONSTEXPR std::size_t currencyEncodingOffset() SBE_NOEXCEPT
    {
        return 76;
    }

    static SBE_CONSTEXPR char currencyNullValue() SBE_NOEXCEPT
    {
        return static_cast<char>(0);
    }

    static SBE_CONSTEXPR char currencyMinValue() SBE_NOEXCEPT
    {
        return static_cast<char>(32);
    }

    static SBE_CONSTEXPR char currencyMaxValue() SBE_NOEXCEPT
    {
        return static_cast<char>(126);
    }

    static SBE_CONSTEXPR std::size_t currencyEncodingLength() SBE_NOEXCEPT
    {
        return 3;
    }

    static SBE_CONSTEXPR std::uint64_t currencyLength() SBE_NOEXCEPT
    {
        return 3;
    }

    SBE_NODISCARD const char *currency() const SBE_NOEXCEPT
    {
        return m_buffer + m_offset + 76;
    }

    SBE_NODISCARD char *currency() SBE_NOEXCEPT
    {
        return m_buffer + m_offset + 76;
    }

    SBE_NODISCARD char currency(const std::uint64_t index) const
    {
        if (index >= 3)
        {
            throw std::runtime_error("index out of range for currency [E104]");
        }

        char val;
        std::memcpy(&val, m_buffer + m_offset + 76 + (index * 1), sizeof(char));
        return (val);
    }

    MDInstrumentDefinitionFuture54 &currency(const std::uint64_t index, const char value)
    {
        if (index >= 3)
        {
            throw std::runtime_error("index out of range for currency [E105]");
        }

        char val = (value);
        std::memcpy(m_buffer + m_offset + 76 + (index * 1), &val, sizeof(char));
        return *this;
    }

    std::uint64_t getCurrency(char *const dst, const std::uint64_t length) const
    {
        if (length > 3)
        {
            throw std::runtime_error("length too large for getCurrency [E106]");
        }

        std::memcpy(dst, m_buffer + m_offset + 76, sizeof(char) * static_cast<std::size_t>(length));
        return length;
    }

    MDInstrumentDefinitionFuture54 &putCurrency(const char *const src) SBE_NOEXCEPT
    {
        std::memcpy(m_buffer + m_offset + 76, src, sizeof(char) * 3);
        return *this;
    }

    MDInstrumentDefinitionFuture54 &putCurrency(
        const char value0,
        const char value1,
        const char value2) SBE_NOEXCEPT
    {
        char val0 = (value0);
        std::memcpy(m_buffer + m_offset + 76, &val0, sizeof(char));
        char val1 = (value1);
        std::memcpy(m_buffer + m_offset + 77, &val1, sizeof(char));
        char val2 = (value2);
        std::memcpy(m_buffer + m_offset + 78, &val2, sizeof(char));

        return *this;
    }

    SBE_NODISCARD std::string getCurrencyAsString() const
    {
        const char *buffer = m_buffer + m_offset + 76;
        std::size_t length = 0;

        for (; length < 3 && *(buffer + length) != '\0'; ++length);
        std::string result(buffer, length);

        return result;
    }

    std::string getCurrencyAsJsonEscapedString()
    {
        std::ostringstream oss;
        std::string s = getCurrencyAsString();

        for (const auto c : s)
        {
            switch (c)
            {
                case '"': oss << "\\\""; break;
                case '\\': oss << "\\\\"; break;
                case '\b': oss << "\\b"; break;
                case '\f': oss << "\\f"; break;
                case '\n': oss << "\\n"; break;
                case '\r': oss << "\\r"; break;
                case '\t': oss << "\\t"; break;

                default:
                    if ('\x00' <= c && c <= '\x1f')
                    {
                        oss << "\\u" << std::hex << std::setw(4)
                            << std::setfill('0') << (int)(c);
                    }
                    else
                    {
                        oss << c;
                    }
            }
        }

        return oss.str();
    }

    #if __cplusplus >= 201703L
    SBE_NODISCARD std::string_view getCurrencyAsStringView() const SBE_NOEXCEPT
    {
        const char *buffer = m_buffer + m_offset + 76;
        std::size_t length = 0;

        for (; length < 3 && *(buffer + length) != '\0'; ++length);
        std::string_view result(buffer, length);

        return result;
    }
    #endif

    #if __cplusplus >= 201703L
    MDInstrumentDefinitionFuture54 &putCurrency(const std::string_view str)
    {
        const std::size_t srcLength = str.length();
        if (srcLength > 3)
        {
            throw std::runtime_error("string too large for putCurrency [E106]");
        }

        std::memcpy(m_buffer + m_offset + 76, str.data(), srcLength);
        for (std::size_t start = srcLength; start < 3; ++start)
        {
            m_buffer[m_offset + 76 + start] = 0;
        }

        return *this;
    }
    #else
    MDInstrumentDefinitionFuture54 &putCurrency(const std::string &str)
    {
        const std::size_t srcLength = str.length();
        if (srcLength > 3)
        {
            throw std::runtime_error("string too large for putCurrency [E106]");
        }

        std::memcpy(m_buffer + m_offset + 76, str.c_str(), srcLength);
        for (std::size_t start = srcLength; start < 3; ++start)
        {
            m_buffer[m_offset + 76 + start] = 0;
        }

        return *this;
    }
    #endif

    SBE_NODISCARD static const char *SettlCurrencyMetaAttribute(const MetaAttribute metaAttribute) SBE_NOEXCEPT
    {
        switch (metaAttribute)
        {
            case MetaAttribute::SEMANTIC_TYPE: return "Currency";
            case MetaAttribute::PRESENCE: return "required";
            default: return "";
        }
    }

    static SBE_CONSTEXPR std::uint16_t settlCurrencyId() SBE_NOEXCEPT
    {
        return 120;
    }

    SBE_NODISCARD static SBE_CONSTEXPR std::uint64_t settlCurrencySinceVersion() SBE_NOEXCEPT
    {
        return 0;
    }

    SBE_NODISCARD bool settlCurrencyInActingVersion() SBE_NOEXCEPT
    {
        return true;
    }

    SBE_NODISCARD static SBE_CONSTEXPR std::size_t settlCurrencyEncodingOffset() SBE_NOEXCEPT
    {
        return 79;
    }

    static SBE_CONSTEXPR char settlCurrencyNullValue() SBE_NOEXCEPT
    {
        return static_cast<char>(0);
    }

    static SBE_CONSTEXPR char settlCurrencyMinValue() SBE_NOEXCEPT
    {
        return static_cast<char>(32);
    }

    static SBE_CONSTEXPR char settlCurrencyMaxValue() SBE_NOEXCEPT
    {
        return static_cast<char>(126);
    }

    static SBE_CONSTEXPR std::size_t settlCurrencyEncodingLength() SBE_NOEXCEPT
    {
        return 3;
    }

    static SBE_CONSTEXPR std::uint64_t settlCurrencyLength() SBE_NOEXCEPT
    {
        return 3;
    }

    SBE_NODISCARD const char *settlCurrency() const SBE_NOEXCEPT
    {
        return m_buffer + m_offset + 79;
    }

    SBE_NODISCARD char *settlCurrency() SBE_NOEXCEPT
    {
        return m_buffer + m_offset + 79;
    }

    SBE_NODISCARD char settlCurrency(const std::uint64_t index) const
    {
        if (index >= 3)
        {
            throw std::runtime_error("index out of range for settlCurrency [E104]");
        }

        char val;
        std::memcpy(&val, m_buffer + m_offset + 79 + (index * 1), sizeof(char));
        return (val);
    }

    MDInstrumentDefinitionFuture54 &settlCurrency(const std::uint64_t index, const char value)
    {
        if (index >= 3)
        {
            throw std::runtime_error("index out of range for settlCurrency [E105]");
        }

        char val = (value);
        std::memcpy(m_buffer + m_offset + 79 + (index * 1), &val, sizeof(char));
        return *this;
    }

    std::uint64_t getSettlCurrency(char *const dst, const std::uint64_t length) const
    {
        if (length > 3)
        {
            throw std::runtime_error("length too large for getSettlCurrency [E106]");
        }

        std::memcpy(dst, m_buffer + m_offset + 79, sizeof(char) * static_cast<std::size_t>(length));
        return length;
    }

    MDInstrumentDefinitionFuture54 &putSettlCurrency(const char *const src) SBE_NOEXCEPT
    {
        std::memcpy(m_buffer + m_offset + 79, src, sizeof(char) * 3);
        return *this;
    }

    MDInstrumentDefinitionFuture54 &putSettlCurrency(
        const char value0,
        const char value1,
        const char value2) SBE_NOEXCEPT
    {
        char val0 = (value0);
        std::memcpy(m_buffer + m_offset + 79, &val0, sizeof(char));
        char val1 = (value1);
        std::memcpy(m_buffer + m_offset + 80, &val1, sizeof(char));
        char val2 = (value2);
        std::memcpy(m_buffer + m_offset + 81, &val2, sizeof(char));

        return *this;
    }

    SBE_NODISCARD std::string getSettlCurrencyAsString() const
    {
        const char *buffer = m_buffer + m_offset + 79;
        std::size_t length = 0;

        for (; length < 3 && *(buffer + length) != '\0'; ++length);
        std::string result(buffer, length);

        return result;
    }

    std::string getSettlCurrencyAsJsonEscapedString()
    {
        std::ostringstream oss;
        std::string s = getSettlCurrencyAsString();

        for (const auto c : s)
        {
            switch (c)
            {
                case '"': oss << "\\\""; break;
                case '\\': oss << "\\\\"; break;
                case '\b': oss << "\\b"; break;
                case '\f': oss << "\\f"; break;
                case '\n': oss << "\\n"; break;
                case '\r': oss << "\\r"; break;
                case '\t': oss << "\\t"; break;

                default:
                    if ('\x00' <= c && c <= '\x1f')
                    {
                        oss << "\\u" << std::hex << std::setw(4)
                            << std::setfill('0') << (int)(c);
                    }
                    else
                    {
                        oss << c;
                    }
            }
        }

        return oss.str();
    }

    #if __cplusplus >= 201703L
    SBE_NODISCARD std::string_view getSettlCurrencyAsStringView() const SBE_NOEXCEPT
    {
        const char *buffer = m_buffer + m_offset + 79;
        std::size_t length = 0;

        for (; length < 3 && *(buffer + length) != '\0'; ++length);
        std::string_view result(buffer, length);

        return result;
    }
    #endif

    #if __cplusplus >= 201703L
    MDInstrumentDefinitionFuture54 &putSettlCurrency(const std::string_view str)
    {
        const std::size_t srcLength = str.length();
        if (srcLength > 3)
        {
            throw std::runtime_error("string too large for putSettlCurrency [E106]");
        }

        std::memcpy(m_buffer + m_offset + 79, str.data(), srcLength);
        for (std::size_t start = srcLength; start < 3; ++start)
        {
            m_buffer[m_offset + 79 + start] = 0;
        }

        return *this;
    }
    #else
    MDInstrumentDefinitionFuture54 &putSettlCurrency(const std::string &str)
    {
        const std::size_t srcLength = str.length();
        if (srcLength > 3)
        {
            throw std::runtime_error("string too large for putSettlCurrency [E106]");
        }

        std::memcpy(m_buffer + m_offset + 79, str.c_str(), srcLength);
        for (std::size_t start = srcLength; start < 3; ++start)
        {
            m_buffer[m_offset + 79 + start] = 0;
        }

        return *this;
    }
    #endif

    SBE_NODISCARD static const char *MatchAlgorithmMetaAttribute(const MetaAttribute metaAttribute) SBE_NOEXCEPT
    {
        switch (metaAttribute)
        {
            case MetaAttribute::SEMANTIC_TYPE: return "char";
            case MetaAttribute::PRESENCE: return "required";
            default: return "";
        }
    }

    static SBE_CONSTEXPR std::uint16_t matchAlgorithmId() SBE_NOEXCEPT
    {
        return 1142;
    }

    SBE_NODISCARD static SBE_CONSTEXPR std::uint64_t matchAlgorithmSinceVersion() SBE_NOEXCEPT
    {
        return 0;
    }

    SBE_NODISCARD bool matchAlgorithmInActingVersion() SBE_NOEXCEPT
    {
        return true;
    }

    SBE_NODISCARD static SBE_CONSTEXPR std::size_t matchAlgorithmEncodingOffset() SBE_NOEXCEPT
    {
        return 82;
    }

    static SBE_CONSTEXPR char matchAlgorithmNullValue() SBE_NOEXCEPT
    {
        return static_cast<char>(0);
    }

    static SBE_CONSTEXPR char matchAlgorithmMinValue() SBE_NOEXCEPT
    {
        return static_cast<char>(32);
    }

    static SBE_CONSTEXPR char matchAlgorithmMaxValue() SBE_NOEXCEPT
    {
        return static_cast<char>(126);
    }

    static SBE_CONSTEXPR std::size_t matchAlgorithmEncodingLength() SBE_NOEXCEPT
    {
        return 1;
    }

    SBE_NODISCARD char matchAlgorithm() const SBE_NOEXCEPT
    {
        char val;
        std::memcpy(&val, m_buffer + m_offset + 82, sizeof(char));
        return (val);
    }

    MDInstrumentDefinitionFuture54 &matchAlgorithm(const char value) SBE_NOEXCEPT
    {
        char val = (value);
        std::memcpy(m_buffer + m_offset + 82, &val, sizeof(char));
        return *this;
    }

    SBE_NODISCARD static const char *MinTradeVolMetaAttribute(const MetaAttribute metaAttribute) SBE_NOEXCEPT
    {
        switch (metaAttribute)
        {
            case MetaAttribute::SEMANTIC_TYPE: return "Qty";
            case MetaAttribute::PRESENCE: return "required";
            default: return "";
        }
    }

    static SBE_CONSTEXPR std::uint16_t minTradeVolId() SBE_NOEXCEPT
    {
        return 562;
    }

    SBE_NODISCARD static SBE_CONSTEXPR std::uint64_t minTradeVolSinceVersion() SBE_NOEXCEPT
    {
        return 0;
    }

    SBE_NODISCARD bool minTradeVolInActingVersion() SBE_NOEXCEPT
    {
        return true;
    }

    SBE_NODISCARD static SBE_CONSTEXPR std::size_t minTradeVolEncodingOffset() SBE_NOEXCEPT
    {
        return 83;
    }

    static SBE_CONSTEXPR std::uint32_t minTradeVolNullValue() SBE_NOEXCEPT
    {
        return SBE_NULLVALUE_UINT32;
    }

    static SBE_CONSTEXPR std::uint32_t minTradeVolMinValue() SBE_NOEXCEPT
    {
        return UINT32_C(0x0);
    }

    static SBE_CONSTEXPR std::uint32_t minTradeVolMaxValue() SBE_NOEXCEPT
    {
        return UINT32_C(0xfffffffe);
    }

    static SBE_CONSTEXPR std::size_t minTradeVolEncodingLength() SBE_NOEXCEPT
    {
        return 4;
    }

    SBE_NODISCARD std::uint32_t minTradeVol() const SBE_NOEXCEPT
    {
        std::uint32_t val;
        std::memcpy(&val, m_buffer + m_offset + 83, sizeof(std::uint32_t));
        return SBE_LITTLE_ENDIAN_ENCODE_32(val);
    }

    MDInstrumentDefinitionFuture54 &minTradeVol(const std::uint32_t value) SBE_NOEXCEPT
    {
        std::uint32_t val = SBE_LITTLE_ENDIAN_ENCODE_32(value);
        std::memcpy(m_buffer + m_offset + 83, &val, sizeof(std::uint32_t));
        return *this;
    }

    SBE_NODISCARD static const char *MaxTradeVolMetaAttribute(const MetaAttribute metaAttribute) SBE_NOEXCEPT
    {
        switch (metaAttribute)
        {
            case MetaAttribute::SEMANTIC_TYPE: return "Qty";
            case MetaAttribute::PRESENCE: return "required";
            default: return "";
        }
    }

    static SBE_CONSTEXPR std::uint16_t maxTradeVolId() SBE_NOEXCEPT
    {
        return 1140;
    }

    SBE_NODISCARD static SBE_CONSTEXPR std::uint64_t maxTradeVolSinceVersion() SBE_NOEXCEPT
    {
        return 0;
    }

    SBE_NODISCARD bool maxTradeVolInActingVersion() SBE_NOEXCEPT
    {
        return true;
    }

    SBE_NODISCARD static SBE_CONSTEXPR std::size_t maxTradeVolEncodingOffset() SBE_NOEXCEPT
    {
        return 87;
    }

    static SBE_CONSTEXPR std::uint32_t maxTradeVolNullValue() SBE_NOEXCEPT
    {
        return SBE_NULLVALUE_UINT32;
    }

    static SBE_CONSTEXPR std::uint32_t maxTradeVolMinValue() SBE_NOEXCEPT
    {
        return UINT32_C(0x0);
    }

    static SBE_CONSTEXPR std::uint32_t maxTradeVolMaxValue() SBE_NOEXCEPT
    {
        return UINT32_C(0xfffffffe);
    }

    static SBE_CONSTEXPR std::size_t maxTradeVolEncodingLength() SBE_NOEXCEPT
    {
        return 4;
    }

    SBE_NODISCARD std::uint32_t maxTradeVol() const SBE_NOEXCEPT
    {
        std::uint32_t val;
        std::memcpy(&val, m_buffer + m_offset + 87, sizeof(std::uint32_t));
        return SBE_LITTLE_ENDIAN_ENCODE_32(val);
    }

    MDInstrumentDefinitionFuture54 &maxTradeVol(const std::uint32_t value) SBE_NOEXCEPT
    {
        std::uint32_t val = SBE_LITTLE_ENDIAN_ENCODE_32(value);
        std::memcpy(m_buffer + m_offset + 87, &val, sizeof(std::uint32_t));
        return *this;
    }

    SBE_NODISCARD static const char *MinPriceIncrementMetaAttribute(const MetaAttribute metaAttribute) SBE_NOEXCEPT
    {
        switch (metaAttribute)
        {
            case MetaAttribute::SEMANTIC_TYPE: return "Price";
            case MetaAttribute::PRESENCE: return "required";
            default: return "";
        }
    }

    static SBE_CONSTEXPR std::uint16_t minPriceIncrementId() SBE_NOEXCEPT
    {
        return 969;
    }

    SBE_NODISCARD static SBE_CONSTEXPR std::uint64_t minPriceIncrementSinceVersion() SBE_NOEXCEPT
    {
        return 9;
    }

    SBE_NODISCARD bool minPriceIncrementInActingVersion() SBE_NOEXCEPT
    {
        return m_actingVersion >= minPriceIncrementSinceVersion();
    }

    SBE_NODISCARD static SBE_CONSTEXPR std::size_t minPriceIncrementEncodingOffset() SBE_NOEXCEPT
    {
        return 91;
    }

private:
    PRICE9 m_minPriceIncrement;

public:
    SBE_NODISCARD PRICE9 &minPriceIncrement()
    {
        m_minPriceIncrement.wrap(m_buffer, m_offset + 91, m_actingVersion, m_bufferLength);
        return m_minPriceIncrement;
    }

    SBE_NODISCARD static const char *DisplayFactorMetaAttribute(const MetaAttribute metaAttribute) SBE_NOEXCEPT
    {
        switch (metaAttribute)
        {
            case MetaAttribute::SEMANTIC_TYPE: return "float";
            case MetaAttribute::PRESENCE: return "required";
            default: return "";
        }
    }

    static SBE_CONSTEXPR std::uint16_t displayFactorId() SBE_NOEXCEPT
    {
        return 9787;
    }

    SBE_NODISCARD static SBE_CONSTEXPR std::uint64_t displayFactorSinceVersion() SBE_NOEXCEPT
    {
        return 9;
    }

    SBE_NODISCARD bool displayFactorInActingVersion() SBE_NOEXCEPT
    {
        return m_actingVersion >= displayFactorSinceVersion();
    }

    SBE_NODISCARD static SBE_CONSTEXPR std::size_t displayFactorEncodingOffset() SBE_NOEXCEPT
    {
        return 99;
    }

private:
    Decimal9 m_displayFactor;

public:
    SBE_NODISCARD Decimal9 &displayFactor()
    {
        m_displayFactor.wrap(m_buffer, m_offset + 99, m_actingVersion, m_bufferLength);
        return m_displayFactor;
    }

    SBE_NODISCARD static const char *MainFractionMetaAttribute(const MetaAttribute metaAttribute) SBE_NOEXCEPT
    {
        switch (metaAttribute)
        {
            case MetaAttribute::SEMANTIC_TYPE: return "int";
            case MetaAttribute::PRESENCE: return "optional";
            default: return "";
        }
    }

    static SBE_CONSTEXPR std::uint16_t mainFractionId() SBE_NOEXCEPT
    {
        return 37702;
    }

    SBE_NODISCARD static SBE_CONSTEXPR std::uint64_t mainFractionSinceVersion() SBE_NOEXCEPT
    {
        return 0;
    }

    SBE_NODISCARD bool mainFractionInActingVersion() SBE_NOEXCEPT
    {
        return true;
    }

    SBE_NODISCARD static SBE_CONSTEXPR std::size_t mainFractionEncodingOffset() SBE_NOEXCEPT
    {
        return 107;
    }

    static SBE_CONSTEXPR std::uint8_t mainFractionNullValue() SBE_NOEXCEPT
    {
        return static_cast<std::uint8_t>(255);
    }

    static SBE_CONSTEXPR std::uint8_t mainFractionMinValue() SBE_NOEXCEPT
    {
        return static_cast<std::uint8_t>(0);
    }

    static SBE_CONSTEXPR std::uint8_t mainFractionMaxValue() SBE_NOEXCEPT
    {
        return static_cast<std::uint8_t>(254);
    }

    static SBE_CONSTEXPR std::size_t mainFractionEncodingLength() SBE_NOEXCEPT
    {
        return 1;
    }

    SBE_NODISCARD std::uint8_t mainFraction() const SBE_NOEXCEPT
    {
        std::uint8_t val;
        std::memcpy(&val, m_buffer + m_offset + 107, sizeof(std::uint8_t));
        return (val);
    }

    MDInstrumentDefinitionFuture54 &mainFraction(const std::uint8_t value) SBE_NOEXCEPT
    {
        std::uint8_t val = (value);
        std::memcpy(m_buffer + m_offset + 107, &val, sizeof(std::uint8_t));
        return *this;
    }

    SBE_NODISCARD static const char *SubFractionMetaAttribute(const MetaAttribute metaAttribute) SBE_NOEXCEPT
    {
        switch (metaAttribute)
        {
            case MetaAttribute::SEMANTIC_TYPE: return "int";
            case MetaAttribute::PRESENCE: return "optional";
            default: return "";
        }
    }

    static SBE_CONSTEXPR std::uint16_t subFractionId() SBE_NOEXCEPT
    {
        return 37703;
    }

    SBE_NODISCARD static SBE_CONSTEXPR std::uint64_t subFractionSinceVersion() SBE_NOEXCEPT
    {
        return 0;
    }

    SBE_NODISCARD bool subFractionInActingVersion() SBE_NOEXCEPT
    {
        return true;
    }

    SBE_NODISCARD static SBE_CONSTEXPR std::size_t subFractionEncodingOffset() SBE_NOEXCEPT
    {
        return 108;
    }

    static SBE_CONSTEXPR std::uint8_t subFractionNullValue() SBE_NOEXCEPT
    {
        return static_cast<std::uint8_t>(255);
    }

    static SBE_CONSTEXPR std::uint8_t subFractionMinValue() SBE_NOEXCEPT
    {
        return static_cast<std::uint8_t>(0);
    }

    static SBE_CONSTEXPR std::uint8_t subFractionMaxValue() SBE_NOEXCEPT
    {
        return static_cast<std::uint8_t>(254);
    }

    static SBE_CONSTEXPR std::size_t subFractionEncodingLength() SBE_NOEXCEPT
    {
        return 1;
    }

    SBE_NODISCARD std::uint8_t subFraction() const SBE_NOEXCEPT
    {
        std::uint8_t val;
        std::memcpy(&val, m_buffer + m_offset + 108, sizeof(std::uint8_t));
        return (val);
    }

    MDInstrumentDefinitionFuture54 &subFraction(const std::uint8_t value) SBE_NOEXCEPT
    {
        std::uint8_t val = (value);
        std::memcpy(m_buffer + m_offset + 108, &val, sizeof(std::uint8_t));
        return *this;
    }

    SBE_NODISCARD static const char *PriceDisplayFormatMetaAttribute(const MetaAttribute metaAttribute) SBE_NOEXCEPT
    {
        switch (metaAttribute)
        {
            case MetaAttribute::SEMANTIC_TYPE: return "int";
            case MetaAttribute::PRESENCE: return "optional";
            default: return "";
        }
    }

    static SBE_CONSTEXPR std::uint16_t priceDisplayFormatId() SBE_NOEXCEPT
    {
        return 9800;
    }

    SBE_NODISCARD static SBE_CONSTEXPR std::uint64_t priceDisplayFormatSinceVersion() SBE_NOEXCEPT
    {
        return 0;
    }

    SBE_NODISCARD bool priceDisplayFormatInActingVersion() SBE_NOEXCEPT
    {
        return true;
    }

    SBE_NODISCARD static SBE_CONSTEXPR std::size_t priceDisplayFormatEncodingOffset() SBE_NOEXCEPT
    {
        return 109;
    }

    static SBE_CONSTEXPR std::uint8_t priceDisplayFormatNullValue() SBE_NOEXCEPT
    {
        return static_cast<std::uint8_t>(255);
    }

    static SBE_CONSTEXPR std::uint8_t priceDisplayFormatMinValue() SBE_NOEXCEPT
    {
        return static_cast<std::uint8_t>(0);
    }

    static SBE_CONSTEXPR std::uint8_t priceDisplayFormatMaxValue() SBE_NOEXCEPT
    {
        return static_cast<std::uint8_t>(254);
    }

    static SBE_CONSTEXPR std::size_t priceDisplayFormatEncodingLength() SBE_NOEXCEPT
    {
        return 1;
    }

    SBE_NODISCARD std::uint8_t priceDisplayFormat() const SBE_NOEXCEPT
    {
        std::uint8_t val;
        std::memcpy(&val, m_buffer + m_offset + 109, sizeof(std::uint8_t));
        return (val);
    }

    MDInstrumentDefinitionFuture54 &priceDisplayFormat(const std::uint8_t value) SBE_NOEXCEPT
    {
        std::uint8_t val = (value);
        std::memcpy(m_buffer + m_offset + 109, &val, sizeof(std::uint8_t));
        return *this;
    }

    SBE_NODISCARD static const char *UnitOfMeasureMetaAttribute(const MetaAttribute metaAttribute) SBE_NOEXCEPT
    {
        switch (metaAttribute)
        {
            case MetaAttribute::SEMANTIC_TYPE: return "String";
            case MetaAttribute::PRESENCE: return "required";
            default: return "";
        }
    }

    static SBE_CONSTEXPR std::uint16_t unitOfMeasureId() SBE_NOEXCEPT
    {
        return 996;
    }

    SBE_NODISCARD static SBE_CONSTEXPR std::uint64_t unitOfMeasureSinceVersion() SBE_NOEXCEPT
    {
        return 0;
    }

    SBE_NODISCARD bool unitOfMeasureInActingVersion() SBE_NOEXCEPT
    {
        return true;
    }

    SBE_NODISCARD static SBE_CONSTEXPR std::size_t unitOfMeasureEncodingOffset() SBE_NOEXCEPT
    {
        return 110;
    }

    static SBE_CONSTEXPR char unitOfMeasureNullValue() SBE_NOEXCEPT
    {
        return static_cast<char>(0);
    }

    static SBE_CONSTEXPR char unitOfMeasureMinValue() SBE_NOEXCEPT
    {
        return static_cast<char>(32);
    }

    static SBE_CONSTEXPR char unitOfMeasureMaxValue() SBE_NOEXCEPT
    {
        return static_cast<char>(126);
    }

    static SBE_CONSTEXPR std::size_t unitOfMeasureEncodingLength() SBE_NOEXCEPT
    {
        return 30;
    }

    static SBE_CONSTEXPR std::uint64_t unitOfMeasureLength() SBE_NOEXCEPT
    {
        return 30;
    }

    SBE_NODISCARD const char *unitOfMeasure() const SBE_NOEXCEPT
    {
        return m_buffer + m_offset + 110;
    }

    SBE_NODISCARD char *unitOfMeasure() SBE_NOEXCEPT
    {
        return m_buffer + m_offset + 110;
    }

    SBE_NODISCARD char unitOfMeasure(const std::uint64_t index) const
    {
        if (index >= 30)
        {
            throw std::runtime_error("index out of range for unitOfMeasure [E104]");
        }

        char val;
        std::memcpy(&val, m_buffer + m_offset + 110 + (index * 1), sizeof(char));
        return (val);
    }

    MDInstrumentDefinitionFuture54 &unitOfMeasure(const std::uint64_t index, const char value)
    {
        if (index >= 30)
        {
            throw std::runtime_error("index out of range for unitOfMeasure [E105]");
        }

        char val = (value);
        std::memcpy(m_buffer + m_offset + 110 + (index * 1), &val, sizeof(char));
        return *this;
    }

    std::uint64_t getUnitOfMeasure(char *const dst, const std::uint64_t length) const
    {
        if (length > 30)
        {
            throw std::runtime_error("length too large for getUnitOfMeasure [E106]");
        }

        std::memcpy(dst, m_buffer + m_offset + 110, sizeof(char) * static_cast<std::size_t>(length));
        return length;
    }

    MDInstrumentDefinitionFuture54 &putUnitOfMeasure(const char *const src) SBE_NOEXCEPT
    {
        std::memcpy(m_buffer + m_offset + 110, src, sizeof(char) * 30);
        return *this;
    }

    SBE_NODISCARD std::string getUnitOfMeasureAsString() const
    {
        const char *buffer = m_buffer + m_offset + 110;
        std::size_t length = 0;

        for (; length < 30 && *(buffer + length) != '\0'; ++length);
        std::string result(buffer, length);

        return result;
    }

    std::string getUnitOfMeasureAsJsonEscapedString()
    {
        std::ostringstream oss;
        std::string s = getUnitOfMeasureAsString();

        for (const auto c : s)
        {
            switch (c)
            {
                case '"': oss << "\\\""; break;
                case '\\': oss << "\\\\"; break;
                case '\b': oss << "\\b"; break;
                case '\f': oss << "\\f"; break;
                case '\n': oss << "\\n"; break;
                case '\r': oss << "\\r"; break;
                case '\t': oss << "\\t"; break;

                default:
                    if ('\x00' <= c && c <= '\x1f')
                    {
                        oss << "\\u" << std::hex << std::setw(4)
                            << std::setfill('0') << (int)(c);
                    }
                    else
                    {
                        oss << c;
                    }
            }
        }

        return oss.str();
    }

    #if __cplusplus >= 201703L
    SBE_NODISCARD std::string_view getUnitOfMeasureAsStringView() const SBE_NOEXCEPT
    {
        const char *buffer = m_buffer + m_offset + 110;
        std::size_t length = 0;

        for (; length < 30 && *(buffer + length) != '\0'; ++length);
        std::string_view result(buffer, length);

        return result;
    }
    #endif

    #if __cplusplus >= 201703L
    MDInstrumentDefinitionFuture54 &putUnitOfMeasure(const std::string_view str)
    {
        const std::size_t srcLength = str.length();
        if (srcLength > 30)
        {
            throw std::runtime_error("string too large for putUnitOfMeasure [E106]");
        }

        std::memcpy(m_buffer + m_offset + 110, str.data(), srcLength);
        for (std::size_t start = srcLength; start < 30; ++start)
        {
            m_buffer[m_offset + 110 + start] = 0;
        }

        return *this;
    }
    #else
    MDInstrumentDefinitionFuture54 &putUnitOfMeasure(const std::string &str)
    {
        const std::size_t srcLength = str.length();
        if (srcLength > 30)
        {
            throw std::runtime_error("string too large for putUnitOfMeasure [E106]");
        }

        std::memcpy(m_buffer + m_offset + 110, str.c_str(), srcLength);
        for (std::size_t start = srcLength; start < 30; ++start)
        {
            m_buffer[m_offset + 110 + start] = 0;
        }

        return *this;
    }
    #endif

    SBE_NODISCARD static const char *UnitOfMeasureQtyMetaAttribute(const MetaAttribute metaAttribute) SBE_NOEXCEPT
    {
        switch (metaAttribute)
        {
            case MetaAttribute::SEMANTIC_TYPE: return "Qty";
            case MetaAttribute::PRESENCE: return "required";
            default: return "";
        }
    }

    static SBE_CONSTEXPR std::uint16_t unitOfMeasureQtyId() SBE_NOEXCEPT
    {
        return 1147;
    }

    SBE_NODISCARD static SBE_CONSTEXPR std::uint64_t unitOfMeasureQtySinceVersion() SBE_NOEXCEPT
    {
        return 9;
    }

    SBE_NODISCARD bool unitOfMeasureQtyInActingVersion() SBE_NOEXCEPT
    {
        return m_actingVersion >= unitOfMeasureQtySinceVersion();
    }

    SBE_NODISCARD static SBE_CONSTEXPR std::size_t unitOfMeasureQtyEncodingOffset() SBE_NOEXCEPT
    {
        return 140;
    }

private:
    Decimal9NULL m_unitOfMeasureQty;

public:
    SBE_NODISCARD Decimal9NULL &unitOfMeasureQty()
    {
        m_unitOfMeasureQty.wrap(m_buffer, m_offset + 140, m_actingVersion, m_bufferLength);
        return m_unitOfMeasureQty;
    }

    SBE_NODISCARD static const char *TradingReferencePriceMetaAttribute(const MetaAttribute metaAttribute) SBE_NOEXCEPT
    {
        switch (metaAttribute)
        {
            case MetaAttribute::SEMANTIC_TYPE: return "Price";
            case MetaAttribute::PRESENCE: return "required";
            default: return "";
        }
    }

    static SBE_CONSTEXPR std::uint16_t tradingReferencePriceId() SBE_NOEXCEPT
    {
        return 1150;
    }

    SBE_NODISCARD static SBE_CONSTEXPR std::uint64_t tradingReferencePriceSinceVersion() SBE_NOEXCEPT
    {
        return 9;
    }

    SBE_NODISCARD bool tradingReferencePriceInActingVersion() SBE_NOEXCEPT
    {
        return m_actingVersion >= tradingReferencePriceSinceVersion();
    }

    SBE_NODISCARD static SBE_CONSTEXPR std::size_t tradingReferencePriceEncodingOffset() SBE_NOEXCEPT
    {
        return 148;
    }

private:
    PRICENULL9 m_tradingReferencePrice;

public:
    SBE_NODISCARD PRICENULL9 &tradingReferencePrice()
    {
        m_tradingReferencePrice.wrap(m_buffer, m_offset + 148, m_actingVersion, m_bufferLength);
        return m_tradingReferencePrice;
    }

    SBE_NODISCARD static const char *SettlPriceTypeMetaAttribute(const MetaAttribute metaAttribute) SBE_NOEXCEPT
    {
        switch (metaAttribute)
        {
            case MetaAttribute::SEMANTIC_TYPE: return "MultipleCharValue";
            case MetaAttribute::PRESENCE: return "required";
            default: return "";
        }
    }

    static SBE_CONSTEXPR std::uint16_t settlPriceTypeId() SBE_NOEXCEPT
    {
        return 731;
    }

    SBE_NODISCARD static SBE_CONSTEXPR std::uint64_t settlPriceTypeSinceVersion() SBE_NOEXCEPT
    {
        return 0;
    }

    SBE_NODISCARD bool settlPriceTypeInActingVersion() SBE_NOEXCEPT
    {
        return true;
    }

    SBE_NODISCARD static SBE_CONSTEXPR std::size_t settlPriceTypeEncodingOffset() SBE_NOEXCEPT
    {
        return 156;
    }

private:
    SettlPriceType m_settlPriceType;

public:
    SBE_NODISCARD SettlPriceType &settlPriceType()
    {
        m_settlPriceType.wrap(m_buffer, m_offset + 156, m_actingVersion, m_bufferLength);
        return m_settlPriceType;
    }

    static SBE_CONSTEXPR std::size_t settlPriceTypeEncodingLength() SBE_NOEXCEPT
    {
        return 1;
    }

    SBE_NODISCARD static const char *OpenInterestQtyMetaAttribute(const MetaAttribute metaAttribute) SBE_NOEXCEPT
    {
        switch (metaAttribute)
        {
            case MetaAttribute::SEMANTIC_TYPE: return "Qty";
            case MetaAttribute::PRESENCE: return "optional";
            default: return "";
        }
    }

    static SBE_CONSTEXPR std::uint16_t openInterestQtyId() SBE_NOEXCEPT
    {
        return 5792;
    }

    SBE_NODISCARD static SBE_CONSTEXPR std::uint64_t openInterestQtySinceVersion() SBE_NOEXCEPT
    {
        return 0;
    }

    SBE_NODISCARD bool openInterestQtyInActingVersion() SBE_NOEXCEPT
    {
        return true;
    }

    SBE_NODISCARD static SBE_CONSTEXPR std::size_t openInterestQtyEncodingOffset() SBE_NOEXCEPT
    {
        return 157;
    }

    static SBE_CONSTEXPR std::int32_t openInterestQtyNullValue() SBE_NOEXCEPT
    {
        return INT32_C(2147483647);
    }

    static SBE_CONSTEXPR std::int32_t openInterestQtyMinValue() SBE_NOEXCEPT
    {
        return INT32_C(-2147483647);
    }

    static SBE_CONSTEXPR std::int32_t openInterestQtyMaxValue() SBE_NOEXCEPT
    {
        return INT32_C(2147483647);
    }

    static SBE_CONSTEXPR std::size_t openInterestQtyEncodingLength() SBE_NOEXCEPT
    {
        return 4;
    }

    SBE_NODISCARD std::int32_t openInterestQty() const SBE_NOEXCEPT
    {
        std::int32_t val;
        std::memcpy(&val, m_buffer + m_offset + 157, sizeof(std::int32_t));
        return SBE_LITTLE_ENDIAN_ENCODE_32(val);
    }

    MDInstrumentDefinitionFuture54 &openInterestQty(const std::int32_t value) SBE_NOEXCEPT
    {
        std::int32_t val = SBE_LITTLE_ENDIAN_ENCODE_32(value);
        std::memcpy(m_buffer + m_offset + 157, &val, sizeof(std::int32_t));
        return *this;
    }

    SBE_NODISCARD static const char *ClearedVolumeMetaAttribute(const MetaAttribute metaAttribute) SBE_NOEXCEPT
    {
        switch (metaAttribute)
        {
            case MetaAttribute::SEMANTIC_TYPE: return "Qty";
            case MetaAttribute::PRESENCE: return "optional";
            default: return "";
        }
    }

    static SBE_CONSTEXPR std::uint16_t clearedVolumeId() SBE_NOEXCEPT
    {
        return 5791;
    }

    SBE_NODISCARD static SBE_CONSTEXPR std::uint64_t clearedVolumeSinceVersion() SBE_NOEXCEPT
    {
        return 0;
    }

    SBE_NODISCARD bool clearedVolumeInActingVersion() SBE_NOEXCEPT
    {
        return true;
    }

    SBE_NODISCARD static SBE_CONSTEXPR std::size_t clearedVolumeEncodingOffset() SBE_NOEXCEPT
    {
        return 161;
    }

    static SBE_CONSTEXPR std::int32_t clearedVolumeNullValue() SBE_NOEXCEPT
    {
        return INT32_C(2147483647);
    }

    static SBE_CONSTEXPR std::int32_t clearedVolumeMinValue() SBE_NOEXCEPT
    {
        return INT32_C(-2147483647);
    }

    static SBE_CONSTEXPR std::int32_t clearedVolumeMaxValue() SBE_NOEXCEPT
    {
        return INT32_C(2147483647);
    }

    static SBE_CONSTEXPR std::size_t clearedVolumeEncodingLength() SBE_NOEXCEPT
    {
        return 4;
    }

    SBE_NODISCARD std::int32_t clearedVolume() const SBE_NOEXCEPT
    {
        std::int32_t val;
        std::memcpy(&val, m_buffer + m_offset + 161, sizeof(std::int32_t));
        return SBE_LITTLE_ENDIAN_ENCODE_32(val);
    }

    MDInstrumentDefinitionFuture54 &clearedVolume(const std::int32_t value) SBE_NOEXCEPT
    {
        std::int32_t val = SBE_LITTLE_ENDIAN_ENCODE_32(value);
        std::memcpy(m_buffer + m_offset + 161, &val, sizeof(std::int32_t));
        return *this;
    }

    SBE_NODISCARD static const char *HighLimitPriceMetaAttribute(const MetaAttribute metaAttribute) SBE_NOEXCEPT
    {
        switch (metaAttribute)
        {
            case MetaAttribute::SEMANTIC_TYPE: return "Price";
            case MetaAttribute::PRESENCE: return "required";
            default: return "";
        }
    }

    static SBE_CONSTEXPR std::uint16_t highLimitPriceId() SBE_NOEXCEPT
    {
        return 1149;
    }

    SBE_NODISCARD static SBE_CONSTEXPR std::uint64_t highLimitPriceSinceVersion() SBE_NOEXCEPT
    {
        return 9;
    }

    SBE_NODISCARD bool highLimitPriceInActingVersion() SBE_NOEXCEPT
    {
        return m_actingVersion >= highLimitPriceSinceVersion();
    }

    SBE_NODISCARD static SBE_CONSTEXPR std::size_t highLimitPriceEncodingOffset() SBE_NOEXCEPT
    {
        return 165;
    }

private:
    PRICENULL9 m_highLimitPrice;

public:
    SBE_NODISCARD PRICENULL9 &highLimitPrice()
    {
        m_highLimitPrice.wrap(m_buffer, m_offset + 165, m_actingVersion, m_bufferLength);
        return m_highLimitPrice;
    }

    SBE_NODISCARD static const char *LowLimitPriceMetaAttribute(const MetaAttribute metaAttribute) SBE_NOEXCEPT
    {
        switch (metaAttribute)
        {
            case MetaAttribute::SEMANTIC_TYPE: return "Price";
            case MetaAttribute::PRESENCE: return "required";
            default: return "";
        }
    }

    static SBE_CONSTEXPR std::uint16_t lowLimitPriceId() SBE_NOEXCEPT
    {
        return 1148;
    }

    SBE_NODISCARD static SBE_CONSTEXPR std::uint64_t lowLimitPriceSinceVersion() SBE_NOEXCEPT
    {
        return 9;
    }

    SBE_NODISCARD bool lowLimitPriceInActingVersion() SBE_NOEXCEPT
    {
        return m_actingVersion >= lowLimitPriceSinceVersion();
    }

    SBE_NODISCARD static SBE_CONSTEXPR std::size_t lowLimitPriceEncodingOffset() SBE_NOEXCEPT
    {
        return 173;
    }

private:
    PRICENULL9 m_lowLimitPrice;

public:
    SBE_NODISCARD PRICENULL9 &lowLimitPrice()
    {
        m_lowLimitPrice.wrap(m_buffer, m_offset + 173, m_actingVersion, m_bufferLength);
        return m_lowLimitPrice;
    }

    SBE_NODISCARD static const char *MaxPriceVariationMetaAttribute(const MetaAttribute metaAttribute) SBE_NOEXCEPT
    {
        switch (metaAttribute)
        {
            case MetaAttribute::SEMANTIC_TYPE: return "Price";
            case MetaAttribute::PRESENCE: return "required";
            default: return "";
        }
    }

    static SBE_CONSTEXPR std::uint16_t maxPriceVariationId() SBE_NOEXCEPT
    {
        return 1143;
    }

    SBE_NODISCARD static SBE_CONSTEXPR std::uint64_t maxPriceVariationSinceVersion() SBE_NOEXCEPT
    {
        return 9;
    }

    SBE_NODISCARD bool maxPriceVariationInActingVersion() SBE_NOEXCEPT
    {
        return m_actingVersion >= maxPriceVariationSinceVersion();
    }

    SBE_NODISCARD static SBE_CONSTEXPR std::size_t maxPriceVariationEncodingOffset() SBE_NOEXCEPT
    {
        return 181;
    }

private:
    PRICENULL9 m_maxPriceVariation;

public:
    SBE_NODISCARD PRICENULL9 &maxPriceVariation()
    {
        m_maxPriceVariation.wrap(m_buffer, m_offset + 181, m_actingVersion, m_bufferLength);
        return m_maxPriceVariation;
    }

    SBE_NODISCARD static const char *DecayQuantityMetaAttribute(const MetaAttribute metaAttribute) SBE_NOEXCEPT
    {
        switch (metaAttribute)
        {
            case MetaAttribute::SEMANTIC_TYPE: return "Qty";
            case MetaAttribute::PRESENCE: return "optional";
            default: return "";
        }
    }

    static SBE_CONSTEXPR std::uint16_t decayQuantityId() SBE_NOEXCEPT
    {
        return 5818;
    }

    SBE_NODISCARD static SBE_CONSTEXPR std::uint64_t decayQuantitySinceVersion() SBE_NOEXCEPT
    {
        return 0;
    }

    SBE_NODISCARD bool decayQuantityInActingVersion() SBE_NOEXCEPT
    {
        return true;
    }

    SBE_NODISCARD static SBE_CONSTEXPR std::size_t decayQuantityEncodingOffset() SBE_NOEXCEPT
    {
        return 189;
    }

    static SBE_CONSTEXPR std::int32_t decayQuantityNullValue() SBE_NOEXCEPT
    {
        return INT32_C(2147483647);
    }

    static SBE_CONSTEXPR std::int32_t decayQuantityMinValue() SBE_NOEXCEPT
    {
        return INT32_C(-2147483647);
    }

    static SBE_CONSTEXPR std::int32_t decayQuantityMaxValue() SBE_NOEXCEPT
    {
        return INT32_C(2147483647);
    }

    static SBE_CONSTEXPR std::size_t decayQuantityEncodingLength() SBE_NOEXCEPT
    {
        return 4;
    }

    SBE_NODISCARD std::int32_t decayQuantity() const SBE_NOEXCEPT
    {
        std::int32_t val;
        std::memcpy(&val, m_buffer + m_offset + 189, sizeof(std::int32_t));
        return SBE_LITTLE_ENDIAN_ENCODE_32(val);
    }

    MDInstrumentDefinitionFuture54 &decayQuantity(const std::int32_t value) SBE_NOEXCEPT
    {
        std::int32_t val = SBE_LITTLE_ENDIAN_ENCODE_32(value);
        std::memcpy(m_buffer + m_offset + 189, &val, sizeof(std::int32_t));
        return *this;
    }

    SBE_NODISCARD static const char *DecayStartDateMetaAttribute(const MetaAttribute metaAttribute) SBE_NOEXCEPT
    {
        switch (metaAttribute)
        {
            case MetaAttribute::SEMANTIC_TYPE: return "LocalMktDate";
            case MetaAttribute::PRESENCE: return "optional";
            default: return "";
        }
    }

    static SBE_CONSTEXPR std::uint16_t decayStartDateId() SBE_NOEXCEPT
    {
        return 5819;
    }

    SBE_NODISCARD static SBE_CONSTEXPR std::uint64_t decayStartDateSinceVersion() SBE_NOEXCEPT
    {
        return 0;
    }

    SBE_NODISCARD bool decayStartDateInActingVersion() SBE_NOEXCEPT
    {
        return true;
    }

    SBE_NODISCARD static SBE_CONSTEXPR std::size_t decayStartDateEncodingOffset() SBE_NOEXCEPT
    {
        return 193;
    }

    static SBE_CONSTEXPR std::uint16_t decayStartDateNullValue() SBE_NOEXCEPT
    {
        return static_cast<std::uint16_t>(65535);
    }

    static SBE_CONSTEXPR std::uint16_t decayStartDateMinValue() SBE_NOEXCEPT
    {
        return static_cast<std::uint16_t>(0);
    }

    static SBE_CONSTEXPR std::uint16_t decayStartDateMaxValue() SBE_NOEXCEPT
    {
        return static_cast<std::uint16_t>(65534);
    }

    static SBE_CONSTEXPR std::size_t decayStartDateEncodingLength() SBE_NOEXCEPT
    {
        return 2;
    }

    SBE_NODISCARD std::uint16_t decayStartDate() const SBE_NOEXCEPT
    {
        std::uint16_t val;
        std::memcpy(&val, m_buffer + m_offset + 193, sizeof(std::uint16_t));
        return SBE_LITTLE_ENDIAN_ENCODE_16(val);
    }

    MDInstrumentDefinitionFuture54 &decayStartDate(const std::uint16_t value) SBE_NOEXCEPT
    {
        std::uint16_t val = SBE_LITTLE_ENDIAN_ENCODE_16(value);
        std::memcpy(m_buffer + m_offset + 193, &val, sizeof(std::uint16_t));
        return *this;
    }

    SBE_NODISCARD static const char *OriginalContractSizeMetaAttribute(const MetaAttribute metaAttribute) SBE_NOEXCEPT
    {
        switch (metaAttribute)
        {
            case MetaAttribute::SEMANTIC_TYPE: return "Qty";
            case MetaAttribute::PRESENCE: return "optional";
            default: return "";
        }
    }

    static SBE_CONSTEXPR std::uint16_t originalContractSizeId() SBE_NOEXCEPT
    {
        return 5849;
    }

    SBE_NODISCARD static SBE_CONSTEXPR std::uint64_t originalContractSizeSinceVersion() SBE_NOEXCEPT
    {
        return 0;
    }

    SBE_NODISCARD bool originalContractSizeInActingVersion() SBE_NOEXCEPT
    {
        return true;
    }

    SBE_NODISCARD static SBE_CONSTEXPR std::size_t originalContractSizeEncodingOffset() SBE_NOEXCEPT
    {
        return 195;
    }

    static SBE_CONSTEXPR std::int32_t originalContractSizeNullValue() SBE_NOEXCEPT
    {
        return INT32_C(2147483647);
    }

    static SBE_CONSTEXPR std::int32_t originalContractSizeMinValue() SBE_NOEXCEPT
    {
        return INT32_C(-2147483647);
    }

    static SBE_CONSTEXPR std::int32_t originalContractSizeMaxValue() SBE_NOEXCEPT
    {
        return INT32_C(2147483647);
    }

    static SBE_CONSTEXPR std::size_t originalContractSizeEncodingLength() SBE_NOEXCEPT
    {
        return 4;
    }

    SBE_NODISCARD std::int32_t originalContractSize() const SBE_NOEXCEPT
    {
        std::int32_t val;
        std::memcpy(&val, m_buffer + m_offset + 195, sizeof(std::int32_t));
        return SBE_LITTLE_ENDIAN_ENCODE_32(val);
    }

    MDInstrumentDefinitionFuture54 &originalContractSize(const std::int32_t value) SBE_NOEXCEPT
    {
        std::int32_t val = SBE_LITTLE_ENDIAN_ENCODE_32(value);
        std::memcpy(m_buffer + m_offset + 195, &val, sizeof(std::int32_t));
        return *this;
    }

    SBE_NODISCARD static const char *ContractMultiplierMetaAttribute(const MetaAttribute metaAttribute) SBE_NOEXCEPT
    {
        switch (metaAttribute)
        {
            case MetaAttribute::SEMANTIC_TYPE: return "int";
            case MetaAttribute::PRESENCE: return "optional";
            default: return "";
        }
    }

    static SBE_CONSTEXPR std::uint16_t contractMultiplierId() SBE_NOEXCEPT
    {
        return 231;
    }

    SBE_NODISCARD static SBE_CONSTEXPR std::uint64_t contractMultiplierSinceVersion() SBE_NOEXCEPT
    {
        return 0;
    }

    SBE_NODISCARD bool contractMultiplierInActingVersion() SBE_NOEXCEPT
    {
        return true;
    }

    SBE_NODISCARD static SBE_CONSTEXPR std::size_t contractMultiplierEncodingOffset() SBE_NOEXCEPT
    {
        return 199;
    }

    static SBE_CONSTEXPR std::int32_t contractMultiplierNullValue() SBE_NOEXCEPT
    {
        return INT32_C(2147483647);
    }

    static SBE_CONSTEXPR std::int32_t contractMultiplierMinValue() SBE_NOEXCEPT
    {
        return INT32_C(-2147483647);
    }

    static SBE_CONSTEXPR std::int32_t contractMultiplierMaxValue() SBE_NOEXCEPT
    {
        return INT32_C(2147483647);
    }

    static SBE_CONSTEXPR std::size_t contractMultiplierEncodingLength() SBE_NOEXCEPT
    {
        return 4;
    }

    SBE_NODISCARD std::int32_t contractMultiplier() const SBE_NOEXCEPT
    {
        std::int32_t val;
        std::memcpy(&val, m_buffer + m_offset + 199, sizeof(std::int32_t));
        return SBE_LITTLE_ENDIAN_ENCODE_32(val);
    }

    MDInstrumentDefinitionFuture54 &contractMultiplier(const std::int32_t value) SBE_NOEXCEPT
    {
        std::int32_t val = SBE_LITTLE_ENDIAN_ENCODE_32(value);
        std::memcpy(m_buffer + m_offset + 199, &val, sizeof(std::int32_t));
        return *this;
    }

    SBE_NODISCARD static const char *ContractMultiplierUnitMetaAttribute(const MetaAttribute metaAttribute) SBE_NOEXCEPT
    {
        switch (metaAttribute)
        {
            case MetaAttribute::SEMANTIC_TYPE: return "int";
            case MetaAttribute::PRESENCE: return "optional";
            default: return "";
        }
    }

    static SBE_CONSTEXPR std::uint16_t contractMultiplierUnitId() SBE_NOEXCEPT
    {
        return 1435;
    }

    SBE_NODISCARD static SBE_CONSTEXPR std::uint64_t contractMultiplierUnitSinceVersion() SBE_NOEXCEPT
    {
        return 0;
    }

    SBE_NODISCARD bool contractMultiplierUnitInActingVersion() SBE_NOEXCEPT
    {
        return true;
    }

    SBE_NODISCARD static SBE_CONSTEXPR std::size_t contractMultiplierUnitEncodingOffset() SBE_NOEXCEPT
    {
        return 203;
    }

    static SBE_CONSTEXPR std::int8_t contractMultiplierUnitNullValue() SBE_NOEXCEPT
    {
        return static_cast<std::int8_t>(127);
    }

    static SBE_CONSTEXPR std::int8_t contractMultiplierUnitMinValue() SBE_NOEXCEPT
    {
        return static_cast<std::int8_t>(-127);
    }

    static SBE_CONSTEXPR std::int8_t contractMultiplierUnitMaxValue() SBE_NOEXCEPT
    {
        return static_cast<std::int8_t>(127);
    }

    static SBE_CONSTEXPR std::size_t contractMultiplierUnitEncodingLength() SBE_NOEXCEPT
    {
        return 1;
    }

    SBE_NODISCARD std::int8_t contractMultiplierUnit() const SBE_NOEXCEPT
    {
        std::int8_t val;
        std::memcpy(&val, m_buffer + m_offset + 203, sizeof(std::int8_t));
        return (val);
    }

    MDInstrumentDefinitionFuture54 &contractMultiplierUnit(const std::int8_t value) SBE_NOEXCEPT
    {
        std::int8_t val = (value);
        std::memcpy(m_buffer + m_offset + 203, &val, sizeof(std::int8_t));
        return *this;
    }

    SBE_NODISCARD static const char *FlowScheduleTypeMetaAttribute(const MetaAttribute metaAttribute) SBE_NOEXCEPT
    {
        switch (metaAttribute)
        {
            case MetaAttribute::SEMANTIC_TYPE: return "int";
            case MetaAttribute::PRESENCE: return "optional";
            default: return "";
        }
    }

    static SBE_CONSTEXPR std::uint16_t flowScheduleTypeId() SBE_NOEXCEPT
    {
        return 1439;
    }

    SBE_NODISCARD static SBE_CONSTEXPR std::uint64_t flowScheduleTypeSinceVersion() SBE_NOEXCEPT
    {
        return 0;
    }

    SBE_NODISCARD bool flowScheduleTypeInActingVersion() SBE_NOEXCEPT
    {
        return true;
    }

    SBE_NODISCARD static SBE_CONSTEXPR std::size_t flowScheduleTypeEncodingOffset() SBE_NOEXCEPT
    {
        return 204;
    }

    static SBE_CONSTEXPR std::int8_t flowScheduleTypeNullValue() SBE_NOEXCEPT
    {
        return static_cast<std::int8_t>(127);
    }

    static SBE_CONSTEXPR std::int8_t flowScheduleTypeMinValue() SBE_NOEXCEPT
    {
        return static_cast<std::int8_t>(-127);
    }

    static SBE_CONSTEXPR std::int8_t flowScheduleTypeMaxValue() SBE_NOEXCEPT
    {
        return static_cast<std::int8_t>(127);
    }

    static SBE_CONSTEXPR std::size_t flowScheduleTypeEncodingLength() SBE_NOEXCEPT
    {
        return 1;
    }

    SBE_NODISCARD std::int8_t flowScheduleType() const SBE_NOEXCEPT
    {
        std::int8_t val;
        std::memcpy(&val, m_buffer + m_offset + 204, sizeof(std::int8_t));
        return (val);
    }

    MDInstrumentDefinitionFuture54 &flowScheduleType(const std::int8_t value) SBE_NOEXCEPT
    {
        std::int8_t val = (value);
        std::memcpy(m_buffer + m_offset + 204, &val, sizeof(std::int8_t));
        return *this;
    }

    SBE_NODISCARD static const char *MinPriceIncrementAmountMetaAttribute(const MetaAttribute metaAttribute) SBE_NOEXCEPT
    {
        switch (metaAttribute)
        {
            case MetaAttribute::SEMANTIC_TYPE: return "Price";
            case MetaAttribute::PRESENCE: return "required";
            default: return "";
        }
    }

    static SBE_CONSTEXPR std::uint16_t minPriceIncrementAmountId() SBE_NOEXCEPT
    {
        return 1146;
    }

    SBE_NODISCARD static SBE_CONSTEXPR std::uint64_t minPriceIncrementAmountSinceVersion() SBE_NOEXCEPT
    {
        return 9;
    }

    SBE_NODISCARD bool minPriceIncrementAmountInActingVersion() SBE_NOEXCEPT
    {
        return m_actingVersion >= minPriceIncrementAmountSinceVersion();
    }

    SBE_NODISCARD static SBE_CONSTEXPR std::size_t minPriceIncrementAmountEncodingOffset() SBE_NOEXCEPT
    {
        return 205;
    }

private:
    PRICENULL9 m_minPriceIncrementAmount;

public:
    SBE_NODISCARD PRICENULL9 &minPriceIncrementAmount()
    {
        m_minPriceIncrementAmount.wrap(m_buffer, m_offset + 205, m_actingVersion, m_bufferLength);
        return m_minPriceIncrementAmount;
    }

    SBE_NODISCARD static const char *UserDefinedInstrumentMetaAttribute(const MetaAttribute metaAttribute) SBE_NOEXCEPT
    {
        switch (metaAttribute)
        {
            case MetaAttribute::SEMANTIC_TYPE: return "char";
            case MetaAttribute::PRESENCE: return "required";
            default: return "";
        }
    }

    static SBE_CONSTEXPR std::uint16_t userDefinedInstrumentId() SBE_NOEXCEPT
    {
        return 9779;
    }

    SBE_NODISCARD static SBE_CONSTEXPR std::uint64_t userDefinedInstrumentSinceVersion() SBE_NOEXCEPT
    {
        return 0;
    }

    SBE_NODISCARD bool userDefinedInstrumentInActingVersion() SBE_NOEXCEPT
    {
        return true;
    }

    SBE_NODISCARD static SBE_CONSTEXPR std::size_t userDefinedInstrumentEncodingOffset() SBE_NOEXCEPT
    {
        return 213;
    }

    static SBE_CONSTEXPR char userDefinedInstrumentNullValue() SBE_NOEXCEPT
    {
        return static_cast<char>(0);
    }

    static SBE_CONSTEXPR char userDefinedInstrumentMinValue() SBE_NOEXCEPT
    {
        return static_cast<char>(32);
    }

    static SBE_CONSTEXPR char userDefinedInstrumentMaxValue() SBE_NOEXCEPT
    {
        return static_cast<char>(126);
    }

    static SBE_CONSTEXPR std::size_t userDefinedInstrumentEncodingLength() SBE_NOEXCEPT
    {
        return 1;
    }

    SBE_NODISCARD char userDefinedInstrument() const SBE_NOEXCEPT
    {
        char val;
        std::memcpy(&val, m_buffer + m_offset + 213, sizeof(char));
        return (val);
    }

    MDInstrumentDefinitionFuture54 &userDefinedInstrument(const char value) SBE_NOEXCEPT
    {
        char val = (value);
        std::memcpy(m_buffer + m_offset + 213, &val, sizeof(char));
        return *this;
    }

    SBE_NODISCARD static const char *TradingReferenceDateMetaAttribute(const MetaAttribute metaAttribute) SBE_NOEXCEPT
    {
        switch (metaAttribute)
        {
            case MetaAttribute::SEMANTIC_TYPE: return "LocalMktDate";
            case MetaAttribute::PRESENCE: return "optional";
            default: return "";
        }
    }

    static SBE_CONSTEXPR std::uint16_t tradingReferenceDateId() SBE_NOEXCEPT
    {
        return 5796;
    }

    SBE_NODISCARD static SBE_CONSTEXPR std::uint64_t tradingReferenceDateSinceVersion() SBE_NOEXCEPT
    {
        return 0;
    }

    SBE_NODISCARD bool tradingReferenceDateInActingVersion() SBE_NOEXCEPT
    {
        return true;
    }

    SBE_NODISCARD static SBE_CONSTEXPR std::size_t tradingReferenceDateEncodingOffset() SBE_NOEXCEPT
    {
        return 214;
    }

    static SBE_CONSTEXPR std::uint16_t tradingReferenceDateNullValue() SBE_NOEXCEPT
    {
        return static_cast<std::uint16_t>(65535);
    }

    static SBE_CONSTEXPR std::uint16_t tradingReferenceDateMinValue() SBE_NOEXCEPT
    {
        return static_cast<std::uint16_t>(0);
    }

    static SBE_CONSTEXPR std::uint16_t tradingReferenceDateMaxValue() SBE_NOEXCEPT
    {
        return static_cast<std::uint16_t>(65534);
    }

    static SBE_CONSTEXPR std::size_t tradingReferenceDateEncodingLength() SBE_NOEXCEPT
    {
        return 2;
    }

    SBE_NODISCARD std::uint16_t tradingReferenceDate() const SBE_NOEXCEPT
    {
        std::uint16_t val;
        std::memcpy(&val, m_buffer + m_offset + 214, sizeof(std::uint16_t));
        return SBE_LITTLE_ENDIAN_ENCODE_16(val);
    }

    MDInstrumentDefinitionFuture54 &tradingReferenceDate(const std::uint16_t value) SBE_NOEXCEPT
    {
        std::uint16_t val = SBE_LITTLE_ENDIAN_ENCODE_16(value);
        std::memcpy(m_buffer + m_offset + 214, &val, sizeof(std::uint16_t));
        return *this;
    }

    SBE_NODISCARD static const char *InstrumentGUIDMetaAttribute(const MetaAttribute metaAttribute) SBE_NOEXCEPT
    {
        switch (metaAttribute)
        {
            case MetaAttribute::SEMANTIC_TYPE: return "int";
            case MetaAttribute::PRESENCE: return "optional";
            default: return "";
        }
    }

    static SBE_CONSTEXPR std::uint16_t instrumentGUIDId() SBE_NOEXCEPT
    {
        return 37513;
    }

    SBE_NODISCARD static SBE_CONSTEXPR std::uint64_t instrumentGUIDSinceVersion() SBE_NOEXCEPT
    {
        return 10;
    }

    SBE_NODISCARD bool instrumentGUIDInActingVersion() SBE_NOEXCEPT
    {
        return m_actingVersion >= instrumentGUIDSinceVersion();
    }

    SBE_NODISCARD static SBE_CONSTEXPR std::size_t instrumentGUIDEncodingOffset() SBE_NOEXCEPT
    {
        return 216;
    }

    static SBE_CONSTEXPR std::uint64_t instrumentGUIDNullValue() SBE_NOEXCEPT
    {
        return UINT64_C(0xffffffffffffffff);
    }

    static SBE_CONSTEXPR std::uint64_t instrumentGUIDMinValue() SBE_NOEXCEPT
    {
        return UINT64_C(0x0);
    }

    static SBE_CONSTEXPR std::uint64_t instrumentGUIDMaxValue() SBE_NOEXCEPT
    {
        return UINT64_C(0xfffffffffffffffe);
    }

    static SBE_CONSTEXPR std::size_t instrumentGUIDEncodingLength() SBE_NOEXCEPT
    {
        return 8;
    }

    SBE_NODISCARD std::uint64_t instrumentGUID() const SBE_NOEXCEPT
    {
        if (m_actingVersion < 10)
        {
            return UINT64_C(0xffffffffffffffff);
        }

        std::uint64_t val;
        std::memcpy(&val, m_buffer + m_offset + 216, sizeof(std::uint64_t));
        return SBE_LITTLE_ENDIAN_ENCODE_64(val);
    }

    MDInstrumentDefinitionFuture54 &instrumentGUID(const std::uint64_t value) SBE_NOEXCEPT
    {
        std::uint64_t val = SBE_LITTLE_ENDIAN_ENCODE_64(value);
        std::memcpy(m_buffer + m_offset + 216, &val, sizeof(std::uint64_t));
        return *this;
    }

    class NoEvents
    {
    private:
        char *m_buffer = nullptr;
        std::uint64_t m_bufferLength = 0;
        std::uint64_t m_initialPosition = 0;
        std::uint64_t *m_positionPtr = nullptr;
        std::uint64_t m_blockLength = 0;
        std::uint64_t m_count = 0;
        std::uint64_t m_index = 0;
        std::uint64_t m_offset = 0;
        std::uint64_t m_actingVersion = 0;

        SBE_NODISCARD std::uint64_t *sbePositionPtr() SBE_NOEXCEPT
        {
            return m_positionPtr;
        }

    public:
        NoEvents() = default;

        inline void wrapForDecode(
            char *buffer,
            std::uint64_t *pos,
            const std::uint64_t actingVersion,
            const std::uint64_t bufferLength)
        {
            GroupSize dimensions(buffer, *pos, bufferLength, actingVersion);
            m_buffer = buffer;
            m_bufferLength = bufferLength;
            m_blockLength = dimensions.blockLength();
            m_count = dimensions.numInGroup();
            m_index = 0;
            m_actingVersion = actingVersion;
            m_initialPosition = *pos;
            m_positionPtr = pos;
            *m_positionPtr = *m_positionPtr + 3;
        }

        inline void wrapForEncode(
            char *buffer,
            const std::uint8_t count,
            std::uint64_t *pos,
            const std::uint64_t actingVersion,
            const std::uint64_t bufferLength)
        {
    #if defined(__GNUG__) && !defined(__clang__)
    #pragma GCC diagnostic push
    #pragma GCC diagnostic ignored "-Wtype-limits"
    #endif
            if (count > 254)
            {
                throw std::runtime_error("count outside of allowed range [E110]");
            }
    #if defined(__GNUG__) && !defined(__clang__)
    #pragma GCC diagnostic pop
    #endif
            m_buffer = buffer;
            m_bufferLength = bufferLength;
            GroupSize dimensions(buffer, *pos, bufferLength, actingVersion);
            dimensions.blockLength(static_cast<std::uint16_t>(9));
            dimensions.numInGroup(static_cast<std::uint8_t>(count));
            m_index = 0;
            m_count = count;
            m_blockLength = 9;
            m_actingVersion = actingVersion;
            m_initialPosition = *pos;
            m_positionPtr = pos;
            *m_positionPtr = *m_positionPtr + 3;
        }

        static SBE_CONSTEXPR std::uint64_t sbeHeaderSize() SBE_NOEXCEPT
        {
            return 3;
        }

        static SBE_CONSTEXPR std::uint64_t sbeBlockLength() SBE_NOEXCEPT
        {
            return 9;
        }

        SBE_NODISCARD std::uint64_t sbeActingBlockLength() SBE_NOEXCEPT
        {
            return m_blockLength;
        }

        SBE_NODISCARD std::uint64_t sbePosition() const SBE_NOEXCEPT
        {
            return *m_positionPtr;
        }

        // NOLINTNEXTLINE(readability-convert-member-functions-to-static)
        std::uint64_t sbeCheckPosition(const std::uint64_t position)
        {
            if (SBE_BOUNDS_CHECK_EXPECT((position > m_bufferLength), false))
            {
                throw std::runtime_error("buffer too short [E100]");
            }
            return position;
        }

        void sbePosition(const std::uint64_t position)
        {
            *m_positionPtr = sbeCheckPosition(position);
        }

        SBE_NODISCARD inline std::uint64_t count() const SBE_NOEXCEPT
        {
            return m_count;
        }

        SBE_NODISCARD inline bool hasNext() const SBE_NOEXCEPT
        {
            return m_index < m_count;
        }

        inline NoEvents &next()
        {
            if (m_index >= m_count)
            {
                throw std::runtime_error("index >= count [E108]");
            }
            m_offset = *m_positionPtr;
            if (SBE_BOUNDS_CHECK_EXPECT(((m_offset + m_blockLength) > m_bufferLength), false))
            {
                throw std::runtime_error("buffer too short for next group index [E108]");
            }
            *m_positionPtr = m_offset + m_blockLength;
            ++m_index;

            return *this;
        }

        inline std::uint64_t resetCountToIndex()
        {
            m_count = m_index;
            GroupSize dimensions(m_buffer, m_initialPosition, m_bufferLength, m_actingVersion);
            dimensions.numInGroup(static_cast<std::uint8_t>(m_count));
            return m_count;
        }

        template<class Func> inline void forEach(Func &&func)
        {
            while (hasNext())
            {
                next();
                func(*this);
            }
        }


        SBE_NODISCARD static const char *EventTypeMetaAttribute(const MetaAttribute metaAttribute) SBE_NOEXCEPT
        {
            switch (metaAttribute)
            {
                case MetaAttribute::SEMANTIC_TYPE: return "int";
                case MetaAttribute::PRESENCE: return "required";
                default: return "";
            }
        }

        static SBE_CONSTEXPR std::uint16_t eventTypeId() SBE_NOEXCEPT
        {
            return 865;
        }

        SBE_NODISCARD static SBE_CONSTEXPR std::uint64_t eventTypeSinceVersion() SBE_NOEXCEPT
        {
            return 0;
        }

        SBE_NODISCARD bool eventTypeInActingVersion() SBE_NOEXCEPT
        {
            return true;
        }

        SBE_NODISCARD static SBE_CONSTEXPR std::size_t eventTypeEncodingOffset() SBE_NOEXCEPT
        {
            return 0;
        }

        SBE_NODISCARD static SBE_CONSTEXPR std::size_t eventTypeEncodingLength() SBE_NOEXCEPT
        {
            return 1;
        }

        SBE_NODISCARD std::uint8_t eventTypeRaw() const SBE_NOEXCEPT
        {
            std::uint8_t val;
            std::memcpy(&val, m_buffer + m_offset + 0, sizeof(std::uint8_t));
            return (val);
        }

        SBE_NODISCARD EventType::Value eventType() const
        {
            std::uint8_t val;
            std::memcpy(&val, m_buffer + m_offset + 0, sizeof(std::uint8_t));
            return EventType::get((val));
        }

        NoEvents &eventType(const EventType::Value value) SBE_NOEXCEPT
        {
            std::uint8_t val = (value);
            std::memcpy(m_buffer + m_offset + 0, &val, sizeof(std::uint8_t));
            return *this;
        }

        SBE_NODISCARD static const char *EventTimeMetaAttribute(const MetaAttribute metaAttribute) SBE_NOEXCEPT
        {
            switch (metaAttribute)
            {
                case MetaAttribute::SEMANTIC_TYPE: return "UTCTimestamp";
                case MetaAttribute::PRESENCE: return "required";
                default: return "";
            }
        }

        static SBE_CONSTEXPR std::uint16_t eventTimeId() SBE_NOEXCEPT
        {
            return 1145;
        }

        SBE_NODISCARD static SBE_CONSTEXPR std::uint64_t eventTimeSinceVersion() SBE_NOEXCEPT
        {
            return 0;
        }

        SBE_NODISCARD bool eventTimeInActingVersion() SBE_NOEXCEPT
        {
            return true;
        }

        SBE_NODISCARD static SBE_CONSTEXPR std::size_t eventTimeEncodingOffset() SBE_NOEXCEPT
        {
            return 1;
        }

        static SBE_CONSTEXPR std::uint64_t eventTimeNullValue() SBE_NOEXCEPT
        {
            return SBE_NULLVALUE_UINT64;
        }

        static SBE_CONSTEXPR std::uint64_t eventTimeMinValue() SBE_NOEXCEPT
        {
            return UINT64_C(0x0);
        }

        static SBE_CONSTEXPR std::uint64_t eventTimeMaxValue() SBE_NOEXCEPT
        {
            return UINT64_C(0xfffffffffffffffe);
        }

        static SBE_CONSTEXPR std::size_t eventTimeEncodingLength() SBE_NOEXCEPT
        {
            return 8;
        }

        SBE_NODISCARD std::uint64_t eventTime() const SBE_NOEXCEPT
        {
            std::uint64_t val;
            std::memcpy(&val, m_buffer + m_offset + 1, sizeof(std::uint64_t));
            return SBE_LITTLE_ENDIAN_ENCODE_64(val);
        }

        NoEvents &eventTime(const std::uint64_t value) SBE_NOEXCEPT
        {
            std::uint64_t val = SBE_LITTLE_ENDIAN_ENCODE_64(value);
            std::memcpy(m_buffer + m_offset + 1, &val, sizeof(std::uint64_t));
            return *this;
        }

        template<typename CharT, typename Traits>
        friend std::basic_ostream<CharT, Traits> & operator << (
            std::basic_ostream<CharT, Traits> &builder, NoEvents &writer)
        {
            builder << '{';
            builder << R"("EventType": )";
            builder << '"' << writer.eventType() << '"';

            builder << ", ";
            builder << R"("EventTime": )";
            builder << +writer.eventTime();

            builder << '}';

            return builder;
        }

        void skip()
        {
        }

        SBE_NODISCARD static SBE_CONSTEXPR bool isConstLength() SBE_NOEXCEPT
        {
            return true;
        }

        SBE_NODISCARD static std::size_t computeLength()
        {
#if defined(__GNUG__) && !defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wtype-limits"
#endif
            std::size_t length = sbeBlockLength();

            return length;
#if defined(__GNUG__) && !defined(__clang__)
#pragma GCC diagnostic pop
#endif
        }
    };

private:
    NoEvents m_noEvents;

public:
    SBE_NODISCARD static SBE_CONSTEXPR std::uint16_t NoEventsId() SBE_NOEXCEPT
    {
        return 864;
    }

    SBE_NODISCARD inline NoEvents &noEvents()
    {
        m_noEvents.wrapForDecode(m_buffer, sbePositionPtr(), m_actingVersion, m_bufferLength);
        return m_noEvents;
    }

    NoEvents &noEventsCount(const std::uint8_t count)
    {
        m_noEvents.wrapForEncode(m_buffer, count, sbePositionPtr(), m_actingVersion, m_bufferLength);
        return m_noEvents;
    }

    SBE_NODISCARD static SBE_CONSTEXPR std::uint64_t noEventsSinceVersion() SBE_NOEXCEPT
    {
        return 0;
    }

    SBE_NODISCARD bool noEventsInActingVersion() const SBE_NOEXCEPT
    {
        return true;
    }

    class NoMDFeedTypes
    {
    private:
        char *m_buffer = nullptr;
        std::uint64_t m_bufferLength = 0;
        std::uint64_t m_initialPosition = 0;
        std::uint64_t *m_positionPtr = nullptr;
        std::uint64_t m_blockLength = 0;
        std::uint64_t m_count = 0;
        std::uint64_t m_index = 0;
        std::uint64_t m_offset = 0;
        std::uint64_t m_actingVersion = 0;

        SBE_NODISCARD std::uint64_t *sbePositionPtr() SBE_NOEXCEPT
        {
            return m_positionPtr;
        }

    public:
        NoMDFeedTypes() = default;

        inline void wrapForDecode(
            char *buffer,
            std::uint64_t *pos,
            const std::uint64_t actingVersion,
            const std::uint64_t bufferLength)
        {
            GroupSize dimensions(buffer, *pos, bufferLength, actingVersion);
            m_buffer = buffer;
            m_bufferLength = bufferLength;
            m_blockLength = dimensions.blockLength();
            m_count = dimensions.numInGroup();
            m_index = 0;
            m_actingVersion = actingVersion;
            m_initialPosition = *pos;
            m_positionPtr = pos;
            *m_positionPtr = *m_positionPtr + 3;
        }

        inline void wrapForEncode(
            char *buffer,
            const std::uint8_t count,
            std::uint64_t *pos,
            const std::uint64_t actingVersion,
            const std::uint64_t bufferLength)
        {
    #if defined(__GNUG__) && !defined(__clang__)
    #pragma GCC diagnostic push
    #pragma GCC diagnostic ignored "-Wtype-limits"
    #endif
            if (count > 254)
            {
                throw std::runtime_error("count outside of allowed range [E110]");
            }
    #if defined(__GNUG__) && !defined(__clang__)
    #pragma GCC diagnostic pop
    #endif
            m_buffer = buffer;
            m_bufferLength = bufferLength;
            GroupSize dimensions(buffer, *pos, bufferLength, actingVersion);
            dimensions.blockLength(static_cast<std::uint16_t>(4));
            dimensions.numInGroup(static_cast<std::uint8_t>(count));
            m_index = 0;
            m_count = count;
            m_blockLength = 4;
            m_actingVersion = actingVersion;
            m_initialPosition = *pos;
            m_positionPtr = pos;
            *m_positionPtr = *m_positionPtr + 3;
        }

        static SBE_CONSTEXPR std::uint64_t sbeHeaderSize() SBE_NOEXCEPT
        {
            return 3;
        }

        static SBE_CONSTEXPR std::uint64_t sbeBlockLength() SBE_NOEXCEPT
        {
            return 4;
        }

        SBE_NODISCARD std::uint64_t sbeActingBlockLength() SBE_NOEXCEPT
        {
            return m_blockLength;
        }

        SBE_NODISCARD std::uint64_t sbePosition() const SBE_NOEXCEPT
        {
            return *m_positionPtr;
        }

        // NOLINTNEXTLINE(readability-convert-member-functions-to-static)
        std::uint64_t sbeCheckPosition(const std::uint64_t position)
        {
            if (SBE_BOUNDS_CHECK_EXPECT((position > m_bufferLength), false))
            {
                throw std::runtime_error("buffer too short [E100]");
            }
            return position;
        }

        void sbePosition(const std::uint64_t position)
        {
            *m_positionPtr = sbeCheckPosition(position);
        }

        SBE_NODISCARD inline std::uint64_t count() const SBE_NOEXCEPT
        {
            return m_count;
        }

        SBE_NODISCARD inline bool hasNext() const SBE_NOEXCEPT
        {
            return m_index < m_count;
        }

        inline NoMDFeedTypes &next()
        {
            if (m_index >= m_count)
            {
                throw std::runtime_error("index >= count [E108]");
            }
            m_offset = *m_positionPtr;
            if (SBE_BOUNDS_CHECK_EXPECT(((m_offset + m_blockLength) > m_bufferLength), false))
            {
                throw std::runtime_error("buffer too short for next group index [E108]");
            }
            *m_positionPtr = m_offset + m_blockLength;
            ++m_index;

            return *this;
        }

        inline std::uint64_t resetCountToIndex()
        {
            m_count = m_index;
            GroupSize dimensions(m_buffer, m_initialPosition, m_bufferLength, m_actingVersion);
            dimensions.numInGroup(static_cast<std::uint8_t>(m_count));
            return m_count;
        }

        template<class Func> inline void forEach(Func &&func)
        {
            while (hasNext())
            {
                next();
                func(*this);
            }
        }


        SBE_NODISCARD static const char *MDFeedTypeMetaAttribute(const MetaAttribute metaAttribute) SBE_NOEXCEPT
        {
            switch (metaAttribute)
            {
                case MetaAttribute::SEMANTIC_TYPE: return "String";
                case MetaAttribute::PRESENCE: return "required";
                default: return "";
            }
        }

        static SBE_CONSTEXPR std::uint16_t mDFeedTypeId() SBE_NOEXCEPT
        {
            return 1022;
        }

        SBE_NODISCARD static SBE_CONSTEXPR std::uint64_t mDFeedTypeSinceVersion() SBE_NOEXCEPT
        {
            return 0;
        }

        SBE_NODISCARD bool mDFeedTypeInActingVersion() SBE_NOEXCEPT
        {
            return true;
        }

        SBE_NODISCARD static SBE_CONSTEXPR std::size_t mDFeedTypeEncodingOffset() SBE_NOEXCEPT
        {
            return 0;
        }

        static SBE_CONSTEXPR char mDFeedTypeNullValue() SBE_NOEXCEPT
        {
            return static_cast<char>(0);
        }

        static SBE_CONSTEXPR char mDFeedTypeMinValue() SBE_NOEXCEPT
        {
            return static_cast<char>(32);
        }

        static SBE_CONSTEXPR char mDFeedTypeMaxValue() SBE_NOEXCEPT
        {
            return static_cast<char>(126);
        }

        static SBE_CONSTEXPR std::size_t mDFeedTypeEncodingLength() SBE_NOEXCEPT
        {
            return 3;
        }

        static SBE_CONSTEXPR std::uint64_t mDFeedTypeLength() SBE_NOEXCEPT
        {
            return 3;
        }

        SBE_NODISCARD const char *mDFeedType() const SBE_NOEXCEPT
        {
            return m_buffer + m_offset + 0;
        }

        SBE_NODISCARD char *mDFeedType() SBE_NOEXCEPT
        {
            return m_buffer + m_offset + 0;
        }

        SBE_NODISCARD char mDFeedType(const std::uint64_t index) const
        {
            if (index >= 3)
            {
                throw std::runtime_error("index out of range for mDFeedType [E104]");
            }

            char val;
            std::memcpy(&val, m_buffer + m_offset + 0 + (index * 1), sizeof(char));
            return (val);
        }

        NoMDFeedTypes &mDFeedType(const std::uint64_t index, const char value)
        {
            if (index >= 3)
            {
                throw std::runtime_error("index out of range for mDFeedType [E105]");
            }

            char val = (value);
            std::memcpy(m_buffer + m_offset + 0 + (index * 1), &val, sizeof(char));
            return *this;
        }

        std::uint64_t getMDFeedType(char *const dst, const std::uint64_t length) const
        {
            if (length > 3)
            {
                throw std::runtime_error("length too large for getMDFeedType [E106]");
            }

            std::memcpy(dst, m_buffer + m_offset + 0, sizeof(char) * static_cast<std::size_t>(length));
            return length;
        }

        NoMDFeedTypes &putMDFeedType(const char *const src) SBE_NOEXCEPT
        {
            std::memcpy(m_buffer + m_offset + 0, src, sizeof(char) * 3);
            return *this;
        }

        NoMDFeedTypes &putMDFeedType(
            const char value0,
            const char value1,
            const char value2) SBE_NOEXCEPT
        {
            char val0 = (value0);
            std::memcpy(m_buffer + m_offset + 0, &val0, sizeof(char));
            char val1 = (value1);
            std::memcpy(m_buffer + m_offset + 1, &val1, sizeof(char));
            char val2 = (value2);
            std::memcpy(m_buffer + m_offset + 2, &val2, sizeof(char));

            return *this;
        }

        SBE_NODISCARD std::string getMDFeedTypeAsString() const
        {
            const char *buffer = m_buffer + m_offset + 0;
            std::size_t length = 0;

            for (; length < 3 && *(buffer + length) != '\0'; ++length);
            std::string result(buffer, length);

            return result;
        }

        std::string getMDFeedTypeAsJsonEscapedString()
        {
            std::ostringstream oss;
            std::string s = getMDFeedTypeAsString();

            for (const auto c : s)
            {
                switch (c)
                {
                    case '"': oss << "\\\""; break;
                    case '\\': oss << "\\\\"; break;
                    case '\b': oss << "\\b"; break;
                    case '\f': oss << "\\f"; break;
                    case '\n': oss << "\\n"; break;
                    case '\r': oss << "\\r"; break;
                    case '\t': oss << "\\t"; break;

                    default:
                        if ('\x00' <= c && c <= '\x1f')
                        {
                            oss << "\\u" << std::hex << std::setw(4)
                                << std::setfill('0') << (int)(c);
                        }
                        else
                        {
                            oss << c;
                        }
                }
            }

            return oss.str();
        }

        #if __cplusplus >= 201703L
        SBE_NODISCARD std::string_view getMDFeedTypeAsStringView() const SBE_NOEXCEPT
        {
            const char *buffer = m_buffer + m_offset + 0;
            std::size_t length = 0;

            for (; length < 3 && *(buffer + length) != '\0'; ++length);
            std::string_view result(buffer, length);

            return result;
        }
        #endif

        #if __cplusplus >= 201703L
        NoMDFeedTypes &putMDFeedType(const std::string_view str)
        {
            const std::size_t srcLength = str.length();
            if (srcLength > 3)
            {
                throw std::runtime_error("string too large for putMDFeedType [E106]");
            }

            std::memcpy(m_buffer + m_offset + 0, str.data(), srcLength);
            for (std::size_t start = srcLength; start < 3; ++start)
            {
                m_buffer[m_offset + 0 + start] = 0;
            }

            return *this;
        }
        #else
        NoMDFeedTypes &putMDFeedType(const std::string &str)
        {
            const std::size_t srcLength = str.length();
            if (srcLength > 3)
            {
                throw std::runtime_error("string too large for putMDFeedType [E106]");
            }

            std::memcpy(m_buffer + m_offset + 0, str.c_str(), srcLength);
            for (std::size_t start = srcLength; start < 3; ++start)
            {
                m_buffer[m_offset + 0 + start] = 0;
            }

            return *this;
        }
        #endif

        SBE_NODISCARD static const char *MarketDepthMetaAttribute(const MetaAttribute metaAttribute) SBE_NOEXCEPT
        {
            switch (metaAttribute)
            {
                case MetaAttribute::SEMANTIC_TYPE: return "int";
                case MetaAttribute::PRESENCE: return "required";
                default: return "";
            }
        }

        static SBE_CONSTEXPR std::uint16_t marketDepthId() SBE_NOEXCEPT
        {
            return 264;
        }

        SBE_NODISCARD static SBE_CONSTEXPR std::uint64_t marketDepthSinceVersion() SBE_NOEXCEPT
        {
            return 0;
        }

        SBE_NODISCARD bool marketDepthInActingVersion() SBE_NOEXCEPT
        {
            return true;
        }

        SBE_NODISCARD static SBE_CONSTEXPR std::size_t marketDepthEncodingOffset() SBE_NOEXCEPT
        {
            return 3;
        }

        static SBE_CONSTEXPR std::int8_t marketDepthNullValue() SBE_NOEXCEPT
        {
            return SBE_NULLVALUE_INT8;
        }

        static SBE_CONSTEXPR std::int8_t marketDepthMinValue() SBE_NOEXCEPT
        {
            return static_cast<std::int8_t>(-127);
        }

        static SBE_CONSTEXPR std::int8_t marketDepthMaxValue() SBE_NOEXCEPT
        {
            return static_cast<std::int8_t>(127);
        }

        static SBE_CONSTEXPR std::size_t marketDepthEncodingLength() SBE_NOEXCEPT
        {
            return 1;
        }

        SBE_NODISCARD std::int8_t marketDepth() const SBE_NOEXCEPT
        {
            std::int8_t val;
            std::memcpy(&val, m_buffer + m_offset + 3, sizeof(std::int8_t));
            return (val);
        }

        NoMDFeedTypes &marketDepth(const std::int8_t value) SBE_NOEXCEPT
        {
            std::int8_t val = (value);
            std::memcpy(m_buffer + m_offset + 3, &val, sizeof(std::int8_t));
            return *this;
        }

        template<typename CharT, typename Traits>
        friend std::basic_ostream<CharT, Traits> & operator << (
            std::basic_ostream<CharT, Traits> &builder, NoMDFeedTypes &writer)
        {
            builder << '{';
            builder << R"("MDFeedType": )";
            builder << '"' <<
                writer.getMDFeedTypeAsJsonEscapedString().c_str() << '"';

            builder << ", ";
            builder << R"("MarketDepth": )";
            builder << +writer.marketDepth();

            builder << '}';

            return builder;
        }

        void skip()
        {
        }

        SBE_NODISCARD static SBE_CONSTEXPR bool isConstLength() SBE_NOEXCEPT
        {
            return true;
        }

        SBE_NODISCARD static std::size_t computeLength()
        {
#if defined(__GNUG__) && !defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wtype-limits"
#endif
            std::size_t length = sbeBlockLength();

            return length;
#if defined(__GNUG__) && !defined(__clang__)
#pragma GCC diagnostic pop
#endif
        }
    };

private:
    NoMDFeedTypes m_noMDFeedTypes;

public:
    SBE_NODISCARD static SBE_CONSTEXPR std::uint16_t NoMDFeedTypesId() SBE_NOEXCEPT
    {
        return 1141;
    }

    SBE_NODISCARD inline NoMDFeedTypes &noMDFeedTypes()
    {
        m_noMDFeedTypes.wrapForDecode(m_buffer, sbePositionPtr(), m_actingVersion, m_bufferLength);
        return m_noMDFeedTypes;
    }

    NoMDFeedTypes &noMDFeedTypesCount(const std::uint8_t count)
    {
        m_noMDFeedTypes.wrapForEncode(m_buffer, count, sbePositionPtr(), m_actingVersion, m_bufferLength);
        return m_noMDFeedTypes;
    }

    SBE_NODISCARD static SBE_CONSTEXPR std::uint64_t noMDFeedTypesSinceVersion() SBE_NOEXCEPT
    {
        return 0;
    }

    SBE_NODISCARD bool noMDFeedTypesInActingVersion() const SBE_NOEXCEPT
    {
        return true;
    }

    class NoInstAttrib
    {
    private:
        char *m_buffer = nullptr;
        std::uint64_t m_bufferLength = 0;
        std::uint64_t m_initialPosition = 0;
        std::uint64_t *m_positionPtr = nullptr;
        std::uint64_t m_blockLength = 0;
        std::uint64_t m_count = 0;
        std::uint64_t m_index = 0;
        std::uint64_t m_offset = 0;
        std::uint64_t m_actingVersion = 0;

        SBE_NODISCARD std::uint64_t *sbePositionPtr() SBE_NOEXCEPT
        {
            return m_positionPtr;
        }

    public:
        NoInstAttrib() = default;

        inline void wrapForDecode(
            char *buffer,
            std::uint64_t *pos,
            const std::uint64_t actingVersion,
            const std::uint64_t bufferLength)
        {
            GroupSize dimensions(buffer, *pos, bufferLength, actingVersion);
            m_buffer = buffer;
            m_bufferLength = bufferLength;
            m_blockLength = dimensions.blockLength();
            m_count = dimensions.numInGroup();
            m_index = 0;
            m_actingVersion = actingVersion;
            m_initialPosition = *pos;
            m_positionPtr = pos;
            *m_positionPtr = *m_positionPtr + 3;
        }

        inline void wrapForEncode(
            char *buffer,
            const std::uint8_t count,
            std::uint64_t *pos,
            const std::uint64_t actingVersion,
            const std::uint64_t bufferLength)
        {
    #if defined(__GNUG__) && !defined(__clang__)
    #pragma GCC diagnostic push
    #pragma GCC diagnostic ignored "-Wtype-limits"
    #endif
            if (count > 254)
            {
                throw std::runtime_error("count outside of allowed range [E110]");
            }
    #if defined(__GNUG__) && !defined(__clang__)
    #pragma GCC diagnostic pop
    #endif
            m_buffer = buffer;
            m_bufferLength = bufferLength;
            GroupSize dimensions(buffer, *pos, bufferLength, actingVersion);
            dimensions.blockLength(static_cast<std::uint16_t>(4));
            dimensions.numInGroup(static_cast<std::uint8_t>(count));
            m_index = 0;
            m_count = count;
            m_blockLength = 4;
            m_actingVersion = actingVersion;
            m_initialPosition = *pos;
            m_positionPtr = pos;
            *m_positionPtr = *m_positionPtr + 3;
        }

        static SBE_CONSTEXPR std::uint64_t sbeHeaderSize() SBE_NOEXCEPT
        {
            return 3;
        }

        static SBE_CONSTEXPR std::uint64_t sbeBlockLength() SBE_NOEXCEPT
        {
            return 4;
        }

        SBE_NODISCARD std::uint64_t sbeActingBlockLength() SBE_NOEXCEPT
        {
            return m_blockLength;
        }

        SBE_NODISCARD std::uint64_t sbePosition() const SBE_NOEXCEPT
        {
            return *m_positionPtr;
        }

        // NOLINTNEXTLINE(readability-convert-member-functions-to-static)
        std::uint64_t sbeCheckPosition(const std::uint64_t position)
        {
            if (SBE_BOUNDS_CHECK_EXPECT((position > m_bufferLength), false))
            {
                throw std::runtime_error("buffer too short [E100]");
            }
            return position;
        }

        void sbePosition(const std::uint64_t position)
        {
            *m_positionPtr = sbeCheckPosition(position);
        }

        SBE_NODISCARD inline std::uint64_t count() const SBE_NOEXCEPT
        {
            return m_count;
        }

        SBE_NODISCARD inline bool hasNext() const SBE_NOEXCEPT
        {
            return m_index < m_count;
        }

        inline NoInstAttrib &next()
        {
            if (m_index >= m_count)
            {
                throw std::runtime_error("index >= count [E108]");
            }
            m_offset = *m_positionPtr;
            if (SBE_BOUNDS_CHECK_EXPECT(((m_offset + m_blockLength) > m_bufferLength), false))
            {
                throw std::runtime_error("buffer too short for next group index [E108]");
            }
            *m_positionPtr = m_offset + m_blockLength;
            ++m_index;

            return *this;
        }

        inline std::uint64_t resetCountToIndex()
        {
            m_count = m_index;
            GroupSize dimensions(m_buffer, m_initialPosition, m_bufferLength, m_actingVersion);
            dimensions.numInGroup(static_cast<std::uint8_t>(m_count));
            return m_count;
        }

        template<class Func> inline void forEach(Func &&func)
        {
            while (hasNext())
            {
                next();
                func(*this);
            }
        }


        SBE_NODISCARD static const char *InstAttribTypeMetaAttribute(const MetaAttribute metaAttribute) SBE_NOEXCEPT
        {
            switch (metaAttribute)
            {
                case MetaAttribute::SEMANTIC_TYPE: return "int";
                case MetaAttribute::PRESENCE: return "constant";
                default: return "";
            }
        }

        static SBE_CONSTEXPR std::uint16_t instAttribTypeId() SBE_NOEXCEPT
        {
            return 871;
        }

        SBE_NODISCARD static SBE_CONSTEXPR std::uint64_t instAttribTypeSinceVersion() SBE_NOEXCEPT
        {
            return 0;
        }

        SBE_NODISCARD bool instAttribTypeInActingVersion() SBE_NOEXCEPT
        {
            return true;
        }

        SBE_NODISCARD static SBE_CONSTEXPR std::size_t instAttribTypeEncodingOffset() SBE_NOEXCEPT
        {
            return 0;
        }

        static SBE_CONSTEXPR std::int8_t instAttribTypeNullValue() SBE_NOEXCEPT
        {
            return SBE_NULLVALUE_INT8;
        }

        static SBE_CONSTEXPR std::int8_t instAttribTypeMinValue() SBE_NOEXCEPT
        {
            return static_cast<std::int8_t>(-127);
        }

        static SBE_CONSTEXPR std::int8_t instAttribTypeMaxValue() SBE_NOEXCEPT
        {
            return static_cast<std::int8_t>(127);
        }

        static SBE_CONSTEXPR std::size_t instAttribTypeEncodingLength() SBE_NOEXCEPT
        {
            return 0;
        }

        SBE_NODISCARD static SBE_CONSTEXPR std::int8_t instAttribType() SBE_NOEXCEPT
        {
            return static_cast<std::int8_t>(24);
        }

        SBE_NODISCARD static const char *InstAttribValueMetaAttribute(const MetaAttribute metaAttribute) SBE_NOEXCEPT
        {
            switch (metaAttribute)
            {
                case MetaAttribute::SEMANTIC_TYPE: return "MultipleCharValue";
                case MetaAttribute::PRESENCE: return "required";
                default: return "";
            }
        }

        static SBE_CONSTEXPR std::uint16_t instAttribValueId() SBE_NOEXCEPT
        {
            return 872;
        }

        SBE_NODISCARD static SBE_CONSTEXPR std::uint64_t instAttribValueSinceVersion() SBE_NOEXCEPT
        {
            return 0;
        }

        SBE_NODISCARD bool instAttribValueInActingVersion() SBE_NOEXCEPT
        {
            return true;
        }

        SBE_NODISCARD static SBE_CONSTEXPR std::size_t instAttribValueEncodingOffset() SBE_NOEXCEPT
        {
            return 0;
        }

    private:
        InstAttribValue m_instAttribValue;

    public:
        SBE_NODISCARD InstAttribValue &instAttribValue()
        {
            m_instAttribValue.wrap(m_buffer, m_offset + 0, m_actingVersion, m_bufferLength);
            return m_instAttribValue;
        }

        static SBE_CONSTEXPR std::size_t instAttribValueEncodingLength() SBE_NOEXCEPT
        {
            return 4;
        }

        template<typename CharT, typename Traits>
        friend std::basic_ostream<CharT, Traits> & operator << (
            std::basic_ostream<CharT, Traits> &builder, NoInstAttrib &writer)
        {
            builder << '{';
            builder << R"("InstAttribValue": )";
            builder << writer.instAttribValue();

            builder << '}';

            return builder;
        }

        void skip()
        {
        }

        SBE_NODISCARD static SBE_CONSTEXPR bool isConstLength() SBE_NOEXCEPT
        {
            return true;
        }

        SBE_NODISCARD static std::size_t computeLength()
        {
#if defined(__GNUG__) && !defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wtype-limits"
#endif
            std::size_t length = sbeBlockLength();

            return length;
#if defined(__GNUG__) && !defined(__clang__)
#pragma GCC diagnostic pop
#endif
        }
    };

private:
    NoInstAttrib m_noInstAttrib;

public:
    SBE_NODISCARD static SBE_CONSTEXPR std::uint16_t NoInstAttribId() SBE_NOEXCEPT
    {
        return 870;
    }

    SBE_NODISCARD inline NoInstAttrib &noInstAttrib()
    {
        m_noInstAttrib.wrapForDecode(m_buffer, sbePositionPtr(), m_actingVersion, m_bufferLength);
        return m_noInstAttrib;
    }

    NoInstAttrib &noInstAttribCount(const std::uint8_t count)
    {
        m_noInstAttrib.wrapForEncode(m_buffer, count, sbePositionPtr(), m_actingVersion, m_bufferLength);
        return m_noInstAttrib;
    }

    SBE_NODISCARD static SBE_CONSTEXPR std::uint64_t noInstAttribSinceVersion() SBE_NOEXCEPT
    {
        return 0;
    }

    SBE_NODISCARD bool noInstAttribInActingVersion() const SBE_NOEXCEPT
    {
        return true;
    }

    class NoLotTypeRules
    {
    private:
        char *m_buffer = nullptr;
        std::uint64_t m_bufferLength = 0;
        std::uint64_t m_initialPosition = 0;
        std::uint64_t *m_positionPtr = nullptr;
        std::uint64_t m_blockLength = 0;
        std::uint64_t m_count = 0;
        std::uint64_t m_index = 0;
        std::uint64_t m_offset = 0;
        std::uint64_t m_actingVersion = 0;

        SBE_NODISCARD std::uint64_t *sbePositionPtr() SBE_NOEXCEPT
        {
            return m_positionPtr;
        }

    public:
        NoLotTypeRules() = default;

        inline void wrapForDecode(
            char *buffer,
            std::uint64_t *pos,
            const std::uint64_t actingVersion,
            const std::uint64_t bufferLength)
        {
            GroupSize dimensions(buffer, *pos, bufferLength, actingVersion);
            m_buffer = buffer;
            m_bufferLength = bufferLength;
            m_blockLength = dimensions.blockLength();
            m_count = dimensions.numInGroup();
            m_index = 0;
            m_actingVersion = actingVersion;
            m_initialPosition = *pos;
            m_positionPtr = pos;
            *m_positionPtr = *m_positionPtr + 3;
        }

        inline void wrapForEncode(
            char *buffer,
            const std::uint8_t count,
            std::uint64_t *pos,
            const std::uint64_t actingVersion,
            const std::uint64_t bufferLength)
        {
    #if defined(__GNUG__) && !defined(__clang__)
    #pragma GCC diagnostic push
    #pragma GCC diagnostic ignored "-Wtype-limits"
    #endif
            if (count > 254)
            {
                throw std::runtime_error("count outside of allowed range [E110]");
            }
    #if defined(__GNUG__) && !defined(__clang__)
    #pragma GCC diagnostic pop
    #endif
            m_buffer = buffer;
            m_bufferLength = bufferLength;
            GroupSize dimensions(buffer, *pos, bufferLength, actingVersion);
            dimensions.blockLength(static_cast<std::uint16_t>(5));
            dimensions.numInGroup(static_cast<std::uint8_t>(count));
            m_index = 0;
            m_count = count;
            m_blockLength = 5;
            m_actingVersion = actingVersion;
            m_initialPosition = *pos;
            m_positionPtr = pos;
            *m_positionPtr = *m_positionPtr + 3;
        }

        static SBE_CONSTEXPR std::uint64_t sbeHeaderSize() SBE_NOEXCEPT
        {
            return 3;
        }

        static SBE_CONSTEXPR std::uint64_t sbeBlockLength() SBE_NOEXCEPT
        {
            return 5;
        }

        SBE_NODISCARD std::uint64_t sbeActingBlockLength() SBE_NOEXCEPT
        {
            return m_blockLength;
        }

        SBE_NODISCARD std::uint64_t sbePosition() const SBE_NOEXCEPT
        {
            return *m_positionPtr;
        }

        // NOLINTNEXTLINE(readability-convert-member-functions-to-static)
        std::uint64_t sbeCheckPosition(const std::uint64_t position)
        {
            if (SBE_BOUNDS_CHECK_EXPECT((position > m_bufferLength), false))
            {
                throw std::runtime_error("buffer too short [E100]");
            }
            return position;
        }

        void sbePosition(const std::uint64_t position)
        {
            *m_positionPtr = sbeCheckPosition(position);
        }

        SBE_NODISCARD inline std::uint64_t count() const SBE_NOEXCEPT
        {
            return m_count;
        }

        SBE_NODISCARD inline bool hasNext() const SBE_NOEXCEPT
        {
            return m_index < m_count;
        }

        inline NoLotTypeRules &next()
        {
            if (m_index >= m_count)
            {
                throw std::runtime_error("index >= count [E108]");
            }
            m_offset = *m_positionPtr;
            if (SBE_BOUNDS_CHECK_EXPECT(((m_offset + m_blockLength) > m_bufferLength), false))
            {
                throw std::runtime_error("buffer too short for next group index [E108]");
            }
            *m_positionPtr = m_offset + m_blockLength;
            ++m_index;

            return *this;
        }

        inline std::uint64_t resetCountToIndex()
        {
            m_count = m_index;
            GroupSize dimensions(m_buffer, m_initialPosition, m_bufferLength, m_actingVersion);
            dimensions.numInGroup(static_cast<std::uint8_t>(m_count));
            return m_count;
        }

        template<class Func> inline void forEach(Func &&func)
        {
            while (hasNext())
            {
                next();
                func(*this);
            }
        }


        SBE_NODISCARD static const char *LotTypeMetaAttribute(const MetaAttribute metaAttribute) SBE_NOEXCEPT
        {
            switch (metaAttribute)
            {
                case MetaAttribute::SEMANTIC_TYPE: return "int";
                case MetaAttribute::PRESENCE: return "required";
                default: return "";
            }
        }

        static SBE_CONSTEXPR std::uint16_t lotTypeId() SBE_NOEXCEPT
        {
            return 1093;
        }

        SBE_NODISCARD static SBE_CONSTEXPR std::uint64_t lotTypeSinceVersion() SBE_NOEXCEPT
        {
            return 0;
        }

        SBE_NODISCARD bool lotTypeInActingVersion() SBE_NOEXCEPT
        {
            return true;
        }

        SBE_NODISCARD static SBE_CONSTEXPR std::size_t lotTypeEncodingOffset() SBE_NOEXCEPT
        {
            return 0;
        }

        static SBE_CONSTEXPR std::int8_t lotTypeNullValue() SBE_NOEXCEPT
        {
            return SBE_NULLVALUE_INT8;
        }

        static SBE_CONSTEXPR std::int8_t lotTypeMinValue() SBE_NOEXCEPT
        {
            return static_cast<std::int8_t>(-127);
        }

        static SBE_CONSTEXPR std::int8_t lotTypeMaxValue() SBE_NOEXCEPT
        {
            return static_cast<std::int8_t>(127);
        }

        static SBE_CONSTEXPR std::size_t lotTypeEncodingLength() SBE_NOEXCEPT
        {
            return 1;
        }

        SBE_NODISCARD std::int8_t lotType() const SBE_NOEXCEPT
        {
            std::int8_t val;
            std::memcpy(&val, m_buffer + m_offset + 0, sizeof(std::int8_t));
            return (val);
        }

        NoLotTypeRules &lotType(const std::int8_t value) SBE_NOEXCEPT
        {
            std::int8_t val = (value);
            std::memcpy(m_buffer + m_offset + 0, &val, sizeof(std::int8_t));
            return *this;
        }

        SBE_NODISCARD static const char *MinLotSizeMetaAttribute(const MetaAttribute metaAttribute) SBE_NOEXCEPT
        {
            switch (metaAttribute)
            {
                case MetaAttribute::SEMANTIC_TYPE: return "Qty";
                case MetaAttribute::PRESENCE: return "required";
                default: return "";
            }
        }

        static SBE_CONSTEXPR std::uint16_t minLotSizeId() SBE_NOEXCEPT
        {
            return 1231;
        }

        SBE_NODISCARD static SBE_CONSTEXPR std::uint64_t minLotSizeSinceVersion() SBE_NOEXCEPT
        {
            return 0;
        }

        SBE_NODISCARD bool minLotSizeInActingVersion() SBE_NOEXCEPT
        {
            return true;
        }

        SBE_NODISCARD static SBE_CONSTEXPR std::size_t minLotSizeEncodingOffset() SBE_NOEXCEPT
        {
            return 1;
        }

private:
        DecimalQty m_minLotSize;

public:
        SBE_NODISCARD DecimalQty &minLotSize()
        {
            m_minLotSize.wrap(m_buffer, m_offset + 1, m_actingVersion, m_bufferLength);
            return m_minLotSize;
        }

        template<typename CharT, typename Traits>
        friend std::basic_ostream<CharT, Traits> & operator << (
            std::basic_ostream<CharT, Traits> &builder, NoLotTypeRules &writer)
        {
            builder << '{';
            builder << R"("LotType": )";
            builder << +writer.lotType();

            builder << ", ";
            builder << R"("MinLotSize": )";
            builder << writer.minLotSize();

            builder << '}';

            return builder;
        }

        void skip()
        {
        }

        SBE_NODISCARD static SBE_CONSTEXPR bool isConstLength() SBE_NOEXCEPT
        {
            return true;
        }

        SBE_NODISCARD static std::size_t computeLength()
        {
#if defined(__GNUG__) && !defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wtype-limits"
#endif
            std::size_t length = sbeBlockLength();

            return length;
#if defined(__GNUG__) && !defined(__clang__)
#pragma GCC diagnostic pop
#endif
        }
    };

private:
    NoLotTypeRules m_noLotTypeRules;

public:
    SBE_NODISCARD static SBE_CONSTEXPR std::uint16_t NoLotTypeRulesId() SBE_NOEXCEPT
    {
        return 1234;
    }

    SBE_NODISCARD inline NoLotTypeRules &noLotTypeRules()
    {
        m_noLotTypeRules.wrapForDecode(m_buffer, sbePositionPtr(), m_actingVersion, m_bufferLength);
        return m_noLotTypeRules;
    }

    NoLotTypeRules &noLotTypeRulesCount(const std::uint8_t count)
    {
        m_noLotTypeRules.wrapForEncode(m_buffer, count, sbePositionPtr(), m_actingVersion, m_bufferLength);
        return m_noLotTypeRules;
    }

    SBE_NODISCARD static SBE_CONSTEXPR std::uint64_t noLotTypeRulesSinceVersion() SBE_NOEXCEPT
    {
        return 0;
    }

    SBE_NODISCARD bool noLotTypeRulesInActingVersion() const SBE_NOEXCEPT
    {
        return true;
    }

template<typename CharT, typename Traits>
friend std::basic_ostream<CharT, Traits> & operator << (
    std::basic_ostream<CharT, Traits> &builder, const MDInstrumentDefinitionFuture54 &_writer)
{
    MDInstrumentDefinitionFuture54 writer(
        _writer.m_buffer,
        _writer.m_offset,
        _writer.m_bufferLength,
        _writer.m_actingBlockLength,
        _writer.m_actingVersion);

    builder << '{';
    builder << R"("Name": "MDInstrumentDefinitionFuture54", )";
    builder << R"("sbeTemplateId": )";
    builder << writer.sbeTemplateId();
    builder << ", ";

    builder << R"("MatchEventIndicator": )";
    builder << writer.matchEventIndicator();

    builder << ", ";
    builder << R"("TotNumReports": )";
    builder << +writer.totNumReports();

    builder << ", ";
    builder << R"("SecurityUpdateAction": )";
    builder << '"' << writer.securityUpdateAction() << '"';

    builder << ", ";
    builder << R"("LastUpdateTime": )";
    builder << +writer.lastUpdateTime();

    builder << ", ";
    builder << R"("MDSecurityTradingStatus": )";
    builder << '"' << writer.mDSecurityTradingStatus() << '"';

    builder << ", ";
    builder << R"("ApplID": )";
    builder << +writer.applID();

    builder << ", ";
    builder << R"("MarketSegmentID": )";
    builder << +writer.marketSegmentID();

    builder << ", ";
    builder << R"("UnderlyingProduct": )";
    builder << +writer.underlyingProduct();

    builder << ", ";
    builder << R"("SecurityExchange": )";
    builder << '"' <<
        writer.getSecurityExchangeAsJsonEscapedString().c_str() << '"';

    builder << ", ";
    builder << R"("SecurityGroup": )";
    builder << '"' <<
        writer.getSecurityGroupAsJsonEscapedString().c_str() << '"';

    builder << ", ";
    builder << R"("Asset": )";
    builder << '"' <<
        writer.getAssetAsJsonEscapedString().c_str() << '"';

    builder << ", ";
    builder << R"("Symbol": )";
    builder << '"' <<
        writer.getSymbolAsJsonEscapedString().c_str() << '"';

    builder << ", ";
    builder << R"("SecurityID": )";
    builder << +writer.securityID();

    builder << ", ";
    builder << R"("SecurityType": )";
    builder << '"' <<
        writer.getSecurityTypeAsJsonEscapedString().c_str() << '"';

    builder << ", ";
    builder << R"("CFICode": )";
    builder << '"' <<
        writer.getCFICodeAsJsonEscapedString().c_str() << '"';

    builder << ", ";
    builder << R"("MaturityMonthYear": )";
    builder << writer.maturityMonthYear();

    builder << ", ";
    builder << R"("Currency": )";
    builder << '"' <<
        writer.getCurrencyAsJsonEscapedString().c_str() << '"';

    builder << ", ";
    builder << R"("SettlCurrency": )";
    builder << '"' <<
        writer.getSettlCurrencyAsJsonEscapedString().c_str() << '"';

    builder << ", ";
    builder << R"("MatchAlgorithm": )";
    if (std::isprint(writer.matchAlgorithm()))
    {
        builder << '"' << (char)writer.matchAlgorithm() << '"';
    }
    else
    {
        builder << (int)writer.matchAlgorithm();
    }

    builder << ", ";
    builder << R"("MinTradeVol": )";
    builder << +writer.minTradeVol();

    builder << ", ";
    builder << R"("MaxTradeVol": )";
    builder << +writer.maxTradeVol();

    builder << ", ";
    builder << R"("MinPriceIncrement": )";
    if (writer.minPriceIncrementInActingVersion())
    {
        builder << writer.minPriceIncrement();
    }
    else
    {
        builder << "{}";
    }

    builder << ", ";
    builder << R"("DisplayFactor": )";
    if (writer.displayFactorInActingVersion())
    {
        builder << writer.displayFactor();
    }
    else
    {
        builder << "{}";
    }

    builder << ", ";
    builder << R"("MainFraction": )";
    builder << +writer.mainFraction();

    builder << ", ";
    builder << R"("SubFraction": )";
    builder << +writer.subFraction();

    builder << ", ";
    builder << R"("PriceDisplayFormat": )";
    builder << +writer.priceDisplayFormat();

    builder << ", ";
    builder << R"("UnitOfMeasure": )";
    builder << '"' <<
        writer.getUnitOfMeasureAsJsonEscapedString().c_str() << '"';

    builder << ", ";
    builder << R"("UnitOfMeasureQty": )";
    if (writer.unitOfMeasureQtyInActingVersion())
    {
        builder << writer.unitOfMeasureQty();
    }
    else
    {
        builder << "{}";
    }

    builder << ", ";
    builder << R"("TradingReferencePrice": )";
    if (writer.tradingReferencePriceInActingVersion())
    {
        builder << writer.tradingReferencePrice();
    }
    else
    {
        builder << "{}";
    }

    builder << ", ";
    builder << R"("SettlPriceType": )";
    builder << writer.settlPriceType();

    builder << ", ";
    builder << R"("OpenInterestQty": )";
    builder << +writer.openInterestQty();

    builder << ", ";
    builder << R"("ClearedVolume": )";
    builder << +writer.clearedVolume();

    builder << ", ";
    builder << R"("HighLimitPrice": )";
    if (writer.highLimitPriceInActingVersion())
    {
        builder << writer.highLimitPrice();
    }
    else
    {
        builder << "{}";
    }

    builder << ", ";
    builder << R"("LowLimitPrice": )";
    if (writer.lowLimitPriceInActingVersion())
    {
        builder << writer.lowLimitPrice();
    }
    else
    {
        builder << "{}";
    }

    builder << ", ";
    builder << R"("MaxPriceVariation": )";
    if (writer.maxPriceVariationInActingVersion())
    {
        builder << writer.maxPriceVariation();
    }
    else
    {
        builder << "{}";
    }

    builder << ", ";
    builder << R"("DecayQuantity": )";
    builder << +writer.decayQuantity();

    builder << ", ";
    builder << R"("DecayStartDate": )";
    builder << +writer.decayStartDate();

    builder << ", ";
    builder << R"("OriginalContractSize": )";
    builder << +writer.originalContractSize();

    builder << ", ";
    builder << R"("ContractMultiplier": )";
    builder << +writer.contractMultiplier();

    builder << ", ";
    builder << R"("ContractMultiplierUnit": )";
    builder << +writer.contractMultiplierUnit();

    builder << ", ";
    builder << R"("FlowScheduleType": )";
    builder << +writer.flowScheduleType();

    builder << ", ";
    builder << R"("MinPriceIncrementAmount": )";
    if (writer.minPriceIncrementAmountInActingVersion())
    {
        builder << writer.minPriceIncrementAmount();
    }
    else
    {
        builder << "{}";
    }

    builder << ", ";
    builder << R"("UserDefinedInstrument": )";
    if (std::isprint(writer.userDefinedInstrument()))
    {
        builder << '"' << (char)writer.userDefinedInstrument() << '"';
    }
    else
    {
        builder << (int)writer.userDefinedInstrument();
    }

    builder << ", ";
    builder << R"("TradingReferenceDate": )";
    builder << +writer.tradingReferenceDate();

    builder << ", ";
    builder << R"("InstrumentGUID": )";
    builder << +writer.instrumentGUID();

    builder << ", ";
    {
        bool atLeastOne = false;
        builder << R"("NoEvents": [)";
        writer.noEvents().forEach(
            [&](NoEvents &noEvents)
            {
                if (atLeastOne)
                {
                    builder << ", ";
                }
                atLeastOne = true;
                builder << noEvents;
            });
        builder << ']';
    }

    builder << ", ";
    {
        bool atLeastOne = false;
        builder << R"("NoMDFeedTypes": [)";
        writer.noMDFeedTypes().forEach(
            [&](NoMDFeedTypes &noMDFeedTypes)
            {
                if (atLeastOne)
                {
                    builder << ", ";
                }
                atLeastOne = true;
                builder << noMDFeedTypes;
            });
        builder << ']';
    }

    builder << ", ";
    {
        bool atLeastOne = false;
        builder << R"("NoInstAttrib": [)";
        writer.noInstAttrib().forEach(
            [&](NoInstAttrib &noInstAttrib)
            {
                if (atLeastOne)
                {
                    builder << ", ";
                }
                atLeastOne = true;
                builder << noInstAttrib;
            });
        builder << ']';
    }

    builder << ", ";
    {
        bool atLeastOne = false;
        builder << R"("NoLotTypeRules": [)";
        writer.noLotTypeRules().forEach(
            [&](NoLotTypeRules &noLotTypeRules)
            {
                if (atLeastOne)
                {
                    builder << ", ";
                }
                atLeastOne = true;
                builder << noLotTypeRules;
            });
        builder << ']';
    }

    builder << '}';

    return builder;
}

void skip()
{
    auto &noEventsGroup { noEvents() };
    while (noEventsGroup.hasNext())
    {
        noEventsGroup.next().skip();
    }
    auto &noMDFeedTypesGroup { noMDFeedTypes() };
    while (noMDFeedTypesGroup.hasNext())
    {
        noMDFeedTypesGroup.next().skip();
    }
    auto &noInstAttribGroup { noInstAttrib() };
    while (noInstAttribGroup.hasNext())
    {
        noInstAttribGroup.next().skip();
    }
    auto &noLotTypeRulesGroup { noLotTypeRules() };
    while (noLotTypeRulesGroup.hasNext())
    {
        noLotTypeRulesGroup.next().skip();
    }
}

SBE_NODISCARD static SBE_CONSTEXPR bool isConstLength() SBE_NOEXCEPT
{
    return false;
}

SBE_NODISCARD static std::size_t computeLength(
    std::size_t noEventsLength = 0,
    std::size_t noMDFeedTypesLength = 0,
    std::size_t noInstAttribLength = 0,
    std::size_t noLotTypeRulesLength = 0)
{
#if defined(__GNUG__) && !defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wtype-limits"
#endif
    std::size_t length = sbeBlockLength();

    length += NoEvents::sbeHeaderSize();
    if (noEventsLength > 254LL)
    {
        throw std::runtime_error("noEventsLength outside of allowed range [E110]");
    }
    length += noEventsLength *NoEvents::sbeBlockLength();

    length += NoMDFeedTypes::sbeHeaderSize();
    if (noMDFeedTypesLength > 254LL)
    {
        throw std::runtime_error("noMDFeedTypesLength outside of allowed range [E110]");
    }
    length += noMDFeedTypesLength *NoMDFeedTypes::sbeBlockLength();

    length += NoInstAttrib::sbeHeaderSize();
    if (noInstAttribLength > 254LL)
    {
        throw std::runtime_error("noInstAttribLength outside of allowed range [E110]");
    }
    length += noInstAttribLength *NoInstAttrib::sbeBlockLength();

    length += NoLotTypeRules::sbeHeaderSize();
    if (noLotTypeRulesLength > 254LL)
    {
        throw std::runtime_error("noLotTypeRulesLength outside of allowed range [E110]");
    }
    length += noLotTypeRulesLength *NoLotTypeRules::sbeBlockLength();

    return length;
#if defined(__GNUG__) && !defined(__clang__)
#pragma GCC diagnostic pop
#endif
}
};
}
#endif
