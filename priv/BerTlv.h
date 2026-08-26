#pragma once
#include "ddk/Span.h"
#include <cstdint>
#include <vector>

struct BerTlv {
    std::vector<uint8_t> tag;    // 1+ bytes
    std::vector<uint8_t> value;

    bool is_constructed() const {
        return !tag.empty() && (tag[0] & 0x20);
    }

    bool tag_equals(ddk::span<const uint8_t> t) const {
        return tag.size() == t.size() &&
               std::equal(tag.begin(), tag.end(), t.begin());
    }

    bool tag_equals(uint8_t t) const {
        return tag.size() == 1 && tag[0] == t;
    }

    // Parse this tag's value as a nested BerTlvMessage.
    class BerTlvMessage parse_inner() const;
};

class BerTlvMessage {
public:
    std::vector<BerTlv> tags;

    static BerTlvMessage from_bytes(const uint8_t* data, size_t len);
    static BerTlvMessage from_bytes(ddk::span<const uint8_t> data) {
        return from_bytes(data.data(), data.size());
    }

    const BerTlv* find(ddk::span<const uint8_t> tag) const;
    const BerTlv* find(uint8_t tag) const;

    BerTlvMessage find_inner(uint8_t tag) const;

    std::vector<uint8_t> to_bytes() const;

    bool empty() const { return tags.empty(); }
    size_t size() const { return tags.size(); }
};

inline BerTlvMessage BerTlv::parse_inner() const {
    return BerTlvMessage::from_bytes(value.data(), value.size());
}
