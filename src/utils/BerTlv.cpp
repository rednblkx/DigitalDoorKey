#include "BerTlv.h"
#include "DDKLogging.h"
#include <cstring>

constexpr const char* TAG = "BerTlv";

namespace {

// Read a BER-TLV tag (1 or more bytes).
// Tag encoding:
//   bits 8-7 of first byte: class (00=universal, 01=application,
//                                10=context, 11=private)
//   bit 6: primitive (0) or constructed (1)
//   bits 5-1: tag number, or 0x1F = multi-byte follows
// Multi-byte: subsequent bytes, bit 8 = continuation (1=more, 0=last)
size_t read_tag(const uint8_t* data, size_t len, std::vector<uint8_t>& tag) {
    if (len == 0) return 0;
    size_t pos = 0;
    tag.push_back(data[pos++]);

    if ((tag[0] & 0x1F) == 0x1F) {
        while (pos < len) {
            uint8_t b = data[pos++];
            tag.push_back(b);
            if (!(b & 0x80)) break;
        }
        if (tag.size() < 2 || (tag.back() & 0x80)) {
            return 0;  // unterminated multi-byte tag
        }
    }
    return pos;
}

// Read a BER-TLV length.
// Short form: byte < 0x80, length = byte value
// Long form: byte > 0x80, lower 7 bits = count of subsequent length bytes
// Indefinite (0x80): not supported
size_t read_length(const uint8_t* data, size_t len, size_t& out) {
    if (len == 0) return 0;
    uint8_t first = data[0];

    if (first < 0x80) {
        out = first;
        return 1;
    }
    if (first == 0x80) return 0;  // indefinite — unsupported

    size_t num_bytes = first & 0x7F;
    if (num_bytes == 0 || num_bytes > sizeof(size_t) || len < 1 + num_bytes)
        return 0;

    size_t value = 0;
    for (size_t i = 0; i < num_bytes; ++i)
        value = (value << 8) | data[1 + i];

    out = value;
    return 1 + num_bytes;
}

void write_tag(std::vector<uint8_t>& out, ddk::span<const uint8_t> tag) {
    out.insert(out.end(), tag.begin(), tag.end());
}

void write_length(std::vector<uint8_t>& out, size_t len) {
    if (len < 0x80) {
        out.push_back(static_cast<uint8_t>(len));
    } else {
        size_t n = 0, tmp = len;
        while (tmp > 0) { n++; tmp >>= 8; }
        out.push_back(static_cast<uint8_t>(0x80 | n));
        for (size_t i = 0; i < n; ++i)
            out.push_back(static_cast<uint8_t>(len >> (8 * (n - 1 - i))));
    }
}

} // namespace

BerTlvMessage BerTlvMessage::from_bytes(const uint8_t* data, size_t len) {
    BerTlvMessage msg;
    const uint8_t* pos = data;
    const uint8_t* end = data + len;

    while (pos < end) {
        std::vector<uint8_t> tag;
        size_t tag_consumed = read_tag(pos, end - pos, tag);
        if (tag_consumed == 0) {
            LOG(E, "BerTlv: bad tag at offset %zu", (size_t)(pos - data));
            break;
        }
        pos += tag_consumed;

        size_t value_len = 0;
        size_t len_consumed = read_length(pos, end - pos, value_len);
        if (len_consumed == 0) {
            LOG(E, "BerTlv: bad length at offset %zu", (size_t)(pos - data));
            break;
        }
        pos += len_consumed;

        if (pos + value_len > end) {
            LOG(E, "BerTlv: value overflow (tag %zu bytes, value_len %zu, remaining %zu)",
                tag.size(), value_len, (size_t)(end - pos));
            break;
        }

        BerTlv tlv;
        tlv.tag = std::move(tag);
        tlv.value.assign(pos, pos + value_len);
        pos += value_len;
        msg.tags.push_back(std::move(tlv));
    }
    return msg;
}

const BerTlv* BerTlvMessage::find(ddk::span<const uint8_t> tag) const {
    for (const auto& tlv : tags)
        if (tlv.tag_equals(tag)) return &tlv;
    return nullptr;
}

const BerTlv* BerTlvMessage::find(uint8_t tag) const {
    for (const auto& tlv : tags)
        if (tlv.tag_equals(tag)) return &tlv;
    return nullptr;
}

BerTlvMessage BerTlvMessage::find_inner(uint8_t tag) const {
    const BerTlv* tlv = find(tag);
    if (!tlv) return {};
    return tlv->parse_inner();
}

std::vector<uint8_t> BerTlvMessage::to_bytes() const {
    std::vector<uint8_t> out;
    for (const auto& tlv : tags) {
        write_tag(out, tlv.tag);
        write_length(out, tlv.value.size());
        out.insert(out.end(), tlv.value.begin(), tlv.value.end());
    }
    return out;
}
