#include "BleMessages.h"
#include "DDKLogging.h"

namespace ddk::ble {

constexpr const char* TAG = "BleMessages";

namespace {
constexpr size_t kHeaderSize = 4;   // type | id | len MSB | len LSB
constexpr size_t kGcmTagSize = 16;
}  // namespace

std::vector<uint8_t> Message::encode() const {
    std::vector<uint8_t> out;
    out.reserve(kHeaderSize + payload.size());
    out.push_back(static_cast<uint8_t>(type));
    out.push_back(message_id);
    out.push_back(static_cast<uint8_t>((payload.size() >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>(payload.size() & 0xFF));
    out.insert(out.end(), payload.begin(), payload.end());
    return out;
}

std::optional<Message> Message::decode(const uint8_t*& cursor, const uint8_t* end) {
    if (end - cursor < kHeaderSize) return std::nullopt;
    Message msg;
    msg.type = static_cast<ProtocolType>((*cursor++) & 0x3F);  // B5:B0; B7:B6 RFU
    msg.message_id = *cursor++;
    size_t length = static_cast<size_t>(*cursor++) << 8;
    length |= *cursor++;
    if (length == 0) return std::nullopt;
    if (static_cast<size_t>(end - cursor) < length) return std::nullopt;
    msg.payload.assign(cursor, cursor + length);
    cursor += length;
    return msg;
}

std::array<uint8_t,4> message_aad(ProtocolType type, uint8_t message_id,
                                  size_t plain_length) {
    return {static_cast<uint8_t>(type), message_id,
            static_cast<uint8_t>((plain_length >> 8) & 0xFF),
            static_cast<uint8_t>(plain_length & 0xFF)};
}

std::vector<uint8_t> encode_attributes(const std::vector<Attribute>& attrs) {
    std::vector<uint8_t> out;
    for (const auto& a : attrs) {
        out.push_back(a.id);
        out.push_back(static_cast<uint8_t>(a.value.size()));
        out.insert(out.end(), a.value.begin(), a.value.end());
    }
    return out;
}

std::optional<std::vector<Attribute>> parse_attributes(ddk::span<const uint8_t> payload) {
    std::vector<Attribute> attrs;
    size_t i = 0;
    while (i < payload.size()) {
        Attribute a;
        a.id = payload[i];
        if (++i >= payload.size()) return std::nullopt;
        size_t len = payload[i++];
        if (payload.size() - i < len) return std::nullopt;
        a.value.assign(payload.begin() + i, payload.begin() + i + len);
        i += len;
        attrs.push_back(std::move(a));
    }
    return attrs;
}

const Attribute* find_attribute(const std::vector<Attribute>& attrs, uint8_t id) {
    for (const auto& a : attrs)
        if (a.id == id) return &a;
    return nullptr;
}

std::vector<uint8_t> event_busy() {
    return encode_attributes({{event_attr::kBusy, {}}});
}

std::vector<uint8_t> event_general_error(GeneralError reason) {
    return encode_attributes({{event_attr::kGeneralError,
                               {static_cast<uint8_t>(reason)}}});
}

std::vector<uint8_t> reader_status_ap_completed(uint8_t status_byte,
                                                uint8_t unsolicited_mode) {
    uint16_t v = static_cast<uint16_t>((unsolicited_mode & 0x07) << 13) | status_byte;
    return encode_attributes({{0, {static_cast<uint8_t>(v >> 8),
                                   static_cast<uint8_t>(v & 0xFF)}}});
}

std::vector<uint8_t> reader_status_changed(uint8_t status_byte, OperationSource source) {
    uint16_t v = static_cast<uint16_t>(static_cast<uint8_t>(source) << 8) | status_byte;
    return encode_attributes({{0, {static_cast<uint8_t>(v >> 8),
                                   static_cast<uint8_t>(v & 0xFF)}}});
}

std::vector<uint8_t> rke_request(bool secure) {
    return encode_attributes({{0, {static_cast<uint8_t>(
        secure ? rke_action::kSecure : rke_action::kUnsecure)}}});
}

std::vector<uint8_t> ranging_attribute(uint8_t id) {
    return encode_attributes({{id, {}}});
}

std::vector<uint8_t> pack_sdu(const std::vector<Message>& messages) {
    std::vector<uint8_t> sdu;
    for (const auto& m : messages) {
        auto bytes = m.encode();
        sdu.insert(sdu.end(), bytes.begin(), bytes.end());
    }
    return sdu;
}

std::vector<Message> unpack_sdu(ddk::span<const uint8_t> sdu) {
    std::vector<Message> out;
    const uint8_t* cursor = sdu.data();
    const uint8_t* end = sdu.data() + sdu.size();
    while (cursor < end) {
        auto msg = Message::decode(cursor, end);
        if (!msg) {
            LOG(W, "malformed Aliro message in SDU (offset %zu)",
                static_cast<size_t>(cursor - sdu.data()));
            return {};
        }
        out.push_back(std::move(*msg));
    }
    return out;
}

}  // namespace ddk::ble
