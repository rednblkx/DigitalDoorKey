#include "aliro/AliroSecureContext.h"
#include "BerTlv.h"
#include "DDKLogging.h"
#include <array>
#include "cbor.h"
#include "ddk/session/Session.h"

constexpr const char* TAG = "AliroSecureContext";

AliroSecureContext::AliroSecureContext(std::array<uint8_t, 32> sk_reader, std::array<uint8_t, 32> sk_device,
                                       std::optional<std::array<uint8_t,32>> ursk,
                                       std::optional<std::array<uint8_t,32>> ble_sk)
  : exchange_channel_(std::make_unique<GcmSecureChannel>(sk_reader, sk_device)),
    ursk_(std::move(ursk)), ble_sk_(std::move(ble_sk)) {};

AliroSecureContext::AliroSecureContext(
    std::unique_ptr<GcmSecureChannel> exchange,
    std::array<uint8_t,32> step_up_sk_reader,
    std::array<uint8_t,32> step_up_sk_device,
    std::optional<std::array<uint8_t,32>> ursk,
    std::optional<std::array<uint8_t,32>> ble_sk)
  : exchange_channel_(std::move(exchange)),
    step_up_(std::in_place, step_up_sk_reader, step_up_sk_device),
    ursk_(std::move(ursk)), ble_sk_(std::move(ble_sk)) {}

ddk::ApduResponse AliroSecureContext::exchange(
    ddk::Session& session, ddk::span<const uint8_t> tlvs, bool skip_chaining)
{
    if (!active_channel_) {
        LOG(E, "exchange: no active secure channel");
        return {};
    }
    auto& ch = *active_channel_;
    auto encrypted = ch.encrypt_reader_data(
        std::vector<uint8_t>(tlvs.begin(), tlvs.end()));
    if (encrypted.empty() && !tlvs.empty()) {
        LOG(E, "GCM encrypt failed");
        return {};
    }

    // ne=256 -> case-4 short form (Le=0x00): the BLE AP parser rejects
    // Le-less commands with General Error.
    ddk::ApduCommand cmd{0x80, 0xC9, 0x00, 0x00,
                         std::vector<uint8_t>(encrypted.begin(), encrypted.end()), 256};
    auto resp = session.apdu().transceive_full(cmd, skip_chaining);
    if (!resp.ok() || resp.data.empty()) {
        return resp;
    }

    auto plaintext = ch.decrypt_endpoint_data(resp.data);
    return {std::move(plaintext), resp.sw1, resp.sw2};
}

std::optional<std::vector<uint8_t>> AliroSecureContext::envelope(
    ddk::Session& session, ddk::span<const uint8_t> message,
    size_t max_command_chunk)
{
    if (!step_up_) {
        LOG(E, "envelope: no step-up channel (expedited-fast only?)");
        return std::nullopt;
    }
    active_channel_ = &*step_up_;

    auto encrypted = step_up_->encrypt_reader_data(
        std::vector<uint8_t>(message.begin(), message.end()));
    if (encrypted.empty() && !message.empty()) return std::nullopt;

    // SessionData = {"data": bstr(encrypted)} — single-pair CBOR map
    uint8_t sd[2048];
    CborEncoder enc, map;
    cbor_encoder_init(&enc, sd, sizeof(sd), 0);
    cbor_encoder_create_map(&enc, &map, 1);
    cbor_encode_text_stringz(&map, "data");
    cbor_encode_byte_string(&map, encrypted.data(), encrypted.size());
    cbor_encoder_close_container(&enc, &map);
    size_t sd_len = cbor_encoder_get_buffer_size(&enc, sd);

    // BerTLV(0x53, session_data) — DER length encoding
    std::vector<uint8_t> tlv{0x53};
    if (sd_len < 0x80) tlv.push_back(sd_len);
    else if (sd_len <= 0xFF) { tlv.push_back(0x81); tlv.push_back(sd_len); }
    else { tlv.push_back(0x82);
           tlv.push_back(sd_len >> 8); tlv.push_back(sd_len & 0xFF); }
    tlv.insert(tlv.end(), sd, sd + sd_len);

    // ENVELOPE: CLA=0x00, INS=0xC3, P1=0x00, P2=0x00 — response chaining ON
    ddk::ApduCommand cmd{0x00, 0xC3, 0x00, 0x00, std::move(tlv), 0};
    auto resp = session.apdu().transceive_full(cmd, /*skip_response_chaining=*/false,
                                               max_command_chunk);
    if (resp.sw1 != 0x90) {
        LOG(E, "ENVELOPE failed: SW=%02X%02X", resp.sw1, resp.sw2);
        return std::nullopt;
    }

    // Response: 0x53 TLV → SessionData {"data": bstr} or raw ciphertext.
    auto msg = BerTlvMessage::from_bytes(resp.data);
    const BerTlv* outer = msg.find(0x53);
    if (!outer && !msg.empty()) outer = &msg.tags.front();
    if (!outer) { LOG(E, "ENVELOPE response missing 0x53"); return std::nullopt; }

    const auto& v = outer->value;
    std::vector<uint8_t> ciphertext;

    // Try SessionData: CBOR map with text key "data"
    CborParser parser; CborValue it, val;
    if (cbor_parser_init(v.data(), v.size(), 0, &parser, &it) == CborNoError &&
        cbor_value_is_map(&it) &&
        cbor_value_map_find_value(&it, "data", &val) == CborNoError &&
        cbor_value_is_byte_string(&val))
    {
        size_t len = 0;
        cbor_value_get_string_length(&val, &len);
        ciphertext.resize(len);
        cbor_value_copy_byte_string(&val, ciphertext.data(), &len, nullptr);
    } else {
        ciphertext = v;   // raw ciphertext — device variance
    }

    return step_up_->decrypt_endpoint_data(ciphertext);
}
