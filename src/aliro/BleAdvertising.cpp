#include "ddk/aliro/BleAdvertising.h"
#include "DDKLogging.h"
#include <mbedtls/aes.h>

namespace ddk::aliro {

namespace {
constexpr const char* TAG = "BleAdvertising";
}  // namespace

std::array<uint8_t, 7> compute_dynamic_tag(const std::array<uint8_t, 16>& grk,
                                           const std::array<uint8_t, 6>& adv_a,
                                           uint32_t expiry_unix) {
    // plaintext = Pad_Bytes(0x000000000000, 6) || AdvA || expiry, all MSB first
    uint8_t plaintext[16] = {0};
    for (size_t i = 0; i < adv_a.size(); ++i) plaintext[6 + i] = adv_a[i];
    plaintext[12] = static_cast<uint8_t>((expiry_unix >> 24) & 0xFF);
    plaintext[13] = static_cast<uint8_t>((expiry_unix >> 16) & 0xFF);
    plaintext[14] = static_cast<uint8_t>((expiry_unix >> 8) & 0xFF);
    plaintext[15] = static_cast<uint8_t>(expiry_unix & 0xFF);

    uint8_t ciphertext[16] = {0};
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    std::array<uint8_t, 7> tag{};
    if (mbedtls_aes_setkey_enc(&aes, grk.data(), 128) != 0) {
        LOG(E, "dynamic tag: AES-128 key schedule failed");
    } else if (mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_ENCRYPT, plaintext,
                                     ciphertext) != 0) {
        LOG(E, "dynamic tag: AES-128 encryption failed");
    } else {
        for (size_t i = 0; i < tag.size(); ++i) tag[i] = ciphertext[i];
    }
    mbedtls_aes_free(&aes);
    return tag;
}

std::vector<uint8_t> build_adv_payload(const BleAdvertisementData& data) {
    std::vector<uint8_t> out;
    out.reserve(31);

    // Flags AD: LE General Discoverable + BR/EDR not supported.
    out.push_back(0x02);
    out.push_back(0x01);
    out.push_back(0x06);

    // Service Data AD header: len (27 = 3-byte header + 24-byte Aliro
    // block), type 0x16, UUID 0xFFF2 (little-endian).
    out.push_back(27);
    out.push_back(0x16);
    out.push_back(0xF2);
    out.push_back(0xFF);

    uint8_t flags = 0;
    if (data.ble_uwb_flow_supported) flags |= 0x80;
    if (data.ble_only_flow_supported) flags |= 0x40;
    flags |= static_cast<uint8_t>((data.notification_state & 0x03) << 3);
    flags |= static_cast<uint8_t>(data.ble_advertisement_version & 0x07);
    out.push_back(flags);

    out.push_back(static_cast<uint8_t>(data.tx_power_dbm));

    for (uint8_t b : data.group_prefix) out.push_back(b);
    for (uint8_t b : data.group_sub_prefix) out.push_back(b);
    out.push_back(static_cast<uint8_t>((data.dynamic_tag_expiry >> 24) & 0xFF));
    out.push_back(static_cast<uint8_t>((data.dynamic_tag_expiry >> 16) & 0xFF));
    out.push_back(static_cast<uint8_t>((data.dynamic_tag_expiry >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>(data.dynamic_tag_expiry & 0xFF));
    out.push_back(0x00);
    for (uint8_t b : data.dynamic_tag) out.push_back(b);
    return out;
}

std::vector<uint8_t> build_reader_gatt_value(uint16_t spsm,
                                             const std::vector<uint8_t>& supported_versions,
                                             uint8_t features) {
    std::vector<uint8_t> out;
    out.push_back(static_cast<uint8_t>((spsm >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>(spsm & 0xFF));
    out.push_back(static_cast<uint8_t>(supported_versions.size()));
    out.insert(out.end(), supported_versions.begin(), supported_versions.end());
    out.push_back(1);   // features length (1-octet bitmap)
    out.push_back(features);
    return out;
}

std::optional<DeviceGattSelection> parse_device_gatt_value(
    ddk::span<const uint8_t> value) {
    if (value.size() < 4) return std::nullopt;
    DeviceGattSelection sel;
    sel.selected_version = {value[0], value[1]};
    if (value[2] < 1 || value.size() < 3u + value[2]) return std::nullopt;
    sel.features = value[3];
    return sel;
}

std::array<uint8_t, 8> truncate_group_identifier(ddk::span<const uint8_t> gid) {
    std::array<uint8_t, 8> out{};
    for (size_t i = 0; i < out.size() && i < gid.size(); ++i) out[i] = gid[i];
    return out;
}

std::array<uint8_t, 2> truncate_group_sub_identifier(ddk::span<const uint8_t> gid) {
    std::array<uint8_t, 2> out{};
    for (size_t i = 0; i < out.size() && i < gid.size(); ++i) out[i] = gid[i];
    return out;
}

}  // namespace ddk::aliro
