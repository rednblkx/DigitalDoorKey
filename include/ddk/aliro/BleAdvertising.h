#pragma once
#include "ddk/Span.h"
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

namespace ddk::aliro {

// Reader advertising + GATT material for Aliro over BLE.
// Pure byte builders — the app feeds the results into its BLE stack.

// ADV_IND service-data content. The reader advertises on LE
// 1M PHY (ADV_IND, connectable + scannable undirected) with a static
// address; the 0xFFF2 service UUID and AdvA are little-endian on air,
// every other multi-octet field is MSB first.
struct BleAdvertisementData {
    bool ble_uwb_flow_supported = false;   // byte 7, bit 7
    bool ble_only_flow_supported = false;  // byte 7, bit 6
    // bits[4:3]: 0 no error, 1 unknown error, 2 low battery, 3 sensor
    // triggered (sensor-triggered must persist for ≥10 advertisements).
    uint8_t notification_state = 0;
    uint8_t ble_advertisement_version = 0; // bits[2:0]
    int8_t tx_power_dbm = 0;               // byte 8, range [-100, 20]
    // truncated_reader_group_identifier / _sub_identifier: leading octets
    // of the provisioned identity (see truncate_* helpers).
    std::array<uint8_t, 8> group_prefix{};
    std::array<uint8_t, 2> group_sub_prefix{};
    // Unix seconds, MSB first; 0xFFFFFFFF when no clock is available. The
    // tag is regenerated whenever the expiry changes.
    uint32_t dynamic_tag_expiry = 0xFFFFFFFF;
    std::array<uint8_t, 7> dynamic_tag{};
};

// Dynamic Tag: the 7 most significant octets of
// AES-128-Enc(GRK, 6B zero pad || AdvA || expiry). AdvA is the reader's
// static address in the conventional written order (e.g. c4:bb:86:...).
std::array<uint8_t, 7> compute_dynamic_tag(const std::array<uint8_t, 16>& grk,
                                           const std::array<uint8_t, 6>& adv_a,
                                           uint32_t expiry_unix);

// Full advertisement payload: Flags AD (02 01 06) || Service Data AD
// (1B 16 F2 FF || 24-byte Aliro block). 31 bytes total.
std::vector<uint8_t> build_adv_payload(const BleAdvertisementData& data);

// Reader GATT characteristic value
// SPSM (2B, MSB first) || version-list length || versions (2B each) || features length || features bitmap.
std::vector<uint8_t> build_reader_gatt_value(uint16_t spsm,
                                             const std::vector<uint8_t>& supported_versions,
                                             uint8_t features);

struct DeviceGattSelection {
    std::array<uint8_t, 2> selected_version{};
    uint8_t features = 0;
};

// User-Device characteristic write
// selected version (2B) || features length || features bitmap.
std::optional<DeviceGattSelection> parse_device_gatt_value(
    ddk::span<const uint8_t> value);

// Leading octets of the provisioned reader identity for the
// advertisement (first 8 / first 2 bytes).
std::array<uint8_t, 8> truncate_group_identifier(ddk::span<const uint8_t> gid);
std::array<uint8_t, 2> truncate_group_sub_identifier(ddk::span<const uint8_t> gid);

}  // namespace ddk::aliro
