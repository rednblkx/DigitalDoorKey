#include <catch2/catch_test_macros.hpp>
#include "ddk/aliro/BleAdvertising.h"

using namespace ddk::aliro;

TEST_CASE("Advertisement payload", "[ble][advertising]") {
    BleAdvertisementData data;
    data.ble_uwb_flow_supported = true;
    data.ble_only_flow_supported = false;
    data.notification_state = 2;              // low battery
    data.ble_advertisement_version = 0;
    data.tx_power_dbm = -12;
    data.group_prefix = {0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7};
    data.group_sub_prefix = {0xB0, 0xB1};
    data.dynamic_tag_expiry = 0x7a4b8500;
    data.dynamic_tag = {1, 2, 3, 4, 5, 6, 7};

    auto payload = build_adv_payload(data);
    REQUIRE(payload.size() == 31);

    // Flags AD
    CHECK(payload[0] == 0x02);
    CHECK(payload[1] == 0x01);
    CHECK(payload[2] == 0x06);
    // Service Data AD: len 27, type 0x16, UUID 0xFFF2 little-endian
    CHECK(payload[3] == 0x1B);
    CHECK(payload[4] == 0x16);
    CHECK(payload[5] == 0xF2);
    CHECK(payload[6] == 0xFF);
    // flags byte: bit7 BLE+UWB | bits[4:3] notification | bits[2:0] version
    constexpr uint8_t expected_flags = 0x80 | (2 << 3) | 0x00;
    CHECK(payload[7] == expected_flags);
    // tx power, MSB-first group prefixes
    CHECK(payload[8] == static_cast<uint8_t>(-12));
    CHECK(payload[9] == 0xA0);
    CHECK(payload[16] == 0xA7);
    CHECK(payload[17] == 0xB0);
    CHECK(payload[18] == 0xB1);
    // expiry MSB first + RFU + dynamic tag
    CHECK(payload[19] == 0x7a);
    CHECK(payload[20] == 0x4b);
    CHECK(payload[21] == 0x85);
    CHECK(payload[22] == 0x00);
    CHECK(payload[23] == 0x00);   // RFU byte
    for (size_t i = 0; i < 7; ++i) CHECK(payload[24 + i] == i + 1);
}

TEST_CASE("Reader GATT value: SPSM, versions, features", "[ble][advertising]") {
    auto value = build_reader_gatt_value(0x00FD, {0x01, 0x00}, 0x03);
    REQUIRE(value.size() == 2 + 1 + 2 + 1 + 1);
    CHECK(value[0] == 0x00);   // SPSM MSB
    CHECK(value[1] == 0xFD);
    CHECK(value[2] == 0x02);   // version-list length
    CHECK(value[3] == 0x01);
    CHECK(value[4] == 0x00);
    CHECK(value[5] == 0x01);   // features length
    CHECK(value[6] == 0x03);
}

TEST_CASE("Device GATT selection parses", "[ble][advertising]") {
    auto sel = parse_device_gatt_value({{0x01, 0x00, 0x01, 0x02}});
    REQUIRE(sel.has_value());
    CHECK(sel->selected_version[0] == 0x01);
    CHECK(sel->selected_version[1] == 0x00);
    CHECK(sel->features == 0x02);

    SECTION("too short") {
        CHECK_FALSE(parse_device_gatt_value({{0x01, 0x00}}).has_value());
    }
    SECTION("features length overruns") {
        CHECK_FALSE(parse_device_gatt_value({{0x01, 0x00, 0x05, 0x02}}).has_value());
    }
}

TEST_CASE("Truncated identity prefixes take leading octets", "[ble][advertising]") {
    std::vector<uint8_t> gid(16);
    for (size_t i = 0; i < gid.size(); ++i) gid[i] = static_cast<uint8_t>(i);
    auto prefix = truncate_group_identifier(gid);
    CHECK(prefix == std::array<uint8_t, 8>{0, 1, 2, 3, 4, 5, 6, 7});
    auto sub = truncate_group_sub_identifier(gid);
    CHECK(sub == std::array<uint8_t, 2>{0, 1});
}
