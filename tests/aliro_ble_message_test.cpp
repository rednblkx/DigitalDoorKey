// Byte-level checks for the Aliro BLE message framing:
// header codec, zero-length-payload rejection, attribute TLVs, and
// multi-message SDU pack/parse.
#include <catch2/catch_test_macros.hpp>
#include "BleMessages.h"

using namespace ddk::ble;

TEST_CASE("Message header encoding", "[ble][messages]") {
    Message m;
    m.type = ProtocolType::Notification;
    m.message_id = notification_id::kInitiateAccessProtocol;
    m.payload = {0x01, 0x02, 0x03};

    auto bytes = m.encode();
    REQUIRE(bytes.size() == 7);
    CHECK(bytes[0] == 0x02);   // Notification
    CHECK(bytes[1] == 0x05);   // Initiate Access Protocol
    CHECK(bytes[2] == 0x00);   // length MSB
    CHECK(bytes[3] == 0x03);   // length LSB
    CHECK(bytes[4] == 0x01);
    CHECK(bytes[5] == 0x02);
    CHECK(bytes[6] == 0x03);
}

TEST_CASE("Message round-trips through decode", "[ble][messages]") {
    Message m;
    m.type = ProtocolType::UwbRanging;
    m.message_id = 2;   // RSS M3
    m.payload = std::vector<uint8_t>(200, 0xAA);
    auto bytes = m.encode();

    const uint8_t* cursor = bytes.data();
    auto decoded = Message::decode(cursor, bytes.data() + bytes.size());
    REQUIRE(decoded.has_value());
    CHECK(decoded->type == ProtocolType::UwbRanging);
    CHECK(decoded->message_id == 2);
    CHECK(decoded->payload.size() == 200);
    CHECK(cursor == bytes.data() + bytes.size());   // fully consumed
}

TEST_CASE("Zero-length payload is malformed", "[ble][messages]") {
    const uint8_t frame[] = {0x02, 0x00, 0x00, 0x00};   // length 0
    const uint8_t* cursor = frame;
    auto decoded = Message::decode(cursor, frame + sizeof(frame));
    CHECK_FALSE(decoded.has_value());
}

TEST_CASE("Truncated frames are rejected", "[ble][messages]") {
    SECTION("header cut short") {
        const uint8_t frame[] = {0x02, 0x00, 0x00};
        const uint8_t* cursor = frame;
        CHECK_FALSE(Message::decode(cursor, frame + sizeof(frame)).has_value());
    }
    SECTION("payload cut short") {
        const uint8_t frame[] = {0x02, 0x00, 0x00, 0x05, 0x01};
        const uint8_t* cursor = frame;
        CHECK_FALSE(Message::decode(cursor, frame + sizeof(frame)).has_value());
    }
}

TEST_CASE("Attribute codec matches", "[ble][messages]") {
    auto bytes = encode_attributes({
        {0, {0xA5, 0x04, 0x5C, 0x02, 0x01, 0x00}},   // proprietary info
        {0, {0x04, 0x81}},                            // user device descriptor
    });
    // One attribute whose length byte 0x06 must not be confused with the
    // 0x81 long form; raw layout: id len v...
    REQUIRE(bytes.size() == 2 + 6 + 2 + 2);
    CHECK(bytes[0] == 0x00);
    CHECK(bytes[1] == 0x06);
    CHECK(bytes[2] == 0xA5);
    CHECK(bytes[8] == 0x00);
    CHECK(bytes[9] == 0x02);

    auto parsed = parse_attributes(bytes);
    REQUIRE(parsed.has_value());
    REQUIRE(parsed->size() == 2);
    CHECK((*parsed)[0].id == 0);
    CHECK((*parsed)[0].value.size() == 6);
    CHECK((*parsed)[1].value == std::vector<uint8_t>{0x04, 0x81});
}

TEST_CASE("Truncated attribute list is rejected", "[ble][messages]") {
    SECTION("length byte missing") {
        const uint8_t payload[] = {0x00};
        CHECK_FALSE(parse_attributes(payload).has_value());
    }
    SECTION("value shorter than declared") {
        const uint8_t payload[] = {0x00, 0x05, 0x01, 0x02};
        CHECK_FALSE(parse_attributes(payload).has_value());
    }
}

TEST_CASE("Event payloads encode Busy and General Error", "[ble][messages]") {
    auto busy = event_busy();
    CHECK(busy == std::vector<uint8_t>{0x00, 0x00});   // attr 0, len 0

    auto err = event_general_error(GeneralError::UrskUnavailable);
    CHECK(err == std::vector<uint8_t>{0x01, 0x01, 0x03});
}

TEST_CASE("Reader status payloads pack source and status bytes", "[ble][messages]") {
    // State: source 4 (BLE+UWB) << 8 | unsecure (0x01).
    auto state = reader_status_changed(0x01, OperationSource::ThisDeviceBleUwb);
    CHECK(state == std::vector<uint8_t>{0x00, 0x02, 0x04, 0x01});

    // Reader Information: mode 1 << 13 | 0x81.
    auto completed = reader_status_ap_completed(0x81, 1);
    CHECK(completed == std::vector<uint8_t>{0x00, 0x02, 0x20, 0x81});
}

TEST_CASE("RKE request encodes the action byte", "[ble][messages]") {
    CHECK(rke_request(true) == std::vector<uint8_t>{0x00, 0x01, 0x00});
    CHECK(rke_request(false) == std::vector<uint8_t>{0x00, 0x01, 0x01});
}

TEST_CASE("SDU packs several messages", "[ble][messages]") {
    Message a;
    a.type = ProtocolType::Ap;
    a.message_id = ap_id::kApRq;
    a.payload = {0x80, 0x80, 0x00, 0x00, 0x00};
    Message b;
    b.type = ProtocolType::Notification;
    b.message_id = notification_id::kEvent;
    b.payload = event_busy();

    auto sdu = pack_sdu({a, b});
    REQUIRE(sdu.size() == 9 + 6);

    auto parsed = unpack_sdu(sdu);
    REQUIRE(parsed.size() == 2);
    CHECK(parsed[0].type == ProtocolType::Ap);
    CHECK(parsed[0].message_id == ap_id::kApRq);
    CHECK(parsed[1].type == ProtocolType::Notification);
    CHECK(parsed[1].payload == b.payload);
}

TEST_CASE("SDU parse fails closed on a malformed tail", "[ble][messages]") {
    Message a;
    a.type = ProtocolType::Ap;
    a.message_id = ap_id::kApRq;
    a.payload = {0x80, 0x80, 0x00, 0x00, 0x00};

    auto sdu = pack_sdu({a});
    sdu.push_back(0x02);   // orphan header fragment
    CHECK(unpack_sdu(sdu).empty());
}

TEST_CASE("AAD carries the plain length in the header layout", "[ble][messages]") {
    auto aad = message_aad(ProtocolType::Supplementary, 0x00, 0x0123);
    CHECK(aad[0] == 0x03);
    CHECK(aad[1] == 0x00);
    CHECK(aad[2] == 0x01);
    CHECK(aad[3] == 0x23);
}
