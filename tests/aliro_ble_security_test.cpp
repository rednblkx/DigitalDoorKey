#include <catch2/catch_test_macros.hpp>
#include "aliro/AliroKeySchedule.h"
#include "BleMessageSecurity.h"
#include "BleMessages.h"
#include "CommonCryptoUtils.h"

using namespace ddk::ble;
using ddk::ble::GeneralError;
using ddk::ble::Message;
using ddk::ble::ProtocolType;

namespace {

std::array<uint8_t, 32> some_ble_sk(uint8_t seed) {
    std::array<uint8_t, 32> sk{};
    for (size_t i = 0; i < sk.size(); ++i) sk[i] = static_cast<uint8_t>(seed + i);
    return sk;
}

}  // namespace

TEST_CASE("BleSK KDF is deterministic and direction-separated", "[ble][security]") {
    auto ble_sk = some_ble_sk(1);
    const std::vector<uint8_t> reader_versions{0x01, 0x00};
    const std::array<uint8_t, 2> selected{0x01, 0x00};

    auto a = AliroKeySchedule::derive_ble_session_keys(
        ble_sk, reader_versions, ddk::span<const uint8_t>(selected.data(), 2));
    auto b = AliroKeySchedule::derive_ble_session_keys(
        ble_sk, reader_versions, ddk::span<const uint8_t>(selected.data(), 2));

    CHECK(a.sk_reader == b.sk_reader);
    CHECK(a.sk_device == b.sk_device);
    CHECK(a.sk_reader != a.sk_device);
}

TEST_CASE("BleSK KDF binds the version lists (anti-downgrade salt)", "[ble][security]") {
    auto ble_sk = some_ble_sk(2);
    const std::array<uint8_t, 2> selected{0x01, 0x00};

    auto v10 = AliroKeySchedule::derive_ble_session_keys(
        ble_sk, {0x01, 0x00}, ddk::span<const uint8_t>(selected.data(), 2));
    auto v11 = AliroKeySchedule::derive_ble_session_keys(
        ble_sk, {0x01, 0x01}, ddk::span<const uint8_t>(selected.data(), 2));

    // A different reader-supported list must yield different channels.
    CHECK(v10.sk_reader != v11.sk_reader);
    CHECK(v10.sk_device != v11.sk_device);
}

TEST_CASE("Message security passes through in the clear window", "[ble][security]") {
    auto sk = some_ble_sk(3);
    BleMessageSecurity sec(sk, some_ble_sk(4));
    CHECK_FALSE(sec.secured());

    Message m;
    m.type = ProtocolType::Notification;
    m.message_id = notification_id::kEvent;
    m.payload = ddk::ble::event_general_error(GeneralError::Unknown);

    auto sealed = sec.seal(m);
    REQUIRE(sealed.has_value());
    CHECK(*sealed == m.payload);   // clear until AP Completed

    auto opened = sec.unseal(m);
    REQUIRE(opened.has_value());
    CHECK(*opened == m.payload);
    CHECK_FALSE(sec.aborted());
}

TEST_CASE("Message security seals with AAD after AP Completed", "[ble][security]") {
    auto sk_reader = some_ble_sk(5);
    auto sk_device = some_ble_sk(6);
    BleMessageSecurity reader_side(sk_reader, sk_device);
    BleMessageSecurity device_side(sk_reader, sk_device, /*device_role=*/true);

    Message m;
    m.type = ProtocolType::Supplementary;   // Time Sync
    m.message_id = 0;
    m.payload = std::vector<uint8_t>(40, 0x5A);

    reader_side.set_secured(true);
    device_side.set_secured(true);

    auto sealed = reader_side.seal(m);
    REQUIRE(sealed.has_value());
    REQUIRE(sealed->size() == m.payload.size() + 16);   // ct || tag
    CHECK(*sealed != m.payload);

    Message wire;
    wire.type = m.type;
    wire.message_id = m.message_id;
    wire.payload = *sealed;
    auto opened = device_side.unseal(wire);
    REQUIRE(opened.has_value());
    CHECK(*opened == m.payload);
    CHECK_FALSE(reader_side.aborted());
    CHECK_FALSE(device_side.aborted());

    CHECK(reader_side.counter_reader() == 2);
    CHECK(device_side.counter_reader() == 2);
}

TEST_CASE("A tampered secured payload aborts the session", "[ble][security]") {
    auto sk_reader = some_ble_sk(7);
    auto sk_device = some_ble_sk(8);
    BleMessageSecurity reader_side(sk_reader, sk_device);
    BleMessageSecurity device_side(sk_reader, sk_device, /*device_role=*/true);
    reader_side.set_secured(true);
    device_side.set_secured(true);

    Message m;
    m.type = ProtocolType::Notification;
    m.message_id = notification_id::kRkeRequest;
    m.payload = ddk::ble::rke_request(false);
    auto sealed = *reader_side.seal(m);

    Message wire;
    wire.type = m.type;
    wire.message_id = m.message_id;
    wire.payload = sealed;
    wire.payload[0] ^= 0xFF;   // flip ciphertext

    auto opened = device_side.unseal(wire);
    CHECK_FALSE(opened.has_value());
    CHECK(device_side.aborted());   // invalid tag → abort + teardown
}

TEST_CASE("Counter exhaustion aborts", "[ble][security]") {
    auto sk_reader = some_ble_sk(9);
    auto sk_device = some_ble_sk(10);
    // Start one below the 0xFFFF limit — the next message must abort.
    BleMessageSecurity reader_side(sk_reader, sk_device, /*device_role=*/false,
                                   /*counter_reader=*/0xFFFF,
                                   /*counter_device=*/1);
    reader_side.set_secured(true);

    Message m;
    m.type = ProtocolType::Notification;
    m.message_id = notification_id::kEvent;
    m.payload = ddk::ble::event_busy();

    auto sealed = reader_side.seal(m);
    REQUIRE(sealed.has_value());   // message still goes out
    CHECK(reader_side.aborted());  // …and the session must be torn down
}

TEST_CASE("Device-role security mirrors the GCM directions", "[ble][security]") {
    auto sk_reader = some_ble_sk(20);
    auto sk_device = some_ble_sk(21);
    BleMessageSecurity reader_side(sk_reader, sk_device);
    BleMessageSecurity device_side(sk_reader, sk_device, /*device_role=*/true);
    reader_side.set_secured(true);
    device_side.set_secured(true);

    Message m;
    m.type = ProtocolType::Notification;
    m.message_id = notification_id::kRkeRequest;
    m.payload = rke_request(false);

    // device → reader: sealed with sk_device, opened with sk_device.
    auto up = device_side.seal(m);
    REQUIRE(up.has_value());
    Message up_wire;
    up_wire.type = m.type;
    up_wire.message_id = m.message_id;
    up_wire.payload = *up;
    auto got = reader_side.unseal(up_wire);
    REQUIRE(got.has_value());
    CHECK(*got == m.payload);

    // reader → device: sealed with sk_reader, opened with sk_reader.
    m.payload = event_general_error(GeneralError::WrongParameters);
    auto down = reader_side.seal(m);
    REQUIRE(down.has_value());
    Message down_wire;
    down_wire.type = m.type;
    down_wire.message_id = m.message_id;
    down_wire.payload = *down;
    got = device_side.unseal(down_wire);
    REQUIRE(got.has_value());
    CHECK(*got == m.payload);

    CHECK_FALSE(reader_side.aborted());
    CHECK_FALSE(device_side.aborted());
}

TEST_CASE("AP payloads never pass through message security", "[ble][security]") {
    auto sk_reader = some_ble_sk(11);
    auto sk_device = some_ble_sk(12);
    BleMessageSecurity sec(sk_reader, sk_device);
    sec.set_secured(true);

    Message m;
    m.type = ProtocolType::Ap;
    m.message_id = 0;
    m.payload = {0x80, 0x80, 0x00, 0x00};

    auto sealed = sec.seal(m);
    REQUIRE(sealed.has_value());
    CHECK(*sealed == m.payload);   // AP layer has its own secure channel
    CHECK_FALSE(sec.aborted());
}

TEST_CASE("CommonCryptoUtils GCM honors AAD", "[ble][security]") {
    std::array<uint8_t, 32> key = some_ble_sk(13);
    std::array<uint8_t, 12> iv{};
    iv[11] = 1;
    std::vector<uint8_t> plaintext = {1, 2, 3, 4, 5};
    std::vector<uint8_t> aad = {0x02, 0x00, 0x00, 0x05};

    auto ct = CommonCryptoUtils::encryptAesGcm(plaintext, key, iv, aad);
    REQUIRE(ct.size() == plaintext.size() + 16);

    auto pt = CommonCryptoUtils::decryptAesGcm(ct, key, iv, aad);
    REQUIRE(pt == plaintext);

    // Wrong AAD must fail authentication.
    auto wrong = aad;
    wrong[3] = 0x06;
    CHECK(CommonCryptoUtils::decryptAesGcm(ct, key, iv, wrong).empty());

    // No AAD must not decrypt an AAD-protected message either.
    CHECK(CommonCryptoUtils::decryptAesGcm(ct, key, iv).empty());
}
