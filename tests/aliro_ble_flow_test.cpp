// Full Aliro-over-BLE flow tests: the expedited ladder rides AP_RQ/AP_RS
// messages through the real BleChannel/BleTransport stack, with the
// simulated user device (tests/harness) on a loopback BleLink pair.
// Covers the BLE+UWB flow (fast + standard), the BLE-only RKE flow,
// failure surfaces, and the responseTimeout teardown.
#include <catch2/catch_test_macros.hpp>

#include "aliro_ble_device.hpp"
#include "aliro_test_endpoint.hpp"
#include "ble_loopback.hpp"
#include "BleMessages.h"
#include "ddk/aliro/BleFlow.h"

#include <optional>
#include <thread>
#include <utility>
#include <vector>

using namespace ddk;
using namespace ddk::ble;
using aliro_test::AliroBleDevice;
using aliro_test::BleLoopbackPair;
using aliro_test::FlowRig;

namespace {

// One BLE transaction: reader flow + simulated device over a loopback
// pair, sharing the NFC flow rig's store/endpoint/key material.
struct BleRig {
    FlowRig base;
    std::shared_ptr<BleLink> reader_link, device_link;
    std::unique_ptr<AliroBleDevice> device;
    aliro::BleFlowConfig config;
    aliro::BleFlow::Callbacks callbacks;

    // Callback captures.
    int ursk_reports = 0;
    std::array<uint8_t, 32> reported_ursk{};
    uint32_t reported_uwb_session_id = 0;
    int time_sync_count = 0;
    std::vector<uint8_t> time_sync_payload;
    std::optional<bool> rke_action;
    aliro::ReaderStatus rke_status = aliro::ReaderStatus::StateUnsecure;

    std::unique_ptr<aliro::BleFlow> flow;

    explicit BleRig(bool provision_persistent_key)
        : base(provision_persistent_key)
    {
        std::tie(reader_link, device_link) = BleLoopbackPair::make();
        device = std::make_unique<AliroBleDevice>(
            device_link, base.endpoint,
            std::vector<uint8_t>{0x01, 0x00}, std::array<uint8_t, 2>{0x01, 0x00});

        callbacks.on_ursk_available =
            [this](const std::array<uint8_t, 32>& ursk, uint32_t sid) {
                reported_ursk = ursk;
                reported_uwb_session_id = sid;
                ++ursk_reports;
            };
        callbacks.on_time_sync = [this](const std::vector<uint8_t>& payload) {
            time_sync_payload = payload;
            ++time_sync_count;
        };
        callbacks.on_rke_request = [this](bool secure) {
            rke_action = secure;
            return rke_status;
        };

        // Keep test wall-time short: the post-AP loop only needs to cover
        // the device round-trips on the loopback pair.
        config.post_ap_idle_ms = 400;
        config.initiate_wait_ms = 2000;
    }

    AuthOutcome run(SessionConfig session_config = {}) {
        flow = std::make_unique<aliro::BleFlow>(reader_link, base.store, config);
        flow->set_callbacks(callbacks);
        device->start();
        auto outcome = flow->run(std::move(session_config));
        device->stop();
        return outcome;
    }

    uint32_t expected_uwb_session_id() const {
        auto tid = base.endpoint.recorded_session_input().transaction_id;
        return (static_cast<uint32_t>(tid[12]) << 24) |
               (static_cast<uint32_t>(tid[13]) << 16) |
               (static_cast<uint32_t>(tid[14]) << 8) |
               static_cast<uint32_t>(tid[15]);
    }
};

}  // namespace

TEST_CASE("BLE+UWB flow: expedited-fast ladder with URSK handoff", "[ble][flow]") {
    BleRig rig(/*provision_persistent_key=*/true);
    rig.base.endpoint.scenario.serve_cryptogram = true;
    rig.config.ble_uwb_flow_supported = true;

    auto outcome = rig.run();
    REQUIRE(outcome.state == FlowState::Done);
    REQUIRE(outcome.endpoint != nullptr);

    // Ladder: AUTH0, then EXCHANGE 0x98 (URSK offer). The success
    // completion is the AP Completed notification — tag 0x97 is
    // failure-only over BLE, so no second EXCHANGE.
    const std::vector<std::pair<uint8_t, uint8_t>> expected_apdus = {
        {0x80, 0x80}, {0x80, 0xC9}};
    CHECK(rig.device->apdus_seen == expected_apdus);
    CHECK(rig.base.endpoint.control_flow_status == std::nullopt);
    REQUIRE(rig.device->exchange_098_seen == 1);

    // Reader Status Access Protocol Completed arrived sealed and read:
    // Reader Information = mode 1 << 13 | StateUnsecure (0x01).
    REQUIRE(rig.device->ap_completed_seen);
    auto completed_attrs = parse_attributes(rig.device->ap_completed_payload);
    REQUIRE(completed_attrs.has_value());
    REQUIRE(completed_attrs->size() == 1);
    CHECK((*completed_attrs)[0].value == std::vector<uint8_t>{0x20, 0x01});

    // URSK callback carries the key the device derived, bound to the
    // low 4 octets of the transaction identifier.
    CHECK(rig.ursk_reports == 1);
    CHECK(rig.reported_ursk == rig.base.endpoint.fast_ursk);
    CHECK(rig.device->ursk == rig.base.endpoint.fast_ursk);
    CHECK(rig.reported_uwb_session_id == rig.expected_uwb_session_id());

    // The flow ended in the BleSK-secured window.
    CHECK(rig.flow->secured());
    CHECK_FALSE(rig.flow->link_down());
}

TEST_CASE("BLE+UWB flow: standard fallback (fast miss) with URSK handoff",
          "[ble][flow]") {
    BleRig rig(/*provision_persistent_key=*/false);
    rig.config.ble_uwb_flow_supported = true;

    auto outcome = rig.run();
    REQUIRE(outcome.state == FlowState::Done);
    REQUIRE(outcome.endpoint != nullptr);

    const std::vector<std::pair<uint8_t, uint8_t>> expected_apdus = {
        {0x80, 0x80}, {0x80, 0x81}, {0x80, 0xC9}};
    CHECK(rig.device->apdus_seen == expected_apdus);
    REQUIRE(rig.device->exchange_098_seen == 1);
    CHECK(rig.ursk_reports == 1);
    CHECK(rig.reported_ursk == rig.base.endpoint.std_ursk);
    CHECK(rig.reported_uwb_session_id == rig.expected_uwb_session_id());
    CHECK(rig.device->ap_completed_seen);
}

TEST_CASE("BLE-only RKE flow: standard auth, RKE request, status change",
          "[ble][flow]") {
    BleRig rig(/*provision_persistent_key=*/false);
    rig.config.ble_only_flow_supported = true;
    rig.config.ble_uwb_flow_supported = false;
    rig.device->arm_initiate(/*rke=*/true);
    rig.device->arm_rke(/*secure_action=*/false);   // unlock/disarm/open

    auto outcome = rig.run();
    REQUIRE(outcome.state == FlowState::Done);

    // RKE flow prohibits expedited-fast: the device must not serve or the
    // reader attempt a cryptogram — AUTH1 ran.
    bool saw_auth1 = false;
    for (auto [cla, ins] : rig.device->apdus_seen)
        if (ins == 0x81) saw_auth1 = true;
    CHECK(saw_auth1);

    // No URSK handoff outside the BLE+UWB flow.
    CHECK(rig.device->exchange_098_seen == 0);
    CHECK(rig.ursk_reports == 0);

    // The RKE request reached the app and the status went back sealed:
    // State = source BLE-only (6) << 8 | unsecure (0x01).
    REQUIRE(rig.rke_action.has_value());
    CHECK_FALSE(*rig.rke_action);
    REQUIRE(rig.device->reader_status_payloads.size() == 1);
    auto state_attrs = parse_attributes(rig.device->reader_status_payloads[0]);
    REQUIRE(state_attrs.has_value());
    CHECK((*state_attrs)[0].value == std::vector<uint8_t>{0x06, 0x01});
}

TEST_CASE("Unknown endpoint fails with a clear General Error, never CONTROL FLOW",
          "[ble][flow]") {
    BleRig rig(/*provision_persistent_key=*/false);
    rig.base.endpoint.scenario.unknown_endpoint_key = true;
    rig.config.ble_uwb_flow_supported = true;

    auto outcome = rig.run();
    CHECK(outcome.state == FlowState::Failed);

    // failure event instead of the NFC CONTROL FLOW.
    // Only reason 0 (Unknown) is legal in the clear window.
    REQUIRE(rig.device->general_error_reasons.size() >= 1);
    CHECK(rig.device->general_error_reasons.front() == 0x00);
    CHECK(rig.base.endpoint.control_flow_status == std::nullopt);
    CHECK_FALSE(rig.device->ap_completed_seen);
    CHECK(rig.flow->link_down());
}

TEST_CASE("responseTimeout expiry tears the connection down", "[ble][flow]") {
    BleRig rig(/*provision_persistent_key=*/true);
    rig.base.endpoint.scenario.serve_cryptogram = true;
    rig.device->arm_silent_auth0();
    rig.config.response_timeout_ms = 150;

    auto outcome = rig.run();
    CHECK(outcome.state == FlowState::Failed);

    // The device swallows AUTH0 — the reader times out, emits the failure
    // event (clear General Error) and initiates teardown.
    REQUIRE(rig.device->general_error_reasons.size() >= 1);
    CHECK(rig.device->general_error_reasons.front() == 0x00);
    CHECK(rig.flow->link_down());
    CHECK_FALSE(rig.device->ap_completed_seen);
}

TEST_CASE("Time Sync is accepted and forwarded after AP Completed",
          "[ble][flow]") {
    BleRig rig(/*provision_persistent_key=*/true);
    rig.base.endpoint.scenario.serve_cryptogram = true;
    rig.config.ble_uwb_flow_supported = true;
    rig.device->arm_time_sync();

    auto outcome = rig.run();
    REQUIRE(outcome.state == FlowState::Done);

    REQUIRE(rig.time_sync_count == 1);
    auto attrs = parse_attributes(rig.time_sync_payload);
    REQUIRE(attrs.has_value());
    CHECK(attrs->size() == 7);
}
