// UWB ranging seam tests: BleFlow routes ranging-relevant frames to the
// injected UwbRangingChannel BleSK-decrypted, seals what the engine emits,
// arms it with the URSK + session id at the 0x98 handoff, ticks poll() from
// the post-AP loop, and stops it at teardown — while a flow without a
// channel keeps declining ranging with a General Error.
#include <catch2/catch_test_macros.hpp>

#include "aliro_ble_device.hpp"
#include "aliro_test_endpoint.hpp"
#include "ble_loopback.hpp"
#include "BleMessages.h"
#include "ddk/aliro/BleFlow.h"
#include "ddk/aliro/UwbRangingChannel.h"

#include <algorithm>
#include <chrono>
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

// Records everything the flow does to the seam; the canned M1 reply proves
// the outgoing path is sealed and delivered.
struct FakeUwbChannel : public ddk::aliro::UwbRangingChannel {
    std::function<bool(ddk::span<const uint8_t>)> send;
    bool armed = false;
    uint32_t armed_session_id = 0;
    std::vector<uint8_t> armed_ursk;
    std::vector<std::vector<uint8_t>> frames_in;
    std::vector<std::vector<uint8_t>> frames_out;
    int polls = 0;
    bool stopped = false;
    // When set, handle_frame emits this frame once (e.g. after the phone's
    // Initiate-Ranging-Session).
    std::optional<std::vector<uint8_t>> reply_after_initiate;
    bool replied = false;

    void set_sender(std::function<bool(ddk::span<const uint8_t>)> s) override {
        send = std::move(s);
    }
    void arm(uint32_t session_id, ddk::span<const uint8_t> ursk,
             const std::array<uint8_t, 2>& selected_version) override {
        armed = true;
        armed_session_id = session_id;
        armed_ursk.assign(ursk.begin(), ursk.end());
        armed_version = selected_version;
    }
    std::array<uint8_t, 2> armed_version{0, 0};
    void handle_frame(ddk::span<const uint8_t> frame) override {
        frames_in.emplace_back(frame.begin(), frame.end());
        if (reply_after_initiate && !replied && send) {
            // Reply to the phone's Initiate-Ranging-Session with the canned
            // frame (an M1: proto 1, id 0).
            std::vector<uint8_t> out = *reply_after_initiate;
            frames_out.push_back(out);
            CHECK(send(out));
            replied = true;
        }
    }
    void poll() override { ++polls; }
    bool ranging_active() const override { return ranging_live; }
    void stop() override { stopped = true; }

    // Pretend M4 completed and the responder is on the radio.
    bool ranging_live = false;
};

struct UwbRig {
    FlowRig base;
    std::shared_ptr<BleLink> reader_link, device_link;
    std::unique_ptr<AliroBleDevice> device;
    aliro::BleFlowConfig config;
    aliro::BleFlow::Callbacks callbacks;
    FakeUwbChannel channel;
    std::unique_ptr<aliro::BleFlow> flow;

    explicit UwbRig(bool provision_persistent_key)
        : base(provision_persistent_key)
    {
        std::tie(reader_link, device_link) = BleLoopbackPair::make();
        device = std::make_unique<AliroBleDevice>(
            device_link, base.endpoint,
            std::vector<uint8_t>{0x01, 0x00}, std::array<uint8_t, 2>{0x01, 0x00});
        config.post_ap_idle_ms = 400;
        config.initiate_wait_ms = 2000;
        config.ble_uwb_flow_supported = true;
    }

    bool attach_channel = true;

    AuthOutcome run() {
        flow = std::make_unique<aliro::BleFlow>(reader_link, base.store, config);
        flow->set_callbacks(callbacks);
        if (attach_channel) flow->set_uwb_ranging_channel(&channel);
        device->start();
        auto outcome = flow->run();
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

// Notification/Ranging frame: Initiate-Ranging-Session (proto 2, id 1,
// zero-length attribute 0x00).
std::vector<uint8_t> initiate_ranging_frame()
{
    Message m;
    m.type = ProtocolType::Notification;
    m.message_id = notification_id::kRanging;
    m.payload = ranging_attribute(ranging_attr::kInitiateRangingSession);
    return m.encode();
}

// UWB Ranging Service Setup M1 (proto 1, id 0) — one Session-Identifier
// attribute is enough to exercise the sealed path.
std::vector<uint8_t> m1_frame()
{
    Message m;
    m.type = ProtocolType::UwbRanging;
    m.message_id = 0;   // Setup M1
    m.payload = encode_attributes({{0x02, {0x51, 0x8E, 0xB9, 0x8F}}});
    return m.encode();
}

}  // namespace

TEST_CASE("Ranging frames route to the UWB channel and replies go out sealed",
          "[ble][uwb]") {
    UwbRig rig(/*provision_persistent_key=*/true);
    rig.base.endpoint.scenario.serve_cryptogram = true;
    rig.device->arm_ranging_initiation();
    rig.channel.reply_after_initiate = m1_frame();

    auto outcome = rig.run();
    REQUIRE(outcome.state == FlowState::Done);

    // Armed at the 0x98 handoff with the fast-flow URSK.
    REQUIRE(rig.channel.armed);
    CHECK(rig.channel.armed_session_id == rig.expected_uwb_session_id());
    CHECK(rig.channel.armed_ursk ==
          std::vector<uint8_t>(rig.base.endpoint.fast_ursk.begin(),
                               rig.base.endpoint.fast_ursk.end()));

    // The phone's Initiate-Ranging-Session reached the seam decrypted:
    // proto 2 / id 1 / zero-length attribute 0.
    REQUIRE(rig.channel.frames_in.size() >= 1);
    auto initiate = rig.channel.frames_in.front();
    REQUIRE(initiate.size() >= 6);
    CHECK(initiate[0] == 0x02);
    CHECK(initiate[1] == notification_id::kRanging);
    auto attrs = parse_attributes(
        ddk::span<const uint8_t>(initiate).subspan(4));
    REQUIRE(attrs.has_value());
    REQUIRE(find_attribute(*attrs, ranging_attr::kInitiateRangingSession));

    // The canned M1 went out and arrived at the device BleSK-encrypted:
    // proto 1 / id 0, sealed payload (device security is up post-AP).
    REQUIRE(rig.channel.replied);
    bool m1_received = false;
    for (const auto& sdu : rig.device->uwb_frames_seen) {
        auto messages = unpack_sdu(sdu);
        for (const auto& m : messages) {
            if (m.type == ProtocolType::UwbRanging && m.message_id == 0) {
                m1_received = true;
            }
        }
    }
    CHECK(m1_received);

    // Ticks happened and the seam was stopped at teardown.
    CHECK(rig.channel.polls > 0);
    CHECK(rig.channel.stopped);
    CHECK(rig.flow->secured());
}

TEST_CASE("Without a UWB channel, ranging requests are still declined",
          "[ble][uwb]") {
    UwbRig rig(/*provision_persistent_key=*/true);
    rig.base.endpoint.scenario.serve_cryptogram = true;
    rig.attach_channel = false;
    rig.device->arm_ranging_initiation();
    // No channel: the device arms nothing, and the phone's Initiate-Ranging-
    // Session draws the WrongParameters decline. The device records the
    // encrypted General Error; the flow stays up until the idle timeout.
    auto outcome = rig.run();
    REQUIRE(outcome.state == FlowState::Done);   // auth itself succeeded
    CHECK_FALSE(rig.channel.armed);
    CHECK(rig.channel.frames_in.empty());
    CHECK(rig.channel.polls == 0);
    CHECK_FALSE(rig.channel.stopped);            // never registered → never stopped
}

TEST_CASE("A live ranging session outlives the post-AP idle timeout",
          "[ble][uwb]") {
    UwbRig rig(/*provision_persistent_key=*/true);
    rig.base.endpoint.scenario.serve_cryptogram = true;
    rig.device->arm_ranging_initiation();
    rig.channel.reply_after_initiate = m1_frame();
    rig.channel.ranging_live = true;   // responder on the radio: hold the session

    // Close the link from the device side well past the 400 ms idle window.
    // If the flow still ended on idle (or on an absolute post-AP cap), run()
    // would return before the closer fires.
    const auto started = std::chrono::steady_clock::now();
    constexpr int kCloseAfterMs = 900;
    std::thread closer([&] {
        std::this_thread::sleep_for(std::chrono::milliseconds(kCloseAfterMs));
        rig.device_link->close();
    });
    auto outcome = rig.run();
    closer.join();
    REQUIRE(outcome.state == FlowState::Done);
    auto served_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                         std::chrono::steady_clock::now() - started).count();
    CHECK(served_ms >= kCloseAfterMs - 100);   // held open until the link broke
    CHECK(rig.channel.stopped);               // and was torn down properly
}
