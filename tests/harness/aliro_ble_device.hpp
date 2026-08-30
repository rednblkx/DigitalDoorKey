#pragma once
#include "aliro_test_endpoint.hpp"
#include "BleMessageSecurity.h"
#include "ddk/transport/BleLink.h"

#include <array>
#include <atomic>
#include <cstdint>
#include <memory>
#include <optional>
#include <thread>
#include <vector>

namespace aliro_test {

// Simulated user device (phone side) for the Aliro BLE flows. It wraps the
// existing AliroTestEndpoint APDU handlers — AUTH0/AUTH1/EXCHANGE/ENVELOPE
// device logic and key derivation are unchanged — and adds the BLE surface:
// Initiate Access Protocol, AP_RQ/AP_RS packing, device-side BleSK message
// security, Time Sync, RKE
// requests and status-change observation.
//
// Runs on its own thread; the test arms device-initiated messages before
// start() and reads observations after stop().
class AliroBleDevice {
public:
    AliroBleDevice(std::shared_ptr<ddk::BleLink> link, AliroTestEndpoint& endpoint,
                   std::vector<uint8_t> reader_supported_versions,
                   std::array<uint8_t,2> selected_version);

    ~AliroBleDevice() { stop(); }

    void start();
    void stop();

    void arm_initiate(bool rke) { initiate_rke_ = rke; initiate_armed_ = true; }
    void arm_time_sync() { time_sync_armed_ = true; }
    // Send Notification/Ranging "Initiate Ranging Session" right after the
    // AP Completed notification (what a real phone does pre-M1).
    void arm_ranging_initiation() { ranging_initiation_armed_ = true; }
    void arm_rke(bool secure_action) { rke_armed_ = true; rke_secure_ = secure_action; }
    // Swallow the AUTH0 AP_RQ — the reader must hit responseTimeout.
    void arm_silent_auth0() { silent_auth0_ = true; }

    // Observations (valid after stop()).
    std::vector<std::pair<uint8_t, uint8_t>> apdus_seen;         // (CLA, INS)
    std::vector<std::vector<uint8_t>> exchange_payloads;         // decrypted EXCHANGE payloads
    int exchange_098_seen = 0;                                    // EXCHANGE carrying tag 0x98
    bool ap_completed_seen = false;
    std::vector<uint8_t> ap_completed_payload;                    // decrypted Reader Information
    std::vector<std::vector<uint8_t>> reader_status_payloads;     // decrypted State attributes
    std::vector<uint8_t> general_error_reasons;                   // reason bytes seen
    std::vector<std::vector<uint8_t>> uwb_frames_seen;             // raw SDUs received post-AP (still sealed)
    bool time_sync_acknowledged_by_reader = false;                // reader sent something after Time Sync? (unused)

    // Device-side key material for cross-checks against the reader's.
    std::array<uint8_t, 32> ble_sk{};     // active OKM slice at AP Completed
    std::array<uint8_t, 32> ursk{};       // URSK the reader must report too

private:
    void run();
    bool handle_message(ddk::ble::Message msg);
    bool send(const ddk::ble::Message& msg);
    void activate_security(const std::array<uint8_t, 32>& okm_slice);
    void send_time_sync();

    std::shared_ptr<ddk::BleLink> link_;
    AliroTestEndpoint& endpoint_;
    ddk::NfcChannel::Callback endpoint_cb_;
    std::vector<uint8_t> reader_supported_versions_;
    std::array<uint8_t, 2> selected_version_;
    std::optional<BleMessageSecurity> security_;
    bool saw_auth1_ = false;

    std::atomic<bool> running_{false};
    std::thread thread_;
    // The device always initiates (normal AP unless arm_initiate(true) is
    // called before start()).
    bool initiate_armed_ = true;
    bool initiate_rke_ = false;
    bool time_sync_armed_ = false;
    bool ranging_initiation_armed_ = false;
    bool rke_armed_ = false;
    bool rke_secure_ = false;
    bool silent_auth0_ = false;
};

}  // namespace aliro_test
