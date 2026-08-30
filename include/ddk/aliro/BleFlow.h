#pragma once
#include "ddk/aliro/ReaderStatus.h"
#include "ddk/session/AuthOutcome.h"
#include "ddk/session/Profile.h"
#include "ddk/session/Session.h"
#include "ddk/store/CredentialStore.h"
#include "ddk/transport/BleLink.h"
#include <array>
#include <functional>
#include <memory>
#include <vector>

class AliroBleTransport;
class BleChannel;

namespace ddk::aliro {

class UwbRangingChannel;

// Reader-side configuration for Aliro-over-BLE transactions.
// The GATT-advertised material must match what the app actually serves:
// the version lists are bound into the BleSK KDF salt.
struct BleFlowConfig {
    // SPSM of the Aliro BLE AC Service L2CAP CoC
    uint16_t spsm = 0x00FD;
    // Reader's supported ALIRO BLE UWB protocol versions — 2B each, MSB
    // first, ordered highest → lowest.
    std::vector<uint8_t> reader_supported_versions{0x01, 0x00};
    // Version the user device selected via the GATT write characteristic.
    std::array<uint8_t, 2> selected_version{0x01, 0x00};
    bool ble_uwb_flow_supported = false;
    bool ble_only_flow_supported = false;
    // bit0 Time Sync Procedure 0
    // bit1 Procedure 1
    // bit2 LE Coded PHY.
    uint8_t features = 0;
    // Reader Information unsolicited-report bits of AP Completed
    // 1 = push status changes to every connected device,
    // 2 = only to the device that caused the change.
    uint8_t unsolicited_status_mode = 1;
    // responseTimeout, wait for the device's Initiate Access Protocol, 
    // and how long the post-AP loop keeps serving the connection after AP Completed.
    uint32_t response_timeout_ms = 1500;
    uint32_t initiate_wait_ms = 10000;
    uint32_t post_ap_idle_ms = 5000;
};

// One Aliro-over-BLE transaction: the expedited ladder over the L2CAP
// channel plus the BLE-specific completion surface (URSK handoff, Reader
// Status notifications, RKE requests). The link carries the L2CAP SDUs;
// everything above it — message framing, BleSK message security, the
// ladder — lives here. Single-threaded: run() and all callbacks execute
// on the caller's thread.
class BleFlow {
public:
    struct Callbacks {
        // return the reader status to report
        // in the Reader Status Changed notification.
        std::function<ReaderStatus(bool secure_action)> on_rke_request;
        // EXCHANGE tag 0x98 accepted — the URSK is available for the UWB
        // session identified by the low 4 octets of the transaction id.
        // The app moves the key into its UWB subsystem (securely).
        std::function<void(const std::array<uint8_t,32>& ursk,
                           uint32_t uwb_session_id)> on_ursk_available;
        std::function<void(const std::vector<uint8_t>& payload)> on_time_sync;
    };

    BleFlow(std::shared_ptr<BleLink> link, CredentialStore& store,
            BleFlowConfig config = {});
    ~BleFlow();
    BleFlow(const BleFlow&) = delete;
    BleFlow& operator=(const BleFlow&) = delete;

    void set_callbacks(Callbacks callbacks);

    // Waits for the device's Initiate Access Protocol (clear), validates
    // the negotiated version, runs the expedited ladder (fast with
    // standard fallback; step-up when signaled), sends Reader Status
    // Access Protocol Completed on success, then serves post-AP messages
    // (Time Sync, RKE Request, ranging requests) until the idle budget
    // expires or the link goes down.
    AuthOutcome run(SessionConfig session_config = {});

    // Reader Status Changed (Notification 2). Requires AP Completed
    // (BleSK window); call from the flow thread.
    bool notify_status(ReaderStatus status, uint8_t operation_source);

    // Optional UWB ranging engine seam. When set, the post-AP loop routes
    // ranging frames to it (instead of declining) and ticks poll(); the
    // URSK handoff arms it. Without one, ranging requests keep getting
    // declined with a General Error.
    void set_uwb_ranging_channel(UwbRangingChannel* channel);

    bool secured() const;    // AP Completed sent — BleSK protection active
    bool link_down() const;

private:
    bool establish(const SessionConfig& session_config, FailureReason& reason);
    bool offer_ursk(Session& session);
    void send_ap_completed();
    void send_failure_event();
    bool send_notification(uint8_t message_id, std::vector<uint8_t> payload);
    bool send_uwb_frame(ddk::span<const uint8_t> frame);
    void serve_post_ap();
    bool handle_rke_request(const std::vector<uint8_t>& payload);

    std::unique_ptr<AliroBleTransport> transport_;
    std::shared_ptr<BleChannel> channel_;
    std::unique_ptr<ddk::Profile> profile_;
    std::unique_ptr<Session> session_;
    CredentialStore& store_;
    BleFlowConfig config_;
    Callbacks callbacks_;
    bool rke_transaction_ = false;
    bool ap_completed_ = false;
    bool ble_security_active_ = false;
    UwbRangingChannel* uwb_channel_ = nullptr;
};

}  // namespace ddk::aliro
