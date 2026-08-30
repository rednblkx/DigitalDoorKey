#pragma once
#include "aliro/Profile.h"
#include <functional>

// ddk::aliro::Profile with BLE completion semantics
// CONTROL FLOW (INS 0x3C) is NFC-only and never sent; success
// ends with the completion EXCHANGE (0x97) followed by the BleSK-encrypted
// Reader Status Access Protocol Completed notification; failures end with
// a General Error event (clear with reason 0 before AP Completed).
class BleProfile : public ddk::aliro::Profile {
public:
    struct Hooks {
        // Sends the EXCHANGE tag 0x98 (make URSK available) through the
        // session's secure context; false fails the ladder.
        std::function<bool(ddk::Session&)> make_ursk_available;
        // Completion EXCHANGE delivered: send Reader Status Access
        // Protocol Completed (first BleSK-encrypted message).
        std::function<void()> notify_ap_completed;
        // Failure surface: General Error event instead of CONTROL FLOW.
        std::function<void()> notify_failure;
    };

    explicit BleProfile(Hooks hooks);

    bool complete(ddk::Session& session, ddk::aliro::ReaderStatus status) override;
    ddk::ApduResponse control_flow(
        ddk::Session& session, uint8_t s1, uint8_t s2) override;

protected:
    bool on_auth_success(ddk::Session& session) override;

private:
    Hooks hooks_;
    bool ursk_requested_ = false;   // tag 0x98 is accepted once per phase
};
