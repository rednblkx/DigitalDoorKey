#include "aliro/BleProfile.h"
#include "aliro/AliroSecureContext.h"
#include "DDKLogging.h"

namespace {
constexpr const char* TAG = "BleProfile";
}  // namespace

BleProfile::BleProfile(Hooks hooks) : hooks_(std::move(hooks)) {}

bool BleProfile::complete(ddk::Session& session, ddk::aliro::ReaderStatus status) {
    if ((static_cast<uint16_t>(status) >> 8) == 0x01) {
        if (hooks_.notify_ap_completed) hooks_.notify_ap_completed();
        return true;
    }

    auto* ctx = static_cast<AliroSecureContext*>(session.secure_context());
    if (ctx) {
        uint16_t s = static_cast<uint16_t>(status);
        std::vector<uint8_t> payload{0x97, 0x02,
            static_cast<uint8_t>(s >> 8), static_cast<uint8_t>(s & 0xFF)};
        auto resp = ctx->exchange(session, payload, /*skip_response_chaining=*/true);
        if (resp.sw1 == 0x90 || resp.sw1 == 0x61) {
            LOG(D, "failure EXCHANGE delivered (status %04X)", s);
            if (hooks_.notify_failure) hooks_.notify_failure();
            return true;
        }
        LOG(W, "failure EXCHANGE failed (SW %02X%02X)", resp.sw1, resp.sw2);
    }
    if (hooks_.notify_failure) hooks_.notify_failure();
    return false;
}

ddk::ApduResponse BleProfile::control_flow(ddk::Session&, uint8_t, uint8_t) {
    if (hooks_.notify_failure) hooks_.notify_failure();
    return {};
}

bool BleProfile::on_auth_success(ddk::Session& session) {
    if (!hooks_.make_ursk_available || ursk_requested_) return true;
    ursk_requested_ = true;
    return hooks_.make_ursk_available(session);
}
