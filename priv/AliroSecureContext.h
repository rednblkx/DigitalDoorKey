#pragma once
#include "GcmSecureChannel.h"
#include "ddk/session/SecureContext.h"
#include <array>
#include <memory>
#include <optional>

class AliroSecureContext : public ddk::SecureContext {
public:
    // Expedited-only construction (FAST auth — no step-up keys)
    AliroSecureContext(std::array<uint8_t,32> exchange_sk_reader,
                       std::array<uint8_t,32> exchange_sk_device);

    // Standard construction — includes step-up channel
    AliroSecureContext(std::unique_ptr<GcmSecureChannel> exchange,
											 std::array<uint8_t,32> exchange_sk_reader,
                       std::array<uint8_t,32> exchange_sk_device);

    [[nodiscard]] GcmSecureChannel* exchange_channel() const { return exchange_channel_.get(); }
    GcmSecureChannel* step_up_channel() { return step_up_.has_value()
                                            ? &*step_up_ : nullptr; }
    // URSK accessor when BLE+UWB lands

    ddk::ApduResponse exchange(ddk::Session& session,
                               ddk::span<const uint8_t> tlvs,
                               bool skip_response_chaining) override;

    // Step-up ENVELOPE: encrypt DeviceRequest via step-up channel,
    // SessionData wrap, 0x53 TLV, ENVELOPE APDU, decrypt response.
    std::optional<std::vector<uint8_t>> envelope(
        ddk::Session& session, ddk::span<const uint8_t> message);

private:
    std::unique_ptr<GcmSecureChannel> exchange_channel_;
    std::optional<GcmSecureChannel> step_up_;
    GcmSecureChannel* active_channel_ = exchange_channel_.get();
    // ENVELOPE switches active_channel_ to step-up when present;
    // post-step-up EXCHANGE (0x97 completion) uses it too (8.3.3.5).
};
