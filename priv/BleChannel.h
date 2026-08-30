#pragma once
#include "ddk/transport/ApduChannel.h"
#include <cstdint>
#include <memory>

class AliroBleTransport;

// ApduChannel over the Aliro BLE message layer: raw C-APDUs ride in AP_RQ
// (protocol type 0, message id 0), responses in AP_RS (id 1).
// Honors the 1500 ms responseTimeout with Busy reset; General Error or
// timeout expiry forces teardown. Non-AP messages arriving
// while waiting are parked in the transport's deferred queue for the flow.
class BleChannel : public ddk::ApduChannel {
public:
    BleChannel(AliroBleTransport& transport,
               uint32_t response_timeout_ms = 1500);

    ddk::TransportKind kind() const override;
    size_t max_command_payload() const override;
    ddk::ApduResponse transceive(ddk::span<const uint8_t> capdu) override;
    ddk::ApduResponse transceive_full(
        const ddk::ApduCommand& command, bool skip_response_chaining = false,
        size_t max_command_chunk = 255) override;

    AliroBleTransport& transport() { return transport_; }

private:
    AliroBleTransport& transport_;
    uint32_t response_timeout_ms_;
};
