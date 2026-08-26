#pragma once
#include "GcmSecureChannel.h"
#include "ddk/session/Session.h"
#include "ddk/transport/ApduChannel.h"
#include <array>

class AliroSecureContext : public ddk::SecureContext {
public:
    AliroSecureContext(std::array<uint8_t,32> exchange_sk_reader,
                       std::array<uint8_t,32> exchange_sk_device);

    GcmSecureChannel& exchange_channel() { return exchange_channel_; };

    ddk::ApduResponse exchange(ddk::Session& session,
                          ddk::span<const uint8_t> tlvs) override;

private:
    GcmSecureChannel exchange_channel_;
};
