#pragma once
#include "../ScbSecureChannel.h"
#include "ddk/session/Session.h"
#include "ddk/transport/ApduChannel.h"
#include <memory>

class HKSecureContext : public ddk::SecureContext {
public:
    explicit HKSecureContext(std::unique_ptr<ScbSecureChannel> scb);

    ScbSecureChannel& channel() { return *scb_.get(); };

    ddk::ApduResponse exchange(ddk::Session& session,
                              ddk::span<const uint8_t> tlvs,
                              bool skip_response_chaining = false) override;
private:
    std::unique_ptr<ScbSecureChannel> scb_;
};
