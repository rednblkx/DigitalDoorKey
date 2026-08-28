#pragma once
#include "ddk/Span.h"
#include "ddk/transport/ApduChannel.h"

namespace ddk {

class Session;

// Abstract secure context — owns the secure channel established during
// authentication. Lifetime is the session's lifetime.
// Protocol-specific subclasses (private) expose additional channels.
class SecureContext {
public:
    virtual ~SecureContext() = default;

    // Post-auth EXCHANGE: encrypt plaintext TLVs via the secure channel,
    // send as EXCHANGE APDU (INS 0xC9), decrypt the response.
    // Returns response with DECRYPTED data + status word.
    virtual ApduResponse exchange(Session& session,
                                  span<const uint8_t> tlvs, bool skip_response_chaining = false) = 0;
};

}  // namespace ddk
