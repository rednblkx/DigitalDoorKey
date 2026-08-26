#pragma once
#include "ddk/Span.h"
#include "SecureBuffer.h"
#include "ddk/session/SecureContext.h"
#include "ddk/transport/ApduChannel.h"
#include "ddk/session/Flow.h"
#include <array>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace ddk {

class CredentialStore;

struct SessionConfig {
    Flow target_flow = Flow::Fast;
    uint8_t authentication_policy = 0x01;
    std::optional<std::vector<uint8_t>> auth0_command_vendor_extension;
    std::optional<std::map<std::string, bool>> step_up_scopes;
};

struct Transcript {
    // From store — span into store data, valid for Session lifetime
    ddk::span<const uint8_t> reader_pk_x;

    // Built from store — owned by Transcript (gid || sub)
    std::vector<uint8_t> reader_identifier;

    // Generated after FAST fails
    SecureBuffer<32> reader_eph_priv;
    SecureBuffer<65> reader_eph_pub;
    SecureBuffer<32> reader_eph_x;

    // From AUTH0 response
    SecureBuffer<65> endpoint_eph_pub;
    SecureBuffer<32> endpoint_eph_x;

    // Per-session
    SecureBuffer<16> transaction_id;
    std::array<uint8_t,2> protocol_version{};
    std::array<uint8_t,2> flags{0x01, 0x01};

    // From SELECT response
    std::vector<uint8_t> fci_proprietary;
    uint8_t interface = 0;
    std::vector<uint8_t> auth0_info_suffix;
};

class Session {
public:
    Session(std::shared_ptr<ApduChannel> apdu,
            CredentialStore& store,
            SessionConfig config = {});

    ApduChannel& apdu() { return *apdu_; }
    CredentialStore& store() { return store_; }
    const SessionConfig& config() const { return config_; }
    Transcript& transcript() { return transcript_; }

    SecureContext* secure_context() const { return secure_context_.get(); }

    void set_secure_context(std::unique_ptr<SecureContext> ctx) {
        secure_context_ = std::move(ctx);
    }

private:
    std::shared_ptr<ApduChannel> apdu_;
    CredentialStore& store_;
    SessionConfig config_;
    Transcript transcript_;
    std::unique_ptr<SecureContext> secure_context_;
};

}  // namespace ddk
