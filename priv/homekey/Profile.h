#pragma once
#include "AuthResults.hpp"
#include "HKSecureContext.h"
#include "ddk/session/Profile.h"
#include "ddk/store/CredentialStore.h"

namespace ddk::homekey {

class Profile final : public ddk::Profile {
public:
    explicit Profile(CredentialStore& store);

    ddk::FailureReason validate_select(
        Session& session, std::span<const uint8_t> fci) override;

    FlowState step(Session& session, FlowState current) override;

    AuthOutcome finalize(Session& session) override;

    ApduResponse control_flow(
        Session& session, uint8_t s1, uint8_t s2) override;

private:
    CredentialStore& store_;
    AuthContextResult result_;
    std::unique_ptr<HKSecureContext> secure_context_;
    bool ran_ = false;
};

}  // namespace ddk::homekey
