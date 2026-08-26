#pragma once
#include "AuthResults.hpp"
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

    ApduResponse exchange(
        Session& session, std::span<const uint8_t> tlvs) override;

    ApduResponse control_flow(
        Session& session, uint8_t s1, uint8_t s2) override;

private:
    CredentialStore& store_;
    AuthContextResult result_;
    bool ran_ = false;
};

}  // namespace ddk::homekey
