#pragma once
#include "AuthResults.hpp"
#include "ddk/session/Profile.h"
#include "ddk/aliro/ReaderStatus.h"

namespace ddk::aliro {

class Profile : public ddk::Profile {
public:
    explicit Profile();

    FailureReason validate_select(
        Session& session, ddk::span<const uint8_t> select_response) override;

    FlowState step(Session& session, FlowState current) override;

    virtual bool complete(Session& session, ReaderStatus status);
    AuthOutcome finalize(Session& session) override;

    ApduResponse control_flow(
        Session& session, uint8_t s1, uint8_t s2) override;

    // NFC parses this from the SELECT FCI (0x7F66 ext-info); the BLE flow
    // parses the device's 0xA5 proprietary info and sets it before stepping.
    void set_max_command_data_size(size_t size) { max_command_data_size_ = size; }

protected:
    virtual bool on_auth_success(Session& session) { (void)session; return true; }

private:
    AuthContextResult result_;
    bool ran_ = false;
    size_t max_command_data_size_ = 255;
    std::vector<uint8_t> step_up_access_document_;
};

}  // namespace ddk::aliro
