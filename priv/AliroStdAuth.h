#pragma once
#include "ddk/session/Session.h"
#include "AuthResults.hpp"

class AliroStdAuth {
public:
    explicit AliroStdAuth(ddk::Session& session) : session_(session) {}
    AliroStdAuthResult attest();

private:
    ddk::Session& session_;

    std::array<uint8_t,4> readerCtx{0x41, 0x5d, 0x95, 0x69};
    std::array<uint8_t,4> deviceCtx{0x4e, 0x88, 0x7b, 0x4c};

    std::vector<uint8_t> buildAuth1SignatureInput();
    std::vector<uint8_t> buildVerificationInput();
};
