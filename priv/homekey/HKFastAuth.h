#pragma once
#include "ddk/session/Session.h"
#include "AuthResults.hpp"

class HomeKeyFastAuth {
public:
    explicit HomeKeyFastAuth(ddk::Session& session) : session_(session) {}
    FastAuthResult attest(const std::vector<uint8_t>& cryptogram);
private:
    ddk::Session& session_;
};
