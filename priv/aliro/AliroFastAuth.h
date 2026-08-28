#pragma once
#include "ddk/session/Session.h"
#include "../AuthResults.hpp"

class AliroFastAuth {
public:
    explicit AliroFastAuth(ddk::Session& session) : session_(session) {}
    FastAuthResult attest(const std::vector<uint8_t>& cryptogram);
private:
    ddk::Session& session_;
};
