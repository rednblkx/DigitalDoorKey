#pragma once
#include "AuthParams.h"
#include "AuthResults.hpp"

class DDKStdAuth
{
private:
  const char *TAG = "HKStdAuth";
  DDKAuthParams &params;

public:
  DDKStdAuth(DDKAuthParams &params);
  StandardAuthResult attest();
};
