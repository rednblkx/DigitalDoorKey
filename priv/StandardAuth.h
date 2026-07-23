#pragma once
#include "AuthParams.h"
#include "AuthResults.hpp"
#include <string_view>
#include <vector>

class DDKStdAuth
{
private:
  const char *TAG = "HKStdAuth";
  DDKAuthParams &params;
  std::vector<uint8_t> *epPkX;
  template <typename Container>
  void Auth1_keying_material(std::array<uint8_t,32> &keyingMaterial, std::string_view context, Container &out);

public:
  DDKStdAuth(DDKAuthParams &params);
  StandardAuthResult attest();
};
