#include "AuthResults.hpp"
#include "DDKReaderData.h"
#include "AuthParams.h"

class DDKFastAuth
{
private:
  const char *TAG = "HKFastAuth";
  DDKAuthParams &params;
  void Auth0_keying_material(const char* context, const std::vector<uint8_t>& ePubX, const std::vector<uint8_t>& keyingMaterial, uint8_t* out, size_t outLen);
  std::tuple<hkIssuer_t *, hkEndpoint_t *> find_endpoint_by_cryptogram(std::vector<uint8_t>& cryptogram);
public:
  FastAuthResult attest(std::vector<uint8_t> &encryptedMessage);
  DDKFastAuth(DDKAuthParams &params);
};
