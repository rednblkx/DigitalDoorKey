#include "AuthResults.hpp"
#include "AuthParams.h"

class DDKFastAuth
{
private:
  const char *TAG = "HKFastAuth";
  DDKAuthParams &params;
  std::tuple<ddk::Issuer *, ddk::Endpoint *> find_endpoint_by_cryptogram(std::vector<uint8_t>& cryptogram);
public:
  FastAuthResult attest(std::vector<uint8_t> &encryptedMessage);
  DDKFastAuth(DDKAuthParams &params);
};
