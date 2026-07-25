#include "DDKReaderData.h"
#include "AuthParams.h"
#include "AuthResults.hpp"

class DDKAttestationAuth
{
private:
  const char *TAG = "HKAttestAuth";
  DDKAuthParams &params;
  std::vector<uint8_t> attestation_exchange_common_secret;
  std::vector<unsigned char> attestation_salt(std::vector<unsigned char> &env1Data, std::vector<unsigned char> &readerCmd);
  std::tuple<std::vector<uint8_t>, std::vector<uint8_t>> envelope1Cmd();
  std::vector<unsigned char> envelope2Cmd(std::vector<uint8_t> &salt);
  std::tuple<hkIssuer_t*, std::array<uint8_t,65>> verify(std::vector<uint8_t>& decryptedCbor);

public:
  DDKAttestationAuth(DDKAuthParams &params);
  AttestationResult attest();
};
