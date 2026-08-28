#pragma once
#include "ddk/session/Session.h"
#include "AuthResults.hpp"
#include "ScbSecureChannel.h"
#include <tuple>
#include <vector>

class HKAttestationAuth
{
private:
  const char *TAG = "HKAttestAuth";
  ddk::Session& session_;
  ScbSecureChannel& scb_;
  std::vector<uint8_t> attestation_exchange_common_secret;
  std::vector<unsigned char> attestation_salt(
      std::vector<unsigned char> &env1Data,
      std::vector<unsigned char> &readerCmd);
  std::tuple<std::vector<uint8_t>, std::vector<uint8_t>> envelope1Cmd();
  std::vector<unsigned char> envelope2Cmd(std::vector<uint8_t> &salt);
  HKAttestationVerificationResult verify(std::vector<uint8_t>& decryptedCbor);
  static bool extract_device_key(
      ddk::span<const uint8_t> payload,          // tag-24-wrapped MSO bytes
      std::vector<uint8_t>& x_out,
      std::vector<uint8_t>& y_out);
public:
  HKAttestationAuth(ddk::Session& session, ScbSecureChannel& scb);
  HKAttestationResult attest();
};
