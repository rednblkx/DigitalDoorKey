#pragma once
#include <array>
#include <functional>
#include <vector>
#include "DDKReaderData.h"
#include "DigitalKeySecureContext.h"
#include "SecureBuffer.h"

struct DDKAuthParams {
  DigitalKeyType type;
  std::vector<hkIssuer_t> &issuers;
  std::vector<uint8_t> &reader_pk_x;
  SecureBuffer<32> &readerEphX;
  SecureBuffer<65> &endpointEphPubKey;
  SecureBuffer<32> &endpointEphX;
  SecureBuffer<16> &transactionIdentifier;
  std::vector<uint8_t> &readerIdentifier;
  std::vector<uint8_t> &aliroFCI;
  std::array<uint8_t, 2> &version;
  const std::function<bool(std::vector<uint8_t>&, std::vector<uint8_t>&, bool)>& nfc;
  
  std::vector<uint8_t> *reader_private_key{};
  SecureBuffer<32> *readerEphPrivKey{};
  SecureBuffer<65> *readerEphPubKey{};
  std::array<uint8_t, 2> &flags;
  DigitalKeySecureContext *context = nullptr;
};
