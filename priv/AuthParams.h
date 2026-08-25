#pragma once
#include <array>
#include <vector>
#include "DDKReaderData.h"
#include "ScbSecureChannel.h"
#include "SecureBuffer.h"

namespace ddk {
  class ApduChannel;
}

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
  
  std::vector<uint8_t> *reader_private_key{};
  SecureBuffer<32> *readerEphPrivKey{};
  SecureBuffer<65> *readerEphPubKey{};
  std::array<uint8_t, 2> &flags;
  ScbSecureChannel *scb_context = nullptr;
  ddk::ApduChannel* channel_ = nullptr;
};
