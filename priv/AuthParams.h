#pragma once
#include <array>
#include <vector>
#include "DDKReaderData.h"
#include "ScbSecureChannel.h"
#include "SecureBuffer.h"
#include "ddk/store/CredentialStore.h"

namespace ddk {
  class ApduChannel;
}

struct DDKAuthParams {
  DigitalKeyType type;
  ddk::CredentialStore &store;
  SecureBuffer<32> &readerEphX;
  SecureBuffer<65> &endpointEphPubKey;
  SecureBuffer<32> &endpointEphX;
  SecureBuffer<16> &transactionIdentifier;
  std::vector<uint8_t> &readerIdentifier;
  std::vector<uint8_t> &aliroFCI;
  std::array<uint8_t, 2> &version;
  
  SecureBuffer<32> *readerEphPrivKey{};
  SecureBuffer<65> *readerEphPubKey{};
  std::array<uint8_t, 2> &flags;
  ScbSecureChannel *scb_context = nullptr;
  ddk::ApduChannel* channel_ = nullptr;
};
