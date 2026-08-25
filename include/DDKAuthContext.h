#pragma once
#include "ddk/store/CredentialStore.h"
#include "SecureBuffer.h"
#include "DDKReaderData.h"
#include <cstdint>
#include <memory>
#include <vector>
#include "ddk/transport/ApduChannel.h"

/**
 * Result of the higher-level Context authentication.
 */
struct AuthContextResult {
    std::vector<uint8_t> issuer_id;
    std::vector<uint8_t> endpoint_id;
    KeyFlow flow = kFlowFailed;
};

class DDKAuthenticationContext
{
private:
  const char *TAG = "AuthCtx";
  DigitalKeyType type;
  ddk::CredentialStore& store;
  SecureBuffer<32> readerEphX;
  SecureBuffer<32> readerEphPrivKey;
  SecureBuffer<65> readerEphPubKey;
  SecureBuffer<65> endpointEphPubKey;
  SecureBuffer<32> endpointEphX;
  std::shared_ptr<ddk::ApduChannel> channel_;
  SecureBuffer<16> transactionIdentifier;
  std::vector<uint8_t> readerIdentifier;
  std::vector<uint8_t> commandFlow(CommandFlowStatus status);
	std::array<uint8_t,2> protocolVersion;
	std::array<uint8_t,2> flags{0x01, 0x01};
	std::vector<uint8_t> aliroFCI;
public:
  DDKAuthenticationContext(DigitalKeyType type,
      std::shared_ptr<ddk::ApduChannel> transport,
      ddk::CredentialStore& store);

  AuthContextResult authenticate(KeyFlow);
};
