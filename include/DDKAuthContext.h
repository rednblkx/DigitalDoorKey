#pragma once
#include "SecureBuffer.h"
#include "DDKReaderData.h"
#include <cstdint>
#include <functional>
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
  readerData_t &readerData;
  SecureBuffer<32> readerEphX;
  SecureBuffer<32> readerEphPrivKey;
  SecureBuffer<65> readerEphPubKey;
  SecureBuffer<65> endpointEphPubKey;
  SecureBuffer<32> endpointEphX;
  std::shared_ptr<ddk::ApduChannel> channel_;
  const std::function<void(const readerData_t&)> &save_cb;
  SecureBuffer<16> transactionIdentifier;
  std::vector<uint8_t> readerIdentifier;
  std::vector<uint8_t> getHashIdentifier(const std::array<uint8_t,65>& key);
  std::vector<uint8_t> commandFlow(CommandFlowStatus status);
	std::array<uint8_t,2> protocolVersion;
	std::array<uint8_t,2> flags{0x01, 0x01};
	std::vector<uint8_t> aliroFCI;
public:
  DDKAuthenticationContext(DigitalKeyType type,
      std::shared_ptr<ddk::ApduChannel> transport,
      readerData_t &readerData,
      const std::function<void(const readerData_t &)> &save_cb);

  AuthContextResult authenticate(KeyFlow);
};
