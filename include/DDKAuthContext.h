#pragma once
#include "SecureBuffer.h"
#include "DDKReaderData.h"
#include <cstdint>
#include <functional>
#include <vector>

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
  const char *TAG = "HKAuthCtx";
  DigitalKeyType type;
  readerData_t &readerData;
  SecureBuffer<32> readerEphX;
  SecureBuffer<32> readerEphPrivKey;
  SecureBuffer<65> readerEphPubKey;
  SecureBuffer<65> endpointEphPubKey;
  SecureBuffer<32> endpointEphX;
  const std::function<bool(std::vector<uint8_t>&, std::vector<uint8_t>&, bool)> &nfc;
  const std::function<void(const readerData_t&)> &save_cb;
  SecureBuffer<16> transactionIdentifier;
  std::vector<uint8_t> readerIdentifier;
  std::vector<uint8_t> getHashIdentifier(const std::array<uint8_t,65>& key);
  std::vector<uint8_t> commandFlow(CommandFlowStatus status);
	std::array<uint8_t,2> protocolVersion;
	std::array<uint8_t,2> flags{0x01, 0x01};
	std::vector<uint8_t> aliroFCI;
public:
  DDKAuthenticationContext(DigitalKeyType type,const std::function<bool(std::vector<uint8_t> &, std::vector<uint8_t> &, bool)> &nfc,
                          readerData_t &readerData, const std::function<void(const readerData_t &)> &save_cb);
	void setAliroFCI(const std::vector<uint8_t> &fci);
	void overrideProtocolVersion(std::array<uint8_t,2> ver);
  AuthContextResult authenticate(KeyFlow);
};
