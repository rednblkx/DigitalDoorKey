#pragma once
#include "DDKReaderData.h"
#include <cstdint>
#include <functional>
#include <vector>

class DDKAuthenticationContext
{
private:
  const char *TAG = "HKAuthCtx";
  DigitalKeyType type;
  readerData_t &readerData;
  std::vector<uint8_t> readerEphX;
  std::vector<uint8_t> readerEphPrivKey;
  std::vector<uint8_t> readerEphPubKey;
  std::vector<uint8_t> endpointEphPubKey;
  std::vector<uint8_t> endpointEphX;
  const std::function<bool(std::vector<uint8_t>&, std::vector<uint8_t>&, bool)> &nfc;
  const std::function<void(const readerData_t&)> &save_cb;
  std::vector<uint8_t> transactionIdentifier;
  std::vector<uint8_t> readerIdentifier;
  std::vector<uint8_t> getHashIdentifier(const std::vector<uint8_t>& key);
  std::vector<uint8_t> commandFlow(CommandFlowStatus status);
	std::array<uint8_t,2> protocolVersion;
	std::array<uint8_t,2> flags{0x01, 0x01};
	std::vector<uint8_t> aliroFCI;
public:
  DDKAuthenticationContext(DigitalKeyType type,const std::function<bool(std::vector<uint8_t> &, std::vector<uint8_t> &, bool)> &nfc,
                          readerData_t &readerData, const std::function<void(const readerData_t &)> &save_cb);
	void setAliroFCI(const std::vector<uint8_t> &fci);
	void overrideProtocolVersion(std::array<uint8_t,2> ver);
  std::tuple<std::vector<uint8_t>, std::vector<uint8_t>, KeyFlow> authenticate(KeyFlow);
};
