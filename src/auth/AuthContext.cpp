#include <algorithm>
#include <DDKAuthContext.h>
#include "CommonCryptoUtils.h"
#include "DDKReaderData.h"
#include "fmt/ranges.h"
#include "FastAuth.h"
#include "StandardAuth.h"
#include "AttestationAuth.h"
#include "AuthParams.h"
#include "simple_tlv.hpp"
#include "logging.h"
#if defined(CONFIG_IDF_CMAKE)
#include <esp_random.h>
#else 
#include "sodium.h"
#endif
#include <iterator>
#include <mbedtls/sha1.h>
#include <chrono>
#include <TLV8.hpp>

std::vector<uint8_t> DDKAuthenticationContext::getHashIdentifier(const std::vector<uint8_t>& key) {
  LOG(V, "Key: %s, Length: %d", fmt::format("{:02X}", fmt::join(key, "")).c_str(), key.size());
  std::vector<unsigned char> hashable;
  hashable.insert(hashable.end(), key.begin(), key.end());
  LOG(V, "Hashable: %s", fmt::format("{:02X}", fmt::join(hashable, "")).c_str());
  std::vector<uint8_t> hash(32);
  mbedtls_sha1(&hashable.front(), hashable.size(), hash.data());
  LOG(V, "HashIdentifier: %s", fmt::format("{:02X}", fmt::join(hash, "")).c_str());
  return hash;
}

/**
 * The function `HKAuthenticationContext::commandFlow` sends the command flow status APDU command
 * and returns the response.
 *
 * @param status The parameter "status" is of type "CommandFlowStatus"
 *
 * @return a std::vector<uint8_t> object, which contains the received response
 */
std::vector<uint8_t> DDKAuthenticationContext::commandFlow(CommandFlowStatus status)
{
  std::vector<uint8_t> cmdFlowRes(3);
  if (type == kHomeKey) {
    std::vector<uint8_t> apdu = {0x80, 0x3c, static_cast<uint8_t>(status), 0x0};
    LOG(D, "APDU: %s, Length: %d", fmt::format("{:02X}", fmt::join(apdu, "")).c_str(), apdu.size());
    nfc(apdu, cmdFlowRes, false);
  }
  if (type == kAliro) {
    const uint8_t t = (status == kCmdFlowFailed ? 0x00 : 0x01);
    std::vector<uint8_t> apdu {
      0x80, 0x3C, 0x00, 0x00,
      0x06,
      0x41, 0x01, t,
      0x42, 0x01, 0x01
  };

    LOG(I, "Aliro Control Flow APDU: %s", fmt::format("{:02X}", fmt::join(apdu, "")).c_str());
    nfc(apdu, cmdFlowRes, false);
  }
  return cmdFlowRes;
}

/**
 * The HKAuthenticationContext constructor generates an ephemeral key for the reader and initializes
 * core variables
 *
 * @param nfc The `nfc` parameter is a function pointer that points to a
 * function responsible for exchanging data with an NFC device. It takes input data, its length, and
 * returns a response along with the response length.
 * @param readerData The `readerData` parameter is a reference to an object of the type
 * `readerData_t`.
 * @param save_cb Callback to persist the reader data
 */
DDKAuthenticationContext::DDKAuthenticationContext(DigitalKeyType type, const std::function<bool(std::vector<uint8_t>&, std::vector<uint8_t>&, bool)> &nfc, readerData_t &readerData, const std::function<void(const readerData_t&)> &save_cb) : type(type), readerData(readerData), nfc(nfc), save_cb(save_cb), transactionIdentifier(16)
{
  // esp_log_level_set(TAG, ESP_LOG_VERBOSE);
  if (type == DigitalKeyType::kAliro) {
    protocolVersion = {0x00, 0x09};
  } else if (type == DigitalKeyType::kHomeKey) {
    protocolVersion = {0x02, 0x00};
  }
  auto startTime = std::chrono::high_resolution_clock::now();
  auto readerEphKey = CommonCryptoUtils::generateEphemeralKey();
  readerEphPrivKey.swap(std::get<0>(readerEphKey));
  readerEphPubKey.swap(std::get<1>(readerEphKey));
#if defined(CONFIG_IDF_CMAKE)
  esp_fill_random(transactionIdentifier.data(), 16);
#else
  randombytes(transactionIdentifier.data(), 16);
#endif
  readerIdentifier.reserve(readerData.reader_gid.size() + readerData.reader_id.size());
  readerIdentifier.insert(readerIdentifier.begin(), readerData.reader_gid.begin(), readerData.reader_gid.end());
  readerIdentifier.insert(readerIdentifier.end(), readerData.reader_id.begin(), readerData.reader_id.end());
  readerEphX = CommonCryptoUtils::get_x(readerEphPubKey);
  auto stopTime = std::chrono::high_resolution_clock::now();
  LOG(I, "Initialization Time: %lli ms", std::chrono::duration_cast<std::chrono::milliseconds>(stopTime - startTime).count());
}

void DDKAuthenticationContext::setAliroFCI(const std::vector<uint8_t> &fci) {
  aliroFCI = fci;
}

void DDKAuthenticationContext::overrideProtocolVersion(std::array<uint8_t,2> ver) {
  this->protocolVersion = ver;
}

/**
 * The function `authenticate` in the `HKAuthenticationContext` class processes authentication data and
 * returns the issuer and endpoint IDs along with the authentication flow type.
 *
 * @param hkFlow The `hkFlow` parameter in the `authenticate` function is an integer that determines
 * the type of HomeKey flow to be used for authentication. It can have the following values defined in
 * the `KeyFlow` enum: kFlowFAST, kFlowSTANDARD and kFlowATTESTATION
 *
 * @return A tuple containing the matching `issuer_id` and `ep_id`, and the successful flow from
 * the enum `KeyFlow`.
 */
std::tuple<std::vector<uint8_t>, std::vector<uint8_t>, KeyFlow> DDKAuthenticationContext::authenticate(KeyFlow hkFlow){
  auto startTime = std::chrono::high_resolution_clock::now();
  std::vector<uint8_t> fastTlv;
  fastTlv.reserve(protocolVersion.size() + readerEphPubKey.size() + transactionIdentifier.size() + readerIdentifier.size() + 8); // +8 for TLV overhead
#if __cplusplus >= 202002L
  if (type == DigitalKeyType::kAliro) {
    std::ranges::copy(simple_tlv<std::array<uint8_t, 1>>(0x41, {flags[0]}), std::back_inserter(fastTlv));
    std::ranges::copy(simple_tlv<std::array<uint8_t, 1>>(0x42, {flags[1]}), std::back_inserter(fastTlv));
  }
  std::ranges::copy(simple_tlv(0x5C, protocolVersion), std::back_inserter(fastTlv));
  std::ranges::copy(simple_tlv(0x87, readerEphPubKey), std::back_inserter(fastTlv));
  std::ranges::copy(simple_tlv(0x4C, transactionIdentifier), std::back_inserter(fastTlv));
  std::ranges::copy(simple_tlv(0x4D, readerIdentifier), std::back_inserter(fastTlv));
#else
  if (type == DigitalKeyType::kAliro) {
    auto txflags_tlv = simple_tlv<std::array<uint8_t,1>>(0x41, {flags[0]});
    std::copy(txflags_tlv.begin(), txflags_tlv.end(), std::back_inserter(fastTlv));
    auto txcode_tlv = simple_tlv<std::array<uint8_t,1>>(0x42, {flags[1]});
    std::copy(txcode_tlv.begin(), txcode_tlv.end(), std::back_inserter(fastTlv));
  }

  auto version_tlv = simple_tlv(0x5C, protocolVersion);
  std::copy(version_tlv.begin(), version_tlv.end(), std::back_inserter(fastTlv));

  auto reader_pk_tlv = simple_tlv(0x87, readerEphPubKey);
  std::copy(reader_pk_tlv.begin(), reader_pk_tlv.end(), std::back_inserter(fastTlv));

  auto txId_tlv = simple_tlv(0x4C, transactionIdentifier);
  std::copy(txId_tlv.begin(), txId_tlv.end(), std::back_inserter(fastTlv));

  auto reader_id_tlv = simple_tlv(0x4D, readerIdentifier);
  std::copy(reader_id_tlv.begin(), reader_id_tlv.end(), std::back_inserter(fastTlv));
#endif

  if (fastTlv.size() > 255) {
    LOG(E, "Error: TLV data is too large for APDU!");
  }
  uint8_t p1 = type == kAliro ? 0x00 : flags[0];
  uint8_t p2 = type == kAliro ? 0x00 : flags[1];
  std::vector<uint8_t> apdu{0x80, 0x80, p1, p2, static_cast<uint8_t>(fastTlv.size())};

  apdu.insert(apdu.end(), std::make_move_iterator(fastTlv.begin()), std::make_move_iterator(fastTlv.end()));
  std::vector<uint8_t> response;
  LOG(D, "Auth0 APDU Length: %d, DATA: %s", apdu.size(), fmt::format("{:02X}", fmt::join(apdu, "")).c_str());
  nfc(apdu, response, false);
#if defined(CONFIG_IDF_CMAKE)
  ESP_LOG_BUFFER_HEX_LEVEL(TAG, response.data(), response.size(), ESP_LOG_VERBOSE);
#else
  for (int i = 0; i < response.size(); i++) {
    printf("%02X", response[i]);
  }
#endif
  LOG(D, "Auth0 Response Length: %d, DATA: %s", response.size(), fmt::format("{:02X}", fmt::join(response, "")).c_str());
  if (response.size() > 64 && response[0] == 0x86) {
    DDKAuthParams auth_params{
      type,
      readerData.issuers,
      readerData.reader_pk_x,
      readerEphX,
      endpointEphPubKey,
      endpointEphX,
      transactionIdentifier,
      readerIdentifier,
      aliroFCI,
      protocolVersion,
      nfc,
      nullptr,
      nullptr,
      nullptr,
      flags,
      nullptr
    };
    TLV8 Auth0Res;
    Auth0Res.parse(response.data(), response.size());
    tlv_it pubkey = Auth0Res.find(kEndpoint_Public_Key);
    endpointEphPubKey = pubkey->value;
    endpointEphX = CommonCryptoUtils::get_x(endpointEphPubKey);
    hkIssuer_t *foundIssuer = nullptr;
    hkEndpoint_t *foundEndpoint = nullptr;
    KeyFlow flowUsed = kFlowFailed;
    if (hkFlow == kFlowFAST) {
      tlv_it crypt = Auth0Res.find(kAuth0_Cryptogram);
      std::vector<uint8_t> encryptedMessage = crypt->value;
      auto fastAuth = DDKFastAuth(auth_params).attest(encryptedMessage);
      if (std::get<1>(fastAuth) != nullptr && (flowUsed = std::get<2>(fastAuth)) == kFlowFAST)
      {
        foundIssuer = std::get<0>(fastAuth);
        foundEndpoint = std::get<1>(fastAuth);
        LOG(D, "Endpoint %s Authenticated via FAST Flow", fmt::format("{:02X}", fmt::join(foundEndpoint->endpoint_id, "")).c_str());
      }
    }
    if(foundEndpoint == nullptr){
      std::array<uint8_t,32> persistentKey{};
      auth_params.reader_private_key = &readerData.reader_sk;
      auth_params.readerEphPrivKey = &readerEphPrivKey;
      auto stdAuth = DDKStdAuth(auth_params).attest();
      if(std::get<1>(stdAuth) != nullptr){
        foundIssuer = std::get<0>(stdAuth);
        foundEndpoint = std::get<1>(stdAuth);
        if ((flowUsed = std::get<4>(stdAuth)) == kFlowSTANDARD)
        {
          LOG(D, "Endpoint %s Authenticated via STANDARD Flow", fmt::format("{:02X}", fmt::join(foundEndpoint->endpoint_id, "")).c_str());
          persistentKey = std::get<3>(stdAuth);
          foundEndpoint->endpoint_prst_k.clear();
          foundEndpoint->endpoint_prst_k.insert(foundEndpoint->endpoint_prst_k.begin(), persistentKey.begin(), persistentKey.end());
          LOG(V, "New Persistent Key: %s", fmt::format("{:02X}", fmt::join(foundEndpoint->endpoint_prst_k, "")).c_str());
        }
      }
      if ((std::get<4>(stdAuth) == kFlowNext || hkFlow == kFlowATTESTATION) && type != kAliro) {
        auth_params.context = std::get<2>(stdAuth).get();
        auto attestation = DDKAttestationAuth(auth_params).attest();
        if ((flowUsed = std::get<KeyFlow>(attestation)) == kFlowATTESTATION) {
          hkEndpoint_t endpoint;
          foundIssuer = std::get<0>(attestation);
          std::vector<uint8_t> devicePubKey = std::get<1>(attestation);
          std::vector<uint8_t> deviceKeyX = CommonCryptoUtils::get_x(std::get<1>(attestation));
          endpoint.endpoint_pk_x = deviceKeyX;
          std::vector<uint8_t> eId = getHashIdentifier(devicePubKey);
          endpoint.endpoint_id = std::vector<uint8_t>{eId.begin(), eId.begin() + 6};
          endpoint.endpoint_pk = devicePubKey;
          LOG(I, "ATTESTATION Flow complete, transaction took %lli ms", std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - startTime).count());
          LOG(D, "Endpoint %s Authenticated via ATTESTATION Flow", fmt::format("{:02X}", fmt::join(endpoint.endpoint_id, "")).c_str());
          persistentKey = std::get<3>(stdAuth);
          endpoint.endpoint_prst_k.clear();
          endpoint.endpoint_prst_k.insert(endpoint.endpoint_prst_k.begin(), persistentKey.begin(), persistentKey.end());
          LOG(V, "New Persistent Key: %s", fmt::format("{:02X}", fmt::join(endpoint.endpoint_prst_k, "")).c_str());
          foundEndpoint = &(*foundIssuer->endpoints.emplace(foundIssuer->endpoints.end(),endpoint));
        }
      }
      if(flowUsed >= kFlowSTANDARD){
        save_cb(readerData);
      }
    }
    if(foundIssuer != nullptr && foundEndpoint != nullptr && flowUsed != kFlowFailed) {
      std::vector<uint8_t> cmdFlowStatus;
      if (flowUsed < kFlowATTESTATION)
      {
        cmdFlowStatus = commandFlow(kCmdFlowSuccess);
        LOG(D, "CONTROL FLOW RESPONSE: %s, Length: %d", fmt::format("{:02X}", fmt::join(cmdFlowStatus, "")).c_str(), cmdFlowStatus.size());
      }
      if (flowUsed == kFlowATTESTATION || cmdFlowStatus[0] == 0x90)
      {
        LOG(I, "Endpoint authenticated, transaction took %lli ms", std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - startTime).count());
        return std::make_tuple(foundIssuer->issuer_id, foundEndpoint->endpoint_id, flowUsed);
      } else {
        LOG(E, "Control Flow Response not 0x90!, %s", fmt::format("{:02X}", fmt::join(cmdFlowStatus, "")).c_str());
        return std::make_tuple(foundIssuer->issuer_id, foundEndpoint->endpoint_id, kFlowFailed);
      }
    } else commandFlow(kCmdFlowFailed);
  }
  commandFlow(kCmdFlowFailed);
  LOG(E, "Response not valid, something went wrong!");
  return std::make_tuple(std::vector<uint8_t>(), std::vector<uint8_t>(), kFlowFailed);
}
