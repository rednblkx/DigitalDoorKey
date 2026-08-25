#include "HomeKeyKeySchedule.h"
#include "AliroKeySchedule.h"
#include "FastAuth.h"
#include "AuthResults.hpp"
#include "ddk/store/ReaderIdentity.h"
#include "DDKLogging.h"
#include "TLV8.hpp"
#include "CommonCryptoUtils.h"
#include <vector>

std::tuple<ddk::Issuer *, ddk::Endpoint *>
DDKFastAuth::find_endpoint_by_cryptogram(std::vector<uint8_t> &cryptogram)
{
  ddk::Endpoint *foundEndpoint = nullptr;
  ddk::Issuer *foundIssuer = nullptr;
  constexpr size_t kHomeKeyCryptogramLength = 16;

  if (params.type == kHomeKey && cryptogram.size() != kHomeKeyCryptogramLength) {
    LOG(W, "Invalid Home Key cryptogram length: %zu", cryptogram.size());
    return std::make_tuple(foundIssuer, foundEndpoint);
  }

  // --- HomeKey FAST ---
  if (params.type == kHomeKey) {
    HomeKeyKeySchedule schedule;   // stateless, zero-cost
    HomeKeyKeySchedule::SessionInput input{
      params.store.reader_identity().public_key_x,
      params.readerIdentifier,
      params.readerEphX,
      params.endpointEphX,
      params.transactionIdentifier,
      params.version,
      params.flags,
    };
    for (auto &&issuer : params.store.issuers()) {
      for (auto &&endpoint : issuer.endpoints) {
        if (endpoint.persistent_key.empty()) continue;
        auto okm = schedule.derive_fast_material(
            input, endpoint.public_key_x, endpoint.persistent_key);
        LOG_HEX(V, "HKDF Derived Key", okm);
        if (CommonCryptoUtils::constant_time_compare(okm.data(), cryptogram.data(), 16)) {
          LOG(D, "Endpoint %s matches cryptogram",
              redactHex("", endpoint.id.data(), endpoint.id.size()).c_str());
          foundIssuer = &issuer;
          foundEndpoint = &endpoint;
          break;
        }
      }
      if (foundEndpoint) break;
    }
  }

  // --- Aliro FAST ---
  if (params.type == kAliro) {
    AliroKeySchedule schedule;
    AliroKeySchedule::SessionInput input{
      params.store.reader_identity().public_key_x,
      params.readerIdentifier,
      params.readerEphX,
      params.endpointEphX,
      params.transactionIdentifier,
      params.version,
      params.flags,
      params.aliroFCI,
      0x5E,    // interface — verify against aliro/interface.py
      {},      // auth0_info_suffix (vendor extensions, empty)
    };
    for (auto &&issuer : params.store.issuers()) {
      for (auto &&endpoint : issuer.endpoints) {
        if (endpoint.persistent_key.empty()) continue;
        auto result = schedule.derive_fast(
            input, endpoint.public_key_x, endpoint.persistent_key);
        std::array<uint8_t,32> sk{};
        std::copy_n(result.cryptogram_sk.data(), 32, sk.data());
        auto plaintext = CommonCryptoUtils::decryptAesGcm(
            cryptogram, sk, {0,0,0,0,0,0,0,0,0,0,0,0});
        if (!plaintext.empty()) {
          LOG_HEX(D, "Decrypted Cryptogram", plaintext);
          TLV8 decryptedTlv;
          decryptedTlv.parse(plaintext.data(), plaintext.size());
          auto idItem = decryptedTlv.expect(0x5E);
          auto issuedAtItem = decryptedTlv.expect(0x91);
          auto expiresAtItem = decryptedTlv.expect(0x92);
          if (idItem && issuedAtItem && expiresAtItem) {
            foundIssuer = &issuer;
            foundEndpoint = &endpoint;
            break;
          }
        }
      }
      if (foundEndpoint) break;
    }
  }

  return std::make_tuple(foundIssuer, foundEndpoint);
}

/**
 * The function `attest` in the `DDKFastAuth` class performs authentication using FAST Flow and returns
 * the issuer, endpoint, and key flow type based on the encrypted message provided.
 * 
 * @param encryptedMessage The `attest` function takes a vector of uint8_t named `encryptedMessage` as
 * input. This function processes the encrypted message to authenticate an endpoint using the FAST
 * flow. If the endpoint is successfully authenticated, it returns a tuple containing the issuer
 * pointer, endpoint pointer, and the KeyFlow type
 * 
 * @return A tuple containing a pointer to the issuer, a pointer to the endpoint, and the KeyFlow type
 * is being returned. The function first checks if the endpoint is authenticated via FAST Flow, and if
 * so, it logs the authentication and returns the tuple with the FAST flow type. If the authentication
 * fails, it logs the failure and returns the tuple with the STANDARD flow type.
 */
FastAuthResult DDKFastAuth::attest(std::vector<uint8_t> &encryptedMessage)
{
  auto foundData = find_endpoint_by_cryptogram(encryptedMessage);
  FastAuthResult result;
  if (std::get<1>(foundData) != nullptr)
  {
    LOG(D, "Endpoint %s Authenticated via FAST Flow", redactHex("", std::get<1>(foundData)->id.data(), std::get<1>(foundData)->id.size()).c_str());
    result.issuer = std::get<ddk::Issuer *>(foundData);
    result.endpoint = std::get<ddk::Endpoint*>(foundData);
    result.flow = kFlowFAST;
    return result;
  }
  LOG(W, "FAST Flow failed! Moving to STANDARD Flow!");
  result.flow = kFlowNext;
  return result;
}

DDKFastAuth::DDKFastAuth(DDKAuthParams &params) : params(params) {
}
