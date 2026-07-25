#include "FastAuth.h"
#include "AuthResults.hpp"
#include "DDKLogging.h"
#include <mbedtls/hkdf.h>
#include <vector>

#include "TLV8.hpp"
#include "CommonCryptoUtils.h"

/**
 * The function `Auth0_keying_material` generates keying material using the HKDF algorithm based on
 * various input parameters.
 *
 * @param context The `context` parameter is a pointer to a character array that represents the context
 * for the keying material generation. It is used as input to the HKDF (HMAC-based Key Derivation
 * Function) algorithm.
 * @param ePubX ePub_X is a pointer to a uint8_t array that represents the public key of the entity
 * being authenticated. It has a length of 32 bytes.
 * @param keyingMaterial The `keyingMaterial` parameter is a pointer to a buffer where the input keying material to be used with HKDF is stored.
 * It should have a size of at least 32 bytes.
 * @param out The `out` parameter is a pointer to the buffer where the output keying material will be
 * stored. The size of the buffer is specified by the `outLen` parameter.
 * @param outLen The parameter `outLen` represents the length of the output buffer `out`. It specifies
 * the maximum number of bytes that can be written to the `out` buffer.
 */
void DDKFastAuth::Auth0_keying_material(const char *context, const std::vector<uint8_t> &ePubX, const std::vector<uint8_t> &keyingMaterial, uint8_t *out, size_t outLen)
{
  uint8_t sel_version_tlv[4] = {0x5c, 0x02, params.version[0], params.version[1]};
  constexpr uint8_t hk_versions[6] = {0x5c, 0x04, 0x02, 0x0, 0x01, 0x0};
  std::vector<uint8_t> dataMaterial;
  dataMaterial.reserve(32 + strlen(context) + params.readerIdentifier.size() + 32 + 1 + sizeof(hk_versions) + sizeof(sel_version_tlv) + params.readerEphX.size() + 16 + 2 + params.endpointEphX.size());
  dataMaterial.insert(dataMaterial.end(), std::make_move_iterator(params.reader_pk_x.begin()), std::make_move_iterator(params.reader_pk_x.end()));
  dataMaterial.insert(dataMaterial.end(), (uint8_t *)context, (uint8_t*)context + strlen(context));
  dataMaterial.insert(dataMaterial.end(), std::make_move_iterator(params.readerIdentifier.begin()), std::make_move_iterator(params.readerIdentifier.end()));
  if (params.type == kHomeKey) {
    dataMaterial.insert(dataMaterial.end(), std::make_move_iterator(ePubX.begin()), std::make_move_iterator(ePubX.end()));
  }
  dataMaterial.push_back(0x5E);
  if (params.type == kHomeKey) {
    dataMaterial.insert(dataMaterial.end(), hk_versions, hk_versions + sizeof(hk_versions));
  }
  dataMaterial.insert(dataMaterial.end(), sel_version_tlv, sel_version_tlv + sizeof(sel_version_tlv));
  dataMaterial.insert(dataMaterial.end(), std::make_move_iterator(params.readerEphX.begin()), std::make_move_iterator(params.readerEphX.end()));
  dataMaterial.insert(dataMaterial.end(), std::make_move_iterator(params.transactionIdentifier.begin()), std::make_move_iterator(params.transactionIdentifier.end()));
  dataMaterial.push_back(params.flags[0]);
  dataMaterial.push_back(params.flags[1]);
  if (params.type == kAliro) {
    dataMaterial.push_back(0xA5);
    dataMaterial.push_back(static_cast<uint8_t>(params.aliroFCI.size()));
    dataMaterial.insert(dataMaterial.end(), params.aliroFCI.begin(), params.aliroFCI.end());
    dataMaterial.insert(dataMaterial.end(), ePubX.begin(), ePubX.end());
  }
  if (params.type == kHomeKey) {
    dataMaterial.insert(dataMaterial.end(), std::make_move_iterator(params.endpointEphX.begin()), std::make_move_iterator(params.endpointEphX.end()));
  }
  LOG_HEX(D, "Auth0 HKDF Material", dataMaterial);
  int ret = 0;
  if (params.type == kHomeKey) {
    ret = mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), NULL, 0, keyingMaterial.data(),
                       keyingMaterial.size(), dataMaterial.data(), dataMaterial.size(), out, outLen);
  } else if (params.type == kAliro) {
    ret = mbedtls_hkdf(
      mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
      dataMaterial.data(), dataMaterial.size(),
      keyingMaterial.data(), keyingMaterial.size(),
      params.endpointEphX.data(), params.endpointEphX.size(),
      out, outLen
    );
  }
  LOG(V, "HKDF Status: %d", ret);
}

/**
 * The function `find_endpoint_by_cryptogram` searches for an endpoint in a list of issuers based on a
 * given cryptogram.
 *
 * @param cryptogram The parameter "cryptogram" is a vector of uint8_t, which represents the cryptogram received in the Auth0 response.
 *
 * @return a pointer to an object of type `hkEndpoint_t`.
 */
std::tuple<hkIssuer_t *, hkEndpoint_t *> DDKFastAuth::find_endpoint_by_cryptogram(std::vector<uint8_t> &cryptogram)
{
  hkEndpoint_t *foundEndpoint = nullptr;
  hkIssuer_t *foundIssuer = nullptr;
  for (auto &&issuer : params.issuers)
  {
    LOG(V, "Issuer: %s, Endpoints: %d", redactHex("", issuer.issuer_id.data(), issuer.issuer_id.size()).c_str(), issuer.endpoints.size());
    for (auto &&endpoint : issuer.endpoints)
    {
      if(endpoint.endpoint_prst_k.size() == 0) continue;
      LOG(V, "Endpoint: %s, Persistent Key: %s", redactHex("", endpoint.endpoint_id.data(), endpoint.endpoint_id.size()).c_str(), redactHex("PK", endpoint.endpoint_prst_k.data(), endpoint.endpoint_prst_k.size()).c_str());
      std::vector<uint8_t> hkdf(params.type == kHomeKey ? 58 : 160);
      Auth0_keying_material("VolatileFast", endpoint.endpoint_pk_x, endpoint.endpoint_prst_k, hkdf.data(), hkdf.size());
      LOG_HEX(V, "HKDF Derived Key", hkdf);
      if (params.type == kAliro) {
        std::array<uint8_t,32> sk{};
        std::copy_n(hkdf.data(), 32, sk.data());
        LOG_HEX(D, "SK", sk);
        auto plaintext = CommonCryptoUtils::decryptAesGcm(cryptogram, sk, {0,0,0,0,0,0,0,0,0,0,0,0});
        if (!plaintext.empty()) {
          LOG_HEX(D, "Decrypted Cryptogram", plaintext);
          TLV8 decryptedTlv;
          decryptedTlv.parse(plaintext.data(), plaintext.size());
          auto idItem = decryptedTlv.expect(0x5E);
          auto issuedAtItem = decryptedTlv.expect(0x91);
          auto expiresAtItem = decryptedTlv.expect(0x92);
          if (idItem && issuedAtItem && expiresAtItem) {
            LOG(D, "Identifier: %s", redactHex("", idItem->value.data(), idItem->value.size()).c_str());
            LOG(D, "issued_at: %s", redactHex("", issuedAtItem->value.data(), issuedAtItem->value.size()).c_str());
            LOG(D, "expires_at: %s", redactHex("", expiresAtItem->value.data(), expiresAtItem->value.size()).c_str());
            foundIssuer = &issuer;
            foundEndpoint = &endpoint;
            break;
          } else {
            LOG(E, "Could not validate endpoint!");
            continue;
          }
        }
      }
      if (params.type == kHomeKey) {
        if (CommonCryptoUtils::constant_time_compare(hkdf.data(), cryptogram.data(), 16))
        {
          LOG(D, "Endpoint %s matches cryptogram", redactHex("", endpoint.endpoint_id.data(), endpoint.endpoint_id.size()).c_str());
          foundIssuer = &issuer;
          foundEndpoint = &endpoint;
          break;
        }
      }
    }
    if (foundEndpoint != nullptr)
    {
      break;
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
    LOG(D, "Endpoint %s Authenticated via FAST Flow", redactHex("", std::get<1>(foundData)->endpoint_id.data(), std::get<1>(foundData)->endpoint_id.size()).c_str());
    result.issuer = std::get<hkIssuer_t *>(foundData);
    result.endpoint = std::get<hkEndpoint_t*>(foundData);
    result.flow = kFlowFAST;
    return result;
  }
  LOG(W, "FAST Flow failed! Moving to STANDARD Flow!");
  result.flow = kFlowNext;
  return result;
}

DDKFastAuth::DDKFastAuth(DDKAuthParams &params) : params(params) {
}
