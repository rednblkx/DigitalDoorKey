#include "StandardAuth.h"
#include "AuthResults.hpp"
#include "CommonCryptoUtils.h"
#include "DigitalKeySecureContext.h"
#include "DDKReaderData.h"
#include "fmt/ranges.h"
#include "x963kdf.h"
#include "logging.h"
#include "simple_tlv.hpp"
#include <iterator>
#include <memory>
#include <mbedtls/hkdf.h>
#include <mbedtls/ecp.h>
#include <mbedtls/bignum.h>
#include <TLV8.hpp>
#include <mbedtls/ecdsa.h>
#include <tuple>
#include <vector>

constexpr char ALIRO_CTX_PERSISTENT_ASTR[] = "Persistent**";
constexpr char HK_CTX_PERSISTENT_ASTR[] = "Persistent";
constexpr char ALIRO_CTX_VOLATILE_ASTR[] = "Volatile****";
constexpr char HK_CTX_VOLATILE_ASTR[] = "Volatile";

/**
 * The function `Auth1_keying_material` generates keying material using various input data and the HKDF
 * algorithm.
 *
 * @param keyingMaterial A pointer to the buffer where the generated keying material will be stored.
 * @param context The "context" parameter is a string that represents the context or additional
 * information for the authentication process. It is used as input to generate the keying material.
 * @param out The `out` parameter is a pointer to a buffer where the generated keying material will be
 * stored. The size of this buffer is specified by the `outLen` parameter.
 * @param outLen The parameter `outLen` represents the length of the output buffer `out` where the
 * generated keying material will be stored.
 */
template<typename Container>
void DDKStdAuth::Auth1_keying_material(std::array<uint8_t,32> &keyingMaterial, std::string_view context, Container &out)
{
  std::vector<uint8_t> dataMaterial;
  if (params.type == kHomeKey) {
    uint8_t supported_vers[6] = {0x5c, 0x04, 0x02, 0x0, 0x01, 0x0};
    dataMaterial.reserve(params.readerEphX.size() + params.endpointEphX.size() + params.transactionIdentifier.size() + 1 + params.flags.size() + context.size() + params.version.size() + sizeof(supported_vers));
    dataMaterial.insert(dataMaterial.end(), std::make_move_iterator(params.readerEphX.begin()), std::make_move_iterator(params.readerEphX.end()));
    dataMaterial.insert(dataMaterial.end(), std::make_move_iterator(params.endpointEphX.begin()), std::make_move_iterator(params.endpointEphX.end()));
    dataMaterial.insert(dataMaterial.end(), std::make_move_iterator(params.transactionIdentifier.begin()), std::make_move_iterator(params.transactionIdentifier.end()));
    dataMaterial.push_back(0x5E);
    dataMaterial.push_back(params.flags[0]);
    dataMaterial.push_back(params.flags[1]);
    dataMaterial.insert(dataMaterial.end(), (uint8_t*)context.begin(), (uint8_t*)context.end());
    dataMaterial.push_back(0x5C);
    dataMaterial.push_back(static_cast<uint8_t>(params.version.size()));
    dataMaterial.insert(dataMaterial.end(), params.version.begin(), params.version.end());
    dataMaterial.insert(dataMaterial.end(), supported_vers, supported_vers + sizeof(supported_vers));
    LOG(D, "%s", redactHex("DATA Material", dataMaterial).c_str());
    mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), NULL, 0, keyingMaterial.data(), 32, dataMaterial.data(), dataMaterial.size(), out.data(), out.size());
  }
  if (params.type == kAliro) {
    dataMaterial.reserve(params.reader_pk_x.size() + context.size() + params.readerIdentifier.size() + params.version.size() + params.readerEphX.size() + params.transactionIdentifier.size() + params.aliroFCI.size());
    LOG(I, "%s", redactHex("readerPublicKeyX", params.reader_pk_x).c_str());
    dataMaterial.insert(dataMaterial.end(), params.reader_pk_x.begin(), params.reader_pk_x.end());

    LOG(I, "context: %s", context.data());
    dataMaterial.insert(dataMaterial.end(), context.begin(), context.end());

    LOG(I, "%s", redactHex("readerIdentifier", params.readerIdentifier).c_str());
    dataMaterial.insert(dataMaterial.end(), params.readerIdentifier.begin(), params.readerIdentifier.end());

    LOG(I, "transport_type: 0x%02X", 0x5E);
    dataMaterial.push_back(0x5E);

    LOG(I, "protocol_version TLV: 5C %02X %02X%02X", params.version.size(),
        params.version[0], params.version[1]);
    dataMaterial.push_back(0x5C);
    dataMaterial.push_back(params.version.size());
    dataMaterial.insert(dataMaterial.end(), params.version.begin(), params.version.end());

    LOG(I, "%s", redactHex("readerEphX", params.readerEphX).c_str());
    dataMaterial.insert(dataMaterial.end(), params.readerEphX.begin(), params.readerEphX.end());

    LOG(I, "%s", redactHex("transactionIdentifier", params.transactionIdentifier).c_str());
    dataMaterial.insert(dataMaterial.end(), params.transactionIdentifier.begin(), params.transactionIdentifier.end());

    LOG(I, "transaction_flags: 0x01, transaction_code: 0x01");
    dataMaterial.push_back(params.flags[0]);
    dataMaterial.push_back(params.flags[1]);

    LOG(I, "%s", redactHex("fciProprietaryTemplate", params.aliroFCI).c_str());
    dataMaterial.push_back(0xA5);
    dataMaterial.push_back(static_cast<uint8_t>(params.aliroFCI.size()));
    dataMaterial.insert(dataMaterial.end(), params.aliroFCI.begin(), params.aliroFCI.end());

    if (context == ALIRO_CTX_PERSISTENT_ASTR) {
        LOG(I, "%s", redactHex("ep_pk", *epPkX).c_str());
        dataMaterial.insert(dataMaterial.end(), epPkX->begin(), epPkX->end());
    }
    LOG(I, "%s", redactHex("HKDF Salt", dataMaterial).c_str());
    mbedtls_hkdf(
      mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
      dataMaterial.data(), dataMaterial.size(),
      keyingMaterial.data(), 32,
      params.endpointEphX.data(), params.endpointEphX.size(),
      out.data(), out.size()
    );
  }
}

DDKStdAuth::DDKStdAuth(DDKAuthParams &params) : params(params) {
}

/**
 * Performs authentication using the STANDARD flow.
 *
 * @return a tuple containing the following elements:
 * 1. A pointer to the issuer object (`hkIssuer_t*`)
 * 2. A pointer to the endpoint object (`hkEndpoint_t*`)
 * 3. An smart pointer of type `DigitalKeySecureContext`
 * 4. A 32 byte array containing the derived persistent key
 * 5. An enum value of type `KeyFlow`
 */
StandardAuthResult DDKStdAuth::attest()
{
  // int readerContext = 1096652137;
  std::array<uint8_t,4> readerCtx{0x41, 0x5d, 0x95, 0x69};
  // int deviceContext = 1317567308;
  std::array<uint8_t,4> deviceCtx{0x4e, 0x88, 0x7b, 0x4c};

  std::vector<uint8_t> stdTlv;
  stdTlv.reserve(16 + params.endpointEphX.size() + params.readerEphX.size() + 30);
#if __cplusplus >= 202002L
  std::ranges::copy(simple_tlv(0x4D, params.readerIdentifier), std::back_inserter(stdTlv));
  std::ranges::copy(simple_tlv(0x86, params.endpointEphX), std::back_inserter(stdTlv));
  std::ranges::copy(simple_tlv(0x87, params.readerEphX), std::back_inserter(stdTlv));
  std::ranges::copy(simple_tlv(0x4C, params.transactionIdentifier), std::back_inserter(stdTlv));
  std::ranges::copy(simple_tlv(0x93, readerCtx), std::back_inserter(stdTlv));
#else
  auto tlv1 = simple_tlv(0x4D, params.readerIdentifier);
  std::copy(tlv1.begin(), tlv1.end(), std::back_inserter(stdTlv));
  auto tlv2 = simple_tlv(0x86, params.endpointEphX);
  std::copy(tlv2.begin(), tlv2.end(), std::back_inserter(stdTlv));
  auto tlv3 = simple_tlv(0x87, params.readerEphX);
  std::copy(tlv3.begin(), tlv3.end(), std::back_inserter(stdTlv));
  auto tlv4 = simple_tlv(0x4C, params.transactionIdentifier);
  std::copy(tlv4.begin(), tlv4.end(), std::back_inserter(stdTlv));
  auto tlv5 = simple_tlv(0x93, readerCtx);
  std::copy(tlv5.begin(), tlv5.end(), std::back_inserter(stdTlv));
#endif

  std::vector<uint8_t> sigPoint = CommonCryptoUtils::signSharedInfo(stdTlv.data(), stdTlv.size(), params.reader_private_key->data(), params.reader_private_key->size());
  std::vector<uint8_t> sigTlv = simple_tlv(0x9E, sigPoint);
  std::vector<uint8_t> apdu{0x80, 0x81, 0x0, 0x0};
  if (params.type == kHomeKey) {
    apdu.push_back(sigTlv.size());
    apdu.resize(apdu.size() + sigTlv.size());
    std::move(sigTlv.begin(), sigTlv.end(), apdu.begin() + 5);
  }
  if (params.type == kAliro) {
    apdu.push_back(sigTlv.size() + 3);
    apdu.push_back(0x41);
    apdu.push_back(0x01);
    apdu.push_back(0x01);
    apdu.resize(apdu.size() + sigTlv.size());
    std::move(sigTlv.begin(), sigTlv.end(), apdu.begin() + 8);
  }
  std::vector<uint8_t> response;
  LOG(D, "%s", redactHex("Auth1 APDU", apdu).c_str());
  params.nfc(apdu, response, false);
  LOG(D, "%s", redactHex("Auth1 Response", response).c_str());
  std::array<uint8_t,32> persistentKey{};
  std::vector<uint8_t> volatileKey(48);
  if (params.type == kAliro){ volatileKey.resize(160); }
  uint8_t sharedKey[32];

  CommonCryptoUtils::get_shared_key(*params.readerEphPrivKey, params.endpointEphPubKey, sharedKey, sizeof(sharedKey));
  LOG_HEX_FMT(D, "Shared Key", sharedKey);

  X963KDF kdf(MBEDTLS_MD_SHA256, 32, params.transactionIdentifier.data(), 16);

  std::array<uint8_t,32> derivedKey{};
  std::array<uint8_t,32> skDevice{};
  std::array<uint8_t,32> skReader{};
  kdf.derive(sharedKey, sizeof(sharedKey), derivedKey.data());
  LOG_HEX_FMT(D, "X963KDF Derived Key", derivedKey);
  if (params.type == kHomeKey) {
    Auth1_keying_material(derivedKey, HK_CTX_PERSISTENT_ASTR, persistentKey);
    Auth1_keying_material(derivedKey, HK_CTX_VOLATILE_ASTR, volatileKey);
  }
  if (params.type == kAliro) {
    Auth1_keying_material(derivedKey, ALIRO_CTX_VOLATILE_ASTR, volatileKey);
    std::memcpy(skReader.data(), volatileKey.data(), 32);
    std::memcpy(skDevice.data(), volatileKey.data() + 32, 32);

    // std::memcpy(step_up_material.data(), volatileKey.data() + 64, 32);
    // std::memcpy(ble_material.data(), volatileKey.data(), 32);
    // std::memcpy(ur_sk.data(), volatileKey.data() + 0x80, 32);
    // std::vector<uint8_t> saltInput(32, 0);
    // mbedtls_hkdf(
    //     mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
    //     saltInput.data(), saltInput.size(),
    //     step_up_material.data(), step_up_material.size(),
    //     reinterpret_cast<const unsigned char *>("SKReader"), 8,
    //     step_up_sk_reader.data(), step_up_sk_reader.size()
    //     );
    // mbedtls_hkdf(
    //     mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
    //     saltInput.data(), saltInput.size(),
    //     step_up_material.data(), step_up_material.size(),
    //     reinterpret_cast<const unsigned char *>("SKDevice"), 8,
    //     step_up_sk_device.data(), step_up_sk_device.size());
    // mbedtls_hkdf(
    //     mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
    //     saltInput.data(), saltInput.size(),
    //     ble_material.data(),ble_material.size(),
    //     reinterpret_cast<const unsigned char *>("BleSKReader"), 8,
    //     ble_sk_reader.data(), ble_sk_reader.size()
    //     );
    // mbedtls_hkdf(
    //     mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
    //     saltInput.data(), saltInput.size(),
    //     ble_material.data(),ble_material.size(),
    //     reinterpret_cast<const unsigned char *>("BleSKDevice"), 8,
    //     ble_sk_device.data(), ble_sk_device.size());

    LOG(D, "Exchange SK Reader - %s", redactHex("", skReader.data(), 32).c_str());
    LOG(I, "Exchange SK Device - %s", redactHex("", skDevice.data(), 32).c_str());
  }
  LOG_HEX_FMT(D, "Persistent Key", persistentKey);
  LOG_HEX_FMT(I, "Volatile Key", volatileKey);
  std::unique_ptr<DigitalKeySecureContext> context;
  if (params.type == kHomeKey) {
    context = std::make_unique<DigitalKeySecureContext>(volatileKey);
  }
  if (params.type == kAliro) {
    context = std::make_unique<DigitalKeySecureContext>(&skReader, &skDevice);
  }
  hkEndpoint_t *foundEndpoint = nullptr;
  hkIssuer_t *foundIssuer = nullptr;
  StandardAuthResult result;
  if (response.size() > 2 && response[response.size() - 2] == 0x90)
  {
    auto response_result = context->decrypt_response(response.data(), response.size() - 2);
    LOG(D, "%s", redactHex("Decrypted", response_result).c_str());
    if (!response_result.empty())
    {
      TLV8 decryptedTlv;
      decryptedTlv.parse(response_result.data(), response_result.size());
      auto item = decryptedTlv.expect(0x9E);
      std::vector<uint8_t> signature;
      if (item) {
        signature = item->value;
        if (params.type == kHomeKey) {
          if (auto idItem = decryptedTlv.expect(0x4E)) {
            std::vector<uint8_t> device_identifier = idItem->value;
            LOG_HEX_FMT(D, "Device Identifier", device_identifier);
            LOG_HEX_FMT(D, "Signature", signature);
            if (device_identifier.empty())
            {
              LOG(E, "TLV DATA INVALID!");
              goto err;
            }
            for (auto &&issuer : params.issuers)
            {
              for (auto &&endpoint : issuer.endpoints)
              {
                if (std::equal(endpoint.endpoint_id.begin(), endpoint.endpoint_id.end(), device_identifier.begin()))
                {
                  LOG(D, "STD_AUTH: Found Matching Endpoint, ID: %s", redactHex("", endpoint.endpoint_id.data(), endpoint.endpoint_id.size()).c_str());
                  foundEndpoint = &endpoint;
                  foundIssuer = &issuer;
                  epPkX = &endpoint.endpoint_pk_x;
                }
              }
            }
          }
        }
        if (params.type == kAliro) {
          if (auto pkItem = decryptedTlv.expect(0x5A)) {
            std::vector<uint8_t> devicePk = pkItem->value;
            for (auto &issuer: params.issuers) {
              for (auto &endpoint: issuer.endpoints) {
                if (devicePk.size() >= endpoint.endpoint_pk.size() && memcmp(devicePk.data(), endpoint.endpoint_pk.data(), endpoint.endpoint_pk.size()) == 0) {
                  foundIssuer = &issuer;
                  foundEndpoint = &endpoint;
                  LOG(I, "Found matching endpoint with public key: %s",
                      redactHex("", devicePk.data(), devicePk.size()).c_str());
                  epPkX = &endpoint.endpoint_pk_x;
                  break;
                }
              }
              if (foundEndpoint != nullptr) {
                break;
              }
            }
          }
        }
      }
      if (foundEndpoint != nullptr)
      {
        std::vector<uint8_t> verification_hash_input_material;
        verification_hash_input_material.reserve(params.readerIdentifier.size() + params.endpointEphX.size() + params.readerEphX.size() + 30);

#if __cplusplus >= 202002L
        std::ranges::copy(simple_tlv(0x4D, params.readerIdentifier), std::back_inserter(verification_hash_input_material));
        std::ranges::copy(simple_tlv(0x86, params.endpointEphX), std::back_inserter(verification_hash_input_material));
        std::ranges::copy(simple_tlv(0x87, params.readerEphX), std::back_inserter(verification_hash_input_material));
        std::ranges::copy(simple_tlv(0x4C, params.transactionIdentifier), std::back_inserter(verification_hash_input_material));
        std::ranges::copy(simple_tlv(0x93, deviceCtx), std::back_inserter(verification_hash_input_material));
#else
        auto vtlv1 = simple_tlv(0x4D, params.readerIdentifier);
        std::copy(vtlv1.begin(), vtlv1.end(), std::back_inserter(verification_hash_input_material));
        auto vtlv2 = simple_tlv(0x86, params.endpointEphX);
        std::copy(vtlv2.begin(), vtlv2.end(), std::back_inserter(verification_hash_input_material));
        auto vtlv3 = simple_tlv(0x87, params.readerEphX);
        std::copy(vtlv3.begin(), vtlv3.end(), std::back_inserter(verification_hash_input_material));
        auto vtlv4 = simple_tlv(0x4C, params.transactionIdentifier);
        std::copy(vtlv4.begin(), vtlv4.end(), std::back_inserter(verification_hash_input_material));
        auto vtlv5 = simple_tlv(0x93, deviceCtx);
        std::copy(vtlv5.begin(), vtlv5.end(), std::back_inserter(verification_hash_input_material));
#endif

        CommonCryptoUtils::EcpKeyPairGuard keypair;

        uint8_t hash[32];

        mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), verification_hash_input_material.data(), verification_hash_input_material.size(), hash);

        LOG_HEX_FMT(D, "verification_hash_input_material", hash);
        CommonCryptoUtils::MpiGuard r,s;

        mbedtls_ecp_group_load(&keypair.kp.MBEDTLS_PRIVATE(grp), MBEDTLS_ECP_DP_SECP256R1);
        int pubImport = mbedtls_ecp_point_read_binary(&keypair.kp.MBEDTLS_PRIVATE(grp), &keypair.kp.MBEDTLS_PRIVATE(Q), foundEndpoint->endpoint_pk.data(), foundEndpoint->endpoint_pk.size());
        LOG(V, "public key import result: %d", pubImport);

        mbedtls_mpi_read_binary(r, signature.data(), signature.size() / 2);
        mbedtls_mpi_read_binary(s, signature.data() + (signature.size() / 2), signature.size() / 2);

        int signature_result = mbedtls_ecdsa_verify(&keypair.kp.MBEDTLS_PRIVATE(grp), hash, 32, &keypair.kp.MBEDTLS_PRIVATE(Q), r, s);

        LOG(V, "signature verification result: %d", signature_result);

        if (signature_result == 0)
        {
          if (params.type == kAliro) {
            Auth1_keying_material(derivedKey, ALIRO_CTX_PERSISTENT_ASTR, persistentKey);
          }
          result.issuer = foundIssuer;
          result.endpoint = foundEndpoint;
          result.secure_context = std::move(context);
          result.shared_secret = persistentKey;
          result.flow = kFlowSTANDARD;
          return result;
        }
        LOG(W, "Signature failed verification! Will attempt EXCHANGE flow(last resort)!");
        goto next;
      }
      LOG(W, "Endpoint data missing! Will attempt EXCHANGE flow(last resort)!");
      next:
      result.issuer = foundIssuer;
      result.endpoint = foundEndpoint;
      result.secure_context = std::move(context);
      result.shared_secret = persistentKey;
      result.flow = kFlowNext;
      return result;
    }
    else
    {
      LOG(E, "Invalid Response! STANDARD Flow failed!");
      goto err;
    }
  }
  LOG(E, "Response Status not 0x90, something went wrong!");
err:
  result.issuer = foundIssuer;
  result.endpoint = foundEndpoint;
  result.secure_context = std::move(context);
  result.shared_secret = persistentKey;
  return result;
}
