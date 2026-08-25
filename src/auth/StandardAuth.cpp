#include "StandardAuth.h"
#include "ddk/store/ReaderIdentity.h"
#include "AuthResults.hpp"
#include "CommonCryptoUtils.h"
#include "ScbSecureChannel.h"
#include "GcmSecureChannel.h"
#include "DDKReaderData.h"
#include "ddk/transport/ApduChannel.h"
#include "simple_tlv.hpp"
#include "x963kdf.h"
#include "DDKLogging.h"
#include "HomeKeyKeySchedule.h"
#include "AliroKeySchedule.h"
#include <iterator>
#include <memory>
#include <mbedtls/ecp.h>
#include <mbedtls/bignum.h>
#include <mbedtls/ecdsa.h>
#include <TLV8.hpp>
#include <vector>

DDKStdAuth::DDKStdAuth(DDKAuthParams &params) : params(params) {
}

/**
 * Performs authentication using the STANDARD flow.
 *
 * @return a tuple containing the following elements:
 * 1. A pointer to the issuer object (`hkIssuer_t*`)
 * 2. A pointer to the endpoint object (`hkEndpoint_t*`)
 * 3. An smart pointer of type `ScbSecureChannel`
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

  std::vector<uint8_t> sigPoint = CommonCryptoUtils::signSharedInfo(stdTlv.data(), stdTlv.size(), params.store.reader_identity().private_key.data(), params.store.reader_identity().private_key.size());
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
  LOG(D, "%s", redactHex("Auth1 APDU", apdu).c_str());
  auto response = params.channel_->transceive(apdu);
  LOG(D, "%s", redactHex("Auth1 Response", response.data).c_str());
  uint8_t sharedKey[32];

  CommonCryptoUtils::get_shared_key(*params.readerEphPrivKey, params.endpointEphPubKey, sharedKey, sizeof(sharedKey));
  LOG_HEX(D, "Shared Key", sharedKey);

  X963KDF kdf(MBEDTLS_MD_SHA256, 32, params.transactionIdentifier.data(), 16);
  std::array<uint8_t,32> derivedKey{};
  kdf.derive(sharedKey, sizeof(sharedKey), derivedKey.data());
  LOG_HEX(D, "X963KDF Derived Key", derivedKey);

  std::array<uint8_t,32> persistentKey{};
  std::vector<uint8_t> volatileKey;
  std::array<uint8_t,32> skDevice{};
  std::array<uint8_t,32> skReader{};

  if (params.type == kHomeKey) {
    HomeKeyKeySchedule schedule;
    HomeKeyKeySchedule::SessionInput input{
      params.store.reader_identity().public_key_x,
      params.readerIdentifier,
      params.readerEphX,
      params.endpointEphX,
      params.transactionIdentifier,
      params.version,
      params.flags,
    };
    auto ks = schedule.derive_standard(input, derivedKey);
    persistentKey = ks.persistent_key;
    volatileKey = std::move(ks.volatile_key);
  }

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
      0x5E,
      {},
    };
    auto vol = schedule.derive_volatile(input, derivedKey);
    skReader = vol.exchange_sk_reader;
    skDevice = vol.exchange_sk_device;
    // persistentKey stays zero-initialized — derived after signature verify
  }

  LOG_HEX(D, "Persistent Key", persistentKey);
  LOG_HEX(D, "Volatile Key", volatileKey);
  std::unique_ptr<ScbSecureChannel> scb_context;
  ddk::Endpoint *foundEndpoint = nullptr;
  ddk::Issuer *foundIssuer = nullptr;
  StandardAuthResult result;
  constexpr size_t standard_min_secure_response_size = 16 + 8;
  constexpr size_t aliro_min_secure_response_size = 16;
  const size_t min_secure_response_size =
      params.type == kHomeKey ? standard_min_secure_response_size : aliro_min_secure_response_size;
  if (response.data.size() >= min_secure_response_size &&
      response.ok())
  {
    std::vector<uint8_t> response_result;
    if (params.type == kHomeKey) {
        scb_context = std::make_unique<ScbSecureChannel>(volatileKey);
        response_result = scb_context->decrypt_response(response.data.data(), response.data.size());
    } else {
        GcmSecureChannel gcm(skReader, skDevice);
        response_result = gcm.decrypt_endpoint_data(response.data);
    }
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
            LOG_HEX(D, "Device Identifier", device_identifier);
            LOG_HEX(D, "Signature", signature);
            if (device_identifier.empty())
            {
              LOG(E, "TLV DATA INVALID!");
              goto err;
            }
            for (auto &&issuer : params.store.issuers())
            {
              for (auto &&endpoint : issuer.endpoints)
              {
                if (std::equal(endpoint.id.begin(), endpoint.id.end(), device_identifier.begin()))
                {
                  LOG(D, "STD_AUTH: Found Matching Endpoint, ID: %s", redactHex("", endpoint.id.data(), endpoint.id.size()).c_str());
                  foundEndpoint = &endpoint;
                  foundIssuer = &issuer;
                }
              }
            }
          }
        }
        if (params.type == kAliro) {
          if (auto pkItem = decryptedTlv.expect(0x5A)) {
            std::vector<uint8_t> devicePk = pkItem->value;
            for (auto &issuer: params.store.issuers()) {
              for (auto &endpoint: issuer.endpoints) {
                if (devicePk.size() >= endpoint.public_key.size() && memcmp(devicePk.data(), endpoint.public_key.data(), endpoint.public_key.size()) == 0) {
                  foundIssuer = &issuer;
                  foundEndpoint = &endpoint;
                  LOG(D, "Found matching endpoint with public key: %s",
                      redactHex("", devicePk.data(), devicePk.size()).c_str());
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

        LOG_HEX(D, "verification_hash_input_material", hash);
        CommonCryptoUtils::MpiGuard r,s;

        mbedtls_ecp_group_load(&keypair.kp.MBEDTLS_PRIVATE(grp), MBEDTLS_ECP_DP_SECP256R1);
        int pubImport = mbedtls_ecp_point_read_binary(&keypair.kp.MBEDTLS_PRIVATE(grp), &keypair.kp.MBEDTLS_PRIVATE(Q), foundEndpoint->public_key.data(), foundEndpoint->public_key.size());
        LOG(V, "public key import result: %d", pubImport);

        mbedtls_mpi_read_binary(r, signature.data(), signature.size() / 2);
        mbedtls_mpi_read_binary(s, signature.data() + (signature.size() / 2), signature.size() / 2);

        int signature_result = mbedtls_ecdsa_verify(&keypair.kp.MBEDTLS_PRIVATE(grp), hash, 32, &keypair.kp.MBEDTLS_PRIVATE(Q), r, s);

        LOG(V, "signature verification result: %d", signature_result);

        if (signature_result == 0)
        {
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
              0x5E,
              {},
            };
            persistentKey = schedule.derive_persistent(
                input, derivedKey, foundEndpoint->public_key_x);
          }
          // HomeKey persistent was already derived above — nothing to do here

          result.issuer = foundIssuer;
          result.endpoint = foundEndpoint;
          result.scb_context = std::move(scb_context);
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
      result.scb_context = std::move(scb_context);
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
  result.scb_context = std::move(scb_context);
  result.shared_secret = persistentKey;
  return result;
}
