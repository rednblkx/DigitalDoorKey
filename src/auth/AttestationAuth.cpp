#include "AttestationAuth.h"
#include "AuthResults.hpp"
#include "esp_log_buffer.h"
#include "esp_log_level.h"
#include "ndef.h"
#include "simple_tlv.hpp"
#include "TLV8.hpp"
#include "ISO18013SecureContext.h"
#include "CommonCryptoUtils.h"
#include "DDKLogging.h"
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#if defined(CONFIG_IDF_CMAKE)
#include <esp_random.h>
#else 
#include "sodium.h"
#endif
#include <mbedtls/sha256.h>
#include <mbedtls/error.h>
#include <cbor.h>
#include <vector>
#include "ddk/transport/ApduChannel.h"
#include "CoseSign1.h"

HKAttestationAuth::HKAttestationAuth(
    ddk::Session& session, ScbSecureChannel& scb)
  : session_(session), scb_(scb) {}

std::vector<unsigned char> HKAttestationAuth::attestation_salt(std::vector<unsigned char> &env1Data, std::vector<unsigned char> &readerCmd)
{
  TLV8 env1ResTlv;
  env1ResTlv.parse(env1Data.data(), env1Data.size());
  tlv_it tlvEnv1Ndef = env1ResTlv.find(kNDEF_MESSAGE);
  if (tlvEnv1Ndef == env1ResTlv.end()) {
    LOG(E, "Envelope 1 response is missing required NDEF message (0x53).");
    return std::vector<unsigned char>();
  }
  std::vector<uint8_t> env1Ndef = tlvEnv1Ndef->value;
  NDEFMessage ndefEnv1Ctx = NDEFMessage(env1Ndef.data(), env1Ndef.size());
  auto ndefEnv1Data = ndefEnv1Ctx.unpack();
  auto ndefEnv1Pack = ndefEnv1Ctx.pack();
  NDEFRecord* res_eng = ndefEnv1Ctx.findType("iso.org:18013:deviceengagement");
  if (res_eng == nullptr) {
    LOG(E, "Envelope 1 NDEF message is missing required device engagement record.");
    return std::vector<unsigned char>();
  }
  if (res_eng->data.size() <= 1) {
    LOG(E, "Device engagement record has an empty payload.");
    return std::vector<unsigned char>();
  }
  uint8_t buf[255];
  uint8_t devEngCbor[255];
  CborEncoder devEng;
  CborEncoder devEngArray;
  cbor_encoder_init(&devEng, devEngCbor, sizeof(devEngCbor), 0);
  cbor_encoder_create_array(&devEng, &devEngArray, 2);
  cbor_encode_tag(&devEngArray, CborEncodedCborTag);
  cbor_encode_byte_string(&devEngArray, res_eng->data.data(), res_eng->data.size() - 1);
  CborEncoder innerArray;
  cbor_encoder_create_array(&devEngArray, &innerArray, 2);
  cbor_encode_byte_string(&innerArray, env1Ndef.data(), env1Ndef.size());
  cbor_encode_byte_string(&innerArray, readerCmd.data(), readerCmd.size());
  cbor_encoder_close_container(&devEngArray, &innerArray);
  cbor_encoder_close_container(&devEng, &devEngArray);
  size_t devSize = cbor_encoder_get_buffer_size(&devEng, devEngCbor);
  LOG(D, "Device Engagement CBOR");
  CborEncoder root;
  cbor_encoder_init(&root, buf, sizeof(buf), 0);
  cbor_encode_tag(&root, CborEncodedCborTag);
  cbor_encode_byte_string(&root, devEngCbor, devSize);
  size_t rootSize = cbor_encoder_get_buffer_size(&root, buf);
  LOG(D, "NDEF CBOR");

  LOG_HEX(D, "CBOR MATERIAL DATA", std::vector(buf, buf + rootSize));

  std::vector<uint8_t> salt(32);
  int shaRet = mbedtls_sha256(buf, rootSize, salt.data(), false);

  if (shaRet != 0)
  {
      LOG(E, "SHA256 Failed - %d", shaRet);
      return std::vector<unsigned char>();
  }

  LOG_HEX(D, "ATTESTATION SALT", salt);

  return salt;
}

std::tuple<std::vector<uint8_t>, std::vector<uint8_t>> HKAttestationAuth::envelope1Cmd()
{
  std::vector<uint8_t> ctrlFlow = {0x80, 0x3c, 0x40, 0xa0};
  auto ctrlFlowRes = session_.apdu().transceive(ctrlFlow);
  if (!ctrlFlowRes.ok()) {
    return std::make_tuple(std::vector<uint8_t>(), std::vector<uint8_t>());
  }
  LOG(D, "CONTROL FLOW %02x %02x", ctrlFlowRes.sw1, ctrlFlowRes.sw2);
  // cla=0x00; ins=0xa4; p1=0x04; p2=0x00; lc=0x07(7); data=a0000008580102; le=0x00
  std::vector<uint8_t> data = {0x00, 0xA4, 0x04, 0x00, 0x07, 0xA0, 0x00, 0x00, 0x08, 0x58, 0x01, 0x02, 0x0};
  auto response = session_.apdu().transceive(data);
  if (!response.ok()) {
    return std::make_tuple(std::vector<uint8_t>(), std::vector<uint8_t>());
  }
  LOG(D, "SELECT %02x %02x", response.sw1, response.sw2);
  unsigned char payload[] = {0x15, 0x91, 0x02, 0x02, 0x63, 0x72, 0x01, 0x02, 0x51, 0x02, 0x11, 0x61, 0x63, 0x01, 0x03, 0x6e, 0x66, 0x63, 0x01, 0x0a, 0x6d, 0x64, 0x6f, 0x63, 0x72, 0x65, 0x61, 0x64, 0x65, 0x72};
  unsigned char payload1[] = {0x01};
  unsigned char payload2[] = {0xa2, 0x00, 0x63, 0x31, 0x2e, 0x30, 0x20, 0x81, 0x29};
  auto ndefMessage = NDEFMessage({NDEFRecord("", 0x01, "Hr", payload, sizeof(payload)),
                                  NDEFRecord("nfc", 0x04, "iso.org:18013:nfc", payload1, 1),
                                  NDEFRecord("mdocreader", 0x04, "iso.org:18013:readerengagement", payload2, sizeof(payload2))})
                        .pack();
  LOG(D, "%s", redactHex("NDEF CMD", ndefMessage).c_str());
  auto envelope1Tlv = simple_tlv(0x53, ndefMessage);
  std::vector<uint8_t> env1Apdu = {0x00, 0xc3, 0x00, 0x01, static_cast<uint8_t>(envelope1Tlv.size())};
  env1Apdu.reserve(envelope1Tlv.size() + 6);
  env1Apdu.insert(env1Apdu.end(), envelope1Tlv.begin(), envelope1Tlv.end());
  env1Apdu.push_back(0x0);
  LOG(D, "%s", redactHex("APDU CMD", env1Apdu).c_str());
  auto env1Res = session_.apdu().transceive(env1Apdu);
  if (!env1Res.ok()) {
    return std::make_tuple(std::vector<uint8_t>(), std::vector<uint8_t>());
  }
  LOG(D, "%s", redactHex("APDU RES", env1Res.data).c_str());
  return std::make_tuple(std::move(env1Res.data), ndefMessage);
}

std::vector<unsigned char> HKAttestationAuth::envelope2Cmd(std::vector<uint8_t> &salt)
{
  ISO18013SecureContext secureCtx = ISO18013SecureContext(attestation_exchange_common_secret, salt, 16);

  uint8_t doctype[150];
  CborEncoder docType;
  CborEncoder docMap;
  cbor_encoder_init(&docType, doctype, 150, 0);
  cbor_encoder_create_map(&docType, &docMap, 2);
  cbor_encode_text_stringz(&docMap, "docType");
  cbor_encode_text_stringz(&docMap, "com.apple.HomeKit.1.credential");
  cbor_encode_text_stringz(&docMap, "nameSpaces");
  CborEncoder namespaces;
  CborEncoder homeCred;
  cbor_encoder_create_map(&docMap, &namespaces, 1);
  cbor_encode_text_stringz(&namespaces, "com.apple.HomeKit");
  cbor_encoder_create_map(&namespaces, &homeCred, 1);
  cbor_encode_text_stringz(&homeCred, "credential_id");
  cbor_encode_boolean(&homeCred, false);
  cbor_encoder_close_container(&namespaces, &homeCred);
  cbor_encoder_close_container(&docMap, &namespaces);
  cbor_encoder_close_container(&docType, &docMap);

  LOG(V, "ENV2 CBOR");
  #if defined(CONFIG_IDF_CMAKE)
  ESP_LOG_BUFFER_HEX_LEVEL(TAG, doctype, cbor_encoder_get_buffer_size(&docType, doctype), ESP_LOG_VERBOSE);
  #else
  for (int i = 0; i < cbor_encoder_get_buffer_size(&docType, doctype); i++) {
    printf("%02X", doctype[i]);
  }
  #endif

  uint8_t docBuf[150];
  CborEncoder doc;
  cbor_encoder_init(&doc, docBuf, sizeof(docBuf), 0);
  CborEncoder docReq;
  cbor_encoder_create_map(&doc, &docReq, 2);
  cbor_encode_text_stringz(&docReq, "docRequests");
  CborEncoder docArray;
  cbor_encoder_create_array(&docReq, &docArray, 1);
  CborEncoder itemMap;
  cbor_encoder_create_map(&docArray, &itemMap, 1);
  cbor_encode_text_stringz(&itemMap, "itemsRequest");
  cbor_encode_tag(&itemMap, CborEncodedCborTag);
  cbor_encode_byte_string(&itemMap, doctype, cbor_encoder_get_buffer_size(&docType, doctype));
  cbor_encoder_close_container(&docArray, &itemMap);
  cbor_encoder_close_container(&docReq, &docArray);
  cbor_encode_text_stringz(&docReq, "version");
  cbor_encode_text_stringz(&docReq, "1.0");
  cbor_encoder_close_container(&doc, &docReq);
  size_t docSize = cbor_encoder_get_buffer_size(&doc, docBuf);
  LOG(V, "ENV2 CBOR");
  #if defined(CONFIG_IDF_CMAKE)
  ESP_LOG_BUFFER_HEX_LEVEL(TAG, docBuf, docSize, ESP_LOG_VERBOSE);
  #else
  for (int i = 0; i < docSize; i++) {
    printf("%02X", docBuf[i]);
  }
  #endif
  auto encrypted = secureCtx.encryptMessageToEndpoint(
      std::vector<uint8_t>(docBuf, docBuf + docSize));
  if (encrypted.empty()) {
    return {};
  }
  LOG_HEX(D, "ENC DATA", encrypted);

  auto tlv = simple_tlv(0x53, encrypted);

  ddk::ApduCommand env2{0x00, 0xC3, 0x00, 0x00, std::move(tlv), 0};
  auto resp = session_.apdu().transceive_full(env2);
  if (!resp.ok()) {
    LOG(E, "ENVELOPE 2 failed: SW=%02X%02X", resp.sw1, resp.sw2);
    return {};
  }

  const std::vector<uint8_t>& attestation_package = resp.data;
  LOG(D, "Attestation package: %zu bytes", attestation_package.size());
  LOG(D, "%s", redactHex("ATT PKG", attestation_package).c_str());

  TLV8 data(true);
  data.parse(attestation_package.data(), attestation_package.size());
  tlv_it tlvEncMsg = data.find(0x53);
  if (tlvEncMsg == data.end()) {
    LOG(E, "Envelope 2 response is missing required encrypted message (0x53).");
    return {};
  }
  auto decrypted_message = secureCtx.decryptMessageFromEndpoint(tlvEncMsg->value);
  if (decrypted_message.size() > 0) {
    return decrypted_message;
  }
  return {};
}

bool HKAttestationAuth::extract_device_key(
    ddk::span<const uint8_t> payload,
    std::vector<uint8_t>& x_out,
    std::vector<uint8_t>& y_out)
{
    // payload = tag(24) → bstr → MSO map bytes
    CborParser parser;
    CborValue it;
    if (cbor_parser_init(payload.data(), payload.size(), 0, &parser, &it)
        != CborNoError)
        return false;

    CborTag tag;
    if (!cbor_value_is_tag(&it) ||
        cbor_value_get_tag(&it, &tag) != CborNoError || tag != 24)
        return false;
    if (cbor_value_advance(&it) != CborNoError) return false;   // → bstr

    if (!cbor_value_is_byte_string(&it))
        return false;
    std::vector<uint8_t> mso;
    {
        size_t len = 0;
        if (cbor_value_get_string_length(&it, &len) != CborNoError)
            return false;
        mso.resize(len);
        cbor_value_copy_byte_string(&it, mso.data(), &len, nullptr);
    }

    CborParser mso_parser;
    CborValue root, key_info, key_map;
    if (cbor_parser_init(mso.data(), mso.size(), 0, &mso_parser, &root)
        != CborNoError || !cbor_value_is_map(&root))
        return false;

    if (cbor_value_map_find_value(&root, "deviceKeyInfo", &key_info)
        != CborNoError || !cbor_value_is_map(&key_info))
        return false;
    if (cbor_value_map_find_value(&key_info, "deviceKey", &key_map)
        != CborNoError || !cbor_value_is_map(&key_map))
        return false;

    CborValue kv;
    if (cbor_value_enter_container(&key_map, &kv) != CborNoError) return false;
    while (!cbor_value_at_end(&kv)) {
        int key = 0;
        if (!cbor_value_is_integer(&kv)) { cbor_value_advance(&kv); continue; }
        cbor_value_get_int(&kv, &key);
        if (cbor_value_advance(&kv) != CborNoError) return false;

        if (key == -2 || key == -3) {
            auto& out = (key == -2) ? x_out : y_out;
            if (cbor_value_is_byte_string(&kv)) {
                size_t len = 0;
                cbor_value_get_string_length(&kv, &len);
                out.resize(len);
                cbor_value_copy_byte_string(&kv, out.data(), &len, nullptr);
            }
        }
        if (cbor_value_advance(&kv) != CborNoError) return false;
    }
    return !x_out.empty() && !y_out.empty();
}

HKAttestationVerificationResult HKAttestationAuth::verify(std::vector<uint8_t>& decryptedCbor) {
    ddk::Issuer* foundIssuer = nullptr;
    std::array<uint8_t, 65> devicePubKey{};

    LOG(D, "Starting attestation verification with %d bytes of CBOR.",
        (int)decryptedCbor.size());

    do {
        CborParser parser;
        CborValue root, documents_array, document, issuer_signed, issuer_auth;
        CborError err;

        err = cbor_parser_init(decryptedCbor.data(), decryptedCbor.size(),
                               0, &parser, &root);
        if (err != CborNoError || !cbor_value_is_map(&root)) {
            LOG(E, "Failed to init CBOR parser or root not a map.");
            break;
        }

        err = cbor_value_map_find_value(&root, "documents", &documents_array);
        if (err != CborNoError || !cbor_value_is_array(&documents_array)) {
            LOG(E, "Failed to find 'documents' array.");
            break;
        }

        err = cbor_value_enter_container(&documents_array, &document);
        if (err != CborNoError || !cbor_value_is_map(&document)) {
            LOG(E, "Failed to enter first document.");
            break;
        }

        err = cbor_value_map_find_value(&document, "issuerSigned", &issuer_signed);
        if (err != CborNoError || !cbor_value_is_map(&issuer_signed)) {
            LOG(E, "Failed to find 'issuerSigned' map.");
            break;
        }

        err = cbor_value_map_find_value(&issuer_signed, "issuerAuth",
                                        &issuer_auth);
        if (err != CborNoError || !cbor_value_is_array(&issuer_auth)) {
            LOG(E, "Failed to find 'issuerAuth' array.");
            break;
        }

        auto cose = CoseSign1::parse_from_iterator(&issuer_auth);
        if (!cose) {
            LOG(E, "CoseSign1::parse_from_iterator failed on issuerAuth.");
            break;
        }

        if (!cose->issuer_id || cose->issuer_id->size() != 8) {
            LOG(E, "issuerId missing or wrong size (%zu).",
                cose->issuer_id ? cose->issuer_id->size() : 0);
            break;
        }

        for (auto& issuer : session_.store().issuers()) {
            if (issuer.id.size() != 8) continue;
            if (CommonCryptoUtils::constant_time_compare(
                    issuer.id, *cose->issuer_id)) {
                foundIssuer = &issuer;
                break;
            }
        }
        if (!foundIssuer) {
            LOG_HEX(E, "No matching issuer for issuerId", *cose->issuer_id);
            break;
        }

        std::vector<uint8_t> deviceKeyX, deviceKeyY;
        if (!extract_device_key(cose->payload, deviceKeyX, deviceKeyY)) {
            LOG(E, "Failed to extract deviceKey from MSO.");
            break;
        }
        if (deviceKeyX.size() != 32 || deviceKeyY.size() != 32) {
            LOG(E, "deviceKey coordinates wrong size (X: %zu, Y: %zu).",
                deviceKeyX.size(), deviceKeyY.size());
            break;
        }

        devicePubKey[0] = 0x04;
        std::copy(deviceKeyX.begin(), deviceKeyX.end(), devicePubKey.begin() + 1);
        std::copy(deviceKeyY.begin(), deviceKeyY.end(),
                  devicePubKey.begin() + 33);

        if (!CoseSign1::verify(*cose, CoseAlgorithm::Ed25519,
                               foundIssuer->public_key)) {
            LOG(E, "Attestation signature verification failed.");
            break;
        }

        LOG(D, "Attestation signature verification successful!");
        return {foundIssuer, devicePubKey};

    } while (0);

    LOG(E, "Attestation verification failed. Returning empty result.");
    return {};
}

HKAttestationResult HKAttestationAuth::attest()
{
    attestation_exchange_common_secret.resize(32);
#if defined(CONFIG_IDF_CMAKE)
  esp_fill_random(attestation_exchange_common_secret.data(), 32);
#else
  randombytes(attestation_exchange_common_secret.data(), 32);
#endif
  auto attTlv = simple_tlv(0xC0, attestation_exchange_common_secret);
  auto opAttTlv = simple_tlv(0x8E, attTlv);
  std::vector<uint8_t> attComm{0x0};
  attComm.reserve(opAttTlv.size() + 1);
  attComm.insert(attComm.begin() + 1, opAttTlv.begin(), opAttTlv.end());
  auto status = session_.secure_context()->exchange(session_, attComm);
  HKAttestationResult result;
  if (status.ok())
  {
    auto env1Data = envelope1Cmd();
    std::vector<uint8_t> env1Res = std::get<0>(env1Data);
    if (!env1Res.empty())
    {
      auto salt = attestation_salt(std::get<0>(env1Data), std::get<1>(env1Data));
      if (salt.size() > 0) {
        auto env2DataDec = envelope2Cmd(salt);
        if (env2DataDec.size() > 0)
        {
          auto verify_result = verify(env2DataDec);
          if (verify_result) {
            result.device_pub_key = verify_result.device_pub_key;
            result.issuer = verify_result.issuer;
            result.flow = kFlowATTESTATION;
            return result;
          }
        }
      }
    }
  }
  return result;
}
