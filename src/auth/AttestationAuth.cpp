#include "AttestationAuth.h"
#include "AuthResults.hpp"
#include "ndef.h"
#include "simple_tlv.hpp"
#include "TLV8.hpp"
#include "ISO18013SecureContext.h"
#include "DDKLogging.h"
#include <array>
#include <cstdint>
#if defined(CONFIG_IDF_CMAKE)
#include <esp_random.h>
#else 
#include "sodium.h"
#endif
#include <sodium/crypto_sign_ed25519.h>
#include <mbedtls/sha256.h>
#include <mbedtls/error.h>
#include <cbor.h>
#include <vector>

DDKAttestationAuth::DDKAttestationAuth(DDKAuthParams &params) : params(params) {
}

std::vector<unsigned char> DDKAttestationAuth::attestation_salt(std::vector<unsigned char> &env1Data, std::vector<unsigned char> &readerCmd)
{
  TLV8 env1ResTlv;
  env1ResTlv.parse(env1Data.data(), env1Data.size());
  tlv_it tlvEnv1Ndef = env1ResTlv.find(kNDEF_MESSAGE);
  std::vector<uint8_t> env1Ndef = tlvEnv1Ndef->value;
  NDEFMessage ndefEnv1Ctx = NDEFMessage(env1Ndef.data(), env1Ndef.size());
  auto ndefEnv1Data = ndefEnv1Ctx.unpack();
  auto ndefEnv1Pack = ndefEnv1Ctx.pack();
  NDEFRecord* res_eng = ndefEnv1Ctx.findType("iso.org:18013:deviceengagement");
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

std::tuple<std::vector<uint8_t>, std::vector<uint8_t>> DDKAttestationAuth::envelope1Cmd()
{
  std::vector<uint8_t> ctrlFlow = {0x80, 0x3c, 0x40, 0xa0};
  std::vector<uint8_t> ctrlFlowRes;
  if (!params.nfc(ctrlFlow, ctrlFlowRes, false) || ctrlFlowRes.size() < 2) {
    return std::make_tuple(std::vector<uint8_t>(), std::vector<uint8_t>());
  }
  LOG(D, "%s", redactHex("CTRL FLOW RES", ctrlFlowRes).c_str());
  if (ctrlFlowRes[0] == 0x90 && ctrlFlowRes[1] == 0x0)
  { // cla=0x00; ins=0xa4; p1=0x04; p2=0x00; lc=0x07(7); data=a0000008580102; le=0x00
    std::vector<uint8_t> data = {0x00, 0xA4, 0x04, 0x00, 0x07, 0xA0, 0x00, 0x00, 0x08, 0x58, 0x01, 0x02, 0x0};
    std::vector<uint8_t> response;
    if (!params.nfc(data, response, false) || response.size() < 2) {
      return std::make_tuple(std::vector<uint8_t>(), std::vector<uint8_t>());
    }
    LOG(D, "%s", redactHex("ENV1.2 RES", response).c_str());
    if (response[0] == 0x90 && response[1] == 0x0){
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
      std::vector<uint8_t> env1Res;
      if (!params.nfc(env1Apdu, env1Res, false) || env1Res.size() < 2) {
        return std::make_tuple(std::vector<uint8_t>(), std::vector<uint8_t>());
      }
      LOG(D, "%s", redactHex("APDU RES", env1Res).c_str());
      if (env1Res[env1Res.size() - 2] == 0x90 && env1Res[env1Res.size() - 1] == 0x0){
        return std::make_tuple(env1Res, ndefMessage);
      }
    }
  }
  return std::make_tuple(std::vector<uint8_t>(), std::vector<uint8_t>());
}

std::vector<unsigned char> DDKAttestationAuth::envelope2Cmd(std::vector<uint8_t> &salt)
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
  auto encrypted = secureCtx.encryptMessageToEndpoint(std::vector<uint8_t>(docBuf, docBuf + docSize));
  if(encrypted.size() > 0){
    LOG_HEX(D, "ENC DATA", encrypted);

    auto tlv = simple_tlv(0x53, encrypted);

    std::vector<uint8_t> apdu = {0x0, 0xC3, 0x0, 0x0, (unsigned char)tlv.size()};

    apdu.insert(apdu.end(), tlv.begin(), tlv.end());
    LOG(D, "%s", redactHex("ENV2 APDU", apdu).c_str());
    std::vector<uint8_t> env2Res;
    std::vector<uint8_t> attestation_package;
    std::vector<uint8_t> dataStatus;
    std::vector<uint8_t> getData = {0x0, 0xc0, 0x0, 0x0, 0x0};
    LOG(D, "%s", redactHex("ENV2 APDU", apdu).c_str());
    if (!params.nfc(apdu, dataStatus, false) || dataStatus.size() < 2) {
      return std::vector<uint8_t>();
    }
    bool getMore = false;
    do
    {
      getMore = false;
      bool status = params.nfc(getData, env2Res, false);
      if(!status || env2Res.size() < 2) {
        return std::vector<uint8_t>();
      }
      attestation_package.insert(attestation_package.end(), env2Res.begin(), env2Res.end());
      LOG(D, "Data Length: %d - pkg length: %d", env2Res.size(), attestation_package.size());
      if(env2Res.size() >= 250 && (*(&env2Res.back() - 1) == 0x61)){
        getMore = true;
        attestation_package.pop_back();
        attestation_package.pop_back();
      } else if((*(&env2Res.back() - 1) == 0x90) && (*&env2Res.back() == 0x0)){
        getMore = false;
        break;
      }
      env2Res.clear();
    } while (getMore);
    LOG(D, "%s", redactHex("ATT PKG", attestation_package).c_str());
    TLV8 data(true);
    data.parse(attestation_package.data(), attestation_package.size());
    tlv_it tlvStatus = data.find(0x90);
    if (tlvStatus != data.end()) {
      tlv_it tlvEncMsg = data.find(0x53);
      std::vector<uint8_t> encryptedMessage = tlvEncMsg->value;
      auto decrypted_message = secureCtx.decryptMessageFromEndpoint(encryptedMessage);
      if(decrypted_message.size() > 0){
        return decrypted_message;
      }
    }
  }
  return std::vector<uint8_t>();
}

// Helper function to copy a CborValue byte string to a std::vector
CborError copy_byte_string(CborValue *value, std::vector<uint8_t> &target) {
    if (!cbor_value_is_byte_string(value)) {
        return CborErrorIllegalType;
    }
    size_t len;
    CborError err = cbor_value_get_string_length(value, &len);
    if (err != CborNoError) {
        return err;
    }
    target.resize(len);
    return cbor_value_copy_byte_string(value, target.data(), &len, nullptr);
}


std::tuple<hkIssuer_t*, std::array<uint8_t, 65>> DDKAttestationAuth::verify(std::vector<uint8_t>& decryptedCbor) {
    hkIssuer_t* foundIssuer = nullptr;
    std::array<uint8_t, 65> devicePubKey;

    LOG(D, "Starting attestation verification with %d bytes of CBOR.", decryptedCbor.size());

    do {
        CborParser parser;
        CborValue root, documents_array, document, issuer_signed, issuer_auth, issuer_auth_array;
        CborError err;

        err = cbor_parser_init(decryptedCbor.data(), decryptedCbor.size(), 0, &parser, &root);
        if (err != CborNoError) {
            LOG(E, "CBOR parser initialization failed. Error: %d", err);
            break;
        }
        if (!cbor_value_is_map(&root)) {
            LOG(E, "Root CBOR element is not a map.");
            break;
        }
        LOG(V, "Successfully initialized CBOR parser.");

        // Find "documents"
        err = cbor_value_map_find_value(&root, "documents", &documents_array);
        if (err != CborNoError) {
            LOG(E, "Failed to find 'documents' key. Error: %d", err);
            break;
        }
        if (!cbor_value_is_array(&documents_array)) {
            LOG(E, "'documents' value is not an array.");
            break;
        }
        LOG(V, "Found 'documents' array.");

        // Enter first document
        err = cbor_value_enter_container(&documents_array, &document);
        if (err != CborNoError) {
            LOG(E, "Failed to enter 'documents' container. Error: %d", err);
            break;
        }
        if (!cbor_value_is_map(&document)) {
            LOG(E, "First element in 'documents' is not a map.");
            break;
        }
        LOG(V, "Entered first document map.");

        // Find "issuerSigned"
        err = cbor_value_map_find_value(&document, "issuerSigned", &issuer_signed);
        if (err != CborNoError) {
            LOG(E, "Failed to find 'issuerSigned' key. Error: %d", err);
            break;
        }
        if (!cbor_value_is_map(&issuer_signed)) {
            LOG(E, "'issuerSigned' value is not a map.");
            break;
        }
        LOG(V, "Found 'issuerSigned' map.");

        // Find "issuerAuth"
        err = cbor_value_map_find_value(&issuer_signed, "issuerAuth", &issuer_auth);
        if (err != CborNoError) {
            LOG(E, "Failed to find 'issuerAuth' key. Error: %d", err);
            break;
        }
        if (!cbor_value_is_array(&issuer_auth)) {
            LOG(E, "'issuerAuth' value is not an array.");
            break;
        }
        LOG(V, "Found 'issuerAuth' array. Starting extraction...");
        
        // --- Start Parsing issuerAuth array ---
        std::vector<uint8_t> protectedHeaders, issuerId, data, signature;

        err = cbor_value_enter_container(&issuer_auth, &issuer_auth_array);
        if (err != CborNoError) {
            LOG(E, "Failed to enter 'issuerAuth' container. Error: %d", err);
            break;
        }

        // protectedHeaders (byte string)
        if (copy_byte_string(&issuer_auth_array, protectedHeaders) != CborNoError) {
            LOG(E, "Failed to copy protectedHeaders or it's not a byte string.");
            break;
        }
        LOG(D, "Extracted protectedHeaders, size: %d", protectedHeaders.size());
        if (cbor_value_advance(&issuer_auth_array) != CborNoError) {
            LOG(E, "Failed to advance past protectedHeaders.");
            break;
        }

        // unprotectedHeaders (map), find issuerId by key 4
        CborValue unprotected_headers;
        if (!cbor_value_is_map(&issuer_auth_array)) {
            LOG(E, "Expected unprotectedHeaders map, found other type.");
            break;
        }
        err = cbor_value_enter_container(&issuer_auth_array, &unprotected_headers);
        if (err != CborNoError) {
            LOG(E, "Failed to enter unprotectedHeaders container. Error: %d", err);
            break;
        }
        
        while (!cbor_value_at_end(&unprotected_headers)) {
            if (cbor_value_is_integer(&unprotected_headers)) {
                int64_t key;
                cbor_value_get_int64(&unprotected_headers, &key);
                err = cbor_value_advance(&unprotected_headers);
                if (err != CborNoError) { LOG(E, "Failed to advance to value in unprotectedHeaders."); break; }

                if (key == 4) { // issuerId
                    if (copy_byte_string(&unprotected_headers, issuerId) != CborNoError) {
                        err = CborErrorInternalError; 
                        LOG(E, "Failed to copy issuerId value.");
                        break;
                    }
                    LOG_HEX(D, "Extracted issuerId", issuerId);
                }
            }
            if (cbor_value_at_end(&unprotected_headers)) break;
            err = cbor_value_advance(&unprotected_headers); // Advance past value to next key
            if (err != CborNoError) { LOG(E, "Failed to advance to next key in unprotectedHeaders."); break; }
        }
        if (err != CborNoError) break;
        
        err = cbor_value_leave_container(&issuer_auth_array, &unprotected_headers);
        if (err != CborNoError) {
            LOG(E, "Failed to leave unprotectedHeaders container. Error: %d", err);
            break;
        }
        
        // data (byte string containing nested CBOR)
        if (copy_byte_string(&issuer_auth_array, data) != CborNoError) {
            LOG(E, "Failed to copy inner 'data' payload or it's not a byte string.");
            break;
        }
        LOG(D, "Extracted inner 'data' payload, size: %d", data.size());
        if (cbor_value_advance(&issuer_auth_array) != CborNoError) {
            LOG(E, "Failed to advance past inner 'data' payload.");
            break;
        }
        
        // signature (byte string)
        if (copy_byte_string(&issuer_auth_array, signature) != CborNoError) {
            LOG(E, "Failed to copy signature or it's not a byte string.");
            break;
        }
        LOG(D, "Extracted signature, size: %d", signature.size());

        // --- Start Parsing the inner 'data' CBOR payload ---
        std::vector<uint8_t> deviceKeyX, deviceKeyY;
        
        // The 'data' payload is a single CBOR item: a byte string tagged with 24.
        CborParser intermediate_parser;
        CborValue tagged_bstr_val;
        std::vector<uint8_t> final_payload;

        err = cbor_parser_init(data.data(), data.size(), 0, &intermediate_parser, &tagged_bstr_val);
        if (err != CborNoError) { LOG(E, "Failed to init parser for intermediate payload."); break; }

        CborTag tag;
        err = cbor_value_get_tag(&tagged_bstr_val, &tag);
        if (err != CborNoError || tag != 24) { LOG(E, "Payload is not a byte string tagged with 24."); break; }

        err = cbor_value_advance(&tagged_bstr_val);
        if (err != CborNoError) { LOG(E, "Failed to advance parser past the tag."); break; }

        if (copy_byte_string(&tagged_bstr_val, final_payload) != CborNoError) {
            LOG(E, "Failed to copy final payload from tagged byte string.");
            break;
        }

        CborParser inner_parser;
        CborValue inner_root, device_key_info, device_key_map, key_map_iterator;
        
        err = cbor_parser_init(final_payload.data(), final_payload.size(), 0, &inner_parser, &inner_root);
        if (err != CborNoError || !cbor_value_is_map(&inner_root)) { LOG(E, "Final inner payload is not a valid CBOR map."); break; }

        err = cbor_value_map_find_value(&inner_root, "deviceKeyInfo", &device_key_info);
        if (err != CborNoError || !cbor_value_is_map(&device_key_info)) { LOG(E, "Could not find 'deviceKeyInfo' map in inner payload."); break; }
        
        err = cbor_value_map_find_value(&device_key_info, "deviceKey", &device_key_map);
        if (err != CborNoError || !cbor_value_is_map(&device_key_map)) { LOG(E, "Could not find 'deviceKey' map in inner payload."); break; }
        LOG(V, "Found 'deviceKey' map, parsing keys...");

        err = cbor_value_enter_container(&device_key_map, &key_map_iterator);
        if (err != CborNoError) { LOG(E, "Failed to enter 'deviceKey' container."); break; }

        while (!cbor_value_at_end(&key_map_iterator)) {
            if (cbor_value_is_integer(&key_map_iterator)) {
                int64_t key;
                cbor_value_get_int64(&key_map_iterator, &key);
                err = cbor_value_advance(&key_map_iterator);
                if (err != CborNoError) { LOG(E, "Failed to advance to value in deviceKey map."); break; }

                if (key == -2) { // deviceKeyX
                    if (copy_byte_string(&key_map_iterator, deviceKeyX) != CborNoError) { err = CborErrorInternalError; LOG(E, "Failed to copy deviceKeyX."); break; }
                } else if (key == -3) { // deviceKeyY
                    if (copy_byte_string(&key_map_iterator, deviceKeyY) != CborNoError) { err = CborErrorInternalError; LOG(E, "Failed to copy deviceKeyY."); break; }
                }
            }
            if (cbor_value_at_end(&key_map_iterator)) break;
            err = cbor_value_advance(&key_map_iterator); // move past value to next key
            if (err != CborNoError) { LOG(E, "Failed to advance to next key in deviceKey map."); break; }
        }
        if (err != CborNoError) break;

        err = cbor_value_leave_container(&device_key_map, &key_map_iterator);
        if (err != CborNoError) { LOG(E, "Failed to leave deviceKey container."); break; }

        if (deviceKeyX.empty() || deviceKeyY.empty()) {
            LOG(E, "Parsing finished but deviceKeyX or deviceKeyY is missing.");
            break;
        }
        LOG(D, "Extracted deviceKeyX (size: %d) and deviceKeyY (size: %d)", deviceKeyX.size(), deviceKeyY.size());

        devicePubKey[0] = 0x04;
        std::move(std::make_move_iterator(deviceKeyX.begin()), std::make_move_iterator(deviceKeyX.end()), devicePubKey.data() + 1);
        std::move(std::make_move_iterator(deviceKeyY.begin()), std::make_move_iterator(deviceKeyY.end()), devicePubKey.data() + 1);
        
        // --- Verification Logic ---
        for (auto &&issuer : params.issuers) {
          if (std::equal(issuer.issuer_id.begin(), issuer.issuer_id.end(), issuerId.begin())) {
            LOG_HEX(D, "Found matching Issuer", issuer.issuer_id);
            foundIssuer = &issuer;
          }
        }

        if (foundIssuer != nullptr) {
          CborEncoder package;
          std::vector<uint8_t> packageBuf(strlen("Signature1") + protectedHeaders.size() + data.size() + 16); // Increased buffer margin
          cbor_encoder_init(&package, packageBuf.data(), packageBuf.size(), 0);
          CborEncoder packageArray;
          cbor_encoder_create_array(&package, &packageArray, 4);
          cbor_encode_text_stringz(&packageArray, "Signature1");
          cbor_encode_byte_string(&packageArray, protectedHeaders.data(), protectedHeaders.size());
          cbor_encode_byte_string(&packageArray, {}, 0); // external_aad
          cbor_encode_byte_string(&packageArray, data.data(), data.size());
          cbor_encoder_close_container(&package, &packageArray);
          size_t package_size = cbor_encoder_get_buffer_size(&package, packageBuf.data());
          packageBuf.resize(package_size);
          LOG(D, "Verifying signature against package of size %d", package_size);
          LOG_HEX(V, "SIGNED PACKAGE", packageBuf);

          int res = crypto_sign_ed25519_verify_detached(signature.data(), packageBuf.data(), package_size, foundIssuer->issuer_pk.data());
          if (res == 0) {
            LOG(D, "Attestation signature verification successful!");
            return std::make_tuple(foundIssuer, devicePubKey);
          }
          LOG(E, "Failed to verify attestation signature! Result code: %d", res);
        } else {
            LOG_HEX(E, "No matching issuer found for issuerId", issuerId);
        }

    } while(0);

    LOG(E, "Attestation verification failed. Returning empty result.");
    return std::make_tuple(nullptr, devicePubKey);
}

AttestationResult DDKAttestationAuth::attest()
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
  LOG_HEX(D, "attComm", attComm);
  auto encryptedCmd = params.context->encrypt_command(attComm.data(), attComm.size());

  LOG_HEX(V, "encrypted_command", std::get<0>(encryptedCmd));
  LOG_HEX(V, "calculated_rmac", std::get<1>(encryptedCmd));
  std::vector<uint8_t> xchApdu = {0x84, 0xc9, 0x0, 0x0, (uint8_t)std::get<0>(encryptedCmd).size()};
  xchApdu.reserve(std::get<0>(encryptedCmd).size() + 5);
  xchApdu.insert(xchApdu.end(), std::get<0>(encryptedCmd).begin(), std::get<0>(encryptedCmd).end());
  LOG(V, "%s", redactHex("APDU CMD", xchApdu).c_str());
  std::vector<uint8_t> xchRes;
  params.nfc(xchApdu, xchRes, false);
  LOG(D, "%s", redactHex("APDU RES", xchRes).c_str());
  AttestationResult result;
  if (xchRes.size() > 2 && xchRes[xchRes.size() - 2] == 0x90)
  {
    auto env1Data = envelope1Cmd();
    std::vector<uint8_t> env1Res = std::get<0>(env1Data);
    if (env1Res.size() > 2 && env1Res.data()[env1Res.size() - 2] == 0x90)
    {
      auto salt = attestation_salt(std::get<0>(env1Data), std::get<1>(env1Data));
      if(salt.size() > 0){
        auto env2DataDec = envelope2Cmd(salt);
        if (env2DataDec.size() > 0)
        {
          auto verify_result = verify(env2DataDec);
          if (std::get<1>(verify_result).size() > 0) {
            result.device_pub_key = std::get<std::array<uint8_t,65>>(verify_result);
            result.issuer = std::get<hkIssuer_t*>(verify_result);
            result.flow = kFlowATTESTATION;
            return result;
          }
        }
      }
    }
  }
  return result;
}
