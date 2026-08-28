#include <HK_HomeKit.h>
#include "CommonCryptoUtils.h"
#include "ddk/homekey/HapTags.h"
#include "TLV8.hpp"
#include "DDKLogging.h"
#include "ddk/store/ReaderIdentity.h"
#include "ddk/store/Issuer.h"
#include <mbedtls/ecp.h>
#include <mbedtls/sha256.h>
#include <mbedtls/sha1.h>
#include <mbedtls/error.h>
#include <vector>

std::mutex HK_HomeKit::provision_mutex;

HK_HomeKit::HK_HomeKit(ddk::CredentialStore& store, std::function<void()> remove_key_cb, std::vector<uint8_t>& tlvData) : store(store), tlvData(tlvData), remove_key_cb(remove_key_cb) { }

std::vector<uint8_t> HK_HomeKit::processResult() {
  std::lock_guard<std::mutex> lock(provision_mutex);

  TLV8 rxTlv;
  rxTlv.parse(tlvData.data(), tlvData.size());
  if (!rxTlv.ok()) {
    LOG(E, "Failed to parse incoming TLV data");
    return std::vector<uint8_t>();
  }

  tlv_it operation = rxTlv.find(kReader_Operation);
  tlv_it RKR = rxTlv.find(kReader_Reader_Key_Request);
  tlv_it DCR = rxTlv.find(kReader_Device_Credential_Request);

  if (operation != rxTlv.end() && operation->length() > 0) {
    uint8_t op = *operation->data();
    LOG(I, "TLV OPERATION: %d", op);

    if (op == kReader_Operation_Read) {
      if (RKR != rxTlv.end() && RKR->tag == kReader_Reader_Key_Request) {
        LOG(I, "GET READER KEY REQUEST");
        if (!store.reader_identity().private_key.empty() && !store.reader_identity().group_identifier.empty()) {
          TLV8 getResSub;
          getResSub.add(kReader_Res_Key_Identifier, store.reader_identity().group_identifier);
          std::vector<uint8_t> subTlv = getResSub.get();
          LOG(D, "%s", redactHex("SUB-TLV", subTlv).c_str());
          TLV8 getResSubStatus;
          getResSubStatus.add(kReader_Res_Status, 0);
          std::vector<uint8_t> getSubTlvStatus = getResSubStatus.get();
          TLV8 getResTlv;
          getResTlv.add(kReader_Res_Reader_Key_Response, subTlv);
          getResTlv.add(kReader_Res_Reader_Key_Response, getSubTlvStatus);
          std::vector<uint8_t> tlvRes = getResTlv.get();
          LOG(D, "%s", redactHex("TLV", tlvRes).c_str());
          return tlvRes;
        }
        return std::vector<uint8_t>();
      }
    } else if (op == kReader_Operation_Write) {
      if (RKR != rxTlv.end()) {
        LOG(I, "TLV RKR: %d", RKR->length());
        LOG(I, "SET READER KEY REQUEST");
        int ret = set_reader_key(RKR->value);
        if (ret == 0) {
          LOG(I, "READER KEY SAVED TO NVS, COMPOSING RESPONSE");
          TLV8 rkResSub;
          rkResSub.add(kReader_Res_Status, 0);
          std::vector<uint8_t> rkSubTlv = rkResSub.get();
          LOG(D, "%s", redactHex("SUB-TLV", rkSubTlv).c_str());
          TLV8 rkResTlv;
          rkResTlv.add(kReader_Res_Reader_Key_Response, rkSubTlv);
          return rkResTlv.get();
        }
      } else if (DCR != rxTlv.end()) {
        LOG(I, "TLV DCR: %d", DCR->length());
        LOG(D, "PROVISION DEVICE CREDENTIAL REQUEST");
        auto state = provision_device_cred(DCR->value);
        TLV8 dcrResSubTlv;
        if (!std::get<std::vector<uint8_t>>(state).empty()) {
          dcrResSubTlv.add(kDevice_Res_Issuer_Key_Identifier, std::get<0>(state).size(), std::get<0>(state).data());
        }
        dcrResSubTlv.add(kDevice_Res_Status, std::get<int>(state));
        std::vector<uint8_t> packedRes = dcrResSubTlv.get();
        LOG(D, "SUB-TLV: %d", (int)packedRes.size());
        LOG(D, "%s", redactHex("SUB-TLV", packedRes).c_str());
        TLV8 dcrResTlv;
        dcrResTlv.add(kDevice_Credential_Response, packedRes);
        return dcrResTlv.get();
      }
    } else if (op == kReader_Operation_Remove) {
      if (RKR != rxTlv.end()) {
        LOG(I, "REMOVE READER KEY REQUEST");
        remove_key_cb();
        return std::vector<uint8_t>{ 0x7, 0x3, 0x2, 0x1, 0x0 };
      } else if (DCR != rxTlv.end()) {
        LOG(I, "TLV DCR: %d", DCR->length());
        LOG(D, "REMOVE DEVICE CREDENTIAL REQUEST");
        auto state = remove_device_cred(DCR->value);
        const auto& issuerId = std::get<0>(state);
        int status = std::get<1>(state);
        TLV8 dcrResSubTlv;
        if (!issuerId.empty()) {
          dcrResSubTlv.add(kDevice_Res_Issuer_Key_Identifier, issuerId.size(), issuerId.data());
        }
        dcrResSubTlv.add(kDevice_Res_Status, status);
        std::vector<uint8_t> packedRes = dcrResSubTlv.get();
        LOG(D, "SUB-TLV: %d", (int)packedRes.size());
        LOG(D, "%s", redactHex("SUB-TLV", packedRes).c_str());
        TLV8 dcrResTlv;
        dcrResTlv.add(kDevice_Credential_Response, packedRes);
        return dcrResTlv.get();
      }
    }
  }

  return std::vector<uint8_t>();
}

std::tuple<std::vector<uint8_t>, int> HK_HomeKit::provision_device_cred(const std::vector<uint8_t> &buf) {
  LOG(D, "DCReq Add length: %d (data redacted)", (int)buf.size());
  TLV8 dcrTlv;
  dcrTlv.parse(buf.data(), buf.size());
  if (!dcrTlv.ok()) {
    LOG(E, "DCReq TLV parse error");
    return {std::vector<uint8_t>{}, DOES_NOT_EXIST};
  }
  ddk::Issuer* foundIssuer = nullptr;
  const tlv_t* tlvIssuerId = dcrTlv.expect(kDevice_Req_Issuer_Key_Identifier);
  if (tlvIssuerId == nullptr) {
    LOG(E, "Issuer Key Identifier missing from DCR");
    return {std::vector<uint8_t>{}, DOES_NOT_EXIST};
  }
  std::vector<uint8_t> issuerIdentifier = tlvIssuerId->value;
  if (issuerIdentifier.size() > 0) {
    for (auto& issuer : store.issuers()) {
      if (CommonCryptoUtils::constant_time_compare(issuer.id, issuerIdentifier)) {
        LOG_HEX(D, "Found issuer - ID", issuer.id);
        foundIssuer = &issuer;
      }
    }
    if (foundIssuer != nullptr) {
      ddk::Endpoint* foundEndpoint = nullptr;
      const tlv_t* tlvDevicePubKey = dcrTlv.expect(kDevice_Req_Public_Key);
      if (tlvDevicePubKey == nullptr) {
        LOG(E, "Device Public Key missing from DCR");
        return std::make_tuple(issuerIdentifier, DOES_NOT_EXIST);
      }
      std::vector<uint8_t> devicePubKey = tlvDevicePubKey->value;
      devicePubKey.insert(devicePubKey.begin(), 0x04);
      std::vector<uint8_t> hash = CommonCryptoUtils::hash_identifier_sha1(devicePubKey);
      std::vector<uint8_t> endpointId(hash.begin(), hash.begin() + 6);
      for (auto& endpoint : foundIssuer->endpoints) {
        if (CommonCryptoUtils::constant_time_compare(endpoint.id, endpointId)) {
          LOG_HEX(D, "Found endpoint - ID", endpoint.id);
          foundEndpoint = &endpoint;
        }
      }
      if (foundEndpoint == nullptr) {
        LOG(D, "Adding new endpoint - ID: %s , %s", redactHex("", endpointId.data(), endpointId.size()).c_str(), redactHex("PK", devicePubKey.data(), devicePubKey.size()).c_str());
        ddk::Endpoint endpoint;
        std::vector<uint8_t> x_coordinate = CommonCryptoUtils::get_x(devicePubKey);
        const tlv_t* tlvKeyType = dcrTlv.expect(kDevice_Req_Key_Type);
        if (tlvKeyType == nullptr || tlvKeyType->value.empty()) {
          LOG(E, "Key Type missing from DCR");
          return std::make_tuple(issuerIdentifier, DOES_NOT_EXIST);
        }
        std::vector<uint8_t> keyType = tlvKeyType->value;
        endpoint.counter = 0;
        endpoint.key_type = static_cast<ddk::KeyType>(*keyType.data());
        if (hash.size() >= 6) {
          endpoint.id = endpointId;
        }
        endpoint.public_key = devicePubKey;
        endpoint.public_key_x = x_coordinate;
        foundIssuer->endpoints.emplace_back(endpoint);
        auto identity = store.reader_identity();
        LOG(D, "identity sizes: sk=%zu pk=%zu pkx=%zu gid=%zu sub=%zu cert=%d",
            identity.private_key.size(),
            identity.public_key.size(),
            identity.public_key_x.size(),
            identity.group_identifier.size(),
            identity.sub_identifier.size(),
            identity.certificate.has_value());

        LOG(D, "issuers count: %zu", store.issuers().size());
        for (size_t i = 0; i < store.issuers().size(); ++i) {
            auto& iss = store.issuers()[i];
            LOG(D, "issuer[%zu] id=%zu pk=%zu pkx=%zu endpoints=%zu",
                i, iss.id.size(), iss.public_key.size(),
                iss.public_key_x.size(), iss.endpoints.size());
        }
        store.save();
        return std::make_tuple(foundIssuer->id, SUCCESS);
      }
      else {
        LOG_HEX(D, "Endpoint already exists - ID", foundEndpoint->id);
        return std::make_tuple(issuerIdentifier, DUPLICATE);
      }
    }
    else {
      LOG_HEX(D, "Issuer does not exist - ID", issuerIdentifier);
      return std::make_tuple(issuerIdentifier, DOES_NOT_EXIST);
    }
  }
  return {std::vector<uint8_t>{}, DOES_NOT_EXIST};
}

std::tuple<std::vector<uint8_t>, int> HK_HomeKit::remove_device_cred(const std::vector<uint8_t> &buf) {
  LOG(D, "DCReq Remove Buffer length: %d (data redacted)", (int)buf.size());
  TLV8 dcrTlv;
  dcrTlv.parse(buf.data(), buf.size());
  if(!dcrTlv.ok()){
    LOG(E, "DCReq TLV parse error");
    return {std::vector<uint8_t>{}, DOES_NOT_EXIST};
  }

  const tlv_t* tlvIssuerId = dcrTlv.expect(kDevice_Req_Issuer_Key_Identifier);
  const tlv_t* tlvKeyId = dcrTlv.expect(kDevice_Req_Key_Identifier);
  const tlv_t* tlvDevicePubKey = dcrTlv.expect(kDevice_Req_Public_Key);

  std::vector<uint8_t> issuerIdentifier;
  if (tlvIssuerId != nullptr && !tlvIssuerId->value.empty()) {
    issuerIdentifier = tlvIssuerId->value;
  }

  std::vector<uint8_t> keyIdentifier;
  if (tlvKeyId != nullptr && !tlvKeyId->value.empty()) {
    keyIdentifier = tlvKeyId->value;
  }

  std::vector<uint8_t> devicePubKey;
  if (tlvDevicePubKey != nullptr && !tlvDevicePubKey->value.empty()) {
    devicePubKey = tlvDevicePubKey->value;
    if (devicePubKey.size() == 64) {
      devicePubKey.insert(devicePubKey.begin(), 0x04);
    }
  }

  if (keyIdentifier.empty() && !devicePubKey.empty()) {
    std::vector<uint8_t> hash = CommonCryptoUtils::hash_identifier_sha1(devicePubKey);
    if (hash.size() >= 6) {
      keyIdentifier = std::vector<uint8_t>(hash.begin(), hash.begin() + 6);
    }
  }

  if (!issuerIdentifier.empty()) {
    ddk::Issuer* foundIssuer = nullptr;
    for (auto& issuer : store.issuers()) {
      if (CommonCryptoUtils::constant_time_compare(issuer.id, issuerIdentifier)) {
        LOG_HEX(D, "Found issuer - ID", issuer.id);
        foundIssuer = &issuer;
        break;
      }
    }

    if (foundIssuer == nullptr) {
      LOG_HEX(D, "Issuer does not exist - ID", issuerIdentifier);
      return std::make_tuple(issuerIdentifier, DOES_NOT_EXIST);
    }

    if (!keyIdentifier.empty() || !devicePubKey.empty()) {
      bool removed = false;
      for (auto it = foundIssuer->endpoints.begin(); it != foundIssuer->endpoints.end(); ++it) {
        bool match = false;
        if (!keyIdentifier.empty()) {
          if (CommonCryptoUtils::constant_time_compare(it->id, keyIdentifier)) {
            match = true;
          }
        }
        if (!match && !devicePubKey.empty()) {
          if (CommonCryptoUtils::constant_time_compare(it->public_key, devicePubKey)) {
            match = true;
          }
        }
        if (match) {
          LOG_HEX(D, "Removing endpoint - ID", it->id);
          foundIssuer->endpoints.erase(it);
          removed = true;
          break;
        }
      }

      if (removed) {
        store.save();
        return std::make_tuple(issuerIdentifier, SUCCESS);
      } else {
        LOG(D, "Endpoint does not exist in specified issuer");
        return std::make_tuple(issuerIdentifier, DOES_NOT_EXIST);
      }
    } else {
      LOG_HEX(D, "Removing all endpoints for issuer - ID", issuerIdentifier);
      foundIssuer->endpoints.clear();
      store.save();
      return std::make_tuple(issuerIdentifier, SUCCESS);
    }
  }

  if (!keyIdentifier.empty() || !devicePubKey.empty()) {
    for (auto& issuer : store.issuers()) {
      for (auto it = issuer.endpoints.begin(); it != issuer.endpoints.end(); ++it) {
        bool match = false;
        if (!keyIdentifier.empty()) {
          if (CommonCryptoUtils::constant_time_compare(it->id, keyIdentifier)) {
            match = true;
          }
        }
        if (!match && !devicePubKey.empty()) {
          if (CommonCryptoUtils::constant_time_compare(it->public_key, devicePubKey)) {
            match = true;
          }
        }
        if (match) {
          LOG_HEX(D, "Removing endpoint - ID", it->id);
          std::vector<uint8_t> matchedIssuerId = issuer.id;
          issuer.endpoints.erase(it);
          store.save();
          return std::make_tuple(matchedIssuerId, SUCCESS);
        }
      }
    }
    LOG(D, "Endpoint missing across all issuers");
    return {std::vector<uint8_t>{}, DOES_NOT_EXIST};
  }

  LOG(E, "Invalid remove DCR: missing issuer ID, key ID, and public key");
  return {std::vector<uint8_t>{}, DOES_NOT_EXIST};
}

int HK_HomeKit::set_reader_key(const std::vector<uint8_t>& buf) {
  LOG(D, "Setting reader key (%d bytes, redacted)", (int)buf.size());
  TLV8 rkrTLv;
  rkrTLv.parse(buf.data(), buf.size());
  if (!rkrTLv.ok()) {
    LOG(E, "RKR TLV parse error");
    return -1;
  }
  tlv_it tlvReaderKey = rkrTLv.find(kReader_Req_Reader_Private_Key);
  if (tlvReaderKey == rkrTLv.end()) { LOG(D, "kReader_Req_Reader_Private_Key not found"); return -1; }
  std::vector<uint8_t> readerKey = tlvReaderKey->value;
  tlv_it tlvUniqueId = rkrTLv.find(kReader_Req_Identifier);
  if (tlvUniqueId == rkrTLv.end()) { LOG(D, "kReader_Req_Identifier not found"); return -1; }
  std::vector<uint8_t> uniqueIdentifier = tlvUniqueId->value;
  if (readerKey.empty() || uniqueIdentifier.empty()) {
    LOG(E, "RKR contains empty key or identifier");
    return -1;                                  // ← delta 1, see below
  }

  std::vector<uint8_t> pubKey = CommonCryptoUtils::derive_public_key(readerKey);
  if (pubKey.empty()) {
    LOG(E, "Failed to derive reader public key");
    return -1;                                  // ← delta 2, see below
  }
  std::vector<uint8_t> x_coordinate = CommonCryptoUtils::get_x(pubKey);
  LOG(D, "%s", redactHex("X coordinate", x_coordinate).c_str());

  ddk::ReaderIdentity identity;
  identity.private_key     = readerKey;
  identity.public_key      = std::move(pubKey);
  identity.public_key_x    = std::move(x_coordinate);
  identity.sub_identifier  = uniqueIdentifier;

  std::vector<uint8_t> gid_hash = CommonCryptoUtils::hash_identifier_sha256(readerKey);
  identity.group_identifier.assign(
      gid_hash.begin(), gid_hash.begin() + std::min<size_t>(8, gid_hash.size()));
  store.provision_identity(identity);

  LOG(D, "identity sizes: sk=%zu pk=%zu pkx=%zu gid=%zu sub=%zu cert=%d",
      identity.private_key.size(),
      identity.public_key.size(),
      identity.public_key_x.size(),
      identity.group_identifier.size(),
      identity.sub_identifier.size(),
      identity.certificate.has_value());

  LOG(D, "issuers count: %zu", store.issuers().size());
  for (size_t i = 0; i < store.issuers().size(); ++i) {
      auto& iss = store.issuers()[i];
      LOG(D, "issuer[%zu] id=%zu pk=%zu pkx=%zu endpoints=%zu",
          i, iss.id.size(), iss.public_key.size(),
          iss.public_key_x.size(), iss.endpoints.size());
  }
  store.save();
  return 0;
}
