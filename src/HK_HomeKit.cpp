#include <HK_HomeKit.h>
#include "CommonCryptoUtils.h"
#include "TLV8.hpp"
#include "logging.h"
#include <mbedtls/ecp.h>
#include <mbedtls/sha256.h>
#include <mbedtls/sha1.h>
#include <mbedtls/error.h>
#include <vector>
#include "fmt/base.h"
#include <fmt/ranges.h>

std::mutex HK_HomeKit::provision_mutex;

HK_HomeKit::HK_HomeKit(readerData_t& readerData, std::function<void(const readerData_t&)> save_cb, std::function<void()> remove_key_cb, std::vector<uint8_t>& tlvData) : tlvData(tlvData), readerData(readerData), save_cb(save_cb), remove_key_cb(remove_key_cb) { }

std::vector<uint8_t> HK_HomeKit::processResult() {
  tlv_it operation;
  tlv_it RKR;
  tlv_it DCR;
  TLV8 rxTlv;
  rxTlv.parse(tlvData.data(), tlvData.size());
  operation = rxTlv.find(kReader_Operation);
  RKR = rxTlv.find(kReader_Reader_Key_Request);
  DCR = rxTlv.find(kReader_Device_Credential_Request);
  if (operation != rxTlv.end() && operation->length() > 0) {
    LOG(I, "TLV OPERATION: %d", *operation->data());
    if (*operation->data() == kReader_Operation_Read)
      if ((*RKR).tag == kReader_Reader_Key_Request) {
        LOG(I,"GET READER KEY REQUEST");
        if (readerData.reader_sk.size() > 0) {
          TLV8 getResSub;
          getResSub.add(kReader_Res_Key_Identifier, readerData.reader_gid);
          std::vector<uint8_t> subTlv = getResSub.get();
          LOG(D, "SUB-TLV LENGTH:  %d, DATA: %s", (int)subTlv.size(), fmt::format("{:02X}", fmt::join(subTlv, "")).c_str());
          TLV8 getResTlv;
          getResTlv.add(kReader_Res_Reader_Key_Response, subTlv);
          std::vector<uint8_t> tlvRes = getResTlv.get();
          LOG(D, "TLV LENGTH: %d, DATA: %s", (int)tlvRes.size(), fmt::format("{:02X}", fmt::join(tlvRes, "")).c_str());
          return tlvRes;
        }
        return std::vector<uint8_t>{  };
      }
  }
  if (operation != rxTlv.end() && *operation->data() == kReader_Operation_Write) {
    if (RKR != rxTlv.end()) {
      LOG(I,"TLV RKR: %d", RKR->length());
      LOG(I,"SET READER KEY REQUEST");
      int ret = set_reader_key(RKR->value);
      if (ret == 0) {
        LOG(I,"READER KEY SAVED TO NVS, COMPOSING RESPONSE");
        TLV8 rkResSub;
        rkResSub.add(kReader_Res_Status, 0);
        std::vector<uint8_t> rkSubTlv = rkResSub.get();
        LOG(D, "SUB-TLV LENGTH: %d, DATA: %s", (int)rkSubTlv.size(), fmt::format("{:02X}", fmt::join(rkSubTlv, "")).c_str());
        TLV8 rkResTlv;
        rkResTlv.add(kReader_Res_Reader_Key_Response, rkSubTlv);
        std::vector<uint8_t> rkRes = rkResTlv.get();
        return rkRes;
      }
    }
    else if (DCR != rxTlv.end()) {
      LOG(I,"TLV DCR: %d",DCR->length());
      LOG(D,"PROVISION DEVICE CREDENTIAL REQUEST");
      auto state = provision_device_cred(DCR->value);
      if (std::get<1>(state) != 99 && std::get<0>(state).size() > 0) {
        TLV8 dcrResSubTlv;
        dcrResSubTlv.add(kDevice_Res_Issuer_Key_Identifier, std::get<0>(state).size(), std::get<0>(state).data());
        dcrResSubTlv.add(kDevice_Res_Status, std::get<1>(state));
        std::vector<uint8_t> packedRes = dcrResSubTlv.get();
        LOG(D,"SUB-TLV: %d",(int)packedRes.size());
        LOG(D,"SUB-TLV: %s", fmt::format("{:02X}", fmt::join(packedRes, "")).c_str());
        TLV8 dcrResTlv;
        dcrResTlv.add(kDevice_Credential_Response, packedRes);
        std::vector<uint8_t> result = dcrResTlv.get();
        LOG(D,"TLV: %d", (int)result.size());
        LOG(D,"TLV: %s", fmt::format("{:02X}", fmt::join(result, "")).c_str());
        return result;
      }
    }
  }
  if (operation != rxTlv.end() && *operation->data() == kReader_Operation_Remove)
    if (RKR != rxTlv.end()) {
      LOG(I,"REMOVE READER KEY REQUEST");
      readerData.reader_gid.clear();
      readerData.reader_id.clear();
      readerData.reader_sk.clear();
      save_cb(readerData);
      return std::vector<uint8_t>{ 0x7, 0x3, 0x2, 0x1, 0x0 };
    }
  return std::vector<uint8_t>();
}

std::vector<uint8_t> HK_HomeKit::get_x(std::vector<uint8_t> &pubKey)
{
  CommonCryptoUtils::EcpGroupGuard grp;
  CommonCryptoUtils::EcpPointGuard point;
  mbedtls_ecp_group_load(grp, MBEDTLS_ECP_DP_SECP256R1);
  int ecp_read = mbedtls_ecp_point_read_binary(grp, point, pubKey.data(), pubKey.size());
  if(ecp_read != 0)
    LOG(E, "ecp_read - %d", ecp_read);
  size_t buffer_size_x = mbedtls_mpi_size(&point.pt.MBEDTLS_PRIVATE(X));
  std::vector<uint8_t> X(buffer_size_x);
  int ecp_write = mbedtls_mpi_write_binary(&point.pt.MBEDTLS_PRIVATE(X), X.data(), buffer_size_x);
  if(ecp_write != 0)
    LOG(E, "ecp_write - %d", ecp_write);
  LOG(V, "PublicKey: %s, X Coordinate: %s", fmt::format("{:02X}", fmt::join(pubKey, "")).c_str(), fmt::format("{:02X}", fmt::join(X, "")).c_str());
  return X;
}

std::vector<uint8_t> HK_HomeKit::getPublicKey(uint8_t *privKey, size_t len)
{
  CommonCryptoUtils::EcpKeyPairGuard keypair;
  int ecp_key = mbedtls_ecp_read_key(MBEDTLS_ECP_DP_SECP256R1, keypair, privKey, len);
  if(ecp_key != 0){
    LOG(E, "ecp_read_key - %d", ecp_key);
    return std::vector<uint8_t>();
  }
  int ret = mbedtls_ecp_mul(&keypair.kp.MBEDTLS_PRIVATE(grp), &keypair.kp.MBEDTLS_PRIVATE(Q), &keypair.kp.MBEDTLS_PRIVATE(d), &keypair.kp.MBEDTLS_PRIVATE(grp).G, CommonCryptoUtils::esp_rng, NULL);
  if (ret != 0) {
    LOG(E, "mbedtls_ecp_mul - %d", ret);
    return std::vector<uint8_t>();
  }
  size_t olenPub = 0;
  std::vector<uint8_t> readerPublicKey(MBEDTLS_ECP_MAX_PT_LEN);
  int write_ret = mbedtls_ecp_point_write_binary(&keypair.kp.MBEDTLS_PRIVATE(grp), &keypair.kp.MBEDTLS_PRIVATE(Q), MBEDTLS_ECP_PF_UNCOMPRESSED, &olenPub, readerPublicKey.data(), readerPublicKey.capacity());
  if (write_ret != 0) {
    LOG(E, "mbedtls_ecp_point_write_binary - %d", write_ret);
    return std::vector<uint8_t>();
  }
  readerPublicKey.resize(olenPub);
  return readerPublicKey;
}

std::vector<uint8_t> HK_HomeKit::getHashIdentifier(const std::vector<uint8_t>& key, bool sha256) {
  // ESP_LOGV(TAG, "Key: {}, Length: {}, sha256?: {}", bufToHexString(key.data(), key.size()).c_str(), key.size(), sha256);
  std::vector<unsigned char> hashable;
  if (sha256) {
    std::string string = "key-identifier";
    hashable.insert(hashable.begin(), string.begin(), string.end());
  }
  hashable.insert(hashable.end(), key.begin(), key.end());
  // ESP_LOGV(TAG, "Hashable: {}", bufToHexString(&hashable.front(), hashable.size()).c_str());
  std::vector<uint8_t> hash(32);
  if (sha256) {
    mbedtls_sha256(&hashable.front(), hashable.size(), hash.data(), 0);
  }
  else {
    mbedtls_sha1(&hashable.front(), hashable.size(), hash.data());
  }
  // ESP_LOGD(TAG, "HashIdentifier: {}", bufToHexString(hash.data(), 32).c_str());
  return hash;
}

std::tuple<std::vector<uint8_t>, int> HK_HomeKit::provision_device_cred(std::vector<uint8_t> buf) {
  std::lock_guard<std::mutex> lock(provision_mutex);
  LOG(D, "DCReq Buffer length: %d (data redacted)", (int)buf.size());
  TLV8 dcrTlv;
  dcrTlv.parse(buf.data(), buf.size());
  hkIssuer_t* foundIssuer = nullptr;
  const tlv_t* tlvIssuerId = dcrTlv.expect(kDevice_Req_Issuer_Key_Identifier);
  if (tlvIssuerId == nullptr) {
    LOG(E, "Issuer Key Identifier missing from DCR");
    return std::make_tuple(readerData.reader_gid, DOES_NOT_EXIST);
  }
  std::vector<uint8_t> issuerIdentifier = tlvIssuerId->value;
  if (issuerIdentifier.size() > 0) {
    for (auto& issuer : readerData.issuers) {
      if (CommonCryptoUtils::constant_time_compare(issuer.issuer_id, issuerIdentifier)) {
        LOG_HEX_FMT(D, "Found issuer - ID", issuer.issuer_id);
        foundIssuer = &issuer;
      }
    }
    if (foundIssuer != nullptr) {
      hkEndpoint_t* foundEndpoint = nullptr;
      const tlv_t* tlvDevicePubKey = dcrTlv.expect(kDevice_Req_Public_Key);
      if (tlvDevicePubKey == nullptr) {
        LOG(E, "Device Public Key missing from DCR");
        return std::make_tuple(issuerIdentifier, DOES_NOT_EXIST);
      }
      std::vector<uint8_t> devicePubKey = tlvDevicePubKey->value;
      devicePubKey.insert(devicePubKey.begin(), 0x04);
      std::vector<uint8_t> hash = getHashIdentifier(devicePubKey, false);
      std::vector<uint8_t> endpointId(hash.begin(), hash.begin() + 6);
      for (auto& endpoint : foundIssuer->endpoints) {
        if (CommonCryptoUtils::constant_time_compare(endpoint.endpoint_id, endpointId)) {
          LOG_HEX_FMT(D, "Found endpoint - ID", endpoint.endpoint_id);
          foundEndpoint = &endpoint;
        }
      }
      if (foundEndpoint == nullptr) {
        LOG(D, "Adding new endpoint - ID: %s , %s", fmt::format("{:02X}", fmt::join(endpointId, "")).c_str(), redactHex("PK", devicePubKey.data(), devicePubKey.size()).c_str());
        hkEndpoint_t endpoint;
        std::vector<uint8_t> x_coordinate = get_x(devicePubKey);
        const tlv_t* tlvKeyType = dcrTlv.expect(kDevice_Req_Key_Type);
        if (tlvKeyType == nullptr || tlvKeyType->value.empty()) {
          LOG(E, "Key Type missing from DCR");
          return std::make_tuple(issuerIdentifier, DOES_NOT_EXIST);
        }
        std::vector<uint8_t> keyType = tlvKeyType->value;
        endpoint.counter = 0;
        endpoint.key_type = *keyType.data();
        endpoint.last_used_at = 0;
        // endpoint.enrollments.hap = hap;
        endpoint.endpoint_id = std::vector<uint8_t>{ endpointId.begin(), endpointId.begin() + 6 };
        endpoint.endpoint_pk = devicePubKey;
        endpoint.endpoint_pk_x = x_coordinate;
        foundIssuer->endpoints.emplace_back(endpoint);
        save_cb(readerData);
        return std::make_tuple(foundIssuer->issuer_id, SUCCESS);
      }
      else {
        LOG_HEX_FMT(D, "Endpoint already exists - ID", foundEndpoint->endpoint_id);
        save_cb(readerData);
        return std::make_tuple(issuerIdentifier, DUPLICATE);
      }
    }
    else {
      LOG_HEX_FMT(D, "Issuer does not exist - ID", issuerIdentifier);
      save_cb(readerData);
      return std::make_tuple(issuerIdentifier, DOES_NOT_EXIST);
    }
  }
  return std::make_tuple(readerData.reader_gid, DOES_NOT_EXIST);
}

int HK_HomeKit::set_reader_key(std::vector<uint8_t>& buf) {
  LOG(D, "Setting reader key (%d bytes, redacted)", (int)buf.size());
  TLV8 rkrTLv;
  rkrTLv.parse(buf.data(), buf.size());
  tlv_it tlvReaderKey = rkrTLv.find(kReader_Req_Reader_Private_Key);
  if(tlvReaderKey == rkrTLv.end()){ LOG(D, "kReader_Req_Reader_Private_Key not found"); return -1;}
  std::vector<uint8_t> readerKey = tlvReaderKey->value;
  tlv_it tlvUniqueId = rkrTLv.find(kReader_Req_Identifier);
  if(tlvUniqueId == rkrTLv.end()){ LOG(D, "kReader_Req_Identifier not found"); return -1;}
  std::vector<uint8_t> uniqueIdentifier = tlvUniqueId->value;
  if (readerKey.size() > 0 && uniqueIdentifier.size() > 0) {
    LOG(D, "%s", redactHex("Reader Key (private)", readerKey.data(), readerKey.size()).c_str());
    LOG(D, "%s", redactHex("UniqueIdentifier", uniqueIdentifier.data(), uniqueIdentifier.size()).c_str());
    std::vector<uint8_t> pubKey = getPublicKey(readerKey.data(), readerKey.size());
    LOG(D, "%s", redactHex("Reader public key", pubKey.data(), pubKey.size()).c_str());
    std::vector<uint8_t> x_coordinate = get_x(pubKey);
    LOG(D, "%s", redactHex("X coordinate", x_coordinate.data(), x_coordinate.size()).c_str());
    readerData.reader_pk_x = x_coordinate;
    readerData.reader_pk = pubKey;
    readerData.reader_sk = readerKey;
    readerData.reader_id = uniqueIdentifier;
    std::vector<uint8_t> readeridentifier = getHashIdentifier(readerData.reader_sk, true);
    LOG(D, "%s", redactHex("Reader GroupIdentifier", readeridentifier.data(), readeridentifier.size()).c_str());
    readerData.reader_gid = std::vector<uint8_t>{readeridentifier.begin(), readeridentifier.begin() + 8};
    save_cb(readerData);
  }
  return 0;
}
