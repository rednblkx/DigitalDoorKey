#include "homekey/Profile.h"
#include "AuthParams.h"
#include "CommonCryptoUtils.h"
#include "DDKReaderData.h"
#include "TLV8.hpp"
#include "ddk/session/AuthOutcome.h"
#include "ddk/session/Flow.h"
#include "ddk/store/CredentialStore.h"
#include "DDKLogging.h"
#include "esp_random.h"
#include "simple_tlv.hpp"
#include "FastAuth.h"
#include "StandardAuth.h"
#include "AttestationAuth.h"
#include <chrono>

namespace ddk::homekey {

constexpr const char* TAG = "HKProfile";

Profile::Profile(CredentialStore& store) : store_(store) {}

FailureReason Profile::validate_select(
    Session& session, std::span<const uint8_t> select_response)
{
    size_t len = select_response.size();
    if (len >= 2 &&
        select_response[len - 2] == 0x90 && select_response[len - 1] == 0x00)
    {
        len -= 2;
    }

    TLV8 tlv;
    tlv.parse(select_response.data(), len);

    const tlv_t* versions = tlv.expect(0x5C);
    if (!versions || versions->value.size() < 2) {
        LOG(E, "SELECT response missing protocol versions (0x5C)");
        return FailureReason::VersionMismatch;
    }

    const auto& v = versions->value;
    bool v20_supported = false;
    for (size_t i = 0; i + 1 < v.size(); i += 2) {
        if (v[i] == 0x02 && v[i + 1] == 0x00) {
            v20_supported = true;
            break;
        }
    }

    if (!v20_supported) {
        LOG(E, "HomeKey v2.0 not in supported versions list");
        return FailureReason::VersionMismatch;
    }

    session.transcript().protocol_version = {0x02, 0x00};

    auto startTime = std::chrono::high_resolution_clock::now();;
    auto& transcript = session.transcript();
    auto [priv, pub] = CommonCryptoUtils::generateEphemeralKey();
    transcript.reader_eph_priv = priv;
    transcript.reader_eph_pub  = pub;
    transcript.reader_eph_x     = CommonCryptoUtils::get_x(transcript.reader_eph_pub);

#if defined(CONFIG_IDF_CMAKE)
    esp_fill_random(transcript.transaction_id.data(), 16);
#else
    randombytes(transcript.transaction_id.data(), 16);
#endif
    LOG(I, "Ephemeral keys generated in %lli ms", std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - startTime).count());
    return FailureReason::None;
}

FlowState Profile::step(Session& session, FlowState current)
{
    auto startTime = std::chrono::high_resolution_clock::now();
    if (current != FlowState::Selected || ran_) return current;
    ran_ = true;

    auto& transcript = session.transcript();
    auto& store = session.store();

    std::array<uint8_t,2> flags = transcript.flags;
    std::vector<uint8_t> aliroFCI;  // empty for HomeKey

    DDKAuthParams auth_params{
        kHomeKey,
        store,
        transcript.reader_eph_x,
        transcript.endpoint_eph_pub,
        transcript.endpoint_eph_x,
        transcript.transaction_id,
        transcript.reader_identifier,
        aliroFCI,
        transcript.protocol_version,
        &transcript.reader_eph_priv,
        &transcript.reader_eph_pub,
        flags,
        nullptr,                    // scb_context — set after STANDARD
        &session.apdu(),
    };
  
    std::vector<uint8_t> fastTlv;
    fastTlv.reserve(transcript.protocol_version.size() + transcript.reader_eph_pub.size() + transcript.transaction_id.size() + transcript.reader_identifier.size() + 8); // +8 for TLV overhead
    auto version_tlv = simple_tlv(0x5C, transcript.protocol_version);
    std::copy(version_tlv.begin(), version_tlv.end(), std::back_inserter(fastTlv));

    auto reader_pk_tlv = simple_tlv(0x87, transcript.reader_eph_pub);
    std::copy(reader_pk_tlv.begin(), reader_pk_tlv.end(), std::back_inserter(fastTlv));

    auto txId_tlv = simple_tlv(0x4C, transcript.transaction_id);
    std::copy(txId_tlv.begin(), txId_tlv.end(), std::back_inserter(fastTlv));

    auto reader_id_tlv = simple_tlv(0x4D, transcript.reader_identifier);
    std::copy(reader_id_tlv.begin(), reader_id_tlv.end(), std::back_inserter(fastTlv));
    std::vector<uint8_t> apdu{0x80, 0x80, transcript.flags[0], flags[1], static_cast<uint8_t>(fastTlv.size())};

    apdu.insert(apdu.end(), std::make_move_iterator(fastTlv.begin()), std::make_move_iterator(fastTlv.end()));
    LOG(D, "%s", redactHex("Auth0 APDU", apdu).c_str());
    auto response = session.apdu().transceive(apdu);
#if defined(CONFIG_IDF_CMAKE)
    ESP_LOG_BUFFER_HEX_LEVEL(TAG, response.data.data(), response.data.size(), ESP_LOG_VERBOSE);
#else
    for (int i = 0; i < response.data.size(); i++) {
      printf("%02X", response.data[i]);
    }
#endif
    LOG(D, "%s", redactHex("Auth0 Response", response.data).c_str());
  if (response.ok() && response.data.size() > 64 && response.data[0] == 0x86) {
    TLV8 Auth0Res;
    Auth0Res.parse(response.data.data(), response.data.size());
    const tlv_t *pubkey = Auth0Res.expect(kEndpoint_Public_Key);
    // SEC1 uncompressed P-256 point: 0x04 prefix || X (32 bytes) || Y (32 bytes).
    constexpr size_t kP256UncompressedPublicKeySize = 1 + 32 + 32;
    if (!Auth0Res.ok() || pubkey == nullptr ||
        pubkey->value.size() != kP256UncompressedPublicKeySize) {
      LOG(E, "Auth0 response is malformed or has an invalid endpoint public key");
      control_flow(session, kCmdFlowFailed, 0x0);
      return FlowState::Failed;
    }
    transcript.endpoint_eph_pub = pubkey->value;
    transcript.endpoint_eph_x = CommonCryptoUtils::get_x(transcript.endpoint_eph_pub);
    ddk::Issuer *foundIssuer = nullptr;
    ddk::Endpoint *foundEndpoint = nullptr;
    KeyFlow flowUsed = kFlowFailed;
    if (session.config().target_flow == Flow::Fast) {
      const tlv_t *crypt = Auth0Res.expect(kAuth0_Cryptogram);
      if (crypt != nullptr) {
        std::vector<uint8_t> encryptedMessage = crypt->value;
        auto fastAuth = DDKFastAuth(auth_params).attest(encryptedMessage);
        if (fastAuth && (flowUsed = fastAuth.flow) == kFlowFAST) {
            foundIssuer = fastAuth.issuer;
            foundEndpoint = fastAuth.endpoint;
            LOG(D, "Endpoint %s Authenticated via FAST Flow", redactHex("", foundEndpoint->id.data(), foundEndpoint->id.size()).c_str());
        }
      } else {
        LOG(W, "Auth0 cryptogram missing; moving to STANDARD Flow");
      }
    }
    if(foundEndpoint == nullptr){
      auto stdAuth = DDKStdAuth(auth_params).attest();
      if (stdAuth) {
        foundIssuer = stdAuth.issuer;
        foundEndpoint = stdAuth.endpoint;
        if ((flowUsed = stdAuth.flow) == kFlowSTANDARD)
        {
          LOG(D, "Endpoint %s Authenticated via STANDARD Flow", redactHex("", foundEndpoint->id.data(), foundEndpoint->id.size()).c_str());
          foundEndpoint->persistent_key.clear();
          foundEndpoint->persistent_key.insert(foundEndpoint->persistent_key.begin(), stdAuth.shared_secret.begin(), stdAuth.shared_secret.end());
          LOG_HEX(V, "New Persistent Key", foundEndpoint->persistent_key);
        }
      }
      if ((stdAuth.flow == kFlowNext || session.config().target_flow == Flow::StepUp) &&
          stdAuth.scb_context != nullptr) {
        auth_params.scb_context = stdAuth.scb_context.get();
        auto attestation = DDKAttestationAuth(auth_params).attest();
        if (attestation && (flowUsed = attestation.flow) == kFlowATTESTATION) {
          LOG(I, "ATTESTATION Flow complete, transaction took %lli ms", std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - startTime).count());
          if(foundEndpoint != nullptr){
            foundEndpoint->persistent_key.clear();
            foundEndpoint->persistent_key.insert(foundEndpoint->persistent_key.begin(), stdAuth.shared_secret.begin(), stdAuth.shared_secret.end());
          } else {
            ddk::Endpoint endpoint;
            foundIssuer = attestation.issuer;
            const std::array<uint8_t,65> devicePubKey = attestation.device_pub_key;
            std::vector<uint8_t> deviceKeyX = CommonCryptoUtils::get_x(attestation.device_pub_key);
            endpoint.public_key_x = deviceKeyX;
            std::vector<uint8_t> eId = CommonCryptoUtils::hash_identifier_sha1({devicePubKey.begin(), devicePubKey.end()});
            endpoint.id = std::vector<uint8_t>{eId.begin(), eId.begin() + 6};
            endpoint.public_key.assign(devicePubKey.begin(), devicePubKey.end());
            endpoint.persistent_key.clear();
            endpoint.persistent_key.assign(stdAuth.shared_secret.begin(), stdAuth.shared_secret.end());
            foundEndpoint = &(*foundIssuer->endpoints.emplace(foundIssuer->endpoints.end(),endpoint));
          }
          if(foundEndpoint != nullptr){
            LOG_HEX(V, "New Persistent Key", foundEndpoint->persistent_key);
            LOG(D, "Endpoint %s Authenticated via ATTESTATION Flow", redactHex("", foundEndpoint->id.data(), foundEndpoint->id.size()).c_str());
          }
        } else LOG(E, "STEPUP FAILED");
      }
      if(flowUsed >= kFlowSTANDARD){
        store.save();
      }
    }
    if (foundIssuer != nullptr && foundEndpoint != nullptr && flowUsed != kFlowFailed) {
        if (flowUsed < kFlowATTESTATION) {
          auto cf = control_flow(session, kCmdFlowSuccess, 0x0);
          if (!cf.ok()) {
              LOG(E, "Control Flow response not 0x90");
              result_.flow = kFlowFailed;
              return FlowState::Failed;
          }
        }

        result_.issuer_id = foundIssuer->id;
        result_.endpoint_id = foundEndpoint->id;
        result_.flow = flowUsed;
        return FlowState::Done;
    } else {
      control_flow(session, kCmdFlowFailed, 0x00);
      return FlowState::Failed;
    }
  }
  control_flow(session, kCmdFlowFailed, 0x00);
  LOG(E, "Response not valid, something went wrong!");
  return FlowState::Failed;
}

AuthOutcome Profile::finalize(Session& session)
{
    AuthOutcome outcome;

    if (result_.flow != kFlowFailed) {
        outcome.state = FlowState::Done;

        // Look up issuer + endpoint by ID in the store
        for (auto& issuer : store_.issuers()) {
            if (issuer.id == result_.issuer_id) {
                outcome.issuer = &issuer;
                for (auto& endpoint : issuer.endpoints) {
                    if (endpoint.id == result_.endpoint_id) {
                        outcome.endpoint = &endpoint;
                        break;
                    }
                }
                break;
            }
        }

        if (!outcome.issuer || !outcome.endpoint) {
            LOG(W, "finalize: issuer/endpoint not found in store "
                   "(ids may be stale)");
        }
    } else {
        outcome.state = FlowState::Failed;
        outcome.reason = FailureReason::Auth0Reject;  // coarse — refine later
    }

    return outcome;
}

ApduResponse Profile::exchange(
    Session& session, std::span<const uint8_t> tlvs)
{
    // Post-auth EXCHANGE via SCB secure channel.
    // Not implemented yet — attestation manages its own exchange internally.
    // Will be filled when the secure context is exposed from the auth flow.
    return {};
}

ApduResponse Profile::control_flow(
    Session& session, uint8_t s1, uint8_t s2)
{
    // HomeKey CONTROL FLOW: CLA=0x80, INS=0x3C, P1=status, P2=0x00
    std::vector<uint8_t> apdu = {0x80, 0x3c, s1, 0x00};
    return session.apdu().transceive(apdu);
}

}  // namespace ddk::homekey
