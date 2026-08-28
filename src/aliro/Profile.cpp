#include "aliro/Profile.h"
#include "AliroKeySchedule.h"
#include "AliroStdAuth.h"
#include "AliroStepUp.h"
#include "BerTlv.h"
#include "CommonCryptoUtils.h"
#include "AliroFastAuth.h"
#include "TLV8.hpp"
#include "ddk/session/AuthOutcome.h"
#include "ddk/store/CredentialStore.h"
#include "DDKLogging.h"
#include "esp_random.h"
#include "simple_tlv.hpp"
#include <cstring>
#include "AliroSecureContext.h"
#include "ddk/store/ReaderIdentity.h"

namespace ddk::aliro {

constexpr const char* TAG = "AliroProfile";

Profile::Profile(CredentialStore& store) : store_(store) {}

FailureReason Profile::validate_select(
    Session& session, ddk::span<const uint8_t> select_response)
{
    size_t len = select_response.size();
    if (len >= 2 &&
        select_response[len - 2] == 0x90 && select_response[len - 1] == 0x00)
    {
        len -= 2;
    }

    auto select_parsed = BerTlvMessage::from_bytes(select_response.data(), len);

    const BerTlv* fci = select_parsed.find(0x6F);
    if (!fci) {
        LOG(E, "Aliro SELECT: missing FCI template (0x6F)");
        return FailureReason::VersionMismatch;
    }
    auto fci_inner = fci->parse_inner();
    const BerTlv* proprietary = fci_inner.find(0xA5);

    auto proprietary_inner = proprietary->parse_inner();
    const BerTlv* version = proprietary_inner.find(0x5C);
    if (!version || version->value.empty() || version->value.size() % 2 != 0) {
        LOG(E, "Aliro SELECT: missing or malformed version list (0x5C)");
        return FailureReason::VersionMismatch;
    }
    bool v10_supported = false;
    for (size_t i = 0; i + 1 < version->value.size(); i += 2) {
        if (version->value[i] == 0x01 && version->value[i + 1] == 0x00) {
            v10_supported = true;
            break;
        }
    }
    if (!v10_supported) {
        LOG(E, "Aliro v1.0 not in supported versions list (%zu bytes)",
            version->value.size());
        return FailureReason::VersionMismatch;
    }

    const std::array<uint8_t,2> ext_info_tag{0x7F, 0x66};
    const BerTlv* ext_info = proprietary_inner.find(ext_info_tag);
    if (ext_info) {
        auto ext_inner = ext_info->parse_inner();
        const BerTlv* max_recv = ext_inner.find(0x02);
        if (max_recv && !max_recv->value.empty()) {
            max_command_data_size_ = 0;
            for (uint8_t b : max_recv->value)
                max_command_data_size_ = (max_command_data_size_ << 8) | b;
            LOG(I, "Aliro max_command_data_size: %zu", max_command_data_size_);
        }
    }

    const auto& identity = session.store().reader_identity();
    if (identity.group_identifier.size() != 16 ||
        identity.sub_identifier.size() != 16) {
        LOG(E, "Aliro reader identity must be gid(16)+sub(16), got %zu+%zu",
            identity.group_identifier.size(), identity.sub_identifier.size());
        return FailureReason::ChannelError;   // misprovisioned — fail fast
    }

    auto& transcript = session.transcript();
  
    transcript.protocol_version = {0x01, 0x00};
    transcript.flags[0] = (session.config().target_flow == Flow::Fast) ? 0x01 : 0x00;
    transcript.flags[1] = session.config().authentication_policy;
    transcript.interface = static_cast<uint8_t>(session.apdu().kind());
    auto& fci_buffer = transcript.fci_proprietary;
    fci_buffer.clear();
    fci_buffer.push_back(0xA5);
    const auto& pv = proprietary->value;
    if (pv.size() < 0x80) {
        fci_buffer.push_back(static_cast<uint8_t>(pv.size()));
    } else if (pv.size() <= 0xFF) {
        fci_buffer.push_back(0x81);
        fci_buffer.push_back(static_cast<uint8_t>(pv.size()));
    } else if (pv.size() <= 0xFFFF) {
        fci_buffer.push_back(0x82);
        fci_buffer.push_back(static_cast<uint8_t>(pv.size() >> 8));
        fci_buffer.push_back(static_cast<uint8_t>(pv.size() & 0xFF));
    }
    fci_buffer.insert(fci_buffer.end(), pv.begin(), pv.end());
    // Generate ephemeral key pair + transaction ID
    auto [priv, pub] = CommonCryptoUtils::generateEphemeralKey();
    transcript.reader_eph_priv = priv;
    transcript.reader_eph_pub  = pub;
    transcript.reader_eph_x    = CommonCryptoUtils::get_x(transcript.reader_eph_pub);
    esp_fill_random(transcript.transaction_id.data(), 16);
    LOG(I, "Aliro v1.0 validated, max_cmd=%zu, FCI=%zu bytes",
        max_command_data_size_, transcript.fci_proprietary.size());
    return FailureReason::None;
}

FlowState Profile::step(Session& session, FlowState current)
{
  if (current != FlowState::Selected || ran_) return current;
  ran_ = true;

  auto& transcript = session.transcript();
  auto& store = session.store();

  std::array<uint8_t,2> flags = transcript.flags;

  // AUTH0 APDU — Aliro adds 0x41/0x42 flags TLVs before common TLVs
  std::vector<uint8_t> fastTlv;
  auto txflags_tlv = simple_tlv(0x41, std::array<uint8_t,1>{flags[0]});
  std::copy(txflags_tlv.begin(), txflags_tlv.end(), std::back_inserter(fastTlv));
  auto txcode_tlv = simple_tlv(0x42, std::array<uint8_t,1>{flags[1]});
  std::copy(txcode_tlv.begin(), txcode_tlv.end(), std::back_inserter(fastTlv));

  auto version_tlv = simple_tlv(0x5C, transcript.protocol_version);
  std::copy(version_tlv.begin(), version_tlv.end(), std::back_inserter(fastTlv));
  auto reader_pk_tlv = simple_tlv(0x87, transcript.reader_eph_pub);
  std::copy(reader_pk_tlv.begin(), reader_pk_tlv.end(), std::back_inserter(fastTlv));
  auto txId_tlv = simple_tlv(0x4C, transcript.transaction_id);
  std::copy(txId_tlv.begin(), txId_tlv.end(), std::back_inserter(fastTlv));
  auto reader_id_tlv = simple_tlv(0x4D, transcript.reader_identifier);
  std::copy(reader_id_tlv.begin(), reader_id_tlv.end(), std::back_inserter(fastTlv));

  // Aliro: P1=0x00, P2=0x00 (not flags)
  std::vector<uint8_t> apdu{0x80, 0x80, 0x00, 0x00, static_cast<uint8_t>(fastTlv.size())};
  apdu.insert(apdu.end(), std::make_move_iterator(fastTlv.begin()),
              std::make_move_iterator(fastTlv.end()));

  auto response = session.apdu().transceive(apdu);

  if (response.ok() && response.data.size() > 64 && response.data[0] == 0x86) {
    TLV8 Auth0Res;
    Auth0Res.parse(response.data.data(), response.data.size());
    const tlv_t *pubkey = Auth0Res.expect(kEndpoint_Public_Key);
    // SEC1 uncompressed P-256 point: 0x04 prefix || X (32 bytes) || Y (32 bytes).
    constexpr size_t kP256UncompressedPublicKeySize = 1 + 32 + 32;
    if (!Auth0Res.ok() || pubkey == nullptr ||
        pubkey->value.size() != kP256UncompressedPublicKeySize) {
      LOG(E, "Auth0 response is malformed or has an invalid endpoint public key");
      control_flow(session, 0x0, 0x0);
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
        auto fastAuth = AliroFastAuth(session).attest(encryptedMessage);
        if (fastAuth && (flowUsed = fastAuth.flow) == kFlowFAST) {
            session.set_secure_context(std::make_unique<AliroSecureContext>(
              fastAuth.exchange_sk_reader, fastAuth.exchange_sk_device));
            foundIssuer = fastAuth.issuer;
            foundEndpoint = fastAuth.endpoint;
            LOG(D, "Endpoint %s Authenticated via FAST Flow", redactHex("", foundEndpoint->id.data(), foundEndpoint->id.size()).c_str());
        }
      } else {
        LOG(W, "Auth0 cryptogram missing; moving to STANDARD Flow");
      }
    }
    if(foundEndpoint == nullptr){
      auto stdAuth = AliroStdAuth(session).attest();
        session.set_secure_context(std::make_unique<AliroSecureContext>(
          std::move(stdAuth.gcm_context),
          stdAuth.step_up_sk_reader, stdAuth.step_up_sk_device));
      if (stdAuth) {
        foundIssuer = stdAuth.issuer;
        foundEndpoint = stdAuth.endpoint;
        if ((flowUsed = stdAuth.flow) == kFlowSTANDARD)
        {
          LOG(D, "Endpoint %s Authenticated via STANDARD Flow", redactHex("", foundEndpoint->id.data(), foundEndpoint->id.size()).c_str());
          foundEndpoint->persistent_key.clear();
          foundEndpoint->persistent_key.insert(foundEndpoint->persistent_key.begin(), stdAuth.persistent_key.begin(), stdAuth.persistent_key.end());
          LOG_HEX(V, "New Persistent Key", foundEndpoint->persistent_key);
        }
      }
      auto* ctx = static_cast<AliroSecureContext*>(session.secure_context());

      if (session.config().target_flow == Flow::StepUp) {
        if (ctx && ctx->step_up_channel()) {
          uint16_t bitmap = static_cast<uint16_t>(
              SignalingBitmask::AccessDocumentRetrievable |
              SignalingBitmask::StepUpSelectRequired);
          if (stdAuth.signaling_bitmap) {
            bitmap = (static_cast<uint16_t>((*stdAuth.signaling_bitmap)[0]) << 8)
                   | (*stdAuth.signaling_bitmap)[1];
          }
          auto scopes = session.config().step_up_scopes.value_or(
              std::map<std::string, bool>{{"id", false}});
          auto step = AliroStepUp(session, *ctx).run(
              static_cast<SignalingBitmask>(bitmap), scopes);
          if (step.success) {
            flowUsed = kFlowATTESTATION;
            foundIssuer = step.issuer;
            if (foundEndpoint == nullptr) {
              ddk::Endpoint endpoint;
              endpoint.public_key = step.endpoint_public_key;
              endpoint.public_key_x.assign(
                  step.endpoint_public_key.begin() + 1,
                  step.endpoint_public_key.begin() + 33);
              auto eId = CommonCryptoUtils::hash_identifier_sha1(
                  step.endpoint_public_key);
              endpoint.id.assign(eId.begin(), eId.begin() + 6);
              foundEndpoint = &*foundIssuer->endpoints.emplace(
                  foundIssuer->endpoints.end(), std::move(endpoint));
            }
            AliroKeySchedule schedule;
            AliroKeySchedule::SessionInput input{
                store.reader_identity().public_key_x,
                transcript.reader_identifier,
                transcript.reader_eph_x,
                transcript.endpoint_eph_x,
                transcript.transaction_id,
                transcript.protocol_version,
                transcript.flags,
                transcript.fci_proprietary,
                transcript.interface,
                transcript.auth0_info_suffix,
            };
            auto Kpersistent = schedule.derive_persistent(
                input, stdAuth.derived_key, foundEndpoint->public_key_x);
            foundEndpoint->persistent_key.assign(Kpersistent.begin(), Kpersistent.end());
            LOG_HEX(D, "StepUp Provisioned Persistent Key",
                    foundEndpoint->persistent_key);
          }
        }
      }
      if (foundEndpoint) {
        foundEndpoint->aliro.key_slot = stdAuth.key_slot;
        if (stdAuth.signaling_bitmap) {
          foundEndpoint->aliro.signaling_bitmask =
              (static_cast<uint16_t>((*stdAuth.signaling_bitmap)[0]) << 8)
            | (*stdAuth.signaling_bitmap)[1];
        }
        foundEndpoint->aliro.credential_signed_timestamp =
            stdAuth.credential_signed_timestamp;
        foundEndpoint->aliro.revocation_signed_timestamp =
            stdAuth.revocation_signed_timestamp;
        foundEndpoint->aliro.last_flow = flowUsed;
      }
      if(flowUsed >= kFlowSTANDARD){
        store.save();
      }
    }
    if (foundIssuer && foundEndpoint && flowUsed != kFlowFailed) {
      if (!complete(session, ReaderStatus::StateUnsecure)) {
        LOG(W, "Completion delivery failed; auth result stands");
      }
      result_ = {foundIssuer->id, foundEndpoint->id, flowUsed};
      return FlowState::Done;
    }
    if (session.secure_context()) {
      complete(session, ReaderStatus::PublicKeyNotFound);
    } else {
      control_flow(session, 0x00, 0x00);   // no channel — row 9
    }
    return FlowState::Failed;
  }
  control_flow(session, 0x0, 0x0);
  return FlowState::Failed;
}

bool Profile::complete(Session& session, ReaderStatus status)
{
    auto* ctx = static_cast<AliroSecureContext*>(session.secure_context());
    uint16_t s = static_cast<uint16_t>(status);
    std::vector<uint8_t> payload{0x97, 0x02,
        static_cast<uint8_t>(s >> 8), static_cast<uint8_t>(s & 0xFF)};

    if (ctx) {
        auto resp = ctx->exchange(session, payload, /*skip_response_chaining=*/true);
        if (resp.sw1 == 0x90 || resp.sw1 == 0x61)
            return true;
        LOG(W, "Completion EXCHANGE failed (SW %02X%02X) — CONTROL FLOW fallback",
            resp.sw1, resp.sw2);
    }
    control_flow(session, 0x00, 0x00);
    return false;
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
    } else {
        outcome.state = FlowState::Failed;
        outcome.reason = FailureReason::Auth0Reject;
    }

    return outcome;
}

ApduResponse Profile::control_flow(
    Session& session, uint8_t s1, uint8_t s2)
{
    // Aliro CONTROL FLOW: CLA=0x80, INS=0x3C, P1=0x00, P2=0x00
    // Data: BER-TLV body: 0x41 0x01 <s1> 0x42 0x01 <s2>
    std::vector<uint8_t> apdu = {
        0x80, 0x3C, 0x00, 0x00,
        0x06,
        0x41, 0x01, s1,
        0x42, 0x01, s2
    };
    LOG_HEX(D, "Aliro Control Flow APDU", apdu);
    return session.apdu().transceive(apdu);
}

}  // namespace ddk::aliro
