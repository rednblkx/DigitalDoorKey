#include "aliro/Profile.h"
#include "AuthParams.h"
#include "BerTlv.h"
#include "CommonCryptoUtils.h"
#include "FastAuth.h"
#include "StandardAuth.h"
#include "TLV8.hpp"
#include "ddk/session/AuthOutcome.h"
#include "ddk/store/CredentialStore.h"
#include "DDKLogging.h"
#include "simple_tlv.hpp"
#include <cstring>

namespace ddk::aliro {

constexpr const char* TAG = "AliroProfile";

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

    auto fci = BerTlvMessage::from_bytes(select_response.data(), len);

    const BerTlv* proprietary = fci.find(0xA5);
    if (!proprietary) {
        LOG(E, "Aliro SELECT: missing FCI proprietary template (0xA5)");
        return FailureReason::VersionMismatch;
    }

    auto inner = proprietary->parse_inner();

    const BerTlv* version = inner.find(0x5C);
    if (!version || version->value.size() < 2) {
        LOG(E, "Aliro SELECT: missing protocol version (0x5C)");
        return FailureReason::VersionMismatch;
    }

    if (version->value[0] != 0x01 || version->value[1] != 0x00) {
        LOG(E, "Aliro v1.0 required, got %02X.%02X",
             version->value[0], version->value[1]);
        return FailureReason::VersionMismatch;
    }

    const BerTlv* ext_info = inner.find({0x7F, 0x66});
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

    auto& transcript = session.transcript();
    transcript.fci_proprietary.assign(select_response.data(), select_response.data() + len);
    transcript.protocol_version = {0x01, 0x00};
    transcript.interface = 0x5E;  // NFC — verify against interface.py

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

  DDKAuthParams auth_params{
      kAliro,                             // ← kAliro, not kHomeKey
      store,
      transcript.reader_eph_x,
      transcript.endpoint_eph_pub,
      transcript.endpoint_eph_x,
      transcript.transaction_id,
      transcript.reader_identifier,
      transcript.fci_proprietary,         // ← from SELECT, not empty
      transcript.protocol_version,        // {0x01, 0x00} from validate_select
      nullptr, nullptr,
      flags,
      nullptr,
      &session.apdu(),
  };
  auth_params.readerEphPrivKey = &transcript.reader_eph_priv;
  auth_params.readerEphPubKey  = &transcript.reader_eph_pub;

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
      control_flow(session, 0x0, 0x1);
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
      if(flowUsed >= kFlowSTANDARD){
        store.save();
      }
    }
    if (foundIssuer && foundEndpoint && flowUsed != kFlowFailed) {
      if (flowUsed < kFlowATTESTATION) {
        control_flow(session, 0x01, 0x01);
      }
      result_ = {foundIssuer->id, foundEndpoint->id, flowUsed};
      return FlowState::Done;
    } else {
      control_flow(session, 0x0, 0x1);
      return FlowState::Failed;
    }
  }
  control_flow(session, 0x0, 0x1);
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
    } else {
        outcome.state = FlowState::Failed;
        outcome.reason = FailureReason::Auth0Reject;
    }

    return outcome;
}

ApduResponse Profile::exchange(
    Session& session, std::span<const uint8_t> tlvs)
{
    // Post-auth EXCHANGE via GCM secure channel.
    // Not implemented yet — the secure context isn't exposed from the auth flow.
    // Will be filled when AliroSecureContext is integrated.
    return {};
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
