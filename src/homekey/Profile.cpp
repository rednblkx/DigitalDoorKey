#include "homekey/Profile.h"
#include "AuthParams.h"
#include "CommonCryptoUtils.h"
#include "DDKReaderData.h"
#include "HKFastAuth.h"
#include "HKStandardAuth.h"
#include "TLV8.hpp"
#include "ddk/session/AuthOutcome.h"
#include "ddk/session/Flow.h"
#include "ddk/store/CredentialStore.h"
#include "DDKLogging.h"
#include "esp_random.h"
#include "simple_tlv.hpp"
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

    // --- AUTH0 (always) ---

    std::vector<uint8_t> fastTlv;
    fastTlv.reserve(transcript.protocol_version.size() +
                    transcript.reader_eph_pub.size() +
                    transcript.transaction_id.size() +
                    transcript.reader_identifier.size() + 8);
    auto version_tlv = simple_tlv(0x5C, transcript.protocol_version);
    std::copy(version_tlv.begin(), version_tlv.end(), std::back_inserter(fastTlv));
    auto reader_pk_tlv = simple_tlv(0x87, transcript.reader_eph_pub);
    std::copy(reader_pk_tlv.begin(), reader_pk_tlv.end(), std::back_inserter(fastTlv));
    auto txId_tlv = simple_tlv(0x4C, transcript.transaction_id);
    std::copy(txId_tlv.begin(), txId_tlv.end(), std::back_inserter(fastTlv));
    auto reader_id_tlv = simple_tlv(0x4D, transcript.reader_identifier);
    std::copy(reader_id_tlv.begin(), reader_id_tlv.end(), std::back_inserter(fastTlv));

    std::vector<uint8_t> apdu{0x80, 0x80, transcript.flags[0], transcript.flags[1],
                              static_cast<uint8_t>(fastTlv.size())};
    apdu.insert(apdu.end(), std::make_move_iterator(fastTlv.begin()),
                std::make_move_iterator(fastTlv.end()));
    LOG(D, "%s", redactHex("Auth0 APDU", apdu).c_str());
    auto response = session.apdu().transceive(apdu);
    LOG(D, "%s", redactHex("Auth0 Response", response.data).c_str());

    if (!response.ok() || response.data.size() <= 64 || response.data[0] != 0x86) {
        LOG(E, "Auth0 response invalid");
        control_flow(session, kCmdFlowFailed, 0x0);
        return FlowState::Failed;
    }

    TLV8 Auth0Res;
    Auth0Res.parse(response.data.data(), response.data.size());
    const tlv_t* pubkey = Auth0Res.expect(kEndpoint_Public_Key);
    constexpr size_t kP256UncompressedPublicKeySize = 1 + 32 + 32;
    if (!Auth0Res.ok() || pubkey == nullptr ||
        pubkey->value.size() != kP256UncompressedPublicKeySize) {
        LOG(E, "Auth0 response is malformed or has an invalid endpoint public key");
        control_flow(session, kCmdFlowFailed, 0x0);
        return FlowState::Failed;
    }
    transcript.endpoint_eph_pub = pubkey->value;
    transcript.endpoint_eph_x = CommonCryptoUtils::get_x(transcript.endpoint_eph_pub);

    // --- Ladder state ---

    ddk::Issuer* foundIssuer = nullptr;
    ddk::Endpoint* foundEndpoint = nullptr;
    KeyFlow flowUsed = kFlowFailed;
    std::array<uint8_t,32> persistentKey{};

    auto target = session.config().target_flow;

    // --- Rung 1: FAST (entry rung only — cryptogram check is pointless after STANDARD) ---

    if (target == Flow::Fast) {
        const tlv_t* crypt = Auth0Res.expect(kAuth0_Cryptogram);
        if (crypt != nullptr) {
            auto fast = HomeKeyFastAuth(session).attest(crypt->value);
            if (fast && (flowUsed = fast.flow) == kFlowFAST) {
                foundIssuer = fast.issuer;
                foundEndpoint = fast.endpoint;
                LOG(D, "Endpoint %s Authenticated via FAST Flow",
                    redactHex("", foundEndpoint->id.data(), foundEndpoint->id.size()).c_str());
            } else {
                LOG(W, "FAST missed — descending to STANDARD");
            }
        } else {
            LOG(W, "Auth0 cryptogram missing — descending to STANDARD");
        }
    }

    // --- Rung 2: STANDARD (if FAST didn't hit, or wasn't the entry rung) ---

    if (foundEndpoint == nullptr) {
        auto std = HomeKeyStdAuth(session).attest();

        if (std.flow == kFlowSTANDARD && std.issuer && std.endpoint) {
            foundIssuer = std.issuer;
            foundEndpoint = std.endpoint;
            flowUsed = kFlowSTANDARD;
            persistentKey = std.persistent_key;
            LOG(D, "Endpoint %s Authenticated via STANDARD Flow",
                redactHex("", foundEndpoint->id.data(), foundEndpoint->id.size()).c_str());
        } else if (std.flow == kFlowFailed || !std.scb_context) {
            LOG(E, "STANDARD failed with no secure channel — cannot continue");
            control_flow(session, kCmdFlowFailed, 0x0);
            return FlowState::Failed;
        }
        persistentKey = std.persistent_key;

        // The channel becomes the session's secure context regardless of
        // STANDARD's outcome — attestation (next rung) and post-auth
        // exchange both need it.
        if (std.scb_context != nullptr) {
            auto ctx = std::make_unique<HKSecureContext>(
                std::move(std.scb_context));
            HKSecureContext* ctx_raw = ctx.get();
            session.set_secure_context(std::move(ctx));

            // --- Rung 3: StepUp ---
            if (std.flow == kFlowNext || target == Flow::StepUp) {
                auto att = HKAttestationAuth(session, ctx_raw->channel()).attest();
                if (att && (flowUsed = att.flow) == kFlowATTESTATION) {
                    foundIssuer = att.issuer;
                    if (foundEndpoint == nullptr) {
                        ddk::Endpoint endpoint;
                        const std::array<uint8_t,65> devicePubKey = att.device_pub_key;
                        endpoint.public_key_x = CommonCryptoUtils::get_x(att.device_pub_key);
                        auto eId = CommonCryptoUtils::hash_identifier_sha1(
                            {devicePubKey.begin(), devicePubKey.end()});
                        endpoint.id.assign(eId.begin(), eId.begin() + 6);
                        endpoint.public_key.assign(devicePubKey.begin(), devicePubKey.end());
                        foundEndpoint = &(*foundIssuer->endpoints.emplace(
                            foundIssuer->endpoints.end(), std::move(endpoint)));
                    }
                    LOG(I, "ATTESTATION Flow complete, transaction took %lli ms",
                        std::chrono::duration_cast<std::chrono::milliseconds>(
                            std::chrono::high_resolution_clock::now() - startTime).count());
                    LOG(D, "Endpoint %s Authenticated via ATTESTATION Flow",
                        redactHex("", foundEndpoint->id.data(), foundEndpoint->id.size()).c_str());
                } else {
                    LOG(E, "ATTESTATION failed");
                }
            }
        }
    }

    if (foundIssuer == nullptr || foundEndpoint == nullptr || flowUsed == kFlowFailed) {
        control_flow(session, kCmdFlowFailed, 0x0);
        return FlowState::Failed;
    }

    if (persistentKey != std::array<uint8_t,32>{}) {
        foundEndpoint->persistent_key.assign(persistentKey.begin(), persistentKey.end());
        LOG_HEX(V, "New Persistent Key", foundEndpoint->persistent_key);
        store.save();
    }

    // CONTROL FLOW success (FAST and STANDARD rungs; ATTESTATION already
    // sent its own 0x40 inside the attestation flow itself)
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

ApduResponse Profile::control_flow(
    Session& session, uint8_t s1, uint8_t s2)
{
    // HomeKey CONTROL FLOW: CLA=0x80, INS=0x3C, P1=status, P2=0x00
    std::vector<uint8_t> apdu = {0x80, 0x3c, s1, 0x00};
    return session.apdu().transceive(apdu);
}

}  // namespace ddk::homekey
