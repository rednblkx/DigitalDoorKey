// Simulated Aliro endpoint + credential store for host-side flow tests.
//
// AliroTestEndpoint implements the device side of the Aliro NFC ladder
// (SELECT / AUTH0 / AUTH1 / EXCHANGE / CONTROL FLOW), mirroring the
// reader-side implementations in src/auth/AliroFastAuth.cpp,
// src/auth/AliroStdAuth.cpp and src/aliro/Profile.cpp:
//   - the Aliro GCM IV scheme: 8B direction (reader 0x00 / endpoint 0x01)
//     || 4B big-endian per-direction counter, 16B tag appended, no AAD
//   - the key schedule inputs (AliroKeySchedule::SessionInput), including
//     the fci_proprietary template validate_select copies into the transcript
//   - the ES256 device signature over the AUTH1 verification input
//     (TLVs 4D/86/87/4C/93 with deviceCtx 4e 88 7b 4c)
//
// The endpoint is connected to the reader through the production
// ddk::NfcChannel, so APDU framing and chaining code is exercised too.
#pragma once

// Note on includes: include/ddk/store/Issuer.h has no include guard, so it
// must reach every TU exactly once — it is pulled in via the private
// aliro/Profile.h → AuthResults.hpp chain and not included directly here.
#include "aliro/AliroKeySchedule.h"
#include "aliro/Profile.h"
#include "ddk/session/AuthOutcome.h"
#include "ddk/session/Session.h"
#include "ddk/store/CredentialStore.h"
#include "ddk/store/ReaderIdentity.h"
#include "ddk/transport/ApduChannel.h"
#include "ddk/transport/NfcChannel.h"

#include <array>
#include <cstdint>
#include <memory>
#include <optional>
#include <utility>
#include <vector>

namespace aliro_test {

// 32B scalar + 65B SEC1-uncompressed P-256 key.
struct P256KeyPair {
    std::array<uint8_t, 32> priv{};
    std::array<uint8_t, 65> pub{};
    std::array<uint8_t, 32> pub_x{};
};

P256KeyPair generate_p256_key();

// FCI the endpoint answers SELECT with: 6F [ A5 [ 5C 02 01 00 ] ].
std::vector<uint8_t> build_select_fci();
// The 0xA5 proprietary template as validate_select copies it into the
// transcript (A5 || length || A5-value); part of the key-schedule salt.
std::vector<uint8_t> fci_proprietary();

// AUTH1 response metadata the reader persists on the endpoint.
std::vector<uint8_t> test_key_slot();        // 8B, tag 0x4E
std::vector<uint8_t> credential_tdate();     // 20B, tag 0x91
std::vector<uint8_t> revocation_tdate();     // 20B, tag 0x92

// AES-256-GCM with the Aliro IV scheme: 8B direction (reader 0x00 /
// endpoint 0x01) || 4B big-endian counter, 16B tag appended, no AAD —
// the Session Encryption framing used across all Aliro channels.
std::vector<uint8_t> aliro_gcm(const std::array<uint8_t, 32>& key,
                               uint8_t direction_last_byte, uint32_t counter,
                               const std::vector<uint8_t>& in, bool encrypt);

// SessionData {"data": bstr(ciphertext)} wrap/unwrap (no "status" field) 
// and the 0x53 BER-TLV wrapper ENVELOPE carries it in.
std::vector<uint8_t> session_data_wrap(const std::vector<uint8_t>& ct);
std::vector<uint8_t> session_data_unwrap(const std::vector<uint8_t>& cbor);
std::vector<uint8_t> tlv53(const std::vector<uint8_t>& value);

// Golden DeviceRequest CBOR for docType
// "aliro-a" and scopes {"matter1": true} — matches the reader's
// buildDeviceRequest output byte for byte.
std::vector<uint8_t> mock_device_request();

// Device-side step-up credential material: an MSO with the deviceKey
// wrapped as tag24, plus a COSE_Sign1 issuerAuth over it.
struct StepUpMaterial {
    std::vector<uint8_t> x;          // 32B deviceKey X
    std::vector<uint8_t> y;          // 32B deviceKey Y
    std::vector<uint8_t> issuer_id;  // 8B, matches a store issuer id
    std::vector<uint8_t> sig;        // 64B raw r||s
    std::vector<uint8_t> protected_headers;  // bstr {1: -7}
    std::vector<uint8_t> payload;    // tag24(MSO)
};

// mso_text_keys: MSO/deviceKeyInfo keys as digit text strings ("4"/"1") —
//   the form real devices and the Python reference's fixtures use — instead
//   of ISO integers. omit_tag24: COSE payload carries the MSO map encoding
//   directly, without the tag-24 wrapper.
StepUpMaterial make_step_up_material(const std::array<uint8_t, 32>& device_x,
                                     const std::array<uint8_t, 32>& device_y,
                                     const std::vector<uint8_t>& issuer_id,
                                     bool mso_text_keys = false,
                                     bool omit_tag24 = false);

// ES256 over ["Signature1", protected, aad="", payload] — the issuerAuth
// signature form CoseSign1::verify_es256 expects.
std::vector<uint8_t> sign_cose_es256(const P256KeyPair& key,
                                     const std::vector<uint8_t>& protected_headers,
                                     const std::vector<uint8_t>& payload);

// DeviceResponse {1: version, 2: [doc], 3: status} with the doc embedded
// inline; optionally outputs the standalone doc encoding (must byte-match
// the slice the parser captures).
std::vector<uint8_t> build_step_up_device_response(const StepUpMaterial& m,
                                                   bool text_keys,
                                                   std::vector<uint8_t>* doc_out = nullptr);

// Knobs the tests set before running a transaction.
struct EndpointScenario {
    // Fast flow: 0x9D cryptogram in the AUTH0 response (needs a non-empty
    // persistent_key to encrypt it with).
    bool serve_cryptogram = false;
    // Fast flow: cryptogram encrypted under a wrong key (fast miss →
    // Standard fallback).
    bool tamper_cryptogram = false;
    // Standard flow: garbage 0x9E device signature.
    bool corrupt_device_signature = false;
    // Standard flow: 0x5A/0x4E values that match no store endpoint.
    bool unknown_endpoint_key = false;
    // AUTH0 response without the 0x86 endpoint ephemeral public key.
    bool malformed_auth0 = false;
    bool serve_step_up = false;
    // AUTH1 signaling bitmap sets Bit2 → reader SHALL do the step-up AID
    // SELECT before the step-up phase.
    bool step_up_select_required = false;
    bool corrupt_step_up_signature = false;
};

// CredentialStore fake: a provisioned reader identity plus a single
// issuer with one endpoint. save() is counted (the persistence gate
// distinguishes Fast hits from Standard/StepUp completions).
class FakeStore : public ddk::CredentialStore {
public:
    ddk::ReaderIdentity identity;
    std::vector<ddk::Issuer> issuer_list;
    int save_count = 0;

    FakeStore();  // fills gid/sub with fixed 16B patterns

    const ddk::ReaderIdentity& reader_identity() const override { return identity; }
    void provision_identity(const ddk::ReaderIdentity&) override {}
    ddk::span<ddk::Issuer> issuers() override { return issuer_list; }
    void save() override { ++save_count; }
};

// Device side of the ladder, fed to the reader via ddk::NfcChannel's
// transport callback. Every APDU is recorded for assertions.
class AliroTestEndpoint {
public:
    // Identity material, wired up by FlowRig.
    P256KeyPair endpoint_key{};               // static key; store must match
    std::array<uint8_t, 32> persistent_key{}; // pre-provisioned fast key
    std::array<uint8_t, 32> reader_pk_x{};    // reader static key X (provisioned out-of-band)
    // Interface byte fed into the key schedule — the BLE device harness
    // flips this to TransportKind::Ble so both sides derive identical keys.
    ddk::TransportKind interface_kind = ddk::TransportKind::Nfc;
    EndpointScenario scenario;

    // Step-up credential material (device side). device_key defaults to the
    // endpoint's static key; for enrollment scenarios tests swap in a fresh
    // key that is absent from the store.
    P256KeyPair device_key{};
    P256KeyPair issuer_key{};                 // signs the issuerAuth
    std::vector<uint8_t> issuer_id{};         // 8B, matches a store issuer id

    // Observations for assertions.
    std::vector<std::pair<uint8_t, uint8_t>> apdus_seen;  // (CLA, INS) in order
    std::vector<uint8_t> completion_payload;   // decrypted completion EXCHANGE (97 02 s1 s2)
    bool completion_exchanged = false;
    std::optional<std::pair<uint8_t, uint8_t>> control_flow_status;
    bool saw_auth1 = false;

    // Step-up observations.
    int envelope_count = 0;
    int step_up_selects = 0;                   // step-up AID SELECTs answered
    std::vector<uint8_t> decrypted_device_request;
    std::vector<uint8_t> served_document_cbor; // standalone doc encoding served

    // Key-schedule recording — lets tests recompute the expected Kpersistent.
    AliroKeySchedule::SessionInput recorded_session_input() const;
    std::array<uint8_t, 32> derived_key{};     // X963KDF output from AUTH1

    // BLE+UWB extras captured device-side while serving AUTH0/AUTH1 —
    // the BLE device harness derives its BleSK channels from these.
    std::array<uint8_t, 32> fast_ble_sk{}, fast_ursk{};
    std::array<uint8_t, 32> std_ble_sk{}, std_ursk{};

    ddk::NfcChannel::Callback callback();

private:
    ddk::ApduResponse handle_select(const std::vector<uint8_t>& data);
    ddk::ApduResponse handle_auth0(const std::vector<uint8_t>& data);
    ddk::ApduResponse handle_auth1(const std::vector<uint8_t>& data);
    ddk::ApduResponse handle_exchange(const std::vector<uint8_t>& data);
    ddk::ApduResponse handle_control_flow(const std::vector<uint8_t>& data);
    ddk::ApduResponse handle_envelope(const std::vector<uint8_t>& data);
    void build_step_up_response();

    // Rebuilds the reader-side key-schedule input from the parsed AUTH0
    // command and the served FCI (fci must outlive the schedule call).
    AliroKeySchedule::SessionInput session_input(const std::vector<uint8_t>& fci) const;

    // Parsed from the AUTH0 command, reused by AUTH1.
    std::array<uint8_t, 65> reader_eph_pub{};
    std::array<uint8_t, 32> endpoint_eph_priv{};
    std::array<uint8_t, 65> endpoint_eph_pub{};
    std::array<uint8_t, 16> txn_id{};
    std::vector<uint8_t> reader_identifier;
    std::array<uint8_t, 2> flags{};
    std::array<uint8_t, 2> version{0x01, 0x00};

    // Derived channel keys.
    std::array<uint8_t, 32> fast_sk_reader{}, fast_sk_device{};
    std::array<uint8_t, 32> std_sk_reader{}, std_sk_device{};
    std::array<uint8_t, 32> step_up_sk_reader{}, step_up_sk_device{};
    uint32_t reader_ctr = 1;      // reader→endpoint decrypt counter (EXCHANGE)
    uint32_t step_up_reader_ctr = 1;   // step-up channel counters
    uint32_t step_up_endpoint_ctr = 1;
    bool step_up_engaged = false; // active channel switched to step-up

    std::vector<uint8_t> recorded_fci;
    std::vector<uint8_t> step_up_response_cbor;
};

// Everything one flow transaction needs: provisioned store, simulated
// endpoint, and the production driver sequence (SELECT → validate_select
// → step loop → finalize) as run by main/lock/aliro_door_lock_delegate.cpp.
class FlowRig {
public:
    P256KeyPair reader_key{};
    P256KeyPair endpoint_key{};
    P256KeyPair issuer_key{};
    FakeStore store;
    AliroTestEndpoint endpoint;
    std::shared_ptr<ddk::ApduChannel> channel;

    explicit FlowRig(bool provision_persistent_key);

    ddk::Endpoint& store_endpoint() { return store.issuer_list.at(0).endpoints.at(0); }

    // A SELECT/FCI failure surfaces as a Failed outcome.
    ddk::AuthOutcome run(ddk::SessionConfig config);

    // Access document as reported by the outcome — captured while the
    // profile is alive (AuthOutcome::access_document_cbor spans into
    // Profile state that dies with it).
    std::vector<uint8_t> access_document;
};

}  // namespace aliro_test
