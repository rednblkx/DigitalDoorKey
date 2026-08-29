// Unit tests for the AliroStepUp plumbing in isolation: the ENVELOPE
// channel is driven directly with pre-derived session keys, bypassing the
// expedited phase and key schedule (the full Flow::StepUp ladder is covered
// by aliro_stepup_flow_test.cpp — the split keeps parser regressions
// pinpointable).
//
// Covered:
//  1. The DeviceRequest CBOR built by AliroStepUp must equal the reference
//     encoder output (doc_types=["aliro-a"], scopes={"matter1": true}).
//  2. parseDeviceResponse must accept INTEGER-keyed DeviceResponse CBOR (the
//     ISO 18013-5 form: {1: version, 2: [docs], 3: status}) — the text-keyed
//     legacy form is covered too.
//  3. ES256 issuerAuth verification, MSO deviceKey extraction, full-document
//     CBOR slicing, and access-document selection. The MSO is accepted with
//     integer keys (ISO), digit-text keys (real devices / the reference's
//     fixtures) and with the tag-24 payload wrapper omitted.
//  4. Negative: empty scopes rejected before any APDU; tampered signature
//     rejected.

#include "aliro_test_endpoint.hpp"

#include "aliro/AliroStepUp.h"
#include "aliro/AliroSecureContext.h"
#include "aliro/SignalingBitmask.h"
#include "BerTlv.h"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <map>
#include <memory>
#include <utility>
#include <vector>

using namespace aliro_test;

namespace {

// ENVELOPE-only endpoint: decrypts the SessionData request, records the
// plaintext for assertions, and answers with a canned DeviceResponse.
class StepUpEndpointChannel : public ddk::ApduChannel {
public:
    std::array<uint8_t, 32> sk_reader{};
    std::array<uint8_t, 32> sk_device{};
    std::vector<uint8_t> response_payload;   // DeviceResponse CBOR
    std::vector<uint8_t> decrypted_request;  // recorded from the ENVELOPE command
    int envelope_count = 0;

    ddk::TransportKind kind() const override { return ddk::TransportKind::Nfc; }
    size_t max_command_payload() const override { return 255; }

    ddk::ApduResponse transceive(ddk::span<const uint8_t>) override
    {
        return {};  // step-up AID SELECT not exercised here
    }

    ddk::ApduResponse transceive_full(const ddk::ApduCommand& cmd,
                                      bool, size_t) override
    {
        ddk::ApduResponse resp;
        if (cmd.cla != 0x00 || cmd.ins != 0xC3) {  // ENVELOPE
            resp.sw1 = 0x6D; resp.sw2 = 0x00;
            return resp;
        }
        ++envelope_count;

        auto msg = BerTlvMessage::from_bytes(cmd.data);
        const BerTlv* tlv = msg.find(0x53);
        if (!tlv) { resp.sw1 = 0x6A; resp.sw2 = 0x80; return resp; }

        auto ciphertext = session_data_unwrap(tlv->value);
        // Reader→device: sk_reader, READER_MODE (last byte 0x00), counter 1
        auto plaintext = aliro_gcm(sk_reader, 0x00, 1, ciphertext, false);
        if (plaintext.empty()) { resp.sw1 = 0x6A; resp.sw2 = 0x80; return resp; }
        decrypted_request = plaintext;

        // Device→reader: sk_device, ENDPOINT_MODE (last byte 0x01), counter 1
        auto enc = aliro_gcm(sk_device, 0x01, 1, response_payload, true);
        if (enc.empty()) { resp.sw1 = 0x6A; resp.sw2 = 0x80; return resp; }

        resp.data = tlv53(session_data_wrap(enc));
        resp.sw1 = 0x90; resp.sw2 = 0x00;
        return resp;
    }
};

// 8B issuer id the issuerAuth carries; the store issuer must match it.
const std::vector<uint8_t> kIssuerId = {0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18};

std::array<uint8_t, 32> pattern32(uint8_t base)
{
    std::array<uint8_t, 32> out{};
    for (size_t i = 0; i < out.size(); ++i) out[i] = static_cast<uint8_t>(base + i);
    return out;
}

StepUpMaterial test_material()
{
    return make_step_up_material(pattern32(0x10), pattern32(0x30), kIssuerId);
}

// One full AliroStepUp exchange against the simulated endpoint. Returned via
// unique_ptr so the store/channel pointers stay stable after the return.
struct StepUpExchange {
    FakeStore store;
    std::shared_ptr<StepUpEndpointChannel> channel;
    std::vector<uint8_t> document_cbor;  // standalone doc encoding from the builder
    AliroStepUpResult result;
};

std::unique_ptr<StepUpExchange> run_step_up(const P256KeyPair& issuer_key,
                                            const StepUpMaterial& material,
                                            bool text_keys,
                                            std::map<std::string, bool> scopes)
{
    auto ex = std::make_unique<StepUpExchange>();
    auto response =
        build_step_up_device_response(material, text_keys, &ex->document_cbor);

    ddk::Issuer issuer;
    issuer.id = material.issuer_id;
    issuer.public_key.assign(issuer_key.pub.begin(), issuer_key.pub.end());
    ex->store.issuer_list.push_back(std::move(issuer));

    ex->channel = std::make_shared<StepUpEndpointChannel>();
    ex->channel->sk_reader.fill(0xAA);
    ex->channel->sk_device.fill(0xBB);
    ex->channel->response_payload = std::move(response);

    ddk::Session session(ex->channel, ex->store);
    std::array<uint8_t, 32> sk_reader{}, sk_device{};
    sk_reader.fill(0xAA);
    sk_device.fill(0xBB);
    AliroSecureContext ctx(nullptr, sk_reader, sk_device);  // step-up keys only

    AliroStepUp step_up(session, ctx);
    ex->result = step_up.run(
        ddk::aliro::SignalingBitmask::AccessDocumentRetrievable,
        std::move(scopes));
    return ex;
}

void require_round_trip(const P256KeyPair& issuer_key,
                        const StepUpMaterial& material, bool text_keys)
{
    auto ex = run_step_up(issuer_key, material, text_keys, {{"matter1", true}});

    REQUIRE(ex->channel->decrypted_request == mock_device_request());

    REQUIRE(ex->result.success);
    REQUIRE(ex->result.issuer == &ex->store.issuer_list[0]);

    REQUIRE(ex->result.endpoint_public_key.size() == 65);
    REQUIRE(ex->result.endpoint_public_key[0] == 0x04);
    REQUIRE(std::vector<uint8_t>(ex->result.endpoint_public_key.begin() + 1,
                                 ex->result.endpoint_public_key.begin() + 33) ==
            material.x);
    REQUIRE(std::vector<uint8_t>(ex->result.endpoint_public_key.begin() + 33,
                                 ex->result.endpoint_public_key.end()) ==
            material.y);

    REQUIRE(ex->result.documents.size() == 1);
    REQUIRE(ex->result.documents[0] == ex->document_cbor);
    REQUIRE(ex->result.access_document_cbor == ex->document_cbor);
}

}  // namespace

TEST_CASE("AliroStepUp round-trips the reference DeviceRequest and parses the response",
          "[aliro][step-up]")
{
    auto issuer_key = generate_p256_key();
    REQUIRE(issuer_key.pub[0] == 0x04);  // keypair materialized

    auto material = test_material();
    material.sig = sign_cose_es256(issuer_key, material.protected_headers,
                                   material.payload);

    SECTION("integer-keyed DeviceResponse (ISO 18013-5 form)")
    {
        require_round_trip(issuer_key, material, /*text_keys=*/false);
    }
    SECTION("text-keyed DeviceResponse (legacy form)")
    {
        require_round_trip(issuer_key, material, /*text_keys=*/true);
    }
    SECTION("MSO with digit-text keys (real-device form)")
    {
        // Real devices encode the MSO keys as digit text strings ("4" =
        // deviceKeyInfo, "1" = deviceKey) — the form in the reference's
        // fixtures — rather than ISO integers.
        auto m = make_step_up_material(pattern32(0x10), pattern32(0x30),
                                       kIssuerId, /*mso_text_keys=*/true);
        m.sig = sign_cose_es256(issuer_key, m.protected_headers, m.payload);
        require_round_trip(issuer_key, m, /*text_keys=*/false);
    }
    SECTION("MSO payload without the tag-24 wrapper")
    {
        auto m = make_step_up_material(pattern32(0x10), pattern32(0x30),
                                       kIssuerId, /*mso_text_keys=*/true,
                                       /*omit_tag24=*/true);
        m.sig = sign_cose_es256(issuer_key, m.protected_headers, m.payload);
        require_round_trip(issuer_key, m, /*text_keys=*/false);
    }
}

TEST_CASE("AliroStepUp rejects a tampered issuerAuth signature", "[aliro][step-up]")
{
    auto issuer_key = generate_p256_key();
    auto material = test_material();
    material.sig.assign(64, 0xAB);

    auto ex = run_step_up(issuer_key, material, /*text_keys=*/false,
                          {{"matter1", true}});

    REQUIRE_FALSE(ex->result.success);
    REQUIRE(ex->result.endpoint_public_key.empty());
}

TEST_CASE("AliroStepUp rejects an empty scope map before sending any APDU",
          "[aliro][step-up]")
{
    auto issuer_key = generate_p256_key();
    auto material = test_material();
    material.sig = sign_cose_es256(issuer_key, material.protected_headers,
                                   material.payload);

    auto ex = run_step_up(issuer_key, material, /*text_keys=*/false,
                          /*scopes=*/{});

    REQUIRE_FALSE(ex->result.success);
    REQUIRE(ex->channel->envelope_count == 0);
}
