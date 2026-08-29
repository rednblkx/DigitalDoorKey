// Full authentication phase with the step-up flow (ddk::Flow::StepUp):
// SELECT (expedited AID) → AUTH0 → AUTH1 (expedited-standard, establishes
// ExpeditedSK + StepUpSK) → [step-up AID SELECT when the AUTH1 signaling
// bitmap requires it] → ENVELOPE carrying the SessionData-encapsulated
// DeviceRequest → DeviceResponse with the signed Access Document →
// completion EXCHANGE with the reader status — all driven through
// ddk::aliro::Profile like the production reader does.
//
// Covered:
//  1. Step-up over a known endpoint — transaction completes with
//     kFlowATTESTATION, document persisted, Kpersistent re-derived.
//  2. Step-up enrolls an unknown endpoint (the Access Credential's
//     deviceKey is not in the store) — new endpoint provisioned.
//  3. Step-up AID SELECT performed when the AUTH1 bitmap sets Bit2.
//  4. Step-up document verification failure degrades to a Standard-flow
//     completion for a known endpoint.

#include "aliro_test_endpoint.hpp"

#include "CommonCryptoUtils.h"

#include <catch2/catch_test_macros.hpp>

#include <map>
#include <utility>
#include <vector>

using namespace aliro_test;

namespace {

ddk::SessionConfig stepup_config()
{
    ddk::SessionConfig config;
    config.target_flow = ddk::Flow::StepUp;
    config.step_up_scopes = std::map<std::string, bool>{{"matter1", true}};
    return config;
}

const std::vector<uint8_t> kCompletionStateUnsecure{0x97, 0x02, 0x01, 0x01};

std::vector<uint8_t> expected_persistent_key(const AliroTestEndpoint& endpoint,
                                             const std::vector<uint8_t>& credential_pk_x)
{
    AliroKeySchedule schedule;
    auto key = schedule.derive_persistent(endpoint.recorded_session_input(),
                                          endpoint.derived_key, credential_pk_x);
    return std::vector<uint8_t>(key.begin(), key.end());
}

}  // namespace

TEST_CASE("Full step-up flow authenticates a known endpoint", "[aliro][stepup][flow]")
{
    FlowRig rig(/*provision_persistent_key=*/true);
    rig.endpoint.scenario.serve_step_up = true;

    auto outcome = rig.run(stepup_config());

    REQUIRE(outcome);
    REQUIRE(outcome.state == ddk::FlowState::Done);
    REQUIRE(outcome.endpoint == &rig.store_endpoint());

    REQUIRE(rig.endpoint.saw_auth1);
    REQUIRE(rig.endpoint.step_up_selects == 0);  // bitmap Bit2 not set
    REQUIRE(rig.endpoint.envelope_count == 1);
    REQUIRE(rig.endpoint.decrypted_device_request == mock_device_request());

    // Document persisted on the endpoint; completion via the step-up channel.
    auto& endpoint = rig.store_endpoint();
    REQUIRE(endpoint.aliro.last_flow == ddk::kFlowATTESTATION);
    REQUIRE(endpoint.aliro.documents.size() == 1);
    REQUIRE(endpoint.aliro.documents[0] == rig.endpoint.served_document_cbor);
    REQUIRE(rig.access_document == rig.endpoint.served_document_cbor);
    REQUIRE(rig.endpoint.completion_payload == kCompletionStateUnsecure);
    REQUIRE(rig.store.save_count == 1);

    // Kpersistent re-derived over the (known) endpoint public key.
    REQUIRE(endpoint.persistent_key ==
            expected_persistent_key(rig.endpoint, endpoint.public_key_x));
}

TEST_CASE("Full step-up flow enrolls an unknown endpoint", "[aliro][stepup][flow]")
{
    FlowRig rig(/*provision_persistent_key=*/true);
    rig.endpoint.scenario.serve_step_up = true;
    // AUTH1 carries a device public key that matches no store endpoint, so
    // the expedited-standard phase cannot resolve the credential; the
    // step-up MSO deviceKey is the missing credential and gets enrolled.
    rig.endpoint.scenario.unknown_endpoint_key = true;
    rig.endpoint.device_key = generate_p256_key();
    const auto enrolled_pub = std::vector<uint8_t>(
        rig.endpoint.device_key.pub.begin(), rig.endpoint.device_key.pub.end());
    const auto enrolled_pk_x = std::vector<uint8_t>(
        rig.endpoint.device_key.pub_x.begin(), rig.endpoint.device_key.pub_x.end());

    auto outcome = rig.run(stepup_config());

    REQUIRE(outcome);
    REQUIRE(outcome.state == ddk::FlowState::Done);
    REQUIRE(rig.endpoint.saw_auth1);
    REQUIRE(rig.endpoint.envelope_count == 1);
    REQUIRE(rig.endpoint.decrypted_device_request == mock_device_request());
    REQUIRE(rig.store.save_count == 1);

    auto& issuer = rig.store.issuer_list.at(0);
    REQUIRE(issuer.endpoints.size() == 2);
    auto& enrolled = issuer.endpoints.at(1);
    REQUIRE(outcome.endpoint == &enrolled);

    REQUIRE(enrolled.public_key == enrolled_pub);
    REQUIRE(enrolled.public_key_x == enrolled_pk_x);
    // endpointId = first 6 bytes of SHA-1 over the endpoint public key.
    auto sha1 = CommonCryptoUtils::hash_identifier_sha1(enrolled.public_key);
    REQUIRE(enrolled.id == std::vector<uint8_t>(sha1.begin(), sha1.begin() + 6));

    REQUIRE(enrolled.aliro.last_flow == ddk::kFlowATTESTATION);
    REQUIRE(enrolled.aliro.documents.size() == 1);
    REQUIRE(enrolled.aliro.documents[0] == rig.endpoint.served_document_cbor);
    REQUIRE(enrolled.persistent_key ==
            expected_persistent_key(rig.endpoint, enrolled_pk_x));
    REQUIRE(rig.endpoint.completion_payload == kCompletionStateUnsecure);

    REQUIRE(rig.store_endpoint().aliro.empty());
}

TEST_CASE("Step-up AID SELECT performed when the AUTH1 bitmap requires it",
          "[aliro][stepup][flow]")
{
    FlowRig rig(/*provision_persistent_key=*/true);
    rig.endpoint.scenario.serve_step_up = true;
    rig.endpoint.scenario.step_up_select_required = true;

    auto outcome = rig.run(stepup_config());

    REQUIRE(outcome);
    REQUIRE(outcome.state == ddk::FlowState::Done);
    // Expedited AID SELECT (driver) + step-up AID SELECT (bitmap Bit2).
    REQUIRE(rig.endpoint.step_up_selects == 1);
    REQUIRE(rig.endpoint.envelope_count == 1);
    REQUIRE(rig.endpoint.decrypted_device_request == mock_device_request());
    REQUIRE(rig.store_endpoint().aliro.last_flow == ddk::kFlowATTESTATION);
    REQUIRE(rig.endpoint.completion_payload == kCompletionStateUnsecure);
}

TEST_CASE("Step-up document failure degrades to Standard for a known endpoint",
          "[aliro][stepup][flow]")
{
    FlowRig rig(/*provision_persistent_key=*/true);
    rig.endpoint.scenario.serve_step_up = true;
    rig.endpoint.scenario.corrupt_step_up_signature = true;

    auto outcome = rig.run(stepup_config());

    // The expedited-standard phase already authenticated the endpoint, so
    // the transaction still completes — via the Standard flow, with no
    // document persisted.
    REQUIRE(outcome);
    REQUIRE(outcome.state == ddk::FlowState::Done);
    REQUIRE(rig.endpoint.envelope_count == 1);
    REQUIRE(rig.store_endpoint().aliro.last_flow == ddk::kFlowSTANDARD);
    REQUIRE(rig.store_endpoint().aliro.documents.empty());
    REQUIRE(rig.store.save_count == 1);
    REQUIRE(rig.endpoint.completion_payload == kCompletionStateUnsecure);
}
