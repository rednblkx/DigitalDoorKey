// Standard flow (AUTH0 + signed AUTH1 with ECDH key schedule) against the
// simulated Aliro endpoint.
//
// Covers:
//  1. Happy path — AUTH1 signature verifies, credentials persist, completion
//     signaling over the standard exchange channel.
//  2. A served fast cryptogram is ignored when the target flow is Standard.
//  3. Corrupt device signature → failed transaction, PublicKeyNotFound
//     completion, no store write.
//  4. Unknown endpoint key (0x5A/0x4E match nothing) → failed transaction.

#include "aliro_test_endpoint.hpp"

#include <catch2/catch_test_macros.hpp>

using namespace aliro_test;

namespace {

ddk::SessionConfig standard_config()
{
    ddk::SessionConfig config;
    config.target_flow = ddk::Flow::Standard;
    return config;
}

const std::vector<uint8_t> kCompletionStateUnsecure{0x97, 0x02, 0x01, 0x01};
const std::vector<uint8_t> kCompletionPublicKeyNotFound{0x97, 0x02, 0x00, 0x01};

}  // namespace

TEST_CASE("Standard flow authenticates and persists credentials", "[aliro][standard]")
{
    FlowRig rig(/*provision_persistent_key=*/true);

    auto outcome = rig.run(standard_config());

    REQUIRE(outcome);
    REQUIRE(outcome.state == ddk::FlowState::Done);
    REQUIRE(outcome.endpoint == &rig.store_endpoint());
    REQUIRE(rig.endpoint.saw_auth1);
    REQUIRE(rig.store.save_count == 1);

    auto& endpoint = rig.store_endpoint();
    REQUIRE(endpoint.aliro.last_flow == ddk::kFlowSTANDARD);
    REQUIRE(endpoint.aliro.key_slot == test_key_slot());
    REQUIRE(endpoint.aliro.signaling_bitmask == std::optional<uint16_t>(0x0001));
    REQUIRE(endpoint.aliro.credential_signed_timestamp == credential_tdate());
    REQUIRE(endpoint.aliro.revocation_signed_timestamp == revocation_tdate());
    REQUIRE(endpoint.persistent_key.size() == 32);
    REQUIRE(rig.endpoint.completion_payload == kCompletionStateUnsecure);
}

TEST_CASE("Standard target ignores a served fast cryptogram", "[aliro][standard]")
{
    FlowRig rig(/*provision_persistent_key=*/true);
    rig.endpoint.scenario.serve_cryptogram = true;  // endpoint offers Fast anyway

    auto outcome = rig.run(standard_config());

    REQUIRE(outcome);
    // Fast dispatch requires target_flow == Fast; the reader must still
    // go through AUTH1.
    REQUIRE(rig.endpoint.saw_auth1);
    REQUIRE(rig.store.save_count == 1);
    REQUIRE(rig.store_endpoint().aliro.last_flow == ddk::kFlowSTANDARD);
    REQUIRE(rig.endpoint.completion_payload == kCompletionStateUnsecure);
}

TEST_CASE("Standard flow rejects a corrupt device signature", "[aliro][standard]")
{
    FlowRig rig(/*provision_persistent_key=*/true);
    rig.endpoint.scenario.corrupt_device_signature = true;

    auto outcome = rig.run(standard_config());

    REQUIRE_FALSE(outcome);
    REQUIRE(outcome.state == ddk::FlowState::Failed);
    REQUIRE(rig.endpoint.saw_auth1);
    REQUIRE(rig.store.save_count == 0);
    // Secure channel exists, so failure is delivered as a completion
    // EXCHANGE with PublicKeyNotFound.
    REQUIRE(rig.endpoint.completion_payload == kCompletionPublicKeyNotFound);
}

TEST_CASE("Standard flow fails when the endpoint key is unknown", "[aliro][standard]")
{
    FlowRig rig(/*provision_persistent_key=*/true);
    rig.endpoint.scenario.unknown_endpoint_key = true;

    auto outcome = rig.run(standard_config());

    REQUIRE_FALSE(outcome);
    REQUIRE(outcome.state == ddk::FlowState::Failed);
    REQUIRE(rig.endpoint.saw_auth1);
    REQUIRE(rig.store.save_count == 0);
    REQUIRE(rig.endpoint.completion_payload == kCompletionPublicKeyNotFound);
}
