// Fast flow (single AUTH0 round trip with a persistent-key cryptogram)
// against the simulated Aliro endpoint.
//
// Covers:
//  1. Fast hit — AUTH0 cryptogram decrypts, no AUTH1, no store write,
//     completion signaling over the fast exchange channel.
//  2. Fast miss (no cryptogram served) → Standard fallback.
//  3. Fast miss (tampered cryptogram) → Standard fallback.
//  4. Malformed AUTH0 → CONTROL FLOW failure, neither flow attempted.

#include "aliro_test_endpoint.hpp"

#include <catch2/catch_test_macros.hpp>

#include <utility>

using namespace aliro_test;

namespace {

ddk::SessionConfig fast_config()
{
    ddk::SessionConfig config;
    config.target_flow = ddk::Flow::Fast;
    return config;
}

const std::vector<uint8_t> kCompletionStateUnsecure{0x97, 0x02, 0x01, 0x01};

}  // namespace

TEST_CASE("Fast flow authenticates with a single AUTH0 round trip", "[aliro][fast]")
{
    FlowRig rig(/*provision_persistent_key=*/true);
    rig.endpoint.scenario.serve_cryptogram = true;

    auto outcome = rig.run(fast_config());

    REQUIRE(outcome);
    REQUIRE(outcome.state == ddk::FlowState::Done);
    REQUIRE(outcome.endpoint == &rig.store_endpoint());
    REQUIRE(rig.endpoint.saw_auth1 == false);
    REQUIRE(rig.store.save_count == 0);  // fast hits skip persistence
    REQUIRE(rig.endpoint.completion_exchanged);
    REQUIRE(rig.endpoint.completion_payload == kCompletionStateUnsecure);
}

TEST_CASE("Fast miss without cryptogram falls back to Standard", "[aliro][fast]")
{
    FlowRig rig(/*provision_persistent_key=*/true);
    rig.endpoint.scenario.serve_cryptogram = false;

    auto outcome = rig.run(fast_config());

    REQUIRE(outcome);
    REQUIRE(outcome.state == ddk::FlowState::Done);
    REQUIRE(rig.endpoint.saw_auth1);
    REQUIRE(rig.store.save_count == 1);  // Standard flow persists
    auto& endpoint = rig.store_endpoint();
    REQUIRE(endpoint.aliro.last_flow == ddk::kFlowSTANDARD);
    REQUIRE(endpoint.aliro.key_slot == test_key_slot());
    REQUIRE(endpoint.persistent_key.size() == 32);
    // The pre-provisioned key was replaced by the freshly derived one.
    REQUIRE(endpoint.persistent_key !=
            std::vector<uint8_t>(rig.endpoint.persistent_key.begin(),
                                 rig.endpoint.persistent_key.end()));
    REQUIRE(rig.endpoint.completion_payload == kCompletionStateUnsecure);
}

TEST_CASE("Tampered fast cryptogram falls back to Standard", "[aliro][fast]")
{
    FlowRig rig(/*provision_persistent_key=*/true);
    rig.endpoint.scenario.serve_cryptogram = true;
    rig.endpoint.scenario.tamper_cryptogram = true;

    auto outcome = rig.run(fast_config());

    REQUIRE(outcome);
    REQUIRE(outcome.state == ddk::FlowState::Done);
    REQUIRE(rig.endpoint.saw_auth1);
    REQUIRE(rig.store.save_count == 1);
    REQUIRE(rig.store_endpoint().aliro.last_flow == ddk::kFlowSTANDARD);
    REQUIRE(rig.endpoint.completion_payload == kCompletionStateUnsecure);
}

TEST_CASE("Malformed AUTH0 fails the transaction", "[aliro][fast]")
{
    FlowRig rig(/*provision_persistent_key=*/true);
    rig.endpoint.scenario.malformed_auth0 = true;

    auto outcome = rig.run(fast_config());

    REQUIRE_FALSE(outcome);
    REQUIRE(outcome.state == ddk::FlowState::Failed);
    REQUIRE(rig.endpoint.saw_auth1 == false);
    REQUIRE(rig.endpoint.completion_exchanged == false);
    REQUIRE(rig.store.save_count == 0);
    REQUIRE(rig.endpoint.control_flow_status == std::make_pair(uint8_t{0x00}, uint8_t{0x00}));
}
