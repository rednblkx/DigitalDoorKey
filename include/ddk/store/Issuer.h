#include <cstdint>
#include <vector>
#include "Endpoint.h"

namespace ddk {
struct Issuer {
    std::vector<uint8_t> id;           // "issuerId"      supplied by HAP / derived (Aliro)
    std::vector<uint8_t> public_key;   // "publicKey"     Ed25519 (HK) / group key (Aliro)
    std::vector<uint8_t> public_key_x; // "issuer_key_x"  wire fidelity; unused by auth
    std::vector<Endpoint> endpoints;
};
}
