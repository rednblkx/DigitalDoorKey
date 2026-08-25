#include <cstdint>
#include <vector>
namespace ddk {

enum class KeyType : uint8_t { Secp256r1 = 2 };

struct Endpoint {
    std::vector<uint8_t> id;              // "endpointId"
    std::vector<uint8_t> public_key;      // "publicKey"      65B uncompressed
    std::vector<uint8_t> public_key_x;    // "endpoint_key_x" 32B
    std::vector<uint8_t> persistent_key;  // "persistent_key" 32B
    uint32_t used_at = 0;                 // "last_used_at"
    uint8_t  counter = 0;                 // "counter"        width preserved
    KeyType  key_type = KeyType::Secp256r1;
};
}
