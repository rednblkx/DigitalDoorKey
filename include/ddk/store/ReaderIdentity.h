#include <cstdint>
#include <optional>
#include <vector>

namespace ddk {
struct ReaderIdentity {
    ReaderIdentity() : private_key(0), public_key(0), public_key_x(0), group_identifier(0), sub_identifier(0) {}
    std::vector<uint8_t> private_key;       // "reader_private_key"
    std::vector<uint8_t> public_key;        // "reader_public_key"  derived at provisioning
    std::vector<uint8_t> public_key_x;      // "reader_key_x"       derived at provisioning
    std::vector<uint8_t> group_identifier;  // "group_identifier"
    std::vector<uint8_t> sub_identifier;    // "unique_identifier"
    std::optional<std::vector<uint8_t>> certificate;  // future: Aliro Profile0000; not on wire yet
};
}
