#include "TLV8.hpp"
#include <cstdio>

// Defined in another translation unit containing an unrelated global TLV8.
bool foreign_tlv8_works();

int main() {
    if (!foreign_tlv8_works()) return 1;

    DdkTlv8 status;
    // Keep the colliding overload out of line even in optimized Release builds.
    tlv_it (DdkTlv8::*volatile add)(uint8_t, size_t, const uint8_t*) = &DdkTlv8::add;
    const uint8_t success = 0;
    (status.*add)(2, 1, &success);
    if (status.get() != std::vector<uint8_t>{2, 1, 0}) {
        std::fputs("DigitalDoorKey TLV add resolved to the wrong implementation\n", stderr);
        return 1;
    }

    DdkTlv8 response;
    response.add(7, status.get());
    const auto encoded = response.get();
    if (encoded != std::vector<uint8_t>{7, 3, 2, 1, 0}) return 1;

    DdkTlv8 parsed;
    parsed.parse(encoded.data(), encoded.size());
    std::vector<uint8_t> value;
    if (!parsed.ok() || !parsed.get(7, value) || value != status.get()) return 1;

    const std::vector<uint8_t> large(300, 0xA5);
    for (bool ber : {false, true}) {
        DdkTlv8 original(ber);
        original.add(1, large);
        const auto packed = original.get();
        DdkTlv8 decoded(ber);
        decoded.parse(packed.data(), packed.size());
        if (!decoded.ok() || !decoded.get(1, value) || value != large) return 1;
    }
    // Keep these checks active in Release builds (NDEBUG), too.
    return foreign_tlv8_works() ? 0 : 1;
}
