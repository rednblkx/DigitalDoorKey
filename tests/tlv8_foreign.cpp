#include <cstddef>
#include <cstdint>

namespace {
size_t added_bytes = 0;
}

// An unrelated dependency can export exactly this symbol (as HomeSpan does).
// A return type is not part of a non-template C++ function's mangled name.
// Define the method out of line in its own translation unit to test the linker.
class TLV8 {
    uint32_t unrelated_layout = 0;
public:
    void add(uint8_t tag, size_t length, const uint8_t* value);
};

void TLV8::add(uint8_t, size_t length, const uint8_t*) {
    added_bytes += length;
}

bool foreign_tlv8_works() {
    added_bytes = 0;
    TLV8 foreign;
    const uint8_t value = 0;
    foreign.add(2, 1, &value);
    return added_bytes == 1;
}
