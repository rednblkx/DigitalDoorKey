#pragma once
#include <cstdint>

namespace ddk {

enum class Flow : uint8_t {
    Fast     = 0x00,
    Standard = 0x01,
    StepUp   = 0x02,
};

}  // namespace ddk
