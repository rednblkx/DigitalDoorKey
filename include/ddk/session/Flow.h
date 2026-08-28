#pragma once
#include <cstdint>

namespace ddk {

enum class Flow : uint8_t {
    Fast     = 0x00,
    Standard = 0x01,
    StepUp   = 0x02,
};

typedef enum
{
    kFlowFAST = 0x00,
    kFlowSTANDARD = 0x01,
    kFlowATTESTATION = 0x02,
    kFlowNext = 0xFF,
    kFlowFailed = -1
} KeyFlow;

}  // namespace ddk
