#pragma once
#include "ddk/transport/ApduChannel.h"
#include <functional>
#include <vector>

namespace ddk {

class NfcChannel : public ApduChannel {
public:
    using Callback = std::function<bool(
        std::vector<uint8_t>& command,
        std::vector<uint8_t>& response)>;

    explicit NfcChannel(Callback cb);

    TransportKind kind() const override;
    size_t max_command_payload() const override;
    ApduResponse transceive(ddk::span<const uint8_t> capdu) override;
    ApduResponse transceive_full(
        const ApduCommand& command,
        bool skip_response_chaining = false,
        size_t max_command_chunk = 255) override;

private:
    Callback callback_;
};

}  // namespace ddk
