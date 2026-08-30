#pragma once
#include "ddk/Span.h"
#include <cstddef>
#include <cstdint>
#include <vector>

namespace ddk {

class BleLink {
public:
    virtual ~BleLink() = default;

    virtual size_t max_sdu_size() const = 0;

    // Send one SDU (may pack several Aliro messages). False = link down.
    virtual bool send_sdu(ddk::span<const uint8_t> sdu) = 0;

    // Receive one SDU, blocking up to timeout_ms. False = timeout or the
    // link went down (check connected()).
    virtual bool recv_sdu(std::vector<uint8_t>& sdu, uint32_t timeout_ms) = 0;

    // True while the L2CAP channel is established.
    virtual bool connected() const = 0;

    virtual void close() {}
};

}  // namespace ddk
