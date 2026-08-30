#pragma once
#include "ddk/transport/BleLink.h"
#include <condition_variable>
#include <deque>
#include <memory>
#include <mutex>
#include <utility>
#include <vector>

namespace aliro_test {

// Two ddk::BleLink ends wired through queues — the host-test stand-in for
// an L2CAP credit-based channel. One end runs the reader (BleFlow's
// thread), the other the simulated user device on its own thread.
// close() on either end drops the whole channel, as an L2CAP disconnect
// would; peers observe connected() == false and recv failures.
class BleLoopbackPair {
public:
    static std::pair<std::shared_ptr<ddk::BleLink>, std::shared_ptr<ddk::BleLink>>
    make(size_t max_sdu_size = 512, size_t queue_limit = 64);
};

}  // namespace aliro_test
