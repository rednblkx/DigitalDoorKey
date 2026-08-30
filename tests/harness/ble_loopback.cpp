#include "ble_loopback.hpp"

#include <chrono>
#include <utility>

namespace aliro_test {

namespace {

struct EndState {
    std::mutex mu;
    std::condition_variable cv;
    std::deque<std::vector<uint8_t>> queue;
    bool connected = true;
};

class LoopbackEnd : public ddk::BleLink {
public:
    LoopbackEnd(std::shared_ptr<EndState> self, std::shared_ptr<EndState> peer,
                size_t max_sdu, size_t queue_limit)
        : self_(std::move(self)), peer_(std::move(peer)),
          max_sdu_(max_sdu), queue_limit_(queue_limit) {}

    size_t max_sdu_size() const override { return max_sdu_; }

    bool send_sdu(ddk::span<const uint8_t> sdu) override {
        std::vector<uint8_t> copy(sdu.begin(), sdu.end());
        {
            std::lock_guard<std::mutex> lock(peer_->mu);
            if (!peer_->connected || !self_->connected) return false;
            if (peer_->queue.size() >= queue_limit_) return false;   // backpressure
            peer_->queue.push_back(std::move(copy));
        }
        peer_->cv.notify_one();
        return true;
    }

    bool recv_sdu(std::vector<uint8_t>& sdu, uint32_t timeout_ms) override {
        const auto deadline = std::chrono::steady_clock::now() +
                              std::chrono::milliseconds(timeout_ms);
        std::unique_lock<std::mutex> lock(self_->mu);
        for (;;) {
            if (!self_->queue.empty()) {
                sdu = std::move(self_->queue.front());
                self_->queue.pop_front();
                return true;
            }
            if (!self_->connected) return false;
            if (std::chrono::steady_clock::now() >= deadline) return false;
            self_->cv.wait_until(lock, deadline);
        }
    }

    bool connected() const override {
        std::lock_guard<std::mutex> lock(self_->mu);
        return self_->connected;
    }

    void close() override {
        // Marks the channel down for both ends but leaves already-queued
        // SDUs in place: data the peer sent before the disconnect stays
        // deliverable, like a real L2CAP teardown. The closer's own queue
        // is irrelevant — its side stops receiving.
        peer_->connected = false;
        self_->connected = false;
        peer_->cv.notify_all();
        self_->cv.notify_all();
    }

private:
    std::shared_ptr<EndState> self_;
    std::shared_ptr<EndState> peer_;
    size_t max_sdu_;
    size_t queue_limit_;
};

}  // namespace

std::pair<std::shared_ptr<ddk::BleLink>, std::shared_ptr<ddk::BleLink>>
BleLoopbackPair::make(size_t max_sdu_size, size_t queue_limit) {
    auto a = std::make_shared<EndState>();
    auto b = std::make_shared<EndState>();
    return {std::make_shared<LoopbackEnd>(a, b, max_sdu_size, queue_limit),
            std::make_shared<LoopbackEnd>(b, a, max_sdu_size, queue_limit)};
}

}  // namespace aliro_test
