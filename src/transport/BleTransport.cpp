#include "BleTransport.h"
#include "DDKLogging.h"
#include <chrono>

namespace {
constexpr const char* TAG = "BleTransport";
}  // namespace

AliroBleTransport::AliroBleTransport(std::shared_ptr<ddk::BleLink> link)
    : link_(std::move(link)) {}

size_t AliroBleTransport::max_sdu_size() const {
    return link_ ? link_->max_sdu_size() : 0;
}

bool AliroBleTransport::send_sdu(ddk::span<const uint8_t> sdu) {
    if (!link_ || !link_->connected()) {
        LOG(W, "send on disconnected link");
        link_down_ = true;
        return false;
    }
    if (!link_->send_sdu(sdu)) {
        LOG(W, "link refused SDU — marking link down");
        link_down_ = true;
        return false;
    }
    return true;
}

bool AliroBleTransport::send(const ddk::ble::Message& msg) {
    if (security_aborted()) {
        LOG(E, "send after security abort — tearing down");
        if (link_) link_->close();
        return false;
    }

    ddk::ble::Message out = msg;
    if (security_) {
        auto sealed = security_->seal(msg);
        if (!sealed) {
            if (link_) link_->close();
            return false;
        }
        out.payload = std::move(*sealed);
    }

    auto encoded = out.encode();
    if (encoded.size() > max_sdu_size()) {
        LOG(E, "message %zu bytes exceeds SDU size %zu — no BLE segmentation layer",
            encoded.size(), max_sdu_size());
        return false;
    }
    return send_sdu(encoded);
}

std::optional<ddk::ble::Message> AliroBleTransport::receive(uint32_t timeout_ms) {
    if (!rx_.empty()) {
        auto msg = std::move(rx_.front());
        rx_.pop_front();
        return msg;
    }
    if (link_down_) return std::nullopt;

    ddk::ble::Message out;
    if (!pump(out, timeout_ms)) return std::nullopt;
    return out;
}

bool AliroBleTransport::pump(ddk::ble::Message& out, uint32_t timeout_ms) {
    if (!link_) {
        link_down_ = true;
        return false;
    }
    auto deadline = std::chrono::steady_clock::now() +
                    std::chrono::milliseconds(timeout_ms);
    std::vector<uint8_t> sdu;
    for (;;) {
        if (link_down_) return false;
        long remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
                             deadline - std::chrono::steady_clock::now()).count();
        if (remaining < 0) remaining = 0;
        if (!link_->recv_sdu(sdu, static_cast<uint32_t>(remaining))) {
            if (!link_->connected()) {
                LOG(W, "link went down while receiving");
                link_down_ = true;
            }
            return false;  // timeout or link down
        }

        auto messages = ddk::ble::unpack_sdu(sdu);
        if (messages.empty()) {
            LOG(W, "dropping SDU with malformed framing");
            continue;
        }
        for (auto& msg : messages) {
            if (security_) {
                if (security_->aborted()) {
                    LOG(E, "security aborted — tearing down");
                    link_->close();
                    link_down_ = true;
                    return false;
                }
                auto plain = security_->unseal(msg);
                if (!plain) {
                    link_->close();
                    link_down_ = true;
                    return false;
                }
                msg.payload = std::move(*plain);
            }
            rx_.push_back(std::move(msg));
        }
        if (!rx_.empty()) {
            out = std::move(rx_.front());
            rx_.pop_front();
            return true;
        }
    }
}

void AliroBleTransport::activate_message_security(
    const std::array<uint8_t,32>& sk_reader, const std::array<uint8_t,32>& sk_device) {
    security_.emplace(sk_reader, sk_device);
}

void AliroBleTransport::set_secured(bool secured) {
    if (security_) security_->set_secured(secured);
}

bool AliroBleTransport::secured() const {
    return security_ && security_->secured();
}

bool AliroBleTransport::security_aborted() const {
    return security_ && security_->aborted();
}

void AliroBleTransport::mark_link_down() {
    link_down_ = true;
}

void AliroBleTransport::close_link() {
    link_down_ = true;
    if (link_) link_->close();
}
