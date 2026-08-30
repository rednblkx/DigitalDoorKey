#pragma once
#include "BleMessageSecurity.h"
#include "BleMessages.h"
#include "ddk/transport/BleLink.h"
#include <array>
#include <deque>
#include <memory>
#include <optional>

// Reader-side Aliro BLE message pump over a ddk::BleLink: packs/unpacks
// SDUs, applies BleSK message
// security to non-AP types, and queues messages between the synchronous
// ApduChannel consumer (BleChannel) and the flow's message loop.
//
// Single-threaded cooperative like the NFC callback model: every call
// must come from the flow's thread.
class AliroBleTransport {
public:
    explicit AliroBleTransport(std::shared_ptr<ddk::BleLink> link);

    // Sends one message, sealing non-AP payloads once message security is
    // active. False = link refused or security aborted.
    bool send(const ddk::ble::Message& msg);

    // Pops the next message, pulling from the link when the queue is dry.
    // nullopt = timeout exhausted or link down (check link_down()).
    std::optional<ddk::ble::Message> receive(uint32_t timeout_ms);

    // Messages that arrived while a transceive was waiting for its AP_RS —
    // the flow drains these after the AP ladder, they are never dropped.
    std::deque<ddk::ble::Message>& deferred() { return deferred_; }

    void activate_message_security(const std::array<uint8_t,32>& sk_reader,
                                   const std::array<uint8_t,32>& sk_device);
    // Flips at Reader Status Access Protocol Completed.
    void set_secured(bool secured);
    bool secured() const;
    bool security_aborted() const;

    bool link_down() const { return link_down_; }
    void mark_link_down();
    // Tears the link down (BleLink::close) — responseTimeout expiry,
    // General Error, security abort.
    void close_link();
    size_t max_sdu_size() const;

private:
    bool send_sdu(ddk::span<const uint8_t> sdu);
    // Pulls SDUs into rx_; false = timeout or link down.
    bool pump(ddk::ble::Message& out, uint32_t timeout_ms);

    std::shared_ptr<ddk::BleLink> link_;
    std::optional<BleMessageSecurity> security_;
    std::deque<ddk::ble::Message> rx_;
    std::deque<ddk::ble::Message> deferred_;
    bool link_down_ = false;
};
