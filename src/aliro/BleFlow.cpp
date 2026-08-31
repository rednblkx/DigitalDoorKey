#include "ddk/aliro/BleFlow.h"
#include "ddk/aliro/UwbRangingChannel.h"
#include "aliro/AliroKeySchedule.h"
#include "aliro/AliroSecureContext.h"
#include "aliro/BleProfile.h"
#include "aliro/Profile.h"
#include "BleChannel.h"
#include "BleMessages.h"
#include "BleTransport.h"
#include "BerTlv.h"
#include "DDKLogging.h"
#include "ddk/store/ReaderIdentity.h"
#include <chrono>
#include <optional>

namespace {
constexpr const char* TAG = "BleFlow";

using namespace ddk::ble;
using BleMessage = ddk::ble::Message;

// Re-encodes the device's 0xA5 proprietary TLV exactly the way
// Profile::validate_select rebuilds it from the NFC SELECT FCI — the
// byte string that feeds the key-schedule salt must match both paths.
std::vector<uint8_t> rewrap_a5(const std::vector<uint8_t>& value) {
    std::vector<uint8_t> out;
    out.push_back(0xA5);
    const auto& pv = value;
    if (pv.size() < 0x80) {
        out.push_back(static_cast<uint8_t>(pv.size()));
    } else if (pv.size() <= 0xFF) {
        out.push_back(0x81);
        out.push_back(static_cast<uint8_t>(pv.size()));
    } else if (pv.size() <= 0xFFFF) {
        out.push_back(0x82);
        out.push_back(static_cast<uint8_t>(pv.size() >> 8));
        out.push_back(static_cast<uint8_t>(pv.size() & 0xFF));
    }
    out.insert(out.end(), pv.begin(), pv.end());
    return out;
}

// True when version (2B) appears in a supported-versions list (2B each).
bool version_in_list(const std::vector<uint8_t>& list, const std::array<uint8_t,2>& v) {
    if (list.empty()) return true;   // no list served — nothing to check
    for (size_t i = 0; i + 1 < list.size(); i += 2)
        if (list[i] == v[0] && list[i + 1] == v[1]) return true;
    return false;
}

uint8_t status_byte(ddk::aliro::ReaderStatus status) {
    return static_cast<uint8_t>(static_cast<uint16_t>(status) & 0xFF);
}

}  // namespace

namespace ddk::aliro {

BleFlow::BleFlow(std::shared_ptr<BleLink> link, CredentialStore& store,
                 BleFlowConfig config)
    : transport_(std::make_unique<AliroBleTransport>(std::move(link))),
      store_(store), config_(std::move(config))
{
    channel_ = std::make_shared<BleChannel>(*transport_, config_.response_timeout_ms);
}

BleFlow::~BleFlow() = default;

void BleFlow::set_callbacks(Callbacks callbacks) {
    callbacks_ = std::move(callbacks);
}

bool BleFlow::secured() const { return transport_->secured(); }
bool BleFlow::link_down() const { return transport_->link_down(); }

void BleFlow::set_uwb_ranging_channel(UwbRangingChannel* channel) {
    uwb_channel_ = channel;
    if (channel) {
        channel->set_sender([this](ddk::span<const uint8_t> frame) {
            return send_uwb_frame(frame);
        });
    }
}

bool BleFlow::send_uwb_frame(ddk::span<const uint8_t> frame) {
    if (frame.size() < 4) return false;
    BleMessage msg;
    msg.type = static_cast<ProtocolType>(frame[0] & 0x3F);
    msg.message_id = frame[1];
    msg.payload.assign(frame.begin() + 4, frame.end());
    return transport_->send(msg);
}

bool BleFlow::send_notification(uint8_t message_id, std::vector<uint8_t> payload) {
    BleMessage msg;
    msg.type = ProtocolType::Notification;
    msg.message_id = message_id;
    msg.payload = std::move(payload);
    return transport_->send(msg);
}

void BleFlow::send_failure_event() {
    // Pre-completion failures surface as a CLEAR General Error;
    // The reader status itself rode the 0x97 EXCHANGE where a channel existed. 
    // Post-completion this seals automatically (secured window).
    send_notification(notification_id::kEvent,
                      ddk::ble::event_general_error(ddk::ble::GeneralError::Unknown));
}

void BleFlow::send_ap_completed() {
    // Everything from Reader Status Access Protocol Completed onward is
    // BleSK-encrypted — flip the window before sending.
    transport_->set_secured(true);
    ap_completed_ = true;
    send_notification(notification_id::kReaderStatusApCompleted,
                      ddk::ble::reader_status_ap_completed(
                          status_byte(ReaderStatus::StateUnknown),
                          config_.unsolicited_status_mode));
    // Expedited/step-up keys are deleted by both sides at AP Completed
    // drop the context, only BleSK stays live.
    if (session_) session_->set_secure_context(nullptr);
    LOG(I, "Reader Status Access Protocol Completed sent");
}

bool BleFlow::notify_status(ReaderStatus status, uint8_t operation_source) {
    if (!secured()) {
        LOG(E, "notify_status requires the AP Completed (BleSK) window");
        return false;
    }
    return send_notification(notification_id::kReaderStatusChanged,
                             ddk::ble::reader_status_changed(
                                 status_byte(status),
                                 static_cast<ddk::ble::OperationSource>(operation_source)));
}

// Called via BleProfile's on_auth_success hook: activates BleSK message
// security (both sides hold the OKM slices now) and performs the URSK
// handoff for the BLE+UWB flow.
bool BleFlow::offer_ursk(Session& session) {
    auto* ctx = static_cast<AliroSecureContext*>(session.secure_context());

    if (ctx && ctx->ble_sk() && !ble_security_active_) {
        auto keys = AliroKeySchedule::derive_ble_session_keys(
            ddk::span<const uint8_t>(ctx->ble_sk()->data(), ctx->ble_sk()->size()),
            config_.reader_supported_versions,
            ddk::span<const uint8_t>(config_.selected_version.data(),
                                     config_.selected_version.size()));
        transport_->activate_message_security(keys.sk_reader, keys.sk_device);
        ble_security_active_ = true;
    }

    if (!config_.ble_uwb_flow_supported) return true;
    if (!ctx || !ctx->ursk()) {
        LOG(W, "BLE+UWB flow advertised but no URSK available");
        return true;
    }

    std::vector<uint8_t> tlv{0x98, 0x00};   // "Make URSK available", zero-length
    auto resp = ctx->exchange(session, tlv, /*skip_response_chaining=*/true);
    if (!resp.ok()) {
        LOG(E, "URSK-offer EXCHANGE failed (SW %02X%02X)", resp.sw1, resp.sw2);
        return false;
    }

    const auto& tid = session.transcript().transaction_id;
    uint32_t uwb_session_id = (static_cast<uint32_t>(tid[12]) << 24) |
                              (static_cast<uint32_t>(tid[13]) << 16) |
                              (static_cast<uint32_t>(tid[14]) << 8) |
                              static_cast<uint32_t>(tid[15]);
    LOG(I, "URSK offered for UWB session %08X", uwb_session_id);
    if (uwb_channel_) {
        uwb_channel_->arm(uwb_session_id,
                          ddk::span<const uint8_t>(ctx->ursk()->data(),
                                                   ctx->ursk()->size()));
    }
    if (callbacks_.on_ursk_available)
        callbacks_.on_ursk_available(*ctx->ursk(), uwb_session_id);
    return true;
}

bool BleFlow::establish(const SessionConfig& session_config, FailureReason& reason) {
    const auto& identity = store_.reader_identity();
    if (identity.group_identifier.size() != 16 ||
        identity.sub_identifier.size() != 16) {
        LOG(E, "reader identity must be gid(16)+sub(16), got %zu+%zu",
            identity.group_identifier.size(), identity.sub_identifier.size());
        reason = FailureReason::ChannelError;
        return false;
    }

    if (!version_in_list(config_.reader_supported_versions, config_.selected_version)) {
        LOG(E, "selected version %02X%02X not in the reader's supported list",
            config_.selected_version[0], config_.selected_version[1]);
        reason = FailureReason::VersionMismatch;
        return false;
    }

    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::milliseconds(config_.initiate_wait_ms);
    std::optional<BleMessage> initiate;
    while (!initiate) {
        long remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
                             deadline - std::chrono::steady_clock::now()).count();
        if (remaining <= 0) {
            LOG(W, "no Initiate Access Protocol within %u ms", config_.initiate_wait_ms);
            reason = FailureReason::ChannelError;
            return false;
        }
        auto msg = transport_->receive(static_cast<uint32_t>(remaining));
        if (!msg) {
            LOG(W, "Initiate Access Protocol reception failed (link down or timeout)");
            reason = FailureReason::ChannelError;
            return false;
        }
        if (msg->type == ProtocolType::Notification &&
            msg->message_id == notification_id::kInitiateAccessProtocol) {
            rke_transaction_ = false;
            initiate = std::move(*msg);
        } else if (msg->type == ProtocolType::Notification &&
                   msg->message_id == notification_id::kInitiateAccessProtocolRke) {
            if (!config_.ble_only_flow_supported) {
                LOG(W, "RKE initiation but BLE-only flow is not advertised");
                send_failure_event();
                reason = FailureReason::ChannelError;
                return false;
            }
            rke_transaction_ = true;
            initiate = std::move(*msg);
        } else if (msg->type == ProtocolType::Notification &&
                   msg->message_id == notification_id::kEvent) {
            auto attrs = ddk::ble::parse_attributes(msg->payload);
            if (attrs && ddk::ble::find_attribute(*attrs, event_attr::kGeneralError)) {
                LOG(W, "General Error from device before initiation");
                reason = FailureReason::ChannelError;
                return false;
            }
            LOG(D, "Event Busy before initiation — continuing");
        } else {
            LOG(W, "message %d/%d before Initiate Access Protocol — ignored",
                static_cast<int>(msg->type), msg->message_id);
        }
    }

    auto attrs = ddk::ble::parse_attributes(initiate->payload);
    const ddk::ble::Attribute* proprietary =
        attrs ? ddk::ble::find_attribute(*attrs, 0) : nullptr;
    if (!proprietary || proprietary->value.empty()) {
        LOG(E, "Initiate Access Protocol without proprietary information");
        reason = FailureReason::ChannelError;
        return false;
    }

    auto parsed = BerTlvMessage::from_bytes(proprietary->value.data(),
                                            proprietary->value.size());
    const BerTlv* a5 = parsed.find(0xA5);
    if (!a5) {
        LOG(E, "proprietary information missing the 0xA5 TLV");
        reason = FailureReason::ChannelError;
        return false;
    }

    auto a5_inner = a5->parse_inner();
    const BerTlv* version = a5_inner.find(0x5C);
    if (version && !version->value.empty()) {
        std::array<uint8_t,2> selected{config_.selected_version[0],
                                       config_.selected_version[1]};
        if (!version_in_list(version->value, selected)) {
            LOG(E, "device does not list the selected version %02X%02X",
                selected[0], selected[1]);
            reason = FailureReason::VersionMismatch;
            return false;
        }
    }

    // Ext-info 0x7F66: max command data size for ENVELOPE chunking —
    // same input Profile::validate_select parses on NFC.
    size_t max_command_data_size = 255;
    const std::array<uint8_t,2> ext_info_tag{0x7F, 0x66};
    if (const BerTlv* ext_info = a5_inner.find(ext_info_tag)) {
        auto ext_inner = ext_info->parse_inner();
        if (const BerTlv* max_recv = ext_inner.find(0x02);
            max_recv && !max_recv->value.empty()) {
            max_command_data_size = 0;
            for (uint8_t b : max_recv->value)
                max_command_data_size = (max_command_data_size << 8) | b;
        }
    }

    SessionConfig cfg = session_config;
    if (cfg.authentication_policy == 0x02) {
        LOG(W, "authentication_policy 0x02 (setting-secure) is not permitted "
               "over BLE — using 0x01");
        cfg.authentication_policy = 0x01;
    }
    if (rke_transaction_ && cfg.target_flow == Flow::Fast) {
        LOG(D, "RKE flow: expedited-fast is not permitted — using standard");
        cfg.target_flow = Flow::Standard;
    }

    session_ = std::make_unique<Session>(channel_, store_, cfg);
    auto& t = session_->transcript();
    t.protocol_version = {config_.selected_version[0], config_.selected_version[1]};
    t.flags[0] = (cfg.target_flow == Flow::Fast) ? 0x01 : 0x00;
    t.flags[1] = cfg.authentication_policy;
    t.interface = static_cast<uint8_t>(session_->apdu().kind());   // 0xC3
    t.fci_proprietary = rewrap_a5(a5->value);

    BleProfile::Hooks hooks;
    hooks.make_ursk_available = [this](Session& s) { return offer_ursk(s); };
    hooks.notify_ap_completed = [this] { send_ap_completed(); };
    hooks.notify_failure = [this] { send_failure_event(); };
    profile_ = std::make_unique<BleProfile>(std::move(hooks));
    static_cast<Profile*>(profile_.get())->set_max_command_data_size(max_command_data_size);
    return true;
}

AuthOutcome BleFlow::run(SessionConfig session_config) {
    AuthOutcome outcome;
    ap_completed_ = false;
    rke_transaction_ = false;
    ble_security_active_ = false;

    FailureReason reason = FailureReason::None;
    if (!establish(session_config, reason)) {
        outcome.state = FlowState::Failed;
        outcome.reason = reason;
        transport_->close_link();
        return outcome;
    }

    auto state = FlowState::Selected;
    while (state != FlowState::Done && state != FlowState::Failed)
        state = profile_->step(*session_, state);

    outcome = profile_->finalize(*session_);
    if (ap_completed_)
        serve_post_ap();
    else
        transport_->close_link();
    return outcome;
}

void BleFlow::serve_post_ap() {
    auto dispatch = [this](const BleMessage& msg) -> bool {
        if (msg.type == ProtocolType::Notification) {
            switch (msg.message_id) {
            case notification_id::kEvent: {
                auto attrs = ddk::ble::parse_attributes(msg.payload);
                if (attrs && ddk::ble::find_attribute(*attrs, event_attr::kGeneralError)) {
                    LOG(W, "General Error from device — ending session");
                    return false;
                }
                return true;   // Busy / Reader Descriptor → nothing to do
            }
            case notification_id::kRkeRequest:
                if (!config_.ble_only_flow_supported) {
                    LOG(W, "RKE Request but BLE-only flow is not advertised — ignored");
                    return true;
                }
                return handle_rke_request(msg.payload);
            case notification_id::kInitiateAccessProtocol:
            case notification_id::kInitiateAccessProtocolRke:
                LOG(W, "Initiate Access Protocol after AP Completed — ignored");
                return true;
            case notification_id::kReaderStatusChanged:
            case notification_id::kReaderStatusApCompleted:
                LOG(W, "reader-status notification from the device side — ignored");
                return true;
            case notification_id::kRanging:
                if (config_.ble_uwb_flow_supported && uwb_channel_) {
                    return true;   // routed below as a whole frame
                }
                if (config_.ble_uwb_flow_supported) {
                    LOG(W, "ranging requested but no UWB service attached — declining");
                    send_notification(notification_id::kEvent,
                                      ddk::ble::event_general_error(
                                          ddk::ble::GeneralError::WrongParameters));
                    return false;
                }
                LOG(W, "ranging attribute in a BLE-only transaction — ignored");
                return true;
            default:
                return true;
            }
        }
        if (msg.type == ProtocolType::Supplementary) {
            if (callbacks_.on_time_sync) callbacks_.on_time_sync(msg.payload);
            else LOG(D, "Time Sync received with no handler");
            return true;
        }
        return true;
    };

    // Ranging-relevant frames go to the engine seam whole (the engine owns
    // the M1–M4 machine and the Time Sync handling parity); everything else
    // follows the generic post-AP dispatch.
    auto handle_post_ap = [this, &dispatch](const BleMessage& msg) -> bool {
        if (msg.type == ProtocolType::Supplementary) {
            if (callbacks_.on_time_sync) {
                callbacks_.on_time_sync(msg.payload);
            }
        }
        bool uwb_relevant =
            msg.type == ProtocolType::UwbRanging ||
            (msg.type == ProtocolType::Notification &&
             msg.message_id == notification_id::kRanging) ||
            msg.type == ProtocolType::Supplementary;
        if (uwb_relevant && uwb_channel_) {
            uwb_channel_->handle_frame(msg.encode());
            return true;
        }
        return dispatch(msg);
    };

    // Drain anything parked while the ladder was waiting on AP_RS.
    auto& deferred = transport_->deferred();
    while (!deferred.empty()) {
        if (handle_post_ap(deferred.front())) deferred.pop_front();
        else { deferred.clear(); break; }
    }

    // Short receive slices once a UWB engine is attached: the ranging
    // exchange is lock-step, and poll() must tick between messages so range
    // latches surface while the loop waits.
    const uint32_t slice_ms = uwb_channel_ ? 200 : config_.post_ap_idle_ms;
    // Idle deadline, not a session cap: any received frame pushes it out, and
    // a live ranging session holds it open indefinitely (the phone stops
    // talking BLE once it ranges; only link loss or a General Error ends it).
    auto idle_deadline = std::chrono::steady_clock::now() +
                         std::chrono::milliseconds(config_.post_ap_idle_ms);
    auto push_idle_deadline = [&idle_deadline, this] {
        idle_deadline = std::chrono::steady_clock::now() +
                        std::chrono::milliseconds(config_.post_ap_idle_ms);
    };
    while (!transport_->link_down() && !transport_->security_aborted()) {
        if (uwb_channel_ && uwb_channel_->ranging_active()) push_idle_deadline();
        long remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
                             idle_deadline - std::chrono::steady_clock::now()).count();
        if (remaining <= 0) {
            LOG(D, "post-AP idle timeout — ending session");
            break;
        }
        if (uwb_channel_) uwb_channel_->poll();
        auto msg = transport_->receive(
            static_cast<uint32_t>(std::min<long>(remaining, slice_ms)));
        if (!msg) continue;   // timeout → re-check deadline and link state
        push_idle_deadline();
        if (!handle_post_ap(*msg)) break;
    }

    if (uwb_channel_) uwb_channel_->stop();
}

bool BleFlow::handle_rke_request(const std::vector<uint8_t>& payload) {
    auto attrs = ddk::ble::parse_attributes(payload);
    const ddk::ble::Attribute* action =
        attrs ? ddk::ble::find_attribute(*attrs, 0) : nullptr;
    if (!action || action->value.size() != 1 ||
        (action->value[0] != ddk::ble::rke_action::kSecure &&
         action->value[0] != ddk::ble::rke_action::kUnsecure)) {
        LOG(W, "malformed RKE Request — ignored");
        return true;
    }

    bool secure = action->value[0] == ddk::ble::rke_action::kSecure;
    ReaderStatus status = ReaderStatus::StateUnknown;
    if (callbacks_.on_rke_request) {
        status = callbacks_.on_rke_request(secure);
    } else {
        LOG(W, "RKE Request with no handler — reporting unknown state");
    }
    return notify_status(status, static_cast<uint8_t>(ddk::ble::OperationSource::ThisDeviceBleOnly));
}

}  // namespace ddk::aliro
