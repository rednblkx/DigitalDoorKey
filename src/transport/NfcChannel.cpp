#include "ddk/transport/NfcChannel.h"
#include "ApduChaining.h"
#include "DDKLogging.h"
#include <algorithm>

namespace {
const char* TAG = "NfcChannel";
} // namespace

namespace ddk {
  NfcChannel::NfcChannel(Callback cb) : callback_(std::move(cb)) {}

  TransportKind NfcChannel::kind() const { return TransportKind::Nfc; }

  size_t NfcChannel::max_command_payload() const { return 255; }
  ApduResponse ddk::NfcChannel::transceive(ddk::span<const uint8_t> capdu) {
      std::vector<uint8_t> cmd(capdu.begin(), capdu.end());
      std::vector<uint8_t> resp;
      bool ok = callback_(cmd, resp);

      if (!ok || resp.size() < 2)
          return {{}, 0x6F, 0x00};  // 6F00 = "no precise diagnosis"

      uint8_t sw1 = resp[resp.size() - 2];
      uint8_t sw2 = resp[resp.size() - 1];
      resp.resize(resp.size() - 2);
      return {std::move(resp), sw1, sw2};
  }

  ApduResponse ddk::NfcChannel::transceive_full(const ApduCommand &cmd,
                                          bool skip_response_chaining,
                                          size_t max_command_chunk) {
    return detail::transceive_with_chaining(*this, cmd,
                                            skip_response_chaining,
                                            max_command_chunk);
  }
}
