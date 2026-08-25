#include <cstdint>
#include <vector>
#include "ddk/transport/ApduChannel.h"

std::vector<uint8_t> ddk::ApduCommand::to_bytes(bool force_extended) const {
    const bool extended = force_extended || data.size() > 255 || ne > 256;
    std::vector<uint8_t> out;
    out.reserve(4 + data.size() + (extended ? 6 : 2));
    out.push_back(cla); out.push_back(ins); out.push_back(p1); out.push_back(p2);

    if (data.empty()) {
        if (ne == 0) return out;                       // case 1
        if (extended) {                                // case 2E: 00 Le1 Le2
            out.push_back(0x00);
            out.push_back(static_cast<uint8_t>(ne >> 8));
            out.push_back(static_cast<uint8_t>(ne & 0xFF));
        } else {                                       // case 2S
            out.push_back(ne == 256 ? 0x00 : static_cast<uint8_t>(ne));
        }
        return out;
    }

    if (extended) {                                    // case 3E/4E
        out.push_back(0x00);                           // extended-length marker
        out.push_back(static_cast<uint8_t>(data.size() >> 8));
        out.push_back(static_cast<uint8_t>(data.size() & 0xFF));
        out.insert(out.end(), data.begin(), data.end());
        if (ne > 0) {
            out.push_back(static_cast<uint8_t>(ne >> 8));
            out.push_back(static_cast<uint8_t>(ne & 0xFF));
        }
    } else {                                           // case 3S/4S
        out.push_back(static_cast<uint8_t>(data.size()));
        out.insert(out.end(), data.begin(), data.end());
        if (ne > 0) {
            out.push_back(ne == 256 ? 0x00 : static_cast<uint8_t>(ne));
        }
    }
    return out;
}
