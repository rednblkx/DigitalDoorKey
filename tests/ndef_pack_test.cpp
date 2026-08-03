#include "ndef.h"

#include <cassert>
#include <vector>

namespace {

NDEFRecord makeRecord(size_t payloadLength) {
  std::vector<unsigned char> payload(payloadLength, 0x5a);
  return NDEFRecord("", 0x01, "T", payload.data(), payload.size());
}

void testPayloadBoundary() {
  auto packed = NDEFMessage({makeRecord(255)}).pack();
  assert(packed.size() == 259);
  assert(packed[0] == 0xd1);
  assert(packed[1] == 1);
  assert(packed[2] == 255);

  packed = NDEFMessage({makeRecord(256)}).pack();
  assert(packed.size() == 263);
  assert(packed[0] == 0xc1);
  assert(packed[1] == 1);
  assert(packed[2] == 0);
  assert(packed[3] == 0);
  assert(packed[4] == 1);
  assert(packed[5] == 0);
  assert(packed[6] == 'T');
}

void testMultiRecordMessageBeyondOldBuffer() {
  auto packed = NDEFMessage({makeRecord(200), makeRecord(200)}).pack();
  assert(packed.size() == 408);
  assert(packed[0] == 0x91);
  assert(packed[204] == 0x51);
  assert(packed[207] == 'T');
}

void testOtherProtocolBoundaries() {
  std::vector<unsigned char> tooLong(257, 'x');
  tooLong.back() = '\0';
  std::vector<unsigned char> empty(1, '\0');

  assert(NDEFMessage({NDEFRecord(empty, 0x01, tooLong, empty)}).pack().empty());
  assert(NDEFMessage({NDEFRecord(tooLong, 0x01, empty, empty)}).pack().empty());
  assert(NDEFMessage({NDEFRecord(empty, 0x08, empty, empty)}).pack().empty());
}

}  // namespace

int main() {
  testPayloadBoundary();
  testMultiRecordMessageBeyondOldBuffer();
  testOtherProtocolBoundaries();
}
