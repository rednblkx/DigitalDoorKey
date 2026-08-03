#include "ndef.h"

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <vector>

namespace {

std::vector<NDEFRecord> unpack(const std::vector<unsigned char>& bytes) {
  auto input = bytes;
  NDEFMessage message(input.data(), input.size());
  return message.unpack();
}

void expect_bytes(const std::vector<unsigned char>& actual,
                  std::initializer_list<unsigned char> expected) {
  assert(actual == std::vector<unsigned char>(expected));
}

void expect_all_truncations_rejected(const std::vector<unsigned char>& valid) {
  assert(!unpack(valid).empty());
  for (size_t length = 0; length < valid.size(); ++length) {
    const std::vector<unsigned char> truncated(valid.begin(), valid.begin() + length);
    assert(unpack(truncated).empty());
  }
}

}  // namespace

int main() {
  const std::vector<unsigned char> short_record = {
      0xd1, 0x01, 0x03, 'T', 'a', 'b', 'c'};
  auto records = unpack(short_record);
  assert(records.size() == 1);
  assert(records[0].tnf == 1);
  expect_bytes(records[0].type, {'T', 0});
  expect_bytes(records[0].id, {0});
  expect_bytes(records[0].data, {'a', 'b', 'c', 0});
  expect_all_truncations_rejected(short_record);

  const std::vector<unsigned char> id_record = {
      0xd9, 0x02, 0x02, 0x03, 'H', 'r', 'i', 'd', '1', 0xaa, 0xbb};
  records = unpack(id_record);
  assert(records.size() == 1);
  expect_bytes(records[0].type, {'H', 'r', 0});
  expect_bytes(records[0].id, {'i', 'd', '1', 0});
  expect_bytes(records[0].data, {0xaa, 0xbb, 0});
  expect_all_truncations_rejected(id_record);

  std::vector<unsigned char> long_record = {
      0xc2, 0x01, 0x00, 0x00, 0x01, 0x2c, 'x'};
  for (uint16_t value = 0; value < 300; ++value) {
    long_record.push_back(static_cast<unsigned char>(value));
  }
  records = unpack(long_record);
  assert(records.size() == 1);
  assert(records[0].data.size() == 301);
  assert(records[0].data[0] == 0);
  assert(records[0].data[255] == 255);
  assert(records[0].data[256] == 0);
  assert(records[0].data.back() == 0);
  expect_all_truncations_rejected(long_record);

  const std::vector<unsigned char> multi_record = {
      0x91, 0x01, 0x01, 'a', 0x01,
      0x51, 0x01, 0x01, 'b', 0x02};
  records = unpack(multi_record);
  assert(records.size() == 2);
  expect_all_truncations_rejected(multi_record);

  const std::vector<unsigned char> missing_mb = {
      0x51, 0x01, 0x01, 'a', 0x01};
  assert(unpack(missing_mb).empty());

  const std::vector<unsigned char> repeated_mb = {
      0x91, 0x01, 0x01, 'a', 0x01,
      0xd1, 0x01, 0x01, 'b', 0x02};
  assert(unpack(repeated_mb).empty());

  const std::vector<unsigned char> early_me = {
      0xd1, 0x01, 0x01, 'a', 0x01,
      0x51, 0x01, 0x01, 'b', 0x02};
  assert(unpack(early_me).empty());

  const std::vector<unsigned char> oversized_payload = {
      0xc1, 0x00, 0xff, 0xff, 0xff, 0xff};
  assert(unpack(oversized_payload).empty());

  return 0;
}
