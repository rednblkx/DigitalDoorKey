/*
  Code highly inspired by https://github.com/kormax/apple-home-key-reader/blob/main/util/ndef.py
 */

#include "ndef.h"
#include <cstdint>
#include <limits>
#include <string.h>
#include <utility>
#include <vector>
#include "DDKLogging.h"

NDEFRecord::NDEFRecord() {
  this->id.assign(1, '\0');
  this->type.assign(1, '\0');
  this->data.assign(1, '\0');
  this->tnf = 0x00;
}

NDEFRecord::NDEFRecord(const char *id, unsigned char tnf, const char *type, unsigned char *data, size_t dataLen)
{
  this->id.insert(this->id.begin(), id, id + strlen(id));
  this->id.push_back('\0');
  this->type.insert(this->type.begin(), type, type + strlen(type));
  this->type.push_back('\0');
  this->data.insert(this->data.begin(), data, data + dataLen);
  this->data.push_back('\0');
  this->tnf = tnf;
}

NDEFRecord::NDEFRecord(std::vector<unsigned char> id, unsigned char tnf, std::vector<unsigned char> type, std::vector<unsigned char> data){
  this->id = id;
  this->type = type;
  this->data = data;
  this->tnf = tnf;
}

NDEFMessage::NDEFMessage(unsigned char *data, size_t length){
  if (length > 0) {
    this->packedData.insert(this->packedData.begin(), data, data + length);
  }
}

NDEFMessage::NDEFMessage(std::initializer_list<NDEFRecord> records)
{
  this->records.assign(records);
}

std::vector<unsigned char> NDEFMessage::pack()
{
  constexpr size_t maxByteLength =
      std::numeric_limits<unsigned char>::max();
  constexpr size_t maxPayloadLength =
      std::numeric_limits<uint32_t>::max();

  size_t packedSize = 0;
  for (const auto& record : this->records)
  {
    const size_t idLength = record.id.empty() ? 0 : record.id.size() - 1;
    const size_t typeLength = record.type.empty() ? 0 : record.type.size() - 1;
    const size_t payloadLength = record.data.empty() ? 0 : record.data.size() - 1;
    if (idLength > maxByteLength || typeLength > maxByteLength) {
      LOG(E, "NDEF record type or ID exceeds 255 bytes");
      return {};
    }
    if (payloadLength > maxPayloadLength) {
      LOG(E, "NDEF record payload exceeds 32-bit length field");
      return {};
    }
    if (record.tnf > 0x07) {
      LOG(E, "NDEF TNF exceeds its 3-bit field");
      return {};
    }

    const size_t payloadLengthFieldSize = payloadLength <= maxByteLength ? 1 : 4;
    const size_t recordSize = 2 + payloadLengthFieldSize +
                              (idLength > 0 ? 1 : 0) +
                              typeLength + idLength + payloadLength;
    if (recordSize > std::numeric_limits<size_t>::max() - packedSize) {
      LOG(E, "NDEF message size overflow");
      return {};
    }
    packedSize += recordSize;
  }

  this->packedData.clear();
  this->packedData.reserve(packedSize);
  for (size_t i = 0; i < this->records.size(); i++)
  {
    const auto& record = this->records[i];
    const size_t idLength = record.id.empty() ? 0 : record.id.size() - 1;
    const size_t typeLength = record.type.empty() ? 0 : record.type.size() - 1;
    const size_t payloadLength = record.data.empty() ? 0 : record.data.size() - 1;
    const bool shortRecord = payloadLength <= maxByteLength;
    const unsigned char header =
        (i == 0 ? 0x80 : 0x00) |
        (i == this->records.size() - 1 ? 0x40 : 0x00) |
        (shortRecord ? 0x10 : 0x00) |
        (idLength > 0 ? 0x08 : 0x00) |
        record.tnf;

    this->packedData.push_back(header);
    this->packedData.push_back(static_cast<unsigned char>(typeLength));
    if (shortRecord) {
      this->packedData.push_back(static_cast<unsigned char>(payloadLength));
    } else {
      const uint32_t encodedLength = static_cast<uint32_t>(payloadLength);
      this->packedData.push_back(static_cast<unsigned char>(encodedLength >> 24));
      this->packedData.push_back(static_cast<unsigned char>(encodedLength >> 16));
      this->packedData.push_back(static_cast<unsigned char>(encodedLength >> 8));
      this->packedData.push_back(static_cast<unsigned char>(encodedLength));
    }
    if (idLength > 0) {
      this->packedData.push_back(static_cast<unsigned char>(idLength));
    }
    this->packedData.insert(this->packedData.end(), record.type.begin(),
                            record.type.begin() + typeLength);
    this->packedData.insert(this->packedData.end(), record.id.begin(),
                            record.id.begin() + idLength);
    this->packedData.insert(this->packedData.end(), record.data.begin(),
                            record.data.begin() + payloadLength);
  }
  LOG(D, "NDEF MSG PACKED - LENGTH: %zu, DATA: %s", packedData.size(), redactHex("", packedData).c_str());
  return this->packedData;
}

std::vector<NDEFRecord> NDEFMessage::unpack(){
  std::vector<NDEFRecord> parsed_records;
  size_t i = 0;
  const size_t size = this->packedData.size();
  bool first_record = true;
  bool message_ended = false;

  const auto available = [&i, size](size_t length) {
    return i <= size && length <= size - i;
  };

  while(i < this->packedData.size())
  {
    if (!available(2)) return {};
    const unsigned char header = this->packedData[i++];
    const bool mb = (header & 0x80) != 0;
    const bool me = (header & 0x40) != 0;
    const bool sr = (header & 0x10) != 0;
    const bool il = (header & 0x08) != 0;
    const unsigned char tnf = header & 0x07;

    if (mb != first_record || message_ended) return {};

    const size_t type_length = this->packedData[i++];

    uint32_t payload_length = 0;
    if (sr) {
      if (!available(1)) return {};
      payload_length = this->packedData[i++];
    } else {
      if (!available(4)) return {};
      payload_length = (static_cast<uint32_t>(this->packedData[i]) << 24) |
                       (static_cast<uint32_t>(this->packedData[i + 1]) << 16) |
                       (static_cast<uint32_t>(this->packedData[i + 2]) << 8) |
                       static_cast<uint32_t>(this->packedData[i + 3]);
      i += 4;
    }

    size_t id_length = 0;
    if (il) {
      if (!available(1)) return {};
      id_length = this->packedData[i++];
    }

    if (!available(type_length)) return {};

    std::vector<unsigned char> type_vec;
    type_vec.insert(type_vec.end(), this->packedData.begin() + i,
                    this->packedData.begin() + i + type_length);
    type_vec.push_back('\0');
    i += type_length;

    if (!available(id_length)) return {};
    std::vector<unsigned char> id_vec;
    id_vec.insert(id_vec.end(), this->packedData.begin() + i,
                  this->packedData.begin() + i + id_length);
    id_vec.push_back('\0');
    i += id_length;

    if (!available(payload_length)) return {};
    std::vector<unsigned char> payload_vec;
    payload_vec.insert(payload_vec.end(), this->packedData.begin() + i,
                       this->packedData.begin() + i + payload_length);
    payload_vec.push_back('\0');
    i += payload_length;
    
    LOG(D, "NDEF RECORD ID: %s, TNF: %d, TYPE: %s, PAYLOAD: %s", redactHex("", id_vec).c_str(), (int)tnf, redactHex("", type_vec).c_str(), redactHex("", payload_vec).c_str());
    parsed_records.emplace_back(id_vec, tnf, type_vec, payload_vec);
    first_record = false;
    message_ended = me;

    if (message_ended && i != size) return {};
  }

  if (!message_ended) return {};
  this->records = std::move(parsed_records);
  return this->records;
}

NDEFRecord* NDEFMessage::findType(const char * type){
  NDEFRecord *foundRecord = nullptr;
  size_t type_len = (type != nullptr) ? strlen(type) : 0;
  for (auto &&record : records)
  {
    // record.type has a trailing '\0' appended by the constructor; compare
    // only the bytes that correspond to the actual type label.
    const auto& rt = record.type;
    size_t rt_len = (rt.empty() ? 0 : rt.size() - 1); // exclude trailing '\0'
    if (type_len == rt_len &&
        (rt_len == 0 || memcmp(type, rt.data(), rt_len) == 0)) {
      foundRecord = &record;
      break;
    }
  }
  if (foundRecord != nullptr) {
    LOG(D, "NDEF RECORD ID: %s, TNF: %s, TYPE: %s, PAYLOAD: %s",
        redactHex("", foundRecord->id).c_str(),
        redactHex("", std::vector<uint8_t>{foundRecord->tnf}).c_str(),
        redactHex("", foundRecord->type).c_str(),
        redactHex("", foundRecord->data).c_str());
  } else {
    LOG(D, "NDEF findType: no record matched type (len=%d)", (int)type_len);
  }
  return foundRecord;
}
