#include "DDKReaderData.h"
#include <functional>
#include <mutex>
#include <tuple>

class HK_HomeKit
{
  private:
    const char* TAG = "HK_HomeKit";
    std::vector<uint8_t> &tlvData;
    readerData_t& readerData;
    static std::mutex provision_mutex;
    std::vector<uint8_t> getHashIdentifier(const std::vector<uint8_t>& key, bool sha256);
    std::vector<uint8_t> get_x(std::vector<uint8_t> &pubKey);
    std::vector<uint8_t> getPublicKey(uint8_t *privKey, size_t len);
    std::tuple<std::vector<uint8_t>, int> provision_device_cred(const std::vector<uint8_t> &buf);
    std::tuple<std::vector<uint8_t>, int> remove_device_cred(const std::vector<uint8_t> &buf);
    int set_reader_key(const std::vector<uint8_t>& buf);
    const std::function<void(const readerData_t&)> save_cb;
    const std::function<void()> remove_key_cb;
  public:
    HK_HomeKit(readerData_t& readerData, std::function<void(const readerData_t&)> save_cb, std::function<void()> remove_key_cb, std::vector<uint8_t> &tlvData);
    std::vector<uint8_t> processResult();
};
