#include "CommonCryptoUtils.h"

#include <array>
#include <cstdio>
#include <string>

#include <mbedtls/ecp.h>
#include <mbedtls/md.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/error.h>
#include <mbedtls/platform_util.h>
#include <logging.h>

#include <mbedtls/gcm.h>
#if defined(CONFIG_IDF_CMAKE)
#include <esp_random.h>
#else 
#include "sodium.h"
#endif

namespace CommonCryptoUtils
{
  const char* TAG = "CCUtils";

  int esp_rng(void *, uint8_t *buf, size_t len)
  {
    #if defined(CONFIG_IDF_CMAKE)
    esp_fill_random(buf, len);
    #else 
    randombytes(buf, len);
    #endif
    return 0;
  }

  bool constant_time_compare(const uint8_t* a, const uint8_t* b, size_t len) {
      uint8_t diff = 0;
      for (size_t i = 0; i < len; ++i) {
          diff |= (a[i] ^ b[i]);
      }
      return diff == 0;
  }

  bool constant_time_compare(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
      return a.size() == b.size() && constant_time_compare(a.data(), b.data(), a.size());
  }
  
  // --- ECC Utilities ---
  
  /**
   * Extracts the X coordinate (first 32 bytes of uncompressed point) from a P-256 public key.
   */
  inline std::vector<uint8_t> get_x(const std::vector<uint8_t> &pubKey) {
    if (pubKey.size() < 65) return {}; // Expect uncompressed point (0x04 + X + Y)
    return std::vector<uint8_t>(pubKey.begin() + 1, pubKey.begin() + 33);
  }

  std::vector<uint8_t> decryptAesGcm(const std::vector<uint8_t> &ciphertext, const std::array<uint8_t,32> &key,
  const std::array<uint8_t,12> &iv) {
    if (ciphertext.size() < 16) {
      ESP_LOGE(TAG, "Ciphertext too short for GCM (needs at least 16 bytes for tag)");
      return {};
    }

    LOG(I, "%s", redactHex("sk_device", key.data(), key.size()).c_str());

    GcmGuard gcm_ctx;

    int ret = mbedtls_gcm_setkey(gcm_ctx, MBEDTLS_CIPHER_ID_AES, key.data(), 256);
    if (ret != 0) {
      ESP_LOGE(TAG, "mbedtls_gcm_setkey failed: %d", ret);
      return {};
    }

    size_t ciphertext_len = ciphertext.size() - 16;
    const unsigned char* tag = ciphertext.data() + ciphertext_len;

    std::vector<uint8_t> plaintext(ciphertext_len);

    ret = mbedtls_gcm_auth_decrypt(gcm_ctx, ciphertext_len,
                                    iv.data(), 12,  // 12-byte IV
                                    nullptr, 0,  // no additional data
                                    tag, 16,  // 16-byte tag
                                    ciphertext.data(), plaintext.data());

    if (ret != 0) {
      ESP_LOGE(TAG, "mbedtls_gcm_auth_decrypt failed: %d", ret);
      return {};
    }

    return plaintext;
  }

  /**
   * The function performs an elliptic curve Diffie-Hellman key exchange to compute a shared key between
   * the reader and the endpoint.
   *
   * @param outBuf The `outBuf` parameter is a pointer to a buffer where the computed shared key will be
   * stored. It should be allocated with enough space to hold `oLen` bytes.
   * @param oLen oLen is the length of the output buffer (outBuf) where the shared key will be written.
   */
  void get_shared_key(const std::vector<uint8_t> &key1, const std::vector<uint8_t> &key2, uint8_t *outBuf, size_t oLen)
  {
    EcpGroupGuard grp;
    MpiGuard reader_ephemeral_private_key;
    MpiGuard shared_key;
    EcpPointGuard endpoint_ephemeral_public_key;

    // Initialize the elliptic curve group (e.g., SECP256R1)
    mbedtls_ecp_group_load(grp, MBEDTLS_ECP_DP_SECP256R1);

    // Set the reader's ephemeral private key
    int mpi_read = mbedtls_mpi_read_binary(reader_ephemeral_private_key, key1.data(), key1.size());

    if(mpi_read != 0){
      LOG(E, "mpi_read - %d", mpi_read);
      return;
    }

    // Set the endpoint's ephemeral public key
    int ecp_read = mbedtls_ecp_point_read_binary(grp, endpoint_ephemeral_public_key, key2.data(), key2.size());
    if(ecp_read != 0){
      LOG(E, "ecp_read - %d", ecp_read);
      return;
    }

    // Perform key exchange
    int ecdh_compute_shared = mbedtls_ecdh_compute_shared(grp, shared_key, endpoint_ephemeral_public_key, reader_ephemeral_private_key,
                                esp_rng, NULL);
    if(ecdh_compute_shared != 0){
      LOG(E, "ecdh_compute_shared - %d", ecdh_compute_shared);
      return;
    }

    int mpi_write = mbedtls_mpi_write_binary(shared_key, outBuf, oLen);
    if(mpi_write != 0){
      LOG(E, "mpi_write - %d", mpi_write);
      return;
    }
  }

  /**
   * The function generates an ephemeral key pair using the secp256r1 elliptic curve and returns the
   * private and public keys as vectors of uint8_t.
   * 
   * @return The function `generateEphemeralKey` returns a tuple containing two vectors of type
   * `uint8_t`. The first vector `bufPriv` contains the private key generated, and the second vector
   * `bufPub` contains the public key generated.
   */
  std::tuple<std::vector<uint8_t>, std::vector<uint8_t>> generateEphemeralKey()
  {
    EcpKeyPairGuard ephemeral;
    int gen_key = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, ephemeral, esp_rng, NULL);
    if(gen_key != 0){
      LOG(E, "gen_key - %d", gen_key);
      return std::make_tuple(std::vector<uint8_t>(), std::vector<uint8_t>());
    }
    std::vector<uint8_t> bufPriv(mbedtls_mpi_size(&ephemeral.kp.MBEDTLS_PRIVATE(d)));
    int mpi_write = mbedtls_mpi_write_binary(&ephemeral.kp.MBEDTLS_PRIVATE(d), bufPriv.data(), bufPriv.capacity());
    if(mpi_write != 0){
      LOG(E, "mpi_write - %d", mpi_write);
      return std::make_tuple(std::vector<uint8_t>(), std::vector<uint8_t>());
    }
    std::vector<uint8_t> bufPub(MBEDTLS_ECP_MAX_PT_LEN);
    size_t olen = 0;
    int ecp_write = mbedtls_ecp_point_write_binary(&ephemeral.kp.MBEDTLS_PRIVATE(grp), &ephemeral.kp.MBEDTLS_PRIVATE(Q), MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, bufPub.data(), bufPub.capacity());
    if(!ecp_write){
      LOG(D, "%s", redactHex("Ephemeral public key", bufPub.data(), olen > 8 ? 8 : olen).c_str());
    } else{
      LOG(E, "ecp_write - %d", ecp_write);
      return std::make_tuple(std::vector<uint8_t>(), std::vector<uint8_t>());
    }
    bufPub.resize(olen);
    return std::make_tuple(std::move(bufPriv), std::move(bufPub));
  }

  /**
   * The function `get_x` takes a public key as input, converts it to a point on an elliptic curve,
   * extracts the X coordinate of the point, and returns it as a vector of bytes.
   * 
   * @param pubKey The `pubKey` parameter is a reference to a `std::vector<uint8_t>` object, which
   * represents a public key. It is passed by reference so that the function can read the key and perform
   * operations on it without making a copy of the data.
   * 
   * @return a std::vector<uint8_t> object, which contains the X coordinate of the given public key.
   */
  std::vector<uint8_t> get_x(std::vector<uint8_t> &pubKey)
  {
    EcpGroupGuard grp;
    EcpPointGuard point;
    mbedtls_ecp_group_load(grp, MBEDTLS_ECP_DP_SECP256R1);
    int ecp_read = mbedtls_ecp_point_read_binary(grp, point, pubKey.data(), pubKey.size());
    if(ecp_read != 0)
      LOG(E, "ecp_read - %d", ecp_read);
    size_t buffer_size_x = mbedtls_mpi_size(&point.pt.MBEDTLS_PRIVATE(X));
    std::vector<uint8_t> X(buffer_size_x);
    int ecp_write = mbedtls_mpi_write_binary(&point.pt.MBEDTLS_PRIVATE(X), X.data(), buffer_size_x);
    if(ecp_write != 0)
      LOG(E, "ecp_write - %d", ecp_write);
    LOG(V, "%s, %s", redactHex("PublicKey", pubKey.data(), pubKey.size()).c_str(), redactHex("X Coordinate", X.data(), X.size()).c_str());
    return X;
  }

  /**
   * The function `signSharedInfo` takes in data and a key, performs a SHA256 hash on the data, and then
   * signs the hash with the key using the ECDSA algorithm.
   * 
   * @param data A pointer to the data that needs to be signed.
   * @param dataLen The parameter `dataLen` represents the length of the `data` array, which is the input
   * data that needs to be signed.
   * @param key The "key" parameter is a pointer to an array of uint8_t values that represents the key
   * used for signing the data. The "keyLen" parameter specifies the length of the key array.
   * @param keyLen The parameter `keyLen` represents the length of the key in bytes.
   * 
   * @return a std::vector<uint8_t> object, which contains the signature point generated by signing the
   * shared information using the provided data and key.
   */
  std::vector<uint8_t> signSharedInfo(const uint8_t *data, const size_t dataLen, const uint8_t *key, const size_t keyLen)
  {
    EcpKeyPairGuard keypair;
    MpiGuard sigMpi1, sigMpi2;

    uint8_t hash[32];

    mbedtls_md(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), data, dataLen, hash);

    int ecp_read = mbedtls_ecp_read_key(MBEDTLS_ECP_DP_SECP256R1, keypair, key, keyLen);
    if(ecp_read != 0){
      LOG(E, "ecp_read - %d", ecp_read);
      return std::vector<uint8_t>();
    }
    int ecdsa_sign = mbedtls_ecdsa_sign_det_ext(&keypair.kp.MBEDTLS_PRIVATE(grp), sigMpi1, sigMpi2, &keypair.kp.MBEDTLS_PRIVATE(d), hash, keyLen, MBEDTLS_MD_SHA256, esp_rng, NULL);
    if(ecdsa_sign != 0){
      LOG(E, "ecdsa_sign - %d", ecdsa_sign);
      return std::vector<uint8_t>();
    }
    std::vector<uint8_t> sigPoint(mbedtls_mpi_size(sigMpi1) + mbedtls_mpi_size(sigMpi2));
    int ecp_write_1 = mbedtls_mpi_write_binary(sigMpi1, sigPoint.data(), mbedtls_mpi_size(sigMpi1));
    if(ecp_write_1 != 0){
      LOG(E, "ecp_write_1 - %d", ecp_write_1);
      return std::vector<uint8_t>();
    }
    int ecp_write_2 = mbedtls_mpi_write_binary(sigMpi2, sigPoint.data() + mbedtls_mpi_size(sigMpi1), mbedtls_mpi_size(sigMpi2));
    if(ecp_write_2 != 0){
      LOG(E, "ecp_write_2 - %d", ecp_write_2);
      return std::vector<uint8_t>();
    }
    return sigPoint;
  }
}
