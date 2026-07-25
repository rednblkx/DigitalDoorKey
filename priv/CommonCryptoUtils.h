#pragma once
#include "mbedtls/ecp.h"
#include <vector>
#include <array>
#include <mbedtls/aes.h>
#include <mbedtls/gcm.h>
#include <mbedtls/ecp.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/sha256.h>
#include <mbedtls/platform_util.h>

namespace CommonCryptoUtils {

struct GcmGuard {
    mbedtls_gcm_context ctx;
    GcmGuard() { mbedtls_gcm_init(&ctx); }
    ~GcmGuard() { mbedtls_gcm_free(&ctx); }
    operator mbedtls_gcm_context*() { return &ctx; };
    operator mbedtls_gcm_context() { return ctx; };
};

struct EcpKeyPairGuard {
    mbedtls_ecp_keypair kp;
    EcpKeyPairGuard() { mbedtls_ecp_keypair_init(&kp); }
    ~EcpKeyPairGuard() { mbedtls_ecp_keypair_free(&kp); }
    operator mbedtls_ecp_keypair*() { return &kp; };
    operator mbedtls_ecp_keypair() { return kp; };
};

struct EcpGroupGuard {
    mbedtls_ecp_group grp;
    EcpGroupGuard() { mbedtls_ecp_group_init(&grp); }
    ~EcpGroupGuard() { mbedtls_ecp_group_free(&grp); }
    operator mbedtls_ecp_group*() { return &grp; };
    operator mbedtls_ecp_group() { return grp; };
};

struct EcpPointGuard {
    mbedtls_ecp_point pt;
    EcpPointGuard() { mbedtls_ecp_point_init(&pt); }
    ~EcpPointGuard() { mbedtls_ecp_point_free(&pt); }
    operator mbedtls_ecp_point*() { return &pt; };
    operator mbedtls_ecp_point() { return pt; };
};

struct MpiGuard {
    mbedtls_mpi m;
    MpiGuard() { mbedtls_mpi_init(&m); }
    ~MpiGuard() { mbedtls_mpi_free(&m); }
    operator mbedtls_mpi*() { return &m; };
    operator mbedtls_mpi() { return m; };
};


bool constant_time_compare(const uint8_t* a, const uint8_t* b, size_t len);
bool constant_time_compare(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b);

std::vector<uint8_t> decryptAesGcm(
    const std::vector<uint8_t>& ciphertext, 
    const std::array<uint8_t, 32>& key,
    const std::array<uint8_t, 12>& iv
);

std::tuple<std::vector<uint8_t>, std::vector<uint8_t>> generateEphemeralKey();

void get_shared_key(
    const std::array<uint8_t,32>& priv_key, 
    const std::array<uint8_t,65>& pub_key, 
    uint8_t* out_buf, 
    size_t out_len
);

std::vector<uint8_t> signSharedInfo(const uint8_t *data, const size_t dataLen, const uint8_t *key, const size_t keyLen);

std::vector<uint8_t> get_x(std::array<uint8_t,65> &pubKey);

int esp_rng(void *, uint8_t *buf, size_t len);

} // namespace CommonCryptoUtils
