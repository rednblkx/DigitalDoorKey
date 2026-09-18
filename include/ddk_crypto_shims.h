#pragma once

// mbedtls 4 / TF-PSA-Crypto 1.x removed the legacy hkdf.h and ecdh.h modules.
// DDK uses two functions from them; this header re-exposes them with the exact
// legacy signatures, implemented on top of the PSA API (which provides HKDF as
// PSA_ALG_HKDF and ECDH as PSA_ALG_ECDH via psa_raw_key_agreement).

#include <mbedtls/build_info.h>
#include "psa/crypto.h"
#include "mbedtls/md.h"

#ifdef __cplusplus
extern "C" {
#endif

#if MBEDTLS_VERSION_MAJOR >= 4

// --- HKDF (RFC 5869), legacy mbedtls_hkdf signature ---

int mbedtls_hkdf(const mbedtls_md_info_t *md, const unsigned char *salt,
                 size_t salt_len, const unsigned char *ikm, size_t ikm_len,
                 const unsigned char *info, size_t info_len,
                 unsigned char *okm, size_t okm_len);

// --- ECDH, legacy mbedtls_ecdh_compute_shared signature ---

struct mbedtls_ecp_group;
struct mbedtls_mpi;
struct mbedtls_ecp_point;

int mbedtls_ecdh_compute_shared(mbedtls_ecp_group *grp, mbedtls_mpi *z,
                                const mbedtls_ecp_point *Q, const mbedtls_mpi *d,
                                int (*f_rng)(void *, unsigned char *, size_t),
                                void *p_rng);

#endif // MBEDTLS_VERSION_MAJOR >= 4

#ifdef __cplusplus
}
#endif
