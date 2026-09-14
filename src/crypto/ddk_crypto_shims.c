#include "ddk_crypto_shims.h"

#if MBEDTLS_VERSION_MAJOR >= 4

#include "mbedtls/private/ecp.h"
#include "mbedtls/private/bignum.h"

#include <string.h>

// ---------------------------------------------------------------------------
// HKDF on the PSA key-derivation interface (PSA_ALG_HKDF = extract+expand).
// ---------------------------------------------------------------------------

static psa_algorithm_t hkdf_alg_from_md(const mbedtls_md_info_t *md) {
    // DDK only ever uses SHA-256 with this call site set; map by digest size.
    switch (mbedtls_md_get_size(md)) {
    case 32: return PSA_ALG_HKDF(PSA_ALG_SHA_256);
    case 48: return PSA_ALG_HKDF(PSA_ALG_SHA_384);
    case 64: return PSA_ALG_HKDF(PSA_ALG_SHA_512);
    default: return 0;
    }
}

int mbedtls_hkdf(const mbedtls_md_info_t *md, const unsigned char *salt,
                 size_t salt_len, const unsigned char *ikm, size_t ikm_len,
                 const unsigned char *info, size_t info_len,
                 unsigned char *okm, size_t okm_len) {
    psa_algorithm_t alg = hkdf_alg_from_md(md);
    if (alg == 0) {
        return MBEDTLS_ERR_MD_BAD_INPUT_DATA;
    }

    psa_status_t status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        return MBEDTLS_ERR_MD_BAD_INPUT_DATA;
    }

    psa_key_derivation_operation_t op = PSA_KEY_DERIVATION_OPERATION_INIT;
    status = psa_key_derivation_setup(&op, alg);
    if (status != PSA_SUCCESS) {
        return MBEDTLS_ERR_MD_BAD_INPUT_DATA;
    }

    // HKDF input order per PSA: salt (optional), secret, info.
    if (salt_len > 0) {
        status = psa_key_derivation_input_bytes(
            &op, PSA_KEY_DERIVATION_INPUT_SALT, salt, salt_len);
        if (status != PSA_SUCCESS) goto abort;
    }
    status = psa_key_derivation_input_bytes(
        &op, PSA_KEY_DERIVATION_INPUT_SECRET, ikm, ikm_len);
    if (status != PSA_SUCCESS) goto abort;
    if (info_len > 0) {
        status = psa_key_derivation_input_bytes(
            &op, PSA_KEY_DERIVATION_INPUT_INFO, info, info_len);
        if (status != PSA_SUCCESS) goto abort;
    }

    status = psa_key_derivation_output_bytes(&op, okm, okm_len);
    if (status != PSA_SUCCESS) goto abort;

    psa_key_derivation_abort(&op);
    return 0;

abort:
    psa_key_derivation_abort(&op);
    return MBEDTLS_ERR_MD_BAD_INPUT_DATA;
}

// ---------------------------------------------------------------------------
// ECDH P-256 shared-secret computation on psa_raw_key_agreement.
//
// The legacy API took raw scalars/points on a caller-owned group; PSA works on
// key objects, so we import both sides, derive, and destroy. Only secp256r1 is
// exercised by DDK (all callers load MBEDTLS_ECP_DP_SECP256R1); other groups
// are rejected.
// ---------------------------------------------------------------------------

int mbedtls_ecdh_compute_shared(mbedtls_ecp_group *grp, mbedtls_mpi *z,
                                const mbedtls_ecp_point *Q, const mbedtls_mpi *d,
                                int (*f_rng)(void *, unsigned char *, size_t),
                                void *p_rng) {
    (void)f_rng;
    (void)p_rng;
    if (grp == NULL || z == NULL || Q == NULL || d == NULL) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }
    if (grp->id != MBEDTLS_ECP_DP_SECP256R1) {
        return MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
    }

    psa_status_t status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    // Export the private scalar and peer point to wire format.
    unsigned char priv_be[32];
    if (mbedtls_mpi_write_binary(d, priv_be, sizeof(priv_be)) != 0) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }
    unsigned char peer[65];
    size_t peer_len = 0;
    if (mbedtls_ecp_point_write_binary(grp, Q, MBEDTLS_ECP_PF_UNCOMPRESSED,
                                       &peer_len, peer, sizeof(peer)) != 0) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    psa_key_attributes_t attrs = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attrs, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attrs, 256);
    psa_set_key_usage_flags(&attrs, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&attrs, PSA_ALG_ECDH);

    mbedtls_svc_key_id_t priv_key = mbedtls_svc_key_id_make(0, 0);
    status = psa_import_key(&attrs, priv_be, sizeof(priv_be), &priv_key);
    if (status != PSA_SUCCESS) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    uint8_t shared[PSA_RAW_KEY_AGREEMENT_OUTPUT_SIZE(
        PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1), 256)];
    size_t shared_len = 0;
    status = psa_raw_key_agreement(PSA_ALG_ECDH, priv_key, peer, peer_len,
                                   shared, sizeof(shared), &shared_len);
    psa_destroy_key(priv_key);
    if (status != PSA_SUCCESS) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    // The legacy API returned the X coordinate as a big-endian MPI.
    int ret = mbedtls_mpi_read_binary(z, shared, shared_len);
    mbedtls_platform_zeroize(shared, sizeof(shared));
    return ret;
}

#endif // MBEDTLS_VERSION_MAJOR >= 4
