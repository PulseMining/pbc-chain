// Copyright (c) 2026, PBC Chain
// HKDF-SHA256 implementation using OpenSSL (already linked in PBC build).

#include "pqc_hkdf.h"
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <cstring>

namespace pqc {

bool hkdf_sha256(uint8_t *output, size_t output_len,
                 const uint8_t *salt, size_t salt_len,
                 const uint8_t *ikm, size_t ikm_len,
                 const uint8_t *info, size_t info_len)
{
    if (!output || output_len == 0 || !ikm || ikm_len == 0)
        return false;
    if (output_len > 255 * 32)
        return false;

    EVP_KDF *kdf = EVP_KDF_fetch(nullptr, "HKDF", nullptr);
    if (!kdf)
        return false;

    EVP_KDF_CTX *ctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (!ctx)
        return false;

    OSSL_PARAM params[6];
    int idx = 0;
    const char *digest = "SHA256";
    params[idx++] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, const_cast<char*>(digest), 0);
    params[idx++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, const_cast<uint8_t*>(ikm), ikm_len);
    if (salt && salt_len > 0)
        params[idx++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, const_cast<uint8_t*>(salt), salt_len);
    if (info && info_len > 0)
        params[idx++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, const_cast<uint8_t*>(info), info_len);
    params[idx] = OSSL_PARAM_construct_end();

    int rc = EVP_KDF_derive(ctx, output, output_len, params);
    EVP_KDF_CTX_free(ctx);
    return rc == 1;
}

bool derive_pqc_seed(uint8_t output[32],
                     const uint8_t *master_seed, size_t master_seed_len,
                     const char *domain_label)
{
    if (!master_seed || master_seed_len == 0 || !domain_label)
        return false;

    return hkdf_sha256(output, 32,
                       nullptr, 0,  // no salt (IKM is already random)
                       master_seed, master_seed_len,
                       reinterpret_cast<const uint8_t*>(domain_label), strlen(domain_label));
}

} // namespace pqc
