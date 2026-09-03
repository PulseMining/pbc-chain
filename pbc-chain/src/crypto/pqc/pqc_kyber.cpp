// Copyright (c) 2026, PBC Chain
// ML-KEM-768 wrapper implementation using liboqs.

#include "pqc_kyber.h"
#include "pqc_hkdf.h"
#include <oqs/oqs.h>
#include <cstring>
#include <mutex>

namespace pqc {

// Secure destructor: zero-fill secret key memory
kyber_secret_key::~kyber_secret_key()
{
    OQS_MEM_cleanse(data, sizeof(data));
}

// Secure destructor: zero-fill shared secret memory
kyber_shared_secret::~kyber_shared_secret()
{
    OQS_MEM_cleanse(data, sizeof(data));
}

bool kyber_keygen(kyber_public_key &pk, kyber_secret_key &sk)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    if (!kem)
        return false;

    OQS_STATUS rc = OQS_KEM_keypair(kem, pk.data, sk.data);
    OQS_KEM_free(kem);
    return rc == OQS_SUCCESS;
}

bool kyber_keygen_deterministic(kyber_public_key &pk, kyber_secret_key &sk,
                                 const uint8_t seed[32])
{
    // Derive a deterministic seed for ML-KEM-768 keygen.
    // Same approach as Dilithium: HKDF-expand, set deterministic RNG, keygen, restore.

    uint8_t kem_seed[32];
    if (!derive_pqc_seed(kem_seed, seed, 32, "PBC_KYBER_V1"))
        return false;

    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    if (!kem)
        return false;

    // ML-KEM-768 internal keygen needs 64 bytes of randomness (d || z in FIPS 203).
    // L4 fix — mirrors pqc_dilithium.cpp: serialize the global-RNG override with a mutex,
    // use a 512-byte margin (HKDF stream → first 256 bytes unchanged, so keys derived from a
    // given seed are identical in the normal case), and HARD-FAIL instead of the old silent
    // memset(0) fallback that could emit weak/zero key material.
    static std::mutex s_kem_rng_mutex;
    static thread_local uint8_t s_kem_expanded[512];
    static thread_local size_t s_kem_offset = 0;
    static thread_local bool s_kem_underflow = false;

    if (!hkdf_sha256(s_kem_expanded, sizeof(s_kem_expanded),
                     nullptr, 0, kem_seed, 32,
                     reinterpret_cast<const uint8_t*>("PBC_KYBER_EXPAND"), 16))
    {
        OQS_KEM_free(kem);
        OQS_MEM_cleanse(kem_seed, sizeof(kem_seed));
        return false;
    }
    s_kem_offset = 0;
    s_kem_underflow = false;

    auto det_rng = [](uint8_t *random_array, size_t bytes_to_read) {
        if (s_kem_offset + bytes_to_read <= sizeof(s_kem_expanded)) {
            memcpy(random_array, s_kem_expanded + s_kem_offset, bytes_to_read);
            s_kem_offset += bytes_to_read;
        } else {
            // HARD FAIL: never silently produce weak/zero key material.
            memset(random_array, 0, bytes_to_read);
            s_kem_underflow = true;
        }
    };

    OQS_STATUS rc;
    {
        std::lock_guard<std::mutex> rng_lock(s_kem_rng_mutex);
        OQS_randombytes_custom_algorithm(det_rng);
        rc = OQS_KEM_keypair(kem, pk.data, sk.data);
        OQS_randombytes_switch_algorithm(OQS_RAND_alg_system);
    }

    OQS_KEM_free(kem);
    OQS_MEM_cleanse(kem_seed, sizeof(kem_seed));
    OQS_MEM_cleanse(s_kem_expanded, sizeof(s_kem_expanded));

    if (s_kem_underflow) {
        // Deterministic entropy was exhausted mid-keygen — refuse to emit a weak key.
        s_kem_underflow = false;
        OQS_MEM_cleanse(sk.data, sizeof(sk.data));
        OQS_MEM_cleanse(pk.data, sizeof(pk.data));
        return false;
    }

    return rc == OQS_SUCCESS;
}

bool kyber_encaps(kyber_ciphertext &ct, kyber_shared_secret &shared_secret,
                  const kyber_public_key &recipient_pk)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    if (!kem)
        return false;

    OQS_STATUS rc = OQS_KEM_encaps(kem, ct.data, shared_secret.data, recipient_pk.data);
    OQS_KEM_free(kem);
    return rc == OQS_SUCCESS;
}

bool kyber_decaps(kyber_shared_secret &shared_secret,
                  const kyber_ciphertext &ct,
                  const kyber_secret_key &sk)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    if (!kem)
        return false;

    OQS_STATUS rc = OQS_KEM_decaps(kem, shared_secret.data, ct.data, sk.data);
    OQS_KEM_free(kem);
    return rc == OQS_SUCCESS;
}

} // namespace pqc
