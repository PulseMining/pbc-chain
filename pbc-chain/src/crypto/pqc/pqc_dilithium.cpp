// Copyright (c) 2026, PBC Chain
// ML-DSA-65 wrapper implementation using liboqs.

#include "pqc_dilithium.h"
#include "pqc_hkdf.h"
#include <oqs/oqs.h>
#include <cstring>
#include <memory>
#include <mutex>

namespace pqc {

// Secure destructor: zero-fill secret key memory
dilithium_secret_key::~dilithium_secret_key()
{
    OQS_MEM_cleanse(data, sizeof(data));
}

bool dilithium_keygen(dilithium_public_key &pk, dilithium_secret_key &sk)
{
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
    if (!sig)
        return false;

    OQS_STATUS rc = OQS_SIG_keypair(sig, pk.data, sk.data);
    OQS_SIG_free(sig);
    return rc == OQS_SUCCESS;
}

bool dilithium_keygen_deterministic(dilithium_public_key &pk, dilithium_secret_key &sk,
                                     const uint8_t seed[32])
{
    // Derive a deterministic seed for ML-DSA-65 keygen.
    // liboqs ML-DSA-65 keypair uses internal randomness by default.
    // To make it deterministic, we seed the DRBG before calling keypair.
    // liboqs supports OQS_randombytes_custom_algorithm() for this purpose.
    // 
    // Approach: derive 4032 bytes (secret_key_size) of pseudorandom material
    // from the 32-byte seed via HKDF, then use liboqs keypair_from_seed if available,
    // or use the standard approach of setting a custom RNG.

    // ML-DSA-65 in liboqs does NOT have a keypair_from_seed function in the public API.
    // Instead, we use a deterministic DRBG approach:
    // 1. Expand seed to 128 bytes via HKDF (more than enough for ML-DSA-65 internal seeding)
    // 2. Set a custom RNG that returns these bytes
    // 3. Generate keypair
    // 4. Restore default RNG

    // For now, use a simple approach: HKDF-expand the seed to 32 bytes,
    // then feed it to OQS_randombytes_switch_algorithm with NIST-KAT mode.
    // This is the standard way liboqs supports deterministic keygen for testing.

    // Actually, the cleanest approach for production is:
    // Derive the ML-DSA secret key material directly and compute the public key.
    // But ML-DSA internal structure is complex (seed → expand → public matrix).
    // The safest approach: use the NIST seed-based keygen.

    // liboqs provides OQS_SIG_keypair_from_KAT_seed for some algorithms.
    // For ML-DSA-65, the internal seed is 32 bytes. We can check if the function exists.

    // Safest production approach: HKDF the master seed to get a 32-byte ML-DSA seed,
    // then call the internal keygen with that seed.
    // ML-DSA spec (FIPS 204 Algorithm 1) takes a 32-byte seed ξ as input.

    uint8_t dil_seed[32];
    if (!derive_pqc_seed(dil_seed, seed, 32, "PBC_DILITHIUM_V1"))
        return false;

    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
    if (!sig)
        return false;

    // Use keypair_from_seed if available (liboqs >= 0.12)
    // The function signature is: keypair(pk, sk) with internal randomness,
    // or we can use the lower-level API.
    // For deterministic keygen, we temporarily override the RNG.

    // Save current RNG state and set deterministic one
    // liboqs approach: use OQS_randombytes_custom_algorithm
    // We'll provide our HKDF-derived bytes as the randomness source.

    // L4 fix — thread-safety: OQS_randombytes_custom_algorithm() overrides the GLOBAL
    // liboqs RNG. The per-keygen state below is thread_local, but the global override and
    // the keypair() call must be serialized so two concurrent keygens cannot interleave on
    // the shared RNG. We hold s_det_rng_mutex across the whole override→keypair→restore
    // critical section. (Wallet keygen is single-threaded in practice, but this makes the
    // routine correct under any caller.)
    static std::mutex s_det_rng_mutex;

    static thread_local const uint8_t *s_det_seed = nullptr;
    static thread_local size_t s_det_offset = 0;
    // L4 fix — larger margin (512 B). HKDF is a stream: the first 256 bytes are byte-for-byte
    // identical to the previous 256-byte expansion, so keys derived from a given seed are
    // UNCHANGED in the normal case (ML-DSA-65 consumes far fewer than 256 bytes). The extra
    // headroom only reduces the chance of ever hitting the underflow path.
    static thread_local uint8_t s_det_expanded[512];
    // L4 fix — hard-fail flag: set by det_rng if the deterministic entropy is exhausted.
    // Replaces the old silent memset(0) fallback that could emit weak/zero key material.
    static thread_local bool s_det_underflow = false;

    // Expand seed for all internal random calls during keygen
    if (!hkdf_sha256(s_det_expanded, sizeof(s_det_expanded),
                     nullptr, 0, dil_seed, 32,
                     reinterpret_cast<const uint8_t*>("PBC_DILITHIUM_EXPAND"), 20))
    {
        OQS_SIG_free(sig);
        OQS_MEM_cleanse(dil_seed, sizeof(dil_seed));
        return false;
    }
    s_det_seed = s_det_expanded;
    s_det_offset = 0;
    s_det_underflow = false;

    auto det_rng = [](uint8_t *random_array, size_t bytes_to_read) {
        if (s_det_seed && s_det_offset + bytes_to_read <= sizeof(s_det_expanded)) {
            memcpy(random_array, s_det_seed + s_det_offset, bytes_to_read);
            s_det_offset += bytes_to_read;
        } else {
            // HARD FAIL: never silently produce weak/zero key material. Zero the buffer
            // defensively and flag the underflow; the caller checks s_det_underflow after
            // keygen and returns false (the key is discarded).
            memset(random_array, 0, bytes_to_read);
            s_det_underflow = true;
        }
    };

    OQS_STATUS rc;
    {
        std::lock_guard<std::mutex> rng_lock(s_det_rng_mutex);
        OQS_randombytes_custom_algorithm(det_rng);
        rc = OQS_SIG_keypair(sig, pk.data, sk.data);
        OQS_randombytes_switch_algorithm(OQS_RAND_alg_system);
    }

    OQS_SIG_free(sig);
    OQS_MEM_cleanse(dil_seed, sizeof(dil_seed));
    OQS_MEM_cleanse(s_det_expanded, sizeof(s_det_expanded));
    s_det_seed = nullptr;

    if (s_det_underflow) {
        // Deterministic entropy was exhausted mid-keygen — refuse to emit a weak key.
        s_det_underflow = false;
        OQS_MEM_cleanse(sk.data, sizeof(sk.data));
        OQS_MEM_cleanse(pk.data, sizeof(pk.data));
        return false;
    }

    return rc == OQS_SUCCESS;
}

bool dilithium_sign(dilithium_signature &sig_out,
                    const uint8_t *message, size_t message_len,
                    const dilithium_secret_key &sk)
{
    if (!message && message_len > 0)
        return false;

    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
    if (!sig)
        return false;

    sig_out.length = sizeof(sig_out.data);
    OQS_STATUS rc = OQS_SIG_sign(sig, sig_out.data, &sig_out.length,
                                  message, message_len, sk.data);
    OQS_SIG_free(sig);
    return rc == OQS_SUCCESS;
}

bool dilithium_verify(const uint8_t *message, size_t message_len,
                      const dilithium_signature &sig,
                      const dilithium_public_key &pk)
{
    if (!message && message_len > 0)
        return false;
    if (sig.length == 0 || sig.length > DILITHIUM_SIGNATURE_SIZE)
        return false;

    OQS_SIG *s = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
    if (!s)
        return false;

    OQS_STATUS rc = OQS_SIG_verify(s, message, message_len,
                                    sig.data, sig.length, pk.data);
    OQS_SIG_free(s);
    return rc == OQS_SUCCESS;
}

} // namespace pqc
