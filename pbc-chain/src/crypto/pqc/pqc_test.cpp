// Copyright (c) 2026, PBC Chain
// Unit test for PQC primitives (ML-DSA-65 + ML-KEM-768 + HKDF).
// Compile: g++ -std=c++17 -o pqc_test pqc_test.cpp pqc_dilithium.cpp pqc_kyber.cpp pqc_hkdf.cpp
//          -I. -I../../external/liboqs/build/install/include
//          -L../../external/liboqs/build/install/lib -loqs -lssl -lcrypto -lpthread

#include "pqc_dilithium.h"
#include "pqc_kyber.h"
#include "pqc_hkdf.h"
#include <oqs/oqs.h>
#include <cstdio>
#include <cstring>
#include <cstdlib>

static int tests_pass = 0;
static int tests_fail = 0;

#define TEST(name, cond) do { \
    if (cond) { printf("  PASS  %s\n", name); tests_pass++; } \
    else { printf("  FAIL  %s\n", name); tests_fail++; } \
} while(0)

void test_hkdf()
{
    printf("\n=== HKDF-SHA256 ===\n");

    uint8_t seed[32];
    memset(seed, 0x42, sizeof(seed));

    uint8_t out1[32], out2[32], out3[32];
    bool ok1 = pqc::derive_pqc_seed(out1, seed, 32, "PBC_DILITHIUM_V1");
    bool ok2 = pqc::derive_pqc_seed(out2, seed, 32, "PBC_KYBER_V1");
    bool ok3 = pqc::derive_pqc_seed(out3, seed, 32, "PBC_DILITHIUM_V1");

    TEST("HKDF derive Dilithium seed", ok1);
    TEST("HKDF derive Kyber seed", ok2);
    TEST("HKDF deterministic (same input = same output)", memcmp(out1, out3, 32) == 0);
    TEST("HKDF domain separation (different labels = different output)", memcmp(out1, out2, 32) != 0);

    // Different master seed → different output
    uint8_t seed2[32];
    memset(seed2, 0x43, sizeof(seed2));
    uint8_t out4[32];
    pqc::derive_pqc_seed(out4, seed2, 32, "PBC_DILITHIUM_V1");
    TEST("HKDF different seed = different output", memcmp(out1, out4, 32) != 0);
}

void test_dilithium()
{
    printf("\n=== ML-DSA-65 (Dilithium3) ===\n");

    // Random keygen
    pqc::dilithium_public_key pk;
    pqc::dilithium_secret_key sk;
    bool ok = pqc::dilithium_keygen(pk, sk);
    TEST("Keygen (random)", ok);

    // Sign
    const uint8_t msg[] = "PBC Chain post-quantum test message";
    pqc::dilithium_signature sig;
    ok = pqc::dilithium_sign(sig, msg, sizeof(msg) - 1, sk);
    TEST("Sign", ok);
    TEST("Signature length > 0", sig.length > 0);
    TEST("Signature length <= max", sig.length <= pqc::DILITHIUM_SIGNATURE_SIZE);
    printf("  INFO  Signature length: %zu bytes\n", sig.length);

    // Verify
    ok = pqc::dilithium_verify(msg, sizeof(msg) - 1, sig, pk);
    TEST("Verify (valid)", ok);

    // Verify with wrong message
    const uint8_t wrong_msg[] = "Wrong message";
    ok = pqc::dilithium_verify(wrong_msg, sizeof(wrong_msg) - 1, sig, pk);
    TEST("Verify (wrong message = reject)", !ok);

    // Verify with wrong key
    pqc::dilithium_public_key pk2;
    pqc::dilithium_secret_key sk2;
    pqc::dilithium_keygen(pk2, sk2);
    ok = pqc::dilithium_verify(msg, sizeof(msg) - 1, sig, pk2);
    TEST("Verify (wrong key = reject)", !ok);

    // Deterministic keygen
    uint8_t seed[32];
    memset(seed, 0xAB, sizeof(seed));
    pqc::dilithium_public_key dpk1, dpk2;
    pqc::dilithium_secret_key dsk1, dsk2;
    ok = pqc::dilithium_keygen_deterministic(dpk1, dsk1, seed);
    TEST("Deterministic keygen 1", ok);
    ok = pqc::dilithium_keygen_deterministic(dpk2, dsk2, seed);
    TEST("Deterministic keygen 2", ok);
    TEST("Deterministic keygen: same seed = same public key", memcmp(dpk1.data, dpk2.data, sizeof(dpk1.data)) == 0);
    TEST("Deterministic keygen: same seed = same secret key", memcmp(dsk1.data, dsk2.data, sizeof(dsk1.data)) == 0);

    // Different seed → different keys
    uint8_t seed2[32];
    memset(seed2, 0xCD, sizeof(seed2));
    pqc::dilithium_public_key dpk3;
    pqc::dilithium_secret_key dsk3;
    pqc::dilithium_keygen_deterministic(dpk3, dsk3, seed2);
    TEST("Deterministic keygen: different seed = different key", memcmp(dpk1.data, dpk3.data, sizeof(dpk1.data)) != 0);

    // Sign with deterministic key and verify
    pqc::dilithium_signature dsig;
    pqc::dilithium_sign(dsig, msg, sizeof(msg) - 1, dsk1);
    ok = pqc::dilithium_verify(msg, sizeof(msg) - 1, dsig, dpk1);
    TEST("Deterministic key: sign+verify", ok);
}

void test_kyber()
{
    printf("\n=== ML-KEM-768 (Kyber768) ===\n");

    // Random keygen
    pqc::kyber_public_key pk;
    pqc::kyber_secret_key sk;
    bool ok = pqc::kyber_keygen(pk, sk);
    TEST("Keygen (random)", ok);

    // Encapsulate
    pqc::kyber_ciphertext ct;
    pqc::kyber_shared_secret ss_enc;
    ok = pqc::kyber_encaps(ct, ss_enc, pk);
    TEST("Encapsulate", ok);

    // Decapsulate
    pqc::kyber_shared_secret ss_dec;
    ok = pqc::kyber_decaps(ss_dec, ct, sk);
    TEST("Decapsulate", ok);
    TEST("Shared secrets match", memcmp(ss_enc.data, ss_dec.data, pqc::KYBER_SHARED_SECRET_SIZE) == 0);

    // Decapsulate with wrong key → different shared secret
    pqc::kyber_public_key pk2;
    pqc::kyber_secret_key sk2;
    pqc::kyber_keygen(pk2, sk2);
    pqc::kyber_shared_secret ss_wrong;
    pqc::kyber_decaps(ss_wrong, ct, sk2);
    TEST("Decaps with wrong key = different secret", memcmp(ss_enc.data, ss_wrong.data, pqc::KYBER_SHARED_SECRET_SIZE) != 0);

    // Deterministic keygen
    uint8_t seed[32];
    memset(seed, 0xEF, sizeof(seed));
    pqc::kyber_public_key kpk1, kpk2;
    pqc::kyber_secret_key ksk1, ksk2;
    ok = pqc::kyber_keygen_deterministic(kpk1, ksk1, seed);
    TEST("Deterministic keygen 1", ok);
    ok = pqc::kyber_keygen_deterministic(kpk2, ksk2, seed);
    TEST("Deterministic keygen 2", ok);
    TEST("Deterministic keygen: same seed = same public key", memcmp(kpk1.data, kpk2.data, sizeof(kpk1.data)) == 0);
    TEST("Deterministic keygen: same seed = same secret key", memcmp(ksk1.data, ksk2.data, sizeof(ksk1.data)) == 0);

    // Encaps/decaps with deterministic key
    pqc::kyber_ciphertext dct;
    pqc::kyber_shared_secret dss_enc, dss_dec;
    pqc::kyber_encaps(dct, dss_enc, kpk1);
    ok = pqc::kyber_decaps(dss_dec, dct, ksk1);
    TEST("Deterministic key: encaps+decaps match", ok && memcmp(dss_enc.data, dss_dec.data, 32) == 0);
}

int main()
{
    OQS_init();

    printf("PBC PQC Unit Tests\n");
    printf("==================\n");
    printf("ML-DSA-65 public key:  %d bytes\n", (int)pqc::DILITHIUM_PUBLIC_KEY_SIZE);
    printf("ML-DSA-65 signature:   %d bytes\n", (int)pqc::DILITHIUM_SIGNATURE_SIZE);
    printf("ML-KEM-768 public key: %d bytes\n", (int)pqc::KYBER_PUBLIC_KEY_SIZE);
    printf("ML-KEM-768 ciphertext: %d bytes\n", (int)pqc::KYBER_CIPHERTEXT_SIZE);

    test_hkdf();
    test_dilithium();
    test_kyber();

    printf("\n==================\n");
    printf("PASS: %d  FAIL: %d\n", tests_pass, tests_fail);
    if (tests_fail == 0)
        printf("ALL TESTS PASSED\n");
    else
        printf("SOME TESTS FAILED\n");

    OQS_destroy();
    return tests_fail > 0 ? 1 : 0;
}
