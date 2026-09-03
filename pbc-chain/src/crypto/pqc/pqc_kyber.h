// Copyright (c) 2026, PBC Chain
// All rights reserved.
//
// Post-quantum key encapsulation using ML-KEM-768 (NIST FIPS 203).
// Wrapper around liboqs for clean integration with PBC/CryptoNote.

#pragma once

#include <cstdint>
#include <cstddef>

namespace pqc {

// ─── ML-KEM-768 Constants (from NIST FIPS 203 / liboqs) ───
constexpr size_t KYBER_PUBLIC_KEY_SIZE    = 1184;
constexpr size_t KYBER_SECRET_KEY_SIZE    = 2400;
constexpr size_t KYBER_CIPHERTEXT_SIZE    = 1088;
constexpr size_t KYBER_SHARED_SECRET_SIZE = 32;

// ─── Key types ───
struct kyber_public_key {
    uint8_t data[KYBER_PUBLIC_KEY_SIZE];
};

struct kyber_secret_key {
    uint8_t data[KYBER_SECRET_KEY_SIZE];
    ~kyber_secret_key(); // securely erases memory
};

struct kyber_ciphertext {
    uint8_t data[KYBER_CIPHERTEXT_SIZE];
};

struct kyber_shared_secret {
    uint8_t data[KYBER_SHARED_SECRET_SIZE];
    ~kyber_shared_secret(); // securely erases memory
};

// ─── API ───

// Generate a new ML-KEM-768 keypair.
// Returns true on success.
bool kyber_keygen(kyber_public_key &pk, kyber_secret_key &sk);

// Generate a deterministic ML-KEM-768 keypair from a 32-byte seed.
// The seed is expanded via HKDF-SHA256 to produce the required entropy.
// Returns true on success.
bool kyber_keygen_deterministic(kyber_public_key &pk, kyber_secret_key &sk,
                                 const uint8_t seed[32]);

// Encapsulate: generate a shared secret and ciphertext using the recipient's public key.
// The sender sends ct to the recipient. Both parties derive the same shared_secret.
// Returns true on success.
bool kyber_encaps(kyber_ciphertext &ct, kyber_shared_secret &shared_secret,
                  const kyber_public_key &recipient_pk);

// Decapsulate: recover the shared secret from a ciphertext using the recipient's secret key.
// Returns true on success.
bool kyber_decaps(kyber_shared_secret &shared_secret,
                  const kyber_ciphertext &ct,
                  const kyber_secret_key &sk);

} // namespace pqc
