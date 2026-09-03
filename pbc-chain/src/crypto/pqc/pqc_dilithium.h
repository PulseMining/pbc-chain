// Copyright (c) 2026, PBC Chain
// All rights reserved.
//
// Post-quantum digital signatures using ML-DSA-65 (NIST FIPS 204).
// Wrapper around liboqs for clean integration with PBC/CryptoNote.

#pragma once

#include <cstdint>
#include <cstddef>
#include <vector>
#include <string>

namespace pqc {

// ─── ML-DSA-65 Constants (from NIST FIPS 204 / liboqs) ───
constexpr size_t DILITHIUM_PUBLIC_KEY_SIZE  = 1952;
constexpr size_t DILITHIUM_SECRET_KEY_SIZE  = 4032;
constexpr size_t DILITHIUM_SIGNATURE_SIZE   = 3309;  // max signature size

// ─── Key types ───
struct dilithium_public_key {
    uint8_t data[DILITHIUM_PUBLIC_KEY_SIZE];
};

struct dilithium_secret_key {
    uint8_t data[DILITHIUM_SECRET_KEY_SIZE];
    ~dilithium_secret_key(); // securely erases memory
};

struct dilithium_signature {
    uint8_t data[DILITHIUM_SIGNATURE_SIZE];
    size_t  length = 0; // actual signature length (<= DILITHIUM_SIGNATURE_SIZE)
};

// ─── API ───

// Generate a new ML-DSA-65 keypair.
// Returns true on success.
bool dilithium_keygen(dilithium_public_key &pk, dilithium_secret_key &sk);

// Generate a deterministic ML-DSA-65 keypair from a 32-byte seed.
// The seed is expanded via HKDF-SHA256 to produce the required entropy.
// Returns true on success.
bool dilithium_keygen_deterministic(dilithium_public_key &pk, dilithium_secret_key &sk,
                                     const uint8_t seed[32]);

// Sign a message. Returns true on success.
bool dilithium_sign(dilithium_signature &sig_out,
                    const uint8_t *message, size_t message_len,
                    const dilithium_secret_key &sk);

// Verify a signature. Returns true if valid.
bool dilithium_verify(const uint8_t *message, size_t message_len,
                      const dilithium_signature &sig,
                      const dilithium_public_key &pk);

} // namespace pqc
