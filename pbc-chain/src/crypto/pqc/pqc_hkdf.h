// Copyright (c) 2026, PBC Chain
// All rights reserved.
//
// HKDF-SHA256 (RFC 5869) for deterministic PQC key derivation.
// Used to derive Dilithium and Kyber seeds from the wallet's master seed.

#pragma once

#include <cstdint>
#include <cstddef>

namespace pqc {

// HKDF-SHA256 Extract + Expand (RFC 5869).
// Derives output_len bytes of keying material from ikm using salt and info.
// output_len must be <= 255 * 32 (8160 bytes).
// Returns true on success.
bool hkdf_sha256(uint8_t *output, size_t output_len,
                 const uint8_t *salt, size_t salt_len,
                 const uint8_t *ikm, size_t ikm_len,
                 const uint8_t *info, size_t info_len);

// Convenience: derive a 32-byte seed for PQC key generation.
// Uses the wallet's master seed (from the 25-word mnemonic) as IKM,
// and a domain-specific label as info (e.g., "PBC_DILITHIUM_V1").
// Salt is empty (as per common HKDF usage when IKM is already random).
bool derive_pqc_seed(uint8_t output[32],
                     const uint8_t *master_seed, size_t master_seed_len,
                     const char *domain_label);

} // namespace pqc
