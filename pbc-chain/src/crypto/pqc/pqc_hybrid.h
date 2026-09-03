// Copyright (c) 2026, PBC Chain
// All rights reserved.
//
// Hybrid ECDH: combines classical Ed25519 derivation with ML-KEM-768 shared secret.
// Result: derivation_hybrid = H("PBC_HYBRID_V1" || derivation_classical || shared_secret_kyber)

#pragma once

#include <cstdint>
#include <cstddef>
#include "crypto/crypto.h"
#include "crypto/pqc/pqc_kyber.h"

namespace pqc {

// Combine a classical ECDH derivation with a Kyber shared secret.
// Output replaces the derivation in-place.
// If kyber_secret is nullptr or zero, returns the classical derivation unchanged.
void hybridize_derivation(crypto::key_derivation &derivation,
                          const uint8_t *kyber_shared_secret,
                          size_t kyber_secret_len);

} // namespace pqc
