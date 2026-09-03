// Copyright (c) 2026, PBC Chain
// Hybrid ECDH implementation.

#include "pqc_hybrid.h"
#include "crypto/hash.h"
#include <cstring>

namespace pqc {

void hybridize_derivation(crypto::key_derivation &derivation,
                          const uint8_t *kyber_shared_secret,
                          size_t kyber_secret_len)
{
    if (!kyber_shared_secret || kyber_secret_len == 0)
        return; // no Kyber secret → keep classical derivation as-is

    // derivation_hybrid = H("PBC_HYBRID_V1" || derivation_classical || kyber_shared_secret)
    const char prefix[] = "PBC_HYBRID_V1";
    const size_t prefix_len = sizeof(prefix) - 1; // exclude null terminator

    const size_t total = prefix_len + sizeof(crypto::key_derivation) + kyber_secret_len;
    uint8_t *buf = new uint8_t[total];

    size_t offset = 0;
    memcpy(buf + offset, prefix, prefix_len);
    offset += prefix_len;
    memcpy(buf + offset, &derivation, sizeof(crypto::key_derivation));
    offset += sizeof(crypto::key_derivation);
    memcpy(buf + offset, kyber_shared_secret, kyber_secret_len);

    // Hash to 32 bytes — same size as key_derivation
    crypto::hash h;
    crypto::cn_fast_hash(buf, total, h);

    // Replace derivation with the hybrid hash
    static_assert(sizeof(crypto::key_derivation) == sizeof(crypto::hash),
                  "key_derivation and hash must be same size");
    memcpy(&derivation, &h, sizeof(derivation));

    // Secure cleanup
    memset(buf, 0, total);
    delete[] buf;
}

} // namespace pqc
