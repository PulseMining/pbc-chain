#include "pbc_inherit.h"

#include <cstring>

namespace cryptonote
{
  void pbc_pack_inherit_record(const pbc_inherit_record& rec, uint8_t out[PBC_INHERIT_RECORD_PACKED_SIZE])
  {
    memset(out, 0, PBC_INHERIT_RECORD_PACKED_SIZE);
    size_t off = 0;
    out[off++] = rec.version;

    // heir address
    memcpy(out + off, &rec.heir.m_spend_public_key, sizeof(rec.heir.m_spend_public_key)); off += sizeof(rec.heir.m_spend_public_key);
    memcpy(out + off, &rec.heir.m_view_public_key, sizeof(rec.heir.m_view_public_key));   off += sizeof(rec.heir.m_view_public_key);

    memcpy(out + off, &rec.last_activity_height, sizeof(rec.last_activity_height)); off += sizeof(rec.last_activity_height);
    memcpy(out + off, &rec.request_height, sizeof(rec.request_height));             off += sizeof(rec.request_height);

    out[off++] = rec.request_active;
    out[off++] = rec.reserved0;
    memcpy(out + off, &rec.reserved1, sizeof(rec.reserved1)); off += sizeof(rec.reserved1);
  }

  bool pbc_unpack_inherit_record(const uint8_t* data, size_t size, pbc_inherit_record& rec)
  {
    if (size < 1 + 64 + 8 + 8 + 1 + 1 + 2)
      return false;
    size_t off = 0;
    rec = pbc_inherit_record{};
    rec.version = data[off++];
    if (rec.version != PBC_INHERIT_RECORD_VERSION)
      return false;

    memcpy(&rec.heir.m_spend_public_key, data + off, sizeof(rec.heir.m_spend_public_key)); off += sizeof(rec.heir.m_spend_public_key);
    memcpy(&rec.heir.m_view_public_key,  data + off, sizeof(rec.heir.m_view_public_key));  off += sizeof(rec.heir.m_view_public_key);

    memcpy(&rec.last_activity_height, data + off, sizeof(rec.last_activity_height)); off += sizeof(rec.last_activity_height);
    memcpy(&rec.request_height,       data + off, sizeof(rec.request_height));       off += sizeof(rec.request_height);

    rec.request_active = data[off++];
    rec.reserved0      = data[off++];
    memcpy(&rec.reserved1, data + off, sizeof(rec.reserved1)); off += sizeof(rec.reserved1);

    return true;
  }
}
