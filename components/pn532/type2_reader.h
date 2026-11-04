#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace esphome {
namespace pn532 {

// Reader appends exactly count bytes from a physical page, or returns false.
// Only contiguous Type 2 memory is supported. Fail closed on reserved layouts.
template<typename Reader> std::vector<uint8_t> read_type2_ndef(Reader read) {
  std::vector<uint8_t> cc;
  if (!read(3, 4, cc) || cc.size() != 4 || cc[0] != 0xE1)
    return {};
  // MIFARE READ uses a one-byte page address. Never wrap it.
  const size_t capacity = std::min<size_t>(cc[2] * 8U, 1008U);
  std::vector<uint8_t> data;
  auto ensure = [&read, &data, capacity](size_t count) {
    if (count > capacity)
      return false;
    while (data.size() < count) {
      const size_t bytes = std::min<size_t>(16, capacity - data.size());
      const size_t page = 4 + data.size() / 4;
      if (page > 252 || !read(page, bytes, data))
        return false;
    }
    return true;
  };
  size_t offset = 0;
  while (ensure(offset + 1)) {
    const uint8_t type = data[offset++];
    if (type == 0x00)
      continue;
    if (type == 0xFE)
      break;
    if (!ensure(offset + 1))
      break;
    size_t length = data[offset++];
    if (length == 0xFF) {
      // 03 FF HH LL is one extended-length TLV, never nested TLVs.
      if (!ensure(offset + 2))
        break;
      length = (static_cast<size_t>(data[offset]) << 8) | data[offset + 1];
      offset += 2;
    }
    if (offset > capacity || length > capacity - offset || !ensure(offset + length))
      return {};
    if (type == 0x03)
      return std::vector<uint8_t>(data.begin() + offset, data.begin() + offset + length);
    if (type == 0x01 || type == 0x02)
      return {};  // Lock/memory-control TLVs need logical-to-physical mapping.
    offset += length;
  }
  return {};
}

}  // namespace pn532
}  // namespace esphome
