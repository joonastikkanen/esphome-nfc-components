// Modified for Watermeter NFC Reader: strict, read-only extended-length TLV reads.
#include <algorithm>
#include <memory>

#include "pn532.h"
#include "type2_reader.h"
#include "esphome/core/log.h"

namespace esphome {
namespace pn532 {

static const char *const TAG = "pn532.mifare_ultralight";

std::unique_ptr<nfc::NfcTag> PN532::read_mifare_ultralight_tag_(std::vector<uint8_t> &uid) {
  auto message = read_type2_ndef([this](uint8_t page, uint16_t count, std::vector<uint8_t> &data) {
    return this->read_mifare_ultralight_bytes_(page, count, data);
  });
  if (message.empty()) {
    ESP_LOGW(TAG, "No complete contiguous Type 2 NDEF message (read error or unsupported layout)");
    return make_unique<nfc::NfcTag>(uid, nfc::NFC_FORUM_TYPE_2);
  }
  ESP_LOGD(TAG, "Read complete NDEF message: %u bytes", unsigned(message.size()));
  return make_unique<nfc::NfcTag>(uid, nfc::NFC_FORUM_TYPE_2, message);
}

bool PN532::read_mifare_ultralight_bytes_(uint8_t start_page, uint16_t num_bytes,
                                         std::vector<uint8_t> &data) {
  for (size_t offset = 0; offset < num_bytes; offset += 16) {
    const size_t page = start_page + offset / 4;
    if (page > 252)
      return false;
    if (!this->write_command_({PN532_COMMAND_INDATAEXCHANGE, 0x01, nfc::MIFARE_CMD_READ,
                              static_cast<uint8_t>(page)}))
      return false;
    std::vector<uint8_t> response;
    if (!this->read_response(PN532_COMMAND_INDATAEXCHANGE, response) ||
        response.size() < 17 || response[0] != 0x00)
      return false;
    const size_t count = std::min<size_t>(16, num_bytes - offset);
    data.insert(data.end(), response.begin() + 1, response.begin() + 1 + count);
  }
  return true;
}

uint16_t PN532::read_mifare_ultralight_capacity_() {
  std::vector<uint8_t> data;
  if (this->read_mifare_ultralight_bytes_(3, 4, data) && data.size() == 4 && data[0] == 0xE1)
    return std::min<uint16_t>(data[2] * 8U, 1008U);
  return 0;
}

// This reader is deliberately read-only: never change the meter's NFC memory.
bool PN532::write_mifare_ultralight_page_(uint8_t, std::vector<uint8_t> &) {
  ESP_LOGE(TAG, "Watermeter NFC driver is read-only");
  return false;
}
bool PN532::write_mifare_ultralight_tag_(std::vector<uint8_t> &, nfc::NdefMessage *) { return false; }
bool PN532::clean_mifare_ultralight_() { return false; }

}  // namespace pn532
}  // namespace esphome
