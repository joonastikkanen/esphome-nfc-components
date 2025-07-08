#include <memory>

#include "pn532.h"
#include "esphome/core/log.h"

namespace esphome {
namespace pn532 {

static const char *const TAG = "pn532.mifare_ultralight";

std::unique_ptr<nfc::NfcTag> PN532::read_mifare_ultralight_tag_(std::vector<uint8_t> &uid) {
  std::vector<uint8_t> data;
  // pages 3 to 6 contain various info we are interested in -- do one read to grab it all
  if (!this->read_mifare_ultralight_bytes_(3, nfc::MIFARE_ULTRALIGHT_PAGE_SIZE * nfc::MIFARE_ULTRALIGHT_READ_SIZE,
                                           data)) {
    return make_unique<nfc::NfcTag>(uid, nfc::NFC_FORUM_TYPE_2);
  }

  if (!this->is_mifare_ultralight_formatted_(data)) {
    ESP_LOGW(TAG, "Not NDEF formatted");
    return make_unique<nfc::NfcTag>(uid, nfc::NFC_FORUM_TYPE_2);
  }

  uint16_t message_length;
  uint8_t message_start_index;
  if (!this->find_mifare_ultralight_ndef_(data, message_length, message_start_index)) {
    ESP_LOGW(TAG, "Couldn't find NDEF message");
    return make_unique<nfc::NfcTag>(uid, nfc::NFC_FORUM_TYPE_2);
  }
  ESP_LOGVV(TAG, "NDEF message length: %u, start: %u", message_length, message_start_index);
  ESP_LOGD(TAG, "Initial data size: %u", data.size());

  if (message_length == 0) {
    return make_unique<nfc::NfcTag>(uid, nfc::NFC_FORUM_TYPE_2);
  }
  // we already read pages 3-6 earlier -- pick up where we left off so we're not re-reading pages
  const uint8_t read_length = message_length + message_start_index > 12 ? message_length + message_start_index - 12 : 0;
  ESP_LOGD(TAG, "Need to read additional %u bytes (message_length=%u, start_index=%u)", 
           read_length, message_length, message_start_index);
  if (read_length) {
    if (!this->read_mifare_ultralight_bytes_(nfc::MIFARE_ULTRALIGHT_DATA_START_PAGE + 3, read_length, data)) {
      ESP_LOGE(TAG, "Error reading tag data");
      return make_unique<nfc::NfcTag>(uid, nfc::NFC_FORUM_TYPE_2);
    }
    ESP_LOGD(TAG, "After additional read, data size: %u", data.size());
  }
  
  // Check if we have enough data to trim
  uint32_t trim_offset = message_start_index + nfc::MIFARE_ULTRALIGHT_PAGE_SIZE;
  if (data.size() < trim_offset) {
    ESP_LOGE(TAG, "Not enough data to trim: data size %u, trim offset %u", data.size(), trim_offset);
    return make_unique<nfc::NfcTag>(uid, nfc::NFC_FORUM_TYPE_2);
  }
  
  // Check if we have enough data for the message
  if (data.size() < trim_offset + message_length) {
    ESP_LOGW(TAG, "Not enough data for full message: data size %u, need %u", data.size(), trim_offset + message_length);
    ESP_LOGW(TAG, "Truncating message to available data");
    // Adjust message length to what's actually available
    if (data.size() > trim_offset) {
      message_length = data.size() - trim_offset;
      ESP_LOGD(TAG, "Adjusted message length to %u bytes", message_length);
    } else {
      ESP_LOGE(TAG, "No message data available after trim offset");
      return make_unique<nfc::NfcTag>(uid, nfc::NFC_FORUM_TYPE_2);
    }
  }
  
  // we need to trim off page 3 as well as any bytes ahead of message_start_index
  // message_start_index is relative to start of page 4, so we add the page 4 offset
  data.erase(data.begin(), data.begin() + trim_offset);
  
  // Also trim the data to the exact message length
  if (data.size() > message_length) {
    data.resize(message_length);
  }

  return make_unique<nfc::NfcTag>(uid, nfc::NFC_FORUM_TYPE_2, data);
}

bool PN532::read_mifare_ultralight_bytes_(uint8_t start_page, uint16_t num_bytes, std::vector<uint8_t> &data) {
  const uint8_t read_increment = nfc::MIFARE_ULTRALIGHT_READ_SIZE * nfc::MIFARE_ULTRALIGHT_PAGE_SIZE;
  std::vector<uint8_t> response;

  for (uint8_t i = 0; i * read_increment < num_bytes; i++) {
    if (!this->write_command_({
            PN532_COMMAND_INDATAEXCHANGE,
            0x01,  // One card
            nfc::MIFARE_CMD_READ,
            uint8_t(i * nfc::MIFARE_ULTRALIGHT_READ_SIZE + start_page),
        })) {
      return false;
    }

    if (!this->read_response(PN532_COMMAND_INDATAEXCHANGE, response) || response[0] != 0x00) {
      return false;
    }
    uint16_t bytes_offset = (i + 1) * read_increment;
    auto pages_in_end_itr = bytes_offset <= num_bytes ? response.end() : response.end() - (bytes_offset - num_bytes);

    if ((pages_in_end_itr > response.begin()) && (pages_in_end_itr <= response.end())) {
      data.insert(data.end(), response.begin() + 1, pages_in_end_itr);
    }
  }

  ESP_LOGVV(TAG, "Data read: %s", nfc::format_bytes(data).c_str());

  return true;
}

bool PN532::is_mifare_ultralight_formatted_(const std::vector<uint8_t> &page_3_to_6) {
  const uint8_t p4_offset = nfc::MIFARE_ULTRALIGHT_PAGE_SIZE;  // page 4 will begin 4 bytes into the vector

  return (page_3_to_6.size() > p4_offset + 3) &&
         ((page_3_to_6[p4_offset + 0] != 0xFF) || (page_3_to_6[p4_offset + 1] != 0xFF) ||
          (page_3_to_6[p4_offset + 2] != 0xFF) || (page_3_to_6[p4_offset + 3] != 0xFF));
}

uint16_t PN532::read_mifare_ultralight_capacity_() {
  std::vector<uint8_t> data;
  if (this->read_mifare_ultralight_bytes_(3, nfc::MIFARE_ULTRALIGHT_PAGE_SIZE, data)) {
    if (data.size() >= 3) {
      ESP_LOGV(TAG, "Tag capacity is %u bytes", data[2] * 8U);
      return data[2] * 8U;
    }
  }
  return 0;
}

bool PN532::find_mifare_ultralight_ndef_(const std::vector<uint8_t> &page_3_to_6, uint16_t &message_length,
                                         uint8_t &message_start_index) {
  const uint8_t p4_offset = nfc::MIFARE_ULTRALIGHT_PAGE_SIZE;  // page 4 will begin 4 bytes into the vector
  ESP_LOGD(TAG, "MALOG: find_mifare_ultralight_ndef_");
  std::vector<uint8_t> page_data_copy = page_3_to_6;  // Create a copy for logging
  ESP_LOGD(TAG, "Full page data (pages 3-6): %s", nfc::format_bytes(page_data_copy).c_str());
  ESP_LOGD(TAG, "Page 4 data: %02X %02X %02X %02X", 
           page_3_to_6[p4_offset + 0], page_3_to_6[p4_offset + 1], 
           page_3_to_6[p4_offset + 2], page_3_to_6[p4_offset + 3]);

  if (!(page_3_to_6.size() > p4_offset + 5)) {
    return false;
  }

  if (page_3_to_6[p4_offset + 0] == 0x03) {
    
	if (page_3_to_6[p4_offset + 1] == 0xFF) {
      // Check if this is really extended length format or just length = 255
      if (page_3_to_6.size() < p4_offset + 4) {
        ESP_LOGE(TAG, "Not enough data for dynamic length format");
        return false;
      }
      uint8_t potential_high_byte = page_3_to_6[p4_offset + 2];
      uint8_t potential_low_byte = page_3_to_6[p4_offset + 3];
      ESP_LOGD(TAG, "Potential length bytes: high=0x%02X, low=0x%02X", potential_high_byte, potential_low_byte);
	  uint16_t potential_length = potential_high_byte * 256 + potential_low_byte;
      
      // Only treat as extended length if the calculated length makes sense for the available data
      // Extended length should only be used for lengths > 254, and must be reasonable
      if (potential_length > 254 && potential_length <= 924) {
        message_length = potential_length;
        message_start_index = 4;
        ESP_LOGD(TAG, "MALOG: find_mifare_ultralight_ndef_: TRUE1a (extended), length=%u", message_length);
      } else {
        // Treat 0xFF as regular length = 255
        ESP_LOGD(TAG, "Treating 0xFF as regular length (255), not extended format");
        message_length = page_3_to_6[p4_offset + 1];  // 255
        message_start_index = 2;
        ESP_LOGD(TAG, "MALOG: find_mifare_ultralight_ndef_: TRUE1b (255 bytes), length=%u", message_length);
      }
	} else {
      // fixed length: byte 0 = 0x03; byte 1 = Length
	  message_length = page_3_to_6[p4_offset + 1];
      message_start_index = 2;
      ESP_LOGD(TAG, "MALOG: find_mifare_ultralight_ndef_: TRUE1b, length=%u", message_length);
    }
    return true;
  } else if (page_3_to_6[p4_offset + 5] == 0x03) {
    if (page_3_to_6.size() < p4_offset + 7) {
      ESP_LOGE(TAG, "Not enough data for NDEF TLV at offset 5");
      return false;
    }
    message_length = page_3_to_6[p4_offset + 6];
    message_start_index = 7;
    ESP_LOGD(TAG, "MALOG: find_mifare_ultralight_ndef_: TRUE2");
    return true;
  }
  ESP_LOGD(TAG, "MALOG: find_mifare_ultralight_ndef_: FALSE");
  return false;
}

bool PN532::write_mifare_ultralight_tag_(std::vector<uint8_t> &uid, nfc::NdefMessage *message) {
  uint32_t capacity = this->read_mifare_ultralight_capacity_();

  auto encoded = message->encode();

  uint32_t message_length = encoded.size();
  uint32_t buffer_length = nfc::get_mifare_ultralight_buffer_size(message_length);

  if (buffer_length > capacity) {
    ESP_LOGE(TAG, "Message length exceeds tag capacity %" PRIu32 " > %" PRIu32, buffer_length, capacity);
    return false;
  }

  encoded.insert(encoded.begin(), 0x03);
  if (message_length < 255) {
    encoded.insert(encoded.begin() + 1, message_length);
  } else {
    encoded.insert(encoded.begin() + 1, 0xFF);
    encoded.insert(encoded.begin() + 2, (message_length >> 8) & 0xFF); // high byte first
    encoded.insert(encoded.begin() + 3, message_length & 0xFF);        // low byte second
  }
  encoded.push_back(0xFE);

  encoded.resize(buffer_length, 0);

  uint32_t index = 0;
  uint8_t current_page = nfc::MIFARE_ULTRALIGHT_DATA_START_PAGE;

  while (index < buffer_length) {
    std::vector<uint8_t> data(encoded.begin() + index, encoded.begin() + index + nfc::MIFARE_ULTRALIGHT_PAGE_SIZE);
    if (!this->write_mifare_ultralight_page_(current_page, data)) {
      return false;
    }
    index += nfc::MIFARE_ULTRALIGHT_PAGE_SIZE;
    current_page++;
  }
  return true;
}

bool PN532::clean_mifare_ultralight_() {
  uint32_t capacity = this->read_mifare_ultralight_capacity_();
  uint8_t pages = (capacity / nfc::MIFARE_ULTRALIGHT_PAGE_SIZE) + nfc::MIFARE_ULTRALIGHT_DATA_START_PAGE;

  std::vector<uint8_t> blank_data = {0x00, 0x00, 0x00, 0x00};

  for (int i = nfc::MIFARE_ULTRALIGHT_DATA_START_PAGE; i < pages; i++) {
    if (!this->write_mifare_ultralight_page_(i, blank_data)) {
      return false;
    }
  }
  return true;
}

bool PN532::write_mifare_ultralight_page_(uint8_t page_num, std::vector<uint8_t> &write_data) {
  std::vector<uint8_t> data({
      PN532_COMMAND_INDATAEXCHANGE,
      0x01,  // One card
      nfc::MIFARE_CMD_WRITE_ULTRALIGHT,
      page_num,
  });
  data.insert(data.end(), write_data.begin(), write_data.end());
  if (!this->write_command_(data)) {
    ESP_LOGE(TAG, "Error writing page %u", page_num);
    return false;
  }

  std::vector<uint8_t> response;
  if (!this->read_response(PN532_COMMAND_INDATAEXCHANGE, response)) {
    ESP_LOGE(TAG, "Error writing page %u", page_num);
    return false;
  }

  return true;
}

}  // namespace pn532
}  // namespace esphome