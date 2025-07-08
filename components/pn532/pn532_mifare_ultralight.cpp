#include <memory>
#include <algorithm>

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
  
  // For water meter tags, we often need to read much more data than the TLV indicates
  // Let's read extra data to ensure we get the complete NDEF message
  uint16_t extra_read_length = std::max(read_length, (uint16_t)200);  // Read at least 200 bytes
  ESP_LOGD(TAG, "Reading extra data: %u bytes (original: %u)", extra_read_length, read_length);
  
  if (extra_read_length > 0) {
    if (!this->read_mifare_ultralight_bytes_(nfc::MIFARE_ULTRALIGHT_DATA_START_PAGE + 3, extra_read_length, data)) {
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
  ESP_LOGD(TAG, "Before trimming: data size=%u, trim_offset=%u", data.size(), trim_offset);
  
  // Show some context around where we're trimming
  if (data.size() >= trim_offset + 8 && trim_offset >= 4) {
    std::vector<uint8_t> context_data(data.begin() + trim_offset - 4, data.begin() + trim_offset + 8);
    ESP_LOGD(TAG, "Data around trim point: %s", nfc::format_bytes(context_data).c_str());
  }
  
  data.erase(data.begin(), data.begin() + trim_offset);
  
  // Also trim the data to the exact message length
  if (data.size() > message_length) {
    data.resize(message_length);
  }
  
  // Show the first few bytes of the NDEF message for debugging
  ESP_LOGD(TAG, "First 16 bytes of NDEF message: %s", 
           [&data]() {
             std::vector<uint8_t> temp(data.begin(), data.begin() + std::min((size_t)16, data.size()));
             return nfc::format_bytes(temp);
           }().c_str());
  
  // Check if there's another TLV inside the message data
  // Look for pattern like "xx xx xx xx 03 yy" where 03 is another NDEF TLV
  std::vector<uint8_t> combined_inner_data;
  bool found_inner_tlv = false;
  uint32_t expected_total_size = 0;
  
  for (size_t i = 0; i < data.size() - 1; i++) {
    if (data[i] == 0x03 && i + 1 < data.size()) {
      uint8_t inner_length = data[i + 1];
      ESP_LOGD(TAG, "Found potential inner TLV at offset %u: 03 %02X (length %u)", i, inner_length, inner_length);
      
      // If this inner TLV has a reasonable length and would fit in our data
      if (inner_length > 0 && inner_length < 255 && i + 2 + inner_length <= data.size()) {
        ESP_LOGD(TAG, "Inner TLV seems valid, extracting from offset %u with length %u", i + 2, inner_length);
        
        // Extract the inner message
        std::vector<uint8_t> inner_data(data.begin() + i + 2, data.begin() + i + 2 + inner_length);
        
        ESP_LOGD(TAG, "Inner NDEF message (%u bytes): %s", inner_data.size(), 
                 inner_data.size() <= 64 ? [&inner_data]() {
                   std::vector<uint8_t> temp = inner_data;
                   return nfc::format_bytes(temp);
                 }().c_str() : "too long to display");
        
        // Analyze the NDEF record structure (only for the first TLV)
        if (!found_inner_tlv && inner_data.size() >= 4) {
          uint8_t flags = inner_data[0];
          uint8_t type_length = inner_data[1];
          ESP_LOGD(TAG, "NDEF record analysis: flags=0x%02X, type_length=%u", flags, type_length);
          ESP_LOGD(TAG, "  MB=%u, ME=%u, CF=%u, SR=%u, IL=%u, TNF=%u", 
                   (flags >> 7) & 1, (flags >> 6) & 1, (flags >> 5) & 1, 
                   (flags >> 4) & 1, (flags >> 3) & 1, flags & 7);
          
          // Check if this is a short record (SR=1)
          bool is_short_record = (flags & 0x10) != 0;
          if (is_short_record) {
            ESP_LOGD(TAG, "  Short record format detected");
            if (inner_data.size() >= 3) {
              uint8_t payload_length = inner_data[2];
              ESP_LOGD(TAG, "  Payload length: %u", payload_length);
              
              // The complete record should be: flags + type_length + payload_length + type + payload
              expected_total_size = 3 + type_length + payload_length;
              ESP_LOGD(TAG, "  Expected total record size: %u, actual: %u", expected_total_size, inner_data.size());
              
              // If the record is incomplete, we need to read more data
              if (expected_total_size > inner_data.size()) {
                ESP_LOGW(TAG, "  NDEF record is incomplete! Need %u more bytes", expected_total_size - inner_data.size());
                // Mark this as an incomplete record - we'll need to read more data
                // For now, let's try to work with what we have and see if we can get more data
              }
            }
          }
        }
        
        if (!found_inner_tlv) {
          // First inner TLV found - use it as the base
          combined_inner_data = inner_data;
          found_inner_tlv = true;
        } else {
          // Subsequent inner TLVs - append to the combined data (this might be continuation)
          ESP_LOGD(TAG, "Appending additional inner TLV data (%u bytes)", inner_data.size());
          combined_inner_data.insert(combined_inner_data.end(), inner_data.begin(), inner_data.end());
        }
        
        // Skip ahead to avoid re-processing this TLV
        i += inner_length + 1;
      }
    }
  }
  
  if (found_inner_tlv) {
    ESP_LOGD(TAG, "Using combined inner TLV data (%u bytes)", combined_inner_data.size());
    if (expected_total_size > 0 && combined_inner_data.size() >= expected_total_size) {
      ESP_LOGD(TAG, "Trimming combined data to expected size: %u", expected_total_size);
      combined_inner_data.resize(expected_total_size);
    }
    data = combined_inner_data;
  }

  ESP_LOGD(TAG, "Final NDEF message data (%u bytes): %s", data.size(), 
           data.size() <= 64 ? [&data]() {  // Show more data for debugging
             std::vector<uint8_t> temp = data; 
             return nfc::format_bytes(temp); 
           }().c_str() : "too long to display");

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
  
  // Log page 5 and 6 data as well for better debugging
  if (page_3_to_6.size() >= p4_offset + 8) {
    ESP_LOGD(TAG, "Page 5 data: %02X %02X %02X %02X", 
             page_3_to_6[p4_offset + 4], page_3_to_6[p4_offset + 5], 
             page_3_to_6[p4_offset + 6], page_3_to_6[p4_offset + 7]);
  }
  if (page_3_to_6.size() >= p4_offset + 12) {
    ESP_LOGD(TAG, "Page 6 data: %02X %02X %02X %02X", 
             page_3_to_6[p4_offset + 8], page_3_to_6[p4_offset + 9], 
             page_3_to_6[p4_offset + 10], page_3_to_6[p4_offset + 11]);
  }

  if (!(page_3_to_6.size() > p4_offset + 5)) {
    return false;
  }

  if (page_3_to_6[p4_offset + 0] == 0x03) {
    
	if (page_3_to_6[p4_offset + 1] == 0xFF) {
      // The byte 0xFF could mean either:
      // 1. Regular length = 255 bytes (2-byte TLV: Type=0x03, Length=0xFF)
      // 2. Extended length indicator (4-byte TLV: Type=0x03, Ext=0xFF, Length=HH LL)
      
      // Check if we have enough data for extended length format
      if (page_3_to_6.size() < p4_offset + 4) {
        ESP_LOGE(TAG, "Not enough data for extended length format");
        return false;
      }
      
      uint8_t potential_high_byte = page_3_to_6[p4_offset + 2];
      uint8_t potential_low_byte = page_3_to_6[p4_offset + 3];
      ESP_LOGD(TAG, "Potential length bytes: high=0x%02X, low=0x%02X", potential_high_byte, potential_low_byte);
      
      // Key insight: If the byte after 0xFF is 0x03, it's likely the start of a new TLV,
      // not part of extended length format. Extended length format: 03 FF HH LL
      // But pattern like "03 FF 03 xx" suggests: TLV1=(03 FF) TLV2=(03 xx)
      if (potential_high_byte == 0x03) {
        ESP_LOGD(TAG, "Byte after 0xFF is 0x03 - found second TLV, not extended length");
        
        // In this case, we likely have two TLVs: "03 FF" and "03 xx"
        // The first TLV (03 FF) with 255 bytes is probably invalid or too large
        // Let's try to use the second TLV (03 xx) instead
        uint8_t second_tlv_length = potential_low_byte;
        ESP_LOGD(TAG, "Second TLV length: %u bytes", second_tlv_length);
        
        // If the second TLV length seems more reasonable, use it
        if (second_tlv_length > 0 && second_tlv_length <= 100) {
          ESP_LOGD(TAG, "Using second TLV (length %u) instead of first TLV (255)", second_tlv_length);
          message_length = second_tlv_length;
          message_start_index = 4;  // Skip "03 FF 03", start at the data after the second TLV length
        } else {
          ESP_LOGD(TAG, "Second TLV length %u also seems invalid, falling back to first TLV (255)", second_tlv_length);
          message_length = 255;
          message_start_index = 2;
        }
      } else {
        // Check if extended length makes sense
        uint16_t potential_length = potential_high_byte * 256 + potential_low_byte;
        
        // Extended length should only be used for lengths > 254
        if (potential_length > 254 && potential_length <= 924) {
          ESP_LOGD(TAG, "Using extended length format: %u bytes", potential_length);
          message_length = potential_length;
          message_start_index = 4;
        } else {
          ESP_LOGD(TAG, "Extended length %u is invalid, treating as regular length (255)", potential_length);
          message_length = 255;
          message_start_index = 2;
        }
      }
      
      // Additional sanity check: if the chosen length seems too large, warn about it
      if (message_length > 100) {
        ESP_LOGW(TAG, "Length %u seems large, tag may have corrupted length field", message_length);
      }
      
      ESP_LOGD(TAG, "MALOG: find_mifare_ultralight_ndef_: TRUE1b, length=%u", message_length);
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