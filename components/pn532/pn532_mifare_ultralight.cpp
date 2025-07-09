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
  // Let's try to read additional data in increments, starting with what we need
  // Water meter tags can have data spread across many pages, so be more aggressive
  uint16_t target_read_length = std::max((uint16_t)read_length, (uint16_t)300);  // Start with 300 bytes for complex tags
  ESP_LOGD(TAG, "Target read length: %u bytes (original: %u)", target_read_length, read_length);
  
  if (target_read_length > 0) {
    // Try to read the target length first
    if (!this->read_mifare_ultralight_bytes_(nfc::MIFARE_ULTRALIGHT_DATA_START_PAGE + 3, target_read_length, data)) {
      ESP_LOGW(TAG, "Failed to read %u bytes, trying chunked reading", target_read_length);
      
      // Reset data to initial 16 bytes and try chunked reading
      data.resize(16);
      
      // Try reading in chunks, accumulating data
      std::vector<uint16_t> chunk_sizes = {32, 16, 8};  // Start with smaller chunks that are more likely to work
      bool success = false;
      
      for (uint16_t chunk_size : chunk_sizes) {
        ESP_LOGD(TAG, "Trying chunked reading with %u byte chunks", chunk_size);
        
        uint16_t bytes_read = 0;
        uint8_t current_page = nfc::MIFARE_ULTRALIGHT_DATA_START_PAGE + 3;
        data.resize(16);  // Reset to initial pages 3-6
        
        while (bytes_read < target_read_length) {
          uint16_t bytes_to_read = std::min(chunk_size, (uint16_t)(target_read_length - bytes_read));
          std::vector<uint8_t> chunk_data;
          
          if (!this->read_mifare_ultralight_bytes_(current_page, bytes_to_read, chunk_data)) {
            ESP_LOGW(TAG, "Failed to read chunk of %u bytes at page %u", bytes_to_read, current_page);
            // If we've already read some data, we can continue with what we have
            if (bytes_read > 0) {
              ESP_LOGD(TAG, "Continuing with %u bytes already read", bytes_read);
              success = true;
            }
            break;
          }
          
          data.insert(data.end(), chunk_data.begin(), chunk_data.end());
          bytes_read += chunk_data.size();
          current_page += (chunk_data.size() + nfc::MIFARE_ULTRALIGHT_PAGE_SIZE - 1) / nfc::MIFARE_ULTRALIGHT_PAGE_SIZE;
          
          ESP_LOGD(TAG, "Read chunk: %u bytes, total read: %u/%u", chunk_data.size(), bytes_read, target_read_length);
        }
        
        // Consider it successful if we've read at least what we originally needed or 100 bytes
        if (bytes_read >= std::min(target_read_length, (uint16_t)100) || success) {
          if (!success) {
            success = true;
            ESP_LOGD(TAG, "Successfully read %u bytes using %u byte chunks (partial)", bytes_read, chunk_size);
          }
          break;
        }
      }
      
      if (!success) {
        ESP_LOGW(TAG, "Failed to read additional data from tag with all chunk sizes, using initial data");
        // Don't return an error - use the initial 16 bytes we already have
        success = true;
      }
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
  
  // Show full data for debugging water meter tags
  ESP_LOGD(TAG, "Full NDEF message data (%u bytes): %s", data.size(),
           data.size() <= 32 ? [&data]() {
             std::vector<uint8_t> temp = data;
             return nfc::format_bytes(temp);
           }().c_str() : "too long to display");
  
  // Check if there's another TLV inside the message data
  // Look for pattern like "xx xx xx xx 03 yy" where 03 is another NDEF TLV
  std::vector<uint8_t> combined_inner_data;
  bool found_inner_tlv = false;
  uint32_t expected_total_size = 0;
  
  // Also look for direct NDEF record patterns (starting with flags like 0x54, 0xD1, etc.)
  // These indicate the start of an actual NDEF record
  std::vector<size_t> ndef_record_starts;
  
  ESP_LOGD(TAG, "Searching for NDEF record patterns in %u bytes of data", data.size());
  
  for (size_t i = 0; i < data.size() - 3; i++) {
    uint8_t potential_flags = data[i];
    ESP_LOGVV(TAG, "Checking offset %u: 0x%02X", i, potential_flags);
    
    // Check for common NDEF record flag patterns
    if ((potential_flags & 0x07) <= 0x06 && // TNF field should be 0-6
        (potential_flags & 0x10) != 0 &&     // SR (Short Record) bit should be set for short records
        i + 3 < data.size()) {               // Make sure we have enough data for header
      
      uint8_t type_length = data[i + 1];
      uint8_t payload_length = data[i + 2];
      
      ESP_LOGD(TAG, "Potential NDEF record at offset %u: flags=0x%02X, type_len=%u, payload_len=%u", 
               i, potential_flags, type_length, payload_length);
      
      // Validate that this looks like a reasonable NDEF record
      if (type_length <= 8 && payload_length > 0 && payload_length < 200) {
        ESP_LOGD(TAG, "Found valid NDEF record at offset %u: flags=0x%02X, type_len=%u, payload_len=%u", 
                 i, potential_flags, type_length, payload_length);
        ndef_record_starts.push_back(i);
        
        // Calculate expected total size for this record
        uint32_t expected_size = 3 + type_length + payload_length;
        if (expected_total_size == 0) {
          expected_total_size = expected_size;
          ESP_LOGD(TAG, "Setting expected total size to %u based on NDEF record", expected_size);
        }
      }
    }
  }
  
  // If we found direct NDEF record patterns, use the first one
  if (!ndef_record_starts.empty()) {
    size_t record_start = ndef_record_starts[0];
    ESP_LOGD(TAG, "Using direct NDEF record starting at offset %u", record_start);
    
    // Extract as much data as we can from the record start
    size_t available_data = data.size() - record_start;
    
    // If we don't have enough data for the complete record, try to read more first
    if (expected_total_size > 0 && available_data < expected_total_size) {
      ESP_LOGD(TAG, "Need %u more bytes for complete NDEF record, attempting to read more", 
               expected_total_size - available_data);
      
      // Calculate how much more data we need
      uint32_t bytes_needed = expected_total_size - available_data;
      uint32_t current_data_size = data.size();
      
      // Try to read more data to get the complete record
      // We need to read from where our current data ends
      uint8_t start_page = nfc::MIFARE_ULTRALIGHT_DATA_START_PAGE + 
                          (current_data_size / nfc::MIFARE_ULTRALIGHT_PAGE_SIZE);
      
      // Read extra bytes to ensure we get the complete record
      uint16_t additional_read = bytes_needed + 64; // Add more buffer for safety
      
      ESP_LOGD(TAG, "Attempting to read %u additional bytes starting from page %u", 
               additional_read, start_page);
      
      std::vector<uint8_t> additional_data;
      if (this->read_mifare_ultralight_bytes_(start_page, additional_read, additional_data)) {
        ESP_LOGD(TAG, "Successfully read %u additional bytes", additional_data.size());
        data.insert(data.end(), additional_data.begin(), additional_data.end());
        
        // Update available data after successful read
        available_data = data.size() - record_start;
        ESP_LOGD(TAG, "Total data now: %u bytes, available for record: %u bytes", 
                 data.size(), available_data);
        
        // Show more of the data for debugging
        ESP_LOGD(TAG, "Data around record start (offset %u): %s", record_start,
                 format_bytes(std::vector<uint8_t>(data.begin() + record_start, 
                                                  data.begin() + std::min(record_start + 32, data.size()))).c_str());
      } else {
        ESP_LOGW(TAG, "Failed to read additional data for complete NDEF record");
        
        // Try multiple smaller reads as a fallback
        ESP_LOGD(TAG, "Attempting fallback chunked reads");
        uint8_t current_page = start_page;
        std::vector<uint16_t> chunk_sizes = {64, 32, 16};
        
        for (uint16_t chunk_size : chunk_sizes) {
          std::vector<uint8_t> chunk_data;
          if (this->read_mifare_ultralight_bytes_(current_page, chunk_size, chunk_data)) {
            ESP_LOGD(TAG, "Successfully read %u bytes in fallback chunk", chunk_data.size());
            data.insert(data.end(), chunk_data.begin(), chunk_data.end());
            
            // Update available data
            available_data = data.size() - record_start;
            ESP_LOGD(TAG, "Total data now: %u bytes, available for record: %u bytes", 
                     data.size(), available_data);
            
            // Check if we have enough now
            if (expected_total_size > 0 && available_data >= expected_total_size) {
              ESP_LOGD(TAG, "Got enough data with fallback reads");
              break;
            }
            
            // Move to next page for next chunk
            current_page += (chunk_size + nfc::MIFARE_ULTRALIGHT_PAGE_SIZE - 1) / nfc::MIFARE_ULTRALIGHT_PAGE_SIZE;
          } else {
            ESP_LOGW(TAG, "Fallback chunk read of %u bytes failed", chunk_size);
          }
        }
      }
    }
    
    // Now extract the record data
    available_data = data.size() - record_start;
    size_t data_to_extract = available_data; // Default to all available data
    
    // If we have an expected size, try to extract exactly that much
    if (expected_total_size > 0) {
      if (available_data >= expected_total_size) {
        data_to_extract = expected_total_size;
      } else {
        // Use all available data but warn about incompleteness
        ESP_LOGW(TAG, "Only %u bytes available for NDEF record, expected %u", 
                 available_data, expected_total_size);
      }
    }
    
    // Make sure we don't go beyond the data bounds
    data_to_extract = std::min(data_to_extract, available_data);
    
    combined_inner_data = std::vector<uint8_t>(data.begin() + record_start, 
                                              data.begin() + record_start + data_to_extract);
    found_inner_tlv = true;
    
    ESP_LOGD(TAG, "Extracted %u bytes of direct NDEF record data", combined_inner_data.size());
    
    // Log the extracted data for debugging
    ESP_LOGD(TAG, "Direct NDEF record data (first 32 bytes): %s", 
             format_bytes(std::vector<uint8_t>(combined_inner_data.begin(), 
                                              combined_inner_data.begin() + std::min((size_t)32, combined_inner_data.size()))).c_str());
    
    // Check if we have the complete record now
    if (expected_total_size > 0 && combined_inner_data.size() < expected_total_size) {
      ESP_LOGW(TAG, "Direct NDEF record is still incomplete: have %u bytes, need %u", 
               combined_inner_data.size(), expected_total_size);
      ESP_LOGW(TAG, "This may be due to tag limitations or corruption");
    } else if (expected_total_size > 0) {
      ESP_LOGD(TAG, "Successfully extracted complete NDEF record (%u bytes)", combined_inner_data.size());
    }
  } else {
    // Fall back to TLV-based approach
    ESP_LOGD(TAG, "No direct NDEF record found, using TLV-based approach");
    
    // First, find all potential TLVs in the data
    struct TlvInfo {
      size_t offset;
      uint8_t length;
      std::vector<uint8_t> data;
    };
    std::vector<TlvInfo> found_tlvs;
    
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
          
          // Store this TLV info
          found_tlvs.push_back({i, inner_length, inner_data});
          
          // Analyze the NDEF record structure (only for the first TLV that looks like an NDEF record)
          if (!found_inner_tlv && inner_data.size() >= 4) {
            uint8_t flags = inner_data[0];
            uint8_t type_length = inner_data[1];
            
            // Check if this looks like a valid NDEF record
            if ((flags & 0x07) <= 0x06 && type_length <= 8) {
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
                  }
                }
              }
            }
          }
          
          // Skip ahead to avoid re-processing this TLV
          i += inner_length + 1;
        }
      }
    }
    
    // Now combine the TLVs to try to get a complete NDEF record
    if (!found_tlvs.empty()) {
      ESP_LOGD(TAG, "Found %u inner TLVs, attempting to combine", found_tlvs.size());
      
      // Start with the first TLV
      combined_inner_data = found_tlvs[0].data;
      found_inner_tlv = true;
      
      // If we have an incomplete record and multiple TLVs, try to combine them
      if (expected_total_size > combined_inner_data.size() && found_tlvs.size() > 1) {
        ESP_LOGD(TAG, "Attempting to combine TLVs to reach expected size %u", expected_total_size);
        
        for (size_t tlv_idx = 1; tlv_idx < found_tlvs.size(); tlv_idx++) {
          const auto& tlv = found_tlvs[tlv_idx];
          ESP_LOGD(TAG, "Appending TLV %u data (%u bytes)", tlv_idx, tlv.data.size());
          combined_inner_data.insert(combined_inner_data.end(), tlv.data.begin(), tlv.data.end());
          
          // Check if we've reached the expected size
          if (combined_inner_data.size() >= expected_total_size) {
            ESP_LOGD(TAG, "Reached expected size %u with %u TLVs", expected_total_size, tlv_idx + 1);
            break;
          }
        }
      }
    }
  }
  
  if (found_inner_tlv) {
    ESP_LOGD(TAG, "Using combined inner TLV data (%u bytes)", combined_inner_data.size());
    
    // For water meter tags, we often have all the data we need in the first few pages
    // If we detected an incomplete NDEF record, try to read more data if possible
    if (expected_total_size > 0 && combined_inner_data.size() < expected_total_size) {
      uint32_t bytes_needed = expected_total_size - combined_inner_data.size();
      ESP_LOGW(TAG, "NDEF record incomplete: have %u bytes, need %u (missing %u bytes)", 
               combined_inner_data.size(), expected_total_size, bytes_needed);
      
      // Try to read more data if we haven't read enough yet
      if (data.size() < 200) {
        ESP_LOGD(TAG, "Attempting to read more data to complete NDEF record");
        
        // Try to read additional pages to get the complete record
        uint16_t additional_read = bytes_needed + 50;  // Read extra to be safe
        std::vector<uint8_t> expanded_data = data;
        
        // Calculate starting page based on how much data we already have
        uint8_t start_page = nfc::MIFARE_ULTRALIGHT_DATA_START_PAGE + (data.size() / nfc::MIFARE_ULTRALIGHT_PAGE_SIZE);
        
        if (this->read_mifare_ultralight_bytes_(start_page, additional_read, expanded_data)) {
          ESP_LOGD(TAG, "Successfully read %u additional bytes, total data now: %u", 
                   expanded_data.size() - data.size(), expanded_data.size());
          
          // Look for the complete NDEF record in the expanded data
          bool found_complete_record = false;
          
          // Search for the same NDEF record pattern in the expanded data
          for (size_t i = 0; i < expanded_data.size() - 3; i++) {
            uint8_t potential_flags = expanded_data[i];
            if ((potential_flags & 0x07) <= 0x06 && (potential_flags & 0x10) != 0 && i + 3 < expanded_data.size()) {
              uint8_t type_length = expanded_data[i + 1];
              uint8_t payload_length = expanded_data[i + 2];
              
              if (type_length <= 8 && payload_length > 0 && payload_length < 200) {
                uint32_t complete_size = 3 + type_length + payload_length;
                if (complete_size == expected_total_size && i + complete_size <= expanded_data.size()) {
                  ESP_LOGD(TAG, "Found complete NDEF record at offset %u with %u bytes in expanded data", i, complete_size);
                  combined_inner_data = std::vector<uint8_t>(expanded_data.begin() + i, expanded_data.begin() + i + complete_size);
                  found_complete_record = true;
                  break;
                }
              }
            }
          }
          
          if (!found_complete_record) {
            ESP_LOGW(TAG, "Still couldn't find complete NDEF record in expanded data");
          }
        } else {
          ESP_LOGW(TAG, "Failed to read additional data from tag");
        }
      } else {
        ESP_LOGW(TAG, "Already read sufficient data, working with partial NDEF record");
      }
      
      if (combined_inner_data.size() < expected_total_size) {
        ESP_LOGW(TAG, "Working with partial NDEF record - this may be sufficient for basic decoding");
      }
    }
    
    // Don't trim to expected size if we have partial data - use what we have
    if (expected_total_size > 0 && combined_inner_data.size() >= expected_total_size) {
      ESP_LOGD(TAG, "Trimming combined data to expected size: %u", expected_total_size);
      combined_inner_data.resize(expected_total_size);
    }
    data = combined_inner_data;
  }

  ESP_LOGD(TAG, "Final NDEF message data (%u bytes): %s", data.size(), 
           data.size() <= 100 ? [&data]() {  // Show more data for debugging
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