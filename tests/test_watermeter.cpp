#include <cassert>
#include <iostream>
#include "watermeter_parser.h"
#include "esphome/components/nfc/ndef_message.h"
#include "esphome/components/pn532/type2_reader.h"

int main() {
  const std::string meter = "Ultrasonic Water Meter\r\nS/N: 8ZRI9961209777\r\n"
                            "Time: 2026-11-04 13:11\r\nVol: 203.045 m³\r\n"
                            "2026-11-01: 201.000 m³";
  auto reading = watermeter::parse(meter);
  float volume = 0;
  assert(reading.name == "Ultrasonic Water Meter");
  assert(reading.volume(volume) && std::abs(volume - 203.045f) < 0.001f);
  assert(reading.history.size() == 1);  // Last line has no trailing CRLF.
  assert(reading.get("Time") == "2026-11-04 13:11");
  assert(reading.raw_text == meter);
  assert(reading.json("uid", "type", true, false).find("\"RawText\"") == std::string::npos);
  assert(reading.json("04-01-02", "NFC Forum Type 2", false).size() <= 255);
  assert(reading.json("04-01-02", "NFC Forum Type 2").find("\"NFC_Id\":\"04-01-02\"") != std::string::npos);
  assert(watermeter::parse("\nVol:203,045 m3\n").volume(volume));
  for (const auto &bad : {"nan", "inf", "-1", "2 litres", "1.2.3", ""})
    assert(!watermeter::parse(std::string("Vol:") + bad).volume(volume));
  assert(watermeter::parse("Vol:1\rS/N:foo\rCRC:1234\rVol:2").get("Vol") == "1");
  for (const auto &crc : {"CRC: 21284", "CRC=21284", "CRC 21284"})
    assert(watermeter::parse(crc).get("CRC") == "21284");
  assert(watermeter::quote("a\"b\\c\n") == "\"a\\\"b\\\\c\\u000a\"");

  // Exercise the actual vendored NDEF implementation, including >255-byte records.
  esphome::nfc::NdefMessage source;
  std::string long_text = meter + "\r\n" + std::string(700, 'x');
  assert(source.add_text_record(long_text));
  assert(source.add_text_record("second record"));
  auto bytes = source.encode();
  esphome::nfc::NdefMessage decoded(bytes);
  assert(decoded.get_records().size() == 2);
  assert(decoded.get_records()[0]->get_payload() == long_text);
  assert(decoded.get_records()[1]->get_payload() == "second record");
  // All truncated prefixes must fail closed, never publish partial data or crash.
  for (size_t i = 0; i < bytes.size(); ++i) {
    std::vector<uint8_t> partial(bytes.begin(), bytes.begin() + i);
    esphome::nfc::NdefMessage truncated(partial);
    assert(truncated.get_records().empty());
  }
  std::vector<uint8_t> invalid_text = {0x3F, 'e', 'n'};
  esphome::nfc::NdefRecordText bad_text(invalid_text);
  assert(bad_text.get_payload().empty());

  esphome::nfc::NdefMessage tag_message;
  tag_message.add_text_record(std::string(810, 'A'));
  auto encoded = tag_message.encode();
  assert(encoded.size() == 820);  // 0x0334: formerly misidentified as nested TLVs.
  std::vector<uint8_t> memory(1024, 0);
  memory[12] = 0xE1;
  memory[13] = 0x10;
  memory[14] = 126;
  memory[16] = 0x03;
  memory[17] = 0xFF;
  memory[18] = 0x03;
  memory[19] = 0x34;
  std::copy(encoded.begin(), encoded.end(), memory.begin() + 20);
  auto read_pages = [&memory](size_t page, size_t count, std::vector<uint8_t> &data) {
    assert(page <= 252);
    if (page * 4 + count > memory.size())
      return false;
    data.insert(data.end(), memory.begin() + page * 4, memory.begin() + page * 4 + count);
    return true;
  };
  assert(esphome::pn532::read_type2_ndef(read_pages) == encoded);
  memory.resize(200);
  assert(esphome::pn532::read_type2_ndef(read_pages).empty());
  memory.resize(1024);
  memory[18] = 0xFF;  // Message size exceeds advertised memory.
  assert(esphome::pn532::read_type2_ndef(read_pages).empty());
  memory[16] = 0x01;  // Reserved-memory layout is explicitly unsupported.
  memory[17] = 0x03;
  assert(esphome::pn532::read_type2_ndef(read_pages).empty());
  std::cout << reading.json("04-01-02", "NFC Forum Type 2") << '\n';
  std::cout << "All parser and NDEF tests passed\n";
}
