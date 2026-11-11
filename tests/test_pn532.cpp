#include "components/pn532/pn532.h"
#include "esphome/core/hal.h"

#include <cassert>
#include <cmath>
#include <iostream>
#include <limits>

namespace esphome {
uint32_t test_clock = 0;
namespace pn532 {
bool complete_ndef = true;
// Stub the RF memory reader, not the command/recovery state machine under test.
std::unique_ptr<nfc::NfcTag> PN532::read_mifare_ultralight_tag_(std::vector<uint8_t> &uid) {
  auto tag = std::make_unique<nfc::NfcTag>(uid);
  if (complete_ndef)
    tag->message = std::make_shared<nfc::NdefMessage>();
  return tag;
}
std::unique_ptr<nfc::NfcTag> PN532::read_mifare_classic_tag_(std::vector<uint8_t> &uid) {
  return std::make_unique<nfc::NfcTag>(uid);
}
bool PN532::format_mifare_classic_ndef_(std::vector<uint8_t> &) { return false; }
bool PN532::format_mifare_classic_mifare_(std::vector<uint8_t> &) { return false; }
bool PN532::clean_mifare_ultralight_() { return false; }
bool PN532::write_mifare_classic_tag_(std::vector<uint8_t> &, nfc::NdefMessage *) { return false; }
bool PN532::write_mifare_ultralight_tag_(std::vector<uint8_t> &, nfc::NdefMessage *) { return false; }

class FakePN532 : public PN532 {
 public:
  bool online = true, ready = true, short_version = false, short_ack = false;
  bool fail_target_response = false, pending_rf = false, fail_rf = false;
  int writes = 0, ack_reads = 0, rf_responses = 0;
  std::vector<uint8_t> target{1, 1, 0, 0, 0, 7, 4, 1, 2, 3, 4, 5, 6};
  bool initialized() const { return initialized_; }
  bool requested() const { return requested_read_; }
  bool command() { return write_command_({PN532_COMMAND_VERSION_DATA}); }
  PN532ReadReady wait_ready(bool block) { return read_ready_(block); }
 protected:
  bool is_read_ready() override { return ready && online; }
  bool write_data(const std::vector<uint8_t> &data) override {
    ++writes;
    if (!online) return false;
    if (data.size() > 6 && data[6] == PN532_COMMAND_RFCONFIGURATION)
      pending_rf = true;
    return true;
  }
  bool read_data(std::vector<uint8_t> &data, uint8_t) override {
    ++ack_reads;
    if (!online) return false;
    data = short_ack ? std::vector<uint8_t>{1} : std::vector<uint8_t>{1, 0, 0, 255, 0, 255, 0};
    return true;
  }
  bool read_response(uint8_t command, std::vector<uint8_t> &data) override {
    if (!online) return false;
    if (command == PN532_COMMAND_VERSION_DATA)
      data = short_version ? std::vector<uint8_t>{0x32} : std::vector<uint8_t>{0x32, 1, 6, 7};
    else if (command == PN532_COMMAND_INLISTPASSIVETARGET) {
      if (fail_target_response) return false;
      data = target;
    } else if (command == PN532_COMMAND_RFCONFIGURATION) {
      if (fail_rf) return false;
      data.clear();
      pending_rf = false;
      ++rf_responses;
    } else data.clear();
    return true;
  }
};
}  // namespace pn532
}  // namespace esphome

int main() {
  using namespace esphome;
  using namespace esphome::pn532;
  ReaderHealth health;
  assert(!health.has_valid_read && !health.recovery_due(29999, false));
  assert(health.recovery_due(30000, false));
  health.recovery_started(30000);
  for (int i=0; i<3; ++i) health.scan_finished(false);
  assert(!health.recovery_due(59999, true));
  assert(health.recovery_due(60000, true));
  health.scan_finished(true);
  assert(!health.recovery_due(60000, true));
  health.valid_read(1000);
  assert(health.read_age_seconds(61000) == 60);
  health.scan_failures = std::numeric_limits<uint32_t>::max();
  health.scan_finished(false);
  assert(health.scan_failures == std::numeric_limits<uint32_t>::max());
  // Tick through millis rollover; an old reading must not become fresh again.
  ReaderHealth wrap;
  wrap.valid_read(0xfffffff0U);
  assert(std::fabs(wrap.read_age_seconds(0x10) - .032f) < .0001f);
  wrap.tick(0xfffffff0U);
  assert(wrap.read_age_seconds(0x10) > 4294967.0f);

  FakePN532 reader;
  reader.online = false;
  reader.setup();
  assert(!reader.initialized() && !reader.failed && reader.warning);
  test_clock = 29999;
  reader.loop();
  assert(reader.get_recovery_count() == 0);
  reader.online = true;
  test_clock = 30000;
  reader.loop();
  assert(reader.initialized() && reader.get_recovery_count() == 1);
  assert(!reader.pending_rf && reader.rf_responses == 1);

  reader.set_read_same_tag(true);
  nfc::NfcOnTagTrigger trigger;
  int scans = 0;
  trigger.callback = [&]() {
    assert(!reader.pending_rf);  // Response drained before invoking automations.
    ++scans;
    reader.record_valid_read();
  };
  reader.register_ontag_trigger(&trigger);
  for (int i=0; i<2; ++i) {
    reader.update(); reader.loop();
    assert(!reader.requested());
  }
  assert(scans == 2 && reader.has_valid_read() && reader.get_consecutive_failures() == 0);
  test_clock += 1000;
  assert(reader.get_read_age_seconds() == 1);

  // Failed writes are not followed by an ACK read, nor treated as successful scans.
  reader.online = false;
  int previous_acks = reader.ack_reads;
  for (int i=0; i<3; ++i) reader.update();
  assert(reader.ack_reads == previous_acks && reader.get_consecutive_failures() == 3);
  test_clock = 60000;
  reader.loop();
  assert(!reader.initialized() && reader.get_recovery_count() == 2 && !reader.failed);
  reader.loop();
  assert(reader.get_recovery_count() == 2);  // No tight recovery loop.
  reader.online = true;
  test_clock = 90000;
  reader.loop();
  assert(reader.initialized());
  reader.update(); reader.loop();
  assert(reader.get_consecutive_failures() == 0 && !reader.warning);

  FakePN532 bad;
  bad.short_version = true;
  bad.setup();
  assert(!bad.initialized() && !bad.failed);
  bad.short_ack = true;
  assert(!bad.command());
  bad.short_ack = false;
  bad.short_version = false;
  bad.setup();
  // All short/invalid target responses are bounded and recorded as failed scans.
  for (auto response : std::vector<std::vector<uint8_t>>{{}, {0}, {1}, {1,1,0,0,0,7,4}}) {
    bad.target = response;
    bad.update(); bad.loop();
    assert(!bad.requested());
  }
  assert(bad.get_consecutive_failures() == 4);
  bad.ready = false;
  test_clock += 1;
  const auto before = test_clock;
  assert(bad.wait_ready(true) == TIMEOUT);
  assert(test_clock - before == 251);

  // RF-off failure must not be hidden by an otherwise successful NDEF read.
  reader.fail_rf = true;
  reader.update(); reader.loop();
  assert(reader.get_consecutive_failures() == 1 && reader.warning);
  std::cout << "PN532 initialization, bounded recovery, failures, RF response draining, same-tag rereads,\n"
               "short responses, timeout, freshness and millis rollover tests passed\n";
}
