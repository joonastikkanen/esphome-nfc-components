#pragma once

#include <cstdint>
#include <limits>

namespace esphome {
namespace pn532 {

// Hardware-independent policy, shared with the host-side regression tests.
class ReaderHealth {
 public:
  void tick(uint32_t now) {
    this->elapsed_ms_ += static_cast<uint32_t>(now - this->last_tick_);
    this->last_tick_ = now;
  }
  void scan_finished(bool success) {
    if (success)
      this->scan_failures = 0;
    else if (this->scan_failures != std::numeric_limits<uint32_t>::max())
      ++this->scan_failures;
  }
  void valid_read(uint32_t now) {
    this->tick(now);
    this->has_valid_read = true;
    this->last_valid_ms_ = this->elapsed_ms_;
  }
  float read_age_seconds(uint32_t now) {
    this->tick(now);
    return (this->elapsed_ms_ - this->last_valid_ms_) / 1000.0f;
  }
  bool recovery_due(uint32_t now, bool initialized) const {
    return (!initialized || this->scan_failures >= 3) &&
           static_cast<uint32_t>(now - this->last_recovery_ms_) >= 30000;
  }
  void recovery_started(uint32_t now) {
    this->last_recovery_ms_ = now;
    ++this->recoveries;
  }

  bool has_valid_read{false};
  uint32_t scan_failures{0};
  uint32_t recoveries{0};

 protected:
  uint32_t last_tick_{0};
  uint32_t last_recovery_ms_{0};
  uint64_t elapsed_ms_{0};
  uint64_t last_valid_ms_{0};
};

}  // namespace pn532
}  // namespace esphome
