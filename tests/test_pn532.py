"""Exercise the actual PN532 state machine with a simulated transport and clock."""
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
STUBS = {
    "core/log.h": """
#pragma once
#define ESP_LOGCONFIG(...) ((void)0)
#define ESP_LOGD(...) ((void)0)
#define ESP_LOGI(...) ((void)0)
#define ESP_LOGW(...) ((void)0)
#define ESP_LOGE(...) ((void)0)
#define ESP_LOGV(...) ((void)0)
#define ESP_LOGVV(...) ((void)0)
#define LOG_UPDATE_INTERVAL(...) ((void)0)
#define LOG_BINARY_SENSOR(...) ((void)0)
#define YESNO(x) ((x) ? "YES" : "NO")
""",
    "core/hal.h": """
#pragma once
#include <cstdint>
namespace esphome {
extern uint32_t test_clock;
inline uint32_t millis() { return test_clock; }
inline void delay(uint32_t n) { test_clock += n; }
inline void yield() { ++test_clock; }
}
""",
    "core/component.h": """
#pragma once
#include <algorithm>
#include <cstdint>
#include <functional>
#include <memory>
#include <vector>
namespace esphome {
using std::make_unique;
namespace setup_priority { constexpr float DATA = 600; }
template<class T> class CallbackManager {
 public:
  void add(std::function<T> f) { callbacks.push_back(f); }
  void call() { for (auto &f : callbacks) f(); }
  std::vector<std::function<T>> callbacks;
};
class PollingComponent {
 public:
  virtual ~PollingComponent() = default;
  virtual void setup() {}
  virtual void dump_config() {}
  virtual void update() {}
  virtual void loop() {}
  virtual void on_shutdown() {}
  virtual float get_setup_priority() const { return 0; }
  void mark_failed() { failed = true; }
  void status_set_warning() { warning = true; }
  void status_clear_warning() { warning = false; }
  bool failed = false, warning = false;
 protected:
  uint32_t update_interval_ = 10000;
};
}
""",
    "core/automation.h": """
#pragma once
namespace esphome {
template<class... T> class Trigger {};
template<class T> class Parented { protected: T *parent_; };
template<class... T> class Condition { public: virtual bool check(T... x) = 0; };
}
""",
    "components/binary_sensor/binary_sensor.h": """
#pragma once
namespace esphome { namespace binary_sensor {
class BinarySensor { public: void publish_state(bool) {} };
}}
""",
    "components/nfc/nfc_tag.h": """
#pragma once
#include <memory>
#include <string>
#include <vector>
namespace esphome { namespace nfc {
class Record {};
class NdefMessage {
 public:
  const std::vector<std::shared_ptr<Record>> &get_records() { return records; }
  std::vector<std::shared_ptr<Record>> records;
};
class NfcTag {
 public:
  explicit NfcTag(std::vector<uint8_t> &) {}
  bool has_ndef_message() { return bool(message); }
  const std::shared_ptr<NdefMessage> &get_ndef_message() { return message; }
  std::shared_ptr<NdefMessage> message;
};
}}
""",
    "components/nfc/nfc.h": """
#pragma once
#include "nfc_tag.h"
namespace esphome { namespace nfc {
constexpr uint8_t TAG_TYPE_MIFARE_CLASSIC=1, TAG_TYPE_2=2, TAG_TYPE_UNKNOWN=0;
inline uint8_t guess_tag_type(size_t n) { return n == 7 ? TAG_TYPE_2 : TAG_TYPE_UNKNOWN; }
}}
""",
    "components/nfc/automation.h": """
#pragma once
#include <functional>
#include "nfc_tag.h"
namespace esphome { namespace nfc {
class NfcOnTagTrigger {
 public:
  std::function<void()> callback;
  void process(const std::unique_ptr<NfcTag> &) { if (callback) callback(); }
};
}}
""",
}

with tempfile.TemporaryDirectory(prefix="pn532-", dir="/tmp/opencode") as directory:
    build = Path(directory)
    for name, content in STUBS.items():
        path = build / "esphome" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    subprocess.run([
        "g++", "-std=c++17", "-fsanitize=address,undefined", "-g",
        f"-I{build}", f"-I{ROOT}", str(ROOT / "tests/test_pn532.cpp"),
        str(ROOT / "components/pn532/pn532.cpp"), "-o", str(build / "test"),
    ], check=True)
    subprocess.run([str(build / "test")], check=True)
