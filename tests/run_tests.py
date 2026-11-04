"""Host-side tests of the actual NDEF sources, without an ESP32 toolchain."""
import json
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
config = (ROOT / "watermeter-nfc-reader.yaml").read_text()
assert "mqtt.publish" not in config and "homeassistant.action" not in config
assert "name: NFC Read Interval" in config and "restore_value: true" in config
entities = (ROOT / "watermeter_entities.yaml").read_text()
for index in range(1, 29):
    assert f"id: history_volume_{index:02}" in entities
    assert f"id: history_date_{index:02}" in entities
with tempfile.TemporaryDirectory(prefix="watermeter-", dir="/tmp/opencode") as directory:
    build = Path(directory)
    core = build / "esphome/core"
    core.mkdir(parents=True)
    (build / "esphome/components").symlink_to(ROOT / "components")
    (core / "log.h").write_text(
        "#pragma once\n#include <cstdint>\n#include <string>\n"
        "#define ESP_LOGE(...) ((void)0)\n#define ESP_LOGV(...) ((void)0)\n"
        "#define ESP_LOGVV(...) ((void)0)\n#define YESNO(x) ((x) ? \"YES\" : \"NO\")\n"
    )
    (core / "helpers.h").write_text(
        "#pragma once\n#include <memory>\n#include <string>\n"
        "namespace esphome { using std::make_unique; }\n"
    )
    sources = [
        "tests/test_watermeter.cpp",
        "components/nfc/ndef_message.cpp",
        "components/nfc/ndef_record.cpp",
        "components/nfc/ndef_record_text.cpp",
        "components/nfc/ndef_record_uri.cpp",
    ]
    subprocess.run(
        ["g++", "-std=c++17", "-fsanitize=address,undefined", "-g",
         f"-I{ROOT}", f"-I{build}", *[str(ROOT / s) for s in sources],
         "-o", str(build / "test")], check=True,
    )
    output = subprocess.check_output([str(build / "test")], text=True)
    document = json.loads(output.splitlines()[0])
    assert document["Name"] == "Ultrasonic Water Meter"
    assert len(document["history"]) == 1
    assert document["HistoryCount"] == 1
    assert document["RawText"].startswith("Ultrasonic Water Meter\r\n")
    print(output, end="")
