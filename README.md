# Esphome NFC reader custom components (WIP)

These components add functionality to read NFC tags in multiple parts.

Original discussion: https://community.home-assistant.io/t/water-meter-reading-via-nfc/626124/20

## Watermeter NFC Reader

Patched configuration and external components. **Built and installed by OTA on
2026-11-04; manual and automatic rereads verified without rebooting.** The live
ESPHome dashboard's configuration/components have not been synchronized; do not
reinstall its old configuration over this firmware.

## Findings from the live device

Inspected `watermeter-nfc-reader` at `10.20.30.23` on 2026-11-04,
running ESPHome 2026.10.2. Its web event stream reported:

- Volume: **203.045 m³**; meter timestamp: `2026-11-04 13:11`.
- JSON was syntactically valid, but its name was `ltrasonic Water Meter`,
  `NFC_Id` incorrectly duplicated the serial number, and history was empty.
- Wi-Fi RSSI was **-93 dBm** (very weak). This can affect connectivity/OTA,
  but does not explain the deterministic parser/driver defects below.

Code inspection found:

1. PN532 suppresses a read if the tag UID matches the last one. A stationary
   meter never generates another `on_tag`, even when its data changes.
2. The custom Type 2 driver treats some valid extended lengths (`03 FF 03 xx`)
   as nested TLVs. In fact, `03 FF 03 34` means a single **820-byte** message.
   It also uses heuristic header searches, truncates incomplete messages,
   and stores a calculated remaining length in an 8-bit integer.
3. The NDEF parser uses an 8-bit cursor, which wraps on long/multiple records,
   and accesses some headers before checking bounds.
4. The YAML parser reads only record zero, requires CRLF, ignores the last
   unterminated line, drops unrecognized fields, and inserts unescaped strings
   into JSON. Its `delay(500)` blocks the device loop unnecessarily.
5. A full JSON/history document can exceed Home Assistant's 255-character
   entity-state limit. The observed short JSON did not exceed that limit.
6. Two external sources register the same components; which source is selected
   should not depend on ordering. The replacement uses only the local source.

The patched read recovered the complete name and **28 history entries** from a
**929-byte NDEF message** (919-byte text). No missing data is invented or repaired
by adding guessed characters. The original driver was losing data before JSON
conversion.

## Replacement behavior

- `read_same_tag: true` rereads the mounted tag every 30 seconds.
- **Read Water Meter NFC** performs an immediate scan, without rebooting the ESP32.
- Duplicate scan requests while a scan is pending are ignored.
- Type 2 reads honor actual TLV lengths, including extended lengths, and reject
  incomplete/unsupported memory layouts instead of emitting partial data.
- Type 2 write/format/clean operations are disabled in this watermeter driver.
- All supported NDEF text records are parsed; CRLF, LF, CR, and a final line
  without a newline are handled. CRC metadata is preserved, not verified.
- Bad volume/serial reads retain the last good published reading.
- `Water Meter NFC Data` remains a compact HA JSON entity with `SN`, physical
  tag `NFC_Id`, `Time`, `Vol`, and `HistoryCount`. **Its schema differs from
  the old entity:** use the full document for Name, NFC_Typ and history.
- `Water Meter NFC Full JSON` and `Water Meter NFC Raw Text` are internal
  entities visible through the device web server (`include_internal: true`).
  They are not oversized HA entity states. The existing unauthenticated web
  server now exposes this diagnostic data to clients on the device network.
- **`sensor.watermeter_nfc_reader_nfc_full_data`** exposes the complete document
  as Home Assistant attributes through MQTT Discovery. Its short state is the
  meter's timestamp. Attributes include `Name`, `SN`, `NFC_Id`, `NFC_Typ`, `Time`,
  `Vol`, `KDate`, `KVol`, `Temp`, `FVol`, `RVol`, `Battery`, `FW`, `CRC`, `history`,
  `HistoryCount`, and `RawText`. Unrecognized future key/value fields are retained
  too, and `RawText` preserves the original decoded text without dropping lines.
- The ESP32 uses its encrypted native API to request HA's `mqtt.publish` action;
  it holds **no MQTT broker credentials**. This requires the reader integration's
  `allow_service_calls` option, explicitly approved and enabled during deployment.
  HA and its MQTT integration must be running for full-data attributes to update;
  local reads and existing native ESPHome sensors work independently.
- On the device web server, full parsed JSON and raw text remain separate:
  ESPHome caps serialized HTTP responses at 5120 bytes and duplicates text states
  into both `value` and `state`. The MQTT/HA document combines them without that
  web-response limit, so HA still receives the complete `RawText` attribute.
- The full-data MQTT state/discovery are retained. The entity becomes unavailable
  after 120 seconds without a publish. No unrelated MQTT entities are discovered.

## Home Assistant full-data setup

Already deployed on this installation. For another installation:

1. Enable **Allow the device to perform Home Assistant actions** in this reader's
   ESPHome integration options. This is a broad permission for the trusted reader,
   not a per-service allowlist. Leave other devices unchanged.
2. Ensure HA's MQTT integration is connected to your broker.
3. Publish the contents of `homeassistant/mqtt-discovery.json` as a retained
   `mqtt.publish` payload to
   `homeassistant/sensor/watermeter_nfc_reader/full_data/config` (QoS 1).
   Adapt the MAC, identifiers and unique ID before using it with another reader.
4. Install this firmware. A valid NFC read publishes its complete JSON to
   `watermeter-nfc-reader/nfc/full`. Check the resulting full-data entity's
   attributes, not only its short state. Example:

   ```jinja
   {{ state_attr('sensor.watermeter_nfc_reader_nfc_full_data', 'history') }}
   ```

To remove the bridge, remove the `on_value` HA action from the full-JSON sensor,
disable `allow_service_calls` again, and publish empty retained payloads to the
discovery and data topics above. The original summary/volume entities are not
renamed or replaced by this bridge.

This driver supports contiguous Type 2 memory, UTF-8 text, and one-byte page
addresses (up to 1008 data bytes). Reserved-memory/lock-control TLV layouts,
UTF-16 text, and chunked NDEF records are explicitly unsupported.

## Install and verify

1. Back up the current dashboard YAML and **the existing components directory**.
2. Copy `watermeter-nfc-reader.yaml`, `watermeter_parser.h`, and this repository's
   `components/` into the ESPHome configuration directory together. Do not leave
   the old Git external-component entry enabled. Avoid overwriting components
   used by other devices without checking their configurations first.
3. In that installation's `secrets.yaml`, add these names using the device's
   **existing values** (do not generate a new API key or OTA password):

   ```yaml
   watermeter_api_key: "<existing api.encryption.key>"
   watermeter_ota_password: "<existing OTA password>"
   watermeter_ap_password: "<existing fallback AP password>"
   ```

   Keep existing `wifi_ssid` and `wifi_password` secrets. No real credentials
   are included in this repository.
4. Validate and compile in ESPHome Device Builder, then install by OTA.
   **That initial firmware installation requires one reboot.** Afterward,
   subsequent scans do not restart the ESP32.
5. Open `http://10.20.30.23/`, press **Read Water Meter NFC** twice, and check
   `Read complete NDEF message` / `Read … history entries` logs each time.
   Confirm uptime does not reset. Compare raw text, full JSON, and physical
   meter reading. Check for automatic fresh scans after 30 seconds.
6. Verify the meter timestamp/volume changes after actual water usage. A fresh
   NFC read cannot force the meter itself to regenerate its cached NFC data.

## Tests and validation

```sh
python tests/run_tests.py
esphome config watermeter-nfc-reader.yaml
esphome compile watermeter-nfc-reader.yaml
# After installing the firmware (presses Scan twice and checks automatic refresh):
python tests/test_device.py 10.20.30.23
```

On this machine the host tests were run with `env -u LD_LIBRARY_PATH python
tests/run_tests.py` to avoid an inherited libc/library mismatch.

- Host tests passed with AddressSanitizer and UndefinedBehaviorSanitizer:
  JSON parsing, decimal-comma volume, final lines, multiple long NDEF records,
  every truncated prefix, invalid language length, the 820-byte extended TLV,
  partial physical reads, oversized lengths, and unsupported memory layouts.
- ESPHome **2026.10.2** config validation passed using dummy secrets in a
  separate temporary directory; C++ generation also completed.
- Full firmware compilation succeeded in an FHS environment on NixOS:

  ```sh
  nix shell nixpkgs#steam-run-free --command steam-run \
    "$PWD/.venv/bin/python" -m esphome compile watermeter-nfc-reader.yaml
  ```

  The local `.venv` contains ESPHome 2026.10.2. The full-data image uses 1,034,512
  bytes (56.4% of the application partition), and static RAM usage is 33.6%.
- OTA installation succeeded at `10.20.30.23`, latest config hash `24056ef4`.
- `python tests/test_device.py 10.20.30.23` passed: two manual rereads, an
  automatic refresh, full JSON parsing, CRC preservation, and uptime increasing
  from 106 to 144 seconds without restarting on the final firmware. Volume had
  increased to `203.051 m³`, confirming fresh data rather than just cached output.
- Home Assistant was checked directly: its NFC summary is valid and ends in
  `"HistoryCount":28}`. The full-data entity has all 28 history records, every
  other decoded field, CRC `21284`, and the complete original `RawText`.
- Initial reads reported timestamp `2026-11-04 13:11` and volume `203.045 m³`;
  later HA data updated to meter timestamp `2026-11-04 14:00`. These are the
  meter's values, not the time of the most recent reader scan.
- Every key/value line, CRC, and all 28 dated entries in HA's `RawText` were
  compared against the entity's structured attributes: no fields were missing.
- A transient incomplete NFC read was observed; it correctly retained last-good
  data instead of publishing truncated JSON. The acceptance test permits two
  automatic polling opportunities to account for physical RF read failures.
- A full read takes about 1.9 seconds in the existing synchronous PN532 driver.
  It can cause an ESPHome slow-operation warning, but did not reboot the reader.

## Component provenance

`components/` is vendored from
<https://github.com/joonastikkanen/esphome-nfc-components>, commit
`2590c9c5d8c6164b0d6ef4e38ac1f7ac3da79453`, with the changes described above.
Its Apache-2.0 license is preserved in `LICENSE`.
