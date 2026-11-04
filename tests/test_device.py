"""Read-only NFC acceptance test (presses the reader's scan button, not Restart)."""
import argparse
import json
import re
import threading
import time
import urllib.parse
import urllib.request


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("host", nargs="?", default="10.20.30.23")
    args = parser.parse_args()
    base = f"http://{args.host}"
    condition = threading.Condition()
    states = {}
    logs = []
    reads = []
    uptimes = []
    errors = []
    ready = threading.Event()

    def collect():
        try:
            with urllib.request.urlopen(base + "/events", timeout=15) as response:
                event, data = "", []
                for raw in response:
                    line = raw.decode("utf-8").rstrip("\r\n")
                    if line.startswith("event: "):
                        event = line[7:]
                    elif line.startswith("data: "):
                        data.append(line[6:])
                    elif not line:
                        payload = "\n".join(data)
                        with condition:
                            if event == "state":
                                state = json.loads(payload)
                                states[state["id"]] = state
                            elif event == "ping":
                                ping = json.loads(payload)
                                if "uptime" in ping:
                                    uptimes.append(ping["uptime"])
                                ready.set()
                            elif event == "log":
                                logs.append(payload)
                                if re.search(r"Read [\d.]+ m³, \d+ history entries", payload):
                                    reads.append(time.monotonic())
                                    print(payload, flush=True)
                            condition.notify_all()
                        event, data = "", []
        except Exception as error:
            with condition:
                errors.append(str(error))
                condition.notify_all()

    threading.Thread(target=collect, daemon=True).start()
    assert ready.wait(15), "Device event stream unavailable"
    try:
        for number in (1, 2):
            with condition:
                before = len(reads)
            button = urllib.parse.quote("read_water_meter_nfc", safe="")
            request = urllib.request.Request(base + f"/button/{button}/press", method="POST")
            with urllib.request.urlopen(request, timeout=15) as response:
                assert response.status == 200
            with condition:
                assert condition.wait_for(lambda: len(reads) > before or errors, timeout=20), (
                    f"Manual scan {number} produced no successful read"
                )
                assert not errors, errors
            print(f"Manual scan {number} passed", flush=True)

        with condition:
            before = len(reads)
            assert condition.wait_for(lambda: len(reads) > before or errors, timeout=40), (
                "No automatic 30-second refresh"
            )
            assert not errors, errors
            assert len(uptimes) >= 2, "Insufficient uptime samples"
            assert all(b >= a for a, b in zip(uptimes, uptimes[1:])), "Device rebooted during scans"
            full = json.loads(states["text_sensor/Water Meter NFC Full JSON"]["value"])
            summary = states["text_sensor/Water Meter NFC Data"]["value"]
            assert len(summary) <= 255
            json.loads(summary)
            assert full["SN"] and full["NFC_Id"] != full["SN"]
            assert full["Name"].startswith("Ultrasonic"), "Meter name still truncated"
            assert isinstance(full["history"], list)
            print(json.dumps(full, ensure_ascii=False, indent=2))
            print(f"Automatic refresh passed; uptime {uptimes[0]} → {uptimes[-1]} seconds")
    finally:
        for key, value in states.items():
            if "NFC Raw" in key:
                print("Raw meter text:", value.get("value"))
        if errors:
            print("Stream errors:", errors)
        for log in logs[-20:]:
            if "watermeter" in log or "pn532" in log or "nfc" in log:
                print(log)


if __name__ == "__main__":
    main()
