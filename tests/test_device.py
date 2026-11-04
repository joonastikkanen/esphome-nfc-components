"""Read-only NFC acceptance test (presses the reader's scan button, not Restart)."""
import argparse
import json
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
                                # This early log is delivered before large JSON states;
                                # later INFO messages can be dropped by the web SSE queue.
                                if "Read complete NDEF message:" in payload:
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
    passed = False
    try:
        with condition:
            assert condition.wait_for(
                lambda: "button/Read Water Meter NFC" in states or errors, timeout=15
            ), "Scan button not found"
            assert not errors, errors
        for number in (1, 2):
            with condition:
                before = len(reads)
            button = urllib.parse.quote("Read Water Meter NFC", safe="")
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
            # Allow two poll opportunities: a physical NFC read can fail
            # transiently, and the firmware intentionally retains last-good data.
            assert condition.wait_for(lambda: len(reads) > before or errors, timeout=75), (
                "No successful automatic refresh within two polling intervals"
            )
            assert not errors, errors
            assert len(uptimes) >= 2, "Insufficient uptime samples"
            assert all(b >= a for a, b in zip(uptimes, uptimes[1:])), "Device rebooted during scans"
            # Full JSON can exceed the web server's SSE event-size budget once
            # RawText is included. Fetch it with the normal entity REST endpoint.
            full_path = "/text_sensor/" + urllib.parse.quote("Water Meter NFC Full JSON", safe="")
            with urllib.request.urlopen(base + full_path, timeout=15) as response:
                full = json.loads(json.load(response)["value"])
            summary = states["text_sensor/Water Meter NFC Data"]["value"]
            assert len(summary) <= 255
            json.loads(summary)
            assert full["SN"] and full["NFC_Id"] != full["SN"]
            assert full["Name"].startswith("Ultrasonic"), "Meter name still truncated"
            assert isinstance(full["history"], list)
            assert full["HistoryCount"] == len(full["history"])
            assert full["CRC"], "Meter CRC was not preserved"
            assert states["text_sensor/Water Meter NFC Raw Text"]["value"].startswith(full["Name"])
            print(f"{full['Name']}: {full['Vol']}, {len(full['history'])} history entries")
            print(f"Automatic refresh passed; uptime {uptimes[0]} → {uptimes[-1]} seconds")
            passed = True
    finally:
        if not passed:
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
