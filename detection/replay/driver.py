"""Replay driver, runs INSIDE the replay container (see scripts/noise_report.py).

Reads tab-separated `epoch<TAB>log line` records on stdin, in time order. For each
one it moves the analysisd wall clock to `epoch` (clockshim.so offset file), sends
the line to the logtest socket in a single session, and prints one JSON object per
line: {"t": epoch, "rule": "100131", "level": 7, "alert": true}.

Run it WITHOUT the preload (`docker exec -e LD_PRELOAD= ...`): its own clock must be
the real one. Standard library only (the manager's bundled Python runs it).
"""

from __future__ import annotations

import json
import os
import socket
import struct
import sys
import time

SOCKET = "/var/ossec/queue/sockets/logtest"
OFFSET_FILE = "/var/ossec/tmp/clockshim.offset"  # analysisd chroots into /var/ossec
RECORD = 32  # fixed width: one pwrite, never truncated, so a reader never sees half a value
SETTLE = 0.005  # s: analysisd refreshes its cached clock every ~1 ms under clockshim


def set_clock(fd: int, epoch: float) -> None:
    """Shift analysisd's wall clock so that "now" is `epoch`.

    A relative offset keeps the clock ticking, so no thread waits on a frozen time.
    """
    os.pwrite(fd, f"{epoch - time.time():+.6f}".ljust(RECORD - 1).encode() + b"\n", 0)
    time.sleep(SETTLE)


def request(payload: dict) -> dict:
    data = json.dumps(payload).encode()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.connect(SOCKET)
        sock.sendall(struct.pack("<I", len(data)) + data)
        size = struct.unpack("<I", _read(sock, 4))[0]
        return json.loads(_read(sock, size))


def _read(sock: socket.socket, size: int) -> bytes:
    chunks = b""
    while len(chunks) < size:
        chunk = sock.recv(size - len(chunks))
        if not chunk:
            raise ConnectionError("logtest socket closed")
        chunks += chunk
    return chunks


def main() -> int:
    token = None
    fd = os.open(OFFSET_FILE, os.O_WRONLY | os.O_CREAT, 0o644)
    for raw in sys.stdin:
        epoch_text, _, line = raw.rstrip("\n").partition("\t")
        epoch = float(epoch_text)
        set_clock(fd, epoch)
        params = {"location": "replay", "log_format": "syslog", "event": line}
        if token:
            params["token"] = token
        reply = request({"version": 1, "origin": {"name": "replay", "module": "replay"},
                         "command": "log_processing", "parameters": params})
        if reply.get("error"):
            print(json.dumps({"t": epoch, "error": reply}), flush=True)
            return 1
        data = reply["data"]
        token = data.get("token", token)
        rule = data.get("output", {}).get("rule", {})
        print(json.dumps({"t": epoch, "rule": rule.get("id"), "level": rule.get("level"),
                          "alert": bool(data.get("alert"))}), flush=True)
    set_clock(fd, time.time())  # back to the real time
    return 0


if __name__ == "__main__":
    sys.exit(main())
