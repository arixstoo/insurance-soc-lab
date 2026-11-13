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
# Seconds to wait after moving the clock: analysisd refreshes its cached clock every ~1 ms
# under clockshim, but a busy CI runner can delay that thread, and a stale cache makes two
# events look closer than they are (a 125 s spread counted inside a 120 s window, seen on
# GitHub Actions). The detection tests (few lines) pass 0.1; the 24 h noise replay keeps 5 ms.
SETTLE = float(os.environ.get("REPLAY_SETTLE", "0.005"))
# The thread that refreshes that cache (w_log_rotate_thread, wazuh v4.14.9 analysisd.c) also
# dumps the hourly stats and opens / rotates the log files when the hour or the day changes,
# under the writers' mutex: after a move across an hour boundary (every timed case starts a
# simulated day later) the cache can lag by far more than SETTLE. Wait longer there.
BOUNDARY_SETTLE = float(os.environ.get("REPLAY_BOUNDARY_SETTLE", "1.0"))
_last_hour: int | None = None


def set_clock(fd: int, epoch: float) -> None:
    """Shift analysisd's wall clock so that "now" is `epoch`.

    A relative offset keeps the clock ticking, so no thread waits on a frozen time.
    """
    global _last_hour
    os.pwrite(fd, f"{epoch - time.time():+.6f}".ljust(RECORD - 1).encode() + b"\n", 0)
    hour = int(epoch // 3600)  # UTC hours: the lab time zones are whole-hour offsets
    time.sleep(BOUNDARY_SETTLE if hour != _last_hour else SETTLE)
    _last_hour = hour


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
