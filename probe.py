"""Credential-free hosting compatibility probe; no Telegram account/bot login.
Only its own .nexus-hosting-probe/state.json is read/written. Exits after 10 minutes.
No environment dump, sessions, secrets, chats, media downloads or production state.
"""
import importlib.util
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import struct
import sys
import time
import urllib.request


TARGET = ("149.154.167.51", 443)
DURATION_SECONDS = 600
STOP = False


def emit(event, **fields):
    print(json.dumps({"event": event, **fields}, sort_keys=True), flush=True)


def read_text(path):
    try:
        return Path(path).read_text().strip()
    except OSError:
        return None


def limits():
    memory = read_text("/sys/fs/cgroup/memory.max") or read_text("/sys/fs/cgroup/memory/memory.limit_in_bytes")
    cpu = read_text("/sys/fs/cgroup/cpu.max")
    memory_limit = int(memory) if memory and memory.isdecimal() and int(memory) < 10**16 else None
    quota = None
    if cpu and not cpu.startswith("max"):
        a, b = map(int, cpu.split())
        if a > 0 and b > 0:
            quota = a / b
    return {"memory_limit_bytes": memory_limit, "cpu_quota": quota, "scope": "cgroup limits if exposed; not host hardware"}


def mark_start(folder):
    folder = Path(folder)
    if folder.is_symlink():
        raise ValueError("Probe folder cannot be a symlink")
    folder.mkdir(exist_ok=True, parents=True)
    state = folder / "state.json"
    if state.is_symlink():
        raise ValueError("Probe state cannot be a symlink")
    count = 0
    if state.exists():
        if state.stat().st_size > 4096:
            raise ValueError("Unexpected probe state size; refusing overwrite")
        prior = json.loads(state.read_text())
        if prior.get("probe") != "nexus-credential-free-v1" or not isinstance(prior.get("launch_count"), int):
            raise ValueError("Unexpected state; refusing overwrite")
        count = prior["launch_count"]
    data = {"probe": "nexus-credential-free-v1", "launch_count": count + 1}
    temp = folder / "state.tmp"
    if temp.is_symlink():
        raise ValueError("Probe temporary path cannot be a symlink")
    temp.write_text(json.dumps(data))
    os.replace(temp, state)
    return data


def make_request(nonce):
    if len(nonce) != 16:
        raise ValueError("Nonce must be 16 bytes")
    body = struct.pack("<I", 0xBE7E8EF1) + nonce
    msg = b"\0" * 8 + struct.pack("<Q", int(time.time() * 2**32) & ~3) + struct.pack("<I", len(body)) + body
    return b"\xef" + bytes([len(msg) // 4]) + msg


def validate_reply(reply, nonce):
    if len(reply) < 40 or reply[:8] != b"\0" * 8:
        raise ValueError("Invalid unencrypted MTProto envelope")
    size = struct.unpack("<I", reply[16:20])[0]
    if size < 20 or size > len(reply) - 20:
        raise ValueError("Invalid MTProto message size")
    if struct.unpack("<I", reply[20:24])[0] != 0x05162463 or reply[24:40] != nonce:
        raise ValueError("Unexpected resPQ or nonce")
    return True


def mtproto_probe():
    nonce = secrets.token_bytes(16)
    with socket.create_connection(TARGET, timeout=8) as connection:
        connection.sendall(make_request(nonce))

        def exact(size):
            data = b""
            while len(data) < size:
                chunk = connection.recv(size - len(data))
                if not chunk:
                    raise ConnectionError("EOF")
                data += chunk
            return data

        first = exact(1)[0]
        words = int.from_bytes(exact(3), "little") if first == 127 else first
        if not 10 <= words <= 4096:
            raise ValueError("Invalid abridged frame size")
        return validate_reply(exact(words * 4), nonce)


def stop_handler(*unused):
    global STOP
    STOP = True


def main():
    signal.signal(signal.SIGTERM, stop_handler)
    signal.signal(signal.SIGINT, stop_handler)
    emit("PROBE_START", version="1.0", python=sys.version.split()[0], no_credentials=True, auto_exit_seconds=DURATION_SECONDS)
    emit("RESOURCE_LIMITS", **limits())
    try:
        emit("PROBE_STATE", **mark_start(Path.cwd() / ".nexus-hosting-probe"))
    except Exception as exc:
        emit("PROBE_STATE_FAILED", error_type=type(exc).__name__)
    try:
        found = importlib.util.find_spec("telethon") is not None
        version = None
        if found:
            import telethon
            version = telethon.__version__
        emit("TELETHON_IMPORT", installed=found, version=version)
    except Exception as exc:
        emit("TELETHON_IMPORT_FAILED", error_type=type(exc).__name__)
    try:
        with urllib.request.urlopen("https://api.telegram.org/", timeout=10) as response:
            emit("TELEGRAM_HTTPS", status=response.status)
    except Exception as exc:
        emit("TELEGRAM_HTTPS_FAILED", error_type=type(exc).__name__)
    try:
        emit("MTPROTO_REQ_PQ", success=mtproto_probe(), account_login=False, session_created=False)
    except Exception as exc:
        emit("MTPROTO_REQ_PQ_FAILED", error_type=type(exc).__name__)
    emit("PROBE_CHECKS_COMPLETE", note="Compatibility only: not a login, forwarding, large-file, security or uptime certificate")
    start = time.monotonic()
    next_tick = 30
    while not STOP and time.monotonic() - start < DURATION_SECONDS:
        time.sleep(1)
        elapsed = int(time.monotonic() - start)
        if elapsed >= next_tick:
            emit("PROBE_HEARTBEAT", elapsed_seconds=elapsed)
            next_tick += 30
    emit("PROBE_STOP", reason="owner_or_host_stop" if STOP else "intentional_10_minute_end", clean=True)


if __name__ == "__main__":
    main()
