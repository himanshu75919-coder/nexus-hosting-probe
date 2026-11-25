# Nexus credential-free hosting probe

A bounded compatibility test, not a Telegram bot, login client or production forwarder.

- Python/Telethon import and exposed cgroup limits.
- A single Telegram HTTPS request and unauthenticated MTProto req_pq/resPQ handshake. No API_ID/API_HASH/phone/token required; never creates an account auth key or session.
- Its own `.nexus-hosting-probe/state.json` launch counter; restart should show 1 → 2 if the same working directory persists.
- Heartbeat every 30 seconds and intentional clean exit after 10 minutes. Stopped after that time is expected, not a crash.
- No environment dump, other-file read, old session, chats, production code/data, uploads or media downloads.

For Telethon import testing install `requirements.txt` first. Run `python -u probe.py`. Unit tests: `python -m unittest -v test_probe.py` (no network/account).

The host's advertised 1 GB disk does NOT support staging a 2 GB media file. This probe cannot certify heavy-media support, uptime, privacy/isolation, bandwidth allowance or production suitability. Unknown cgroup limits remain unknown, never reported as host hardware allocations.

No persistent server-control API or OAuth access is created by this project. Provider account consent and required browser actions remain with the owner.
