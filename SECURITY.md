# Security notes

This is a **lab**. It is built to be run on one workstation and thrown away.

- All services listen on `127.0.0.1` only. Do not publish the ports.
- The default passwords in `.env.example` are the public Wazuh lab defaults.
  Change them before running the lab on any shared machine (roadmap phase 1).
- TLS certificates are generated locally into `stack/certs/` and are git-ignored.
- All data is synthetic. Company names, users and IP addresses are invented;
  "external" IPs use RFC 5737 documentation ranges.
- The rules are written from the defender's side. The simulator only writes
  log lines; it does not send any traffic.

Found a problem? Open an issue, or contact the author through the profile linked
in the README.
