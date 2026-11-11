# Security notes

This is a **lab**. It is built to be run on one workstation and thrown away.

- All services listen on `127.0.0.1` only. Do not publish the ports.
- TLS certificates are generated locally into `stack/certs/` and are git-ignored.
- All data is synthetic. Company names, users and IP addresses are invented;
  "external" IPs use RFC 5737 documentation ranges.
- The rules are written from the defender's side. The simulator only writes
  log lines; it does not send any traffic.

## Passwords

The committed files (`.env.example`, `stack/config/wazuh_indexer/internal_users.yml`,
`stack/config/wazuh_dashboard/wazuh.yml`) keep the **public wazuh-docker defaults**
so they can be compared with upstream. They are not meant to be used:
`scripts/rotate-passwords.sh` (or `scripts/rotate-passwords.ps1`) replaces them.

| Account | Used by | Stored as |
|---|---|---|
| indexer `admin` | manager (Filebeat), you on the dashboard | bcrypt hash in `stack/secrets/internal_users.yml`, clear text in `.env` |
| indexer `kibanaserver` | dashboard server | bcrypt hash in `stack/secrets/internal_users.yml`, clear text in `.env` |
| API `wazuh-wui` | dashboard -> Wazuh API | `stack/secrets/wazuh.yml` and `.env`; the manager sets it at every start |

The script generates 32-character passwords (about 178 bits of entropy), hashes them
with the indexer's own `hash.sh` in a throwaway `wazuh/wazuh-indexer` container
(the password goes in through an environment variable, not a command line), writes
the git-ignored files above and points compose at them through `INDEXER_USERS_FILE`
and `DASHBOARD_API_CONFIG` in `.env`. The upstream demo users (`kibanaro`, `logstash`,
`readall`, `snapshotrestore`) are left out of the generated users file, so they stop
existing. `python scripts/lab_status.py` checks that every public default is rejected.

### Fresh lab

```bash
make reset          # or: docker compose down -v   (only if a lab existed)
make rotate         # or: scripts/rotate-passwords.sh / .\scripts\rotate-passwords.ps1
make up
make status         # "default passwords (must all be rejected)" -> all rejected
```

On first start the indexer creates its security index from the mounted users file.

### Running lab (rotate in place, data kept)

```bash
make rotate APPLY=1     # or: scripts/rotate-passwords.sh --apply / rotate-passwords.ps1 -Apply
```

The indexer reads `internal_users.yml` only when its security index is first created,
so on a running lab the script:

1. recreates `wazuh.indexer` with the new users file mounted;
2. loads it with `securityadmin.sh -t internalusers`, authenticated by the admin
   client certificate (`stack/certs/admin.pem`), so no old password is needed;
3. recreates `wazuh.manager` (it re-applies `API_PASSWORD` to `wazuh-wui` and the
   indexer password to Filebeat at start) and `wazuh.dashboard` (rebuilds its keystore).

Agents reconnect on their own. Without `APPLY=1`, the script refuses to run while
the lab is up, so `.env` and the indexer cannot drift apart.

## Not covered (lab scope)

- Agent enrollment has no password: any container on the `islab-soc` network can
  enroll. Production plan: [docs/production-integration.md](docs/production-integration.md).
- The admin client certificate key sits in `stack/certs/` on the host.
- `.env` holds the passwords in clear text (mode 600 on Linux/macOS).

## Supply chain

- GitHub Actions are pinned to full commit SHAs; gitleaks and Trivy images to digests.
- The agent and simulator images are scanned by Trivy in CI and every Monday; any
  CRITICAL vulnerability fails the build. Accepted exceptions go in `.trivyignore`
  with a reason and a review date.

Found a problem? Open an issue, or contact the author through the profile linked
in the README.
