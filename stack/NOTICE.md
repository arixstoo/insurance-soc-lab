# Third-party notice

The files in `stack/config/` and the Wazuh services in `docker-compose.yml` are
adapted from [wazuh/wazuh-docker](https://github.com/wazuh/wazuh-docker)
(tag `v4.14.9`, `single-node/`), Copyright Wazuh Inc., licensed under GPLv2.

Changes made for this lab:

- `config/wazuh_cluster/wazuh_manager.conf`: `logall` / `logall_json` set to `yes`
  (keep every event, not only alerts) and an `<auth><force>` block so a rebuilt
  agent container re-enrolls under the same name instead of creating a duplicate.
- `docker-compose.yml`: ports bound to `127.0.0.1`, secrets read from `.env`,
  custom rules mounted from `detection/rules/`, agents and simulator added.

Everything else in this repository is MIT licensed (see `LICENSE`).
