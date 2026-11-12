#!/usr/bin/env bash
# real-linux-01: lab test accounts, then rsyslog, auditd (best effort) and sshd.
set -euo pipefail

SECRETS=/run/lab-secrets
[ -s "$SECRETS/ssh-test" ] || { echo "missing $SECRETS/ssh-test (service real-secrets)" >&2; exit 1; }

# Lab test accounts, no sudo. Their password is generated per lab by real-secrets and only
# exists in the real-secrets volume (shared with real-client), never in git or in .env.
for user in lab.tester lab.ops; do
  id "$user" >/dev/null 2>&1 || useradd --create-home --shell /bin/bash "$user"
  printf '%s:%s\n' "$user" "$(cat "$SECRETS/ssh-test")" | chpasswd
done

# rsyslog with Ubuntu's own config: auth/authpriv -> /var/log/auth.log
rm -f /run/rsyslogd.pid
rsyslogd

# auditd is best effort. The kernel only lets an audit daemon register from the initial PID
# namespace, with CAP_AUDIT_CONTROL, and only one per kernel: an ordinary container usually
# cannot run it (Docker Desktop's WSL2 kernel refuses even `auditctl -s`). The lab does not
# use `pid: host` to force it. SSH detection only needs auth.log; the agent keeps reading
# /var/log/audit/audit.log, so the same image works where auditd can run (a VM).
mkdir -p /var/log/audit
if auditctl -s >/tmp/auditd.err 2>&1 && auditd >>/tmp/auditd.err 2>&1 && sleep 1 \
   && auditctl -R /etc/audit/rules.d/insurco.rules >>/tmp/auditd.err 2>&1; then
  echo "[real-linux] auditd running, $(auditctl -l | wc -l) rules loaded"
else
  echo "[real-linux] WARNING: auditd not available in this container (kernel audit refused: $(tr '\n' ' ' </tmp/auditd.err)). SSH detection is not affected; see docs/real-services.md" >&2
fi

# sshd: per-container host keys, then the daemon (it logs through /dev/log to rsyslog)
ssh-keygen -A >/dev/null
mkdir -p /run/sshd
/usr/sbin/sshd -t
/usr/sbin/sshd
echo "[real-linux] sshd listening on 22"
