"""Static data describing the fictional insurer "InsurCo".

Everything here is invented. IP addresses use lab-private ranges (10.20.0.0/16)
for employees and RFC 5737 documentation ranges for "external" sources, so no
real system is ever referenced.
"""

from __future__ import annotations

from dataclasses import dataclass

EMPLOYEES = [
    "a.benali", "f.khelil", "k.meziane", "s.boukhalfa", "m.hadj",
    "n.bensalem", "y.amrani", "l.brahimi", "r.saidani", "h.ouali",
]
SERVICE_ACCOUNTS = ["svc_backup", "svc_reporting", "it.admin"]
INVALID_USERS = ["root", "admin", "test", "oracle", "postgres"]

INTERNAL_IPS = [f"10.20.10.{i}" for i in range(10, 80)]
EXTERNAL_IPS = [f"203.0.113.{i}" for i in range(10, 60)] + [f"198.51.100.{i}" for i in range(10, 40)]

SENSITIVE_TABLES = ["clients", "policies", "claims", "payments", "beneficiaries"]
OTHER_TABLES = ["agencies", "products", "tariffs"]

WORKSTATIONS = ["WS-CLAIMS-01", "WS-CLAIMS-02", "WS-UNDERWRITING-01", "WS-FINANCE-01", "WS-IT-01"]

WEB_PAGES = [
    "/", "/login", "/dashboard", "/policies/{id}", "/claims/{id}",
    "/api/v1/policies?agency={agency}", "/static/app.css", "/static/app.js",
]
ROUTINE_SUDO = ["/usr/bin/apt update", "/usr/bin/systemctl restart apache2", "/usr/bin/journalctl -u ssh"]
SUSPICIOUS_SUDO = ["/bin/bash", "/usr/bin/passwd root", "/usr/bin/chmod 777 /etc/shadow"]

WEB_ATTACKS = {
    "sqli": [
        "/claims/search?q=%27%20UNION%20SELECT%20username,password%20FROM%20users--",
        "/login?user=admin%27%20OR%20%271%27=%271",
    ],
    "xss": ["/search?q=<script>alert(1)</script>"],
    "traversal": ["/documents/download?file=../../../../etc/passwd"],
    "probe": ["/.env", "/backup.sql", "/.git/config"],
}


@dataclass(frozen=True)
class Host:
    """A simulated machine and the log file its Wazuh agent reads."""

    name: str
    role: str
    log_file: str


HOSTS = {
    "linux": Host("srv-linux-01", "linux", "auth.log"),
    "web": Host("srv-web-01", "web", "access.log"),
    "db": Host("srv-db-01", "db", "db_audit.json"),
    "workstation": Host("ws-claims-01", "workstation", "winsec.json"),
}
