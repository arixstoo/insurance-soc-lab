# From lab to production

This plan was first written for the insurer where the lab was built: a large
company with a national agency network, regional offices, an on-premise data
centre running mostly Linux virtual servers, Active Directory, next-generation
firewalls at every site and XDR on endpoints. Names and figures are withheld;
the approach is generic.

## 1. Sizing (single node, then cluster)

| Stage | Agents | Manager + indexer | Storage |
|---|---|---|---|
| Pilot | 20-30 critical servers | 8 vCPU, 16 GB RAM | 500 GB SSD (90 days hot) |
| Head office | 100-150 | Manager 8 vCPU / 16 GB, indexer 8 vCPU / 32 GB | 2 TB, ILM: 90 days hot, 1 year warm |
| National | 500+ (incl. regional offices) | Manager cluster (2 nodes) + 3 indexer nodes | 6+ TB, snapshots off-site |

## 2. Network flows to open

| From | To | Port | Purpose |
|---|---|---|---|
| Agents (all VLANs) | Manager | 1514/tcp | Event forwarding (encrypted) |
| Agents | Manager | 1515/tcp | Enrollment (only during roll-out, then restrict) |
| Firewalls, switches | Manager | 514/udp or 6514/tcp (TLS) | Syslog from devices without agents |
| Manager | Indexer | 9200/tcp | Alert indexing |
| SOC workstations | Dashboard | 443/tcp | Analyst access (admin VLAN only) |

Place the SIEM in the management / security VLAN; never expose it to user VLANs.

## 3. Log sources, by priority

1. **Domain controllers** (Windows Security channel + Sysmon): logons, account and group changes.
2. **Business platform database** (contracts, claims, payments): audit trail of reads and exports.
3. **Perimeter firewalls** (syslog): denied flows, VPN logons, IPS events.
4. **Linux servers**: `auth.log`, sudo, auditd.
5. **Internal web apps and the HR application** (developed in house): access logs.
6. **Proxy / web filter**: outbound traffic, for exfiltration hunting.

## 4. Roll-out

- **Month 1 - Pilot.** 20-30 servers, rules in "monitor only", tune false positives weekly.
- **Months 2-3 - Extension.** Domain controllers, DB audit, firewalls; alert routing (email -> ticket).
- **Month 6+ - SOC.** On-call rota, runbooks, threat-intel lists, SOAR automation (e.g. Shuffle).

## 5. Constraints seen in the field

- **Data sovereignty:** everything stays on-premise; no cloud SIEM.
- **Confidentiality:** an intern / integrator never sees production logs; the
  rules were therefore built and tested on synthetic data (this repository).
- **Legacy systems:** older Windows Server versions in production need agent
  version checks before roll-out.
- **People:** an alert nobody reads is worthless - assign owners before go-live.
