# SonicWall NSM MCP Server

A read-only [Model Context Protocol](https://modelcontextprotocol.io) server for
SonicWall **Network Security Manager (NSM) SaaS**. It gives any MCP-capable AI
agent — Claude Code, Claude Desktop, Copilot Studio, or your own — 46 tools for
answering real network-operations questions about a SonicWall firewall fleet:

> *"Is the Springfield site up?" · "Which firewalls still have IPS switched
> off?" · "What changed on this firewall in the last 24 hours?" · "Which site
> has the device with MAC 00:1A:2B...?" · "Is anything still permitting RDP
> inbound?"*

Everything is **read-only by construction**: the HTTP client refuses non-GET
methods before any I/O, and the recommended deployment authenticates with a
MySonicWall account whose NSM role is ReadOnly — so a write is impossible even
if the code were wrong.

## Design principles

These rules are enforced across every tool, because they are what make an AI
agent's answers trustworthy:

- **"Zero findings" and "data unavailable" are never merged.** Every response
  carries `data_status: "ok"` (zeros are real zeros) or `"unavailable"`
  (upstream failed — no data keys at all). Partial answers name each area that
  could not be read (`areas_unavailable`) and each area the platform cannot
  report at all (`not_covered`), so silence is never mistaken for health.
- **Provenance is explicit.** Every answer says whether it is **live** (read
  from the firewall right now), **cached** (NSM's tenant record, ≤60 s old), or
  **collected** (NSM's analytics store, only as fresh as the firewall's last
  check-in — where an offline firewall looks identical to a quiet one, the
  payload says so).
- **Responses stay under 500 KB** via field projection, top-N caps, and an
  explicit `truncated` flag with authoritative counts.
- **Secrets never cross the boundary.** Credential-dense payloads are projected
  through allow-lists of named fields (never deny-lists); config diffs return
  changed **key names only**, never values; registration/authentication codes
  are never returned.
- **Chat-client-friendly schemas.** Single primitive parameter types with
  defaults — no `Optional[...]` unions, which some MCP clients silently drop.

## Tools

### Fleet posture (cached from NSM's tenant record, ≤60 s old)

| Tool | What it answers |
| --- | --- |
| `list_devices` | Inventory with filters on name, model, group, online state |
| `device_detail` | Full posture for one firewall or one site |
| `firmware_report` | Version counts, outliers, vulnerable-firmware count |
| `firmware_upgrade_availability` | Who has a newer SonicOS on offer, and the upgrade paths |
| `offline_devices` | Who is offline, why, and since when |
| `drift_summary` | Config modified / out of sync / deploy pending |
| `deploy_failures` | Why NSM couldn't deploy or sync, categorized, worst first |
| `vulnerability_report` | Devices with published PSIRT advisories |
| `license_posture` | Licence status per security service, expiry windows, coterm |
| `template_compliance` | Which NSM templates are applied where, and failed pushes |
| `ha_pairs` | Every HA pair, failed-over/mismatched/degraded pairs flagged |
| `sites_by_location` | Device counts per region/city/country, with coordinates |
| `fleet_by_group` | Posture rolled up per NSM device group |
| `device_health_flags` | ATP off, analytics off, restart required, zero-touch state |
| `fleet_summary` | One-screen fleet posture card, every number source-attributed |

### Per-site live reads (read from the firewall on demand)

| Tool | What it answers |
| --- | --- |
| `site_status` | Is this site up? One-word verdict per site |
| `site_interfaces` | Interfaces, zones, VLANs, LAN summary |
| `site_wan_status` | WAN links with failover roles |
| `site_wan_health` | Which circuit is *actually* carrying traffic right now |
| `site_live_status` | Live uptime, connections, firmware — flags stale NSM cache |
| `site_vpn_tunnels` | Configured site-to-site VPN policies (never the PSK) |
| `site_nat_policies` | NAT policies, searchable |
| `site_access_rules` | The rulebase with hit counts, filterable by zone/action |
| `site_unused_rules` | Never-hit / zero-traffic / disabled rule candidates |
| `site_security_services` | Licence + signature freshness per service, live |
| `site_ssl_vpn_config` | Is SSL-VPN on, WAN-exposed, MFA-configured? |
| `site_ssl_vpn_sessions` | Who is connected right now (flagged as personal data) |
| `site_management_exposure` | Admin-plane hardening graded against a named standard |
| `site_connected_hosts` | DHCP leases / ARP cache behind one firewall |
| `site_wifi` | Built-in radio + SonicPoint APs, clients, RF scores |
| `site_event_log` | The on-box event log, searchable, with buffer coverage |
| `site_health_check` | One composed health verdict from every read above |

### Fleet-wide sweep-backed search (background sweep, one GET per device)

| Tool | What it answers |
| --- | --- |
| `lan_subnet_audit` | Which LANs are on factory-default or non-standard ranges |
| `find_host` | Find an IP/MAC/hostname/vendor anywhere in the fleet |
| `fleet_host_summary` | Host counts per site, fleet-wide vendor breakdown |

### Change management (NSM manager plane)

| Tool | What it answers |
| --- | --- |
| `config_history` | Stored config versions: who, when, committed vs synchronized |
| `nsm_commits` | Commits NSM pushed, failures first |
| `config_diff` | Changed config **key names** between two versions — never values |
| `what_changed` | One timeline of everything NSM knows changed in a window |

### Telemetry & analytics (collected by NSM)

| Tool | What it answers |
| --- | --- |
| `site_system_events` | Attacks, scans, floods, setting changes (long retention) |
| `site_attack_summary` | Top attackers, targets, ports, countries |
| `site_traffic_report` | Top apps/sources/destinations/users by bandwidth |
| `site_threat_report` | Viruses, intrusions, spyware, botnet, blocked categories |
| `is_traffic_blocked` | Evidence retrieval: has a drop been *recorded*? (deliberately has no "allowed" verdict) |

### Fleet security services (one tenant-wide call)

| Tool | What it answers |
| --- | --- |
| `security_services_matrix` | Which services are on/off across every firewall |
| `fleet_security_services` | Service state joined to licence state, per-site gap list |

A diagnostic `_debug_slow` tool (for measuring client timeout budgets) is
registered only when `MCP_DEBUG_TOOLS=1`.

## Requirements

- Python 3.12+
- A SonicWall **NSM SaaS** tenant (this server talks to the NSM cloud API, not
  directly to SonicOS on-box APIs)
- A MySonicWall **API key** — ideally from a dedicated account whose NSM role
  is **ReadOnly**

## Quick start (local)

```bash
git clone <this repo>
cd sonicwall-nsm-mcp
python -m venv .venv
. .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -r requirements.txt -c constraints.txt
```

Provide the API key one of two ways:

```bash
# Option A: environment variable
export MSW_API_KEY_READONLY="<your MySonicWall API key>"

# Option B: OS keyring (Windows Credential Manager / macOS Keychain / libsecret)
python -c "import keyring,getpass; keyring.set_password('msw-api-key-readonly','<your-msw-login>',getpass.getpass('key: '))"
```

Verify the credential and auth chain end to end (also confirms the effective
NSM role, so you know the key really is read-only):

```bash
python nsm_auth.py
```

Run the server:

```bash
export MCP_INBOUND_API_KEY="<generate a long random string>"
python server.py           # serves streamable HTTP MCP on :8080, GET /health for liveness
```

Attach it to Claude Code:

```bash
claude mcp add sonicwall-nsm --transport http http://localhost:8080/mcp \
  --header "X-API-Key: <your MCP_INBOUND_API_KEY>"
```

Any other MCP client works the same way: streamable HTTP transport, `X-API-Key`
header.

## Configuration (environment variables)

| Variable | Default | Purpose |
| --- | --- | --- |
| `MSW_API_KEY_READONLY` | *(keyring fallback)* | MySonicWall API key (read-only account) |
| `MCP_INBOUND_API_KEY` | *(unset = all requests rejected)* | Inbound auth: clients must send this in `X-API-Key`. Fail-closed; `/health` exempt |
| `MSW_TENANT_ID` | *(auto-discovered)* | Tenant productGroupID on MySonicWall |
| `NSM_TENANT_SERIAL` | *(auto-discovered)* | tenantSerial of the NSM service |
| `MSW_TENANT_NAME` | *(unset)* | Tenant name substring, used to pick a tenant when your account sees several |
| `NSM_URL` | `https://nsm-uswest.sonicwall.com` | NSM region host |
| `PORT` | `8080` | Listen port |
| `SWEEP_ENABLED` | `1` | Background fleet sweep (powers `find_host`, `lan_subnet_audit`, `fleet_host_summary`) |
| `SWEEP_INTERVAL_SECONDS` | `1800` | Sweep cycle interval |
| `SWEEP_CALL_DELAY_SECONDS` | `0.2` | Politeness delay between per-device sweep calls |
| `DEFAULT_LAN_SUBNETS` | `192.168.168.0/24` | CIDRs treated as "factory default" by the LAN audit |
| `STANDARD_LAN_SUBNETS` | `10.0.0.0/8` | CIDRs treated as your addressing standard (containment match) |
| `MCP_DEBUG_TOOLS` | *(unset)* | `1` registers the `_debug_slow` diagnostic tool |

Tenant discovery: with `MSW_TENANT_ID`/`NSM_TENANT_SERIAL` unset, the server
discovers them from the MySonicWall `get-cloud-tenants` API at first use. If
your account sees exactly one tenant, nothing more is needed; otherwise set
`MSW_TENANT_NAME` (or the explicit IDs, which `python nsm_auth.py` prints via
`discover_tenant_ids`).

## Docker

```bash
docker build -t sonicwall-nsm-mcp .
docker run -p 8080:8080 \
  -e MSW_API_KEY_READONLY="..." \
  -e MCP_INBOUND_API_KEY="..." \
  sonicwall-nsm-mcp
```

The container logs one structured JSON line per tool call to stdout.

## Security model

- **Read-only, twice over.** `NsmSession` raises on any non-GET/HEAD/OPTIONS
  method before any I/O; and if you provision the recommended ReadOnly
  MySonicWall account, NSM itself will refuse writes regardless of what any
  code asks for. Verify the effective role with `python nsm_auth.py`.
- **Inbound auth is fail-closed.** With `MCP_INBOUND_API_KEY` unset, every
  request except `/health` is rejected. The key is compared constant-time.
- **Secret projection.** Live status reads use allow-lists (registration and
  authentication codes are never projected); config diffs emit changed key
  names only; SNMP community strings, PSKs, password hashes and RADIUS/LDAP
  secrets are never read out of any payload.
- **Personal data is labelled.** SSL-VPN session lists and per-user traffic
  tables carry an explicit `contains_personal_data` / `privacy_note` flag so
  your agent layer can gate them.

## Operational notes

- The **background sweep** makes one GET per online device per cycle (default
  every 30 min) for the three fleet-search tools. Disable with
  `SWEEP_ENABLED=0` if you don't need them; those tools then report
  `data_status: "unavailable"` honestly.
- NSM bearer tokens have a 15-minute inactivity timeout; the session re-runs
  the auth chain automatically.
- Several NSM endpoints answer **HTTP 200 with an error body**; the server
  detects that and reports "unavailable" rather than presenting an
  answer-shaped non-answer. Many hard-won API behaviors (boolean `limit`
  gates, CSV-in-JSON payloads, integer-encoded IPs, misspelled vendor fields)
  are documented in comments where they are handled.

## License

MIT — see [LICENSE](LICENSE).
