"""SonicWall NSM MCP server — read-only fleet-posture tools.

Serves streamable HTTP for any MCP client (Claude Code / Claude Desktop,
Copilot Studio, or your own agent). The fleet-level tools answer from cached
upstream calls (60s TTL, in-process per replica):

    GET /api/manager/devices/tenant      (list/detail/firmware/offline/drift)
    GET /api/manager/devices/vulnerable  (vulnerability_report)

Design rules enforced throughout:
- every response <500 KB: field projection + top-N + explicit "truncated"
- "zero findings" vs "data unavailable" are distinct: data_status is "ok"
  (zeros are real zeros) or "unavailable" (upstream failed; no data keys)
- parameter schemas: single primitive types only, optionality via defaults —
  never Optional[...] (some MCP clients silently drop multi-type schemas)
- stateless transport; custom GET /health (container-platform probes would
  restart-loop an MCP POST-only port); one structured JSON log line per call
- inbound auth: X-API-Key checked constant-time against MCP_INBOUND_API_KEY,
  fail-closed when unset; /health exempt

Credentials: hosted replicas get MSW_API_KEY_READONLY via env (e.g. injected
from a secret store); local runs fall back to the OS keyring through nsm_auth.
"""
from __future__ import annotations

import contextvars
import hmac
import ipaddress
import json
import os
import re
import threading
import urllib.parse
from concurrent.futures import (ThreadPoolExecutor,
                                TimeoutError as FutureTimeout)
import time
from collections import Counter
from datetime import datetime, timedelta, timezone
from functools import wraps

import nsm_auth

from fastmcp import FastMCP

APP_NAME = "sonicwall-nsm"
CACHE_TTL_SECONDS = 60
MAX_LIST_DEVICES = 100
MAX_DRIFT_LIST = 50
MAX_DETAIL_MATCHES = 5
MAX_HOSTS = 100


def default_lan_subnets() -> set:
    """CIDRs that count as 'still on the factory default'. Read per call so a
    hosted replica picks up an env change on restart without a code edit."""
    return {s.strip()
            for s in os.environ.get("DEFAULT_LAN_SUBNETS", "192.168.168.0/24").split(",")
            if s.strip()}


def standard_lan_subnets() -> set:
    """CIDRs that count as your organization's standard LAN addressing.
    Default `10.0.0.0/8`; override with STANDARD_LAN_SUBNETS (comma-separated).
    These are SUPERNETS, matched by containment (see _within), not an exact
    list of per-site subnets."""
    return {s.strip()
            for s in os.environ.get("STANDARD_LAN_SUBNETS", "10.0.0.0/8").split(",")
            if s.strip()}


def _within(cidr: str, subnets) -> bool:
    """True when `cidr` is inside (or equal to) any CIDR in `subnets`.

    Containment, not set membership: a typical standard is a whole supernet
    (e.g. 10.0.0.0/8) with every site on its own subnet inside it. A malformed entry is
    skipped rather than raised — this is config a human types, and an audit
    that crashes is worse than one that reports.
    """
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False
    for s in subnets:
        try:
            candidate = ipaddress.ip_network(s, strict=False)
        except ValueError:
            continue
        if net.version != candidate.version:
            continue
        if net == candidate or net.subnet_of(candidate):
            return True
    return False

# Hosted: read-only key injected as an env var (e.g. from a secret store). The
# provider seam means zero changes to nsm_auth.py. Local: no env var ->
# nsm_auth's default OS-keyring path.
if os.environ.get("MSW_API_KEY_READONLY"):
    nsm_auth.set_api_key_provider(lambda write: os.environ["MSW_API_KEY_READONLY"])

# read_only=True is load-bearing: NsmSession refuses non-GET before any I/O,
# and authenticates as the read-only MySonicWall account.
SESSION = nsm_auth.NsmSession(read_only=True)

mcp = FastMCP(APP_NAME)

# Which inbound credential authenticated this request ("local" = in-process).
_caller_label = contextvars.ContextVar("caller_key_label", default="local")


# ------------------------------------------------------------- upstream + cache

def _upstream_devices() -> list:
    return SESSION.get("/api/manager/devices/tenant", timeout=60)


def _upstream_vulnerable() -> list:
    return SESSION.get("/api/manager/devices/vulnerable", timeout=60)


_cache: dict[str, tuple[float, object]] = {}


def _cached(key: str, fetch):
    hit = _cache.get(key)
    if hit and time.monotonic() - hit[0] < CACHE_TTL_SECONDS:
        return hit[1]
    value = fetch()
    _cache[key] = (time.monotonic(), value)
    return value


def get_devices() -> list:
    return _cached("devices", _upstream_devices)


def get_vulnerable() -> list:
    return _cached("vulnerable", _upstream_vulnerable)


def clear_cache() -> None:
    _cache.clear()


# ------------------------------------------------------ per-device upstream

DEVICE_PATHS = {
    "interfaces": "/api/manager/firewall/interfaces/ipv4",
    "failover": "/api/manager/firewall/failover-lb/groups",
    "vpn": "/api/manager/firewall/vpn/policies/ipv4/site-to-site",
    "nat": "/api/manager/firewall/nat-policies/ipv4",
    "dhcp": "/api/manager/firewall/reporting/dhcp-server/ipv4/leases/status",
    "arp": "/api/manager/firewall/reporting/arp/caches",
    # Live per-device status. These are LIVE reads of the firewall, unlike
    # everything served from get_devices().
    "sys_status": "/api/manager/firewall/reporting/status/system",
    "flb_status_groups":
        "/api/manager/firewall/reporting/failover-lb/status/groups",
    "flb_members":
        "/api/manager/firewall/reporting/failover-lb/status/members",
    "flb_statistics": "/api/manager/firewall/reporting/failover-lb/statistics",
    "iface_status": "/api/manager/firewall/reporting/interfaces/ipv4/status",
    "sec_services":
        "/api/manager/firewall/reporting/status/security-services",
    "gav": "/api/manager/firewall/reporting/gateway-antivirus",
    "ips": "/api/manager/firewall/reporting/intrusion-prevention",
    "appctl": "/api/manager/firewall/reporting/app-control",
    "sslvpn_sessions": "/api/manager/firewall/reporting/ssl-vpn/sessions",
    "ha_status": "/api/manager/firewall/reporting/high-availability",
    # Wireless + on-box log.
    #
    # NOTE THE MISSING v2. reporting/wireless/v2/stations and
    # .../v2/discovered-access-points returned HTTP 400 on every sample device
    # probed. The non-v2 paths below return 200 on the TZ W models. A tool
    # built on the v2 paths would have reported "no Wi-Fi clients" fleet-wide
    # and looked like a healthy answer.
    #
    # Two INDEPENDENT families, never summed blindly:
    #   wireless/*   = the firewall's own built-in radio (TZ xx0W). 400s on a
    #                  radio-less box such as an NSA 3700.
    #   sonicpoint/* = external SonicPoint/SonicWave APs. Returns [] on a site
    #                  with none — which is data, not a failure.
    "wifi_status": "/api/manager/firewall/reporting/wireless/status",
    "wifi_stations": "/api/manager/firewall/reporting/wireless/stations",
    "wifi_discovered_aps":
        "/api/manager/firewall/reporting/wireless/discovered-access-points",
    "wifi_vap_status":
        "/api/manager/firewall/reporting/sonicpoint/virtual-access-point-status",
    "sonicpoint_status": "/api/manager/firewall/reporting/sonicpoint/status",
    "sonicpoint_stations":
        "/api/manager/firewall/reporting/sonicpoint/station/status",
    "sonicpoint_rf_score":
        "/api/manager/firewall/reporting/sonicpoint/rf/analysis/score",
    # site_event_log — the ON-BOX log. log_categories is 340 KB of
    # category definitions on every sample: it is aggregated, never returned.
    "log_view": "/api/manager/firewall/reporting/log/view",
    "log_view_status": "/api/manager/firewall/reporting/log/view-status",
    "log_categories": "/api/manager/firewall/reporting/log/categories",
    # Per-site CONFIGURATION reads.
    #
    # THREE ENDPOINTS THAT DID NOT WORK, recorded so nobody probes them again:
    #   security-policies/ipv4              fails on Classic-mode fleets (it is
    #                                       the Policy-Mode unified engine)
    #   export/shadow-rule-list/access-rules  and nat-policies: the generator
    #                                       that populates them is POST-only,
    #                                       so SonicOS's own shadowed-rule
    #                                       analysis is not reachable
    #                                       read-only.
    #   ssl-vpn/client-settings             200 with an error body: "path
    #                                       /ssl-vpn/client-settings was not
    #                                       found".
    #
    # NOTE: not one GET in the 1772-path SonicOS swagger accepts a query
    # parameter. There is no server-side filtering and no paging anywhere on
    # this plane — every filter and every cap in these tools is client-side,
    # which is why the size discipline lives in the projection.
    "access_rules": "/api/manager/firewall/access-rules/ipv4",
    "access_rules_stats": "/api/manager/firewall/reporting/access-rules/ipv4",
    "sslvpn_base": "/api/manager/firewall/ssl-vpn/server/base",
    "sslvpn_accesses": "/api/manager/firewall/ssl-vpn/server/accesses",
    "sslvpn_portal": "/api/manager/firewall/ssl-vpn/portal",
    "admin_global": "/api/manager/firewall/administration/global",
    "snmp_base": "/api/manager/firewall/snmp/base",
    "local_users": "/api/manager/firewall/user/local/users",
    "auth_base": "/api/manager/firewall/user/authentication/base",
    "zones": "/api/manager/firewall/zones",
    "ntp_servers": "/api/manager/firewall/time/ntp-servers",
    "time_base": "/api/manager/firewall/time/base",
    "dns_base": "/api/manager/firewall/dns/base",
    "syslog_servers": "/api/manager/firewall/log/syslog/syslog-servers",
}
DEVICE_CALL_TIMEOUT = 20


def _upstream_device_json(path: str, serial: str) -> dict:
    """One per-device GET; NsmSession adds the X-Device-ID header. This is the
    monkeypatch seam every offline per-site test replaces."""
    return SESSION.get(path, serial=serial, timeout=DEVICE_CALL_TIMEOUT)


def _device_json(key: str, serial: str) -> dict:
    path = DEVICE_PATHS[key]
    return _cached(f"{key}|{serial}", lambda: _upstream_device_json(path, serial))


def _resolve(site_or_serial: str) -> list:
    """Exact serial match first, else case-insensitive name substring."""
    q = (site_or_serial or "").strip().lower()
    if not q:
        return []
    devs = get_devices()
    exact = [d for d in devs if (d.get("serialNumber") or "").lower() == q]
    if exact:
        return exact
    return [d for d in devs if q in (d.get("friendlyName") or "").lower()]


def _ambiguous(matches: list) -> dict:
    return {
        "data_status": "ok",
        "match_count": len(matches),
        "candidates": [
            {"serial": d.get("serialNumber") or "",
             "name": d.get("friendlyName") or "",
             "online": bool(d.get("liveStatus"))}
            for d in matches[:MAX_DETAIL_MATCHES]
        ],
        "detail": "More than one firewall matches; call again with the exact serial.",
    }


def _no_match(site_or_serial: str) -> dict:
    return {"data_status": "ok", "match_count": 0, "candidates": [],
            "detail": f"No firewall matches {site_or_serial!r} by serial or name."}


def _one_device(site_or_serial: str):
    """Returns (device, None) or (None, early_payload)."""
    matches = _resolve(site_or_serial)
    if not matches:
        return None, _no_match(site_or_serial)
    if len(matches) > 1:
        return None, _ambiguous(matches)
    return matches[0], None


def _dev_ident(d: dict) -> dict:
    return {"serial": d.get("serialNumber") or "",
            "name": d.get("friendlyName") or "",
            "online": bool(d.get("liveStatus"))}


def _first_list(payload) -> list:
    """SonicOS reporting endpoints return either a bare list or a single-key
    wrapper; both shapes are live in this fleet."""
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        for v in payload.values():
            if isinstance(v, list):
                return v
    return []


def _name_of(obj) -> str:
    """Object references arrive as {"name": X}, {"group": X} or one level
    deeper as {"destination_network": {"name": X}} — all three are live."""
    if isinstance(obj, str):
        return obj
    if not isinstance(obj, dict):
        return ""
    if isinstance(obj.get("name"), str):
        return obj["name"]
    for v in obj.values():
        if isinstance(v, str):
            return v
    for v in obj.values():
        if isinstance(v, dict):
            if isinstance(v.get("name"), str):
                return v["name"]
            for inner in v.values():
                if isinstance(inner, str):
                    return inner
    return ""


def _iface_rows(payload: dict) -> list:
    rows = []
    for item in (payload or {}).get("interfaces") or []:
        v4 = item.get("ipv4") or {}
        assign = v4.get("ip_assignment") or {}
        mode = assign.get("mode") or {}
        mode_type = next(iter(mode), "") if isinstance(mode, dict) and mode else ""
        details = mode.get(mode_type) if mode_type else {}
        details = details if isinstance(details, dict) else {}
        rows.append({
            "name": v4.get("name") or "",
            "zone": assign.get("zone") or "",
            "mode": mode_type,
            "ip": details.get("ip") or "",
            "netmask": details.get("netmask") or "",
            "gateway": details.get("gateway") or "",
            "vlan": v4.get("vlan"),
            "comment": v4.get("comment") or "",
            "shutdown": bool(v4.get("shutdown_port")),
        })
    return rows


def _cidr(ip: str, netmask: str) -> str:
    try:
        return str(ipaddress.ip_network(f"{ip}/{netmask}", strict=False))
    except ValueError:
        return ""


def _lan_summary(rows: list) -> dict:
    """X0 if it is addressed, else the first addressed LAN-zone interface."""
    lan = (next((r for r in rows if r["name"] == "X0" and r["ip"]), None)
           or next((r for r in rows if r["zone"].upper() == "LAN" and r["ip"]), None))
    if not lan:
        return {"interface": "", "cidr": "", "ip": "", "netmask": "",
                "is_default": False, "is_standard": False}
    cidr = _cidr(lan["ip"], lan["netmask"])
    return {"interface": lan["name"], "cidr": cidr, "ip": lan["ip"],
            "netmask": lan["netmask"],
            "is_default": _within(cidr, default_lan_subnets()),
            "is_standard": _within(cidr, standard_lan_subnets())}


# ------------------------------------------------------------ logging + wrapper

def _log(tool: str, args_summary: str, t0: float, ok: bool) -> None:
    print(json.dumps({
        "ts": datetime.now(timezone.utc).isoformat(),
        "app": APP_NAME,
        "tool": tool,
        "args_summary": args_summary,
        "caller_key_label": _caller_label.get(),
        "duration_ms": round((time.perf_counter() - t0) * 1000, 1),
        "ok": ok,
    }), flush=True)


def fleet_tool(fn):
    """Uniform envelope: one log line per call; any upstream failure becomes an
    explicit data-unavailable payload, never an empty-but-successful answer."""

    @wraps(fn)
    def wrapper(**kwargs):
        t0 = time.perf_counter()
        args_summary = ",".join(
            f"{k}={v}" for k, v in kwargs.items() if v not in ("", None)
        ) or "-"
        try:
            result = fn(**kwargs)
            _log(fn.__name__, args_summary, t0, ok=True)
            return result
        except Exception as exc:  # noqa: BLE001 — the envelope IS the handler
            _log(fn.__name__, args_summary, t0, ok=False)
            return {
                "data_status": "unavailable",
                "detail": f"{type(exc).__name__}: {exc}",
            }

    return wrapper


def _project(d: dict) -> dict:
    a = d.get("attributes") or {}
    return {
        "serial": d.get("serialNumber") or "",
        "name": d.get("friendlyName") or "",
        "model": a.get("model") or "",
        "firmware": a.get("firmware_version") or "",
        "ip": d.get("ipAddress") or "",
        "group": d.get("deviceGroupName") or "",
        "online": bool(d.get("liveStatus")),
    }


# ------------------------------------------------------------------------ tools

@mcp.tool
@fleet_tool
def list_devices(site: str = "", model: str = "", group: str = "",
                 online: str = "") -> dict:
    """List SonicWall firewalls in the fleet with serial, name, model, firmware,
    IP, device group and online status. All filters are optional substrings:
    site matches the device name (site names like '1042 Springfield' are encoded
    there), model matches the hardware model (e.g. 'TZ 270W'), group matches
    the device group (e.g. 'Retail-East'). online must be '' (no filter), 'true'
    (online only) or 'false' (offline only). Returns at most 100 devices;
    when truncated=true, total_count still reports the full match count —
    narrow the filters to see the rest."""
    rows = [_project(d) for d in get_devices()]
    if site:
        rows = [r for r in rows if site.lower() in r["name"].lower()]
    if model:
        rows = [r for r in rows if model.lower() in r["model"].lower()]
    if group:
        rows = [r for r in rows if group.lower() in r["group"].lower()]
    if online in ("true", "false"):
        want = online == "true"
        rows = [r for r in rows if r["online"] is want]
    out = rows[:MAX_LIST_DEVICES]
    return {
        "data_status": "ok",
        "total_count": len(rows),
        "returned_count": len(out),
        "truncated": len(rows) > len(out),
        "devices": out,
    }


@mcp.tool
@fleet_tool
def device_detail(site_or_serial: str) -> dict:
    """Detailed posture for one firewall (or one site's firewalls): identity,
    firmware, online state, high-availability pairing, applied templates,
    configuration sync/modified/deploy-pending state and firmware-vulnerability
    flag. Pass an exact serial number or a site/name fragment such as
    'Springfield'. Returns up to 5 matches; match_count reports how many matched
    in total. match_count of 0 means the query matched nothing — it is a real
    answer, not an error."""
    q = site_or_serial.strip().lower()
    devs = get_devices()
    matches = [d for d in devs if (d.get("serialNumber") or "").lower() == q]
    if not matches:
        matches = [d for d in devs if q in (d.get("friendlyName") or "").lower()]
    out = []
    for d in matches[:MAX_DETAIL_MATCHES]:
        row = _project(d)
        row.update({
            "synchronized": d.get("synchronized"),
            "config_modified": d.get("configModified"),
            "deploy_pending": d.get("deployPending"),
            "high_availability": d.get("highAvailability"),
            "applied_templates": d.get("appliedTemplates"),
            "vulnerability": d.get("vulnerability"),
        })
        out.append(row)
    return {
        "data_status": "ok",
        "match_count": len(matches),
        "matches": out,
        "truncated": len(matches) > len(out),
    }


@mcp.tool
@fleet_tool
def firmware_report() -> dict:
    """Fleet-wide firmware posture: how many devices run each SonicOS version
    (version_counts), devices whose firmware could not be read (unknown_count),
    outliers (devices on any version shared by fewer than 10 devices — upgrade
    stragglers and one-offs), and how many devices NSM flags as running
    firmware with known vulnerabilities (vulnerable_count)."""
    devs = get_devices()
    versions = Counter(
        (d.get("attributes") or {}).get("firmware_version")
        for d in devs
        if (d.get("attributes") or {}).get("firmware_version")
    )
    unknown = sum(
        1 for d in devs if not (d.get("attributes") or {}).get("firmware_version")
    )
    outliers = [
        {
            "serial": d.get("serialNumber") or "",
            "name": d.get("friendlyName") or "",
            "firmware": (d.get("attributes") or {}).get("firmware_version"),
        }
        for d in devs
        if (v := (d.get("attributes") or {}).get("firmware_version"))
        and versions[v] < 10
    ]
    vulnerable = sum(
        1 for d in devs if (d.get("vulnerability") or {}).get("isFirmwareVulnerable")
    )
    return {
        "data_status": "ok",
        "total_devices": len(devs),
        "version_counts": dict(versions),
        "unknown_count": unknown,
        "outliers": outliers,
        "vulnerable_count": vulnerable,
    }


@mcp.tool
@fleet_tool
def offline_devices() -> dict:
    """Firewalls currently offline in NSM, with the last reason NSM recorded
    for the connection dropping (last_down_reason) and when the live status
    last changed (last_changed_time). offline_count of 0 with an empty list
    means the whole fleet is online — a real answer, not missing data."""
    rows = []
    for d in get_devices():
        if d.get("liveStatus"):
            continue
        a = d.get("attributes") or {}
        rows.append({
            "serial": d.get("serialNumber") or "",
            "name": d.get("friendlyName") or "",
            "model": a.get("model") or "",
            "ip": d.get("ipAddress") or "",
            "group": d.get("deviceGroupName") or "",
            "last_down_reason": d.get("liveStatusLastDownReason"),
            "last_changed_time": d.get("liveStatusLastChangedTime"),
        })
    return {"data_status": "ok", "offline_count": len(rows), "devices": rows}


@mcp.tool
@fleet_tool
def drift_summary() -> dict:
    """Configuration-drift posture across the fleet: devices whose running
    config was modified outside NSM (config_modified), devices out of sync
    with NSM (unsynchronized), and devices with a pending deploy
    (deploy_pending). Counts are authoritative for the whole fleet; each list
    shows at most 50 devices (serial + name)."""
    devs = get_devices()
    modified = [d for d in devs if d.get("configModified")]
    unsync = [d for d in devs if d.get("synchronized") is False]
    pending = [d for d in devs if d.get("deployPending")]

    def slim(items: list) -> list:
        return [
            {"serial": d.get("serialNumber") or "", "name": d.get("friendlyName") or ""}
            for d in items[:MAX_DRIFT_LIST]
        ]

    return {
        "data_status": "ok",
        "total_devices": len(devs),
        "config_modified_count": len(modified),
        "unsynchronized_count": len(unsync),
        "deploy_pending_count": len(pending),
        "config_modified": slim(modified),
        "unsynchronized": slim(unsync),
        "deploy_pending": slim(pending),
    }


@mcp.tool
@fleet_tool
def vulnerability_report() -> dict:
    """Firewalls running firmware with published SonicWall PSIRT advisories:
    per device, each advisory's ID, severity (impact), title, whether a
    workaround exists, and the advisory link. vulnerable_device_count of 0
    with an empty list means no device is flagged — a real answer, not
    missing data."""
    devices = [
        {
            "serial": v.get("serialNumber") or "",
            "name": v.get("friendlyName") or "",
            "advisories": [
                {
                    "id": a.get("advisoryID"),
                    "severity": a.get("impact"),
                    "title": a.get("title"),
                    "workaround_available": a.get("haveWorkaroud"),
                    "link": a.get("noticeLink"),
                }
                for a in v.get("vulnList") or []
            ],
        }
        for v in get_vulnerable()
    ]
    return {
        "data_status": "ok",
        "vulnerable_device_count": len(devices),
        "devices": devices,
    }


# ------------------------------------------------- fleet posture from cache (A)
#
# Every tool below answers from the SAME cached GET /devices/tenant the core
# tools use — zero new upstream calls. Provenance word for all of them:
# **cached** (NSM's tenant record, <=60 s old), never *live* (a per-device
# read). The docstrings say so, because agent instructions should make the
# caller repeat it.

MAX_POSTURE_DEVICES = 50
EXPIRY_SOON_DAYS = 90


def _today():
    """Server clock as a date. A function, not a constant, so time-relative
    fields (licence expiry windows) can be pinned by a test."""
    return datetime.now(timezone.utc).date()


def _as_date(s: str):
    """licenses3 dates are 'YYYY-MM-DD' strings. Anything else -> None rather
    than an exception: a malformed vendor date must not break an audit."""
    try:
        return datetime.strptime((s or "").strip(), "%Y-%m-%d").date()
    except (ValueError, TypeError):
        return None


def _sec_services(d: dict) -> list:
    return ((d.get("licenses3") or {}).get("data") or {}).get(
        "securityServices") or []


@mcp.tool
@fleet_tool
def license_posture(service: str = "", status: str = "") -> dict:
    """SonicWall licence status across the whole fleet, per security service:
    how many firewalls have each service licensed, expired, disabled or not
    licensed, the soonest expiry date, and how many expire within 90 days.
    coterm_date is the date most active licences share. Optional service
    filters by service code ('IDP', 'NSMADVANCED') or a substring of the
    service name ('DNS filtering'); supplying it also returns the matching
    per-device rows (capped at 50; truncated flags the rest, device_match_count
    reports the full total). Optional status narrows those rows to 'licensed',
    'expired', 'disabled' or 'not licensed'. Data is cached from NSM's tenant
    record (<=60 s old), not a live read of each firewall. An empty services
    list means nothing matched the filter — a real answer, not missing data."""
    devs = get_devices()
    q = service.strip().lower()
    want_status = status.strip().lower()
    today = _today()

    agg: dict[str, dict] = {}
    rows: list[dict] = []
    for d in devs:
        for s in _sec_services(d):
            code = s.get("serviceCode")
            if not code:
                continue
            name = s.get("securityService") or ""
            if q and q not in code.lower() and q not in name.lower():
                continue
            rec = agg.setdefault(code, {
                "code": code, "name": name, "device_count": 0,
                "licensed_count": 0, "expired_count": 0, "disabled_count": 0,
                "not_licensed_count": 0, "devices_expiring_within_90d": 0,
                "_expiries": [],
            })
            st = (s.get("status") or "").lower()
            rec["device_count"] += 1
            key = {"licensed": "licensed_count", "expired": "expired_count",
                   "disabled": "disabled_count",
                   "not licensed": "not_licensed_count"}.get(st)
            if key:
                rec[key] += 1
            exp = _as_date(s.get("expires"))
            if exp:
                rec["_expiries"].append(exp)
                if 0 <= (exp - today).days <= EXPIRY_SOON_DAYS:
                    rec["devices_expiring_within_90d"] += 1
            if q and (not want_status or st == want_status):
                rows.append({
                    "serial": d.get("serialNumber") or "",
                    "name": d.get("friendlyName") or "",
                    "group": d.get("deviceGroupName") or "",
                    "status": s.get("status") or "",
                    "expires": s.get("expires") or "",
                })

    services = []
    for rec in agg.values():
        exps = rec.pop("_expiries")
        rec["soonest_expiry"] = min(exps).isoformat() if exps else ""
        services.append(rec)
    services.sort(key=lambda r: (-r["device_count"], r["code"]))

    coterm = Counter(
        s.get("expires") for d in devs for s in _sec_services(d)
        if (s.get("status") or "").lower() == "licensed" and s.get("expires")
    )
    return {
        "data_status": "ok",
        "total_devices": len(devs),
        "coterm_date": coterm.most_common(1)[0][0] if coterm else "",
        "services": services,
        "device_match_count": len(rows),
        "devices": rows[:MAX_POSTURE_DEVICES],
        "truncated": len(rows) > MAX_POSTURE_DEVICES,
    }


# SonicOS versions are 'MAJOR.MINOR.PATCH-BUILD', optionally prefixed 'SonicOS'.
# The strictness is load-bearing: availableVersions rows of releaseType
# 'Local Firmware' carry a FILENAME here ('local_firmware_270w_eng.7.1.1-7040
# -R5387.bin'), and a loose digit scrape reads that as newer than every real
# version — which would advise three TZ 270Ws to "upgrade" 7.3.2 -> 7.1.1.
_VERSION_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)-(\d+)$")
GENERAL_RELEASE = "General Release"


def _version_tuple(v: str):
    """Comparable tuple, or None when the string is not a real version."""
    m = _VERSION_RE.match((v or "").replace("SonicOS", "").strip())
    return tuple(int(g) for g in m.groups()) if m else None


def _newest_offer(d: dict, release_type: str = ""):
    """(running_tuple, best_offer_row_or_None, ignored_unparseable_count)."""
    running = _version_tuple((d.get("attributes") or {}).get("firmware_version"))
    if running is None:
        return None, None, 0
    best = best_row = None
    ignored = 0
    for a in d.get("availableVersions") or []:
        candidate = _version_tuple(a.get("version"))
        if candidate is None:
            ignored += 1
            continue
        if release_type and a.get("releaseType") != release_type:
            continue
        if candidate > running and (best is None or candidate > best):
            best, best_row = candidate, a
    return running, best_row, ignored


@mcp.tool
@fleet_tool
def firmware_upgrade_availability(release_type: str = "") -> dict:
    """Which firewalls have a newer SonicOS version on offer from SonicWall,
    grouped by the version they run now (by_running_version) and by the move
    they would make (upgrade_paths, biggest group first). upgradable_count
    counts any newer release; newer_general_release_count counts only devices
    with a newer General Release, which is the number that matters when the
    fleet standard is a GR — most offers here are Feature Releases, so the two
    differ sharply. Optional release_type restricts the candidate offers to one
    of 'General Release', 'Feature Release', 'Maintenance Release' or 'Initial
    Release', and returns the matching devices (capped at 50; truncated flags
    the rest). 'Local Firmware' offers are excluded because SonicWall puts a
    filename rather than a version in that row; ignored_local_firmware_offers
    reports how many were skipped. Data is cached from NSM's tenant record
    (<=60 s old), not a live read of each firewall."""
    devs = get_devices()
    want = release_type.strip()

    upgradable = up_to_date = unknown = ignored = general = 0
    by_running: dict[str, dict] = {}
    paths: Counter = Counter()
    rows: list[dict] = []

    for d in devs:
        running, offer, skipped = _newest_offer(d, want)
        ignored += skipped
        if running is None:
            unknown += 1
            continue
        if _newest_offer(d, GENERAL_RELEASE)[1]:
            general += 1
        if offer is None:
            up_to_date += 1
            continue
        upgradable += 1
        run_str = (d.get("attributes") or {}).get("firmware_version") or ""
        rec = by_running.setdefault(run_str, {
            "device_count": 0,
            "newest_available": offer.get("version") or "",
            "release_type": offer.get("releaseType") or "",
        })
        rec["device_count"] += 1
        paths[(run_str, offer.get("version") or "",
               offer.get("releaseType") or "")] += 1
        rows.append({
            "serial": d.get("serialNumber") or "",
            "name": d.get("friendlyName") or "",
            "group": d.get("deviceGroupName") or "",
            "running": run_str,
            "newest_available": offer.get("version") or "",
            "release_type": offer.get("releaseType") or "",
        })

    return {
        "data_status": "ok",
        "total_devices": len(devs),
        "release_type_filter": want,
        "upgradable_count": upgradable,
        "newer_general_release_count": general,
        "up_to_date_count": up_to_date,
        "unknown_version_count": unknown,
        "ignored_local_firmware_offers": ignored,
        "by_running_version": by_running,
        "upgrade_paths": [
            {"from": f, "to": t, "release_type": rt, "device_count": n}
            for (f, t, rt), n in paths.most_common()
        ],
        "device_match_count": len(rows) if want else 0,
        "devices": rows[:MAX_POSTURE_DEVICES] if want else [],
        "truncated": bool(want) and len(rows) > MAX_POSTURE_DEVICES,
    }


def _epoch_iso(seconds) -> str:
    """NSM epoch seconds -> ISO-8601 UTC. Empty string for 0/None/garbage: a
    missing timestamp must read as missing, never as 1970."""
    try:
        s = int(seconds)
    except (TypeError, ValueError):
        return ""
    if s <= 0:
        return ""
    return datetime.fromtimestamp(s, tz=timezone.utc).isoformat()


def _latest_templates(d: dict) -> dict:
    """{template_name: newest application row} for one device.

    appliedTemplates is a HISTORY — every push, with the same template
    appearing repeatedly. Current compliance is the newest row per template, so
    everything downstream reduces here first; counting raw rows would report
    412 'applications' of a template that is really on 154 firewalls.
    """
    latest: dict[str, dict] = {}
    for t in d.get("appliedTemplates") or []:
        name = t.get("name")
        if not name:
            continue
        prev = latest.get(name)
        if prev is None or (t.get("time") or 0) >= (prev.get("time") or 0):
            latest[name] = t
    return latest


@mcp.tool
@fleet_tool
def template_compliance(template: str = "") -> dict:
    """Which NSM configuration templates are applied to which firewalls, and
    where the push FAILED. Per template: applied_device_count,
    failed_device_count, the versions seen and when it was last applied.
    Templates are listed worst-first (most failures). Counts reflect the most
    recent application per firewall — appliedTemplates is a history of every
    push, so raw rows would over-count. devices_without_templates lists
    firewalls carrying no template at all. Optional template filters by name
    substring and returns the matching per-device rows, failures first (capped
    at 50; truncated flags the rest). Data is cached from NSM's tenant record
    (<=60 s old), not a live read of each firewall."""
    devs = get_devices()
    q = template.strip().lower()

    agg: dict[str, dict] = {}
    rows: list[dict] = []
    without: list[dict] = []

    for d in devs:
        latest = _latest_templates(d)
        if not latest:
            without.append(_dev_ident(d))
            continue
        for name, t in latest.items():
            if q and q not in name.lower():
                continue
            rec = agg.setdefault(name, {
                "name": name, "applied_device_count": 0,
                "failed_device_count": 0, "versions_seen": set(),
                "_last": 0,
            })
            rec["applied_device_count"] += 1
            if t.get("success") is False:
                rec["failed_device_count"] += 1
            if t.get("version") is not None:
                rec["versions_seen"].add(t["version"])
            rec["_last"] = max(rec["_last"], t.get("time") or 0)
            if q:
                rows.append({
                    "serial": d.get("serialNumber") or "",
                    "name": d.get("friendlyName") or "",
                    "group": d.get("deviceGroupName") or "",
                    "template": name,
                    "version": t.get("version"),
                    "applied": _epoch_iso(t.get("time")),
                    "success": t.get("success"),
                })

    templates = []
    for rec in agg.values():
        rec["versions_seen"] = sorted(rec.pop("versions_seen"),
                                      key=lambda v: (v is None, v))
        rec["last_applied"] = _epoch_iso(rec.pop("_last"))
        templates.append(rec)
    # Worst first: the agent reads the top of the list, so broken pushes go there.
    templates.sort(key=lambda r: (-r["failed_device_count"],
                                  -r["applied_device_count"], r["name"]))
    rows.sort(key=lambda r: (r["success"] is not False, r["name"]))

    return {
        "data_status": "ok",
        "total_devices": len(devs),
        "template_count": len(templates),
        "templates": templates,
        "devices_without_templates_count": len(without),
        "devices_without_templates": without[:MAX_POSTURE_DEVICES],
        "device_match_count": len(rows),
        "devices": rows[:MAX_POSTURE_DEVICES],
        "truncated": len(rows) > MAX_POSTURE_DEVICES,
    }


# Consecutive auto-sync failures above this are a broken device, not a blip.
CHRONIC_SYNC_FAILURES = 10

# NSM's reason strings embed serials, site names and request GUIDs, so a
# literal histogram is all-ones and tells nobody anything. These keyword
# buckets are what an engineer actually acts on; the literal string is kept
# per device alongside, never replaced by the bucket.
_FAILURE_CATEGORIES = (
    ("not reachable", "unreachable"),
    ("already in progress", "acquisition_in_progress"),
    ("failed to sync config", "sync_failed"),
    ("skip sync", "zero_touch_secondary"),
    ("operations failed", "commit_operations_failed"),
)


def _failure_category(reason: str) -> str:
    r = (reason or "").lower()
    for needle, label in _FAILURE_CATEGORIES:
        if needle in r:
            return label
    return "other"


@mcp.tool
@fleet_tool
def deploy_failures(category: str = "") -> dict:
    """Why NSM could not deploy to or synchronise a firewall — the reason
    behind drift_summary's counts. Covers three sources: the last commit
    deploy that reported Failed (last_commit_deploy), auto-sync errors
    (auto_sync, with check_fail_times = consecutive failures, so a chronically
    broken device is distinguishable from a one-off), and devices NSM has not
    fully acquired (acquisition). Each row carries NSM's literal reason string
    plus a category: unreachable, acquisition_in_progress, sync_failed,
    zero_touch_secondary, commit_operations_failed or other. Rows come back
    worst-first by consecutive failures. Optional category filters to one of
    those labels. devices_affected_count counts distinct firewalls, since one
    device can fail in more than one way. Zero failures with data_status ok
    means the fleet is clean — a real answer, not missing data. Data is cached
    from NSM's tenant record (<=60 s old), not a live read of each firewall."""
    devs = get_devices()
    want = category.strip().lower()

    rows: list[dict] = []
    deploy_failed = sync_errors = not_acquired = chronic = 0

    for d in devs:
        ident = _project(d)
        base = {"serial": ident["serial"], "name": ident["name"],
                "group": ident["group"], "online": ident["online"]}
        fails = (d.get("autoSync") or {}).get("checkFailTimes") or 0

        if d.get("lastCommitDeployedStatusMessage") == "Failed":
            deploy_failed += 1
            reason = d.get("lastCommitDeployedErrorReason") or ""
            rows.append({**base, "source": "last_commit_deploy",
                         "category": _failure_category(reason),
                         "reason": reason, "check_fail_times": 0})

        sync_reason = (d.get("autoSync") or {}).get("lastErrorReason") or ""
        is_chronic = fails > CHRONIC_SYNC_FAILURES
        if sync_reason:
            sync_errors += 1
        if is_chronic:
            chronic += 1
        # A reason OR a chronic counter is enough to report. Both matter: a
        # device can carry checkFailTimes in the thousands with an EMPTY
        # reason, so a purely reason-driven report would show it as healthy.
        # Reporting only what came with an explanation is how silent failures
        # stay silent.
        if sync_reason or is_chronic:
            rows.append({**base, "source": "auto_sync",
                         "category": (_failure_category(sync_reason)
                                      if sync_reason else "no_reason_recorded"),
                         "reason": sync_reason, "check_fail_times": fails})

        if d.get("acquireStatus") != 3:
            not_acquired += 1
            rows.append({**base, "source": "acquisition",
                         "category": "acquisition_incomplete",
                         "reason": f"acquireStatus={d.get('acquireStatus')}",
                         "check_fail_times": fails})

    if want:
        rows = [r for r in rows if r["category"] == want]

    # Worst first: the device with the most consecutive failures leads.
    rows.sort(key=lambda r: (-r["check_fail_times"], r["serial"]))
    categories = Counter(
        r["category"] for r in rows if r["source"] != "acquisition"
    )
    return {
        "data_status": "ok",
        "total_devices": len(devs),
        "devices_affected_count": len({r["serial"] for r in rows}),
        "last_deploy_failed_count": deploy_failed,
        "auto_sync_error_count": sync_errors,
        "acquisition_incomplete_count": not_acquired,
        "chronic_sync_failure_count": chronic,
        "chronic_threshold": CHRONIC_SYNC_FAILURES,
        "categories": dict(categories.most_common()),
        "device_match_count": len(rows),
        "devices": rows[:MAX_POSTURE_DEVICES],
        "truncated": len(rows) > MAX_POSTURE_DEVICES,
    }


def _ha_member(d: dict, serial: str) -> dict:
    """One side of a pair. A partner serial is normally its own NSM device, so
    resolve it to the real record; known_to_nsm False when it is not."""
    if d is None:
        return {"serial": serial, "name": "", "online": None, "firmware": "",
                "known_to_nsm": False}
    return {
        "serial": d.get("serialNumber") or serial,
        "name": d.get("friendlyName") or "",
        "online": bool(d.get("liveStatus")),
        "firmware": (d.get("attributes") or {}).get("firmware_version") or "",
        "known_to_nsm": True,
    }


@mcp.tool
@fleet_tool
def ha_pairs() -> dict:
    """Every high-availability pair in the fleet, with both members resolved to
    their NSM records, which unit NSM considers active, and what is wrong with
    the pair. findings per pair may contain: running_on_secondary (the active
    unit is the backup — the site has failed over), member_offline,
    firmware_mismatch (members on different SonicOS versions will not fail over
    cleanly) and firmware_unknown (a member's version could not be read, which
    is reported as unknown, never as a match). healthy is true only when a pair
    has no findings. Pairs are built from each primary's secondarySerialNumber:
    the partner unit is separately registered in NSM too, so counting devices
    with an HA mode flag would double-count. Data is cached from NSM's tenant
    record (<=60 s old), not a live read — for live HA role and sync state see
    the per-device HA status tool."""
    devs = get_devices()
    by_serial = {d.get("serialNumber"): d for d in devs}

    pairs = []
    for d in devs:
        ha = d.get("highAvailability") or {}
        secondary_serial = ha.get("secondarySerialNumber") or ""
        # Partner registrations point at themselves; only a primary anchors a
        # pair. Without this the six mode-1 devices become six "pairs".
        if not ha.get("mode") or not secondary_serial:
            continue
        if secondary_serial == d.get("serialNumber"):
            continue

        primary = _ha_member(d, d.get("serialNumber") or "")
        secondary = _ha_member(by_serial.get(secondary_serial),
                               secondary_serial)
        active = ha.get("activeSerialNumber") or ""
        if active == primary["serial"]:
            active_side = "primary"
        elif active == secondary["serial"]:
            active_side = "secondary"
        else:
            active_side = "unknown"

        findings = []
        if active_side == "secondary":
            findings.append("running_on_secondary")
        elif active_side == "unknown":
            findings.append("active_unit_unknown")
        if primary["online"] is False or secondary["online"] is False:
            findings.append("member_offline")
        if not primary["firmware"] or not secondary["firmware"]:
            firmware_match = None
            findings.append("firmware_unknown")
        elif primary["firmware"] != secondary["firmware"]:
            firmware_match = False
            findings.append("firmware_mismatch")
        else:
            firmware_match = True

        pairs.append({
            "primary": primary,
            "secondary": secondary,
            "active_serial": active,
            "active_side": active_side,
            "both_online": bool(primary["online"]) and bool(secondary["online"]),
            "firmware_match": firmware_match,
            "findings": findings,
            "healthy": not findings,
        })

    pairs.sort(key=lambda p: (p["healthy"], -len(p["findings"]),
                              p["primary"]["name"]))
    members = {p["primary"]["serial"] for p in pairs}
    members |= {p["secondary"]["serial"] for p in pairs}
    healthy = sum(1 for p in pairs if p["healthy"])
    return {
        "data_status": "ok",
        "total_devices": len(devs),
        "pair_count": len(pairs),
        "healthy_pair_count": healthy,
        "degraded_pair_count": len(pairs) - healthy,
        "devices_in_ha_count": len(members),
        "pairs": pairs,
    }


MAX_LOCATION_DEVICES = 200


@mcp.tool
@fleet_tool
def sites_by_location(region: str = "", city: str = "",
                      country: str = "") -> dict:
    """Where the firewalls physically are: device counts per region (US state),
    largest first, plus the matching devices with city, region, country and
    latitude/longitude so the answer can be plotted on a map. Optional region,
    city and country filters are case-insensitive exact matches and combine
    (country accepts either the two-letter code or the full name).
    unknown_location_count reports firewalls with no region recorded — they are
    counted separately rather than dropped, so the region totals plus the
    unknowns always add up to the fleet. Data is cached from NSM's tenant
    record (<=60 s old); locations come from NSM's geolocation of the device's
    public IP unless someone set them manually."""
    devs = get_devices()
    rq, cq, nq = (region.strip().lower(), city.strip().lower(),
                  country.strip().lower())

    counts: Counter = Counter()
    unknown = 0
    rows: list[dict] = []
    for d in devs:
        loc = d.get("location") or {}
        r = loc.get("region") or ""
        if r:
            counts[r] += 1
        else:
            unknown += 1
        if rq and r.lower() != rq:
            continue
        if cq and (loc.get("city") or "").lower() != cq:
            continue
        if nq and nq not in ((loc.get("countryCode") or "").lower(),
                             (loc.get("countryName") or "").lower()):
            continue
        ident = _project(d)
        rows.append({
            "serial": ident["serial"], "name": ident["name"],
            "group": ident["group"], "online": ident["online"],
            "city": loc.get("city") or "", "region": r,
            "country": loc.get("countryCode") or "",
            "latitude": loc.get("latitude"), "longitude": loc.get("longitude"),
        })

    filtered = bool(rq or cq or nq)
    return {
        "data_status": "ok",
        "total_devices": len(devs),
        "unknown_location_count": unknown,
        "regions": [{"region": r, "device_count": n}
                    for r, n in counts.most_common()],
        "device_match_count": len(rows),
        "devices": rows[:MAX_LOCATION_DEVICES] if filtered else [],
        "truncated": filtered and len(rows) > MAX_LOCATION_DEVICES,
    }


UNGROUPED = "(ungrouped)"


def _has_expired_license(d: dict) -> bool:
    return any((s.get("status") or "").lower() == "expired"
               for s in _sec_services(d))


@mcp.tool
@fleet_tool
def fleet_by_group() -> dict:
    """Fleet posture rolled up per NSM device group:
    per group the device count, online/offline, config-modified,
    unsynchronised, vulnerable-firmware and expired-licence counts, and the
    hardware models present. Groups are listed largest first. Firewalls with no
    group are collected under '(ungrouped)' rather than dropped, so the group
    counts always sum to the fleet total. Data is cached from NSM's tenant
    record (<=60 s old), not a live read of each firewall."""
    devs = get_devices()
    groups: dict[str, dict] = {}
    for d in devs:
        name = d.get("deviceGroupName") or UNGROUPED
        g = groups.setdefault(name, {
            "name": name, "device_count": 0, "online_count": 0,
            "offline_count": 0, "config_modified_count": 0,
            "unsynchronized_count": 0, "vulnerable_count": 0,
            "expired_license_count": 0, "_models": set(),
        })
        g["device_count"] += 1
        if d.get("liveStatus"):
            g["online_count"] += 1
        else:
            g["offline_count"] += 1
        if d.get("configModified"):
            g["config_modified_count"] += 1
        if d.get("synchronized") is False:
            g["unsynchronized_count"] += 1
        if (d.get("vulnerability") or {}).get("isFirmwareVulnerable"):
            g["vulnerable_count"] += 1
        if _has_expired_license(d):
            g["expired_license_count"] += 1
        model = (d.get("attributes") or {}).get("model")
        if model:
            g["_models"].add(model)

    out = []
    for g in groups.values():
        g["models"] = sorted(g.pop("_models"))
        out.append(g)
    out.sort(key=lambda g: (-g["device_count"], g["name"]))
    return {
        "data_status": "ok",
        "total_devices": len(devs),
        "group_count": len(out),
        "groups": out,
    }


NSM_SYNC_NOTE = (
    "Flags reflect NSM's tenant record as of its last sync with each firewall, "
    "not a live read of the device."
)

# (flag, description, reader) — reader returns True (affected), False (ok) or
# None (unknown). Three states, never two: a device NSM has no value for must
# not be counted as healthy.
#
# Deliberately absent: attributes.up_time / current_connections. attributes.*
# looks like an acquisition-time snapshot (an HA unit was observed reporting a
# system_time equal to its CreatedTime, years stale), so exposing them here
# would present stale numbers as live. Use site_live_status for those.
_HEALTH_FLAGS = (
    ("atp_disabled",
     "Capture ATP is off in NSM's record",
     lambda d: None if d.get("ATPStatus") is None else d["ATPStatus"] is False),
    ("remote_access_disabled",
     "Remote access (RAStatus) is disabled",
     lambda d: None if d.get("RAStatus") is None else d["RAStatus"] == 0),
    ("zero_touch_not_ready",
     "Zero-touch status is not the ready state (3)",
     lambda d: None if d.get("zeroTouchStatus") is None
     else d["zeroTouchStatus"] != 3),
    ("analytics_disabled",
     "Analytics/flow reporting is disabled, so collected-data tools cannot "
     "answer for this device",
     lambda d: None if (d.get("analytics") or {}).get("enabled") is None
     else (d.get("analytics") or {}).get("enabled") is False),
    ("restart_required",
     "The firewall is waiting for a restart",
     lambda d: None if (d.get("attributes") or {}).get("restart_required") is None
     else (d.get("attributes") or {}).get("restart_required") is True),
)


def _flag_value(d: dict, flag: str):
    for name, _desc, reader in _HEALTH_FLAGS:
        if name == flag:
            return reader(d)
    return None


@mcp.tool
@fleet_tool
def device_health_flags(flag: str = "") -> dict:
    """Posture flags NSM maintains per firewall: atp_disabled (Capture ATP
    off), remote_access_disabled, zero_touch_not_ready, analytics_disabled
    (which also tells you why an analytics-backed answer is empty for a device)
    and restart_required. Each flag reports affected_count, ok_count and
    unknown_count — a firewall NSM holds no value for is counted as unknown,
    never as healthy. Optional flag returns the affected devices for one flag
    by name. These are CACHED values from NSM's tenant record as of its last
    sync with the device, not a live read; uptime and connection counts are
    deliberately not reported here because that part of the record is an
    acquisition-time snapshot on this tenant — use the per-device live status
    tool for those."""
    devs = get_devices()
    want = flag.strip().lower()

    flags = []
    rows: list[dict] = []
    for name, desc, reader in _HEALTH_FLAGS:
        if want and name != want:
            continue
        affected = ok = unknown = 0
        for d in devs:
            v = reader(d)
            if v is None:
                unknown += 1
            elif v:
                affected += 1
                if want:
                    ident = _project(d)
                    rows.append({
                        "serial": ident["serial"], "name": ident["name"],
                        "group": ident["group"], "online": ident["online"],
                        "flag": name, "value": True,
                    })
            else:
                ok += 1
        flags.append({"flag": name, "description": desc,
                      "affected_count": affected, "ok_count": ok,
                      "unknown_count": unknown})

    flags.sort(key=lambda f: -f["affected_count"])
    return {
        "data_status": "ok",
        "total_devices": len(devs),
        "as_of_note": NSM_SYNC_NOTE,
        "flags": flags,
        "device_match_count": len(rows),
        "devices": rows[:MAX_POSTURE_DEVICES],
        "truncated": len(rows) > MAX_POSTURE_DEVICES,
    }


def _unwrap(payload: dict, key: str, default=0):
    """Read a counter out of another tool's envelope. The fleet_tool wrapper
    turns an upstream failure into {'data_status': 'unavailable'}, so a missing
    key here means that tool could not answer — the summary must not silently
    print 0 in its place, and its own envelope re-raises instead."""
    if payload.get("data_status") != "ok":
        raise RuntimeError(f"{key} unavailable: {payload.get('detail', '')}")
    return payload.get(key, default)


@mcp.tool
@fleet_tool
def fleet_summary() -> dict:
    """One-screen fleet posture card: totals, online/offline, HA pairs and how
    many are degraded, config drift, vulnerable firmware, licence expiry,
    upgrade availability, deploy failures, and the top models, firmware
    versions and offline reasons. Every headline number is produced by calling
    the tool that owns it, and the sources map names that tool per field, so
    any number can be expanded by a follow-up call — ask fleet_summary 'how are
    we doing', then the named tool for 'which ones'. Data is cached from NSM's
    tenant record (<=60 s old), not a live read of each firewall."""
    devs = get_devices()

    # Compose by CALLING the other tools, not by re-deriving their logic: a
    # second implementation of the same counter is a second thing to drift.
    fw = firmware_upgrade_availability()
    ha = ha_pairs()
    deploy = deploy_failures()
    tmpl = template_compliance()
    groups = fleet_by_group()
    drift = drift_summary()
    lic = license_posture()

    models = Counter((d.get("attributes") or {}).get("model") or ""
                     for d in devs)
    versions = Counter((d.get("attributes") or {}).get("firmware_version") or ""
                       for d in devs)
    reasons = Counter(
        d.get("liveStatusLastDownReason") or "(no reason recorded)"
        for d in devs if not d.get("liveStatus")
    )
    expired_devices = sum(1 for d in devs if _has_expired_license(d))

    return {
        "data_status": "ok",
        "as_of_note": NSM_SYNC_NOTE,
        "total_devices": len(devs),
        "online": sum(1 for d in devs if d.get("liveStatus")),
        "offline": sum(1 for d in devs if not d.get("liveStatus")),
        "device_groups": _unwrap(groups, "group_count"),
        "ha_pairs": _unwrap(ha, "pair_count"),
        "ha_pairs_degraded": _unwrap(ha, "degraded_pair_count"),
        "config_modified": _unwrap(drift, "config_modified_count"),
        "unsynchronized": _unwrap(drift, "unsynchronized_count"),
        "vulnerable": sum(
            1 for d in get_vulnerable() if d.get("serialNumber")),
        "devices_with_expired_license": expired_devices,
        "licence_coterm_date": _unwrap(lic, "coterm_date", ""),
        "upgradable": _unwrap(fw, "upgradable_count"),
        "newer_general_release": _unwrap(fw, "newer_general_release_count"),
        "scheduled_upgrades": sum(1 for d in devs if d.get("scheduledUpgrade")),
        "deploy_failures_affected": _unwrap(deploy, "devices_affected_count"),
        "chronic_sync_failures": _unwrap(deploy, "chronic_sync_failure_count"),
        "devices_without_templates": _unwrap(
            tmpl, "devices_without_templates_count"),
        "top_models": [{"model": m, "device_count": n}
                       for m, n in models.most_common(3) if m],
        "top_firmware_versions": [{"version": v, "device_count": n}
                                  for v, n in versions.most_common(3) if v],
        "top_offline_reasons": [{"reason": r, "device_count": n}
                                for r, n in reasons.most_common(3)],
        "sources": {
            "offline": "offline_devices",
            "device_groups": "fleet_by_group",
            "ha_pairs": "ha_pairs",
            "ha_pairs_degraded": "ha_pairs",
            "config_modified": "drift_summary",
            "unsynchronized": "drift_summary",
            "vulnerable": "vulnerability_report",
            "devices_with_expired_license": "license_posture",
            "licence_coterm_date": "license_posture",
            "upgradable": "firmware_upgrade_availability",
            "newer_general_release": "firmware_upgrade_availability",
            "deploy_failures_affected": "deploy_failures",
            "chronic_sync_failures": "deploy_failures",
            "devices_without_templates": "template_compliance",
            "top_models": "list_devices",
            "top_firmware_versions": "firmware_report",
            "top_offline_reasons": "offline_devices",
        },
    }


# -------------------------------------------------------------------- sweep
#
# Fleet-wide questions ("how many firewalls still run the default LAN subnet")
# need one GET per device — hundreds of calls on a large fleet, far past a
# 30 s chat budget. A daemon
# thread does them in the background and tools read the finished snapshot.
# Started ONLY in __main__: importing this module must never touch the network,
# which is what keeps the whole test suite offline.

SWEEP_ENABLED = os.environ.get("SWEEP_ENABLED", "1") == "1"
SWEEP_INTERVAL_SECONDS = int(os.environ.get("SWEEP_INTERVAL_SECONDS", "1800"))
SWEEP_CALL_DELAY_SECONDS = float(os.environ.get("SWEEP_CALL_DELAY_SECONDS", "0.2"))
# +1 GET per device per cycle is the documented
# cost of find_host: static-IP devices — cameras, printers, servers — are
# in ARP and never in a DHCP lease table, so a fleet search over DHCP
# alone would answer "not found" for hosts that are really there.
SWEEP_KEYS = ["interfaces", "dhcp", "arp"]

_sweep_lock = threading.Lock()
_sweep: dict = {"as_of": None, "started": None,
                "progress": {"done": 0, "total": 0}, "results": {}}


def reset_sweep() -> None:
    with _sweep_lock:
        _sweep.update(as_of=None, started=None,
                      progress={"done": 0, "total": 0}, results={})


def sweep_snapshot() -> dict:
    with _sweep_lock:
        return {"as_of": _sweep["as_of"], "started": _sweep["started"],
                "progress": dict(_sweep["progress"]), "results": _sweep["results"]}


def _sweep_unavailable() -> dict:
    p = sweep_snapshot()["progress"]
    return {
        "data_status": "unavailable",
        "detail": (f"fleet sweep not complete yet ({p['done']}/{p['total']} devices "
                   f"checked); this answer needs the sweep — try again in a few "
                   f"minutes."),
    }


def run_sweep_once() -> dict:
    """Sequential per-device GETs for every ONLINE device; offline devices are
    recorded as unavailable without a call. Publishes an atomic snapshot: a
    reader mid-sweep sees the previous complete one, never a partial."""
    started = datetime.now(timezone.utc).isoformat()
    devs = get_devices()
    results: dict = {}
    with _sweep_lock:
        _sweep["started"] = started
        _sweep["progress"] = {"done": 0, "total": len(devs)}
    for i, d in enumerate(devs, 1):
        serial = d.get("serialNumber") or ""
        rec = {"name": d.get("friendlyName") or "",
               "online": bool(d.get("liveStatus")), "ok": False, "error": ""}
        if not rec["online"]:
            rec["error"] = "offline in NSM"
        else:
            errors = []
            for key in SWEEP_KEYS:
                try:
                    rec[key] = _upstream_device_json(DEVICE_PATHS[key], serial)
                except Exception as exc:  # noqa: BLE001 — one bad key must not
                    rec[key] = None       # discard the keys that did work
                    errors.append(f"{key}: {type(exc).__name__}: {exc}")
            # "ok" means the interface config was read; that is what every
            # sweep-backed bucket is built from.
            rec["ok"] = rec.get("interfaces") is not None
            rec["error"] = "; ".join(errors)
            if SWEEP_CALL_DELAY_SECONDS:
                time.sleep(SWEEP_CALL_DELAY_SECONDS)
        results[serial] = rec
        with _sweep_lock:
            _sweep["progress"] = {"done": i, "total": len(devs)}
    with _sweep_lock:
        _sweep["as_of"] = datetime.now(timezone.utc).isoformat()
        _sweep["results"] = results
    print(json.dumps({"ts": _sweep["as_of"], "app": APP_NAME,
                      "event": "sweep_complete", "devices": len(results),
                      "ok": sum(1 for r in results.values() if r["ok"])}), flush=True)
    return sweep_snapshot()


def _sweep_loop() -> None:
    while True:
        try:
            run_sweep_once()
        except Exception as exc:  # noqa: BLE001 — the loop must outlive a bad run
            print(json.dumps({"ts": datetime.now(timezone.utc).isoformat(),
                              "app": APP_NAME, "event": "sweep_failed",
                              "detail": f"{type(exc).__name__}: {exc}"}), flush=True)
        time.sleep(SWEEP_INTERVAL_SECONDS)


def start_sweep_thread() -> None:
    threading.Thread(target=_sweep_loop, name="nsm-sweep", daemon=True).start()


# ------------------------------------------------------------ per-site tools

@mcp.tool
@fleet_tool
def site_status(site: str) -> dict:
    """Is a site up? Pass a site name fragment (e.g. 'Springfield') or a
    serial. Returns every firewall whose name matches, each with online state,
    HA role, the last reason NSM recorded for going down and when the state
    last changed, plus a one-word verdict: all_online (every matching firewall
    is online), degraded (some online, some offline — typically an HA peer),
    down (every matching firewall is offline), unknown_site (nothing matched —
    a real answer, check the spelling). This reflects NSM's management
    connection to the firewall, not end-user connectivity."""
    matches = _resolve(site)
    rows = []
    for d in matches:
        a = d.get("attributes") or {}
        ha = d.get("highAvailability") or {}
        rows.append({
            "serial": d.get("serialNumber") or "",
            "name": d.get("friendlyName") or "",
            "model": a.get("model") or "",
            "online": bool(d.get("liveStatus")),
            "ha_role": ha.get("role") if isinstance(ha, dict) else ha,
            "last_down_reason": d.get("liveStatusLastDownReason"),
            "last_changed_time": d.get("liveStatusLastChangedTime"),
        })
    online = sum(1 for r in rows if r["online"])
    if not rows:
        verdict = "unknown_site"
    elif online == len(rows):
        verdict = "all_online"
    elif online == 0:
        verdict = "down"
    else:
        verdict = "degraded"
    return {
        "data_status": "ok",
        "site": site,
        "match_count": len(rows),
        "online_count": online,
        "offline_count": len(rows) - online,
        "verdict": verdict,
        "site_devices": rows[:MAX_LIST_DEVICES],
    }


@mcp.tool
@fleet_tool
def site_interfaces(site_or_serial: str) -> dict:
    """Interface configuration of ONE firewall: every interface's name, zone,
    IP assignment mode (static/dhcp/pppoe/...), IP, netmask, gateway, VLAN,
    comment and whether the port is shut down; a zones map (zone -> member
    interfaces, i.e. which VLANs/zones exist at the site); and a LAN summary
    (X0 or first LAN-zone interface, its CIDR, and is_default = true when it is
    still on SonicWall's factory subnet). Pass an exact serial or a unique
    site-name fragment; if several firewalls match you get candidates back —
    call again with the serial. data_status 'unavailable' means NSM could not
    reach that firewall's configuration."""
    dev, early = _one_device(site_or_serial)
    if early:
        return early
    rows = _iface_rows(_device_json("interfaces", dev["serialNumber"]))
    zones: dict = {}
    for r in rows:
        if r["zone"]:
            zones.setdefault(r["zone"], []).append(r["name"])
    return {
        "data_status": "ok",
        "match_count": 1,
        "device": _dev_ident(dev),
        "interface_count": len(rows),
        "interfaces": rows,
        "zones": zones,
        "lan": _lan_summary(rows),
    }


def _lb_roles(payload: dict) -> dict:
    roles = {}
    for g in (payload.get("failover_lb") or {}).get("group") or []:
        for m in g.get("interface") or []:
            rank = m.get("rank")
            roles[m.get("name")] = ("Primary" if rank == 1
                                    else "Secondary" if rank == 2
                                    else f"Failover rank {rank}")
    return roles


@mcp.tool
@fleet_tool
def site_wan_status(site_or_serial: str) -> dict:
    """WAN links of ONE firewall: each WAN-zone interface (USB modem ports
    excluded) with its IP, netmask, gateway, assignment mode and failover role
    (Primary / Secondary / Failover rank N / Standalone) from the failover &
    load-balancing groups. failover_status 'unavailable' means the interface
    list is real but roles could not be read — say so rather than guessing.
    Pass a serial or a unique site-name fragment."""
    dev, early = _one_device(site_or_serial)
    if early:
        return early
    serial = dev["serialNumber"]
    rows = _iface_rows(_device_json("interfaces", serial))
    wan = [r for r in rows
           if "WAN" in r["zone"].upper() and not r["name"].upper().startswith("U")]
    try:
        roles = _lb_roles(_device_json("failover", serial))
        fo_status, fo_detail = "ok", ""
    except Exception as exc:  # noqa: BLE001 — partial answer, explicitly labelled
        roles, fo_status, fo_detail = None, "unavailable", f"{type(exc).__name__}: {exc}"
    out = []
    for r in wan:
        role = ("unknown (failover data unavailable)" if roles is None
                else roles.get(r["name"], "Standalone / Unassigned"))
        out.append({"interface": r["name"], "ip": r["ip"], "netmask": r["netmask"],
                    "gateway": r["gateway"], "mode": r["mode"], "role": role,
                    "shutdown": r["shutdown"]})
    return {
        "data_status": "ok", "match_count": 1, "device": _dev_ident(dev),
        "wan_count": len(out), "wan_interfaces": out,
        "failover_status": fo_status, "failover_detail": fo_detail,
    }


@mcp.tool
@fleet_tool
def site_vpn_tunnels(site_or_serial: str) -> dict:
    """Site-to-site VPN policies configured on ONE firewall: name, enabled,
    primary/secondary gateway, local and remote network object names, the
    authentication METHOD name (never the key itself) and keep-alive. This is
    configuration, not live tunnel state. tunnel_count 0 is a real answer.
    Pass a serial or a unique site-name fragment."""
    dev, early = _one_device(site_or_serial)
    if early:
        return early
    policies = ((_device_json("vpn", dev["serialNumber"]).get("vpn") or {})
                .get("policy")) or []
    tunnels = []
    for p in policies:
        s2s = (p.get("ipv4") or {}).get("site_to_site") or {}
        gw = s2s.get("gateway") or {}
        net = s2s.get("network") or {}
        auth = s2s.get("auth_method") or {}
        tunnels.append({
            "name": s2s.get("name") or "",
            "enabled": bool(s2s.get("enable")),
            "gateway_primary": gw.get("primary") or "",
            "gateway_secondary": gw.get("secondary") or "",
            "local_network": _name_of(net.get("local")),
            "remote_network": _name_of(net.get("remote")),
            # The METHOD NAME only. The value under it is an encrypted PSK and
            # must never leave this process.
            "auth_method": next(iter(auth), "") if isinstance(auth, dict) else "",
            "keep_alive": bool(s2s.get("keep_alive")),
        })
    return {
        "data_status": "ok", "match_count": 1, "device": _dev_ident(dev),
        "tunnel_count": len(tunnels),
        "enabled_count": sum(1 for t in tunnels if t["enabled"]),
        "tunnels": tunnels[:MAX_DRIFT_LIST],
        "truncated": len(tunnels) > MAX_DRIFT_LIST,
    }


@mcp.tool
@fleet_tool
def site_nat_policies(site_or_serial: str, search: str = "") -> dict:
    """NAT policies configured on ONE firewall, projected to name, enabled,
    comment, inbound/outbound interfaces, original source/destination/service
    object names, translated source/destination/service and NAT method.
    search is an optional case-insensitive substring matched against every
    field (use it for 'is there a NAT for 10.5.0.20' or 'for the camera
    server'). policy_count is the total after filtering; the list is capped at
    50 (truncated=true) — narrow with search. Pass a serial or a unique
    site-name fragment."""
    dev, early = _one_device(site_or_serial)
    if early:
        return early
    raw = _device_json("nat", dev["serialNumber"]).get("nat_policies") or []
    rows = []
    for p in raw:
        v4 = p.get("ipv4") or {}
        rows.append({
            "name": v4.get("name") or "",
            "enabled": bool(v4.get("enable")),
            "comment": v4.get("comment") or "",
            "inbound": v4.get("inbound") or "",
            "outbound": v4.get("outbound") or "",
            "source": _name_of(v4.get("source")),
            "destination": _name_of(v4.get("destination")),
            "service": _name_of(v4.get("service")),
            "translated_source": _name_of(v4.get("translated_source")),
            "translated_destination": _name_of(v4.get("translated_destination")),
            "translated_service": _name_of(v4.get("translated_service")),
            # Swagger-documented but observed absent on SonicOS 7; kept
            # because other firmware populates it.
            "nat_method": v4.get("nat_method") or "",
        })
    if search:
        q = search.lower()
        rows = [r for r in rows if q in " ".join(str(v) for v in r.values()).lower()]
    return {
        "data_status": "ok", "match_count": 1, "device": _dev_ident(dev),
        "policy_count": len(rows), "policies": rows[:MAX_DRIFT_LIST],
        "truncated": len(rows) > MAX_DRIFT_LIST,
    }


def _host_rows(payload) -> list:
    """DHCP leases and ARP entries share enough fields for one projection.
    `hostname` is the live DHCP key; `host_name` is the swagger's — read both,
    or every hostname silently becomes "" on one of the two firmwares."""
    rows = []
    for h in _first_list(payload):
        rows.append({
            "ip": h.get("ip_address") or "",
            "mac": h.get("mac_address") or "",
            "hostname": h.get("hostname") or h.get("host_name") or "",
            "vendor": h.get("vendor") or "",
            "type": h.get("type") or "",
            "interface": h.get("interface") or "",
            "expires": h.get("lease_expires") or h.get("timeout") or "",
        })
    return rows


@mcp.tool
@fleet_tool
def site_connected_hosts(site_or_serial: str, source: str = "dhcp") -> dict:
    """Devices currently connected behind ONE firewall. source 'dhcp' (default)
    reads the firewall's DHCP lease table (hostname, IP, MAC, vendor, lease
    expiry) — devices with static IPs are NOT in it; source 'arp' reads the
    ARP cache (every IP the firewall has talked to recently, with vendor from
    the MAC) — broader but no hostnames. host_count is the total;
    vendor_counts (top 25) is the quickest way to see what KINDS of devices are
    there (cameras, printers, phones). The list caps at 100 hosts. Pass a
    serial or a unique site-name fragment."""
    if source not in ("dhcp", "arp"):
        return {"data_status": "ok", "host_count": 0, "hosts": [],
                "vendor_counts": {}, "source": source,
                "detail": "source must be 'dhcp' or 'arp'"}
    dev, early = _one_device(site_or_serial)
    if early:
        return early
    rows = _host_rows(_device_json(source, dev["serialNumber"]))
    vendors = Counter((r["vendor"] or "unknown") for r in rows)
    return {
        "data_status": "ok", "match_count": 1, "device": _dev_ident(dev),
        "source": source, "host_count": len(rows),
        "vendor_counts": dict(vendors.most_common(25)),
        "hosts": rows[:MAX_HOSTS], "truncated": len(rows) > MAX_HOSTS,
    }


# --------------------------------------------------- per-site LIVE status
#
# These READ THE FIREWALL, unlike everything derived from get_devices().
# Provenance word: **live**.


def _clean(v):
    """SonicOS pads status strings with trailing spaces ('Active  ',
    'Logical   - All targets must reply          '). Strip on the way out so an
    agent does not quote ragged text."""
    return v.strip() if isinstance(v, str) else v


def _is_lte(name: str) -> bool:
    """U0/U1 are the USB/LTE modem ports."""
    return name.upper().startswith("U")


# reporting/status/system returns these alongside the useful fields. They are
# account-takeover material (they re-register the appliance on MySonicWall) and
# are never projected. The tool builds its answer from an allow-list rather
# than deleting from the payload, so a new secret field added by a firmware
# update cannot leak by default.
LIVE_STATUS_FIELDS = (
    "model", "product_code", "firewall_name", "firmware_version",
    "rom_version", "system_time", "up_time", "primary_wan",
    "peak_connections", "current_connections", "max_allowed_connections",
    "max_connections", "connection_usage", "last_modified_by",
    "restart_required",
)
LIVE_STATUS_NEVER = ("authentication_code", "registration_code",
                     "assign_token", "guid")


@mcp.tool
@fleet_tool
def site_live_status(site_or_serial: str) -> dict:
    """Live system status read from ONE firewall right now: uptime, current
    and peak connection counts, connection usage, firmware and ROM version,
    model, the firewall's own clock, primary WAN and who last modified it.
    These are LIVE values, not NSM's cached record — and the two often disagree
    sharply, because NSM's attributes.* is captured when the device is acquired
    and then frozen. differs_from_nsm_cache names each field where the live
    reading disagrees with NSM's, with nsm_cached_up_time given for comparison;
    quote the live figure and say the cache is stale. responding_serial is the
    unit that actually answered — on a failed-over HA pair that is the
    secondary, not the serial you asked about, and responding_unit_differs
    flags it. Registration and authentication codes are never returned. Pass a
    serial or a unique site-name fragment."""
    dev, early = _one_device(site_or_serial)
    if early:
        return early
    serial = dev["serialNumber"]
    payload = _device_json("sys_status", serial)
    if isinstance(payload, dict) and len(payload) == 1:
        inner = next(iter(payload.values()))
        if isinstance(inner, dict):
            payload = inner
    payload = payload if isinstance(payload, dict) else {}

    out = {k: _clean(payload.get(k)) for k in LIVE_STATUS_FIELDS}

    cached = dev.get("attributes") or {}
    differs = [k for k in ("up_time", "system_time", "firmware_version",
                           "current_connections", "connection_usage")
               if cached.get(k) not in (None, "") and out.get(k) not in (None, "")
               and str(cached.get(k)).strip() != str(out.get(k)).strip()]

    responding = _clean(payload.get("serial_number")) or ""
    return {
        "data_status": "ok",
        "match_count": 1,
        "device": _dev_ident(dev),
        "data_source": "live",
        "responding_serial": responding,
        "responding_unit_differs": bool(responding) and responding != serial,
        "differs_from_nsm_cache": differs,
        "nsm_cached_up_time": cached.get("up_time") or "",
        **out,
    }


@mcp.tool
@fleet_tool
def site_wan_health(site_or_serial: str) -> dict:
    """Which WAN circuit one firewall is ACTUALLY using right now — a live read
    of the device, not NSM's cached record. Returns a verdict (on_primary,
    on_backup, all_down or no_failover_configured), the failover/load-balancing
    groups with their primary vs currently-active member, and every member with
    link state, probe/target status, its IP and zone, and traffic counters
    showing which link is really carrying bytes. USB/LTE ports are included and
    labelled is_lte rather than excluded, because they are usually the final
    backup in the group. traffic_status 'unavailable' means the counters could
    not be read but the verdict still stands. Pass a serial or a unique
    site-name fragment. This answers 'is the site on its backup circuit?',
    which offline-in-NSM cannot."""
    dev, early = _one_device(site_or_serial)
    if early:
        return early
    serial = dev["serialNumber"]

    groups_raw = _first_list(_device_json("flb_status_groups", serial))
    members_raw = _first_list(_device_json("flb_members", serial))
    ifaces = {r.get("name"): r
              for r in _first_list(_device_json("iface_status", serial))
              if isinstance(r, dict)}

    # Traffic counters are the nice-to-have; link and probe state are the
    # answer. Losing the counters must not lose the verdict.
    try:
        stats = {(s.get("group_name"), s.get("member_name")): s
                 for s in _first_list(_device_json("flb_statistics", serial))
                 if isinstance(s, dict)}
        traffic_status, traffic_detail = "ok", ""
    except Exception as exc:  # noqa: BLE001 — partial answer, labelled
        stats, traffic_status = {}, "unavailable"
        traffic_detail = f"{type(exc).__name__}: {exc}"

    groups = []
    for g in groups_raw:
        if not isinstance(g, dict):
            continue
        primary = _clean(g.get("primary_member")) or ""
        active = _clean(g.get("active_member")) or ""
        groups.append({
            "group_name": _clean(g.get("group_name")) or "",
            "type": _clean(g.get("type")) or "",
            "status": _clean(g.get("status")) or "",
            "primary_member": primary,
            "active_member": active,
            "active_is_primary": bool(active) and active == primary,
            "total_members": g.get("total_members"),
            "final_back_up": _clean(g.get("final_back_up")) or "",
        })

    members = []
    for m in members_raw:
        if not isinstance(m, dict):
            continue
        gname = _clean(m.get("group_name")) or ""
        name = _clean(m.get("member_name")) or ""
        iface = ifaces.get(name) or {}
        st = stats.get((m.get("group_name"), m.get("member_name"))) or {}
        active_here = any(g["active_member"] == name and g["group_name"] == gname
                          for g in groups)
        members.append({
            "group": gname,
            "interface": name,
            "is_lte": _is_lte(name),
            "link_up": (_clean(m.get("link_status")) or "").lower().startswith(
                "link up"),
            "lb_status": _clean(m.get("lb_status")) or "",
            "probe_status": _clean(m.get("probe_status")) or "",
            "main_target_status": _clean(m.get("main_target_status")),
            "active_now": active_here,
            "zone": _clean(iface.get("zone")) or "",
            "ip": _clean(iface.get("ip_address")) or "",
            "speed": _clean(iface.get("status")) or "",
            "rx_bytes": st.get("rx_bytes") if traffic_status == "ok" else None,
            "tx_bytes": st.get("tx_bytes") if traffic_status == "ok" else None,
            "throughput_kbits_s": (st.get("thoughput_kbits_s")
                                   if traffic_status == "ok" else None),
        })

    findings = []
    if any(not m["link_up"] for m in members):
        findings.append("member_down")
    ipv4_groups = [g for g in groups if "ipv6" not in g["group_name"].lower()]
    if not ipv4_groups:
        verdict = "no_failover_configured"
    elif all(not m["link_up"] for m in members if not m["is_lte"]):
        verdict = "all_down"
        findings.append("all_wan_members_down")
    elif all(g["active_is_primary"] for g in ipv4_groups):
        verdict = "on_primary"
    else:
        verdict = "on_backup"
        findings.append("running_on_backup_circuit")

    return {
        "data_status": "ok",
        "match_count": 1,
        "device": _dev_ident(dev),
        "data_source": "live",
        "verdict": verdict,
        "findings": findings,
        "groups": groups,
        "member_count": len(members),
        "members": members,
        "traffic_status": traffic_status,
        "traffic_detail": traffic_detail,
    }


SIGNATURE_KEYS = {
    "gateway_anti_virus": ("gav", "gateway_anti_virus_expiration_date"),
    "intrusion_prevention": ("ips", "ips_service_expiration_date"),
    "app_control": ("appctl", "app_signature_db_expiration_date"),
}
STALE_SIGNATURE_DAYS = 7
MAX_SESSIONS = 100


def _sonicos_date(s: str):
    """SonicOS stamps look like 'UTC 08/28/2026 14:33:07.000' or
    '08/30/2026 11:04:26.528' or 'UTC 04/16/2027'. Date part only — None when
    it will not parse, so an unreadable stamp reads as unknown, not as today.
    """
    text = (s or "").replace("UTC", "").strip()
    if not text:
        return None
    head = text.split()[0]
    try:
        return datetime.strptime(head, "%m/%d/%Y").date()
    except ValueError:
        return None


@mcp.tool
@fleet_tool
def site_security_services(site_or_serial: str) -> dict:
    """Security-service status read live from ONE firewall: the licence state
    of every service the box reports (Gateway Anti-Virus, IPS, anti-spyware,
    app control, Capture ATP, content filtering, DPI-SSL and the rest), plus
    the signature-database state and age for Gateway Anti-Virus, Intrusion
    Prevention and App Control. IMPORTANT: SonicOS reports LICENSING here, not
    whether a service is switched on — a service can be licensed and still
    disabled, so do not report 'IPS is on' from this tool. stale_signatures
    names services whose signature database has not been updated in over 7
    days, which usually means a licensing or DNS failure rather than an idle
    firewall. signatures_unavailable names services whose signature endpoint
    could not be read; the licence answer still stands. Pass a serial or a
    unique site-name fragment."""
    dev, early = _one_device(site_or_serial)
    if early:
        return early
    serial = dev["serialNumber"]

    raw = _device_json("sec_services", serial)
    raw = raw if isinstance(raw, dict) else {}
    services = [
        {"service": k,
         "licensed": isinstance(v, str) and v.lower().startswith("licensed"),
         "raw": _clean(v)}
        for k, v in sorted(raw.items()) if isinstance(v, str)
    ]

    today = _today()
    sigs, unavailable, stale = [], [], []
    for name, (key, expiry_field) in SIGNATURE_KEYS.items():
        try:
            payload = _device_json(key, serial)
        except Exception:  # noqa: BLE001 — partial answer, named explicitly
            unavailable.append(name)
            continue
        payload = payload if isinstance(payload, dict) else {}
        stamped = _sonicos_date(payload.get("signature_database_timestamp"))
        age = (today - stamped).days if stamped else None
        expires = _sonicos_date(payload.get(expiry_field))
        if age is not None and age > STALE_SIGNATURE_DAYS:
            stale.append(name)
        sigs.append({
            "service": name,
            "signature_database": _clean(payload.get("signature_database")) or "",
            "signature_timestamp": _clean(
                payload.get("signature_database_timestamp")) or "",
            "signature_age_days": age,
            "last_checked": _clean(payload.get("last_checked")) or "",
            "expires": expires.isoformat() if expires else "",
        })

    return {
        "data_status": "ok",
        "match_count": 1,
        "device": _dev_ident(dev),
        "data_source": "live",
        "field_meaning": ("services[].licensed reflects LICENSING as SonicOS "
                          "reports it, not whether the service is enabled"),
        "services": services,
        "signature_databases": sigs,
        "signatures_unavailable": unavailable,
        "stale_signatures": stale,
        "stale_threshold_days": STALE_SIGNATURE_DAYS,
    }


@mcp.tool
@fleet_tool
def site_ssl_vpn_sessions(site_or_serial: str) -> dict:
    """Who is connected to ONE firewall's SSL-VPN right now: a live read
    returning each session's user, client (public) IP, assigned virtual IP,
    login time, duration and idle time, plus per-user session counts. A
    session_count of 0 with an empty list means nobody is connected — a real
    answer, not a failed read. Capped at 100 sessions; truncated flags the rest
    while session_count stays authoritative. This answer names real people and
    their source IPs: report it for the site being troubleshooted, and prefer
    counts over names in a group conversation. Pass a serial or a unique
    site-name fragment."""
    dev, early = _one_device(site_or_serial)
    if early:
        return early
    serial = dev["serialNumber"]
    rows = _first_list(_device_json("sslvpn_sessions", serial))

    sessions = []
    for r in rows:
        if not isinstance(r, dict):
            continue
        sessions.append({
            "user": _clean(r.get("user_name") or r.get("user")) or "",
            "client_ip": _clean(r.get("client_ip")) or "",
            "virtual_ip": _clean(r.get("virtual_ip")) or "",
            "login_time": _clean(r.get("login_time")) or "",
            "duration": _clean(r.get("duration")) or "",
            "inactive_time": _clean(r.get("inactive_time")) or "",
        })
    by_user = Counter(s["user"] for s in sessions if s["user"])
    return {
        "data_status": "ok",
        "match_count": 1,
        "device": _dev_ident(dev),
        "data_source": "live",
        "session_count": len(sessions),
        "sessions": sessions[:MAX_SESSIONS],
        "truncated": len(sessions) > MAX_SESSIONS,
        "by_user": dict(by_user.most_common()),
        "contains_personal_data": True,
    }


MAX_WIFI_CLIENTS = 100

# reporting/wireless/status is projected from an allow-list, not by deleting
# fields: a PSK or passphrase added by a future firmware cannot leak by
# default. No credential-shaped keys were found in this family when probed —
# the allow-list keeps it that way.
WIFI_STATUS_FIELDS = (
    "wlan", "ssid", "channel", "radio_mode", "security", "regulatory_domain",
    "radio_tx_power", "radio_tx_rate", "wireless_firmware", "primary_bssid",
    "mac_filter_list", "wireless_guest_services", "intrusion_detection",
    "associated_stations", "last_scan_time",
)


def _has_builtin_radio(model: str) -> bool:
    """TZ 270W / TZ 470W have a radio; NSA 3700 does not. The 'W' suffix is
    SonicWall's own naming rule and it is the only signal available here, so
    every answer built on it is labelled an inference, never a reading."""
    return (model or "").strip().upper().endswith("W")


def _wifi_internal(serial: str, model: str) -> tuple[dict, list]:
    """The firewall's OWN radio (reporting/wireless/*), present on the
    W-suffixed models. Returns (block, client_rows)."""
    likely_absent = not _has_builtin_radio(model)
    try:
        status = _device_json("wifi_status", serial)
    except Exception as exc:  # noqa: BLE001 — a dead family must be named
        detail = f"{type(exc).__name__}: {exc}"
        if likely_absent:
            detail = (f"model {model} has no built-in radio (the model name "
                      f"does not end in 'W'), so the internal wireless family "
                      f"is expected to be unreadable on this box — inference "
                      f"from the model name, not a reading. Upstream said: "
                      f"{detail}")
        return ({"status": "unavailable", "detail": detail,
                 "likely_absent": likely_absent, "client_count": None}, [])

    status = status if isinstance(status, dict) else {}
    block = {k: _clean(status.get(k)) for k in WIFI_STATUS_FIELDS}
    wlan = (block.get("wlan") or "")
    block.update({
        "status": "ok", "detail": "", "likely_absent": likely_absent,
        "radio_enabled": wlan.lower().startswith("enabled"),
    })

    clients, partial = [], []
    try:
        for st in _first_list(_device_json("wifi_stations", serial)):
            if not isinstance(st, dict):
                continue
            clients.append({
                "family": "internal",
                "access_point": "(built-in radio)",
                "mac": _clean(st.get("mac")) or "",
                "ip": "",
                "vendor": _clean(st.get("vendor")) or "",
                "ssid": _clean(st.get("ssid")) or "",
                "signal": _clean(st.get("signal")) or "",
                "rate": _clean(st.get("connect_rate")) or "",
                "state": _clean(st.get("associated")) or "",
            })
        block["client_count"] = len(clients)
    except Exception as exc:  # noqa: BLE001
        block["client_count"] = None
        partial.append(f"stations: {type(exc).__name__}: {exc}")

    try:
        aps = [a for a in _first_list(_device_json("wifi_discovered_aps", serial))
               if isinstance(a, dict)]
        block["neighbour_ap_count"] = len(aps)
        # "authorized: false" means "not on this firewall's authorized list".
        # At a small site that is the neighbours' Wi-Fi. Counted, never
        # presented as an intruder.
        block["unauthorized_ap_count"] = sum(1 for a in aps
                                             if not a.get("authorized"))
        block["neighbour_aps"] = [
            {"ssid": _clean(a.get("ssid")) or "",
             "bssid": _clean(a.get("mac_address_bssid_")) or "",
             "channel": a.get("channel"),
             "manufacturer": _clean(a.get("manufacturer")) or "",
             "signal_strength": _clean(a.get("signal_strength")) or "",
             "authorized": bool(a.get("authorized"))}
            for a in aps[:MAX_DRIFT_LIST]
        ]
    except Exception as exc:  # noqa: BLE001
        block["neighbour_ap_count"] = None
        block["unauthorized_ap_count"] = None
        block["neighbour_aps"] = []
        partial.append(f"discovered_aps: {type(exc).__name__}: {exc}")

    if partial:
        block["status"] = "partial"
        block["detail"] = "; ".join(partial)
    return block, clients


def _wifi_external(serial: str) -> tuple[dict, list]:
    """External SonicPoint / SonicWave APs (reporting/sonicpoint/*). An empty
    list here means the site has none — data, not a failed read."""
    try:
        aps_raw = [a for a in _first_list(_device_json("sonicpoint_status", serial))
                   if isinstance(a, dict)]
    except Exception as exc:  # noqa: BLE001
        return ({"status": "unavailable",
                 "detail": f"{type(exc).__name__}: {exc}",
                 "client_count": None}, [])

    aps = []
    for a in aps_raw:
        st = _clean(a.get("status")) or ""
        aps.append({
            "name": _clean(a.get("sonicpoint")) or "",
            "model": _clean(a.get("model")) or "",
            "mac": _clean(a.get("mac_address_bssid_")) or "",
            "ip": _clean(a.get("ip")) or "",
            "interface": _clean(a.get("interface")) or "",
            "zone": _clean(a.get("zone")) or "",
            "status": st,
            "operational": st.lower() == "operational",
            "uptime": _clean(a.get("uptime")) or "",
            "radio_status": _clean(a.get("radio_status")) or "",
            "radio_channel": _clean(a.get("radio_channel")) or "",
        })
    block = {
        "status": "ok", "detail": "",
        "ap_count": len(aps), "access_points": aps[:MAX_DRIFT_LIST],
        "aps_not_operational": [a["name"] for a in aps if not a["operational"]],
    }

    clients, partial = [], []
    try:
        for st in _first_list(_device_json("sonicpoint_stations", serial)):
            if not isinstance(st, dict):
                continue
            clients.append({
                "family": "external",
                "access_point": _clean(st.get("sonicpoint_name")) or "",
                "mac": _clean(st.get("mac")) or "",
                # The external family calls the client's IP "station".
                "ip": _clean(st.get("station")) or "",
                "vendor": _clean(st.get("vendor")) or "",
                "ssid": _clean(st.get("ssid")) or "",
                # "signal_strenth" is the API's own misspelling. Read it as
                # spelled or every external client's signal reads as "".
                "signal": _clean(st.get("signal_strenth")) or "",
                "rate": _clean(st.get("connectrate")) or "",
                "state": _clean(st.get("status")) or "",
                "band": _clean(st.get("type")) or "",
            })
        block["client_count"] = len(clients)
    except Exception as exc:  # noqa: BLE001
        block["client_count"] = None
        partial.append(f"stations: {type(exc).__name__}: {exc}")

    try:
        vaps = [v for v in _first_list(_device_json("wifi_vap_status", serial))
                if isinstance(v, dict)]
        block["vap_count"] = len(vaps)
        block["ssids"] = sorted({_clean(v.get("ssid")) or "" for v in vaps}
                                - {""})
        block["virtual_access_points"] = [
            {"access_point": _clean(v.get("name")) or "",
             "ssid": _clean(v.get("ssid")) or "",
             "radio": _clean(v.get("radio")) or "",
             "authentication": _clean(v.get("authen_type")) or "",
             "vlan": _clean(v.get("vlan")) or "",
             "enabled": bool(v.get("enable")),
             "active": (_clean(v.get("active")) or "").lower() == "active"}
            for v in vaps[:MAX_DRIFT_LIST]
        ]
    except Exception as exc:  # noqa: BLE001
        block["vap_count"], block["ssids"] = None, []
        block["virtual_access_points"] = []
        partial.append(f"vap_status: {type(exc).__name__}: {exc}")

    try:
        rf_raw = [r for r in _first_list(_device_json("sonicpoint_rf_score",
                                                      serial))
                  if isinstance(r, dict)]
        rf, all_scores = [], []
        for r in rf_raw:
            channels = []
            for n in (1, 2, 3, 4):
                score = str(r.get(f"rf_score{n}") or "").strip()
                if not score.isdigit():
                    # 'n/a' is "this radio did not report", not a zero score.
                    continue
                channels.append({"channel": _clean(r.get(f"channel{n}")) or "",
                                 "score": int(score)})
                all_scores.append(int(score))
            rf.append({"access_point": _clean(r.get("sonicpoint")) or "",
                       "channels": channels})
        block["rf_scores"] = rf
        block["worst_rf_score"] = min(all_scores) if all_scores else None
        block["rf_score_meaning"] = ("SonicWall RF score is 0-10; higher is a "
                                     "cleaner channel")
    except Exception as exc:  # noqa: BLE001
        block["rf_scores"], block["worst_rf_score"] = [], None
        partial.append(f"rf_score: {type(exc).__name__}: {exc}")

    if partial:
        block["status"] = "partial"
        block["detail"] = "; ".join(partial)
    return block, clients


@mcp.tool
@fleet_tool
def site_wifi(site_or_serial: str) -> dict:
    """Wi-Fi at ONE site, read live from the firewall. TWO SEPARATE SYSTEMS are
    reported and they are never added together: 'internal' is the firewall's
    own built-in radio (the W in TZ 270W), and
    'external' is any SonicPoint/SonicWave access points plugged in behind it.
    A box can have one, both or neither: an NSA 3700 has no built-in radio and
    reports internal unavailable while serving several SonicPoints, and a TZ W
    with no SonicPoints reports external ap_count 0, which is a real answer.
    client_count_total is only filled in when BOTH families answered; when
    either could not be read it is null and client_count_by_family carries what
    is known — quote the per-family numbers in that case and say which side
    could not be read, never present one family's count as the site total.
    internal.likely_absent true means the model name does not end in W, so the
    missing radio is expected rather than a fault (an inference from the model,
    not a reading). Also returns SSIDs, channels, security mode, neighbouring
    access points the radio can see, and SonicPoint RF scores (0-10, higher is
    cleaner). Clients cap at 100; the counts stay authoritative. Pass a serial
    or a unique site-name fragment."""
    dev, early = _one_device(site_or_serial)
    if early:
        return early
    serial = dev["serialNumber"]
    model = (dev.get("attributes") or {}).get("model") or ""

    internal, internal_clients = _wifi_internal(serial, model)
    external, external_clients = _wifi_external(serial)

    by_family = {"internal": internal.get("client_count"),
                 "external": external.get("client_count")}
    answered = sorted(f for f, c in by_family.items() if c is not None)
    unavailable = sorted(f for f, c in by_family.items() if c is None)

    clients = internal_clients + external_clients
    known_total = sum(c for c in by_family.values() if c is not None)
    return {
        "data_status": "ok",
        "match_count": 1,
        "device": _dev_ident(dev),
        "model": model,
        "data_source": "live",
        "families_answered": answered,
        "families_unavailable": unavailable,
        "internal": internal,
        "external": external,
        "client_count_by_family": by_family,
        # Withheld, not guessed: an unread family has an unknown client count,
        # and unknown + known is not a total.
        "client_count_total": None if unavailable else known_total,
        "client_count_total_detail": (
            f"no site total: the {', '.join(unavailable)} wireless family "
            f"could not be read, so its client count is unknown"
            if unavailable else ""),
        "clients": clients[:MAX_WIFI_CLIENTS],
        "truncated": known_total > MAX_WIFI_CLIENTS,
    }


MAX_LOG_ROWS = 200
DEFAULT_LOG_ROWS = 50
MAX_LOG_CATEGORIES = 25
BUFFER_TOTAL_KEY = "Total Number in DB"


def _log_time(stamp: str):
    """'08/30/2026 15:32:36' or 'UTC 08/30/2026 19:32:39' -> datetime. None
    when it will not parse, so an unreadable stamp sorts last instead of
    pretending to be the epoch (which would put it at the TOP of a
    newest-first list)."""
    text = (stamp or "").replace("UTC", "").strip()
    try:
        return datetime.strptime(text, "%m/%d/%Y %H:%M:%S")
    except ValueError:
        return None


def _endpoint(ip, port) -> str:
    ip = _clean(ip) or ""
    if not ip:
        return ""
    return f"{ip}:{port}" if port not in (None, "") else ip


def _log_rows(payload) -> list:
    """Projected to eight fields. The raw row has 15 and the page can be 200
    rows; the tool is read in a chat window."""
    out = []
    for r in _first_list(payload):
        if not isinstance(r, dict):
            continue
        out.append({
            "time": _clean(r.get("time")) or "",
            "category": _clean(r.get("category")) or "",
            "priority": _clean(r.get("priority")) or "",
            "message": _clean(r.get("message")) or "",
            "src": _endpoint(r.get("src_ip"), r.get("src_port")),
            "dst": _endpoint(r.get("dst_ip"), r.get("dst_port")),
            "application": _clean(r.get("application")) or "",
            "user": _clean(r.get("user_name")) or "",
        })
    return out


@mcp.tool
@fleet_tool
def site_event_log(site_or_serial: str, search: str = "", category: str = "",
                   limit: int = DEFAULT_LOG_ROWS) -> dict:
    """The firewall's OWN event log, read live from ONE box. This is the on-box
    log the appliance keeps in memory — NOT NSM's collected log, which has far
    longer retention.

    READ THIS BEFORE REPORTING A ZERO. The firewall serves the most recent PAGE
    of the log (up to 200 rows), and search/category filter that page, not the
    whole buffer. page_rows_returned says how many rows were searched,
    total_in_buffer says how many the firewall holds, and page_covers gives the
    time range actually examined. When page_rows_returned is far below
    total_in_buffer, "no matches" means "not in the last page_rows_returned
    events, covering page_covers" — say it that way; never say the event has
    not happened at this site.

    category_event_counters are the firewall's CUMULATIVE counters since boot
    (they run to billions), so they are not comparable to total_in_buffer and
    are not counts of anything returned here. category_counts_in_view is the
    breakdown of the page you were actually given. category_last_event gives
    the last time each category logged anything, which is the quickest way to
    see whether a subsystem is silent.

    total_in_buffer null with buffer_status 'unavailable' means the count could
    not be read — it does not mean the log is empty. search matches any field
    case-insensitively (message, IPs, application, user, category); category
    matches the category name. limit defaults to 50 and is clamped to 1-200.
    Pass a serial or a unique site-name fragment."""
    dev, early = _one_device(site_or_serial)
    if early:
        return early
    serial = dev["serialNumber"]

    rows = _log_rows(_device_json("log_view", serial))
    # Unparseable stamps sort last rather than first: None must not read as
    # "the oldest possible time" in a newest-first list.
    rows.sort(key=lambda r: (_log_time(r["time"]) is not None,
                             _log_time(r["time"]) or datetime.min),
              reverse=True)
    page_rows = len(rows)

    q = (search or "").strip().lower()
    cat = (category or "").strip().lower()
    if q:
        rows = [r for r in rows
                if q in " ".join(str(v) for v in r.values()).lower()]
    if cat:
        rows = [r for r in rows if cat in r["category"].lower()]

    limit = max(1, min(int(limit), MAX_LOG_ROWS))

    # Buffer size and per-category last-seen. Losing this must not lose the
    # events, and an unreadable total must read as unknown, never as zero.
    total, buffer_status, last_event = None, "ok", {}
    try:
        for r in _first_list(_device_json("log_view_status", serial)):
            if not isinstance(r, dict):
                continue
            name = _clean(r.get("log_view")) or ""
            value = _clean(r.get("status")) or ""
            if name == BUFFER_TOTAL_KEY:
                total = int(value) if value.isdigit() else None
            elif name and value and value != "N/A":
                last_event[name] = value
    except Exception:  # noqa: BLE001 — partial answer, labelled
        buffer_status, last_event = "unavailable", {}

    counters, counters_status = {}, "ok"
    try:
        cats = [c for c in _first_list(_device_json("log_categories", serial))
                if isinstance(c, dict) and c.get("event_count")]
        cats.sort(key=lambda c: -(c.get("event_count") or 0))
        counters = {(_clean(c.get("name")) or ""): c.get("event_count")
                    for c in cats[:MAX_LOG_CATEGORIES]}
    except Exception:  # noqa: BLE001
        counters, counters_status = {}, "unavailable"

    in_view = Counter(r["category"] for r in rows if r["category"])
    times = [r["time"] for r in rows if r["time"]]
    return {
        "data_status": "ok",
        "match_count": 1,
        "device": _dev_ident(dev),
        "data_source": "live",
        "log_source": ("on-box event log (SonicOS reporting/log/view); NSM's "
                       "collected log with longer retention is a separate "
                       "source"),
        "total_in_buffer": total,
        "buffer_status": buffer_status,
        "page_rows_returned": page_rows,
        "page_covers": {"oldest": times[-1] if times else "",
                        "newest": times[0] if times else ""},
        "filter_scope": ("filters are applied to the most recent page the "
                         "firewall returned (page_rows_returned rows), not to "
                         "the whole buffer"),
        "filters": {"search": search, "category": category},
        "event_count_after_filter": len(rows),
        "events": rows[:limit],
        "limit": limit,
        "truncated": len(rows) > limit,
        "category_counts_in_view": dict(in_view),
        "category_last_event": last_event,
        "category_event_counters": counters,
        "counters_status": counters_status,
        "counters_meaning": ("cumulative event counters since boot, reported "
                             "by the firewall; they are not counts of the rows "
                             "returned here and not comparable to "
                             "total_in_buffer (the buffer holds far fewer)"),
    }


HEALTH_CHECK_WORKERS = 4
HEALTH_CHECK_TIMEOUT = 5.0

# Licence codes that protect TRAFFIC. Everything else (NSM management and
# reporting entitlements) is reported as info: an organization may run with a
# management entitlement expired as an accepted, recorded decision, and
# grading that as a health warning would mark most of a fleet degraded for a
# choice already made and bury the findings that matter.
SECURITY_LICENCE_CODES = {"IDP", "CGSS", "AGSS", "GAV", "CFS", "ATP", "SPIKE",
                          "COMPCGSS", "COMPAGSS", "TOTALSECURE"}

# Areas this platform genuinely cannot report, declared so an absent section
# is never read as a clean one.
HEALTH_NOT_SUPPORTED = [
    {"area": "vpn_tunnels",
     "reason": ("no live IPsec SA status endpoint exists: the SonicOS swagger "
                "has no per-SA status collection, reporting/tunnel-interfaces/"
                "vpn/status is empty for policy-based tunnels, and NSM's "
                "vpn-topology monitor is empty unless tunnels were built as "
                "NSM topologies. "
                "site_vpn_tunnels reports the CONFIGURED tunnels; "
                "nothing here proves one is up.")},
]


def _run_health_checks(checks: dict, budget: float | None = None,
                       workers: int | None = None) -> tuple[dict, list]:
    """Run the per-area reads in parallel and bound the ANSWER, not the thread.

    A worker blocked in a socket read cannot be killed, so the executor is shut
    down without waiting: the tool returns a verdict with the slow area named
    while the orphan finishes in the background. Blocking instead would hand
    the chat client a timeout, which tells the engineer nothing at all.

    `budget` exists because the 5-second default is calibrated for SonicOS
    per-device reads, which answer in 200-500 ms. The NSM analytics plane does
    not: /ang/report took 1.6 s to 18.5 s across the samples and TIMED OUT at
    60 s on the busiest one. Left on the default, site_threat_report would
    report all five of its sections unavailable on every call — a tool that
    passes its offline tests (where the fixtures return instantly) and answers
    nothing in production. Callers on that plane pass their own budget.
    """
    limit = HEALTH_CHECK_TIMEOUT if budget is None else budget
    out, unavailable = {}, []
    pool = ThreadPoolExecutor(max_workers=workers or HEALTH_CHECK_WORKERS,
                              thread_name_prefix="health")
    try:
        futures = {area: pool.submit(fn) for area, fn in checks.items()}
        deadline = time.monotonic() + limit
        for area, fut in futures.items():
            try:
                result = fut.result(timeout=max(0.0,
                                                deadline - time.monotonic()))
            except FutureTimeout:
                unavailable.append(
                    {"area": area,
                     "detail": f"timed out after {limit}s"})
                continue
            except Exception as exc:  # noqa: BLE001
                unavailable.append({"area": area,
                                    "detail": f"{type(exc).__name__}: {exc}"})
                continue
            # The sub-tools carry the fleet_tool envelope, so a failed upstream
            # arrives as a payload, not an exception.
            if isinstance(result, dict) and result.get("data_status") != "ok":
                unavailable.append({"area": area,
                                    "detail": result.get("detail") or
                                    "sub-tool reported data unavailable"})
                continue
            out[area] = result
    finally:
        pool.shutdown(wait=False, cancel_futures=True)
    return out, unavailable


def _health_findings(dev: dict, results: dict) -> list:
    """Every finding names the tool it came from, so a disputed line can be
    re-checked at its source."""
    findings = []

    def add(severity, area, text, source):
        findings.append({"severity": severity, "area": area, "text": text,
                         "source_tool": source})

    # ---- NSM tenant record (pattern A, no upstream call) ----------------
    if not dev.get("liveStatus"):
        add("critical", "reachability",
            "NSM reports this firewall offline; no live reads were attempted.",
            "device_detail")
    for lic in _sec_services(dev):
        if str(lic.get("status") or "").lower() != "expired":
            continue
        code = (lic.get("serviceCode") or "").upper()
        name = lic.get("securityService") or code
        sev = "warning" if code in SECURITY_LICENCE_CODES else "info"
        add(sev, "licensing",
            f"{name} ({code}) expired {lic.get('expires') or 'unknown date'}.",
            "license_posture")
    offer = _newest_offer(dev)
    if offer:
        add("info", "firmware",
            f"firmware {offer} is available (running "
            f"{(dev.get('attributes') or {}).get('firmware_version') or '?'}).",
            "firmware_upgrade_availability")
    if dev.get("synchronized") is False:
        add("warning", "nsm_sync",
            "NSM reports this firewall out of sync with its managed config.",
            "device_health_flags")
    if dev.get("configModified"):
        add("info", "local_changes",
            "config was modified locally, outside NSM.",
            "device_health_flags")

    # ---- live reads ------------------------------------------------------
    live = results.get("live") or {}
    if live.get("restart_required"):
        add("warning", "system",
            "the firewall reports a restart is required.", "site_live_status")

    wan = results.get("wan") or {}
    verdict = wan.get("verdict")
    if verdict == "all_down":
        add("critical", "wan", "every WAN member is down.", "site_wan_health")
    elif verdict == "on_backup":
        add("warning", "wan",
            "the site is running on a backup circuit, not its primary.",
            "site_wan_health")
    elif verdict == "no_failover_configured":
        add("info", "wan", "no IPv4 failover group is configured.",
            "site_wan_health")
    down = [m["interface"] for m in wan.get("members") or []
            if not m.get("link_up")]
    if down and verdict != "all_down":
        add("warning", "wan",
            f"WAN member(s) down: {', '.join(down)} — the circuit in use is "
            f"up, but the backup path is not.", "site_wan_health")

    sec = results.get("security_services") or {}
    if sec.get("stale_signatures"):
        add("warning", "security_services",
            f"signature database stale (> "
            f"{sec.get('stale_threshold_days')} days) for: "
            f"{', '.join(sec['stale_signatures'])}.",
            "site_security_services")

    wifi = results.get("wifi") or {}
    notop = (wifi.get("external") or {}).get("aps_not_operational") or []
    if notop:
        add("warning", "wifi",
            f"access point(s) not operational: {', '.join(notop)}.",
            "site_wifi")
    # An unread wireless family on a model with no built-in radio is expected,
    # not a fault, and must not be graded as one.
    internal = wifi.get("internal") or {}
    if internal.get("status") == "unavailable" and not internal.get(
            "likely_absent"):
        add("info", "wifi",
            "the built-in radio could not be read on a model that should have "
            "one.", "site_wifi")
    return findings


@mcp.tool
@fleet_tool
def site_health_check(site_or_serial: str) -> dict:
    """One health verdict for a site, composed from every live read available
    plus NSM's record. Answers "is the Springfield site OK?" in one call.

    overall is:
      healthy             every check ran and nothing was found
      healthy_unverified  nothing was found, but an area could not be checked
                          — say which; do NOT report this site as healthy
      degraded            at least one warning
      critical            at least one critical finding
      unreachable         NSM reports the firewall offline (no live reads made)

    findings each carry severity, area, text and source_tool — quote
    source_tool so the engineer can re-check the claim at first hand. info
    findings are context (firmware available, expired MANAGEMENT licences,
    local config edits) and do not degrade a site; warnings and criticals do.

    coverage says complete or partial. checks_unavailable names each area that
    could not be read and why, and a slow firewall produces a named unavailable
    area rather than a hung call. checks_not_supported names areas this
    platform cannot report at all — live VPN tunnel state is one of them, so
    never infer from this card that the tunnels are up.

    Reads run in parallel with a per-call budget. Pass a serial or a unique
    site-name fragment."""
    dev, early = _one_device(site_or_serial)
    if early:
        return early
    serial = dev["serialNumber"]

    # An offline firewall costs zero live GETs: the whole fleet shares one NSM
    # budget, and every one of these reads would fail anyway.
    if not dev.get("liveStatus"):
        findings = _health_findings(dev, {})
        return {
            "data_status": "ok", "match_count": 1, "device": _dev_ident(dev),
            "data_source": "cached (NSM record only — device offline)",
            "overall": "unreachable", "coverage": "complete",
            "findings": findings, "checks_run": ["nsm_record"],
            "checks_unavailable": [],
            "checks_not_supported": HEALTH_NOT_SUPPORTED,
            "summary": {"online_in_nsm": False,
                        "firmware": (dev.get("attributes") or {}).get(
                            "firmware_version") or ""},
        }

    results, unavailable = _run_health_checks({
        "live": lambda: site_live_status(site_or_serial=serial),
        "wan": lambda: site_wan_health(site_or_serial=serial),
        "security_services": lambda: site_security_services(
            site_or_serial=serial),
        "ssl_vpn": lambda: site_ssl_vpn_sessions(site_or_serial=serial),
        "wifi": lambda: site_wifi(site_or_serial=serial),
    })

    findings = _health_findings(dev, results)
    severities = {f["severity"] for f in findings}
    if "critical" in severities:
        overall = "critical"
    elif "warning" in severities:
        overall = "degraded"
    elif unavailable:
        # Nothing found, but not everything was looked at. Unknown must not
        # collapse into OK.
        overall = "healthy_unverified"
    else:
        overall = "healthy"

    live = results.get("live") or {}
    wan = results.get("wan") or {}
    ssl = results.get("ssl_vpn") or {}
    wifi = results.get("wifi") or {}
    return {
        "data_status": "ok",
        "match_count": 1,
        "device": _dev_ident(dev),
        "data_source": "live reads + NSM cached record",
        "overall": overall,
        "coverage": "partial" if unavailable else "complete",
        "findings": findings,
        "checks_run": sorted(results) + ["nsm_record"],
        "checks_unavailable": unavailable,
        "checks_not_supported": HEALTH_NOT_SUPPORTED,
        "summary": {
            "online_in_nsm": True,
            "up_time": live.get("up_time") or "",
            "firmware": live.get("firmware_version")
            or (dev.get("attributes") or {}).get("firmware_version") or "",
            "current_connections": live.get("current_connections"),
            "wan_verdict": wan.get("verdict") or "",
            "ssl_vpn_sessions": ssl.get("session_count"),
            "wifi_clients": wifi.get("client_count_total"),
        },
    }


# -------------------------------------------------------- fleet-audit tools

@mcp.tool
@fleet_tool
def lan_subnet_audit(standard_cidr: str = "") -> dict:
    """Fleet-wide LAN addressing audit — which firewalls are NOT on your
    organization's standard addressing. The default standard is 10.0.0.0/8: a
    LAN on any
    192.x or other range is flagged. For every online firewall the sweep could
    read, its LAN subnet (X0 or first LAN-zone interface) is bucketed as:
      standard — inside the standard range, correct;
      default  — still on SonicWall's factory 192.168.168.0/24, meaning the LAN
                 was never configured at all (the most urgent kind of wrong);
      other    — configured, but onto a non-standard range (also wrong);
      no_lan   — no addressed LAN interface found.
    non_standard_count = default + other, i.e. how many firewalls are wrong.
    Matching is by containment, so a site on 10.53.10.0/24 counts as standard.
    Override the lists with DEFAULT_LAN_SUBNETS / STANDARD_LAN_SUBNETS, or pass
    standard_cidr (e.g. '172.16.0.0/12') to accept one more range for this call.
    Counts are authoritative; lists cap at 50 per bucket. Answers come from a
    background sweep — as_of says how fresh; devices_unavailable counts
    firewalls the sweep could not read (offline or error) and they are NOT in
    any bucket, so never describe them as compliant. data_status 'unavailable'
    means the sweep has not completed yet since the server started — the detail
    says how far along it is."""
    snap = sweep_snapshot()
    if snap["as_of"] is None:
        return _sweep_unavailable()
    standard = standard_lan_subnets() | (
        {standard_cidr.strip()} if standard_cidr.strip() else set())
    buckets = {"default": [], "standard": [], "other": [], "no_lan": []}
    unavailable = []
    for serial, rec in snap["results"].items():
        if not rec["ok"]:
            unavailable.append({"serial": serial, "name": rec["name"],
                                "error": rec["error"]})
            continue
        lan = _lan_summary(_iface_rows(rec["interfaces"]))
        row = {"serial": serial, "name": rec["name"],
               "interface": lan["interface"], "cidr": lan["cidr"]}
        if not lan["cidr"]:
            buckets["no_lan"].append(row)
        elif _within(lan["cidr"], default_lan_subnets()):
            # Checked FIRST and kept separate from "other": still on the
            # factory subnet means nobody ever configured it, which is a
            # different job from a site configured onto the wrong range.
            buckets["default"].append(row)
        elif _within(lan["cidr"], standard):
            buckets["standard"].append(row)
        else:
            buckets["other"].append(row)
    checked = sum(len(v) for v in buckets.values())
    return {
        "data_status": "ok",
        "as_of": snap["as_of"],
        "default_subnets": sorted(default_lan_subnets()),
        "standard_subnets": sorted(standard),
        "devices_total": checked + len(unavailable),
        "devices_checked": checked,
        "devices_unavailable": len(unavailable),
        "bucket_counts": {k: len(v) for k, v in buckets.items()},
        # The headline number: firewalls not on the standard range.
        "non_standard_count": len(buckets["default"]) + len(buckets["other"]),
        "buckets": {k: v[:MAX_DRIFT_LIST] for k, v in buckets.items()},
        "truncated": any(len(v) > MAX_DRIFT_LIST for v in buckets.values()),
        "unavailable_devices": unavailable[:MAX_DRIFT_LIST],
    }


HOST_SOURCES = ("dhcp", "arp")
_MAC_SEP_RE = re.compile(r"^[0-9a-f]{2}([:-][0-9a-f]{2}){1,5}$", re.I)
_MAC_BARE_RE = re.compile(r"^[0-9a-f]{12}$", re.I)
# One to three octets, and a dot is REQUIRED: "10." and "10.20" are IP
# prefixes, "18" is a hostname. Without the dot requirement a bare
# number becomes an address search nobody asked for.
_IP_PREFIX_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){0,2}\.?$")


def _norm_mac(mac: str) -> str:
    """ARP stores 9C:93:4E:9A:BD:58, DHCP stores 62:7e:83:cf:f1:75. Compared
    un-normalised, a MAC search finds one table and silently misses the
    other."""
    return re.sub(r"[^0-9a-f]", "", (mac or "").lower())


def _query_mode(query: str):
    """Returns (mode, parsed). Order matters: a full IP is checked before the
    MAC pattern, and a token with no dot or colon is never read as an IP —
    ipaddress.ip_network('18') is 0.0.0.18, so searching for a host called
    '18' would silently become a lookup for an address nobody has."""
    q = query.strip()
    if not q:
        return "empty", None
    if ("." in q or ":" in q) and "/" not in q:
        try:
            return "ip", ipaddress.ip_address(q)
        except ValueError:
            pass
    if "/" in q:
        try:
            return "cidr", ipaddress.ip_network(q, strict=False)
        except ValueError:
            pass
    if _MAC_SEP_RE.match(q) or _MAC_BARE_RE.match(q):
        return "mac_prefix", _norm_mac(q)
    if "." in q and _IP_PREFIX_RE.match(q):
        return "ip_prefix", q.rstrip(".")
    return "text", q.lower()


def _host_matches(row: dict, mode: str, parsed) -> bool:
    ip = row.get("ip") or ""
    if mode == "ip":
        try:
            return ipaddress.ip_address(ip) == parsed
        except ValueError:
            return False
    if mode == "cidr":
        try:
            return ipaddress.ip_address(ip) in parsed
        except ValueError:
            return False
    if mode == "ip_prefix":
        return ip == parsed or ip.startswith(parsed + ".")
    if mode == "mac_prefix":
        return _norm_mac(row.get("mac")).startswith(parsed)
    return parsed in (f"{row.get('hostname') or ''} "
                      f"{row.get('vendor') or ''}").lower()


@mcp.tool
@fleet_tool
def find_host(query: str) -> dict:
    """Find a host ANYWHERE in the fleet: which site is 10.196.1.82 at, which
    site has MAC 00:1A:..., find every Hikvision camera. Searches two tables on
    every firewall the background sweep could read — the DHCP lease table
    (hostname, lease) and the ARP cache (interface, every IP the firewall has
    talked to recently). Both are searched because neither is complete on its
    own: a camera or printer with a static IP is in ARP and never in DHCP, and
    a host that has not spoken recently may be in DHCP and not ARP. A host
    found in both is returned ONCE with sources ["dhcp","arp"], the hostname
    from DHCP and the interface from ARP.

    query is an IP (10.196.1.82), a CIDR (10.196.1.0/24), a partial IP
    (10.196.1), a MAC or MAC prefix in any case or separator style
    (00:1A:2B, 001a2b), or free text matched against hostname and vendor.
    match_mode says how the query was read.

    JUDGING A "NOT FOUND". devices_checked, devices_unavailable and
    source_coverage are part of the answer: they say how much of the fleet was
    actually searched and which table backed it. A zero match with
    devices_unavailable above zero means "not found on the firewalls we could
    read", not "not on the network" — say which. as_of is the sweep time, so
    every hit is as of then, not this second; a host that moved since will
    still be reported at its old site."""
    snap = sweep_snapshot()
    if snap["as_of"] is None:
        return _sweep_unavailable()

    mode, parsed = _query_mode(query or "")
    if mode == "empty":
        return {"data_status": "ok", "query": query, "match_mode": "empty",
                "match_count": 0, "matches": [],
                "detail": "query was empty; pass an IP, CIDR, MAC or hostname."}

    coverage = {k: {"devices_with_data": 0, "devices_missing": 0}
                for k in HOST_SOURCES}
    matches, unavailable, checked = [], [], 0

    for serial, rec in snap["results"].items():
        present = [k for k in HOST_SOURCES if rec.get(k) is not None]
        for k in HOST_SOURCES:
            key = "devices_with_data" if k in present else "devices_missing"
            coverage[k][key] += 1
        if not present:
            # No host table at all here. NOT counted as searched: a device the
            # sweep could not read must never make "not found" look wider than
            # it is.
            unavailable.append({"serial": serial, "name": rec.get("name") or "",
                                "error": rec.get("error") or "not read"})
            continue
        checked += 1

        # Merge the two tables per host before matching, so one hit carries
        # DHCP's hostname and ARP's interface instead of two half-answers.
        merged: dict = {}
        for source in present:
            for row in _host_rows(rec[source]):
                mac = _norm_mac(row["mac"])
                key = (mac or row["ip"], row["ip"] if mac else "")
                entry = merged.setdefault(key, {
                    "site": rec.get("name") or "", "serial": serial,
                    "ip": "", "mac": "", "hostname": "", "vendor": "",
                    "type": "", "interface": "", "expires": "", "sources": [],
                })
                entry["sources"].append(source)
                for field in ("ip", "mac", "hostname", "vendor", "type",
                              "interface", "expires"):
                    if not entry[field] and row.get(field):
                        entry[field] = row[field]

        for entry in merged.values():
            if _host_matches(entry, mode, parsed):
                entry["sources"] = sorted(set(entry["sources"]))
                entry["seen_as_of"] = snap["as_of"]
                matches.append(entry)

    return {
        "data_status": "ok",
        "as_of": snap["as_of"],
        "query": query,
        "match_mode": mode,
        "sources_searched": list(HOST_SOURCES),
        "source_coverage": coverage,
        "devices_total": len(snap["results"]),
        "devices_checked": checked,
        "devices_unavailable": len(unavailable),
        "unavailable_devices": unavailable[:MAX_DRIFT_LIST],
        "match_count": len(matches),
        "matches": matches[:MAX_HOSTS],
        "truncated": len(matches) > MAX_HOSTS,
    }


@mcp.tool
@fleet_tool
def fleet_host_summary() -> dict:
    """How many devices are connected at every location, from each online
    firewall's DHCP lease table as read by the background sweep: per-site
    host counts (largest first, top 50), fleet_host_count, and
    fleet_vendor_counts (top 30 MAC vendors — the fastest way to estimate
    IoT/camera/printer populations; say which vendors you counted). Static-IP
    devices are not in DHCP tables. as_of says how fresh; sites the sweep
    could not read are counted in devices_unavailable and excluded."""
    snap = sweep_snapshot()
    if snap["as_of"] is None:
        return _sweep_unavailable()
    sites, vendors, total, unavailable = [], Counter(), 0, 0
    for serial, rec in snap["results"].items():
        if not rec["ok"] or rec.get("dhcp") is None:
            unavailable += 1
            continue
        hosts = _first_list(rec["dhcp"])
        total += len(hosts)
        vendors.update((h.get("vendor") or "unknown") for h in hosts)
        sites.append({"serial": serial, "name": rec["name"],
                      "host_count": len(hosts)})
    sites.sort(key=lambda s: -s["host_count"])
    return {
        "data_status": "ok", "as_of": snap["as_of"],
        "devices_total": len(snap["results"]), "devices_checked": len(sites),
        "devices_unavailable": unavailable,
        "fleet_host_count": total,
        "fleet_vendor_counts": dict(vendors.most_common(30)),
        "sites": sites[:MAX_DRIFT_LIST], "truncated": len(sites) > MAX_DRIFT_LIST,
    }


# ------------------------------------- change management: NSM manager plane (D)
#
# A THIRD SEAM. The two already here are:
#   get_devices()      — NSM's cached tenant record  ("cached")
#   _device_json()     — a SonicOS read proxied per device via X-Device-ID
#                        ("live")
# This one is NSM's own manager plane: no device header, the device named by a
# query parameter, and the data is NSM's record of what it did and what it was
# told ("cached"), or its collected event store ("collected").
#
# That third word matters more than it looks. A firewall that stopped
# reporting to NSM and a firewall where genuinely nothing happened return the
# SAME empty answer from this plane. Every tool below therefore states which
# kind of data it is returning, in the payload and not only in the docstring.
#
# The mutating
# endpoints in these same URL families — /commits/createFromPendingConfigs*,
# /commit-approval/*, /vpn-topology/monitor/clear, /configs/apply* — are never
# called by this server.

MANAGER_PATHS = {
    "config_versions": "/api/manager/configaudit/listconfigs",
    "config_versions_count": "/api/manager/configaudit/listconfigs/count",
    "config_diff": "/api/manager/configaudit/diff",
    "commits": "/api/manager/commits",
    # The WHOLE TENANT in one GET. Verified live: a full fleet x 9 services in
    # well under 100 KB, sub-second warm; `deviceIDs` is optional and filters
    # correctly on comma-separated SERIALS — the response's `id` field IS the
    # serial number, which is what makes the join to get_devices() possible.
    #
    # This is why there is NO sweep key for security services: the sweep
    # alternative was one GET per device per cycle; one tenant-wide call costs
    # a single GET on demand.
    "security_services": "/api/manager/security-services/status",
}
MANAGER_CALL_TIMEOUT = 30
MAX_VERSIONS = 50
MAX_COMMITS = 50
MAX_CHANGED_PATHS = 100
MAX_DIFF_HUNKS = 200


def _upstream_manager_json(path: str, params: dict | None = None):
    """One manager-plane GET. No X-Device-ID: this plane scopes by query
    parameter. The monkeypatch seam offline tests replace."""
    return SESSION.get(path, params=params, timeout=MANAGER_CALL_TIMEOUT)


def _manager_json(key: str, params: dict | None = None):
    cache_key = f"mgr|{key}|" + json.dumps(params or {}, sort_keys=True)
    return _cached(cache_key,
                   lambda: _upstream_manager_json(MANAGER_PATHS[key], params))


def _api_error(payload) -> str:
    """The manager plane answers HTTP 200 with an ERROR BODY.

    Live on 2026-08-30: `/systemevent/logs/count` returns 200 carrying
    `{"status":{"info":[{"code":"E_FAIL","message":"path ... was not
    found"}]}}` — a 200 that means 404 — and `/configaudit/listconfigs` called
    with an X-Device-ID header returns 200 carrying "Internal Server Error -
    Unable to reach DM".

    Treating those as success is how a tool ends up reporting "nothing
    changed" from an endpoint that is not answering. Returns the message, or
    "" when the payload is a real answer.
    """
    if not isinstance(payload, dict):
        return ""
    status = payload.get("status")
    if not isinstance(status, dict) or status.get("success") is not False:
        return ""
    for entry in status.get("info") or []:
        if isinstance(entry, dict) and entry.get("message"):
            return str(entry["message"])
    return "success=false with no message"


class ManagerError(RuntimeError):
    """A manager-plane call that answered, but with an error body."""


def _manager_payload(key: str, params: dict | None = None):
    payload = _manager_json(key, params)
    err = _api_error(payload)
    if err:
        raise ManagerError(f"{MANAGER_PATHS[key]}: {err}")
    return payload


def _window_start(hours: int) -> int:
    """Epoch seconds for the start of a `hours`-long window ending now.

    The window is applied CLIENT-SIDE. /configaudit/listconfigs takes a
    `timeLimit` parameter documented as an hours window; probed
    live it returned an empty list for every non-zero value tried
    (1, 7, 24, 30, 60, 90, 180, 365, 720), while omitting it returns the real
    versions. Sending it would make every firewall report "no changes".
    """
    return int(time.time()) - max(int(hours), 0) * 3600


def _epoch_seconds(value) -> int:
    """NSM mixes seconds and milliseconds in the same payload family:
    configaudit `time` is seconds, commits `scheduledAt` is milliseconds."""
    try:
        v = int(value)
    except (TypeError, ValueError):
        return 0
    return v // 1000 if v > 10_000_000_000 else v


def _text(v, limit: int = 300) -> str:
    """_clean() passes None through unchanged, so `_clean(x)[:300]` blows up on
    any absent field — and on this plane `comment` is frequently absent.
    Always a string, always bounded."""
    s = _clean(v)
    return s[:limit] if isinstance(s, str) else ""


def _version_row(v: dict) -> dict:
    ts = _epoch_seconds(v.get("time"))
    return {
        "hash": _text(v.get("hash"), 64),
        "time": ts,
        "time_utc": _epoch_iso(ts),
        "user": _text(v.get("user"), 120),
        "role": _text(v.get("role"), 40),
        # "Committed" = pushed from NSM; "Synchronized" = NSM pulled the
        # device's own config back. The second one following the first is
        # normal; the second one ALONE is the fingerprint of a change made
        # outside NSM.
        "type": _text(v.get("type"), 40),
        "comment": _text(v.get("comment")),
        "commit_id": _text(v.get("commitID"), 120),
        "name": _text(v.get("name"), 120),
    }


@mcp.tool
@fleet_tool
def config_history(site_or_serial: str, hours: int = 720) -> dict:
    """Configuration versions NSM has stored for one firewall, newest first.

    CACHED: this is NSM's own record of the config versions it holds, not a
    live read of the firewall. Each version carries who saved it, why, and
    whether it came from an NSM commit ("Committed") or from NSM pulling the
    device's running config back ("Synchronized").

    `hours` defaults to 720 (30 days) and is applied by this server, not by
    NSM — see _window_start for why. Zero versions in the window is a real
    answer (data_status stays "ok"), not a failure.

    Returns latest_hash, which is the input config_diff needs.
    """
    device, early = _one_device(site_or_serial)
    if early:
        return early
    serial = device.get("serialNumber") or ""

    versions = _manager_payload("config_versions", {"sn": serial})
    rows = sorted((_version_row(v) for v in _first_list(versions)
                   if isinstance(v, dict)),
                  key=lambda r: r["time"], reverse=True)
    cutoff = _window_start(hours)
    in_window = [r for r in rows if r["time"] >= cutoff]

    detail = ""
    if not in_window:
        detail = (f"NSM holds {len(rows)} configuration version(s) for this "
                  f"firewall, but no configuration versions were saved in the "
                  f"last {hours}h.")
    return {
        "data_status": "ok",
        "data_source": "cached",
        "device": _dev_ident(device),
        "window_hours": hours,
        "window_start_utc": _epoch_iso(cutoff),
        "version_count": len(in_window),
        "stored_version_count": len(rows),
        "latest_hash": in_window[0]["hash"] if in_window else (
            rows[0]["hash"] if rows else ""),
        "versions": in_window[:MAX_VERSIONS],
        "truncated": len(in_window) > MAX_VERSIONS,
        "detail": detail,
    }


_COMMIT_FAILURE_STATUSES = ("Failed", "PartialFailed", "Rejected", "Canceled")


def _commit_row(c: dict) -> dict:
    ts = _epoch_seconds(c.get("scheduledAt"))
    return {
        "commit_id": _text(c.get("id"), 64),
        "commit_name": _text(c.get("commitName"), 200),
        "user": _text(c.get("user"), 120),
        "role": _text(c.get("role"), 40),
        "status": _text(c.get("status"), 40),
        "comment": _text(c.get("comment")),
        "device_count": c.get("deviceCount") or 0,
        "scheduled_at": ts,
        "scheduled_utc": _epoch_iso(ts),
        "approval_enabled": bool(c.get("approvalEnabled")),
        # tenantID is deliberately NOT projected: tenancy plumbing, not an
        # answer, and it has no business in a chat response.
    }


@mcp.tool
@fleet_tool
def nsm_commits(site_or_serial: str = "", hours: int = 168,
                status: str = "") -> dict:
    """Commits NSM pushed — who, when, to how many devices, and whether it took.

    CACHED: NSM's record of its own work, not a live read of any firewall.
    Failures are listed first. Pass `site_or_serial` for one firewall's
    commits, or omit it for the whole tenant. `status` filters to one status
    (e.g. "Failed", "PartialFailed", "Success").

    Two things this answer is careful about, both properties of the upstream
    payload rather than of this fleet:

    * `tenant_wide_totals` are NSM's own counters, and they do NOT respect a
      device filter — they describe the entire tenant even when the question
      was about one site. The per-answer `status_counts` are computed from the
      rows actually returned, and those are the ones that describe the device.
    * NSM pages this collection (500 per page). When `more_available` is true,
      `matched_total` says how many commits matched and `returned_by_nsm` how
      many were read; the answer covers the most recent page only.
    """
    params = {}
    device = None
    if site_or_serial:
        device, early = _one_device(site_or_serial)
        if early:
            return early
        params["filterDeviceSerialNumber"] = device.get("serialNumber") or ""

    payload = _manager_payload("commits", params or None)
    payload = payload if isinstance(payload, dict) else {}
    raw = [c for c in (payload.get("commits") or []) if isinstance(c, dict)]

    cutoff = _window_start(hours)
    rows = [_commit_row(c) for c in raw]
    rows = [r for r in rows if r["scheduled_at"] >= cutoff]
    if status:
        want = status.strip().lower()
        rows = [r for r in rows if r["status"].lower() == want]

    # Failures first, then newest first within each group.
    rows.sort(key=lambda r: (r["status"] not in _COMMIT_FAILURE_STATUSES,
                             -r["scheduled_at"]))

    counts = {}
    for r in rows:
        counts[r["status"]] = counts.get(r["status"], 0) + 1

    matched_total = payload.get("nFilteredTotal") or 0
    returned = len(raw)
    more = matched_total > returned
    detail = ""
    if more:
        detail = (f"NSM matched {matched_total} commits but returns one page "
                  f"of {returned}; this answer covers the most recent page "
                  f"only. Narrow it with site_or_serial or status.")
    elif not rows:
        detail = (f"No commits in the last {hours}h"
                  + (f" with status {status!r}" if status else "") + ".")

    return {
        "data_status": "ok",
        "data_source": "cached",
        "scope": _dev_ident(device) if device else {"scope": "tenant"},
        "window_hours": hours,
        "window_start_utc": _epoch_iso(cutoff),
        "commit_count": len(rows),
        "status_counts": counts,
        "matched_total": matched_total,
        "returned_by_nsm": returned,
        "more_available": more,
        # NSM's own counters. TENANT-WIDE — they do not respect the device
        # filter (verified: identical values on a one-device query and on the
        # tenant query, while nFilteredTotal moved 10 -> 4644).
        "tenant_wide_totals": {
            "deployed": payload.get("nDeploy") or 0,
            "failed": payload.get("nFailed") or 0,
            "partial_failed": payload.get("nPartialFailed") or 0,
            "in_progress": payload.get("nInProgress") or 0,
            "scheduled": payload.get("nScheduled") or 0,
            "pending_approval": payload.get("nPendingApproval") or 0,
            "approval_overdue": payload.get("nApprovalOverdue") or 0,
        },
        "commits": rows[:MAX_COMMITS],
        "truncated": len(rows) > MAX_COMMITS,
        "detail": detail,
    }


# A diff body is the firewall's ENTIRE configuration, so it can contain PSKs,
# SNMP community strings, password hashes and auth codes. This is the highest
# secret-leakage surface in the server, and the defence is structural rather
# than a filter: the tool extracts JSON KEY NAMES with the regex below and
# emits nothing else. Key names are useful ("the shared_secret changed") and
# safe; values are neither, and a blocklist over free text would only ever be
# as good as its list.
SECRET_KEY_PATTERN = (r"secret|password|passwd|community|shared_secret|"
                      r"auth_code|authentication_code|registration_code|"
                      r"psk|token|credential|key$")
_SECRET_KEY_RE = re.compile(SECRET_KEY_PATTERN, re.I)
_JSON_KEY_RE = re.compile(r'"([A-Za-z0-9_.\-]+)"\s*:')
_HUNK_RE = re.compile(r"^@@")


def _diff_keys(left: str, right: str) -> tuple[dict, int, int]:
    """Changed JSON key names between the two sides of an NSM config diff.

    /configaudit/diff returns {diff, diff1, diff2}: `diff` is empty and the
    two sides come back as separate, line-aligned texts. Lines that differ at
    the same index are the change; the key name on such a line is what gets
    reported. NOTHING else from either line is read out.
    """
    lines_l = left.splitlines()
    lines_r = right.splitlines()
    counts: dict[str, int] = {}
    changed_lines = 0
    hunks = 0
    for i in range(max(len(lines_l), len(lines_r))):
        a = lines_l[i] if i < len(lines_l) else ""
        b = lines_r[i] if i < len(lines_r) else ""
        if _HUNK_RE.match(a) or _HUNK_RE.match(b):
            hunks += 1
            continue
        if a == b:
            continue
        changed_lines += 1
        for line in (a, b):
            for key in _JSON_KEY_RE.findall(line):
                counts[key] = counts.get(key, 0) + 1
    return counts, changed_lines, hunks


def _latest_hashes(serial: str, n: int = 2) -> list:
    versions = _manager_payload("config_versions", {"sn": serial})
    rows = sorted((v for v in _first_list(versions) if isinstance(v, dict)),
                  key=lambda v: _epoch_seconds(v.get("time")), reverse=True)
    return [_text(v.get("hash"), 64) for v in rows[:n] if v.get("hash")]


@mcp.tool
@fleet_tool
def config_diff(serial_a: str, hash_a: str = "", serial_b: str = "",
                hash_b: str = "") -> dict:
    """Which configuration settings differ between two stored versions.

    CACHED: compares two configurations NSM has stored. Defaults to one
    device's latest two versions ("what changed here most recently?"); give
    `serial_b` as a different firewall for a site-standardisation review
    ("how does site A differ from site B?"), which NSM supports by design.

    Returns the NAMES of the JSON keys that differ and how often each differs.
    It never returns diff content: a configuration diff contains the whole
    config, including PSKs, SNMP community strings and password hashes, so
    only key names cross this boundary. `sensitive_keys_changed` lists the
    changed keys whose NAME looks credential-ish — worth knowing, and still
    without their values.

    Bodies are large upstream (264 KB for one device's latest two versions,
    2.5 MB across two devices); the answer is a projection, so `truncated`
    says when the key list itself was capped.
    """
    serial_a = (serial_a or "").strip()
    serial_b = (serial_b or "").strip() or serial_a

    if not hash_a or (serial_b == serial_a and not hash_b):
        latest = _latest_hashes(serial_a, 2)
        if len(latest) < 2 and serial_b == serial_a:
            return {
                "data_status": "ok",
                "data_source": "cached",
                "comparison": "same_device",
                "side_a": {"serial": serial_a, "hash": latest[0] if latest else ""},
                "side_b": {"serial": serial_a, "hash": ""},
                "changed_key_count": 0, "changed_keys": [],
                "sensitive_keys_changed": [], "changed_line_count": 0,
                "hunk_count": 0, "truncated": False,
                "detail": f"NSM holds {len(latest)} stored configuration "
                          f"version(s) for {serial_a}; two are needed to diff.",
            }
        # Oldest of the pair on the left so the diff reads forwards in time.
        hash_a = hash_a or (latest[1] if len(latest) > 1 else latest[0])
        if serial_b == serial_a and not hash_b:
            hash_b = latest[0]
    if not hash_b:
        hash_b = (_latest_hashes(serial_b, 1) or [""])[0]

    payload = _manager_payload("config_diff", {
        "sn1": serial_a, "h1": hash_a, "sn2": serial_b, "h2": hash_b})
    payload = payload if isinstance(payload, dict) else {}

    counts, changed_lines, hunks = _diff_keys(
        payload.get("diff1") or "", payload.get("diff2") or "")
    ranked = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
    sensitive = sorted({k for k in counts if _SECRET_KEY_RE.search(k)})

    return {
        "data_status": "ok",
        "data_source": "cached",
        "comparison": "same_device" if serial_a == serial_b else "cross_device",
        "side_a": {"serial": serial_a, "hash": hash_a},
        "side_b": {"serial": serial_b, "hash": hash_b},
        "changed_key_count": len(ranked),
        "changed_line_count": changed_lines,
        "hunk_count": hunks,
        "changed_keys": [{"key": k, "changes": n}
                         for k, n in ranked[:MAX_CHANGED_PATHS]],
        "sensitive_keys_changed": sensitive,
        "truncated": len(ranked) > MAX_CHANGED_PATHS,
        "detail": ("Key names only — configuration values are never returned "
                   "from a diff."),
    }


MAX_TIMELINE = 100

# Local-change attribution is not in the timeline below, and its absence is
# REPORTED, not hidden: /systemevent/localchanges/list and /logs were observed
# answering HTTP 200 with a header row and zero data rows over a 720h window.
# The endpoints work; NSM was simply holding no local-change attribution for
# that fleet. A tool that quietly dropped the area would let "no changes
# found" read as "nobody touched the box locally", which is a claim the data
# does not support.
AREAS_NOT_COVERED = [
    {"area": "local_changes",
     "why": "NSM's /systemevent/localchanges/* can return zero rows for a "
            "whole tenant even where local changes exist. "
            "Changes made directly on a firewall are therefore NOT visible "
            "here; a 'Synchronized' config version with no commit beside it "
            "is the closest available hint."},
]


def _timeline_from_commits(payload: dict) -> list:
    return [{
        "at": c["scheduled_at"],
        "at_utc": c["scheduled_utc"],
        "kind": "nsm_commit",
        "who": c["user"],
        "what": (f"{c['status']}: {c['commit_name']}"
                 + (f" — {c['comment']}" if c["comment"] else "")
                 + f" ({c['device_count']} device(s))"),
        "status": c["status"],
        "ref": c["commit_id"],
        "source_tool": "nsm_commits",
    } for c in payload.get("commits") or []]


def _timeline_from_versions(payload: dict) -> list:
    return [{
        "at": v["time"],
        "at_utc": v["time_utc"],
        "kind": "config_version",
        "who": v["user"],
        # "Committed" = pushed from NSM. "Synchronized" = NSM pulled the
        # device's running config back, which is what follows a local change.
        "what": (f"{v['type']} config version saved"
                 + (f" — {v['comment']}" if v["comment"] else "")),
        "status": v["type"],
        "ref": v["hash"],
        "source_tool": "config_history",
    } for v in payload.get("versions") or []]


@mcp.tool
@fleet_tool
def what_changed(site_or_serial: str, hours: int = 24) -> dict:
    """Everything NSM knows changed on one firewall in a window, as one timeline.

    CACHED: NSM's own records — the commits it pushed and the configuration
    versions it stored. It is NOT a live read of the firewall, and it is not
    complete: see `areas_not_covered`, which names what this plane cannot tell
    you for this tenant.

    A sub-read that fails becomes a named entry in `areas_unavailable` and the
    rest of the answer still stands. "No changes found" and "I could not find
    out" are different answers and are never merged.
    """
    device, early = _one_device(site_or_serial)
    if early:
        return early
    serial = device.get("serialNumber") or ""

    results, unavailable = _run_health_checks({
        "nsm_commits": lambda: nsm_commits(site_or_serial=serial, hours=hours),
        "config_versions": lambda: config_history(site_or_serial=serial,
                                                  hours=hours),
    })

    timeline = []
    if "nsm_commits" in results:
        timeline += _timeline_from_commits(results["nsm_commits"])
    if "config_versions" in results:
        timeline += _timeline_from_versions(results["config_versions"])
    timeline.sort(key=lambda e: e["at"], reverse=True)

    covered = sorted(results)
    if not covered:
        return {
            "data_status": "unavailable",
            "device": _dev_ident(device),
            "window_hours": hours,
            "timeline": [],
            "areas_covered": [],
            "areas_unavailable": unavailable,
            "areas_not_covered": AREAS_NOT_COVERED,
            "detail": "Every change-history area failed to read; "
                      "this is not evidence that nothing changed.",
        }

    detail = ""
    if not timeline:
        detail = (f"No changes recorded by NSM for this firewall in the last "
                  f"{hours}h.")
    if unavailable:
        detail += (" " if detail else "") + (
            "Partial answer: " +
            ", ".join(a["area"] for a in unavailable) + " could not be read.")

    return {
        "data_status": "ok",
        "data_source": "cached",
        "device": _dev_ident(device),
        "window_hours": hours,
        "window_start_utc": _epoch_iso(_window_start(hours)),
        "change_count": len(timeline[:MAX_TIMELINE]),
        "timeline": timeline[:MAX_TIMELINE],
        "truncated": len(timeline) > MAX_TIMELINE,
        "areas_covered": covered,
        "areas_unavailable": unavailable,
        "areas_not_covered": AREAS_NOT_COVERED,
        "detail": detail,
    }


# --------------------------------------------------- per-site access rules
#
# TWO ENDPOINTS, JOINED ON uuid. Verified live across sample devices:
# 402 stats rows matched 402 config rules, zero misses, and from/to/action/
# enable agreed on all 402 pairs. The join key matters because the alternatives
# silently lose rules:
#   * POSITIONAL zip: stats[i].uuid == rules[i].uuid held for 0 of 239 rows on
#     the NSA sample. The two endpoints answer in different orders.
#   * `priority`: a sparse GLOBAL number (1..278 over 239 rules), and 51 of
#     those rules carry {"auto": true} with no number at all — a priority join
#     drops them and still looks like it worked.
#
# THE CONFIG PAYLOAD NESTS ONE LEVEL DEEPER THAN IT LOOKS:
#   {"access_rules": [ {"ipv4": { ...the actual rule... }} ]}
# Reading access_rules[] directly yields rules with no fields, which projects
# to a full-length list of empty rows — an answer-shaped non-answer.

MAX_RULES = 50
MAX_ZONE_PAIRS = 60
# Per-site CONFIGURATION reads are bigger and slower than the status reads the
# 5 s health-check default was sized for: access-rules/ipv4 alone was 260 KB
# and 413 KB on the samples. A timeout here would report "no rules" for exactly
# the site that has the most of them.
CONFIG_READ_BUDGET = 20.0

# SonicOS renders "never hit" as the literal string "-" in time_last_hit;
# time_created / time_updated never use it.
NEVER_HIT = "-"
# 'MM/DD/YYYY HH:MM:SS.mmm', device-local. Not epoch, not ISO.
_SONICOS_STAMP = "%m/%d/%Y %H:%M:%S.%f"

RULE_HYGIENE_NOT_COVERED = [
    {"area": "shadowed_rules",
     "reason": ("SonicOS's own shadowed-rule analysis (rules that can never "
                "match because an earlier rule covers them) is not reachable "
                "read-only: the export/shadow-rule-list/* paths returned "
                "no 2xx on any sample probed, and the "
                "shadow-rules-list/generate/* endpoint that populates them is "
                "POST-only, which this server never calls. A rule listed here "
                "as never-hit may be never-hit BECAUSE it is shadowed, and "
                "nothing here distinguishes the two.")},
    {"area": "rule_reachability",
     "reason": ("never-hit means no traffic has matched, not that the rule is "
                "useless: a correct deny rule for an attack nobody has "
                "attempted, or a DR path, will read as unused. Every "
                "candidate needs a human decision.")},
]


def _addr_ref(obj) -> str:
    """source/destination/service arrive as exactly one of {"any": true},
    {"name": X} or {"group": Y}. Flattened to one string because a Teams
    answer needs a word, and because "any" must stay visible — collapsing it
    to "" would render the widest rule in the book as a blank."""
    if isinstance(obj, str):
        return obj
    if not isinstance(obj, dict):
        return ""
    if obj.get("any") is True:
        return "any"
    for key in ("name", "group"):
        val = obj.get(key)
        if isinstance(val, str) and val:
            return val
    return ""


def _rule_priority(obj):
    """{"manual": {"value": N}} -> N; {"auto": true} -> "auto". Never null:
    a rule with no priority reads as a rule that does not apply."""
    if isinstance(obj, (int, float)) and not isinstance(obj, bool):
        return int(obj)
    if not isinstance(obj, dict):
        return "unknown"
    manual = obj.get("manual")
    if isinstance(manual, dict) and manual.get("value") is not None:
        try:
            return int(manual["value"])
        except (TypeError, ValueError):
            return "unknown"
    if obj.get("auto") is True:
        return "auto"
    if obj.get("end") is True:
        return "end"
    return "unknown"


def _sonicos_stamp(value: str):
    """The stats plane's timestamp format. Returns None for the "-" sentinel
    and for anything unparseable — a malformed vendor date must never become
    a fabricated one."""
    text = (value or "").strip()
    if not text or text == NEVER_HIT:
        return None
    try:
        return datetime.strptime(text, _SONICOS_STAMP)
    except ValueError:
        return None


def _cfg_rule_list(payload) -> list:
    """The ipv4 unwrap, in one place."""
    rows = []
    for item in (payload or {}).get("access_rules") or []:
        if isinstance(item, dict) and isinstance(item.get("ipv4"), dict):
            rows.append(item["ipv4"])
    return rows


def _rule_row(rule: dict, stat: dict | None, stats_available: bool) -> dict:
    """One projected rule. ~280 bytes against ~1,085 raw, which is what keeps
    the NSA sample's 239 rules inside the size budget with room to spare."""
    row = {
        "uuid": _text(rule.get("uuid"), 64),
        "priority": _rule_priority(rule.get("priority")),
        "name": _text(rule.get("name"), 120),
        "from": _text(rule.get("from"), 64),
        "to": _text(rule.get("to"), 64),
        "action": _text(rule.get("action"), 32),
        "src": _addr_ref((rule.get("source") or {}).get("address")),
        "dst": _addr_ref((rule.get("destination") or {}).get("address")),
        "svc": _addr_ref(rule.get("service")),
        "enabled": bool(rule.get("enable")),
        "logging": bool(rule.get("logging")),
        "comment": _text(rule.get("comment"), 200),
    }
    if not stats_available or stat is None:
        # Unknown, NOT zero. A 0 here reads as "this rule has never matched",
        # which is a finding; "we could not read the counters" is not.
        row.update(hits=None, bytes_in=None, bytes_out=None,
                   last_hit=None if stat is None and stats_available else "",
                   never_hit=None)
        row["last_hit"] = ""
        return row
    last = _text(stat.get("time_last_hit"), 40)
    row.update(
        hits=stat.get("usage"),
        bytes_in=stat.get("rxbytes"),
        bytes_out=stat.get("txbytes"),
        last_hit="" if last == NEVER_HIT else last,
        never_hit=(last == NEVER_HIT),
    )
    return row


def _read_rules(serial: str) -> tuple[list, dict, list]:
    """(config rules, {uuid: stats row}, areas_unavailable).

    The two reads run in parallel and are graded SEPARATELY. Config is
    load-bearing — no rules, no answer — but stats failing must not turn every
    rule into a zero-hit finding (two independent sources are
    never silently merged).
    """
    results, unavailable = _run_health_checks({
        "rules": lambda: {"data_status": "ok",
                          "payload": _device_json("access_rules", serial)},
        "stats": lambda: {"data_status": "ok",
                          "payload": _device_json("access_rules_stats", serial)},
    # The rulebase is the largest per-device read in the set — 260 KB and
    # 413 KB on the samples — so the 5 s default is too tight to be safe on a
    # busy box, and a timeout here would report "no rules" for the site with
    # the most rules.
    }, budget=CONFIG_READ_BUDGET, workers=2)
    if "rules" not in results:
        detail = next((a["detail"] for a in unavailable if a["area"] == "rules"),
                      "access-rules read failed")
        raise RuntimeError(f"access-rules/ipv4: {detail}")
    rules = _cfg_rule_list(results["rules"]["payload"])
    stats = {}
    if "stats" in results:
        for row in _first_list(results["stats"]["payload"]) or \
                (results["stats"]["payload"] or []):
            if isinstance(row, dict) and row.get("uuid"):
                stats[row["uuid"]] = row
    return rules, stats, [a for a in unavailable if a["area"] == "stats"]


@mcp.tool
@fleet_tool
def site_access_rules(site_or_serial: str, search: str = "", from_zone: str = "",
                      to_zone: str = "", action: str = "") -> dict:
    """The firewall rulebase at one site, with hit counts. Answers "what rules
    allow WAN to reach the DMZ at this site?" and "is anything still permitting
    RDP inbound?".

    LIVE read of the firewall's own configuration, joined to its statistics
    counters on rule uuid. Filters are applied by this server — the SonicOS API
    accepts no query parameters at all — so rule_count is always the site's
    real total and filtered_count is what matched.

    search matches rule name, comment, and the source/destination/service
    object names. from_zone / to_zone / action narrow further; all are
    case-insensitive. Rules are returned highest-priority first, capped at 50
    with truncated set.

    hits is the rule's match counter and last_hit its most recent match, or ""
    with never_hit true when SonicOS reports no match ever. If the statistics
    endpoint cannot be read, hits and never_hit come back NULL and the missing
    area is named in areas_unavailable — a zero would read as a finding.

    Zero matching rules is a real answer, not missing data. Pass a serial or a
    unique site-name fragment."""
    dev, early = _one_device(site_or_serial)
    if early:
        return early
    serial = dev["serialNumber"]

    rules, stats, unavailable = _read_rules(serial)
    stats_available = not unavailable
    rows = [_rule_row(r, stats.get(_text(r.get("uuid"), 64)), stats_available)
            for r in rules]

    pairs = Counter(f"{r['from']} -> {r['to']}" for r in rows)
    q = search.strip().lower()
    fz, tz, act = (from_zone.strip().lower(), to_zone.strip().lower(),
                   action.strip().lower())

    def keep(row: dict) -> bool:
        if fz and row["from"].lower() != fz:
            return False
        if tz and row["to"].lower() != tz:
            return False
        if act and row["action"].lower() != act:
            return False
        if q and q not in " ".join((row["name"], row["comment"], row["src"],
                                   row["dst"], row["svc"])).lower():
            return False
        return True

    matched = [r for r in rows if keep(r)]
    matched.sort(key=lambda r: (r["priority"] if isinstance(r["priority"], int)
                                else 10 ** 6, r["name"]))
    cfg_uuids = {r["uuid"] for r in rows if r["uuid"]}
    return {
        "data_status": "ok",
        "match_count": 1,
        "device": _dev_ident(dev),
        "data_source": "live read of the firewall config + its rule counters",
        "policy_mode": "classic",
        "rule_count": len(rows),
        "filtered_count": len(matched),
        "rules": matched[:MAX_RULES],
        "truncated": len(matched) > MAX_RULES,
        "zone_pair_counts": dict(pairs.most_common(MAX_ZONE_PAIRS)),
        "action_counts": dict(Counter(r["action"] for r in rows)),
        "disabled_count": sum(1 for r in rows if not r["enabled"]),
        "stats_joined_count": len(cfg_uuids & set(stats)),
        "stats_missing_count": len(cfg_uuids - set(stats)),
        "areas_unavailable": unavailable,
    }


@mcp.tool
@fleet_tool
def site_unused_rules(site_or_serial: str, min_age_days: int = 30) -> dict:
    """Rule-hygiene candidates at one site: rules SonicOS has never seen match,
    rules with no traffic since their counters were last cleared, and rules
    that are simply disabled.

    THE TWO "UNUSED" NUMBERS ARE DIFFERENT AND BOTH ARE REPORTED.
      never_hit  - time_last_hit is the "-" sentinel: SonicOS has no record of
                   this rule EVER matching.
      no_traffic_since_counters_cleared - the match counter is 0 but a real
                   last-hit timestamp exists. These rules HAVE matched; only
                   the volatile counters were reset (a reboot, or a manual
                   clear). On the NSA sample the two differ by 45 rules out of
                   239 — reporting the larger number as "never used" would be a
                   28% overstatement, so they are never merged.

    min_age_days only counts a never-hit rule if it was CREATED at least that
    long ago, so a rule added this morning is not proposed for deletion.

    LIVE read. not_covered names what this does NOT check — shadowed-rule
    analysis is not reachable read-only on this platform — so a short list is
    not read as a clean rulebase. Needs the statistics endpoint: without it
    there is no answer at all, and the tool says so rather than reporting every
    rule as unused."""
    dev, early = _one_device(site_or_serial)
    if early:
        return early
    serial = dev["serialNumber"]

    rules, stats, unavailable = _read_rules(serial)
    if unavailable:
        return {
            "data_status": "unavailable",
            "detail": ("this answer is entirely about rule hit counts and the "
                       "statistics endpoint could not be read: "
                       + (unavailable[0].get("detail") or "unknown error")
                       + ". Reporting every rule as unused would be worse than "
                         "reporting nothing."),
        }

    cutoff = datetime.now() - timedelta(days=max(int(min_age_days), 0))
    never, zero_counter, cleared, disabled = [], [], [], []
    too_new = 0
    for rule in rules:
        uuid = _text(rule.get("uuid"), 64)
        stat = stats.get(uuid)
        row = _rule_row(rule, stat, True)
        if not row["enabled"]:
            disabled.append(row)
        if stat is None:
            continue
        if not stat.get("usage"):
            # What the raw counter says. A SUPERSET of never_hit — kept so the
            # answer reconciles against the device, never as the headline.
            zero_counter.append(row)
        if row["never_hit"]:
            created = _sonicos_stamp(_text(stat.get("time_created"), 40))
            if created is not None and created > cutoff:
                too_new += 1
                continue
            row["created"] = _text(stat.get("time_created"), 40)
            never.append(row)
        elif not stat.get("usage"):
            # THE GAP, and the reason the two numbers are never merged: this
            # rule HAS matched traffic (it carries a real last-hit stamp) and
            # only its volatile counter was reset. 45 of the NSA sample's 239
            # rules land here — a 28% overstatement if counted as unused.
            cleared.append(row)

    for bucket in (never, zero_counter, cleared, disabled):
        bucket.sort(key=lambda r: r["name"])
    return {
        "data_status": "ok",
        "match_count": 1,
        "device": _dev_ident(dev),
        "data_source": "live read of the firewall config + its rule counters",
        "rule_count": len(rules),
        "min_age_days": min_age_days,
        # The defensible headline: SonicOS has no record of these EVER matching.
        "never_hit_count": len(never),
        "never_hit": never[:MAX_RULES],
        "never_hit_truncated": len(never) > MAX_RULES,
        "excluded_as_too_new": too_new,
        # The raw counter view, which is larger. Reported so the number can be
        # checked against the device, and labelled so it is not mistaken for
        # the one above.
        "no_traffic_since_counters_cleared_count": len(zero_counter),
        "no_traffic_since_counters_cleared": zero_counter[:MAX_RULES],
        # The difference between the two, made explicit rather than left for a
        # reader to derive: these rules HAVE matched traffic.
        "matched_before_counters_cleared_count": len(cleared),
        "matched_before_counters_cleared": cleared[:MAX_RULES],
        "disabled_count": len(disabled),
        "disabled": disabled[:MAX_RULES],
        # Deliberately NOT a sum of the buckets: they overlap (a disabled rule
        # is usually also never-hit), and adding them would overstate the work.
        "cleanup_candidate_count": len(never),
        "counter_note": (
            "never_hit_count is the number of rules SonicOS reports as having "
            "NEVER matched (time_last_hit is the '-' sentinel). "
            "no_traffic_since_counters_cleared_count is the larger raw figure "
            "from the match counter alone, and includes "
            f"{len(cleared)} rule(s) that HAVE matched traffic but whose "
            "counters were reset by a reboot or a manual clear. Use "
            "never_hit_count for a cleanup conversation."),
        "not_covered": RULE_HYGIENE_NOT_COVERED,
    }


# ------------------------------ NSM telemetry (D) — the CSV-in-JSON plane
#
# A THIRD SEAM. DEVICE_PATHS is SonicOS proxied per device by the X-Device-ID
# header; MANAGER_PATHS is NSM's own plane, scoped by query parameter and NO
# header. This family needs BOTH: the header is required (bearer alone times
# out) and the query parameters are required too. Hence its own path table and
# its own upstream function.
MANAGER_DEVICE_PATHS = {
    # NSM's COLLECTED event log. Longer retention than the on-box log
    # site_event_log reads. 13 KB / 1.67 MB / 11 KB on the samples probed.
    "sysevent_logs": "/api/manager/systemevent/logs",
    # The attack analytics family. Six sub-paths exist and all six are
    # verified.
    "sysevent_initiators": "/api/manager/systemevent/analytics/initiators",
    "sysevent_targets": "/api/manager/systemevent/analytics/targets",
    "sysevent_fwaction": "/api/manager/systemevent/analytics/fwaction",
    "sysevent_portsinfo": "/api/manager/systemevent/analytics/portsinfo",
    "sysevent_initcountry": "/api/manager/systemevent/analytics/initcountry",
    "sysevent_respcountry": "/api/manager/systemevent/analytics/respcountry",
    # Analyzer NG. ONE path, selected by tableType.
    "ang_report": "/api/manager/ang/report",
}

# /systemevent/* answers HTTP 422 naming exactly one missing parameter per
# response if ANY of these is absent. Discovered by walking the ladder;
# kept as a constant so adding a rung is a one-line edit.
#
# NOTE: `limit` here does NOT bound the row count. Sent as "50", one sample
# still returned 3,140 rows in a 1.67 MB payload. The swagger types `limit` as
# a BOOLEAN gate, not a count — which is the same trap that made /ang/report
# return only its aggregate row. Every cap in these tools is client-side.
SYSEVENT_REQUIRED_PARAMS = {"limit": "50", "sort": "time"}

# /ang/report tableType. The swagger documents 1-14; 11 (destination
# addresses) and 13 (blocked) both answered on every sample probed despite
# being poorly documented.
#
# tableType 3 (source addresses) TIMED OUT on the busiest sample at both 20 s
# and 60 s while answering in 5 s and 17 s on the other two. That is a platform
# limit on a busy box, not a harness defect, so `sources` is expected to be
# unavailable at large sites and says so rather than returning nothing.
ANG_TABLES = {
    "apps": (1, "_totalBytes"),
    "users": (2, "_totalBytes"),
    "sources": (3, "_totalBytes"),
    "destinations": (11, "_totalBytes"),
    "locations": (7, "_totalBytes"),
    "blocked": (13, "_totalBlocked"),
    "viruses": (4, "_threatsBlocked"),
    "intrusions": (5, "_threatsBlocked"),
    "spyware": (6, "_threatsBlocked"),
    "botnet": (8, "_botBlocked"),
    "web_categories": (9, "_totalBytes"),
}
ANG_CALL_TIMEOUT = 45
# Parallel-read budgets for this plane. The _run_health_checks default of 5 s
# is calibrated for SonicOS per-device reads (200-500 ms); /ang/report measured
# 1.6-18.5 s across the samples. One worker per section so a five-section read
# is one wave rather than two, and a budget that fits inside typical
# chat-client connector timeouts.
ANG_PARALLEL_BUDGET = 40.0
SYSEVENT_PARALLEL_BUDGET = 25.0
MAX_EVENT_ROWS = 100
MAX_TOP_N = 50
# The aggregate row every /ang/report answer carries. It is the fleet total for
# the window, not a data row, and must never appear in a top-N list.
ANG_TOTAL_ROW = "Total"


def _upstream_manager_device_json(path: str, serial: str,
                                  params: dict | None = None):
    """One manager-plane GET WITH the device header. The monkeypatch seam every
    offline telemetry test replaces."""
    return SESSION.get(path, serial=serial, params=params,
                       timeout=ANG_CALL_TIMEOUT)


def _manager_device_payload(key: str, serial: str, params: dict | None = None):
    path = MANAGER_DEVICE_PATHS[key]
    cache_key = f"mgrdev|{key}|{serial}|" + json.dumps(params or {},
                                                      sort_keys=True)
    payload = _cached(cache_key,
                      lambda: _upstream_manager_device_json(path, serial,
                                                            params))
    err = _api_error(payload)
    if err:
        raise ManagerError(f"{path}: {err}")
    return payload


def parse_csv_entries(payload) -> tuple[list, list, int]:
    """The CSV-in-JSON parser. Built ONCE here and reused by every tool in this
    family.

    `entries` is a SINGLE STRING holding a whole table:
        header,names,comma,separated|row1,cell,cell|row2,cell,cell
    Rows are `|`-separated, cells are `,`-separated, and every cell is
    URL-encoded.

    SPLIT FIRST, DECODE SECOND. This is not a style preference. Live payloads
    carry cells like `_combinesrc` = `203.0.113.49%2CX1` — an IP and an
    interface joined by an ENCODED comma. Decode before splitting and that one
    cell becomes two, shifting all 64 columns right by one from that row on:
    source IPs land in the destination column and the answer is confidently
    wrong rather than obviously broken.

    Returns (header, rows, dropped). Rows whose arity disagrees with the header
    are DROPPED and counted rather than zipped short — a truncated row silently
    misaligns every field after the gap. Arity agreed on every sample checked,
    so a non-zero `dropped` is a signal worth surfacing, not routine noise.
    """
    raw = (payload or {}).get("entries")
    if not isinstance(raw, str) or not raw:
        return [], [], 0
    chunks = raw.split("|")
    header = [_decode_cell(h) for h in chunks[0].split(",")]
    rows, dropped = [], 0
    for chunk in chunks[1:]:
        if not chunk:
            continue
        cells = chunk.split(",")
        if len(cells) != len(header):
            dropped += 1
            continue
        rows.append([_decode_cell(c) for c in cells])
    return header, rows, dropped


def _decode_cell(cell: str) -> str:
    """One cell: URL-decode, then strip the literal double quotes /ang/report
    wraps its DETAIL rows in. The aggregate row is unquoted, which is a handy
    second signal for telling them apart."""
    text = urllib.parse.unquote_plus(cell or "")
    if len(text) >= 2 and text[0] == '"' and text[-1] == '"':
        return text[1:-1]
    return text


def rows_as_dicts(header: list, rows: list) -> list:
    return [dict(zip(header, row)) for row in rows]


def _int_ip(value: str) -> str:
    """`_srcip` and `_dstip` arrive as 32-BIT INTEGERS, not dotted quads:
    3325256746 is 198.51.100.42. Returned as text so the answer is readable;
    an unconvertible value passes through rather than becoming empty."""
    text = (value or "").strip()
    if not text.isdigit():
        return text
    try:
        return str(ipaddress.IPv4Address(int(text)))
    except (ipaddress.AddressValueError, ValueError):
        return text


def _num(value):
    """CSV cells are all strings. Non-numeric stays None so a missing counter
    is never rendered as 0."""
    text = (value or "").strip()
    if not text or text in ("-", "NA"):
        return None
    try:
        return int(text)
    except ValueError:
        try:
            return float(text)
        except ValueError:
            return None


EVENT_COLLECTED_NOTE = (
    "COLLECTED from NSM, not read from the firewall. A firewall that has "
    "STOPPED REPORTING to NSM returns an empty window that is indistinguishable "
    "from a genuinely quiet site, so device_online and the row counts must be "
    "read together: 0 events from an offline firewall is not evidence of quiet."
)

# `_fwaction` is present in the 64-column event schema and is the string "0" on
# every one of the 3,184 rows across all three samples. It is NOT a usable
# action field on this platform. The block/drop evidence lives in `_notes`
# ("Pkt is dropped. UDP scanned port list, ...") and `_msg`, so
# is_traffic_blocked greps those and this constant records why.
DROP_MARKERS = ("dropped", "denied", "blocked", "reset")


def _event_row(rec: dict) -> dict:
    """One projected event from the 64-column schema.

    `_combinesrc` / `_combinedst` carry "ip,interface" and are the readable
    form; `_srcip` / `_dstip` are 32-bit integers. Both are used: the combine
    field for the interface, the int field converted for the address, so a
    malformed combine cell cannot lose the IP.
    """
    src_combined = (rec.get("_combinesrc") or "").split(",")
    dst_combined = (rec.get("_combinedst") or "").split(",")
    ts = _num(rec.get("_timestamp")) or 0
    return {
        "time": ts,
        "time_utc": _epoch_iso(ts),
        "category": _text(rec.get("_catname"), 80),
        "group": _text(rec.get("_grpname"), 80),
        "event": _text(rec.get("_evtname"), 120),
        "priority": _num(rec.get("_prio")),
        "src": _int_ip(rec.get("_srcip")),
        "src_name": _text(rec.get("_srcName"), 160),
        "src_port": _num(rec.get("_srcport")),
        "src_interface": src_combined[1] if len(src_combined) > 1 else "",
        "src_zone": _text(rec.get("_srczone"), 40),
        "dst": _int_ip(rec.get("_dstip")),
        "dst_port": _num(rec.get("_dstport")),
        "dst_interface": dst_combined[1] if len(dst_combined) > 1 else "",
        "dst_zone": _text(rec.get("_dstzone"), 40),
        "app": _text(rec.get("_appname"), 120),
        "message": _text(rec.get("_msg"), 200),
        "notes": _text(rec.get("_notes"), 200),
    }


def _sysevent_params(hours: int, event_type: str) -> dict:
    return dict(SYSEVENT_REQUIRED_PARAMS,
                type=event_type, start_ts=_window_start(hours),
                end_ts=int(time.time()))


@mcp.tool
@fleet_tool
def site_system_events(site_or_serial: str, hours: int = 24,
                       search: str = "", event_type: str = "all") -> dict:
    """What the firewall has reported to NSM recently: attacks detected, port
    scans, floods, firewall-setting changes. The longer-retention counterpart
    to site_event_log, which reads the small on-box buffer instead.

    COLLECTED from NSM — see collection_note. A firewall that stopped reporting
    looks exactly like a quiet one unless you read device_online too, so both
    are in the payload.

    hours defaults to 24. event_type is 'all', 'attacks' or 'flood-protection'.
    search matches the event name, message, notes, app and either address.

    total_rows is everything NSM returned for the window; events is capped at
    100 with truncated set. NSM's own `limit` parameter does NOT bound the row
    count — one sample returned 3,140 rows in a 1.67 MB payload against
    limit=50 — so the cap here is applied by this server.

    top_events and top_sources summarise the WHOLE window, not just the capped
    page, so the counts stay right when truncated is true.

    NOTE: this platform's event records carry no usable firewall-action field
    (`_fwaction` is "0" on every row in this tenant). Whether a packet was
    dropped is stated in the event's own message and notes text, which is what
    is_traffic_blocked reads."""
    dev, early = _one_device(site_or_serial)
    if early:
        return early
    serial = dev["serialNumber"]
    kind = (event_type or "all").strip().lower()
    if kind not in ("all", "attacks", "flood-protection"):
        return {"data_status": "ok", "match_count": 1,
                "device": _dev_ident(dev), "event_count": 0, "events": [],
                "detail": ("event_type must be 'all', 'attacks' or "
                           f"'flood-protection'; got {event_type!r}")}

    payload = _manager_device_payload("sysevent_logs", serial,
                                      _sysevent_params(hours, kind))
    header, rows, dropped = parse_csv_entries(payload)
    records = [_event_row(r) for r in rows_as_dicts(header, rows)]

    q = search.strip().lower()
    if q:
        matched = [r for r in records
                   if q in " ".join((r["event"], r["message"], r["notes"],
                                     r["app"], r["src"], r["dst"],
                                     r["src_name"])).lower()]
    else:
        matched = records
    matched.sort(key=lambda r: r["time"], reverse=True)

    return {
        "data_status": "ok",
        "match_count": 1,
        "device": _dev_ident(dev),
        "device_online": bool(dev.get("liveStatus")),
        "data_source": "collected",
        "collection_note": EVENT_COLLECTED_NOTE,
        "window_hours": hours,
        "event_type": kind,
        "total_rows": len(records),
        "filtered_count": len(matched),
        "events": matched[:MAX_EVENT_ROWS],
        "truncated": len(matched) > MAX_EVENT_ROWS,
        # Computed over every row in the window, so they remain correct when
        # the event list above is truncated.
        "top_events": [{"event": k, "count": v} for k, v in
                       Counter(r["event"] for r in matched
                               if r["event"]).most_common(10)],
        "top_sources": [{"src": k, "count": v} for k, v in
                        Counter(r["src"] for r in matched
                                if r["src"]).most_common(10)],
        "categories": dict(Counter(r["category"] for r in matched
                                   if r["category"])),
        "malformed_rows_dropped": dropped,
        "column_count": len(header),
    }


# The analytics family's three dead counters. Verified 0 in 869 of 869 rows
# across all three samples and every sub-path: _txbytes, _rxpkts and _txpkts
# are never populated, and _ipver is always 0 (never 4 or 6).
#
# They are NOT projected. A "bytes out: 0" beside a real bytes-in figure reads
# as "nothing was uploaded", which is a claim this data cannot support.
ANALYTICS_DEAD_COLUMNS = ("_txbytes", "_rxpkts", "_txpkts", "_ipver")

ATTACK_NOT_COVERED = [
    {"area": "bytes_out_and_packet_counts",
     "reason": ("_txbytes, _rxpkts and _txpkts are 0 on every row of every "
                "analytics sub-path on all three samples (869/869 rows, "
                "2026-08-31), and _ipver is always 0. They are not projected: "
                "reporting bytes_out 0 next to a real bytes_in would read as "
                "'nothing was uploaded', which this data cannot support. Only "
                "event counts and bytes IN carry signal.")},
]

_ATTACK_AREAS = {
    "initiators": ("sysevent_initiators", "_srcip", "_srchost"),
    "targets": ("sysevent_targets", "_dstip", "_dsthost"),
    "ports": ("sysevent_portsinfo", "_dstport", "_srcport"),
    "source_countries": ("sysevent_initcountry", "_srclocname", "_srclocid"),
    "target_countries": ("sysevent_respcountry", "_dstlocname", "_dstlocid"),
    "firewall_actions": ("sysevent_fwaction", "_fwaction", ""),
}


def _attack_rows(key: str, serial: str, hours: int, label: str,
                 second: str) -> list:
    payload = _manager_device_payload(key, serial,
                                      _sysevent_params(hours, "attacks"))
    header, rows, _ = parse_csv_entries(payload)
    out = []
    for rec in rows_as_dicts(header, rows):
        value = _text(rec.get(label), 120)
        if label in ("_srcip", "_dstip"):
            value = _int_ip(rec.get(label))
        row = {"value": value,
               "events": _num(rec.get("_events")),
               "bytes_in": _num(rec.get("_rxbytes"))}
        if second:
            detail = _text(rec.get(second), 120)
            if second in ("_srcport",):
                row["src_port"] = detail
            elif second.endswith("locid"):
                row["location_id"] = detail
            else:
                row["hostname"] = detail
        out.append(row)
    out.sort(key=lambda r: (r["events"] or 0), reverse=True)
    return out


@mcp.tool
@fleet_tool
def site_attack_summary(site_or_serial: str, hours: int = 24) -> dict:
    """What has been attacking this site, and what it aimed at: the top
    initiator addresses, the targets they hit, the ports involved, the source
    and destination countries, and the actions the firewall recorded.

    COLLECTED from NSM — see collection_note; an offline firewall reports an
    empty window that looks identical to a quiet one.

    Every section is read separately and graded separately: a section that
    could not be read is named in areas_unavailable rather than rendered as
    empty. Zero attackers is a real answer.

    Counts are EVENT counts and bytes are inbound only. not_covered explains
    why: the outbound-byte and packet columns are zero on every row this
    platform serves, so reporting them would assert something the data cannot
    support."""
    dev, early = _one_device(site_or_serial)
    if early:
        return early
    serial = dev["serialNumber"]

    results, unavailable = _run_health_checks({
        area: (lambda k=key, lb=label, sc=second:
               {"data_status": "ok",
                "rows": _attack_rows(k, serial, hours, lb, sc)})
        for area, (key, label, second) in _ATTACK_AREAS.items()
    }, budget=SYSEVENT_PARALLEL_BUDGET, workers=len(_ATTACK_AREAS))
    if not results:
        return {"data_status": "unavailable",
                "detail": "no attack-analytics section could be read: "
                          + "; ".join(a["detail"] for a in unavailable)}

    sections = {area: res["rows"][:MAX_TOP_N] for area, res in results.items()}
    counts = {area: len(res["rows"]) for area, res in results.items()}
    initiators = results.get("initiators", {}).get("rows") or []
    return {
        "data_status": "ok",
        "match_count": 1,
        "device": _dev_ident(dev),
        "device_online": bool(dev.get("liveStatus")),
        "data_source": "collected",
        "collection_note": EVENT_COLLECTED_NOTE,
        "window_hours": hours,
        "attacker_count": counts.get("initiators"),
        "total_attack_events": sum(r["events"] or 0 for r in initiators)
        if "initiators" in results else None,
        "sections": sections,
        "section_row_counts": counts,
        "areas_unavailable": unavailable,
        "not_covered": ATTACK_NOT_COVERED,
    }


# --------------------------------------- is_traffic_blocked — EVIDENCE
#
# THIS IS EVIDENCE RETRIEVAL, NOT POLICY SIMULATION. It reports what the
# firewall has RECORDED, and names every reason the record might be silent. It
# does not evaluate the rulebase, and it cannot tell you traffic is allowed.
#
# Three findings shape it:
#
# 1. `_fwaction` IS UNUSABLE. The obvious design would filter events on
#    fw_action in (drop, deny, reset). That column was the string "0" on
#    every event row across all samples probed. The drop evidence is in the
#    event's own `_notes` ("Pkt is dropped. UDP scanned port list, ...") and
#    `_msg` text, so those are what is matched.
#
# 2. A live per-connection read DOES NOT EXIST. A "show whether a
#    connection currently exists" step is not buildable:
#    reporting/firewall/connection-status returns a fixed four-row CAPACITY
#    matrix (maximum_spi_connections and friends), byte-identical on two
#    different sites, and no per-flow read exists anywhere in the 1772-path
#    SonicOS swagger — the connection-cache paths are DELETE-only.
#
# 3. THIS LOG IS NOT A CONNECTION LOG. `_catname` was only ever "Security
#    Services" or "Firewall Settings": attacks, port scans and floods.
#    Ordinary permitted traffic leaves no row here at all. So `no_evidence` is
#    the NORMAL answer for a working connection, and rendering it as "allowed"
#    would be the single most dangerous thing this tool could do.
#
# Hence: the verdict vocabulary has no "allowed" value, and the caveat is in
# the PAYLOAD, not only in the docstring.

TRAFFIC_VERDICTS = ("blocked_evidence", "no_evidence")

TRAFFIC_NOT_COVERED = [
    {"area": "live_connection_state",
     "reason": ("this platform exposes no live per-connection table. "
                "reporting/firewall/connection-status returns a fixed 4-row "
                "capacity matrix (SPI/DPI connection ceilings), identical on "
                "different sites; the per-connection cache endpoints are "
                "DELETE-only. Nothing here can say whether a session is open "
                "right now.")},
    {"area": "policy_simulation",
     "reason": ("no rulebase evaluation is performed. matching_rules is a "
                "best-effort shortlist by service and zone, not a decision: "
                "address-object contents are not read, "
                "so a rule whose source is a named object cannot be "
                "confirmed to cover the address you asked about.")},
]


def _port_matches(service: str, port: str) -> bool:
    """Best-effort: 'any' covers everything, otherwise the port must appear in
    the service name. Deliberately loose — this feeds a SHORTLIST that the
    payload labels as unconfirmed, not a verdict."""
    if not port:
        return True
    low = (service or "").lower()
    return low == "any" or port in low


@mcp.tool
@fleet_tool
def is_traffic_blocked(site_or_serial: str, src: str = "", dst: str = "",
                       port: str = "", hours: int = 1) -> dict:
    """Has this firewall RECORDED blocking traffic matching src / dst / port?

    EVIDENCE RETRIEVAL, NOT A POLICY DECISION. Two verdicts only:

      blocked_evidence  the firewall logged one or more drops matching your
                        filter. drop_events carries them.
      no_evidence       nothing matching was logged in the window.

    THERE IS DELIBERATELY NO "allowed" VERDICT. no_evidence does NOT mean the
    traffic is permitted. Read caveat and evidence_gaps in the payload before
    concluding anything: NSM's collected log holds attack, scan and flood
    events, not a record of ordinary permitted traffic, so a perfectly healthy
    connection leaves no row here at all. Silence is silence.

    Supply at least one of src, dst or port. hours defaults to 1.

    matching_rules is a SHORTLIST of access rules that could be relevant, by
    service and zone. It is not a decision and rules whose source or
    destination is a named address object are marked unconfirmed — the object's
    contents are not read. Any shortlisted rule with logging disabled is called
    out in evidence_gaps, because that is a concrete reason a real block would
    leave no evidence.

    not_covered names what this cannot see at all, including live connection
    state, which this platform does not expose."""
    dev, early = _one_device(site_or_serial)
    if early:
        return early
    if not any((src.strip(), dst.strip(), port.strip())):
        return {"data_status": "ok", "match_count": 1,
                "device": _dev_ident(dev), "verdict": "no_evidence",
                "detail": ("supply at least one of src, dst or port — an "
                           "unfiltered question would return the whole event "
                           "window, which is not an answer.")}
    serial = dev["serialNumber"]
    want_src, want_dst, want_port = (src.strip(), dst.strip(), port.strip())

    results, unavailable = _run_health_checks({
        "events": lambda: {"data_status": "ok",
                           "payload": _manager_device_payload(
                               "sysevent_logs", serial,
                               _sysevent_params(hours, "all"))},
        "rules": lambda: {"data_status": "ok",
                          "payload": _device_json("access_rules", serial)},
    }, budget=SYSEVENT_PARALLEL_BUDGET, workers=2)

    drops, matched_events = [], 0
    if "events" in results:
        header, rows, _ = parse_csv_entries(results["events"]["payload"])
        for rec in rows_as_dicts(header, rows):
            row = _event_row(rec)
            if want_src and want_src not in (row["src"], row["src_name"]):
                continue
            if want_dst and want_dst != row["dst"]:
                continue
            if want_port and want_port not in (str(row["src_port"]),
                                               str(row["dst_port"])):
                continue
            matched_events += 1
            haystack = f"{row['notes']} {row['message']} {row['event']}".lower()
            if any(marker in haystack for marker in DROP_MARKERS):
                drops.append(row)
    drops.sort(key=lambda r: r["time"], reverse=True)

    shortlist, unlogged = [], []
    if "rules" in results:
        for rule in _cfg_rule_list(results["rules"]["payload"]):
            if not rule.get("enable"):
                continue
            svc = _addr_ref(rule.get("service"))
            if not _port_matches(svc, want_port):
                continue
            rule_src = _addr_ref((rule.get("source") or {}).get("address"))
            rule_dst = _addr_ref((rule.get("destination") or {}).get("address"))
            # Only rules that could plausibly cover the endpoints: "any", or a
            # named object whose contents we cannot read (so, unconfirmed).
            confirmed = rule_src == "any" and rule_dst == "any"
            row = {
                "name": _text(rule.get("name"), 120),
                "priority": _rule_priority(rule.get("priority")),
                "from": _text(rule.get("from"), 64),
                "to": _text(rule.get("to"), 64),
                "action": _text(rule.get("action"), 32),
                "src": rule_src, "dst": rule_dst, "svc": svc,
                "logging": bool(rule.get("logging")),
                "coverage": "confirmed" if confirmed else "unconfirmed",
            }
            shortlist.append(row)
            if not row["logging"] and row["action"] == "deny":
                unlogged.append(row["name"])

    verdict = "blocked_evidence" if drops else "no_evidence"
    gaps = []
    if verdict == "no_evidence":
        gaps.append("NSM's collected log records attack, scan and flood events "
                    "— not ordinary permitted or denied traffic — so an "
                    "absence of rows here is expected even for traffic the "
                    "firewall is actively dropping.")
        if not dev.get("liveStatus"):
            gaps.append("this firewall is OFFLINE in NSM, so it may not have "
                        "reported any events for this window at all.")
        if unlogged:
            gaps.append("deny rule(s) with LOGGING DISABLED could match this "
                        "traffic and would leave no evidence: "
                        + ", ".join(sorted(set(unlogged))[:10]))
        for area in unavailable:
            gaps.append(f"{area['area']} could not be read "
                        f"({area['detail']}), so that source was not searched.")

    return {
        "data_status": "ok",
        "match_count": 1,
        "device": _dev_ident(dev),
        "device_online": bool(dev.get("liveStatus")),
        "data_source": "collected events + live rule configuration",
        "window_hours": hours,
        "query": {"src": want_src, "dst": want_dst, "port": want_port},
        "verdict": verdict,
        "caveat": ("no_evidence means NOTHING MATCHING WAS LOGGED. It is not a "
                   "statement that the traffic is allowed, and it must not be "
                   "reported as one. See evidence_gaps."),
        "events_matching_filter": matched_events,
        "drop_event_count": len(drops),
        "drop_events": drops[:MAX_EVENT_ROWS],
        "drop_events_truncated": len(drops) > MAX_EVENT_ROWS,
        "matching_rule_count": len(shortlist),
        "matching_rules": shortlist[:MAX_RULES],
        "rule_shortlist_note": ("a shortlist by service and zone, not a "
                                "decision; rules marked coverage "
                                "'unconfirmed' reference named address objects "
                                "whose contents were not read."),
        "evidence_gaps": gaps,
        "areas_unavailable": unavailable,
        "not_covered": TRAFFIC_NOT_COVERED,
    }


# ------------------------- Analyzer NG traffic + threat reports
#
# THE TRAP THAT COST A WHOLE PROBE RUN. /ang/report answered HTTP 200 for
# tableTypes 1-9 on all three samples and looked VERIFIED. Every response
# carried exactly ONE row: `_index=1,_elemId=-1,_name=Total`. No apps, no
# addresses, no signatures — the window aggregate and nothing else, from an
# endpoint reporting 2.4 million flows and 110 GB.
#
# CAUSE: `limit` is a BOOLEAN ("whether there should be a limit to the number
# of entries to fetch") and it GATES `limitCount`. Sending limitCount alone
# asks for the summary. So every call here sends limit=true, sort=true, a
# sortBy, and descending — which is also what makes top-N a real top-N rather
# than an arbitrary twenty.
#
# The aggregate row still arrives, mixed in with the detail rows. It is split
# out as `window_total` and must never appear in a ranked list: it would sit at
# position one with the sum of everything below it.

# tableType 2's `_name` column is the username carrier. On a tenant where SSO
# is not identifying users to Analytics it reads "Unknown" on every row and
# there is no personal data to redact. The flag ships anyway, because
# the field WILL populate the moment SSO is wired up, and the agent layer needs
# something to gate on before that happens rather than after.
ANG_PERSONAL_DATA_TABLES = {"users"}
ANG_PRIVACY_NOTE = (
    "This table is keyed by USER IDENTITY and is personal data. Answer it only "
    "for the asker's own site or a named ticket; never volunteer a named "
    "individual's activity in a group chat, and never return one site's users "
    "in answer to a question about another site."
)

_ANG_THREAT_TABLES = ("viruses", "intrusions", "spyware", "botnet",
                      "web_categories")


def _ang_rows(table: str, serial: str, hours: int, top: int) -> tuple[list, dict]:
    """(detail rows, window_total). Raises for an unreadable table."""
    table_type, sort_by = ANG_TABLES[table]
    payload = _manager_device_payload("ang_report", serial, {
        "tableType": str(table_type),
        "serialnum": serial,
        "start_ts": _window_start(hours),
        "end_ts": int(time.time()),
        # limit is the BOOLEAN gate; without it only the aggregate comes back.
        "limit": "true",
        "limitCount": str(max(1, min(int(top), MAX_TOP_N))),
        "sort": "true",
        "sortBy": sort_by,
        "descending": "true",
    })
    header, rows, _ = parse_csv_entries(payload)
    detail, total = [], {}
    for rec in rows_as_dicts(header, rows):
        row = {
            "name": _text(rec.get("_name"), 160),
            "sessions": _num(rec.get("_flows")),
            "bytes_total": _num(rec.get("_totalBytes")),
            "bytes_up": _num(rec.get("_initBytes")),
            "bytes_down": _num(rec.get("_respBytes")),
            "blocked_total": _num(rec.get("_totalBlocked")),
            "threats_blocked": _num(rec.get("_threatsBlocked")),
            "gav_hits": _num(rec.get("_gavCount")),
            "ips_hits": _num(rec.get("_ipsCount")),
            "spyware_hits": _num(rec.get("_aspyCount")),
            "geo_blocked": _num(rec.get("_geoBlocked")),
            "botnet_blocked": _num(rec.get("_botBlocked")),
            "cfs_blocked": _num(rec.get("_cfsBlocked")),
        }
        # The aggregate row: _elemId -1 and an unquoted "Total" label. Split
        # out so it cannot head a ranked list with the sum of everything in it.
        if row["name"] == ANG_TOTAL_ROW and _num(rec.get("_elemId")) == -1:
            total = row
            continue
        detail.append(row)
    return detail, total


@mcp.tool
@fleet_tool
def site_traffic_report(site_or_serial: str, hours: int = 24,
                        table: str = "apps", top: int = 20) -> dict:
    """What is using this site's bandwidth: the top applications, source or
    destination addresses, countries, or blocked traffic, with sessions and
    bytes for each.

    COLLECTED from NSM's analytics store — see collection_note. It depends on
    the firewall reporting in, so a site that stopped reporting shows an empty
    window that looks identical to an idle one.

    table is one of: apps, sources, destinations, locations, blocked, users.
    hours defaults to 24, top to 20 (max 50).

    window_total is the aggregate for the whole window and is reported
    SEPARATELY from rows — it is not the busiest application, it is the sum of
    everything.

    bytes_up + bytes_down = bytes_total, verified on every sample, so the
    upload/download split needs no second call.

    table='sources' is the slowest query on this platform and TIMES OUT on
    busy sites (60 s exceeded on the busiest sample). If it does, this returns
    data_status unavailable naming the timeout; 'destinations' answers the
    same question from the far end and is reliable.

    table='users' is PERSONAL DATA — see privacy_note. If the user column
    reads 'Unknown' on every row, SSO is not identifying users to
    Analytics, which is itself the answer to "who was using the bandwidth?"."""
    dev, early = _one_device(site_or_serial)
    if early:
        return early
    serial = dev["serialNumber"]
    key = (table or "apps").strip().lower()
    if key not in ANG_TABLES:
        return {"data_status": "ok", "match_count": 1,
                "device": _dev_ident(dev), "rows": [],
                "detail": (f"table must be one of "
                           f"{', '.join(sorted(ANG_TABLES))}; got {table!r}")}

    rows, total = _ang_rows(key, serial, hours, top)
    payload = {
        "data_status": "ok",
        "match_count": 1,
        "device": _dev_ident(dev),
        "device_online": bool(dev.get("liveStatus")),
        "data_source": "collected",
        "collection_note": EVENT_COLLECTED_NOTE,
        "window_hours": hours,
        "table": key,
        "row_count": len(rows),
        "rows": rows[:MAX_TOP_N],
        "window_total": total,
        "personal_data": key in ANG_PERSONAL_DATA_TABLES,
    }
    if key in ANG_PERSONAL_DATA_TABLES:
        payload["privacy_note"] = ANG_PRIVACY_NOTE
        identified = [r for r in rows if r["name"].lower() != "unknown"]
        payload["identified_user_count"] = len(identified)
        if not identified:
            payload["user_attribution"] = (
                "no user identity is attached to this site's traffic — every "
                "row is 'Unknown', which means SSO is not reporting user "
                "identity to NSM Analytics. This is a configuration answer, "
                "not an absence of data.")
    return payload


@mcp.tool
@fleet_tool
def site_threat_report(site_or_serial: str, hours: int = 24) -> dict:
    """What the firewall stopped at this site: viruses, intrusions, spyware,
    botnet traffic and blocked web categories, with counts for each.

    COLLECTED from NSM's analytics store — see collection_note. An offline
    firewall produces an empty report that looks identical to a clean one, so
    device_online is in the payload.

    Each of the five sections is a separate read, graded separately: a section
    that could not be read is named in areas_unavailable rather than shown as
    empty. Zero threats in a section is a real answer — several sections are
    genuinely zero across this whole tenant, which is worth saying plainly
    rather than hiding.

    sections_with_zero_events lists the sections that answered but found
    nothing, so 'no viruses' is visibly different from 'viruses not checked'."""
    dev, early = _one_device(site_or_serial)
    if early:
        return early
    serial = dev["serialNumber"]

    results, unavailable = _run_health_checks({
        table: (lambda t=table: {"data_status": "ok",
                                 "rows": _ang_rows(t, serial, hours,
                                                   MAX_TOP_N)[0]})
        for table in _ANG_THREAT_TABLES
    }, budget=ANG_PARALLEL_BUDGET, workers=len(_ANG_THREAT_TABLES))
    if not results:
        return {"data_status": "unavailable",
                "detail": "no threat section could be read: "
                          + "; ".join(a["detail"] for a in unavailable)}

    sections, zero, counts = {}, [], {}
    for table, res in results.items():
        rows = res["rows"]
        sections[table] = rows[:MAX_TOP_N]
        counts[table] = len(rows)
        if not rows:
            zero.append(table)
    return {
        "data_status": "ok",
        "match_count": 1,
        "device": _dev_ident(dev),
        "device_online": bool(dev.get("liveStatus")),
        "data_source": "collected",
        "collection_note": EVENT_COLLECTED_NOTE,
        "window_hours": hours,
        "sections": sections,
        "section_row_counts": counts,
        # Answered-and-empty, kept explicitly apart from not-answered below.
        "sections_with_zero_events": sorted(zero),
        "sections_checked": sorted(results),
        "areas_unavailable": unavailable,
    }


# -------------------------------- SSL-VPN + management exposure
#
# THE TWO MOST CREDENTIAL-DENSE READS IN THE SET. Live payloads were observed
# carrying seven populated secret fields across these endpoints:
#   snmp.get_community_name                 observed IDENTICAL across
#                                           samples — the unchanged vendor
#                                           default, and set even where SNMP
#                                           is disabled
#   snmp.trap_community_name                present, empty here
#   user.local.user[].password              long hashes, per user
#   zones[].guest_services.external_auth.message_auth.shared_secret
#   ...                                    .confirm_secret
#   zones[].local_radius_server.client_password
#   zones[].local_radius_server.ldap_server.identity_dn_password
#
# So every projection below is an ALLOW-LIST of named leaves, never a recursive
# walk with exclusions. Both endpoints have ragged, per-device schemas — one
# sample's zone list had 11 entries where another had 7, and `password` is
# absent (not empty) on LDAP-sourced users — so a deny-list is one firmware
# change away from emitting a secret it has never heard of. Assert the
# absence of each secret BY VALUE, not by key name, when testing.

MAX_ADMINS = 50
MAX_MGMT_RULES = 50

SSL_VPN_NOT_COVERED = [
    {"area": "cipher_suite",
     "reason": ("no 'cipher' field exists in the ssl-vpn/server/base payload "
                "on any sample probed. Nothing here reports the TLS cipher or "
                "protocol version the portal negotiates.")},
    {"area": "client_route_list",
     "reason": ("ssl-vpn/client-settings answers "
                "HTTP 200 with the error body 'path /ssl-vpn/client-settings "
                "was not found'. Tunnel-all vs split routes live in "
                "ssl-vpn/device-profiles, which this server does not read.")},
]


def _device_json_or_none(key: str, serial: str):
    """A read whose failure is a NAMED unavailable area, not an exception.

    Returns (payload, error). The caller must keep the two apart: a None
    payload means "not read", and every field derived from it stays None
    rather than falling back to a default that reads as a clean result.
    """
    try:
        return _device_json(key, serial), ""
    except Exception as exc:  # noqa: BLE001 — the area report IS the handler
        return None, f"{type(exc).__name__}: {exc}"


def _read_areas(serial: str, keys: tuple) -> tuple[dict, list]:
    """Parallel per-device reads, each graded on its own."""
    results, unavailable = _run_health_checks({
        key: (lambda k=key: {"data_status": "ok",
                             "payload": _device_json(k, serial)})
        for key in keys
    }, budget=CONFIG_READ_BUDGET, workers=max(len(keys), 1))
    return ({k: v["payload"] for k, v in results.items()}, unavailable)


def _local_user_rows(payload) -> list:
    """user.local.user[], via .get at every level.

    One sample returns {"user": {"local": {}}} — a successful response with no
    users. `payload["user"]["local"]["user"]` raises KeyError there, and an
    exception would be reported as "could not read the users" when the true
    answer is "there are none".
    """
    local = ((payload or {}).get("user") or {}).get("local") or {}
    return [u for u in (local.get("user") or []) if isinstance(u, dict)]


@mcp.tool
@fleet_tool
def site_ssl_vpn_config(site_or_serial: str) -> dict:
    """Is SSL-VPN switched on at this site, and is it reachable from the
    internet? The question that decides whether the fleet's SSL-VPN advisories
    (SNWLID-2025-0016 pre-auth overflow, -0009, -0001 MFA bypass) actually
    apply here — a vulnerable firmware with SSL-VPN off is not exposed.

    LIVE read of the firewall's configuration.

    enabled and enabled_zones come from the per-zone ACCESS LIST, not from an
    enable flag: ssl-vpn/server/base has no such field on any firmware in this
    fleet. wan_exposed is true only when a WAN-zone row is actually enabled.
    offered_zones lists the zones the access list mentions at all — a zone
    absent from it is not offered, which is different from offered-and-off.

    two_factor.configured is accompanied by the signals it was decided from, so
    a "no MFA" verdict can be checked rather than trusted.

    not_covered names what this cannot report: the TLS cipher suite and the
    client route list are not available on this platform. No credential,
    bookmark password or certificate material is ever returned."""
    dev, early = _one_device(site_or_serial)
    if early:
        return early
    serial = dev["serialNumber"]

    payloads, unavailable = _read_areas(
        serial, ("sslvpn_base", "sslvpn_accesses", "sslvpn_portal",
                 "auth_base", "local_users"))
    if "sslvpn_accesses" not in payloads and "sslvpn_base" not in payloads:
        return {"data_status": "unavailable",
                "detail": "neither SSL-VPN endpoint could be read: "
                          + "; ".join(a["detail"] for a in unavailable)}

    base = ((payloads.get("sslvpn_base") or {}).get("ssl_vpn") or {}).get(
        "server") or {}
    access = (((payloads.get("sslvpn_accesses") or {}).get("ssl_vpn") or {})
              .get("server") or {}).get("access") or []
    portal = ((payloads.get("sslvpn_portal") or {}).get("ssl_vpn") or {}).get(
        "portal") or {}
    auth = ((payloads.get("auth_base") or {}).get("user") or {}).get("auth") or {}

    offered = [_text(r.get("zone"), 64) for r in access
               if isinstance(r, dict) and r.get("zone")]
    enabled_zones = [_text(r.get("zone"), 64) for r in access
                     if isinstance(r, dict) and r.get("enable") and r.get("zone")]
    accesses_read = "sslvpn_accesses" in payloads

    # Three independent signals, all reported. Note the trap: the
    # one_time_password OBJECT is present and populated with format defaults on
    # every device regardless of whether OTP is in use, so its existence proves
    # nothing — only one_time_password_constraints and the per-user enrolment do.
    users = _local_user_rows(payloads.get("local_users"))
    otp_users = sum(1 for u in users if u.get("one_time_password"))
    basis = []
    if "sslvpn_base" in payloads:
        basis.append(f"ssl_vpn.server.auth_type = "
                     f"{_text(base.get('auth_type'), 40) or 'not set'}")
        basis.append("ssl_vpn.server.use_radius is "
                     + ("set" if base.get("use_radius") else "empty"))
    if "auth_base" in payloads:
        basis.append("user.auth.one_time_password_constraints = "
                     f"{bool(auth.get('one_time_password_constraints'))}")
    if "local_users" in payloads:
        basis.append(f"{otp_users} of {len(users)} local users have a "
                     f"one-time-password enrolment")
    configured = bool(
        (base.get("auth_type") or "").lower() not in ("", "password")
        or base.get("use_radius")
        or auth.get("one_time_password_constraints")
        or otp_users)

    return {
        "data_status": "ok",
        "match_count": 1,
        "device": _dev_ident(dev),
        "data_source": "live read of the firewall configuration",
        "enabled": bool(enabled_zones) if accesses_read else None,
        "enabled_zones": sorted(enabled_zones),
        "offered_zones": sorted(offered),
        "wan_exposed": (any(z.upper() == "WAN" for z in enabled_zones)
                        if accesses_read else None),
        "port": base.get("port") if "sslvpn_base" in payloads else None,
        "auth_type": _text(base.get("auth_type"), 40),
        "user_domain": _text(base.get("user_domain"), 120),
        "session_timeout_min": base.get("session_timeout"),
        "inactivity_check": base.get("inactivity_check"),
        "session_source_ip_check": base.get("session_source_ip_check"),
        "portal_management_web": (base.get("management") or {}).get("web"),
        "portal_management_ssh": (base.get("management") or {}).get("ssh"),
        "portal_title": _text(portal.get("site_title"), 120),
        "two_factor": {"configured": configured, "basis": basis},
        "local_user_count": len(users) if "local_users" in payloads else None,
        "areas_unavailable": unavailable,
        "not_covered": SSL_VPN_NOT_COVERED,
    }


# Standards SW-56 grades against. Deliberately small and named in the payload,
# so a disputed finding points at a rule rather than at the tool's opinion.
MGMT_IDLE_TIMEOUT_MAX_MIN = 15
MGMT_PASSWORD_MIN_LENGTH = 8
DEFAULT_ADMIN_NAMES = {"admin"}

# `management: true` on a SonicOS access rule means "this rule TERMINATES ON
# THE APPLIANCE", which is a much wider set than "an administrator can log in".
# On the NSA sample, 18 enabled WAN rules carry the flag and they include IKE,
# SSLVPN and Ping — services that are supposed to face the internet.
#
# Grading all 18 as management exposure produced eleven criticals where two
# were real. That is worse than reporting nothing: an engineer who sees
# "IKE from any is a critical management exposure" stops reading the tool. So
# the finding is raised only for services by which an administrator can reach
# the management plane; everything else is listed as a box-facing service.
ADMIN_SERVICE_MARKERS = ("http management", "https management",
                         "ssh management", "snmp", "gms")
# Not administrative, and expected to be reachable. Listed, never graded.
BOX_SERVICE_MARKERS = ("ike", "sslvpn", "ssl vpn", "ping", "nat traversal",
                       "l2tp", "dhcp", "dns")


def _is_admin_service(name: str) -> bool:
    low = (name or "").lower()
    return any(m in low for m in ADMIN_SERVICE_MARKERS)


@mcp.tool
@fleet_tool
def site_management_exposure(site_or_serial: str) -> dict:
    """How reachable and how hardened is this firewall's own management plane:
    the admin ports, whether plain HTTP admin is on, the idle timeout, login
    lockout, the admin account name, SNMP, the SonicOS API, local accounts, and
    every enabled WAN-to-box management rule with the source it permits.

    LIVE read of the firewall's configuration.

    findings grades those against a small named standard (idle timeout <= 15
    min, password minimum length >= 8, no management from `any`, no default
    admin name, no plain-HTTP admin); every finding names the FIELD it came
    from so it can be disputed at source.

    lockout.enabled reads administration.user_lockout.enable. It is NOT
    local_user_lockout, which looks right but is a mode selector:
    it reads false on firewalls that demonstrably have lockout on.

    fields_not_returned_by_device lists settings this firmware did not send at
    all. Those come back null, never false — an absent field is unknown, and
    unknown must not become a clean result.

    No community string, password, hash or shared secret is ever returned; SNMP
    and the local accounts are reported by state and name only."""
    dev, early = _one_device(site_or_serial)
    if early:
        return early
    serial = dev["serialNumber"]

    payloads, unavailable = _read_areas(
        serial, ("admin_global", "snmp_base", "local_users", "auth_base",
                 "access_rules"))
    if "admin_global" not in payloads:
        return {"data_status": "unavailable",
                "detail": "administration/global could not be read: "
                          + "; ".join(a["detail"] for a in unavailable
                                      if a["area"] == "admin_global")}

    admin = (payloads["admin_global"] or {}).get("administration") or {}
    web = admin.get("web_management") or {}
    lockout = admin.get("user_lockout") or {}
    password = admin.get("password") or {}
    api = admin.get("sonicos_api") or {}
    snmp = ((payloads.get("snmp_base") or {}).get("snmp") or {}) \
        if "snmp_base" in payloads else {}
    auth = ((payloads.get("auth_base") or {}).get("user") or {}).get("auth") or {}
    users = _local_user_rows(payloads.get("local_users"))

    # Absent != false. Reported as null and named, so nobody reads a missing
    # audit-logging flag as "audit logging is off".
    may_be_absent = ("enhanced_audit_logging", "cloud_backup_enable",
                     "multiple_admin", "out_of_band_management")
    settings = {f: admin.get(f) if f in admin else None for f in may_be_absent}
    missing = [f for f in may_be_absent if f not in admin]

    # WAN -> box management rules. `management` is a per-rule boolean and the
    # source object is what decides whether this is a finding or a control.
    mgmt_rules = []
    if "access_rules" in payloads:
        for rule in _cfg_rule_list(payloads["access_rules"]):
            if not (rule.get("management") and rule.get("enable")):
                continue
            if (rule.get("from") or "").upper() != "WAN":
                continue
            svc = _addr_ref(rule.get("service"))
            mgmt_rules.append({
                "name": _text(rule.get("name"), 120),
                "to": _text(rule.get("to"), 64),
                "src": _addr_ref((rule.get("source") or {}).get("address")),
                "dst": _addr_ref((rule.get("destination") or {}).get("address")),
                "svc": svc,
                "action": _text(rule.get("action"), 32),
                "administrative": _is_admin_service(svc),
            })
    # Only administrative services are graded — see ADMIN_SERVICE_MARKERS.
    # Deduped on (service, source, destination zone): SonicOS auto-creates one
    # copy per WAN interface, so the NSA sample carries the same SNMP-from-any
    # rule three times and three identical criticals is noise, not signal.
    from_any = []
    seen_pairs = set()
    for rule in mgmt_rules:
        if not (rule["src"] == "any" and rule["action"] == "allow"
                and rule["administrative"]):
            continue
        key = (rule["svc"], rule["src"], rule["to"])
        if key in seen_pairs:
            continue
        seen_pairs.add(key)
        from_any.append(rule)

    findings = []

    def add(severity, field, text):
        findings.append({"severity": severity, "field": field, "text": text})

    admin_name = _text((admin.get("admin") or {}).get("name"), 120)
    if admin_name.lower() in DEFAULT_ADMIN_NAMES:
        add("warning", "administration.admin.name",
            f"the administrator account still uses the vendor default name "
            f"{admin_name!r}")
    if web.get("allow_http"):
        add("critical", "administration.web_management.allow_http",
            f"plain-HTTP administration is enabled on port "
            f"{admin.get('http_port')} — credentials cross the network in "
            f"clear text")
    idle = admin.get("idle_logout_time")
    if isinstance(idle, (int, float)) and idle > MGMT_IDLE_TIMEOUT_MAX_MIN:
        add("warning", "administration.idle_logout_time",
            f"admin idle timeout is {int(idle)} minutes, over the "
            f"{MGMT_IDLE_TIMEOUT_MAX_MIN}-minute standard")
    if not lockout.get("enable"):
        add("warning", "administration.user_lockout.enable",
            "login lockout is disabled: failed admin logins are unlimited")
    minlen = password.get("minimum_length")
    if isinstance(minlen, (int, float)) and minlen < MGMT_PASSWORD_MIN_LENGTH:
        add("warning", "administration.password.minimum_length",
            f"minimum admin password length is {int(minlen)}, under the "
            f"{MGMT_PASSWORD_MIN_LENGTH}-character standard")
    for rule in from_any:
        add("critical", "access-rules/ipv4",
            f"{rule['svc']} to the appliance is permitted from ANY source on "
            f"the WAN by rule {rule['name']!r} — administrative access is "
            f"open to the internet")
    non_admin = [r for r in mgmt_rules
                 if not r["administrative"] and r["src"] == "any"
                 and r["action"] == "allow"]
    if non_admin:
        add("info", "access-rules/ipv4",
            f"{len({r['svc'] for r in non_admin})} non-administrative "
            f"appliance service(s) also accept WAN traffic from any source "
            f"({', '.join(sorted({r['svc'] for r in non_admin}))}). These "
            f"terminate on the firewall but are not management access; they "
            f"are listed, not graded.")
    if snmp.get("enable") and snmp.get("get_community_name"):
        # The field cited is snmp.enable, not the community-name key. Naming
        # the credential field would put its key name in the payload, which
        # the projection test forbids on purpose: the next reader of this
        # output should not learn where to look.
        add("warning", "snmp.enable",
            "SNMP is enabled with a read community string configured"
            + ("; SNMPv3 is mandatory, which limits v1/v2c polling"
               if (snmp.get("snmp3") or {}).get("mandatory")
               else "; SNMPv3 is NOT mandatory, so v1/v2c polling is accepted"))
    if api.get("enable"):
        add("info", "administration.sonicos_api.enable",
            "the SonicOS API is enabled (auth: "
            + ", ".join(m for m in ("digest", "chap", "basic", "bearer_token")
                        if api.get(m)) + ")")
    for area in unavailable:
        add("info", area["area"],
            f"{area['area']} could not be read, so it was not graded: "
            f"{area['detail']}")

    order = {"critical": 0, "warning": 1, "info": 2}
    findings.sort(key=lambda f: order[f["severity"]])

    return {
        "data_status": "ok",
        "match_count": 1,
        "device": _dev_ident(dev),
        "data_source": "live read of the firewall configuration",
        "firewall_name": _text(admin.get("firewall_name"), 120),
        "admin_account": admin_name,
        "mgmt_http_port": admin.get("http_port"),
        "mgmt_https_port": admin.get("https_port"),
        "http_admin_enabled": bool(web.get("allow_http")),
        "ssh_port": (admin.get("ssh") or {}).get("port"),
        "idle_timeout_min": admin.get("idle_logout_time"),
        "lockout": {
            "enabled": bool(lockout.get("enable")),
            "failures_allowed": lockout.get("failures_rate"),
            "failures_window_min": lockout.get("failures_duration"),
            "lockout_duration_min": lockout.get("lockout_duration"),
            "cli_max_login_attempts": admin.get("max_login_attempts_cli"),
            # local_user_lockout, named for what it actually is.
            "lockout_scope": ("local user account"
                              if admin.get("local_user_lockout")
                              else "source login address"),
        },
        "password_policy": {
            "minimum_length": password.get("minimum_length"),
            "enforce_character_difference":
                password.get("enforce_character_difference"),
        },
        "snmp": {
            "enabled": bool(snmp.get("enable")) if "snmp_base" in payloads
            else None,
            "community_configured": bool(snmp.get("get_community_name"))
            if "snmp_base" in payloads else None,
            "snmp3_mandatory": (snmp.get("snmp3") or {}).get("mandatory")
            if "snmp_base" in payloads else None,
            "trap_hosts_configured": sum(
                1 for k in ("host_1", "host_2", "host_3", "host_4")
                if (snmp.get(k) or "").strip()) if "snmp_base" in payloads
            else None,
        },
        "sonicos_api": {
            "enabled": bool(api.get("enable")),
            "auth_methods": [m for m in ("digest", "sha256_digest",
                                         "md5_digest", "chap", "basic",
                                         "public_key", "bearer_token")
                             if api.get(m)],
            "auto_commit": api.get("auto_commit"),
        },
        "two_factor_policy_enabled":
            bool(auth.get("one_time_password_constraints"))
            if "auth_base" in payloads else None,
        "wan_mgmt_rule_count": len(mgmt_rules),
        "wan_mgmt_rules": mgmt_rules[:MAX_MGMT_RULES],
        # True only for ADMINISTRATIVE services open to any source. IKE, SSL-VPN
        # and Ping also carry the appliance `management` flag and are supposed
        # to face the internet; they appear in wan_mgmt_rules with
        # administrative false and do not set this.
        "wan_mgmt_from_any": bool(from_any),
        "wan_admin_services_from_any": sorted({r["svc"] for r in from_any}),
        "local_user_count": len(users) if "local_users" in payloads else None,
        # Names and group membership only. No password, no hash, no email.
        "local_users": [
            {"name": _text(u.get("name"), 120),
             "domain": _text(u.get("domain"), 120),
             "from_ldap": bool(u.get("domain")),
             "groups": [_name_of(g) for g in (u.get("member_of") or [])][:10]}
            for u in users[:MAX_ADMINS]
        ],
        "settings": settings,
        "fields_not_returned_by_device": missing,
        "findings": findings,
        "areas_unavailable": unavailable,
    }


# --------------------------------- fleet security services: one tenant call
#
# GET /api/manager/security-services/status answers for the
# WHOLE TENANT in a single round-trip — verified live: a full fleet x 9
# services in well under 100 KB, sub-second warm. `deviceIDs` is an optional
# comma-separated filter and the response's `id` field IS the serial number.
#
# WHY THERE IS NO SWEEP KEY HERE. The sweep alternative is one extra GET per
# device per 30-minute cycle. One tenant-wide call on demand replaces it
# entirely, so the standing load against production NSM is unchanged.

MAX_SERVICE_SITES = 50

# Service name -> the licence code in NSM's tenant record that covers it, with
# the BASIS for the mapping written down. Only mappings a reader can check
# against the licence name are made; the rest stay None.
#
# A wrong mapping here is worse than no mapping: it would report "IPS is on but
# unlicensed" for a whole fleet, and the number would look authoritative. So
# Botnet Filter and Geo-IP Filter — which have no dedicated code in this
# tenant's 23 licence codes — are explicitly unmapped rather than guessed into
# the nearest bundle.
SERVICE_LICENCE = {
    "Intrusion Prevention": ("IDP", "licence name contains 'Intrusion Prevention'"),
    "App Control": ("IDP", "licence name contains 'App Control'"),
    "Gateway Anti-Virus": ("IDP", "licence name contains 'Gateway Anti-malware'"),
    "Anti-Spyware": ("IDP", "same Gateway Anti-malware bundle as GAV"),
    "Cloud Anti-Virus": ("IDP", "cloud-assist half of Gateway Anti-malware"),
    "Content Filter": ("CFSP", "licence 'Content Filtering Service'"),
    "Capture ATP": ("SBX", "licence 'Capture Advanced Threat Protection'"),
    "Botnet Filter": (None, "no dedicated licence code in this tenant"),
    "Geo-IP Filter": (None, "no dedicated licence code in this tenant"),
}

SECURITY_SERVICES_CAVEAT = (
    "A firewall that is OFFLINE in NSM has no trustworthy service state: NSM "
    "reports whatever it last knew, and on 2026-08-31 three offline firewalls "
    "reported every service disabled while four others reported only App "
    "Control disabled. enabled_count and disabled_count therefore count "
    "ONLINE firewalls only, offline ones are listed in state_unknown_offline, "
    "and reported_disabled_count carries the raw upstream number so the answer "
    "can still be reconciled against NSM."
)

# Signature freshness is the one thing this tool does not
# answer. Declared in the payload rather than left silent: a services audit
# that says nothing about stale signatures reads as complete.
SECURITY_SERVICES_NOT_COVERED = [
    {"area": "signature_freshness",
     "reason": ("whether GAV/IPS/App-Control SIGNATURES are current is a "
                "per-device read (reporting/gateway-antivirus, "
                "reporting/intrusion-prevention, reporting/app-control) and "
                "would need three new fleet-sweep keys — hundreds of extra "
                "GETs per sweep cycle against production NSM, so it is not "
                "swept by default. Use site_security_services per site: a "
                "service can be ENABLED "
                "here and still be running week-old signatures.")},
    {"area": "per_zone_enforcement",
     "reason": ("this endpoint reports the box-level toggle. A service enabled "
                "globally can still be off for an individual zone, which "
                "is not read here.")},
]


def _security_service_rows() -> tuple[list, dict]:
    """(devices[], by_serial_online_state) from the one tenant-wide call."""
    payload = _manager_payload("security_services")
    devices = (payload or {}).get("devices")
    if not isinstance(devices, list):
        raise ManagerError(
            f"{MANAGER_PATHS['security_services']}: no devices[] in response")
    return devices, {d.get("serialNumber"): d for d in get_devices()}


def _service_buckets(devices: list, tenant: dict) -> tuple[dict, list]:
    """Fold the matrix into {service: bucket}, splitting ONLINE findings from
    OFFLINE unknowns. The split is the whole point of the tool."""
    buckets: dict[str, dict] = {}
    unknown: dict[str, dict] = {}
    for dev in devices:
        serial = _text(dev.get("id"), 64)
        record = tenant.get(serial) or {}
        online = bool(record.get("liveStatus"))
        ident = {"serial": serial,
                 "name": _text(record.get("friendlyName"), 120),
                 "group": _text(record.get("deviceGroupName"), 120)}
        if not online:
            unknown[serial] = ident
        for svc in dev.get("securityServices") or []:
            if not isinstance(svc, dict):
                continue
            name = _text(svc.get("name"), 120)
            if not name:
                continue
            rec = buckets.setdefault(name, {
                "service": name, "enabled_count": 0, "disabled_count": 0,
                "reported_disabled_count": 0, "disabled_sites": []})
            enabled = bool(svc.get("enabled"))
            if not enabled:
                rec["reported_disabled_count"] += 1
            if not online:
                continue
            if enabled:
                rec["enabled_count"] += 1
            else:
                rec["disabled_count"] += 1
                rec["disabled_sites"].append(ident)
    return buckets, sorted(unknown.values(), key=lambda r: r["name"])


def _service_row(rec: dict, unknown_count: int) -> dict:
    sites = sorted(rec["disabled_sites"], key=lambda r: r["name"])
    return {
        "service": rec["service"],
        "enabled_count": rec["enabled_count"],
        "disabled_count": rec["disabled_count"],
        "reported_disabled_count": rec["reported_disabled_count"],
        "state_unknown_count": unknown_count,
        "disabled_site_count": len(sites),
        "disabled_sites": sites[:MAX_SERVICE_SITES],
        "truncated": len(sites) > MAX_SERVICE_SITES,
    }


@mcp.tool
@fleet_tool
def security_services_matrix() -> dict:
    """Which security services are switched on, across every firewall, in one
    call: Intrusion Prevention, Gateway Anti-Virus, Anti-Spyware, App Control,
    Content Filter, Botnet Filter, Geo-IP Filter, Capture ATP, Cloud
    Anti-Virus. Answers "which firewalls have IPS turned off?" and names the
    sites, not just a count.

    COLLECTED: this is NSM's record of each firewall's service state, so it is
    only as fresh as that firewall's last check-in. enabled_count and
    disabled_count deliberately cover ONLINE firewalls only — an offline
    firewall's reported state is not evidence, and those sites are listed
    separately in state_unknown_offline. reported_disabled_count is the raw
    upstream number including offline devices.

    A service with disabled_count 0 is a real answer (every firewall we can see
    has it on), not missing data.
    """
    devices, tenant = _security_service_rows()
    buckets, unknown = _service_buckets(devices, tenant)
    rows = [_service_row(rec, len(unknown))
            for rec in sorted(buckets.values(),
                              key=lambda r: (-r["disabled_count"],
                                             r["service"]))]
    return {
        "data_status": "ok",
        "source": "collected",
        "as_of": datetime.now(timezone.utc).isoformat(),
        "device_count": len(devices),
        "online_device_count": len(devices) - len(unknown),
        "service_count": len(rows),
        "services": rows,
        "state_unknown_offline_count": len(unknown),
        "state_unknown_offline": unknown[:MAX_SERVICE_SITES],
        "state_unknown_truncated": len(unknown) > MAX_SERVICE_SITES,
        "caveat": SECURITY_SERVICES_CAVEAT,
    }


def _licence_state(code: str, devs: list) -> dict:
    """Fleet licence counts for one service code, from the cached tenant
    record — the same source license_posture reads, so the two agree."""
    out = {"code": code, "licensed": 0, "expired": 0, "disabled": 0,
           "not_licensed": 0, "other": 0, "soonest_expiry": ""}
    expiries = []
    for d in devs:
        for s in _sec_services(d):
            if s.get("serviceCode") != code:
                continue
            st = (s.get("status") or "").lower()
            key = {"licensed": "licensed", "expired": "expired",
                   "disabled": "disabled",
                   "not licensed": "not_licensed"}.get(st, "other")
            out[key] += 1
            exp = _as_date(s.get("expires"))
            if exp:
                expiries.append(exp)
    if expiries:
        out["soonest_expiry"] = min(expiries).isoformat()
    return out


@mcp.tool
@fleet_tool
def fleet_security_services(service: str = "", site: str = "") -> dict:
    """Security-service posture for the whole fleet, joined to licence state:
    for each service, how many firewalls have it on, which sites have it off,
    and whether the licence that covers it is current. Also inverts the answer
    per site, so "what protection is missing at Springfield?" is one lookup.

    Optional service filters by name substring ('ips', 'capture', 'content').
    Optional site filters sites_with_gaps to one firewall by serial or
    name fragment — USE IT for "what protection is missing at Springfield?".
    Without it, sites_with_gaps is the worst-offending 50 sites, and on a
    large fleet many affected sites can fall
    outside that list; sites_truncated says so, but a per-site question needs
    the filter, not the top 50.
    An empty services list means nothing matched the filter — a real answer.

    Service state is COLLECTED from NSM (only as fresh as each firewall's last
    check-in) and counts ONLINE firewalls only; licence state is CACHED from
    NSM's tenant record (<=60 s old). Services with no dedicated licence code
    in this tenant report licence_code null rather than a guessed mapping.

    not_covered names what this tool does NOT check — signature freshness and
    per-zone enforcement — so an all-green answer is not read as a full audit.
    """
    devices, tenant = _security_service_rows()
    buckets, unknown = _service_buckets(devices, tenant)
    devs = get_devices()

    q = service.strip().lower()
    rows = []
    for rec in sorted(buckets.values(),
                      key=lambda r: (-r["disabled_count"], r["service"])):
        if q and q not in rec["service"].lower():
            continue
        row = _service_row(rec, len(unknown))
        code, basis = SERVICE_LICENCE.get(rec["service"], (None, "unmapped"))
        row["licence_code"] = code
        row["licence_basis"] = basis
        row["licence_status"] = _licence_state(code, devs) if code else None
        rows.append(row)

    # Per-site inversion. Built from the same online-only buckets, so a site
    # cannot appear here on the strength of an offline device's reported state.
    per_site: dict[str, dict] = {}
    for rec in buckets.values():
        for ident in rec["disabled_sites"]:
            entry = per_site.setdefault(ident["serial"],
                                        dict(ident, disabled=[]))
            entry["disabled"].append(rec["service"])
    sites = sorted(per_site.values(),
                   key=lambda r: (-len(r["disabled"]), r["name"]))
    for s in sites:
        s["disabled"] = sorted(s["disabled"])
        s["disabled_count"] = len(s["disabled"])

    # site narrows the per-site list BEFORE the cap. Without this, a per-site
    # question about a firewall ranked below 50th returns "nothing missing" —
    # an independent oracle caught exactly that during testing, seeing two
    # disabled services at a site the truncated list had dropped.
    total_sites = len(sites)
    q_site = site.strip().lower()
    if q_site:
        sites = [s for s in sites
                 if q_site == s["serial"].lower()
                 or q_site in s["name"].lower()]

    return {
        "data_status": "ok",
        "source": "collected+cached",
        "as_of": datetime.now(timezone.utc).isoformat(),
        "device_count": len(devices),
        "online_device_count": len(devices) - len(unknown),
        "services": rows,
        # The fleet-wide count, so a filtered answer still reports the scale.
        "site_with_gaps_count": total_sites,
        "site_filter": site.strip(),
        "sites_with_gaps": sites[:MAX_SERVICE_SITES],
        "sites_truncated": len(sites) > MAX_SERVICE_SITES,
        "state_unknown_offline_count": len(unknown),
        "state_unknown_offline": unknown[:MAX_SERVICE_SITES],
        "caveat": SECURITY_SERVICES_CAVEAT,
        "not_covered": SECURITY_SERVICES_NOT_COVERED,
    }


# ------------------------------------------------------------------- debug

def register_debug_tools() -> None:
    """Diagnostic instrumentation for measuring a client's end-to-end timeout
    budget empirically (e.g. at 25/45/90/240s). Registered only when
    MCP_DEBUG_TOOLS=1; leave it OFF in any shared deployment."""

    @mcp.tool(name="_debug_slow")
    @fleet_tool
    def _debug_slow(seconds: int = 30) -> dict:
        """Diagnostic only: waits `seconds` seconds server-side, then returns.
        Used to measure the real end-to-end timeout budget between a chat
        client and this server. Not a fleet tool; carries no device data."""
        time.sleep(seconds)
        return {"data_status": "ok", "slept_seconds": seconds}


def unregister_debug_tools() -> None:
    mcp.remove_tool("_debug_slow")


if os.environ.get("MCP_DEBUG_TOOLS") == "1":
    register_debug_tools()


# -------------------------------------------------------------------- ASGI app

class _AuthWrapper:
    """ASGI middleware: /health always answers (liveness must not depend on
    NSM or on auth); everything else requires X-API-Key equal to
    MCP_INBOUND_API_KEY (constant-time compare, fail-closed when unset)."""

    def __init__(self, inner):
        self.inner = inner

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.inner(scope, receive, send)

        path = scope.get("path", "")
        if path in ("/health", "/health/"):
            return await self._json(send, 200, {"status": "ok", "app": APP_NAME})

        expected = os.environ.get("MCP_INBOUND_API_KEY", "")
        provided = ""
        for k, v in scope.get("headers") or []:
            if k.decode("latin-1").lower() == "x-api-key":
                provided = v.decode("latin-1")
                break
        if not expected or not hmac.compare_digest(
            provided.encode(), expected.encode()
        ):
            return await self._json(send, 401, {"error": "unauthorized"})

        token = _caller_label.set("app-key")
        try:
            await self.inner(scope, receive, send)
        finally:
            _caller_label.reset(token)

    @staticmethod
    async def _json(send, status: int, body: dict):
        payload = json.dumps(body).encode()
        await send({
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(payload)).encode()),
            ],
        })
        await send({"type": "http.response.body", "body": payload})


def build_app():
    try:
        inner = mcp.http_app(stateless_http=True)
    except TypeError:  # fastmcp version without the kwarg on http_app()
        inner = mcp.http_app()
    return _AuthWrapper(inner)


if __name__ == "__main__":
    import uvicorn

    port = int(os.environ.get("PORT", "8080"))
    if SWEEP_ENABLED:
        start_sweep_thread()
    uvicorn.run(build_app(), host="0.0.0.0", port=port)
