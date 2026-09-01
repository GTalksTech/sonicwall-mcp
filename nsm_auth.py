"""Authentication and session handling for a SonicWall NSM SaaS tenant.

This module is the single place the MySonicWall API key is read and the single
place the NSM token chain is implemented.

SECRET HANDLING
    API keys are read at runtime, in this order:

    1. A custom provider registered with set_api_key_provider() (this is how
       server.py wires in the MSW_API_KEY_READONLY environment variable for
       hosted runs, where a secret store injects it).
    2. The OS keyring (Windows Credential Manager, macOS Keychain, or
       libsecret/Secret Service on Linux) under the service names below.

    Keys are never stored in this repo.

    There can be TWO credentials, and which one you get is the security boundary:

        msw-api-key-readonly   a MySonicWall account with NSM role ReadOnly
        msw-api-key-write      a MySonicWall account with NSM role Admin

    get_api_key() returns the READ-ONLY key. The write key requires an explicit
    get_api_key(write=True), and NsmSession only requests it when constructed with
    read_only=False. A read-only session therefore cannot write even if the code
    tries -- it is authenticated as an account MySonicWall will not let write.
    That is a real boundary, unlike the method check in NsmSession.request(),
    which only catches our own mistakes. Provision a dedicated ReadOnly
    MySonicWall account for this server if you possibly can.

    Store or replace a key in the keyring by running:

        python -c "import keyring,getpass; keyring.set_password('msw-api-key-readonly','<your-msw-login>',getpass.getpass('key: '))"

    Verify what a credential can actually do with whoami() -- it reports the role
    NSM reports, rather than what we assume the key was provisioned with.

TENANT CONFIGURATION (env vars; all optional)
    MSW_TENANT_ID      the tenant's productGroupID on MySonicWall
    NSM_TENANT_SERIAL  the tenantSerial of the NSM service on that tenant
    MSW_TENANT_NAME    tenant name (substring match) used during auto-discovery
    NSM_URL            NSM base URL (default https://nsm-uswest.sonicwall.com;
                       set your region's host if different)

    When MSW_TENANT_ID / NSM_TENANT_SERIAL are unset they are discovered from
    the MySonicWall get-cloud-tenants API at first use: if your account sees
    exactly one tenant it is used, otherwise set MSW_TENANT_NAME to pick one.
    See discover_tenant_ids().

THE AUTH CHAIN (three calls, only the first carries the secret)
    1. POST {MSW_API}/api/generate-cscaccesscode   header X-api-key
       body {"tenantId": ..., "tileName": "ISNSMSAFEENABLED"}
       -> response["content"]["accessCode"]
    2. POST {NSM_URL}/api/manager/auth/sso         no auth header
       body {"tenantSerial": ..., "code": ...}
       -> response["status"]["info"][0]["message"]   (the bearer token)
    3. GET  {NSM_URL}/api/manager/...              Authorization: Bearer <token>
                                                    X-Device-ID: <firewall serial>

    The bearer token is valid for 8 hours BUT has a 15-minute inactivity timeout.
    A fleet-wide sweep across a couple of hundred devices can idle past that
    between slow calls, so NsmSession re-runs the whole chain automatically
    rather than caching a token and hoping.

INVENTORY -- the "licensing list" method
    Do NOT call /api/manager/firewalls to enumerate the fleet. NSM manager
    endpoints are device-scoped by the X-Device-ID header, so there is no valid
    header value meaning "the whole tenant" and the request fails with
    "X-DEVICE-ID is invalid". Global inventory comes from the MySonicWall
    licensing plane instead, which is tenant-scoped by nature:
    get_cloud_tenants() -> your tenant -> NSM service -> migrateList.
    See get_fleet().
"""

from __future__ import annotations

import os
import time

import requests

# --------------------------------------------------------------------------- config

# Two credentials, deliberately separate. The read-only key belongs to a
# MySonicWall account whose group permission is ReadOnly, so it CANNOT write even
# if our code tries. The write key belongs to an Admin account and exists only for
# deliberate change-pushing work.
#
# Binding the credential to the capability is the point: a read-only session
# resolves the read-only key and never touches the write key, so read-only is
# enforced by what the process can authenticate as, not merely by a method check.
KEYRING_SERVICE_READONLY = "msw-api-key-readonly"
KEYRING_SERVICE_WRITE = "msw-api-key-write"

# Backwards-compatible alias: the default credential is the read-only one.
KEYRING_SERVICE = KEYRING_SERVICE_READONLY

MSW_API = "https://api.mysonicwall.com"   # access-code endpoint
MSW_WEB = "https://mysonicwall.com"       # get-cloud-tenants (bare host, not api.)
NSM_URL = os.environ.get("NSM_URL", "https://nsm-uswest.sonicwall.com").rstrip("/")

# Tenant identity. Set the env vars, or leave them empty and both values are
# discovered from get-cloud-tenants at first use (see _resolve_tenant_ids).
MSW_TENANT_ID = os.environ.get("MSW_TENANT_ID", "")     # productGroupID
NSM_SERIAL = os.environ.get("NSM_TENANT_SERIAL", "")    # NSM tenantSerial
TARGET_TENANT_NAME = os.environ.get("MSW_TENANT_NAME", "")

# In the get-cloud-tenants payload the services live under the tenant's
# 'cloudServices' key, and NSM identifies itself by serviceName 'NGMGMT'.
# 'Network Security Manager' appears only in serviceNameDisp, so code that
# matches on the display name (or on 'NSM' as a substring) silently finds
# nothing and falls through to whatever fallback the caller has.
NSM_SERVICE_NAME = "NGMGMT"

# Re-auth this far before the documented inactivity cutoff rather than waiting
# for a 401, so a long sweep does not pay a failed request per stale token.
INACTIVITY_TIMEOUT = 15 * 60
REAUTH_MARGIN = 120

# --------------------------------------------------------------------- read-only
# The API key inherits its permissions from the MySonicWall account. If the
# account holds an Admin role, the key CAN write to every production firewall
# in the tenant. This server only reads, but "only reads" is a property of
# today's code, not a guarantee.
#
# So the guard lives at the client: NsmSession refuses any method that is not a
# safe read. This is belt-and-braces alongside the real fix, which is a
# MySonicWall account with the ReadOnly permission.
#
# To deliberately allow writes, set READ_ONLY = False, or instantiate
# NsmSession(read_only=False). Do that consciously, in a script whose name makes
# clear it changes configuration.
READ_ONLY = True
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


class ReadOnlyViolation(RuntimeError):
    """Raised when a mutating request is attempted while READ_ONLY is set."""


class AuthError(RuntimeError):
    """Raised when the API key cannot be found or the token chain fails."""


# ------------------------------------------------------------------------- secret

_api_key_provider = None


def set_api_key_provider(fn) -> None:
    """Override where API keys come from.

    Pass a callable taking one bool argument (write) and returning the key. This
    is the seam for plugging in a secret manager (Vault, Key Vault, Secrets
    Manager, ...) without touching any calling script -- the read-only and
    write credentials become two secret IDs:

        nsm_auth.set_api_key_provider(
            lambda write: secrets.get(WRITE_ID if write else READONLY_ID)
        )
    """
    global _api_key_provider
    _api_key_provider = fn


def get_api_key(write: bool = False) -> str:
    """Return a MySonicWall API key (provider, env var, or the OS keyring).

    Defaults to the READ-ONLY credential. Pass write=True only from code that
    genuinely intends to change firewall configuration -- it resolves the Admin
    credential, and nothing else in this repo should ask for it.

    For keyring entries, the username is discovered from the stored credential,
    so callers do not need to know which MySonicWall account minted the key.
    Set NSM_KEYRING_USER to pin a specific username when more than one entry
    exists for a service.
    """
    service = KEYRING_SERVICE_WRITE if write else KEYRING_SERVICE_READONLY
    kind = "write/Admin" if write else "read-only"

    if _api_key_provider is not None:
        return _api_key_provider(write)

    env_key = os.environ.get(
        "MSW_API_KEY_WRITE" if write else "MSW_API_KEY_READONLY")
    if env_key:
        return env_key

    try:
        import keyring
    except ImportError as exc:
        raise AuthError(
            "keyring is not installed in this environment. Install it with:\n"
            "    pip install keyring"
        ) from exc

    pinned = os.environ.get("NSM_KEYRING_USER")
    if pinned:
        key = keyring.get_password(service, pinned)
        if not key:
            raise AuthError(
                f"No credential found for service '{service}' and user "
                f"'{pinned}' (from NSM_KEYRING_USER)."
            )
        return key

    cred = keyring.get_credential(service, None)
    if cred is None or not cred.password:
        raise AuthError(
            f"No {kind} API key in Windows Credential Manager under service "
            f"'{service}'. Store one with:\n"
            f'    python -c "import keyring,getpass; '
            f"keyring.set_password('{service}','<msw-login>',"
            f'getpass.getpass(\'key: \'))"'
        )
    return cred.password


# --------------------------------------------------------------------- token chain

# Discovery result, cached for the life of the process.
_resolved_ids: dict = {}


def _resolve_tenant_ids(api_key: str | None = None) -> tuple[str, str]:
    """Return (tenant_id, tenant_serial), from config or by discovery.

    With MSW_TENANT_ID / NSM_TENANT_SERIAL unset, the tenant is found via
    get-cloud-tenants (matched by MSW_TENANT_NAME when set, or the only tenant
    the account can see). Discovery runs at most once per process.
    """
    if MSW_TENANT_ID and NSM_SERIAL:
        return MSW_TENANT_ID, NSM_SERIAL
    if not _resolved_ids:
        found = discover_tenant_ids(api_key)
        tenant_id = MSW_TENANT_ID or found["tenant_id"]
        tenant_serial = NSM_SERIAL or found["tenant_serial"]
        if not tenant_id or not tenant_serial:
            raise AuthError(
                "Could not resolve the tenant: discovery returned "
                f"tenant_id={tenant_id!r}, tenant_serial={tenant_serial!r}. "
                "Set MSW_TENANT_ID and NSM_TENANT_SERIAL explicitly."
            )
        _resolved_ids.update(tenant_id=tenant_id, tenant_serial=tenant_serial)
    return _resolved_ids["tenant_id"], _resolved_ids["tenant_serial"]


def get_access_code(api_key: str | None = None, timeout: int = 15,
                    write: bool = False) -> str:
    """Step 1: exchange the API key for a short-lived NSM access code.

    Resolves the read-only credential unless write=True.
    """
    api_key = api_key or get_api_key(write=write)
    tenant_id, _ = _resolve_tenant_ids(api_key)
    r = requests.post(
        f"{MSW_API}/api/generate-cscaccesscode",
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "X-api-key": api_key,
        },
        json={"tenantId": tenant_id, "tileName": "ISNSMSAFEENABLED"},
        timeout=timeout,
    )
    if r.status_code != 200:
        raise AuthError(
            f"generate-cscaccesscode failed: HTTP {r.status_code} {r.text[:300]}"
        )
    code = (r.json().get("content") or {}).get("accessCode")
    if not code:
        raise AuthError(
            f"generate-cscaccesscode returned no accessCode: {r.text[:300]}"
        )
    return code


def get_nsm_token(code: str, timeout: int = 15) -> str:
    """Step 2: exchange the access code for an NSM bearer token.

    TLS verification stays on. The old scripts passed verify=False here, which
    disabled certificate checking on the one call that carries the access code --
    and the NSM hosts are publicly CA-signed, so it was never needed.
    """
    _, tenant_serial = _resolve_tenant_ids()
    r = requests.post(
        f"{NSM_URL}/api/manager/auth/sso",
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        json={"tenantSerial": tenant_serial, "code": code},
        timeout=timeout,
    )
    if r.status_code != 200:
        raise AuthError(f"auth/sso failed: HTTP {r.status_code} {r.text[:300]}")
    try:
        return r.json()["status"]["info"][0]["message"]
    except (KeyError, IndexError, TypeError) as exc:
        raise AuthError(f"auth/sso response shape unexpected: {r.text[:300]}") from exc


def get_token(write: bool = False) -> str:
    """Run the full chain and return a bearer token. No caching -- see NsmSession.

    Uses the read-only credential unless write=True.
    """
    return get_nsm_token(get_access_code(write=write))


# ------------------------------------------------------------------------- session


class NsmSession:
    """Read-only NSM client that keeps its own bearer token alive.

    Handles the 15-minute inactivity timeout by re-running the auth chain when the
    token goes stale or when NSM rejects it, so callers can iterate the whole
    fleet without thinking about token lifetime.

        nsm = NsmSession()
        data = nsm.get("/api/manager/firewall/interfaces/ipv4", serial="18C24112D1A8")
    """

    def __init__(self, timeout: int = 20, read_only: bool | None = None):
        self.timeout = timeout
        self.read_only = READ_ONLY if read_only is None else read_only
        self._session = requests.Session()
        self._token: str | None = None
        self._last_used: float = 0.0

    # -- token lifecycle

    def authenticate(self) -> str:
        # A read-only session authenticates with the read-only credential, so it
        # is incapable of writing regardless of what the calling code attempts.
        self._token = get_token(write=not self.read_only)
        self._last_used = time.monotonic()
        return self._token

    @property
    def token(self) -> str:
        stale = time.monotonic() - self._last_used > (INACTIVITY_TIMEOUT - REAUTH_MARGIN)
        if self._token is None or stale:
            self.authenticate()
        return self._token

    def headers(self, serial: str | None = None) -> dict:
        h = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        if serial:
            h["X-Device-ID"] = serial
        return h

    # -- requests

    def request(self, method: str, path: str, serial: str | None = None,
                params: dict | None = None, json_body: dict | None = None,
                timeout: int | None = None) -> requests.Response:
        """Issue a request against NSM, re-authenticating once on 401/403.

        Refuses mutating methods while this session is read-only. The check is
        here rather than in get()/try_get() so it cannot be bypassed by calling
        the lower-level method directly.
        """
        if self.read_only and method.upper() not in SAFE_METHODS:
            raise ReadOnlyViolation(
                f"Refusing {method.upper()} {path}: this session is read-only.\n"
                "The API key currently carries NSM Admin rights, so a mutating "
                "request would actually change firewall configuration.\n"
                "If a write is genuinely intended, pass "
                "NsmSession(read_only=False) explicitly."
            )
        url = path if path.startswith("http") else f"{NSM_URL}{path}"
        r = None
        for attempt in (1, 2):
            r = self._session.request(
                method, url,
                headers=self.headers(serial),
                params=params,
                json=json_body,
                timeout=timeout or self.timeout,
            )
            self._last_used = time.monotonic()
            if r.status_code in (401, 403) and attempt == 1:
                self.authenticate()
                continue
            return r
        return r

    def get(self, path: str, serial: str | None = None, params: dict | None = None,
            timeout: int | None = None) -> dict:
        """GET and return parsed JSON. Raises for HTTP errors."""
        r = self.request("GET", path, serial=serial, params=params, timeout=timeout)
        r.raise_for_status()
        return r.json()

    def try_get(self, path: str, serial: str | None = None, params: dict | None = None,
                timeout: int | None = None):
        """GET returning (ok, payload). Never raises -- for per-device sweeps where
        one offline firewall must not stop the run."""
        try:
            r = self.request("GET", path, serial=serial, params=params, timeout=timeout)
            if r.status_code != 200:
                return False, f"HTTP {r.status_code} {r.text[:200]}"
            return True, r.json()
        except Exception as exc:
            return False, str(exc)


# ----------------------------------------------------------------------- inventory


def get_cloud_tenants(api_key: str | None = None, timeout: int = 30) -> dict:
    """Return the `content` block of the MySonicWall get-cloud-tenants response."""
    api_key = api_key or get_api_key()
    r = requests.get(
        f"{MSW_WEB}/api/hgms/get-cloud-tenants",
        headers={
            "X-API-KEY": api_key,
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        timeout=timeout,
    )
    if r.status_code != 200:
        raise AuthError(f"get-cloud-tenants failed: HTTP {r.status_code} {r.text[:300]}")
    data = r.json()
    if data.get("operationStatus") == "FAILURE":
        raise AuthError(f"get-cloud-tenants failure: {data.get('msgDesc', 'unknown')}")
    return data.get("content") or {}


def find_tenant(content: dict, tenant_name: str | None = None) -> dict:
    """Return the tenant block matching tenant_name (substring, case-insensitive).

    With no name configured at all: if the account sees exactly one tenant,
    that tenant is returned; more than one raises, naming them, so the caller
    knows to set MSW_TENANT_NAME.
    """
    tenants = content.get("arrTenants") or []
    wanted = (tenant_name or TARGET_TENANT_NAME).lower()
    if not wanted:
        if len(tenants) == 1:
            return tenants[0]
        available = ", ".join(repr(t.get("name")) for t in tenants)
        raise AuthError(
            f"This account sees {len(tenants)} tenants and no MSW_TENANT_NAME "
            f"is set. Available tenants: {available}"
        )
    for tenant in tenants:
        if wanted in (tenant.get("name") or "").lower():
            return tenant
    available = ", ".join(repr(t.get("name")) for t in tenants)
    raise AuthError(
        f"Tenant matching '{tenant_name or TARGET_TENANT_NAME}' not found. "
        f"Available tenants: {available}"
    )


def find_nsm_service(tenant: dict) -> dict:
    """Return the NSM service block from a tenant's cloudServices list.

    The services live under 'cloudServices' (not 'services'), and NSM identifies
    itself by serviceName 'NGMGMT' -- 'Network Security Manager' is only the
    display name in serviceNameDisp. Matching on the display string alone fails.
    """
    for service in tenant.get("cloudServices") or []:
        if service.get("serviceName") == NSM_SERVICE_NAME:
            return service
        if "network security manager" in (service.get("serviceNameDisp") or "").lower():
            return service
    available = ", ".join(
        repr(s.get("serviceName")) for s in (tenant.get("cloudServices") or [])
    )
    raise AuthError(
        f"No NSM service ('{NSM_SERVICE_NAME}') on tenant "
        f"{tenant.get('name')!r}. Services present: {available}"
    )


def get_devices(session: "NsmSession | None" = None, timeout: int = 60) -> list[dict]:
    """Return full NSM device records for the tenant -- 57 fields each.

    This is the preferred inventory source. It comes from the NSM manager plane
    rather than the MySonicWall licensing plane, which matters for two reasons:

      * It works with a reduced-privilege MySonicWall account. The licensing
        plane WITHHOLDS the migrateList field from lower-privileged accounts --
        the key is absent, not empty -- so get_fleet_via_licensing() silently
        returns nothing for the read-only credential.
      * The records are far richer. Each one carries modelInfo, licenses3,
        expiringcount, vulnerability, fwUpgradeStatus, availableVersions,
        liveStatus, synchronized, configModified, deployPending,
        highAvailability, appliedTemplates, location and deviceGroupName --
        i.e. most of what a compliance audit needs, for the whole fleet, in a
        single call rather than a per-device sweep.

    No credential material is returned: username is the device admin login name,
    and password_set / invalidPassword / encryptionVersion are booleans and ints.
    """
    nsm = session or NsmSession()
    return nsm.get("/api/manager/devices/tenant", timeout=timeout)


def get_fleet(api_key: str | None = None, content: dict | None = None,
              session: "NsmSession | None" = None) -> list[dict]:
    """Return the fleet as [{'serial','name','model','ip','group'}, ...].

    Prefers the NSM manager plane and falls back to the MySonicWall licensing
    list, so this works under both the read-only and the Admin credential.
    """
    try:
        out = []
        for d in get_devices(session):
            if not d.get("serialNumber"):
                continue
            attrs = d.get("attributes") or {}
            out.append({
                "serial": d.get("serialNumber") or "",
                "name": d.get("friendlyName") or "",
                # attributes.model is the clean form ("TZ 270W"); modelInfo
                # .productName is the verbose SKU ("SONICWALL TZ 270W North America")
                "model": attrs.get("model") or (d.get("modelInfo") or {}).get("productName") or "",
                "firmware": attrs.get("firmware_version") or "",
                "ip": d.get("ipAddress") or "",
                "group": d.get("deviceGroupName") or "",
                "online": bool(d.get("liveStatus")),
                "firmware_vulnerable": bool((d.get("vulnerability") or {}).get("isFirmwareVulnerable")),
            })
        return out
    except Exception:
        return get_fleet_via_licensing(api_key, content)


def get_fleet_via_licensing(api_key: str | None = None,
                            content: dict | None = None) -> list[dict]:
    """Fleet via the MySonicWall licensing list: tenant -> NGMGMT -> migrateList.

    Kept as a fallback. Requires an elevated MySonicWall account -- the
    migrateList key is omitted entirely for lower-privileged users, which shows
    up as an empty fleet rather than an error. Records carry no model field.
    """
    content = content if content is not None else get_cloud_tenants(api_key)
    service = find_nsm_service(find_tenant(content))
    migrate_list = service.get("migrateList")
    if migrate_list is None:
        raise AuthError(
            "The licensing list omitted 'migrateList' for this account -- it is a "
            "privileged field. Use get_devices() / get_fleet(), which read the NSM "
            "manager plane and work with the read-only credential."
        )
    return [
        {
            "serial": d.get("serialNumber") or "",
            "name": d.get("friendlyName") or "",
            "nfr": d.get("NFR") or "",
        }
        for d in migrate_list
        if d.get("serialNumber")
    ]


def discover_tenant_ids(api_key: str | None = None) -> dict:
    """Return {'tenant_id', 'tenant_serial', 'product_count', 'managed_count'}.

    tenantId is the tenant's productGroupID, and tenantSerial sits on the NGMGMT
    service block. This is what _resolve_tenant_ids uses when MSW_TENANT_ID /
    NSM_TENANT_SERIAL are not set; it is also useful for spotting devices
    registered to the tenant but not managed by NSM
    (product_count > managed_count).
    """
    content = get_cloud_tenants(api_key)
    tenant = find_tenant(content)
    service = find_nsm_service(tenant)
    # productCount arrives as a string in the JSON, so coerce it -- callers
    # comparing it against managed_count would otherwise hit a TypeError.
    try:
        product_count = int(tenant.get("productCount") or 0)
    except (TypeError, ValueError):
        product_count = 0
    return {
        "tenant_id": str(tenant.get("productGroupID") or ""),
        "tenant_serial": service.get("tenantSerial") or "",
        "product_count": product_count,
        "managed_count": len(service.get("migrateList") or []),
    }


def whoami(session: "NsmSession | None" = None) -> dict:
    """Return {'email', 'role_id', 'role_name'} for the authenticated identity.

    Use this to verify a credential actually carries the privilege you expect,
    rather than assuming it. Role names come from the tenant's own role table, so
    they reflect this NSM instance rather than hardcoded guesses.
    """
    nsm = session or NsmSession()
    me = nsm.get("/api/manager/users/current", timeout=25)
    roles = nsm.get("/api/manager/roles", timeout=30)
    tenant_roles = me.get("tenant_role") or []
    role_id = tenant_roles[0].get("role") if tenant_roles else None
    names = {r.get("role"): r.get("name") for r in roles}
    return {
        "email": me.get("primaryEmail") or "",
        "role_id": role_id,
        "role_name": names.get(role_id, "UNKNOWN"),
    }


if __name__ == "__main__":
    # Smoke test: proves the credential resolves, all three auth calls work, and
    # the credential carries the privilege level we think it does.
    import sys

    want_write = "--write" in sys.argv
    label = "write/Admin" if want_write else "read-only"
    print(f"[1] reading {label} API key (env or OS keyring) ...")
    key = get_api_key(write=want_write)
    print(f"    got a key, {len(key)} chars")
    print("[2] requesting access code ...")
    code = get_access_code(key)
    print(f"    got access code, {len(code)} chars")
    print("[3] requesting bearer token ...")
    token = get_nsm_token(code)
    print(f"    got bearer token, {len(token)} chars")

    print("[4] confirming effective privilege ...")
    who = whoami(NsmSession(read_only=not want_write))
    print(f"    {who['email']}  ->  role {who['role_id']} = {who['role_name']}")
    if not want_write and who["role_name"] not in ("ReadOnly", "Guest"):
        print(f"    WARNING: default credential carries '{who['role_name']}', "
              f"not ReadOnly. It can change firewall configuration.")

    print("[5] listing fleet via licensing list ...")
    fleet = get_fleet(key)
    print(f"    {len(fleet)} devices; first: {fleet[0] if fleet else 'none'}")
    print("OK")
