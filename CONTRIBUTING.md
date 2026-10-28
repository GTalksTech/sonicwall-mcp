# Contributing

Contributions are welcome: bug reports, fixes, new read tools, tests, and
notes on NSM API behaviour that does not match SonicWall's documentation.

## The rule that does not bend: read-only

This server is read-only by construction. `NsmSession` in `nsm_auth.py`
refuses any method other than GET, HEAD or OPTIONS before any I/O, and the
recommended deployment uses a MySonicWall account whose NSM role is ReadOnly.
**A pull request that adds a write to NSM or SonicOS, or loosens that check,
will not be merged.** If you need writes, fork it.

## Before you start

- **Small fixes:** open a pull request directly.
- **New tools or behaviour changes:** open an issue first so we can agree on
  the shape before you write the code.

## Ground rules

These are the design principles in the README, and review holds every change
to them:

1. **"Zero findings" and "data unavailable" stay different answers.** Every
   response carries `data_status`, and an `unavailable` response carries no
   data keys. Partial answers name what could not be read.
2. **Provenance is explicit.** Say whether an answer is live, cached or
   collected.
3. **Responses stay under 500 KB**, with an explicit `truncated` flag and
   authoritative counts.
4. **Secrets never cross the boundary.** Project payloads through allow-lists
   of named fields, never deny-lists. Config diffs return key names only,
   never values. PSKs, community strings, password hashes, RADIUS/LDAP secrets
   and registration codes are never returned.
5. **Chat-client-friendly schemas.** Single primitive parameter types with
   defaults, no `Optional[...]` unions.
6. **Personal data is labelled** (`contains_personal_data` / `privacy_note`).

## Development setup

```bash
python3.12 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt -c constraints.txt
.venv/bin/python nsm_auth.py   # checks the credential and the effective NSM role
```

On Windows use `py -3.12` and `.venv\Scripts\python.exe`.

There is no automated test suite yet, and an offline one (fake NSM responses,
no network) would be a very welcome contribution. Until then, say in your
pull request exactly how you checked the change, against a tenant whose key
has the ReadOnly role.

## Pull requests

- One change per pull request, with a description of what it does and how you
  checked it.
- Never paste tenant data into an issue or pull request: no API keys, serial
  numbers, tenant IDs, site names, public IPs, MAC addresses or user names.
  Replace them with placeholders.
- If you found an NSM endpoint that behaves differently from its
  documentation, document it in a comment where it is handled, the way the
  existing code does.
- Keep pinned versions in `constraints.txt` unless the change is a dependency
  update.

## Reporting a security issue

Please do not open a public issue for a security problem. Report it privately
through GitHub instead: the repository's **Security** tab, then **Report a
vulnerability**
([direct link](https://github.com/GTalksTech/sonicwall-mcp/security/advisories/new)).
Only you and the maintainer can see the report. If you cannot use GitHub,
email garrett@gtalkstech.com.

## License

By contributing you agree that your contribution is licensed under the
repository's [MIT license](LICENSE).
