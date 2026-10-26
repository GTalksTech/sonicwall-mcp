## What this changes

<!-- One or two sentences. Link the issue if there is one. -->

## How you checked it

<!-- Which tools you ran, against what (ReadOnly-role tenant), and what you saw. No tenant data. -->

## Checklist

- [ ] Read-only: no new write, and the non-GET guard in `nsm_auth.py` is untouched
- [ ] No API keys, serials, tenant IDs, site names, IPs, MACs or user names in code or this description
- [ ] Secret-bearing payloads go through an allow-list projection
- [ ] README updated if a tool, parameter or environment variable changed
