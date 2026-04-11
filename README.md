# tibet-wayback

**System state time-travel with TIBET provenance.**

Seal any moment. Restore any moment. Replay any audit. Debug what changed.

## Quick Start

```bash
pip install tibet-wayback

# Seal current state
wayback seal "before migration"

# List all seals
wayback list

# Restore to a sealed moment
wayback restore wb-3f8a

# Compare two moments
wayback diff wb-3f8a wb-7c2d

# Replay audit at a sealed moment
wayback audit wb-3f8a --framework iso42001

# System SBOM (current or sealed)
wayback sbom
wayback sbom wb-3f8a --json

# Seal + resume on another device (via Phantom)
wayback seal "end of day" --phantom
wayback resume wb-3f8a
```

## What Gets Sealed

Each seal captures:

| Layer | What | How |
|-------|------|-----|
| **Files** | SHA256 of every file | `rglob("*")` with smart skip |
| **Git** | Branch, commit, dirty files, tags | `git rev-parse`, `git diff` |
| **Services** | Running systemd/docker, PIDs, memory | `systemctl`, `docker ps` |
| **Environment** | Filtered env vars (no secrets) | Safe-list approach |
| **Packages** | Installed TIBET packages + versions | `pip list --format=json` |
| **Ports** | Listening network ports | `ss -tlnp` |
| **Audit** | tibet-audit score, grade, check count | Optional: `--audit` flag |
| **Provenance** | TIBET token with manifest hash | Optional: requires `tibet-vault` |
| **VM State** | Airlock microVM snapshot | Optional: requires `tibet-airlock` |

## SBOM — System Bill of Materials

```bash
# Current system manifest
wayback sbom --json > system-sbom.json

# Sealed state manifest
wayback sbom wb-3f8a -o sealed-sbom.json
```

The SBOM includes services, packages, ports, git state, and audit scores — everything an enterprise needs for compliance and debugging.

## Phantom Resume — Cross-Device

Seal your work session, close your laptop, resume on another device:

```bash
# On your workstation
wayback seal "end of day" --phantom

# On your laptop (via Phantom Resume)
wayback resume wb-3f8a
```

Uses Phantom's cross-device session portability with TIBET provenance chain.

## A/B System States

Like Android A/B partitions but for your entire stack:

```bash
wayback seal "state A — working"   # wb-a1b2
# ... make changes ...
wayback seal "state B — broken"    # wb-c3d4
wayback diff wb-a1b2 wb-c3d4       # see exactly what changed
wayback restore wb-a1b2            # back to working
```

Perfect for:
- **Enterprise**: compliance snapshots, audit trails, incident debugging
- **Development**: safe experimentation, A/B testing system configs
- **Education**: Storm can build, seal, experiment, restore if things break

## Optional Dependencies

```bash
pip install tibet-wayback[tibet]    # + tibet-vault, tibet-audit
pip install tibet-wayback[airlock]  # + tibet-airlock (VM snapshots)
pip install tibet-wayback[full]     # everything
```

## Part of TIBET

tibet-wayback is package #91 in the [TIBET ecosystem](https://pypi.org/project/tibet/).

```
tibet-audit  → compliance checks
tibet-vault  → provenance tokens
tibet-airlock → VM snapshots
tibet-wayback → ties them together into time-travel
```

---

*Authors: Jasper van de Meent & Root AI*
*License: MIT*
