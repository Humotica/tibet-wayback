"""
Wayback Core — Seal, Restore, Navigate.
=========================================

The core orchestrator that ties together:
- SystemSnapshot: what the system looks like right now
- TIBET tokens: cryptographic proof of each sealed moment
- Git: code state at each seal
- Airlock: VM-level restore capability

    seal = wayback.seal("before migration")
    wayback.list()
    wayback.restore(seal.seal_id)
    wayback.diff(seal_a, seal_b)
"""

import hashlib
import json
import os
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .snapshot import SystemSnapshot, SnapshotDiff


# ── Seal: a frozen moment with provenance ──────────────────────────

@dataclass
class Seal:
    """
    A sealed system moment.

    Combines a SystemSnapshot with a TIBET provenance token
    and optional git commit reference. This is the unit of
    time-travel — each seal is a restorable checkpoint.
    """
    seal_id: str                          # Short ID (wb-xxxx)
    timestamp: datetime = field(default_factory=datetime.now)
    label: str = ""                       # Human description
    path: str = ""                        # Directory that was sealed

    # The snapshot data
    snapshot: Optional[SystemSnapshot] = None

    # TIBET provenance
    tibet_token_id: Optional[str] = None  # TIBET token for this seal
    tibet_chain_id: Optional[str] = None  # Chain this seal belongs to

    # Git reference
    git_commit: str = ""                  # Commit at seal time
    git_branch: str = ""                  # Branch at seal time
    git_stash: str = ""                   # Stash ref if dirty files were stashed

    # Airlock reference (VM snapshot)
    airlock_snapshot_id: Optional[str] = None

    # Service manifest (SBOM-style)
    service_manifest: Dict[str, dict] = field(default_factory=dict)

    # Metadata
    sealed_by: str = ""                   # Who/what created this seal
    tags: List[str] = field(default_factory=list)
    notes: str = ""

    def to_dict(self) -> dict:
        return {
            "seal_id": self.seal_id,
            "timestamp": self.timestamp.isoformat(),
            "label": self.label,
            "path": self.path,
            "snapshot": self.snapshot.to_dict() if self.snapshot else None,
            "tibet_token_id": self.tibet_token_id,
            "tibet_chain_id": self.tibet_chain_id,
            "git": {
                "commit": self.git_commit,
                "branch": self.git_branch,
                "stash": self.git_stash,
            },
            "airlock_snapshot_id": self.airlock_snapshot_id,
            "service_manifest": self.service_manifest,
            "sealed_by": self.sealed_by,
            "tags": self.tags,
            "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Seal":
        """Reconstruct a Seal from stored dict."""
        seal = cls(
            seal_id=data["seal_id"],
            timestamp=datetime.fromisoformat(data["timestamp"]),
            label=data.get("label", ""),
            path=data.get("path", ""),
            tibet_token_id=data.get("tibet_token_id"),
            tibet_chain_id=data.get("tibet_chain_id"),
            git_commit=data.get("git", {}).get("commit", ""),
            git_branch=data.get("git", {}).get("branch", ""),
            git_stash=data.get("git", {}).get("stash", ""),
            airlock_snapshot_id=data.get("airlock_snapshot_id"),
            service_manifest=data.get("service_manifest", {}),
            sealed_by=data.get("sealed_by", ""),
            tags=data.get("tags", []),
            notes=data.get("notes", ""),
        )
        return seal

    @property
    def short_label(self) -> str:
        return self.label[:50] + "..." if len(self.label) > 50 else self.label

    @property
    def age(self) -> str:
        """Human-readable age string."""
        delta = datetime.now() - self.timestamp
        if delta.days > 0:
            return f"{delta.days}d ago"
        hours = delta.seconds // 3600
        if hours > 0:
            return f"{hours}h ago"
        minutes = delta.seconds // 60
        return f"{minutes}m ago"


# ── Timeline: ordered collection of seals ──────────────────────────

@dataclass
class WaybackTimeline:
    """
    Ordered collection of seals for a path.

    Navigate forward and backward through system states.
    Think of it as git log but for your entire system state,
    not just code.
    """
    path: str
    seals: List[Seal] = field(default_factory=list)

    def add(self, seal: Seal) -> None:
        """Add a seal to the timeline (maintains chronological order)."""
        self.seals.append(seal)
        self.seals.sort(key=lambda s: s.timestamp)

    def get(self, seal_id: str) -> Optional[Seal]:
        """Find a seal by ID (prefix match)."""
        for seal in self.seals:
            if seal.seal_id == seal_id or seal.seal_id.startswith(seal_id):
                return seal
        return None

    def latest(self) -> Optional[Seal]:
        return self.seals[-1] if self.seals else None

    def previous(self, seal_id: str) -> Optional[Seal]:
        """Get the seal before the given one."""
        for i, seal in enumerate(self.seals):
            if seal.seal_id == seal_id and i > 0:
                return self.seals[i - 1]
        return None

    def between(self, seal_a_id: str, seal_b_id: str) -> List[Seal]:
        """Get all seals between two seal IDs (inclusive)."""
        ids = [s.seal_id for s in self.seals]
        try:
            idx_a = next(i for i, sid in enumerate(ids) if sid.startswith(seal_a_id))
            idx_b = next(i for i, sid in enumerate(ids) if sid.startswith(seal_b_id))
            lo, hi = min(idx_a, idx_b), max(idx_a, idx_b)
            return self.seals[lo:hi + 1]
        except StopIteration:
            return []

    def by_tag(self, tag: str) -> List[Seal]:
        return [s for s in self.seals if tag in s.tags]

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "seal_count": len(self.seals),
            "seals": [s.to_dict() for s in self.seals],
        }

    @classmethod
    def from_dict(cls, data: dict) -> "WaybackTimeline":
        tl = cls(path=data["path"])
        for sd in data.get("seals", []):
            tl.seals.append(Seal.from_dict(sd))
        return tl


# ── Wayback: the main orchestrator ─────────────────────────────────

class Wayback:
    """
    System state time-travel.

    Seal any moment. Restore any moment. Replay any audit.
    Compare any two moments. Debug what changed between "it worked"
    and "it broke."

    Usage:
        wb = Wayback("/srv/jtel-stack")
        seal = wb.seal("before migration")
        wb.list_seals()
        wb.restore(seal.seal_id)
        diff = wb.diff(seal_a_id, seal_b_id)
    """

    STORE_DIR = ".wayback"
    TIMELINE_FILE = "timeline.json"

    def __init__(self, path: str = "."):
        self.path = str(Path(path).resolve())
        self.store_path = Path(self.path) / self.STORE_DIR
        self.timeline = self._load_timeline()

    # ── Public API ──

    def seal(
        self,
        label: str = "",
        include_audit: bool = False,
        include_services: bool = True,
        tags: Optional[List[str]] = None,
        notes: str = "",
        sealed_by: str = "",
    ) -> Seal:
        """
        Seal the current system state.

        Captures everything: files, git, services, environment, optional audit.
        Creates a TIBET token for provenance. Optionally stashes dirty git files.

        Returns:
            Seal object with all captured state
        """
        # Generate seal ID
        seal_id = self._generate_seal_id()

        # Capture snapshot
        snapshot = SystemSnapshot.capture(
            path=self.path, label=label, include_audit=include_audit
        )

        # Build service manifest (SBOM-style)
        service_manifest = {}
        if include_services:
            service_manifest = self._capture_service_manifest()

        # Create TIBET token if available
        tibet_token_id = None
        tibet_chain_id = None
        try:
            tibet_token_id, tibet_chain_id = self._create_tibet_seal(
                seal_id, snapshot, label
            )
        except Exception:
            pass  # TIBET is optional

        # Git state
        git_commit = snapshot.git.commit if snapshot.git else ""
        git_branch = snapshot.git.branch if snapshot.git else ""

        # Stash dirty files if any
        git_stash = ""
        if snapshot.git and snapshot.git.is_dirty:
            git_stash = self._git_stash(seal_id)

        # Airlock snapshot if available
        airlock_id = None
        try:
            airlock_id = self._create_airlock_snapshot(seal_id, label)
        except Exception:
            pass  # Airlock is optional

        # Build seal
        seal = Seal(
            seal_id=seal_id,
            timestamp=snapshot.timestamp,
            label=label,
            path=self.path,
            snapshot=snapshot,
            tibet_token_id=tibet_token_id,
            tibet_chain_id=tibet_chain_id,
            git_commit=git_commit,
            git_branch=git_branch,
            git_stash=git_stash,
            airlock_snapshot_id=airlock_id,
            service_manifest=service_manifest,
            sealed_by=sealed_by or self._detect_sealer(),
            tags=tags or [],
            notes=notes,
        )

        # Store seal
        self._store_seal(seal)
        self.timeline.add(seal)
        self._save_timeline()

        return seal

    def restore(self, seal_id: str, restore_git: bool = True,
                restore_services: bool = False) -> dict:
        """
        Restore system to a sealed state.

        Steps:
        1. Find the seal
        2. Restore git state (checkout commit, pop stash)
        3. Optionally restore services
        4. Optionally restore via airlock (VM snapshot)
        5. Report what changed

        Returns:
            dict with restore results
        """
        seal = self.timeline.get(seal_id)
        if not seal:
            return {"error": f"Seal '{seal_id}' not found"}

        results = {
            "seal_id": seal.seal_id,
            "label": seal.label,
            "timestamp": seal.timestamp.isoformat(),
            "restored": [],
            "skipped": [],
            "errors": [],
        }

        # Try airlock restore first (most complete)
        if seal.airlock_snapshot_id:
            try:
                self._restore_airlock(seal.airlock_snapshot_id)
                results["restored"].append("airlock_vm_snapshot")
                return results  # Airlock restores everything
            except Exception as e:
                results["errors"].append(f"airlock: {e}")

        # Git restore
        if restore_git and seal.git_commit:
            try:
                self._restore_git(seal)
                results["restored"].append("git_state")
            except Exception as e:
                results["errors"].append(f"git: {e}")
        else:
            results["skipped"].append("git_state")

        # Service restore
        if restore_services and seal.service_manifest:
            try:
                svc_results = self._restore_services(seal.service_manifest)
                results["restored"].append("services")
                results["service_details"] = svc_results
            except Exception as e:
                results["errors"].append(f"services: {e}")
        else:
            results["skipped"].append("services")

        return results

    def diff(self, seal_a_id: str, seal_b_id: str) -> Optional[SnapshotDiff]:
        """Compare two sealed moments — files, packages, services, memory, ports."""
        seal_a = self.timeline.get(seal_a_id)
        seal_b = self.timeline.get(seal_b_id)

        if not seal_a or not seal_b:
            return None

        # Load full snapshots from individual seal files
        snap_a = self._load_snapshot(seal_a.seal_id)
        snap_b = self._load_snapshot(seal_b.seal_id)

        if not snap_a or not snap_b:
            return None

        d = SnapshotDiff.compute(
            snap_a, snap_b,
            seal_a=seal_a.seal_id, seal_b=seal_b.seal_id,
        )

        # Enrich with service manifest data (package versions, memory, ports)
        if seal_a.service_manifest and seal_b.service_manifest:
            d.enrich_from_manifests(seal_a.service_manifest, seal_b.service_manifest)

        return d

    def audit(self, seal_id: str, framework: str = "") -> Optional[dict]:
        """
        Replay an audit against a sealed state.

        If the seal includes audit results, returns those.
        If not, captures fresh audit against current state (for comparison).
        """
        seal = self.timeline.get(seal_id)
        if not seal:
            return None

        # Load snapshot from disk (timeline doesn't store full snapshot)
        snapshot = seal.snapshot or self._load_snapshot(seal.seal_id)

        result = {
            "seal_id": seal.seal_id,
            "label": seal.label,
            "timestamp": seal.timestamp.isoformat(),
        }

        # Return stored audit if available
        if snapshot and snapshot.audit_score is not None:
            result["audit"] = {
                "score": snapshot.audit_score,
                "grade": snapshot.audit_grade,
                "checks": snapshot.audit_check_count,
                "source": "sealed",
            }
        else:
            # Try running a fresh audit
            try:
                from tibet_audit import TIBETAudit
                audit = TIBETAudit()
                res = audit.scan(seal.path)
                result["audit"] = {
                    "score": res.score,
                    "grade": res.grade,
                    "checks": len(res.results),
                    "source": "live",
                }
            except Exception:
                result["audit"] = None

        # Compliance mapping if framework specified
        if framework and result.get("audit"):
            try:
                from tibet_audit import get_framework_coverage
                from tibet_audit import TIBETAudit
                audit = TIBETAudit()
                res = audit.scan(seal.path)
                coverage = get_framework_coverage(res.results, framework)
                result["compliance"] = coverage
            except Exception:
                pass

        return result

    def list_seals(self, limit: int = 20, tag: Optional[str] = None) -> List[Seal]:
        """List seals, newest first."""
        seals = self.timeline.by_tag(tag) if tag else self.timeline.seals
        return list(reversed(seals[-limit:]))

    def sbom(self, seal_id: Optional[str] = None) -> dict:
        """
        Generate SBOM-style manifest for a seal or current state.

        Includes: files, services, packages, git state, environment.
        Like an Android system dump but for your AI stack.
        """
        if seal_id:
            seal = self.timeline.get(seal_id)
            if not seal or not seal.snapshot:
                return {"error": f"Seal '{seal_id}' not found"}
            snapshot = seal.snapshot
            manifest = seal.service_manifest
        else:
            snapshot = SystemSnapshot.capture(self.path)
            manifest = self._capture_service_manifest()

        return {
            "type": "tibet-wayback-sbom",
            "version": "1.0",
            "generated": datetime.now().isoformat(),
            "system": {
                "hostname": snapshot.hostname,
                "platform": snapshot.platform_info,
                "python": snapshot.python_version,
            },
            "git": snapshot.git.to_dict() if snapshot.git else None,
            "files": {
                "count": len(snapshot.file_hashes),
                "manifest_hash": snapshot.manifest_hash,
            },
            "services": manifest,
            "environment": snapshot.env_snapshot,
            "audit": {
                "score": snapshot.audit_score,
                "grade": snapshot.audit_grade,
            } if snapshot.audit_score is not None else None,
        }

    # ── Private helpers ──

    def _generate_seal_id(self) -> str:
        """Generate short seal ID like wb-3f8a."""
        ts = datetime.now().isoformat().encode()
        h = hashlib.sha256(ts + os.urandom(8)).hexdigest()[:4]
        return f"wb-{h}"

    def _detect_sealer(self) -> str:
        """Detect who is creating this seal."""
        user = os.environ.get("USER", "unknown")
        if os.environ.get("CLAUDE_CODE"):
            return "root_idd"
        return user

    def _capture_service_manifest(self) -> Dict[str, dict]:
        """
        Capture running services SBOM-style.

        Like Android's dumpsys but for the AI stack.
        """
        manifest = {}
        try:
            # Systemd services
            r = subprocess.run(
                "systemctl list-units --type=service --state=running --no-legend --no-pager",
                shell=True, capture_output=True, text=True, timeout=10,
            )
            for line in r.stdout.strip().split("\n"):
                parts = line.split()
                if not parts:
                    continue
                name = parts[0].replace(".service", "")
                manifest[name] = {"type": "systemd", "status": "running"}

                # Get service details
                try:
                    detail = subprocess.run(
                        f"systemctl show {parts[0]} --property=MainPID,ExecMainStartTimestamp,MemoryCurrent --no-pager",
                        shell=True, capture_output=True, text=True, timeout=5,
                    )
                    for prop_line in detail.stdout.strip().split("\n"):
                        if "=" in prop_line:
                            k, v = prop_line.split("=", 1)
                            if k == "MainPID" and v.strip():
                                manifest[name]["pid"] = int(v.strip()) if v.strip().isdigit() else None
                            elif k == "ExecMainStartTimestamp" and v.strip():
                                manifest[name]["started"] = v.strip()
                            elif k == "MemoryCurrent" and v.strip():
                                try:
                                    mem_bytes = int(v.strip())
                                    manifest[name]["memory_mb"] = round(mem_bytes / 1048576, 1)
                                except (ValueError, TypeError):
                                    pass
                except Exception:
                    pass

        except Exception:
            pass

        # Docker containers if available
        try:
            r = subprocess.run(
                "docker ps --format '{{.Names}}|{{.Image}}|{{.Status}}|{{.Ports}}'",
                shell=True, capture_output=True, text=True, timeout=10,
            )
            for line in r.stdout.strip().split("\n"):
                if "|" in line:
                    name, image, status, ports = line.split("|", 3)
                    manifest[f"docker:{name}"] = {
                        "type": "docker",
                        "image": image,
                        "status": status,
                        "ports": ports,
                    }
        except Exception:
            pass

        # Listening ports
        try:
            r = subprocess.run(
                "ss -tlnp 2>/dev/null | tail -n +2",
                shell=True, capture_output=True, text=True, timeout=5,
            )
            ports = []
            for line in r.stdout.strip().split("\n"):
                parts = line.split()
                if len(parts) >= 4:
                    addr = parts[3]
                    ports.append(addr)
            if ports:
                manifest["_listening_ports"] = {"type": "network", "ports": ports[:50]}
        except Exception:
            pass

        # Python packages (pip freeze)
        try:
            r = subprocess.run(
                f"{sys.executable} -m pip list --format=json 2>/dev/null",
                shell=True, capture_output=True, text=True, timeout=15,
            )
            pkgs = json.loads(r.stdout) if r.stdout.strip() else []
            tibet_pkgs = {p["name"]: p["version"] for p in pkgs if "tibet" in p["name"].lower()}
            if tibet_pkgs:
                manifest["_tibet_packages"] = {"type": "python", "packages": tibet_pkgs}
        except Exception:
            pass

        return manifest

    def _create_tibet_seal(self, seal_id: str, snapshot: SystemSnapshot,
                           label: str) -> Tuple[str, str]:
        """Create a TIBET token for this seal."""
        from tibet_vault import TIBETVault

        vault = TIBETVault()
        token = vault.create_token(
            intent=f"wayback:seal:{seal_id}",
            actor="tibet-wayback",
            metadata={
                "seal_id": seal_id,
                "label": label,
                "manifest_hash": snapshot.manifest_hash,
                "file_count": len(snapshot.file_hashes),
                "git_commit": snapshot.git.commit if snapshot.git else "",
            },
        )
        return token.token_id, token.chain_id

    def _create_airlock_snapshot(self, seal_id: str, label: str) -> str:
        """Create an airlock VM snapshot."""
        from tibet_airlock import Airlock

        airlock = Airlock()
        snap = airlock.snapshot(label=f"wayback:{seal_id} — {label}")
        return snap.snapshot_id

    def _git_stash(self, seal_id: str) -> str:
        """Stash dirty git files with seal reference."""
        try:
            r = subprocess.run(
                f'git stash push -m "wayback:{seal_id}"',
                shell=True, capture_output=True, text=True,
                cwd=self.path, timeout=10,
            )
            if "No local changes" not in r.stdout:
                # Get stash ref
                ref = subprocess.run(
                    "git stash list --format=%H -1",
                    shell=True, capture_output=True, text=True,
                    cwd=self.path, timeout=5,
                )
                return ref.stdout.strip()
        except Exception:
            pass
        return ""

    def _restore_git(self, seal: Seal) -> None:
        """Restore git state from seal."""
        if seal.git_branch:
            subprocess.run(
                f"git checkout {seal.git_branch}",
                shell=True, capture_output=True, text=True,
                cwd=self.path, timeout=10,
            )
        if seal.git_commit:
            subprocess.run(
                f"git checkout {seal.git_commit}",
                shell=True, capture_output=True, text=True,
                cwd=self.path, timeout=10,
            )
        if seal.git_stash:
            subprocess.run(
                "git stash pop",
                shell=True, capture_output=True, text=True,
                cwd=self.path, timeout=10,
            )

    def _restore_airlock(self, snapshot_id: str) -> None:
        """Restore from airlock VM snapshot."""
        from tibet_airlock import Airlock
        airlock = Airlock()
        airlock.restore(snapshot_id)

    def _restore_services(self, manifest: Dict[str, dict]) -> dict:
        """Restart services to match sealed state."""
        results = {"restarted": [], "skipped": [], "errors": []}
        for name, info in manifest.items():
            if name.startswith("_"):
                continue
            if info.get("type") == "systemd":
                try:
                    subprocess.run(
                        f"systemctl restart {name}",
                        shell=True, capture_output=True, text=True, timeout=30,
                    )
                    results["restarted"].append(name)
                except Exception as e:
                    results["errors"].append(f"{name}: {e}")
        return results

    def _store_seal(self, seal: Seal) -> None:
        """Persist seal to disk (metadata + full snapshot with file hashes)."""
        self.store_path.mkdir(parents=True, exist_ok=True)

        # Main seal file (metadata + summary)
        seal_file = self.store_path / f"{seal.seal_id}.json"
        seal_file.write_text(json.dumps(seal.to_dict(), indent=2, default=str))

        # Snapshot file (full file hashes for diff)
        if seal.snapshot:
            snap_file = self.store_path / f"{seal.seal_id}.snapshot.json"
            snap_data = {
                "timestamp": seal.snapshot.timestamp.isoformat(),
                "path": seal.snapshot.path,
                "file_hashes": seal.snapshot.file_hashes,
                "git": seal.snapshot.git.to_dict() if seal.snapshot.git else None,
                "services": [s.to_dict() for s in seal.snapshot.services],
                "env_snapshot": seal.snapshot.env_snapshot,
                "manifest_hash": seal.snapshot.manifest_hash,
                "audit_score": seal.snapshot.audit_score,
                "audit_grade": seal.snapshot.audit_grade,
                "audit_check_count": seal.snapshot.audit_check_count,
                "python_version": seal.snapshot.python_version,
                "platform_info": seal.snapshot.platform_info,
                "hostname": seal.snapshot.hostname,
            }
            snap_file.write_text(json.dumps(snap_data, indent=2, default=str))

    def _load_snapshot(self, seal_id: str) -> Optional[SystemSnapshot]:
        """Load full snapshot from disk."""
        snap_file = self.store_path / f"{seal_id}.snapshot.json"
        if not snap_file.exists():
            return None
        try:
            data = json.loads(snap_file.read_text())
            from .snapshot import GitState, ServiceState
            snap = SystemSnapshot(
                timestamp=datetime.fromisoformat(data["timestamp"]),
                path=data["path"],
                file_hashes=data.get("file_hashes", {}),
                manifest_hash=data.get("manifest_hash", ""),
                python_version=data.get("python_version", ""),
                platform_info=data.get("platform_info", ""),
                hostname=data.get("hostname", ""),
                env_snapshot=data.get("env_snapshot", {}),
                audit_score=data.get("audit_score"),
                audit_grade=data.get("audit_grade"),
                audit_check_count=data.get("audit_check_count"),
            )
            if data.get("git"):
                g = data["git"]
                snap.git = GitState(
                    branch=g.get("branch", ""),
                    commit=g.get("commit", ""),
                    commit_message=g.get("commit_message", ""),
                    dirty_files=g.get("dirty_files", []),
                    is_dirty=g.get("is_dirty", False),
                    remote_url=g.get("remote_url", ""),
                    tags_at_head=g.get("tags_at_head", []),
                )
            for s in data.get("services", []):
                snap.services.append(ServiceState(
                    name=s.get("name", ""),
                    status=s.get("status", ""),
                    pid=s.get("pid"),
                ))
            return snap
        except Exception:
            return None

    def _load_timeline(self) -> WaybackTimeline:
        """Load timeline from disk."""
        tl_path = self.store_path / self.TIMELINE_FILE
        if tl_path.exists():
            try:
                data = json.loads(tl_path.read_text())
                return WaybackTimeline.from_dict(data)
            except Exception:
                pass
        return WaybackTimeline(path=self.path)

    def phantom_seal(self, seal: Seal) -> str:
        """
        Seal as Phantom session for cross-device resume.

        Links the wayback seal to a Phantom session so you can
        close your laptop and resume on another device.
        """
        import urllib.request

        phantom_url = os.environ.get("PHANTOM_URL", "http://localhost:8000")
        payload = json.dumps({
            "client": seal.sealed_by or "tibet-wayback",
            "context": {
                "type": "wayback-seal",
                "seal_id": seal.seal_id,
                "label": seal.label,
                "path": seal.path,
                "git_commit": seal.git_commit,
                "git_branch": seal.git_branch,
                "manifest_hash": seal.snapshot.manifest_hash if seal.snapshot else "",
                "tibet_token": seal.tibet_token_id,
                "service_count": sum(1 for k in seal.service_manifest if not k.startswith("_")),
            },
            "seal_type": "wayback",
        }).encode()

        req = urllib.request.Request(
            f"{phantom_url}/phantom/seal",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
            return data.get("session_id", "")

    def phantom_resume(self, seal: Seal, backend: Optional[str] = None) -> dict:
        """
        Resume a sealed session on this device via Phantom.

        Steps:
        1. Restore git state
        2. Resume Phantom session
        3. Report results
        """
        results = {"restored": [], "errors": []}

        # Restore git state first
        if seal.git_commit:
            try:
                self._restore_git(seal)
                results["restored"].append("git_state")
            except Exception as e:
                results["errors"].append(f"git: {e}")

        # Resume via Phantom
        try:
            import urllib.request

            phantom_url = os.environ.get("PHANTOM_URL", "http://localhost:8000")
            payload = json.dumps({
                "seal_id": seal.seal_id,
                "backend": backend,
            }).encode()

            req = urllib.request.Request(
                f"{phantom_url}/phantom/resume",
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read())
                results["session_id"] = data.get("session_id")
                results["backend"] = data.get("backend")
                results["restored"].append("phantom_session")
        except Exception as e:
            results["errors"].append(f"phantom: {e}")

        return results

    def _save_timeline(self) -> None:
        """Save timeline to disk."""
        self.store_path.mkdir(parents=True, exist_ok=True)
        tl_path = self.store_path / self.TIMELINE_FILE
        tl_path.write_text(json.dumps(self.timeline.to_dict(), indent=2, default=str))
