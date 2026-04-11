"""
System Snapshot — Capture and compare system state.
=====================================================

A snapshot captures everything needed to recreate a moment:
- File hashes (what's on disk)
- Git state (branch, commit, dirty files)
- Process list (what's running)
- Service health (what's healthy)
- Environment (key env vars, Python version, etc.)
- Optional: tibet-audit results (compliance state)
"""

import hashlib
import json
import os
import platform
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional


@dataclass
class GitState:
    """Git repository state at snapshot time."""
    branch: str = ""
    commit: str = ""
    commit_message: str = ""
    dirty_files: List[str] = field(default_factory=list)
    is_dirty: bool = False
    remote_url: str = ""
    tags_at_head: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "branch": self.branch,
            "commit": self.commit,
            "commit_message": self.commit_message,
            "dirty_files": self.dirty_files,
            "is_dirty": self.is_dirty,
            "remote_url": self.remote_url,
            "tags_at_head": self.tags_at_head,
        }


@dataclass
class ServiceState:
    """Running services at snapshot time."""
    name: str
    status: str  # running, stopped, failed
    pid: Optional[int] = None
    uptime_seconds: Optional[float] = None

    def to_dict(self) -> dict:
        return {"name": self.name, "status": self.status, "pid": self.pid}


@dataclass
class SystemSnapshot:
    """
    Complete system state at a point in time.

    This is what gets sealed into a TIBET token and can be restored later.
    """
    timestamp: datetime
    path: str
    label: str = ""

    # Git state
    git: Optional[GitState] = None

    # File manifest: path → sha256
    file_hashes: Dict[str, str] = field(default_factory=dict)

    # System info
    python_version: str = ""
    platform_info: str = ""
    hostname: str = ""

    # Services
    services: List[ServiceState] = field(default_factory=list)

    # Environment (filtered — no secrets)
    env_snapshot: Dict[str, str] = field(default_factory=dict)

    # Optional: audit score at this moment
    audit_score: Optional[int] = None
    audit_grade: Optional[str] = None
    audit_check_count: Optional[int] = None

    # Computed
    manifest_hash: str = ""  # SHA256 of entire manifest

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp.isoformat(),
            "path": self.path,
            "label": self.label,
            "git": self.git.to_dict() if self.git else None,
            "file_count": len(self.file_hashes),
            "manifest_hash": self.manifest_hash,
            "python_version": self.python_version,
            "platform": self.platform_info,
            "hostname": self.hostname,
            "services": [s.to_dict() for s in self.services],
            "env": self.env_snapshot,
            "audit": {
                "score": self.audit_score,
                "grade": self.audit_grade,
                "checks": self.audit_check_count,
            } if self.audit_score is not None else None,
        }

    @classmethod
    def capture(cls, path: str = ".", label: str = "", include_audit: bool = False) -> "SystemSnapshot":
        """
        Capture current system state.

        Args:
            path: Directory to snapshot
            label: Human-readable label for this moment
            include_audit: Run tibet-audit and include results
        """
        snap = cls(
            timestamp=datetime.now(),
            path=str(Path(path).resolve()),
            label=label,
            python_version=sys.version.split()[0],
            platform_info=f"{platform.system()} {platform.release()}",
            hostname=platform.node(),
        )

        # Git state
        snap.git = cls._capture_git(path)

        # File hashes (top-level + key subdirs, skip .git and __pycache__)
        snap.file_hashes = cls._capture_files(path)

        # Environment (filtered)
        safe_env_keys = [
            "PATH", "PYTHONPATH", "VIRTUAL_ENV", "TIBET_SOVEREIGN_MODE",
            "NODE_ENV", "LANG", "SHELL", "USER", "HOME",
        ]
        snap.env_snapshot = {k: os.environ.get(k, "") for k in safe_env_keys if os.environ.get(k)}

        # Services (systemd)
        snap.services = cls._capture_services()

        # Audit (optional)
        if include_audit:
            snap.audit_score, snap.audit_grade, snap.audit_check_count = cls._run_audit(path)

        # Compute manifest hash
        manifest_data = json.dumps(snap.file_hashes, sort_keys=True)
        snap.manifest_hash = hashlib.sha256(manifest_data.encode()).hexdigest()

        return snap

    @staticmethod
    def _capture_git(path: str) -> Optional[GitState]:
        """Capture git state."""
        try:
            def _git(cmd: str) -> str:
                r = subprocess.run(
                    f"git {cmd}", shell=True, capture_output=True, text=True,
                    cwd=path, timeout=5
                )
                return r.stdout.strip()

            branch = _git("rev-parse --abbrev-ref HEAD")
            if not branch:
                return None

            commit = _git("rev-parse --short HEAD")
            msg = _git("log -1 --format=%s")
            dirty = [f for f in _git("diff --name-only").split("\n") if f]
            untracked = [f for f in _git("ls-files --others --exclude-standard").split("\n") if f]
            remote = _git("remote get-url origin 2>/dev/null")
            tags = [t for t in _git("tag --points-at HEAD").split("\n") if t]

            return GitState(
                branch=branch,
                commit=commit,
                commit_message=msg,
                dirty_files=dirty + untracked,
                is_dirty=bool(dirty or untracked),
                remote_url=remote,
                tags_at_head=tags,
            )
        except Exception:
            return None

    @staticmethod
    def _capture_files(path: str, max_files: int = 5000) -> Dict[str, str]:
        """Hash files in the directory (skip .git, __pycache__, node_modules, venv)."""
        hashes = {}
        skip_dirs = {".git", "__pycache__", "node_modules", "venv", ".venv", ".tox", "dist", "build"}
        scan_path = Path(path)

        count = 0
        for p in sorted(scan_path.rglob("*")):
            if count >= max_files:
                break
            if any(skip in p.parts for skip in skip_dirs):
                continue
            if not p.is_file():
                continue
            try:
                h = hashlib.sha256(p.read_bytes()).hexdigest()[:16]
                hashes[str(p.relative_to(scan_path))] = h
                count += 1
            except (PermissionError, OSError):
                continue

        return hashes

    @staticmethod
    def _capture_services() -> List[ServiceState]:
        """Capture running systemd services (key ones)."""
        services = []
        try:
            r = subprocess.run(
                "systemctl list-units --type=service --state=running --no-legend --no-pager",
                shell=True, capture_output=True, text=True, timeout=5
            )
            for line in r.stdout.strip().split("\n")[:50]:
                parts = line.split()
                if parts:
                    name = parts[0].replace(".service", "")
                    services.append(ServiceState(name=name, status="running"))
        except Exception:
            pass
        return services

    @staticmethod
    def _run_audit(path: str) -> tuple:
        """Run tibet-audit and return (score, grade, check_count)."""
        try:
            from tibet_audit import TIBETAudit
            audit = TIBETAudit()
            result = audit.scan(path)
            return result.score, result.grade, len(result.results)
        except Exception:
            return None, None, None


@dataclass
class SnapshotDiff:
    """Difference between two snapshots."""
    seal_a: str  # Seal ID
    seal_b: str  # Seal ID
    timestamp_a: datetime = field(default_factory=datetime.now)
    timestamp_b: datetime = field(default_factory=datetime.now)

    # File changes
    added_files: List[str] = field(default_factory=list)
    removed_files: List[str] = field(default_factory=list)
    modified_files: List[str] = field(default_factory=list)
    unchanged_files: int = 0

    # Git changes
    git_commits_between: int = 0
    git_branch_changed: bool = False

    # Service changes
    services_started: List[str] = field(default_factory=list)
    services_stopped: List[str] = field(default_factory=list)
    services_memory_delta: Dict[str, str] = field(default_factory=dict)  # name → "150MB → 200MB"

    # Package version changes (the killer feature for debugging)
    packages_added: Dict[str, str] = field(default_factory=dict)     # name → version
    packages_removed: Dict[str, str] = field(default_factory=dict)   # name → version
    packages_upgraded: Dict[str, str] = field(default_factory=dict)  # name → "0.19.0 → 0.23.0"
    packages_downgraded: Dict[str, str] = field(default_factory=dict)

    # Port changes
    ports_opened: List[str] = field(default_factory=list)
    ports_closed: List[str] = field(default_factory=list)

    # Audit changes
    score_delta: Optional[int] = None
    grade_a: Optional[str] = None
    grade_b: Optional[str] = None

    @classmethod
    def compute(cls, snap_a: SystemSnapshot, snap_b: SystemSnapshot,
                seal_a: str = "", seal_b: str = "") -> "SnapshotDiff":
        """Compute difference between two snapshots."""
        diff = cls(seal_a=seal_a, seal_b=seal_b,
                   timestamp_a=snap_a.timestamp, timestamp_b=snap_b.timestamp)

        # File diff
        files_a = set(snap_a.file_hashes.keys())
        files_b = set(snap_b.file_hashes.keys())

        diff.added_files = sorted(files_b - files_a)
        diff.removed_files = sorted(files_a - files_b)
        common = files_a & files_b
        diff.modified_files = sorted(
            f for f in common if snap_a.file_hashes[f] != snap_b.file_hashes[f]
        )
        diff.unchanged_files = len(common) - len(diff.modified_files)

        # Git diff
        if snap_a.git and snap_b.git:
            diff.git_branch_changed = snap_a.git.branch != snap_b.git.branch

        # Service diff
        svc_a = {s.name for s in snap_a.services}
        svc_b = {s.name for s in snap_b.services}
        diff.services_started = sorted(svc_b - svc_a)
        diff.services_stopped = sorted(svc_a - svc_b)

        # Audit diff
        if snap_a.audit_score is not None and snap_b.audit_score is not None:
            diff.score_delta = snap_b.audit_score - snap_a.audit_score
            diff.grade_a = snap_a.audit_grade
            diff.grade_b = snap_b.audit_grade

        return diff

    def enrich_from_manifests(self, manifest_a: Dict[str, dict], manifest_b: Dict[str, dict]) -> None:
        """
        Enrich diff with service manifest data: package versions, memory, ports.

        This is where you see "tibet-audit 0.19.0 → 0.23.0" and
        "brain_api memory 1156MB → 1300MB" — the debugging goldmine.
        """
        # Package version diffs
        pkgs_a = manifest_a.get("_tibet_packages", {}).get("packages", {})
        pkgs_b = manifest_b.get("_tibet_packages", {}).get("packages", {})

        for name in sorted(set(pkgs_a) | set(pkgs_b)):
            ver_a = pkgs_a.get(name)
            ver_b = pkgs_b.get(name)
            if ver_a and not ver_b:
                self.packages_removed[name] = ver_a
            elif ver_b and not ver_a:
                self.packages_added[name] = ver_b
            elif ver_a != ver_b:
                # Determine upgrade vs downgrade
                try:
                    from packaging.version import Version
                    if Version(ver_b) > Version(ver_a):
                        self.packages_upgraded[name] = f"{ver_a} → {ver_b}"
                    else:
                        self.packages_downgraded[name] = f"{ver_a} → {ver_b}"
                except Exception:
                    self.packages_upgraded[name] = f"{ver_a} → {ver_b}"

        # Service memory diffs
        for name in sorted(set(manifest_a) & set(manifest_b)):
            if name.startswith("_"):
                continue
            mem_a = manifest_a.get(name, {}).get("memory_mb")
            mem_b = manifest_b.get(name, {}).get("memory_mb")
            if mem_a is not None and mem_b is not None and mem_a != mem_b:
                delta = mem_b - mem_a
                sign = "+" if delta > 0 else ""
                self.services_memory_delta[name] = f"{mem_a}MB → {mem_b}MB ({sign}{delta:.1f}MB)"

        # Port diffs
        ports_a = set(manifest_a.get("_listening_ports", {}).get("ports", []))
        ports_b = set(manifest_b.get("_listening_ports", {}).get("ports", []))
        self.ports_opened = sorted(ports_b - ports_a)
        self.ports_closed = sorted(ports_a - ports_b)

    def to_dict(self) -> dict:
        return {
            "seals": [self.seal_a, self.seal_b],
            "time_range": [self.timestamp_a.isoformat(), self.timestamp_b.isoformat()],
            "files": {
                "added": len(self.added_files),
                "removed": len(self.removed_files),
                "modified": len(self.modified_files),
                "unchanged": self.unchanged_files,
            },
            "git": {"branch_changed": self.git_branch_changed, "commits": self.git_commits_between},
            "services": {
                "started": self.services_started,
                "stopped": self.services_stopped,
                "memory_delta": self.services_memory_delta,
            },
            "packages": {
                "added": self.packages_added,
                "removed": self.packages_removed,
                "upgraded": self.packages_upgraded,
                "downgraded": self.packages_downgraded,
            },
            "ports": {
                "opened": self.ports_opened,
                "closed": self.ports_closed,
            },
            "audit": {"score_delta": self.score_delta, "grade_a": self.grade_a, "grade_b": self.grade_b},
        }

    @property
    def total_changes(self) -> int:
        return len(self.added_files) + len(self.removed_files) + len(self.modified_files)

    @property
    def summary(self) -> str:
        parts = []
        if self.added_files:
            parts.append(f"+{len(self.added_files)} files added")
        if self.removed_files:
            parts.append(f"-{len(self.removed_files)} files removed")
        if self.modified_files:
            parts.append(f"~{len(self.modified_files)} files modified")
        if self.packages_upgraded:
            parts.append(f"{len(self.packages_upgraded)} pkg upgraded")
        if self.packages_downgraded:
            parts.append(f"{len(self.packages_downgraded)} pkg downgraded")
        if self.services_started:
            parts.append(f"{len(self.services_started)} svc started")
        if self.services_stopped:
            parts.append(f"{len(self.services_stopped)} svc stopped")
        if self.ports_opened:
            parts.append(f"{len(self.ports_opened)} ports opened")
        if self.ports_closed:
            parts.append(f"{len(self.ports_closed)} ports closed")
        if self.score_delta is not None:
            arrow = "+" if self.score_delta > 0 else ""
            parts.append(f"audit {arrow}{self.score_delta}")
        return ", ".join(parts) if parts else "no changes"
