"""
Tibet Wayback — System State Time-Travel
==========================================

Seal any moment. Restore any moment. Replay any audit.

The building blocks:
- tibet-airlock: VM snapshot/restore (the state)
- TIBET tokens: provenance chain (the proof)
- Phantom: seal/resume (the session)
- Git: code state (the source)

Wayback ties them together into a timeline you can navigate.

    $ wayback seal "before migration"
    $ wayback list
    $ wayback restore wb-3f8a
    $ wayback audit wb-3f8a --framework ietf
    $ wayback diff wb-3f8a wb-7c2d

Authors: Jasper van de Meent & Root AI
License: MIT
"""

__version__ = "0.1.1"
__author__ = "Jasper van de Meent & Root AI"

from .core import Wayback, Seal, WaybackTimeline
from .snapshot import SystemSnapshot, SnapshotDiff

__all__ = [
    "Wayback", "Seal", "WaybackTimeline",
    "SystemSnapshot", "SnapshotDiff",
]
