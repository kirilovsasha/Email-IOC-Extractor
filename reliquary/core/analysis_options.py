"""Unified analysis options for CLI / GUI / batch."""

from __future__ import annotations

from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any


@dataclass
class AnalysisOptions:
    """Paths and runtime knobs shared by pipeline, CLI, GUI, and batch."""

    allowlist_path: str | Path | None = None
    verdict_path: str | Path | None = None
    handoff_template_path: str | Path | None = None
    brands_path: str | Path | None = None
    profile_dir: str | Path | None = None
    max_workers: int = 0  # 0 = auto
    skip_broken: bool = True
    # Session passwords for encrypted ZIP/7z (RAR unlock is unsupported; never persisted)
    archive_passwords: tuple[str, ...] = ()
    yara_rules_path: str | Path | None = None
    enable_yara: bool = False

    def resolved_allowlist(self) -> str | Path | None:
        return self.allowlist_path

    def resolved_verdict(self) -> str | Path | None:
        return self.verdict_path

    def resolved_handoff(self) -> str | Path | None:
        return self.handoff_template_path

    def with_profile(self, profile: Any) -> AnalysisOptions:
        """Merge OrgProfile paths (profile wins only where self is empty)."""
        if profile is None:
            return self
        return replace(
            self,
            allowlist_path=self.allowlist_path or getattr(profile, "allowlist_path", None),
            verdict_path=self.verdict_path or getattr(profile, "verdict_path", None),
            handoff_template_path=self.handoff_template_path
            or getattr(profile, "handoff_template_path", None),
            brands_path=self.brands_path or getattr(profile, "brands_path", None),
            profile_dir=self.profile_dir or getattr(profile, "root", None),
        )

    @classmethod
    def from_prefs(cls, prefs: dict[str, Any]) -> AnalysisOptions:
        return cls(
            allowlist_path=str(prefs.get("allowlist_path") or "") or None,
            verdict_path=str(prefs.get("verdict_path") or "") or None,
            handoff_template_path=str(prefs.get("handoff_template_path") or "") or None,
            brands_path=str(prefs.get("brands_path") or "") or None,
            profile_dir=str(prefs.get("profile_dir") or "") or None,
            max_workers=int(prefs.get("max_workers") or 0),
            skip_broken=bool(prefs.get("skip_broken", True)),
            yara_rules_path=str(prefs.get("yara_rules_path") or "") or None,
            enable_yara=bool(prefs.get("enable_yara", False)),
        )

    def overrides_loaded(self) -> dict[str, str]:
        """Audit map of which override files are in use."""
        out: dict[str, str] = {}
        for key, path in (
            ("allowlist", self.allowlist_path),
            ("verdict", self.verdict_path),
            ("handoff", self.handoff_template_path),
            ("brands", self.brands_path),
            ("profile", self.profile_dir),
        ):
            if path and str(path).strip():
                out[key] = str(path)
        return out
