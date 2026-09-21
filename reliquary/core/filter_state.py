"""Pure IOC filter options shared by GUI and CLI (no Tk)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

from reliquary.core.exporters import filter_iocs, with_iocs
from reliquary.core.models import AnalysisResult, Ioc

# Single source of truth for category chips (GUI theme imports this).
IOC_GROUPS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("Сеть", ("ipv4", "ipv6", "ip_port", "domain", "url", "email", "messenger")),
    ("Хеши и CVE", ("md5", "sha1", "sha256", "cve")),
    ("Хост", ("filename", "filepath", "unc", "registry", "mutex", "command_line")),
    ("Крипто", ("bitcoin", "monero")),
)

# Host-forensics leftovers — hidden in email triage unless full_ioc_types.
LEGACY_HOST_TYPES: frozenset[str] = frozenset(
    {"registry", "mutex", "command_line"}
)
# Kept for tests / docs; crypto is gated by cat_crypto (default off).
LEGACY_IOC_TYPES: frozenset[str] = LEGACY_HOST_TYPES | frozenset({"bitcoin", "monero"})

CATEGORY_TYPES: dict[str, frozenset[str]] = {
    name: frozenset(types) for name, types in IOC_GROUPS
}

CAT_PREF_KEYS = {
    "Сеть": "cat_network",
    "Хеши и CVE": "cat_hashes",
    "Хост": "cat_host",
    "Крипто": "cat_crypto",
}

_ALL_TYPES: frozenset[str] = frozenset().union(*CATEGORY_TYPES.values())


@dataclass
class FilterState:
    """Serializable IOC filter options shared by GUI and CLI."""

    hide_rewriter: bool = True
    hide_allowlisted: bool = True
    hide_private: bool = True
    actionable_only: bool = True
    search: str = ""
    source_file: str = ""
    cat_network: bool = True
    cat_hashes: bool = True
    cat_host: bool = True
    cat_crypto: bool = False  # crypto off by default (email mode)
    full_ioc_types: bool = False
    types: set[str] | None = field(default=None)

    @classmethod
    def from_prefs(cls, prefs: Mapping[str, Any]) -> FilterState:
        return cls(
            hide_rewriter=bool(prefs.get("hide_rewriter", True)),
            hide_allowlisted=bool(prefs.get("hide_allowlisted", True)),
            hide_private=bool(prefs.get("hide_private", True)),
            actionable_only=bool(prefs.get("actionable_only", True)),
            cat_network=bool(prefs.get("cat_network", True)),
            cat_hashes=bool(prefs.get("cat_hashes", True)),
            cat_host=bool(prefs.get("cat_host", True)),
            cat_crypto=bool(prefs.get("cat_crypto", False)),
            full_ioc_types=bool(prefs.get("full_ioc_types", False)),
        )

    @classmethod
    def from_cli_args(cls, args: Any) -> FilterState:
        """CLI flags; defaults should already match GUI prefs (see cli.py)."""
        types: set[str] | None = None
        raw = getattr(args, "types", None)
        if raw:
            types = {t.strip().lower() for t in str(raw).split(",") if t.strip()}
        full = bool(getattr(args, "full_ioc_types", False))
        state = cls(
            hide_rewriter=bool(getattr(args, "hide_rewriter", True)),
            hide_allowlisted=bool(getattr(args, "hide_allowlisted", True)),
            hide_private=bool(getattr(args, "hide_private", True)),
            actionable_only=bool(getattr(args, "actionable", True)),
            search=str(getattr(args, "search", "") or ""),
            types=types,
            full_ioc_types=full,
            cat_network=True,
            cat_hashes=True,
            cat_host=True,
            cat_crypto=full,
        )
        if full and types is None:
            # Show every category including legacy/crypto.
            state.cat_crypto = True
        return state

    def selected_types(self) -> set[str] | None:
        if self.types is not None:
            selected = set(self.types)
        else:
            selected = set()
            flags = {
                "Сеть": self.cat_network,
                "Хеши и CVE": self.cat_hashes,
                "Хост": self.cat_host,
                "Крипто": self.cat_crypto,
            }
            for name, on in flags.items():
                if on:
                    selected |= set(CATEGORY_TYPES[name])

        if not self.full_ioc_types:
            selected -= LEGACY_HOST_TYPES

        if not selected:
            return set()
        if self.full_ioc_types and selected >= _ALL_TYPES:
            return None
        return selected

    def kwargs(self) -> dict[str, Any]:
        return {
            "types": self.selected_types(),
            "hide_private": self.hide_private,
            "hide_rewriter": self.hide_rewriter,
            "hide_allowlisted": self.hide_allowlisted,
            "actionable_only": self.actionable_only,
            "search": (self.search or "").strip(),
            "source_file": self.source_file or "",
        }

    def serializable(self) -> dict[str, Any]:
        kw = self.kwargs()
        types = kw.get("types")
        return {
            "types": sorted(types) if isinstance(types, set) else types,
            "hide_private": kw.get("hide_private"),
            "hide_rewriter": kw.get("hide_rewriter"),
            "hide_allowlisted": kw.get("hide_allowlisted"),
            "actionable_only": kw.get("actionable_only"),
            "search": kw.get("search"),
            "source_file": kw.get("source_file"),
            "full_ioc_types": self.full_ioc_types,
        }

    def apply(self, result: AnalysisResult) -> list[Ioc]:
        return filter_iocs(result, **self.kwargs())

    def filtered_result(self, result: AnalysisResult) -> AnalysisResult:
        return with_iocs(result, self.apply(result))

    def with_focus(self, source_file: str) -> FilterState:
        # Basename must work for both POSIX and Windows paths (CI runs on Linux).
        raw = (source_file or "").replace("\\", "/").rstrip("/")
        base = raw.rsplit("/", 1)[-1] if raw else ""
        return FilterState(
            hide_rewriter=self.hide_rewriter,
            hide_allowlisted=self.hide_allowlisted,
            hide_private=self.hide_private,
            actionable_only=self.actionable_only,
            search=self.search,
            source_file=base,
            cat_network=self.cat_network,
            cat_hashes=self.cat_hashes,
            cat_host=self.cat_host,
            cat_crypto=self.cat_crypto,
            full_ioc_types=self.full_ioc_types,
            types=set(self.types) if self.types is not None else None,
        )
