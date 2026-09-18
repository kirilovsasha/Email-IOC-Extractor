"""Pure IOC filter options shared by GUI and CLI (no Tk)."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

from reliquary.core.exporters import filter_iocs, with_iocs
from reliquary.core.models import AnalysisResult, Ioc

# Category → IOC type values (must stay in sync with gui.theme.IOC_GROUPS)
CATEGORY_TYPES: dict[str, frozenset[str]] = {
    "Сеть": frozenset(
        {"ipv4", "ipv6", "ip_port", "domain", "url", "email", "messenger"}
    ),
    "Хеши": frozenset({"md5", "sha1", "sha256", "cve"}),
    "Хост": frozenset(
        {"filename", "filepath", "unc", "registry", "mutex", "command_line"}
    ),
    "Крипто": frozenset({"bitcoin", "monero"}),
}

CAT_PREF_KEYS = {
    "Сеть": "cat_network",
    "Хеши": "cat_hashes",
    "Хост": "cat_host",
    "Крипто": "cat_crypto",
}


@dataclass
class FilterState:
    """Serializable IOC filter options shared by GUI and CLI."""

    hide_rewriter: bool = True
    hide_allowlisted: bool = True
    hide_private: bool = False
    only_denylisted: bool = False
    actionable_only: bool = False
    search: str = ""
    source_file: str = ""
    cat_network: bool = True
    cat_hashes: bool = True
    cat_host: bool = True
    cat_crypto: bool = True
    types: set[str] | None = field(default=None)

    @classmethod
    def from_prefs(cls, prefs: Mapping[str, Any]) -> FilterState:
        return cls(
            hide_rewriter=bool(prefs.get("hide_rewriter", True)),
            hide_allowlisted=bool(prefs.get("hide_allowlisted", True)),
            hide_private=bool(prefs.get("hide_private", False)),
            only_denylisted=bool(prefs.get("only_denylisted", False)),
            actionable_only=bool(prefs.get("actionable_only", False)),
            cat_network=bool(prefs.get("cat_network", True)),
            cat_hashes=bool(prefs.get("cat_hashes", True)),
            cat_host=bool(prefs.get("cat_host", True)),
            cat_crypto=bool(prefs.get("cat_crypto", True)),
        )

    @classmethod
    def from_cli_args(cls, args: Any) -> FilterState:
        types: set[str] | None = None
        raw = getattr(args, "types", None)
        if raw:
            types = {t.strip().lower() for t in str(raw).split(",") if t.strip()}
        return cls(
            hide_rewriter=bool(getattr(args, "hide_rewriter", False)),
            hide_allowlisted=bool(getattr(args, "hide_allowlisted", False)),
            hide_private=bool(getattr(args, "hide_private", False)),
            only_denylisted=bool(getattr(args, "only_denylisted", False)),
            actionable_only=bool(getattr(args, "actionable", False)),
            search=str(getattr(args, "search", "") or ""),
            types=types,
        )

    def selected_types(self) -> set[str] | None:
        if self.types is not None:
            return self.types
        selected: set[str] = set()
        flags = {
            "Сеть": self.cat_network,
            "Хеши": self.cat_hashes,
            "Хост": self.cat_host,
            "Крипто": self.cat_crypto,
        }
        for name, on in flags.items():
            if on:
                selected |= set(CATEGORY_TYPES[name])
        if len(selected) == sum(len(v) for v in CATEGORY_TYPES.values()):
            return None
        return selected

    def kwargs(self) -> dict[str, Any]:
        return {
            "types": self.selected_types(),
            "hide_private": self.hide_private,
            "hide_rewriter": self.hide_rewriter,
            "hide_allowlisted": self.hide_allowlisted,
            "only_denylisted": self.only_denylisted,
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
            "only_denylisted": kw.get("only_denylisted"),
            "actionable_only": kw.get("actionable_only"),
            "search": kw.get("search"),
            "source_file": kw.get("source_file"),
        }

    def apply(self, result: AnalysisResult) -> list[Ioc]:
        return filter_iocs(result, **self.kwargs())

    def filtered_result(self, result: AnalysisResult) -> AnalysisResult:
        return with_iocs(result, self.apply(result))

    def with_focus(self, source_file: str) -> FilterState:
        return FilterState(
            hide_rewriter=self.hide_rewriter,
            hide_allowlisted=self.hide_allowlisted,
            hide_private=self.hide_private,
            only_denylisted=self.only_denylisted,
            actionable_only=self.actionable_only,
            search=self.search,
            source_file=Path(source_file).name if source_file else "",
            cat_network=self.cat_network,
            cat_hashes=self.cat_hashes,
            cat_host=self.cat_host,
            cat_crypto=self.cat_crypto,
            types=set(self.types) if self.types is not None else None,
        )
