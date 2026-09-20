"""Filter chrome helpers and defaults — mixin for ExtractorApp."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from reliquary.core.filter_state import FilterState
from reliquary.core.models import AnalysisResult

# Filter strip for email evidence (hide = drop noise; focus = narrow list).
HIDE_NOISE_FILTERS = (
    (
        "SafeLinks",
        "hide_rewriter",
        "Скрыть обёртки SafeLinks / Proofpoint — обычно шум, смотрите развёрнутый URL",
    ),
    (
        "allowlist",
        "hide_allowlisted",
        "Скрыть известный шум: Microsoft/Google CDN, SafeLinks и т.п.",
    ),
    (
        "локальные IP",
        "hide_private",
        "Скрыть частные адреса (10.x, 192.168.x, CGNAT…)",
    ),
)
FOCUS_FILTERS = (
    (
        "к разбору",
        "actionable_only",
        "Только полезные доказательства: без прокси, allowlist, локальных IP и «голых» имён",
    ),
)
TYPE_FILTER_TIPS = {
    "Сеть": "IP, домены, URL, адреса email, мессенджеры — главное для фишинга",
    "Хеши и CVE": "MD5/SHA вложений и CVE",
    "Хост": "Имена вложений, пути, UNC — реже нужно в почтовом triage",
    "Крипто": "Bitcoin / Monero в теле письма",
}


class FiltersActionsMixin:
    """Requires ExtractorApp filter BooleanVars and chrome widgets."""

    # Declared for mypy: provided by ExtractorApp / LayoutMixin / PrefsMixin.
    result: AnalysisResult | None
    cat_vars: dict[str, Any]
    hide_rewriter: Any
    hide_allowlisted: Any
    hide_private: Any
    actionable_only: Any
    full_ioc_types: Any
    _filters_open: Any
    _filt_toggle: Any
    _filt_hint: Any
    _filters_panel: Any
    _search_var: Any
    _focus_source_file: str
    _persist_prefs: Callable[[], None]
    _refresh_views: Callable[..., None]
    _update_focus_hint: Callable[[], None]

    def _on_filter_change(self) -> None:
        self._persist_prefs()
        self._update_filter_chrome()
        self._refresh_views()

    def _filter_extra_active_count(self) -> int:
        """How many non-default type/noise settings are engaged (for the «Ещё» badge)."""
        n = 0
        for var in self.cat_vars.values():
            if not bool(var.get()):
                n += 1
        for attr, default in (
            ("hide_rewriter", True),
            ("hide_allowlisted", True),
            ("hide_private", True),
        ):
            if bool(getattr(self, attr).get()) != default:
                n += 1
        if bool(self.full_ioc_types.get()):
            n += 1
        return n

    def _update_filter_chrome(self) -> None:
        open_ = bool(self._filters_open.get())
        extra = self._filter_extra_active_count()
        if open_:
            label = f"Ещё ▾{f' · {extra}' if extra else ''}"
        else:
            label = f"Ещё ▸{f' · {extra}' if extra else ''}"
        try:
            self._filt_toggle.configure(text=label)
        except Exception:  # noqa: BLE001
            pass
        parts: list[str] = []
        if self.actionable_only.get():
            parts.append("к разбору")
        off_types = [n for n, v in self.cat_vars.items() if not v.get()]
        if off_types:
            parts.append("без: " + ", ".join(off_types))
        noise_off = []
        if not self.hide_rewriter.get():
            noise_off.append("SafeLinks видны")
        if not self.hide_allowlisted.get():
            noise_off.append("allowlist виден")
        if not self.hide_private.get():
            noise_off.append("локальные IP видны")
        parts.extend(noise_off)
        hint = " · ".join(parts) if parts else "без доп. ограничений"
        try:
            self._filt_hint.configure(text=hint)
        except Exception:  # noqa: BLE001
            pass

    def _toggle_filters_panel(self) -> None:
        open_ = not bool(self._filters_open.get())
        self._filters_open.set(open_)
        if open_:
            self._filters_panel.pack(fill="x", padx=6, pady=(0, 6))
        else:
            self._filters_panel.pack_forget()
        self._update_filter_chrome()

    def _reset_filters(self) -> None:
        self.cat_vars["Сеть"].set(True)
        self.cat_vars["Хеши и CVE"].set(True)
        self.cat_vars["Хост"].set(True)
        self.cat_vars["Крипто"].set(False)
        self.hide_rewriter.set(True)
        self.hide_allowlisted.set(True)
        self.hide_private.set(True)
        self.actionable_only.set(True)
        self.full_ioc_types.set(False)
        self._search_var.set("")
        self._focus_source_file = ""
        self._update_focus_hint()
        self._on_filter_change()

    def _current_filter_state(self) -> FilterState:
        return FilterState(
            hide_rewriter=bool(self.hide_rewriter.get()),
            hide_allowlisted=bool(self.hide_allowlisted.get()),
            hide_private=bool(self.hide_private.get()),
            actionable_only=bool(self.actionable_only.get()),
            search=self._search_var.get(),
            source_file=self._focus_source_file,
            cat_network=bool(self.cat_vars["Сеть"].get()),
            cat_hashes=bool(self.cat_vars["Хеши и CVE"].get()),
            cat_host=bool(self.cat_vars["Хост"].get()),
            cat_crypto=bool(self.cat_vars["Крипто"].get()),
            full_ioc_types=bool(self.full_ioc_types.get()),
        )

    def _selected_types(self) -> set[str] | None:
        return self._current_filter_state().selected_types()

    def _filter_kwargs(self) -> dict:
        return self._current_filter_state().kwargs()

    def _filtered_iocs(self):
        if not self.result:
            return []
        return self._current_filter_state().apply(self.result)

    def _filtered_result(self) -> AnalysisResult | None:
        if not self.result:
            return None
        return self._current_filter_state().filtered_result(self.result)
