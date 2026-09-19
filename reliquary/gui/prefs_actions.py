"""Prefs persistence and window geometry — mixin for ExtractorApp."""

from __future__ import annotations

from reliquary.core.error_log import append_error_log
from reliquary.core.filter_state import CAT_PREF_KEYS
from reliquary.core.prefs import save_prefs
from reliquary.gui.windowing import fit_window_geometry


class PrefsMixin:
    """Requires ExtractorApp filter vars, paths, and screen helpers."""

    def _apply_saved_geometry(self) -> None:
        geom = str(self._prefs.get("window_geometry") or "1320x820")
        screen, virtual = self._screen_metrics()
        fitted = fit_window_geometry(geom, screen=screen, virtual=virtual)
        try:
            self.geometry(fitted)
        except Exception:  # noqa: BLE001
            self.geometry("1320x820")

    def _persist_prefs(self) -> None:
        screen, virtual = self._screen_metrics()
        updates = {
            "last_dir": self._last_dir,
            "last_export_dir": self._last_export_dir,
            "copy_format": self._copy_format.get(),
            "export_choice": self._export_choice.get(),
            "ui_scale": self._ui_scale,
            "window_geometry": fit_window_geometry(
                str(self.geometry()), screen=screen, virtual=virtual
            ),
            "hide_rewriter": bool(self.hide_rewriter.get()),
            "hide_allowlisted": bool(self.hide_allowlisted.get()),
            "hide_private": bool(self.hide_private.get()),
            "actionable_only": bool(self.actionable_only.get()),
            "full_ioc_types": bool(self.full_ioc_types.get()),
            "appearance_mode": self._appearance_mode,
            "ioc_density": self._ioc_density,
            "brands_path": self._brands_path or "",
            "profile_dir": self._profile_dir or "",
            "post_export_hook": str(self._prefs.get("post_export_hook") or ""),
        }
        for name, var in self.cat_vars.items():
            updates[CAT_PREF_KEYS[name]] = bool(var.get())
        if not save_prefs(updates):
            append_error_log("failed to save ui_prefs.json")

    def _on_close(self) -> None:
        try:
            self._persist_prefs()
        except Exception as exc:  # noqa: BLE001
            append_error_log("prefs save on close failed", exc=exc)
        self.destroy()
