"""Prefs persistence and window geometry — mixin for ExtractorApp."""

from __future__ import annotations

from reliquary.core.error_log import append_error_log
from reliquary.core.filter_state import CAT_PREF_KEYS
from reliquary.core.prefs import save_prefs
from reliquary.gui.windowing import (
    fit_window_geometry,
    parse_geometry,
    primary_work_area,
    size_only_geometry,
)


class PrefsMixin:
    """Requires ExtractorApp filter vars, paths, and screen helpers."""

    def _apply_saved_geometry(self) -> None:
        """Restore size from prefs; center and shrink so the window fits on screen."""
        geom = str(self._prefs.get("window_geometry") or "1320x820")
        screen, virtual = self._screen_metrics()
        work = primary_work_area()
        fitted = fit_window_geometry(
            geom,
            screen=screen,
            virtual=virtual,
            work_area=work,
            force_center=True,
        )
        fw, fh, _, _ = parse_geometry(fitted)
        # minsize must not exceed fitted size, or Tk will clip the window
        try:
            self.minsize(min(920, fw), min(620, fh))
        except Exception:  # noqa: BLE001
            pass
        try:
            self.geometry(fitted)
        except Exception:  # noqa: BLE001
            self.geometry("1320x820")
        try:
            self.after_idle(self._ensure_window_fully_visible)
        except Exception:  # noqa: BLE001
            pass

    def _ensure_window_fully_visible(self) -> None:
        """Second pass after map: re-fit using live screen metrics."""
        try:
            self.update_idletasks()
        except Exception:  # noqa: BLE001
            return
        try:
            cur = str(self.geometry())
        except Exception:  # noqa: BLE001
            return
        screen, virtual = self._screen_metrics()
        fitted = fit_window_geometry(
            cur,
            screen=screen,
            virtual=virtual,
            work_area=primary_work_area(),
            force_center=True,
        )
        if fitted.split("+", 1)[0] != cur.split("+", 1)[0] or fitted != cur:
            fw, fh, _, _ = parse_geometry(fitted)
            try:
                self.minsize(min(920, fw), min(620, fh))
            except Exception:  # noqa: BLE001
                pass
            try:
                self.geometry(fitted)
            except Exception:  # noqa: BLE001
                pass

    def _persist_prefs(self) -> None:
        # Persist size only — position is recalculated (centered) on next launch
        updates = {
            "last_dir": self._last_dir,
            "last_export_dir": self._last_export_dir,
            "copy_format": self._copy_format.get(),
            "export_choice": self._export_choice.get(),
            "ui_scale": self._ui_scale,
            "window_geometry": size_only_geometry(str(self.geometry())),
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
        profile = getattr(self, "_org_profile", None)
        if profile is not None:
            try:
                profile.cleanup()
            except Exception as exc:  # noqa: BLE001
                append_error_log("org profile cleanup failed", exc=exc)
            self._org_profile = None
        self.destroy()
