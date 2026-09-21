"""Prefs persistence and window geometry — mixin for ExtractorApp."""

from __future__ import annotations

from typing import Any

from reliquary.core.error_log import append_error_log
from reliquary.core.filter_state import CAT_PREF_KEYS
from reliquary.core.prefs import save_prefs
from reliquary.gui.settings_dialog import show_settings_dialog
from reliquary.gui.windowing import (
    fit_window_geometry,
    parse_geometry,
    primary_work_area,
    size_only_geometry,
)


class PrefsMixin:
    """Requires ExtractorApp filter vars, paths, and screen helpers."""

    def show_settings(self) -> None:
        """Open fleet prefs dialog (paths / workers / hook / Campaign pack)."""

        def _apply(fresh: dict[str, Any]) -> None:
            self._prefs = fresh
            self._allowlist_path = str(fresh.get("allowlist_path") or "") or None
            self._verdict_path = str(fresh.get("verdict_path") or "") or None
            self._handoff_template_path = (
                str(fresh.get("handoff_template_path") or "") or None
            )
            self._brands_path = str(fresh.get("brands_path") or "") or None
            self._profile_dir = str(fresh.get("profile_dir") or "") or None
            self._appearance_mode = str(fresh.get("appearance_mode") or "dark")
            self._ioc_density = str(fresh.get("ioc_density") or "normal")
            self._verdict_compact = bool(fresh.get("verdict_compact"))
            try:
                from reliquary.gui.theme import apply_appearance, set_high_contrast

                set_high_contrast(bool(fresh.get("high_contrast")))
                remap = apply_appearance(self._appearance_mode)
                self._apply_live_theme(remap)
            except Exception:  # noqa: BLE001
                pass
            try:
                if hasattr(self, "ioc_table"):
                    self.ioc_table.set_density(self._ioc_density)
            except Exception:  # noqa: BLE001
                pass
            try:
                self._apply_verdict_compact()
            except Exception:  # noqa: BLE001
                pass
            try:
                self._export_choice.set(str(fresh.get("export_choice") or "JSON"))
            except Exception:  # noqa: BLE001
                pass
            for attr, key in (
                ("actionable_only", "actionable_only"),
                ("hide_rewriter", "hide_rewriter"),
                ("hide_allowlisted", "hide_allowlisted"),
                ("hide_private", "hide_private"),
                ("full_ioc_types", "full_ioc_types"),
            ):
                var = getattr(self, attr, None)
                if var is not None:
                    try:
                        var.set(bool(fresh.get(key)))
                    except Exception:  # noqa: BLE001
                        pass
            try:
                self._set_status("Настройки сохранены (ui_prefs.json)")
            except Exception:  # noqa: BLE001
                pass

        show_settings_dialog(self, prefs=self._prefs, on_saved=_apply)

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
            "last_inbox_dir": str(self._prefs.get("last_inbox_dir") or ""),
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
            "verdict_compact": bool(getattr(self, "_verdict_compact", False)),
            "brands_path": self._brands_path or "",
            "profile_dir": self._profile_dir or "",
            "allowlist_path": self._allowlist_path or "",
            "verdict_path": self._verdict_path or "",
            "handoff_template_path": self._handoff_template_path or "",
            "post_export_hook": str(self._prefs.get("post_export_hook") or ""),
            "post_export_hook_json_sidecar": bool(
                self._prefs.get("post_export_hook_json_sidecar", True)
            ),
            "post_export_hook_allow_external": bool(
                self._prefs.get("post_export_hook_allow_external", False)
            ),
            "disable_post_export_hook": bool(
                self._prefs.get("disable_post_export_hook", False)
            ),
            "max_workers": int(self._prefs.get("max_workers") or 0),
            "folder_warn_threshold": int(self._prefs.get("folder_warn_threshold") or 80),
            "skip_broken": bool(self._prefs.get("skip_broken", True)),
            "batch_sort_column": str(getattr(self, "_batch_sort_col", "score") or "score"),
            "batch_sort_reverse": bool(getattr(self, "_batch_sort_reverse", True)),
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
