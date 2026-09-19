"""Global hotkeys and UI scale/appearance cycling — mixin for ExtractorApp."""

from __future__ import annotations

import customtkinter as ctk

from reliquary.core.defang import defang_value
from reliquary.gui.theme import COLORS, apply_appearance

_TAB_HOTKEYS = ("mail", "att", "url", "ioc", "batch", "err")
_SCALE_STEPS = (0.85, 1.0, 1.15, 1.25, 1.35, 1.5)


class HotkeysMixin:
    """Requires ExtractorApp widgets, prefs, and clipboard helpers."""

    def _bind_global_hotkeys(self) -> None:
        self.bind("<Control-f>", self._focus_search)
        self.bind("<Control-F>", self._focus_search)
        self.bind("<Control-c>", self._hotkey_copy_values)
        self.bind("<Control-C>", self._hotkey_copy_values)
        self.bind("<Control-Shift-C>", self._hotkey_copy_defanged)
        self.bind("<Control-Shift-c>", self._hotkey_copy_defanged)
        self.bind("<Control-h>", lambda _e: self.copy_handoff())
        self.bind("<Control-H>", lambda _e: self.copy_handoff())
        self.bind("<Control-e>", lambda _e: self._export_clicked())
        self.bind("<Control-E>", lambda _e: self._export_clicked())
        self.bind("<Control-l>", lambda _e: self._cycle_appearance())
        self.bind("<Control-L>", lambda _e: self._cycle_appearance())
        self.bind("<Control-d>", lambda _e: self._cycle_density())
        self.bind("<Control-D>", lambda _e: self._cycle_density())
        self.bind("<Control-plus>", lambda _e: self._bump_scale(1))
        self.bind("<Control-equal>", lambda _e: self._bump_scale(1))
        self.bind("<Control-minus>", lambda _e: self._bump_scale(-1))
        self.bind("<Control-KP_Add>", lambda _e: self._bump_scale(1))
        self.bind("<Control-KP_Subtract>", lambda _e: self._bump_scale(-1))
        for i, key in enumerate(_TAB_HOTKEYS, start=1):
            self.bind(str(i), lambda _e, k=key: self._hotkey_tab(k))
            self.bind(f"<Key-{i}>", lambda _e, k=key: self._hotkey_tab(k))

    def _cycle_appearance(self) -> None:
        nxt = "light" if self._appearance_mode != "light" else "dark"
        self._appearance_mode = nxt
        apply_appearance(nxt)
        self.configure(fg_color=COLORS["bg"])
        self._persist_prefs()
        self._set_status(f"Тема: {nxt}")

    def _cycle_density(self) -> None:
        order = ("compact", "normal", "comfortable")
        try:
            idx = order.index(self._ioc_density)
        except ValueError:
            idx = 1
        self._ioc_density = order[(idx + 1) % len(order)]
        if hasattr(self, "ioc_table"):
            self.ioc_table.set_density(self._ioc_density)
        self._persist_prefs()
        self._set_status(f"Плотность IOC: {self._ioc_density}")

    def _focus_search(self, _event: object = None) -> str:
        try:
            self.search_entry.focus_set()
            self.search_entry.select_range(0, "end")
        except Exception:  # noqa: BLE001
            pass
        return "break"

    def _hotkey_tab(self, key: str) -> str:
        label = self._tab_label_by_key.get(key)
        if not label:
            return "break"
        self._tab_var.set(label)
        self._tab_seg.set(label)
        self._show_tab_frame(key)
        return "break"

    def _hotkey_copy_values(self, _event: object = None) -> str:
        try:
            focus = self.focus_get()
            if focus is not None and focus not in (self,):
                if focus != self.ioc_table.tree:
                    return ""
        except Exception:  # noqa: BLE001
            pass
        if not self.result:
            return "break"
        iocs = self._filtered_iocs()
        text = "\n".join(i.value for i in iocs)
        self.clipboard_clear()
        self.clipboard_append(text)
        self._set_status(f"Ctrl+C: значений {len(iocs)}")
        return "break"

    def _hotkey_copy_defanged(self, _event: object = None) -> str:
        if not self.result:
            return "break"
        iocs = self._filtered_iocs()
        text = "\n".join(defang_value(i.value) for i in iocs)
        self.clipboard_clear()
        self.clipboard_append(text)
        self._set_status(f"Ctrl+Shift+C: defanged {len(iocs)}")
        return "break"

    def _bump_scale(self, direction: int) -> None:
        try:
            idx = _SCALE_STEPS.index(
                min(_SCALE_STEPS, key=lambda s: abs(s - self._ui_scale))
            )
        except ValueError:
            idx = 1
        idx = max(0, min(len(_SCALE_STEPS) - 1, idx + direction))
        self._ui_scale = _SCALE_STEPS[idx]
        try:
            ctk.set_widget_scaling(self._ui_scale)
        except Exception:  # noqa: BLE001
            pass
        try:
            self.ioc_table.set_ui_scale(self._ui_scale)
        except Exception:  # noqa: BLE001
            pass
        try:
            self._apply_panel_fonts()
        except Exception:  # noqa: BLE001
            pass
        self._persist_prefs()
        self._set_status(f"Масштаб UI: {int(self._ui_scale * 100)}%")
