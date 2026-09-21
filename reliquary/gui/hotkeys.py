"""Global hotkeys and UI scale/appearance cycling — mixin for ExtractorApp."""

from __future__ import annotations

import tkinter as tk
from pathlib import Path

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
        self.bind("<Control-Shift-V>", lambda _e: self._toggle_verdict_compact())
        self.bind("<Control-Shift-v>", lambda _e: self._toggle_verdict_compact())
        self.bind("<Control-n>", lambda _e: self._batch_next_mail(1))
        self.bind("<Control-N>", lambda _e: self._batch_next_mail(1))
        self.bind("<Control-p>", lambda _e: self._batch_next_mail(-1))
        self.bind("<Control-P>", lambda _e: self._batch_next_mail(-1))
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

    def _toggle_verdict_compact(self) -> None:
        self._verdict_compact = not bool(getattr(self, "_verdict_compact", False))
        self._apply_verdict_compact()
        self._persist_prefs()
        mode = "вкл" if self._verdict_compact else "выкл"
        self._set_status(f"Компактный вердикт: {mode} (Ctrl+Shift+V)")

    def _apply_verdict_compact(self) -> None:
        """Скрыть левую панель исходника — фокус на вердикте (1 EXE, prefs рядом)."""
        left = getattr(self, "_left", None)
        body = getattr(self, "_body", None)
        if left is None or body is None:
            return
        try:
            if self._verdict_compact:
                left.grid_remove()
                body.grid_columnconfigure(0, weight=0, minsize=0)
                body.grid_columnconfigure(1, weight=1, minsize=320)
                # Jump to verdict tab
                self._hotkey_tab("mail")
            else:
                left.grid()
                body.grid_columnconfigure(0, weight=2, minsize=200)
                body.grid_columnconfigure(1, weight=5, minsize=320)
        except (AttributeError, tk.TclError):
            pass

    def _batch_next_mail(self, direction: int) -> str:
        """Ctrl+N / Ctrl+P — следующее/предыдущее письмо пакета + peer-diff при наличии."""
        batch = getattr(self, "_batch_results", None) or []
        if len(batch) < 2:
            self._set_status("Пакет: нужно ≥2 письма")
            return "break"
        paths = [r.source_path for r in batch]
        current = getattr(self, "result", None)
        cur_path = current.source_path if current else ""
        try:
            idx = paths.index(cur_path)
        except ValueError:
            idx = 0
        nxt = (idx + direction) % len(paths)
        target = batch[nxt]
        # Reuse analysis result already in memory
        self.result = target
        self._focus_source_file = target.source_path
        if hasattr(self, "_refresh_views"):
            self._refresh_views(full=True)
        name = Path(target.source_path).name
        peers: list[str] = []
        if target.file_rows:
            for row in target.file_rows:
                if Path(row.path).name == name:
                    peers = list(row.campaign_peers or [])
                    break
        else:
            for r in batch:
                for row in r.file_rows or []:
                    if Path(row.path).name == name and row.campaign_peers:
                        peers = list(row.campaign_peers)
                        break
                if peers:
                    break
        if peers and hasattr(self, "_show_campaign_diff"):
            self._show_campaign_diff(name, peers[0])
        self._set_status(f"Пакет {nxt + 1}/{len(batch)}: {name}")
        return "break"

    def _focus_search(self, _event: object = None) -> str:
        try:
            self.search_entry.focus_set()
            self.search_entry.select_range(0, "end")
        except (AttributeError, tk.TclError):
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
        except (AttributeError, tk.TclError):
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
        except (AttributeError, ValueError, TypeError, tk.TclError):
            pass
        try:
            self.ioc_table.set_ui_scale(self._ui_scale)
        except (AttributeError, tk.TclError):
            pass
        try:
            self._apply_panel_fonts()
        except (AttributeError, tk.TclError):
            pass
        self._persist_prefs()
        self._set_status(f"Масштаб UI: {int(self._ui_scale * 100)}%")
