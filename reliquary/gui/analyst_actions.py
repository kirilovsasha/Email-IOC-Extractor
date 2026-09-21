"""Действия аналитика — allowlist, override вердикта, заметка о шифрованном архиве."""

from __future__ import annotations

import tkinter as tk
from tkinter import messagebox, simpledialog

from reliquary import __app_name__
from reliquary.core.allowlist import append_allowlist_entry, resolve_allowlist_path
from reliquary.core.error_log import append_error_log
from reliquary.core.handoff import encrypted_archive_handoff_note
from reliquary.core.models import Ioc, VerdictLevel
from reliquary.core.prefs import load_prefs, save_prefs
from reliquary.gui.i18n import t


class AnalystActionsMixin:
    """Требует ExtractorApp: result, clipboard, status."""

    def _allowlist_host_from_ioc(self, ioc: Ioc | None = None) -> None:
        target = ioc
        if target is None and hasattr(self, "ioc_table"):
            target = getattr(self.ioc_table, "selected_ioc", None) or getattr(
                self.ioc_table, "_selected", None
            )
        if target is None and self.result and self.result.iocs:
            value = simpledialog.askstring(
                __app_name__,
                "Домен / IP / URL / email для allowlist:",
                parent=self,
            )
            if not value:
                return
            entry = value
        else:
            if target is None:
                self._set_status("Нет IOC для allowlist")
                return
            entry = target.value
        try:
            prefs = load_prefs()
            path = resolve_allowlist_path(prefs.get("allowlist_path") or None)
            written = append_allowlist_entry(entry, path=path)
            self._set_status(f"Allowlist ← {entry} → {written.name}")
            messagebox.showinfo(
                __app_name__,
                f"Добавлено в {written.name}.\n"
                "Переразберите письмо, чтобы тег allowlisted применился.",
            )
        except (OSError, ValueError, TypeError) as exc:
            append_error_log("allowlist append failed", exc=exc)
            messagebox.showerror(__app_name__, str(exc))

    def _override_verdict(self) -> None:
        if not self.result or not self.result.verdict:
            messagebox.showinfo(__app_name__, "Сначала разберите письмо")
            return
        choice = simpledialog.askstring(
            t("btn_override"),
            "Новый уровень: benign / unknown / suspicious / malicious",
            parent=self,
            initialvalue=self.result.verdict.level.value,
        )
        if not choice:
            return
        level = choice.strip().lower()
        try:
            new_level = VerdictLevel(level)
        except ValueError:
            messagebox.showerror(__app_name__, f"Неизвестный уровень: {choice}")
            return
        note = simpledialog.askstring(
            t("btn_override"),
            "Заметка аналитика (необязательно):",
            parent=self,
        ) or ""
        v = self.result.verdict
        old = v.level.value
        v.analyst_override = new_level.value
        v.analyst_note = note.strip()
        v.level = new_level
        v.summary = f"[override аналитика {old}→{new_level.value}] {v.summary}"
        if note.strip():
            v.reasons = [f"Аналитик: {note.strip()}"] + list(v.reasons)
        self._refresh_views(full=True)
        self._set_status(f"Override: {old} → {new_level.value}")

    def _copy_encrypted_archive_note(self) -> None:
        name = ""
        if self.result and self.result.attachments:
            for att in self.result.attachments:
                if "encrypted_archive" in att.risk_flags:
                    name = att.filename
                    break
        note = encrypted_archive_handoff_note(name)
        try:
            self.clipboard_clear()
            self.clipboard_append(note)
            self._set_status(t("btn_copy_enc_note"))
        except tk.TclError as exc:
            append_error_log("clipboard encrypted note failed", exc=exc)

    def _toggle_high_contrast(self) -> None:
        from reliquary.gui.theme import apply_appearance, set_high_contrast

        enabled = not bool(self._prefs.get("high_contrast"))
        self._prefs["high_contrast"] = enabled
        save_prefs({"high_contrast": enabled})
        try:
            set_high_contrast(enabled)
            apply_appearance(str(self._prefs.get("appearance_mode") or "dark"))
        except (AttributeError, ValueError, TypeError):
            pass
        self._set_status(f"{t('high_contrast')}: {'вкл' if enabled else 'выкл'}")
