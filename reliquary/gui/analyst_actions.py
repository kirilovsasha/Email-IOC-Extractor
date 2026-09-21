"""Действия аналитика — allowlist, override вердикта, заметка о шифрованном архиве."""

from __future__ import annotations

import tkinter as tk
from tkinter import messagebox, simpledialog

from reliquary import __app_name__
from reliquary.core.allowlist import append_allowlist_entry, resolve_allowlist_path
from reliquary.core.error_log import append_error_log
from reliquary.core.handoff import encrypted_archive_handoff_note
from reliquary.core.labels import parse_verdict_level, verdict_label_ru
from reliquary.core.models import Ioc
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
            t("verdict_prompt"),
            parent=self,
            initialvalue=self.result.verdict.level.value,
        )
        if not choice:
            return
        new_level = parse_verdict_level(choice)
        if new_level is None:
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
        v.summary = (
            f"[сменён аналитиком {verdict_label_ru(old)}→"
            f"{verdict_label_ru(new_level)}] {v.summary}"
        )
        if note.strip():
            v.reasons = [f"Аналитик: {note.strip()}"] + list(v.reasons)
        self._refresh_views(full=True)
        self._set_status(
            f"Вердикт: {verdict_label_ru(old)} → {verdict_label_ru(new_level)}"
        )

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
            mode = str(
                getattr(self, "_appearance_mode", None)
                or self._prefs.get("appearance_mode")
                or "dark"
            )
            remap = apply_appearance(mode)
            if hasattr(self, "_apply_live_theme"):
                self._apply_live_theme(remap)
        except (AttributeError, ValueError, TypeError, tk.TclError):
            pass
        self._set_status(f"{t('high_contrast')}: {'вкл' if enabled else 'выкл'}")

    def _record_feedback(self, kind: str) -> None:
        """FP / FN / confirm → analyst_feedback.ndjson рядом с EXE."""
        from reliquary.core.calibration import segment_for
        from reliquary.core.feedback import FeedbackEvent, append_feedback

        if not self.result or not self.result.verdict:
            messagebox.showinfo(__app_name__, "Сначала разберите письмо")
            return
        v = self.result.verdict
        observed = v.level.value
        if kind == "fp":
            expected = "benign"
            prompt = "Ожидаемый уровень (по умолчанию benign):"
        elif kind == "fn":
            expected = "suspicious"
            prompt = "Ожидаемый уровень (suspicious/malicious):"
        else:
            expected = observed
            prompt = "Подтверждённый уровень:"
        choice = simpledialog.askstring(
            __app_name__, prompt, parent=self, initialvalue=expected
        )
        if choice is None:
            return
        expected = (choice or expected).strip().lower() or expected
        note = simpledialog.askstring(
            __app_name__, "Комментарий (необязательно):", parent=self
        ) or ""
        sha = ""
        if self.result.meta and self.result.meta.source_sha256:
            sha = self.result.meta.source_sha256
        try:
            seg = segment_for(self.result)
        except Exception:  # noqa: BLE001
            seg = ""
        path = append_feedback(
            FeedbackEvent(
                kind=kind,
                expected_level=expected,
                observed_level=observed,
                score=int(v.score),
                source_path=self.result.source_path or "",
                source_sha256=sha,
                note=note.strip(),
                segment=seg,
            )
        )
        self._set_status(f"Feedback {kind} → {path.name}")
        messagebox.showinfo(__app_name__, f"Записано в {path.name}")
