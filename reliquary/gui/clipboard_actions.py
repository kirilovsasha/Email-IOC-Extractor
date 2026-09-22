"""Clipboard and export actions — mixin for ExtractorApp."""

from __future__ import annotations

import csv
import io
from pathlib import Path
from tkinter import filedialog, messagebox

from reliquary import __app_name__
from reliquary.core.defang import defang_ioc_line, defang_value
from reliquary.core.error_log import append_error_log
from reliquary.core.handoff import render_handoff
from reliquary.core.models import Ioc
from reliquary.gui.export_actions import (
    default_export_filename,
    normalize_export_kind,
    run_export,
)


class ClipboardActionsMixin:
    """Requires ExtractorApp result, filter helpers, and clipboard widgets."""

    def _copy_from(self) -> None:
        if not self.result or not self.result.mail_identity:
            return
        value = self.result.mail_identity.from_header or ""
        if not value:
            return
        self.clipboard_clear()
        self.clipboard_append(value)
        self._set_status("From скопирован")

    def _copy_auth(self) -> None:
        if not self.result or not self.result.mail_identity:
            return
        mid = self.result.mail_identity
        text = f"SPF={mid.spf or '—'} DKIM={mid.dkim or '—'} DMARC={mid.dmarc or '—'}"
        self.clipboard_clear()
        self.clipboard_append(text)
        self._set_status("Auth скопирован")

    def copy_handoff(self) -> None:
        if not self.result:
            messagebox.showinfo(__app_name__, "Сначала разберите письмо")
            return
        text = render_handoff(
            self.result,
            self._filtered_iocs(),
            template_path=self._handoff_template_path,
            handoff_by_level=getattr(self, "_handoff_by_level", None),
        )
        self.clipboard_clear()
        self.clipboard_append(text)
        self._set_status("Текст для тикета скопирован в буфер")

    def copy_verdict_reasons(self) -> None:
        """Скопировать причины вердикта (для тикета / калибровки)."""
        if not self.result or not self.result.verdict:
            self._set_status("Нет вердикта для копирования причин")
            return
        v = self.result.verdict
        lines = [
            f"Вердикт: {v.level.value}  score={v.score}",
            v.summary,
            "",
            "Причины:",
            *[f"• {r}" for r in v.reasons],
        ]
        text = "\n".join(lines)
        self.clipboard_clear()
        self.clipboard_append(text)
        self._set_status(f"Причины вердикта скопированы ({len(v.reasons)})")

    def _format_iocs_for_clipboard(self, iocs: list[Ioc]) -> str:
        fmt = self._copy_format.get()
        if fmt == "value":
            return "\n".join(i.value for i in iocs)
        if fmt == "csv":
            buf = io.StringIO()
            writer = csv.writer(buf)
            writer.writerow(["ioc_type", "value", "tags"])
            for i in iocs:
                writer.writerow([i.ioc_type.value, i.value, "|".join(i.tags)])
            return buf.getvalue()
        if fmt == "defanged":
            return "\n".join(defang_value(i.value) for i in iocs)
        if fmt == "defanged|type":
            return "\n".join(
                defang_ioc_line(i.ioc_type.value, i.value, with_type=True) for i in iocs
            )
        return "\n".join(f"{i.ioc_type.value}|{i.value}" for i in iocs)

    def copy_iocs(self) -> None:
        if not self.result:
            messagebox.showinfo(__app_name__, "Сначала разберите письмо")
            return
        iocs = self._filtered_iocs()
        if not iocs:
            messagebox.showinfo(__app_name__, "Нет IOC для копирования (проверьте фильтры)")
            return
        text = self._format_iocs_for_clipboard(iocs)
        self.clipboard_clear()
        self.clipboard_append(text)
        self._set_status(f"Скопировано IOC: {len(iocs)} ({self._copy_format.get()})")

    def _export_clicked(self) -> None:
        self.export(self._export_choice.get())

    def export(self, kind: str) -> None:
        filtered = self._filtered_result()
        if not filtered:
            messagebox.showinfo(__app_name__, "Сначала разберите письмо")
            return
        kind_n = normalize_export_kind(kind)
        initialdir = self._last_export_dir or self._last_dir or None
        initial = default_export_filename(kind)
        ext = Path(initial).suffix or ".bin"
        filetypes = {
            "csv": [("CSV", "*.csv")],
            "batch_csv": [("CSV", "*.csv")],
            "json": [("JSON", "*.json")],
            "handoff": [("Text", "*.txt")],
            "ecs": [("ECS JSON", "*.json")],
            "cef": [("CEF", "*.cef"), ("Text", "*.txt")],
            "stix": [("STIX JSON", "*.json")],
            "misp": [("MISP CSV", "*.csv")],
            "opencti": [("OpenCTI JSON", "*.json")],
            "campaign": [("Text", "*.txt")],
        }.get(kind_n, [("All", "*.*")])

        path = filedialog.asksaveasfilename(
            defaultextension=ext,
            filetypes=filetypes,
            initialfile=initial,
            initialdir=initialdir,
        )
        if not path:
            return
        try:
            out = run_export(
                kind_n,
                filtered,
                path,
                filters_applied=self._filter_kwargs_serializable(),
                batch_results=self._batch_results,
                filtered_iocs=list(filtered.iocs),
                handoff_template_path=self._handoff_template_path,
                handoff_by_level=getattr(self, "_handoff_by_level", None),
            )
        except ValueError as exc:
            messagebox.showinfo(__app_name__, str(exc))
            return
        except Exception as exc:  # noqa: BLE001
            append_error_log("export failed", exc=exc)
            messagebox.showerror(__app_name__, f"Экспорт не удался:\n{exc}")
            return
        self._last_export_dir = str(Path(path).parent)
        self._persist_prefs()
        self._set_status(f"{kind}: {out}")

    def _filter_kwargs_serializable(self) -> dict:
        return self._current_filter_state().serializable()
