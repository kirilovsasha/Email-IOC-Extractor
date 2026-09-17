"""Reliquary desktop GUI (CustomTkinter) — offline SOC triage console."""

from __future__ import annotations

import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox

import customtkinter as ctk

from reliquary import __app_name__, __tagline__, __version__
from reliquary.core.exporters import export_csv, export_report_json, export_stix
from reliquary.core.models import AnalysisResult
from reliquary.core.offline import enforce_offline
from reliquary.core.pipeline import analyze_file, analyze_text
from reliquary.gui.theme import COLORS, VERDICT_COLORS, VERDICT_LABELS_RU

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")


class ReliquaryApp(ctk.CTk):
    def __init__(self) -> None:
        super().__init__()
        self.title(f"{__app_name__} — {__tagline__}")
        self.geometry("1280x820")
        self.minsize(1024, 700)
        self.configure(fg_color=COLORS["bg"])

        self.result: AnalysisResult | None = None
        self._build()

    def _build(self) -> None:
        # Brand header — hero-level product signal
        header = ctk.CTkFrame(self, fg_color=COLORS["surface"], corner_radius=0, height=72)
        header.pack(fill="x")
        header.pack_propagate(False)

        brand = ctk.CTkLabel(
            header,
            text="RELIQUARY",
            font=ctk.CTkFont(family="Segoe UI", size=28, weight="bold"),
            text_color=COLORS["accent"],
        )
        brand.pack(side="left", padx=(24, 12), pady=16)

        tag = ctk.CTkLabel(
            header,
            text=f"{__tagline__}  ·  v{__version__}  ·  offline",
            font=ctk.CTkFont(size=13),
            text_color=COLORS["muted"],
        )
        tag.pack(side="left", pady=16)

        # Toolbar
        toolbar = ctk.CTkFrame(self, fg_color=COLORS["bg"])
        toolbar.pack(fill="x", padx=20, pady=(16, 8))

        ctk.CTkButton(
            toolbar,
            text="Открыть файл",
            command=self.open_file,
            fg_color=COLORS["accent"],
            hover_color=COLORS["accent_dim"],
            width=140,
        ).pack(side="left", padx=(0, 8))

        ctk.CTkButton(
            toolbar,
            text="Анализ текста",
            command=self.analyze_clipboard_area,
            fg_color=COLORS["surface_alt"],
            hover_color=COLORS["border"],
            width=140,
        ).pack(side="left", padx=(0, 8))

        ctk.CTkButton(
            toolbar,
            text="Экспорт CSV",
            command=lambda: self.export("csv"),
            fg_color=COLORS["surface_alt"],
            hover_color=COLORS["border"],
            width=120,
        ).pack(side="left", padx=(0, 8))

        ctk.CTkButton(
            toolbar,
            text="Экспорт STIX",
            command=lambda: self.export("stix"),
            fg_color=COLORS["surface_alt"],
            hover_color=COLORS["border"],
            width=120,
        ).pack(side="left", padx=(0, 8))

        ctk.CTkButton(
            toolbar,
            text="Отчёт JSON",
            command=lambda: self.export("json"),
            fg_color=COLORS["surface_alt"],
            hover_color=COLORS["border"],
            width=120,
        ).pack(side="left", padx=(0, 8))

        self.status = ctk.CTkLabel(
            toolbar, text="Готов к работе — сеть не используется", text_color=COLORS["muted"]
        )
        self.status.pack(side="right")

        # Body: left input / right results
        body = ctk.CTkFrame(self, fg_color=COLORS["bg"])
        body.pack(fill="both", expand=True, padx=20, pady=(0, 16))
        body.grid_columnconfigure(0, weight=1)
        body.grid_columnconfigure(1, weight=2)
        body.grid_rowconfigure(0, weight=1)

        left = ctk.CTkFrame(body, fg_color=COLORS["surface"], corner_radius=8)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 10))

        ctk.CTkLabel(
            left,
            text="Входные данные / тикет",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color=COLORS["text"],
        ).pack(anchor="w", padx=16, pady=(16, 8))

        self.input_box = ctk.CTkTextbox(
            left,
            fg_color=COLORS["surface_alt"],
            text_color=COLORS["text"],
            font=ctk.CTkFont(family="Consolas", size=13),
            wrap="word",
        )
        self.input_box.pack(fill="both", expand=True, padx=16, pady=(0, 16))
        self.input_box.insert(
            "1.0",
            "Вставьте текст тикета, письмо или перетащите файл через «Открыть файл».\n"
            "Поддержка: .eml .msg .pdf .html .htm .txt\n\n"
            "Reliquary работает полностью офлайн.",
        )

        right = ctk.CTkFrame(body, fg_color=COLORS["surface"], corner_radius=8)
        right.grid(row=0, column=1, sticky="nsew")

        # Verdict banner
        self.verdict_frame = ctk.CTkFrame(right, fg_color=COLORS["surface_alt"], corner_radius=6)
        self.verdict_frame.pack(fill="x", padx=16, pady=16)

        self.verdict_label = ctk.CTkLabel(
            self.verdict_frame,
            text="ВЕРДИКТ: —",
            font=ctk.CTkFont(size=22, weight="bold"),
            text_color=COLORS["muted"],
        )
        self.verdict_label.pack(anchor="w", padx=16, pady=(12, 4))

        self.verdict_summary = ctk.CTkLabel(
            self.verdict_frame,
            text="Загрузите артефакт для triage",
            font=ctk.CTkFont(size=13),
            text_color=COLORS["muted"],
            wraplength=700,
            justify="left",
        )
        self.verdict_summary.pack(anchor="w", padx=16, pady=(0, 12))

        # Tabs
        self.tabs = ctk.CTkTabview(
            right,
            fg_color=COLORS["surface"],
            segmented_button_fg_color=COLORS["surface_alt"],
            segmented_button_selected_color=COLORS["accent"],
            segmented_button_selected_hover_color=COLORS["accent_dim"],
            segmented_button_unselected_color=COLORS["surface_alt"],
            text_color=COLORS["text"],
        )
        self.tabs.pack(fill="both", expand=True, padx=16, pady=(0, 16))

        for name in ("IOC", "Заголовки", "URL Rewrite", "Вложения", "Действия", "Причины"):
            self.tabs.add(name)

        self.ioc_tree = self._make_text(self.tabs.tab("IOC"))
        self.hdr_tree = self._make_text(self.tabs.tab("Заголовки"))
        self.url_tree = self._make_text(self.tabs.tab("URL Rewrite"))
        self.att_tree = self._make_text(self.tabs.tab("Вложения"))
        self.act_tree = self._make_text(self.tabs.tab("Действия"))
        self.reason_tree = self._make_text(self.tabs.tab("Причины"))

        # Drag-and-drop hint via drop on window (tk doesn't have native DnD everywhere)
        self.bind("<Control-o>", lambda _e: self.open_file())

    def _make_text(self, parent: ctk.CTkFrame) -> ctk.CTkTextbox:
        box = ctk.CTkTextbox(
            parent,
            fg_color=COLORS["surface_alt"],
            text_color=COLORS["text"],
            font=ctk.CTkFont(family="Consolas", size=12),
            wrap="none",
        )
        box.pack(fill="both", expand=True, padx=4, pady=4)
        return box

    def _set_status(self, text: str) -> None:
        self.status.configure(text=text)

    def open_file(self) -> None:
        path = filedialog.askopenfilename(
            title="Reliquary — выбрать артефакт",
            filetypes=[
                ("Все поддерживаемые", "*.eml *.msg *.pdf *.html *.htm *.txt *.csv *.log"),
                ("Email", "*.eml *.msg"),
                ("PDF", "*.pdf"),
                ("HTML", "*.html *.htm"),
                ("Текст / тикет", "*.txt *.csv *.log *.md"),
                ("Все файлы", "*.*"),
            ],
        )
        if not path:
            return
        self._set_status(f"Анализ: {Path(path).name}…")
        self.update_idletasks()
        threading.Thread(target=self._run_file, args=(path,), daemon=True).start()

    def _run_file(self, path: str) -> None:
        try:
            result = analyze_file(path)
            self.after(0, lambda: self._apply_result(result, preload_text=True))
        except Exception as exc:  # noqa: BLE001
            self.after(0, lambda: messagebox.showerror("Ошибка", str(exc)))
            self.after(0, lambda: self._set_status("Ошибка анализа"))

    def analyze_clipboard_area(self) -> None:
        text = self.input_box.get("1.0", "end").strip()
        if not text or text.startswith("Вставьте текст"):
            messagebox.showinfo("Reliquary", "Вставьте текст тикета в левую панель")
            return
        self._set_status("Анализ текста…")
        threading.Thread(target=self._run_text, args=(text,), daemon=True).start()

    def _run_text(self, text: str) -> None:
        try:
            result = analyze_text(text)
            self.after(0, lambda: self._apply_result(result, preload_text=False))
        except Exception as exc:  # noqa: BLE001
            self.after(0, lambda: messagebox.showerror("Ошибка", str(exc)))

    def _apply_result(self, result: AnalysisResult, preload_text: bool) -> None:
        self.result = result
        if preload_text:
            preview = result.raw_text_preview or ""
            meta = (
                f"Файл: {result.source_path}\n"
                f"Тип: {result.source_kind}\n"
                f"From: {result.sender}\n"
                f"Subject: {result.subject}\n"
                f"{'=' * 48}\n\n"
                f"{preview}"
            )
            self.input_box.delete("1.0", "end")
            self.input_box.insert("1.0", meta)

        v = result.verdict
        if v:
            color = VERDICT_COLORS.get(v.level.value, COLORS["muted"])
            label = VERDICT_LABELS_RU.get(v.level.value, v.level.value.upper())
            self.verdict_label.configure(
                text=f"ВЕРДИКТ: {label}  ·  score {v.score}/100",
                text_color=color,
            )
            self.verdict_summary.configure(text=v.summary, text_color=COLORS["text"])
        else:
            self.verdict_label.configure(text="ВЕРДИКТ: —", text_color=COLORS["muted"])

        self._fill_iocs(result)
        self._fill_headers(result)
        self._fill_urls(result)
        self._fill_attachments(result)
        self._fill_actions(result)
        self._fill_reasons(result)

        err = f" · ошибки: {len(result.errors)}" if result.errors else ""
        self._set_status(
            f"Готово: {len(result.iocs)} IOC, {len(result.attachments)} влож., "
            f"{len(result.headers)} находок по заголовкам{err}"
        )

    def _write(self, box: ctk.CTkTextbox, content: str) -> None:
        box.delete("1.0", "end")
        box.insert("1.0", content)

    def _fill_iocs(self, result: AnalysisResult) -> None:
        lines = [f"{'TYPE':<12} {'VALUE':<60} TAGS", "-" * 100]
        for ioc in result.iocs:
            tags = ",".join(ioc.tags)
            extra = f"  ← {ioc.rewritten_from}" if ioc.rewritten_from else ""
            lines.append(f"{ioc.ioc_type.value:<12} {ioc.value:<60} {tags}{extra}")
        if len(lines) == 2:
            lines.append("(IOC не найдены)")
        self._write(self.ioc_tree, "\n".join(lines))

    def _fill_headers(self, result: AnalysisResult) -> None:
        lines = [f"{'SEV':<10} {'NAME':<28} NOTE", "-" * 100]
        for h in result.headers:
            lines.append(f"{h.severity.value:<10} {h.name:<28} {h.note}")
            lines.append(f"{'':10} {h.value[:120]}")
            lines.append("")
        if len(result.headers) == 0:
            lines.append("(нет заголовков — не email или MSG без метаданных)")
        self._write(self.hdr_tree, "\n".join(lines))

    def _fill_urls(self, result: AnalysisResult) -> None:
        lines = [f"{'REWRITER':<22} CHANGED  URL", "-" * 100]
        for u in result.url_rewrites:
            lines.append(f"{u.rewriter:<22} {str(u.changed):<8} {u.original}")
            if u.changed:
                lines.append(f"{'':22} {'=>':<8} {u.unwrapped}")
            lines.append("")
        if not result.url_rewrites:
            lines.append("(URL не найдены)")
        self._write(self.url_tree, "\n".join(lines))

    def _fill_attachments(self, result: AnalysisResult) -> None:
        lines = []
        for a in result.attachments:
            lines.append(f"• {a.filename}  ({a.size} bytes, {a.mime_guess})")
            lines.append(f"  MD5:    {a.md5}")
            lines.append(f"  SHA1:   {a.sha1}")
            lines.append(f"  SHA256: {a.sha256}")
            if a.risk_flags:
                lines.append(f"  FLAGS:  {', '.join(a.risk_flags)}")
            for n in a.notes:
                lines.append(f"  — {n}")
            lines.append("")
        if not lines:
            lines.append("(вложений нет)")
        self._write(self.att_tree, "\n".join(lines))

    def _fill_actions(self, result: AnalysisResult) -> None:
        lines = []
        if result.verdict:
            for a in result.verdict.actions:
                lines.append(f"[{a.priority}] {a.action}")
                lines.append(f"    {a.rationale}")
                lines.append("")
        if not lines:
            lines.append("(нет рекомендаций)")
        self._write(self.act_tree, "\n".join(lines))

    def _fill_reasons(self, result: AnalysisResult) -> None:
        lines = []
        if result.verdict:
            for r in result.verdict.reasons:
                lines.append(f"• {r}")
        if result.errors:
            lines.append("")
            lines.append("Ошибки парсинга:")
            for e in result.errors:
                lines.append(f"! {e}")
        self._write(self.reason_tree, "\n".join(lines) if lines else "(пусто)")

    def export(self, kind: str) -> None:
        if not self.result:
            messagebox.showinfo("Reliquary", "Сначала выполните анализ")
            return
        if kind == "csv":
            path = filedialog.asksaveasfilename(
                defaultextension=".csv",
                filetypes=[("CSV", "*.csv")],
                initialfile="reliquary_iocs.csv",
            )
            if path:
                export_csv(self.result, path)
                self._set_status(f"CSV сохранён: {path}")
        elif kind == "stix":
            path = filedialog.asksaveasfilename(
                defaultextension=".json",
                filetypes=[("STIX JSON", "*.json")],
                initialfile="reliquary_stix.json",
            )
            if path:
                export_stix(self.result, path)
                self._set_status(f"STIX сохранён: {path}")
        elif kind == "json":
            path = filedialog.asksaveasfilename(
                defaultextension=".json",
                filetypes=[("JSON", "*.json")],
                initialfile="reliquary_report.json",
            )
            if path:
                export_report_json(self.result, path)
                self._set_status(f"Отчёт сохранён: {path}")


def run() -> None:
    enforce_offline()
    # Ensure Tcl/Tk is available; fail with a clear message for headless CI.
    try:
        app = ReliquaryApp()
    except tk.TclError as exc:
        raise SystemExit(
            f"GUI недоступен ({exc}). Для headless-среды используйте: "
            "python -m reliquary.cli <файл>"
        ) from exc
    app.mainloop()
