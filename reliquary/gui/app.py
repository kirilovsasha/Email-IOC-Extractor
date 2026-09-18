"""IOC Extractor desktop GUI — extract IOCs from files and text (CustomTkinter)."""

from __future__ import annotations

import csv
import io
import os
import re
import subprocess
import sys
import threading
import tkinter as tk
from collections import Counter
from pathlib import Path
from tkinter import filedialog, messagebox

import customtkinter as ctk

from reliquary import __app_name__, __tagline__, __version__
from reliquary.core.exporters import (
    _with_iocs,
    export_csv,
    export_misp,
    export_opencti,
    export_report_json,
    export_stix,
    export_yara,
    filter_iocs,
)
from reliquary.core.models import AnalysisResult, Ioc
from reliquary.core.offline import enforce_offline
from reliquary.core.paths import app_dir, ensure_user_lists, list_file_path
from reliquary.core.pipeline import analyze_file, analyze_text, merge_results
from reliquary.gui.theme import (
    COLORS,
    IOC_GROUPS,
    IOC_TYPE_COLORS,
    SEVERITY_COLORS,
    SEVERITY_LABELS_RU,
)

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

_PLACEHOLDER = (
    "Вставьте текст тикета или откройте файл.\n\n"
    "Форматы: .eml .msg .pdf .html .txt .docx .xlsx .zip\n"
    "Письма: IOC, URL, вложения, заголовки, вердикт.\n"
    "Перетащите файлы/папки или откройте папку (рекурсивно).\n\n"
    "Клик по IOC — копировать значение. Офлайн."
)

_SUPPORTED_GLOBS = (
    "*.eml",
    "*.msg",
    "*.pdf",
    "*.html",
    "*.htm",
    "*.txt",
    "*.csv",
    "*.log",
    "*.md",
    "*.docx",
    "*.xlsx",
    "*.zip",
)
_SUPPORTED_SUFFIXES = {g[1:].lower() for g in _SUPPORTED_GLOBS}

_CATEGORY_TYPES: dict[str, set[str]] = {
    "Сеть": set(IOC_GROUPS[0][1]),
    "Хеши": set(IOC_GROUPS[1][1]),
    "Хост": set(IOC_GROUPS[2][1]),
    "Крипто": set(IOC_GROUPS[3][1]),
}

_EXPORT_CHOICES = ("CSV", "STIX", "JSON", "MISP", "OpenCTI", "YARA")
_COPY_FORMATS = ("value", "type|value", "csv")
_SAFE_NAME_RE = re.compile(r'[<>:"/\\|?*\x00-\x1f]+')

_VERDICT_COLORS = {
    "malicious": COLORS["danger"],
    "suspicious": COLORS["warn"],
    "unknown": COLORS["info"],
    "benign": COLORS["ok"],
}


def _collect_supported(root: Path, *, recursive: bool = True) -> list[str]:
    paths: list[str] = []
    iterator = root.rglob if recursive else root.glob
    for pattern in _SUPPORTED_GLOBS:
        paths.extend(str(p) for p in iterator(pattern) if p.is_file())
    return sorted(set(paths))


class IocExtractorApp(ctk.CTk):
    def __init__(self) -> None:
        super().__init__()
        ensure_user_lists()
        self.title(f"{__app_name__} — {__tagline__}")
        self.geometry("1280x860")
        self.minsize(1000, 700)
        self.configure(fg_color=COLORS["bg"])

        self.result: AnalysisResult | None = None
        self._placeholder_active = True
        self._cancel_batch = False
        self._ioc_by_tag: dict[str, Ioc] = {}

        self.cat_vars = {name: ctk.BooleanVar(value=True) for name in _CATEGORY_TYPES}
        self.hide_rewriter = ctk.BooleanVar(value=True)
        self.hide_allowlisted = ctk.BooleanVar(value=True)
        self.hide_private = ctk.BooleanVar(value=False)
        self.only_denylisted = ctk.BooleanVar(value=False)
        self._export_choice = ctk.StringVar(value="CSV")
        self._copy_format = ctk.StringVar(value="type|value")

        self._build()
        self._try_hook_drop()

    # ------------------------------------------------------------------ UI
    def _build(self) -> None:
        header = ctk.CTkFrame(self, fg_color=COLORS["surface"], corner_radius=0, height=64)
        header.pack(fill="x")
        header.pack_propagate(False)

        ctk.CTkLabel(
            header,
            text=__app_name__.upper(),
            font=ctk.CTkFont(family="Segoe UI", size=24, weight="bold"),
            text_color=COLORS["accent"],
        ).pack(side="left", padx=(24, 12), pady=14)

        ctk.CTkLabel(
            header,
            text=f"{__tagline__}  ·  v{__version__}  ·  offline",
            font=ctk.CTkFont(size=13),
            text_color=COLORS["muted"],
        ).pack(side="left", pady=14)

        toolbar = ctk.CTkFrame(self, fg_color=COLORS["bg"])
        toolbar.pack(fill="x", padx=20, pady=(16, 8))

        btn_kw = dict(hover_color=COLORS["border"], fg_color=COLORS["surface_alt"])

        ctk.CTkButton(
            toolbar,
            text="Открыть",
            command=self.open_files,
            fg_color=COLORS["accent"],
            hover_color=COLORS["accent_dim"],
            width=100,
        ).pack(side="left", padx=(0, 6))

        ctk.CTkButton(toolbar, text="Папка", command=self.open_folder, width=90, **btn_kw).pack(
            side="left", padx=(0, 6)
        )
        ctk.CTkButton(
            toolbar, text="Из текста", command=self.analyze_text_area, width=110, **btn_kw
        ).pack(side="left", padx=(0, 6))

        ctk.CTkOptionMenu(
            toolbar,
            variable=self._copy_format,
            values=list(_COPY_FORMATS),
            width=110,
            fg_color=COLORS["surface_alt"],
            button_color=COLORS["border"],
            button_hover_color=COLORS["accent_dim"],
            dropdown_fg_color=COLORS["surface"],
        ).pack(side="left", padx=(0, 4))
        ctk.CTkButton(
            toolbar, text="Копировать", command=self.copy_iocs, width=110, **btn_kw
        ).pack(side="left", padx=(0, 6))
        ctk.CTkButton(
            toolbar,
            text="Сохранить вложения",
            command=self.save_attachments,
            width=150,
            **btn_kw,
        ).pack(side="left", padx=(0, 6))

        ctk.CTkOptionMenu(
            toolbar,
            variable=self._export_choice,
            values=list(_EXPORT_CHOICES),
            width=120,
            fg_color=COLORS["surface_alt"],
            button_color=COLORS["border"],
            button_hover_color=COLORS["accent_dim"],
            dropdown_fg_color=COLORS["surface"],
        ).pack(side="left", padx=(0, 4))
        ctk.CTkButton(
            toolbar,
            text="Экспорт",
            command=self._export_clicked,
            width=90,
            fg_color=COLORS["accent"],
            hover_color=COLORS["accent_dim"],
        ).pack(side="left", padx=(0, 6))

        ctk.CTkButton(
            toolbar, text="Конфиги", command=self.open_configs, width=100, **btn_kw
        ).pack(side="left", padx=(0, 6))
        ctk.CTkButton(
            toolbar, text="О программе", command=self.show_about, width=120, **btn_kw
        ).pack(side="left", padx=(0, 6))

        self.status = ctk.CTkLabel(
            toolbar,
            text="Готов — откройте файл, папку или вставьте текст",
            text_color=COLORS["muted"],
        )
        self.status.pack(side="right")

        filter_panel = ctk.CTkFrame(self, fg_color=COLORS["surface"], corner_radius=8)
        filter_panel.pack(fill="x", padx=20, pady=(0, 10))

        row1 = ctk.CTkFrame(filter_panel, fg_color="transparent")
        row1.pack(fill="x", padx=12, pady=(10, 4))
        ctk.CTkLabel(
            row1,
            text="Типы IOC:",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=COLORS["text"],
            width=90,
            anchor="w",
        ).pack(side="left", padx=(0, 8))
        for name, var in self.cat_vars.items():
            ctk.CTkCheckBox(
                row1,
                text=name,
                variable=var,
                command=self._refresh_views,
                text_color=COLORS["text"],
                fg_color=COLORS["accent"],
                hover_color=COLORS["accent_dim"],
                border_color=COLORS["border"],
                width=90,
            ).pack(side="left", padx=(0, 10))
        ctk.CTkButton(
            row1,
            text="Сбросить",
            width=90,
            height=28,
            fg_color=COLORS["surface_alt"],
            hover_color=COLORS["border"],
            command=self._reset_filters,
        ).pack(side="right")

        row2 = ctk.CTkFrame(filter_panel, fg_color="transparent")
        row2.pack(fill="x", padx=12, pady=(0, 4))
        ctk.CTkLabel(
            row2,
            text="Убрать шум:",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=COLORS["text"],
            width=90,
            anchor="w",
        ).pack(side="left", padx=(0, 8))
        for text, var in (
            ("Шлюзы почты (SafeLinks…)", self.hide_rewriter),
            ("Из allowlist", self.hide_allowlisted),
            ("Частные IP", self.hide_private),
            ("Только denylist", self.only_denylisted),
        ):
            ctk.CTkCheckBox(
                row2,
                text=text,
                variable=var,
                command=self._refresh_views,
                text_color=COLORS["muted"],
                fg_color=COLORS["accent"],
                hover_color=COLORS["accent_dim"],
                border_color=COLORS["border"],
            ).pack(side="left", padx=(0, 14))

        self.filter_hint = ctk.CTkLabel(
            filter_panel,
            text="Фильтр → IOC / копирование / экспорт · клик по IOC копирует значение",
            font=ctk.CTkFont(size=12),
            text_color=COLORS["muted"],
            anchor="w",
        )
        self.filter_hint.pack(fill="x", padx=12, pady=(0, 10))

        body = ctk.CTkFrame(self, fg_color=COLORS["bg"])
        body.pack(fill="both", expand=True, padx=20, pady=(0, 16))
        body.grid_columnconfigure(0, weight=1)
        body.grid_columnconfigure(1, weight=2)
        body.grid_rowconfigure(0, weight=1)

        left = ctk.CTkFrame(body, fg_color=COLORS["surface"], corner_radius=8)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 10))

        ctk.CTkLabel(
            left,
            text="Источник",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color=COLORS["text"],
        ).pack(anchor="w", padx=16, pady=(16, 8))

        self.input_box = ctk.CTkTextbox(
            left,
            fg_color=COLORS["surface_alt"],
            text_color=COLORS["muted"],
            font=ctk.CTkFont(family="Consolas", size=13),
            wrap="word",
        )
        self.input_box.pack(fill="both", expand=True, padx=16, pady=(0, 16))
        self.input_box.insert("1.0", _PLACEHOLDER)
        self._bind_placeholder()

        right = ctk.CTkFrame(body, fg_color=COLORS["surface"], corner_radius=8)
        right.grid(row=0, column=1, sticky="nsew")

        summary = ctk.CTkFrame(right, fg_color=COLORS["surface_alt"], corner_radius=6)
        summary.pack(fill="x", padx=16, pady=(16, 8))

        self.ioc_summary_label = ctk.CTkLabel(
            summary,
            text="IOC: —",
            font=ctk.CTkFont(size=22, weight="bold"),
            text_color=COLORS["accent"],
        )
        self.ioc_summary_label.pack(anchor="w", padx=16, pady=(12, 4))

        self.ioc_breakdown = ctk.CTkLabel(
            summary,
            text="Откройте файл или вставьте текст",
            font=ctk.CTkFont(size=13),
            text_color=COLORS["muted"],
            wraplength=520,
            justify="left",
            anchor="w",
        )
        self.ioc_breakdown.pack(anchor="w", fill="x", padx=16, pady=(0, 12))

        self.verdict_card = ctk.CTkFrame(right, fg_color=COLORS["surface_alt"], corner_radius=6)
        self.verdict_card.pack(fill="x", padx=16, pady=(0, 8))
        self.verdict_card.pack_forget()

        self.verdict_title = ctk.CTkLabel(
            self.verdict_card,
            text="Вердикт",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=COLORS["accent"],
        )
        self.verdict_title.pack(anchor="w", padx=16, pady=(10, 4))

        self.verdict_body = ctk.CTkLabel(
            self.verdict_card,
            text="",
            font=ctk.CTkFont(family="Consolas", size=12),
            text_color=COLORS["text"],
            wraplength=520,
            justify="left",
            anchor="w",
        )
        self.verdict_body.pack(anchor="w", fill="x", padx=16, pady=(0, 10))

        self.mail_card = ctk.CTkFrame(right, fg_color=COLORS["surface_alt"], corner_radius=6)
        self.mail_card.pack(fill="x", padx=16, pady=(0, 8))
        self.mail_card.pack_forget()

        self.mail_title = ctk.CTkLabel(
            self.mail_card,
            text="Почтовая идентичность",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=COLORS["accent"],
        )
        self.mail_title.pack(anchor="w", padx=16, pady=(10, 4))

        self.mail_body = ctk.CTkLabel(
            self.mail_card,
            text="",
            font=ctk.CTkFont(family="Consolas", size=12),
            text_color=COLORS["text"],
            wraplength=520,
            justify="left",
            anchor="w",
        )
        self.mail_body.pack(anchor="w", fill="x", padx=16, pady=(0, 8))

        mail_btns = ctk.CTkFrame(self.mail_card, fg_color="transparent")
        mail_btns.pack(anchor="w", padx=12, pady=(0, 10))
        ctk.CTkButton(
            mail_btns,
            text="Copy From",
            width=110,
            height=28,
            command=self._copy_from,
            fg_color=COLORS["surface"],
            hover_color=COLORS["border"],
        ).pack(side="left", padx=4)
        ctk.CTkButton(
            mail_btns,
            text="Copy Message-ID",
            width=140,
            height=28,
            command=self._copy_message_id,
            fg_color=COLORS["surface"],
            hover_color=COLORS["border"],
        ).pack(side="left", padx=4)

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

        for name in ("IOC", "URL", "Вложения", "Заголовки", "Ошибки"):
            self.tabs.add(name)

        self.ioc_box = self._make_text(self.tabs.tab("IOC"))
        self.url_box = self._make_text(self.tabs.tab("URL"))
        self.att_box = self._make_text(self.tabs.tab("Вложения"))
        self.hdr_box = self._make_text(self.tabs.tab("Заголовки"))
        self.err_box = self._make_text(self.tabs.tab("Ошибки"))
        self._bind_ioc_click()

        self.bind("<Control-o>", lambda _e: self.open_files())
        self.bind("<Configure>", self._on_resize, add="+")
        self.after(100, self._update_wraplengths)

    def _try_hook_drop(self) -> None:
        try:
            import windnd  # type: ignore[import-untyped]

            windnd.hook_dropfiles(self, self._on_drop)
        except Exception:  # noqa: BLE001
            pass

    # ---------------------------------------------------------- placeholder
    def _bind_placeholder(self) -> None:
        widget = getattr(self.input_box, "textbox", None) or getattr(
            self.input_box, "_textbox", None
        )
        if widget is None:
            return
        widget.bind("<FocusIn>", self._on_input_focus_in, add="+")
        widget.bind("<FocusOut>", self._on_input_focus_out, add="+")
        widget.bind("<Key>", self._on_input_key, add="+")
        widget.bind("<<Paste>>", self._on_input_paste, add="+")
        widget.bind("<Control-v>", self._on_input_paste, add="+")
        widget.bind("<Control-V>", self._on_input_paste, add="+")
        widget.bind("<Button-1>", self._on_input_click, add="+")

    def _show_placeholder(self) -> None:
        self._placeholder_active = True
        self.input_box.delete("1.0", "end")
        self.input_box.insert("1.0", _PLACEHOLDER)
        self.input_box.configure(text_color=COLORS["muted"])

    def _clear_placeholder(self) -> None:
        if not self._placeholder_active:
            return
        self._placeholder_active = False
        self.input_box.delete("1.0", "end")
        self.input_box.configure(text_color=COLORS["text"])

    def _on_input_focus_in(self, _event: object = None) -> None:
        self._clear_placeholder()

    def _on_input_focus_out(self, _event: object = None) -> None:
        if self._placeholder_active:
            return
        if not self.input_box.get("1.0", "end").strip():
            self._show_placeholder()

    def _on_input_key(self, event: tk.Event) -> None:  # type: ignore[type-arg]
        if self._placeholder_active and event.keysym not in (
            "Shift_L",
            "Shift_R",
            "Control_L",
            "Control_R",
            "Alt_L",
            "Alt_R",
            "Tab",
            "Escape",
        ):
            self._clear_placeholder()

    def _on_input_paste(self, _event: object = None) -> None:
        self._clear_placeholder()

    def _on_input_click(self, _event: object = None) -> None:
        self._clear_placeholder()

    # -------------------------------------------------------- text helpers
    def _make_text(self, parent: ctk.CTkFrame) -> ctk.CTkTextbox:
        box = ctk.CTkTextbox(
            parent,
            fg_color=COLORS["surface_alt"],
            text_color=COLORS["text"],
            font=ctk.CTkFont(family="Consolas", size=12),
            wrap="word",
            activate_scrollbars=True,
        )
        box.pack(fill="both", expand=True, padx=4, pady=4)
        self._configure_result_tags(box)
        return box

    def _tk(self, box: ctk.CTkTextbox):
        return getattr(box, "textbox", None) or getattr(box, "_textbox", None)

    def _configure_result_tags(self, box: ctk.CTkTextbox) -> None:
        widget = self._tk(box)
        if widget is None:
            return
        base = ("Consolas", 12)
        bold = ("Consolas", 12, "bold")
        section = ("Segoe UI", 13, "bold")
        widget.tag_configure(
            "section", foreground=COLORS["accent"], font=section, spacing1=10, spacing3=4
        )
        widget.tag_configure("muted", foreground=COLORS["muted"], font=base)
        widget.tag_configure("value", foreground=COLORS["value"], font=bold)
        widget.tag_configure("label", foreground=COLORS["muted"], font=base)
        widget.tag_configure("ok", foreground=COLORS["ok"], font=bold)
        widget.tag_configure("warn", foreground=COLORS["warn"], font=bold)
        widget.tag_configure("danger", foreground=COLORS["danger"], font=bold)
        widget.tag_configure("info", foreground=COLORS["info"], font=bold)
        widget.tag_configure("meta", foreground=COLORS["info"], font=base)
        widget.tag_configure("empty", foreground=COLORS["muted"], font=section)
        widget.tag_configure("ioc_click", foreground=COLORS["value"], font=bold)
        for itype, color in IOC_TYPE_COLORS.items():
            widget.tag_configure(f"type_{itype}", foreground=color, font=bold)
        for sev, color in SEVERITY_COLORS.items():
            widget.tag_configure(f"sev_{sev}", foreground=color, font=bold)

    def _bind_ioc_click(self) -> None:
        widget = self._tk(self.ioc_box)
        if widget is None:
            return
        widget.tag_bind("ioc_click", "<Button-1>", self._on_ioc_click)
        widget.tag_bind("ioc_click", "<Double-Button-1>", self._on_ioc_click)

    def _on_ioc_click(self, event: tk.Event) -> None:  # type: ignore[type-arg]
        widget = self._tk(self.ioc_box)
        if widget is None:
            return
        index = widget.index(f"@{event.x},{event.y}")
        tags = widget.tag_names(index)
        for tag in tags:
            if tag.startswith("iocid_") and tag in self._ioc_by_tag:
                ioc = self._ioc_by_tag[tag]
                self.clipboard_clear()
                self.clipboard_append(ioc.value)
                self._set_status(f"Скопировано: {ioc.ioc_type.value} → {ioc.value[:80]}")
                return

    def _clear_box(self, box: ctk.CTkTextbox) -> None:
        widget = self._tk(box)
        if widget is None:
            box.delete("1.0", "end")
            return
        widget.configure(state="normal")
        widget.delete("1.0", "end")

    def _put(self, box: ctk.CTkTextbox, text: str, *tags: str) -> None:
        widget = self._tk(box)
        if widget is None:
            box.insert("end", text)
            return
        widget.insert("end", text, tags if tags else ())

    def _on_resize(self, event: tk.Event) -> None:  # type: ignore[type-arg]
        if event.widget is not self:
            return
        self.after_idle(self._update_wraplengths)

    def _update_wraplengths(self) -> None:
        width = max(200, self.winfo_width() - 420)
        try:
            self.ioc_breakdown.configure(wraplength=width)
            self.mail_body.configure(wraplength=width)
            self.verdict_body.configure(wraplength=width)
        except tk.TclError:
            pass

    def _set_status(self, text: str) -> None:
        self.status.configure(text=text)

    # ----------------------------------------------------------- filtering
    def _reset_filters(self) -> None:
        for var in self.cat_vars.values():
            var.set(True)
        self.hide_rewriter.set(True)
        self.hide_allowlisted.set(True)
        self.hide_private.set(False)
        self.only_denylisted.set(False)
        self._refresh_views()

    def _selected_types(self) -> set[str] | None:
        enabled = [name for name, var in self.cat_vars.items() if var.get()]
        if not enabled:
            return set()
        if len(enabled) == len(self.cat_vars):
            return None
        types: set[str] = set()
        for name in enabled:
            types |= _CATEGORY_TYPES[name]
        return types

    def _filter_kwargs(self) -> dict:
        return {
            "types": self._selected_types(),
            "hide_private": bool(self.hide_private.get()),
            "hide_rewriter": bool(self.hide_rewriter.get()),
            "hide_allowlisted": bool(self.hide_allowlisted.get()),
            "only_denylisted": bool(self.only_denylisted.get()),
        }

    def _filtered_iocs(self):
        if not self.result:
            return []
        return filter_iocs(self.result, **self._filter_kwargs())

    def _filtered_result(self) -> AnalysisResult | None:
        if not self.result:
            return None
        return _with_iocs(self.result, self._filtered_iocs())

    def _refresh_views(self) -> None:
        if not self.result:
            self.filter_hint.configure(
                text="Фильтр → IOC / копирование / экспорт · клик по IOC копирует значение"
            )
            return
        filtered = self._filtered_iocs()
        counts = Counter(i.ioc_type.value for i in filtered)
        total = len(filtered)
        full = len(self.result.iocs)
        if total == full:
            self.ioc_summary_label.configure(text=f"IOC: {total}")
            self.filter_hint.configure(
                text=f"Показаны все {full} · клик по IOC копирует · фильтр → экспорт"
            )
        else:
            self.ioc_summary_label.configure(text=f"IOC: {total} из {full}")
            hidden = full - total
            self.filter_hint.configure(
                text=f"Показано {total} из {full} (скрыто {hidden}) · клик копирует значение"
            )
        if counts:
            breakdown = "  ·  ".join(f"{k}: {v}" for k, v in sorted(counts.items()))
            self.ioc_breakdown.configure(text=breakdown, text_color=COLORS["text"])
        else:
            self.ioc_breakdown.configure(
                text="Ничего не попало под фильтр — включите типы или ослабьте «Убрать шум»",
                text_color=COLORS["muted"],
            )
        self._fill_iocs(self.result, filtered)
        self._fill_urls(self.result)
        self._fill_attachments(self.result)
        self._fill_headers(self.result)
        self._fill_errors(self.result)
        self._update_mail_card(self.result)
        self._update_verdict_card(self.result)

    # -------------------------------------------------------------- open
    def open_files(self) -> None:
        paths = filedialog.askopenfilenames(
            title=f"{__app_name__} — открыть файлы",
            filetypes=[
                (
                    "Все поддерживаемые",
                    "*.eml *.msg *.pdf *.html *.htm *.txt *.csv *.log *.docx *.xlsx *.zip",
                ),
                ("Email", "*.eml *.msg"),
                ("Office", "*.docx *.xlsx"),
                ("Архив", "*.zip"),
                ("PDF", "*.pdf"),
                ("HTML", "*.html *.htm"),
                ("Текст / тикет", "*.txt *.csv *.log *.md"),
                ("Все файлы", "*.*"),
            ],
        )
        if not paths:
            return
        self._analyze_paths(list(paths))

    def open_folder(self) -> None:
        folder = filedialog.askdirectory(title=f"{__app_name__} — папка (рекурсивно)")
        if not folder:
            return
        paths = _collect_supported(Path(folder), recursive=True)
        if not paths:
            messagebox.showinfo(
                __app_name__,
                "В папке (включая подпапки) нет поддерживаемых файлов "
                "(.eml .msg .pdf .html .txt .docx .xlsx .zip).",
            )
            return
        self._analyze_paths(paths)

    def _on_drop(self, files) -> None:
        paths: list[str] = []
        for item in files:
            if isinstance(item, bytes):
                for enc in ("utf-8", "mbcs"):
                    try:
                        item = item.decode(enc)
                        break
                    except UnicodeDecodeError:
                        continue
                else:
                    item = item.decode("utf-8", errors="replace")
            path = Path(str(item))
            if path.is_file() and path.suffix.lower() in _SUPPORTED_SUFFIXES:
                paths.append(str(path))
            elif path.is_dir():
                paths.extend(_collect_supported(path, recursive=True))
        paths = sorted(set(paths))
        if not paths:
            self.after(
                0,
                lambda: messagebox.showinfo(
                    __app_name__, "Нет поддерживаемых файлов для анализа"
                ),
            )
            return
        self.after(0, lambda: self._analyze_paths(paths))

    def _analyze_paths(self, paths: list[str]) -> None:
        self._cancel_batch = False
        names = ", ".join(Path(p).name for p in paths[:3])
        extra = f" (+{len(paths) - 3})" if len(paths) > 3 else ""
        self._set_status(f"Извлечение 0/{len(paths)}: {names}{extra}…")
        self.update_idletasks()
        threading.Thread(target=self._run_paths, args=(paths,), daemon=True).start()

    def _run_paths(self, paths: list[str]) -> None:
        results: list[AnalysisResult] = []
        hard_errors: list[str] = []
        total = len(paths)
        for idx, path in enumerate(paths, start=1):
            if self._cancel_batch:
                hard_errors.append("Пакетная обработка отменена")
                break
            self.after(
                0,
                lambda i=idx, t=total, p=path: self._set_status(
                    f"Извлечение {i}/{t}: {Path(p).name}"
                ),
            )
            try:
                results.append(analyze_file(path))
            except Exception as exc:  # noqa: BLE001
                hard_errors.append(f"{path}: {exc}")

        if not results:
            msg = "Не удалось разобрать ни одного файла.\n" + "\n".join(hard_errors[:8])
            self.after(0, lambda: messagebox.showerror("Ошибка", msg))
            self.after(0, lambda: self._set_status("Ошибка извлечения"))
            return

        if len(results) == 1:
            result = results[0]
        else:
            result = merge_results(results, label=f"batch:{len(results)}")
        for err in hard_errors:
            result.errors.append(err)
        if hard_errors:
            result.errors.insert(
                0,
                f"Успешно: {len(results)}/{total}, ошибок: {len(hard_errors)}",
            )
        self.after(0, lambda: self._apply_result(result, preload_text=True))

    def analyze_text_area(self) -> None:
        if self._placeholder_active:
            messagebox.showinfo(__app_name__, "Вставьте текст в левую панель")
            return
        text = self.input_box.get("1.0", "end").strip()
        if not text:
            messagebox.showinfo(__app_name__, "Вставьте текст в левую панель")
            return
        self._set_status("Извлечение из текста…")
        threading.Thread(target=self._run_text, args=(text,), daemon=True).start()

    def _run_text(self, text: str) -> None:
        try:
            result = analyze_text(text)
            self.after(0, lambda: self._apply_result(result, preload_text=False))
        except Exception as exc:  # noqa: BLE001
            self.after(0, lambda: messagebox.showerror("Ошибка", str(exc)))
            self.after(0, lambda: self._set_status("Ошибка извлечения"))

    def _apply_result(self, result: AnalysisResult, preload_text: bool) -> None:
        self.result = result
        if preload_text:
            preview = result.raw_text_preview or ""
            meta_lines = [
                f"Файл: {result.source_path}",
                f"Тип: {result.source_kind}",
            ]
            if result.sender:
                meta_lines.append(f"From: {result.sender}")
            if result.subject:
                meta_lines.append(f"Subject: {result.subject}")
            meta_lines.extend(["=" * 48, "", preview])
            self._placeholder_active = False
            self.input_box.delete("1.0", "end")
            self.input_box.insert("1.0", "\n".join(meta_lines))
            self.input_box.configure(text_color=COLORS["text"])

        self._refresh_views()
        self.tabs.set("IOC")
        filtered_n = len(self._filtered_iocs())
        err = f" · ошибки: {len(result.errors)}" if result.errors else ""
        self._set_status(f"Готово: {filtered_n} IOC{err}")
        if result.errors:
            # Keep IOC tab primary; errors visible in dedicated tab
            pass

    # -------------------------------------------------------- mail / verdict
    def _update_verdict_card(self, result: AnalysisResult) -> None:
        v = result.verdict
        if not v:
            self.verdict_card.pack_forget()
            return
        color = _VERDICT_COLORS.get(v.level.value, COLORS["text"])
        self.verdict_title.configure(
            text=f"Вердикт: {v.level.value.upper()}  ·  score {v.score}",
            text_color=color,
        )
        lines = [v.summary, ""]
        if v.reasons:
            lines.append("Причины:")
            for r in v.reasons[:6]:
                lines.append(f"  • {r}")
        if v.actions:
            lines.append("")
            lines.append("Действия:")
            for a in v.actions[:5]:
                lines.append(f"  {a.priority}. {a.action} — {a.rationale}")
        self.verdict_body.configure(text="\n".join(lines))
        if not self.verdict_card.winfo_ismapped():
            self.verdict_card.pack(fill="x", padx=16, pady=(0, 8), before=self.tabs)

    def _update_mail_card(self, result: AnalysisResult) -> None:
        mid = result.mail_identity
        if not mid:
            self.mail_card.pack_forget()
            return
        lines = [
            f"From: {mid.from_header or '—'}",
            f"Return-Path: {mid.return_path or '—'}",
            f"SPF: {mid.spf or '—'}   DKIM: {mid.dkim or '—'}   DMARC: {mid.dmarc or '—'}",
            f"Hops: {mid.received_hops}"
            + (f"   first: {mid.first_received}" if mid.first_received else ""),
        ]
        if mid.subject:
            lines.insert(1, f"Subject: {mid.subject}")
        if mid.message_id:
            lines.append(f"Message-ID: {mid.message_id}")
        self.mail_body.configure(text="\n".join(lines))
        if not self.mail_card.winfo_ismapped():
            self.mail_card.pack(fill="x", padx=16, pady=(0, 8), before=self.tabs)

    def _copy_from(self) -> None:
        if not self.result or not self.result.mail_identity:
            return
        value = self.result.mail_identity.from_header or ""
        if not value:
            return
        self.clipboard_clear()
        self.clipboard_append(value)
        self._set_status("From скопирован")

    def _copy_message_id(self) -> None:
        if not self.result or not self.result.mail_identity:
            return
        value = self.result.mail_identity.message_id or ""
        if not value:
            return
        self.clipboard_clear()
        self.clipboard_append(value)
        self._set_status("Message-ID скопирован")

    # ----------------------------------------------------------- fillers
    def _fill_iocs(self, result: AnalysisResult, filtered) -> None:
        self._clear_box(self.ioc_box)
        self._ioc_by_tag.clear()
        if not filtered:
            self._put(self.ioc_box, "IOC не найдены\n", "empty")
        else:
            by_type: dict[str, list] = {}
            for ioc in filtered:
                by_type.setdefault(ioc.ioc_type.value, []).append(ioc)

            shown: set[str] = set()
            idx = 0
            for group_name, types in IOC_GROUPS:
                group_items = []
                for t in types:
                    group_items.extend(by_type.get(t, []))
                    shown.add(t)
                if not group_items:
                    continue
                self._put(self.ioc_box, f"▸ {group_name}  ({len(group_items)})\n", "section")
                for ioc in group_items:
                    t = ioc.ioc_type.value
                    tag = f"iocid_{idx}"
                    self._ioc_by_tag[tag] = ioc
                    idx += 1
                    value_tag = "danger" if "denylisted" in ioc.tags else "ioc_click"
                    self._put(self.ioc_box, f"  {t}  ", f"type_{t}")
                    self._put(self.ioc_box, f"{ioc.value}\n", value_tag, "ioc_click", tag)
                    if ioc.tags:
                        self._put(self.ioc_box, f"      {', '.join(ioc.tags)}\n", "muted")
                    if ioc.rewritten_from:
                        self._put(self.ioc_box, "      развёрнут из: ", "label")
                        self._put(self.ioc_box, f"{ioc.rewritten_from}\n", "meta")

            other = [i for i in filtered if i.ioc_type.value not in shown]
            if other:
                self._put(self.ioc_box, f"▸ Прочее  ({len(other)})\n", "section")
                for ioc in other:
                    t = ioc.ioc_type.value
                    tag = f"iocid_{idx}"
                    self._ioc_by_tag[tag] = ioc
                    idx += 1
                    self._put(self.ioc_box, f"  {t}  ", f"type_{t}")
                    self._put(self.ioc_box, f"{ioc.value}\n", "ioc_click", tag)

        if result.errors:
            self._put(self.ioc_box, f"\n▸ Ошибки ({len(result.errors)}) — см. вкладку\n", "warn")

    def _fill_urls(self, result: AnalysisResult) -> None:
        self._clear_box(self.url_box)
        if not result.url_rewrites:
            self._put(self.url_box, "URL не найдены\n", "empty")
            return

        changed = sum(1 for u in result.url_rewrites if u.changed)
        self._put(
            self.url_box,
            f"▸ URL Rewrite  ({len(result.url_rewrites)}, развёрнуто: {changed})\n",
            "section",
        )
        for u in result.url_rewrites:
            status_tag = "ok" if u.changed else "muted"
            status = "развёрнут" if u.changed else "без изменений"
            self._put(self.url_box, f"  {u.rewriter}  ", "info")
            self._put(self.url_box, f"{status}\n", status_tag)
            self._put(self.url_box, "      исходный: ", "label")
            self._put(self.url_box, f"{u.original}\n", "muted" if u.changed else "value")
            if u.changed:
                self._put(self.url_box, "      реальный: ", "label")
                self._put(self.url_box, f"{u.unwrapped}\n", "value")
            self._put(self.url_box, "\n")

    def _fill_attachments(self, result: AnalysisResult) -> None:
        self._clear_box(self.att_box)
        if not result.attachments:
            self._put(self.att_box, "Вложений нет\n", "empty")
            return

        risky = sum(1 for a in result.attachments if a.risk_flags)
        with_data = sum(1 for a in result.attachments if a.data)
        self._put(
            self.att_box,
            f"▸ Вложения  ({len(result.attachments)}"
            + (f", с флагами: {risky}" if risky else "")
            + ")\n",
            "section",
        )
        self._put(
            self.att_box,
            f"  «Сохранить вложения» — файлы с data в памяти (доступно: {with_data}).\n\n",
            "muted",
        )
        for a in result.attachments:
            name_tag = "danger" if a.risk_flags else "value"
            self._put(self.att_box, "  ", "muted")
            self._put(self.att_box, f"{a.filename}\n", name_tag)
            self._put(self.att_box, f"      {a.size} bytes · {a.mime_guess}", "muted")
            if a.data:
                self._put(self.att_box, " · data✓\n", "ok")
            else:
                self._put(self.att_box, " · data✗\n", "muted")
            self._put(self.att_box, "      MD5     ", "label")
            self._put(self.att_box, f"{a.md5}\n", "value")
            self._put(self.att_box, "      SHA1    ", "label")
            self._put(self.att_box, f"{a.sha1}\n", "value")
            self._put(self.att_box, "      SHA256  ", "label")
            self._put(self.att_box, f"{a.sha256}\n", "value")
            if a.risk_flags:
                self._put(self.att_box, "      флаги:  ", "label")
                self._put(self.att_box, f"{', '.join(a.risk_flags)}\n", "warn")
            if a.archive_entries:
                self._put(self.att_box, "      архив:\n", "label")
                for entry in a.archive_entries[:40]:
                    self._put(self.att_box, f"        · {entry}\n", "meta")
                if len(a.archive_entries) > 40:
                    self._put(
                        self.att_box,
                        f"        … ещё {len(a.archive_entries) - 40}\n",
                        "muted",
                    )
            for note in a.notes:
                self._put(self.att_box, f"      — {note}\n", "muted")
            self._put(self.att_box, "\n")

    def _fill_headers(self, result: AnalysisResult) -> None:
        self._clear_box(self.hdr_box)

        mid = result.mail_identity
        if mid:
            self._put(self.hdr_box, "▸ Почтовая идентичность\n", "section")
            self._put(self.hdr_box, "  From: ", "label")
            self._put(self.hdr_box, f"{mid.from_header or '—'}\n", "value")
            self._put(self.hdr_box, "  Return-Path: ", "label")
            self._put(self.hdr_box, f"{mid.return_path or '—'}\n", "value")
            self._put(self.hdr_box, "  Reply-To: ", "label")
            self._put(self.hdr_box, f"{mid.reply_to or '—'}\n", "muted")
            self._put(self.hdr_box, "  Message-ID: ", "label")
            self._put(self.hdr_box, f"{mid.message_id or '—'}\n", "meta")
            self._put(self.hdr_box, "  SPF: ", "label")
            self._put(self.hdr_box, f"{mid.spf or '—'}  ", "info")
            self._put(self.hdr_box, "DKIM: ", "label")
            self._put(self.hdr_box, f"{mid.dkim or '—'}  ", "info")
            self._put(self.hdr_box, "DMARC: ", "label")
            self._put(self.hdr_box, f"{mid.dmarc or '—'}\n", "info")
            self._put(self.hdr_box, "  Hops: ", "label")
            self._put(self.hdr_box, f"{mid.received_hops}\n", "value")
            if mid.first_received:
                self._put(self.hdr_box, "  First Received: ", "label")
                self._put(self.hdr_box, f"{mid.first_received}\n", "muted")
            self._put(self.hdr_box, "\n")

        if result.headers:
            alerts = [
                h for h in result.headers if h.severity.value in ("high", "critical", "medium")
            ]
            self._put(
                self.hdr_box,
                f"▸ Findings  ({len(result.headers)}"
                + (f", замечаний: {len(alerts)}" if alerts else "")
                + ")\n",
                "section",
            )
            for h in result.headers:
                sev = h.severity.value
                sev_ru = SEVERITY_LABELS_RU.get(sev, sev)
                self._put(self.hdr_box, f"  [{sev_ru}] ", f"sev_{sev}")
                self._put(self.hdr_box, f"{h.name}\n", "value")
                self._put(self.hdr_box, f"      {h.note}\n", "muted")
                self._put(self.hdr_box, f"      {h.value}\n\n", "meta")
        elif result.source_kind != "email" and not result.raw_headers and not mid:
            self._put(
                self.hdr_box,
                "Заголовки доступны для писем .eml / .msg\n",
                "empty",
            )
            return

        if result.raw_headers:
            self._put(self.hdr_box, "▸ Сырые заголовки\n", "section")
            for name, value in result.raw_headers.items():
                self._put(self.hdr_box, f"  {name}: ", "label")
                self._put(self.hdr_box, f"{value}\n", "muted")
        elif not result.headers and not mid:
            self._put(self.hdr_box, "Заголовки не разобраны\n", "empty")

    def _fill_errors(self, result: AnalysisResult) -> None:
        self._clear_box(self.err_box)
        if not result.errors:
            self._put(self.err_box, "Ошибок нет\n", "ok")
            return
        self._put(self.err_box, f"▸ Ошибки / замечания  ({len(result.errors)})\n", "section")
        for err in result.errors:
            self._put(self.err_box, f"  ! {err}\n", "danger")

    # ---------------------------------------------------- copy / export
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
        # type|value
        return "\n".join(f"{i.ioc_type.value}|{i.value}" for i in iocs)

    def copy_iocs(self) -> None:
        if not self.result:
            messagebox.showinfo(__app_name__, "Сначала извлеките IOC")
            return
        iocs = self._filtered_iocs()
        if not iocs:
            messagebox.showinfo(__app_name__, "Нет IOC для копирования (проверьте фильтры)")
            return
        text = self._format_iocs_for_clipboard(iocs)
        self.clipboard_clear()
        self.clipboard_append(text)
        self._set_status(f"Скопировано IOC: {len(iocs)} ({self._copy_format.get()})")

    def save_attachments(self) -> None:
        if not self.result or not self.result.attachments:
            messagebox.showinfo(__app_name__, "Нет вложений для сохранения")
            return
        folder = filedialog.askdirectory(title="Сохранить вложения в…")
        if not folder:
            return
        out_dir = Path(folder)
        saved = 0
        skipped = 0
        used_names: set[str] = set()
        for att in self.result.attachments:
            if not att.data:
                skipped += 1
                continue
            name = _SAFE_NAME_RE.sub("_", att.filename or "attachment.bin").strip(" .") or "attachment.bin"
            candidate = name
            n = 1
            while candidate.lower() in used_names or (out_dir / candidate).exists():
                stem = Path(name).stem
                suffix = Path(name).suffix
                candidate = f"{stem}_{n}{suffix}"
                n += 1
            used_names.add(candidate.lower())
            (out_dir / candidate).write_bytes(att.data)
            saved += 1
        self._set_status(f"Вложения: сохранено {saved}, пропущено {skipped}")
        if saved == 0:
            messagebox.showinfo(
                __app_name__,
                "Нет вложений с данными в памяти (слишком большие или недоступны).",
            )

    def _export_clicked(self) -> None:
        self.export(self._export_choice.get())

    def export(self, kind: str) -> None:
        filtered = self._filtered_result()
        if not filtered:
            messagebox.showinfo(__app_name__, "Сначала извлеките IOC")
            return
        iocs = filtered.iocs
        kind_l = kind.lower()

        if kind_l == "csv":
            path = filedialog.asksaveasfilename(
                defaultextension=".csv",
                filetypes=[("CSV", "*.csv")],
                initialfile="iocs.csv",
            )
            if path:
                export_csv(filtered, path)
                self._set_status(f"CSV: {path}")
        elif kind_l == "stix":
            path = filedialog.asksaveasfilename(
                defaultextension=".json",
                filetypes=[("STIX JSON", "*.json")],
                initialfile="iocs_stix.json",
            )
            if path:
                export_stix(filtered, path)
                self._set_status(f"STIX: {path}")
        elif kind_l == "json":
            path = filedialog.asksaveasfilename(
                defaultextension=".json",
                filetypes=[("JSON", "*.json")],
                initialfile="iocs_report.json",
            )
            if path:
                export_report_json(filtered, path)
                self._set_status(f"JSON: {path}")
        elif kind_l == "misp":
            path = filedialog.asksaveasfilename(
                defaultextension=".json",
                filetypes=[("MISP JSON", "*.json")],
                initialfile="iocs_misp.json",
            )
            if path:
                export_misp(filtered, path, iocs=iocs)
                self._set_status(f"MISP: {path}")
        elif kind_l == "opencti":
            path = filedialog.asksaveasfilename(
                defaultextension=".json",
                filetypes=[("OpenCTI JSON", "*.json")],
                initialfile="iocs_opencti.json",
            )
            if path:
                export_opencti(filtered, path, iocs=iocs)
                self._set_status(f"OpenCTI: {path}")
        elif kind_l == "yara":
            path = filedialog.asksaveasfilename(
                defaultextension=".yar",
                filetypes=[("YARA", "*.yar *.yara"), ("All", "*.*")],
                initialfile="ioc_extractor_iocs.yar",
            )
            if path:
                export_yara(filtered, path, iocs=iocs)
                self._set_status(f"YARA: {path}")

    def open_configs(self) -> None:
        root = ensure_user_lists()
        allow = list_file_path("allowlist.txt")
        deny = list_file_path("denylist.txt")
        try:
            if sys.platform.startswith("win"):
                os.startfile(str(root))  # type: ignore[attr-defined]
            elif sys.platform == "darwin":
                subprocess.Popen(["open", str(root)])
            else:
                subprocess.Popen(["xdg-open", str(root)])
        except Exception:
            messagebox.showinfo(
                __app_name__,
                f"Папка конфигов:\n{root}\n\nallowlist:\n{allow}\ndenylist:\n{deny}",
            )
            return
        self._set_status(f"Конфиги: {root}")

    def show_about(self) -> None:
        allowlist = list_file_path("allowlist.txt")
        denylist = list_file_path("denylist.txt")
        messagebox.showinfo(
            f"О программе — {__app_name__}",
            f"{__app_name__} v{__version__}\n"
            f"{__tagline__}\n\n"
            "Офлайн IOC-экстрактор для SOC: письма, PDF, HTML, Office, ZIP, текст.\n"
            "Без сетевых запросов (enforce_offline).\n\n"
            "Экспорт: CSV (UTF-8 BOM), STIX, JSON, MISP, OpenCTI, YARA.\n\n"
            f"Папка приложения:\n{app_dir()}\n\n"
            f"allowlist:\n{allowlist}\n\n"
            f"denylist:\n{denylist}",
        )


def run() -> None:
    enforce_offline()
    ensure_user_lists()
    try:
        app = IocExtractorApp()
    except tk.TclError as exc:
        raise SystemExit(
            f"GUI недоступен ({exc}). Используйте CLI: python -m reliquary.cli <файл>"
        ) from exc
    app.mainloop()
