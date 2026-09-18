"""IOC Extractor desktop GUI — SOC-first dense layout (CustomTkinter)."""

from __future__ import annotations

import concurrent.futures
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
from reliquary.core.allowlist import (
    append_list_entries,
    import_entries_from_csv,
    import_entries_from_misp,
    list_file_path,
    list_mtime_label,
)
from reliquary.core.defang import defang_ioc_line, defang_value
from reliquary.core.exporters import (
    export_case_pack,
    export_case_pack_multi,
    export_csv,
    export_misp,
    export_opencti,
    export_report_json,
    export_stix,
    export_yara,
    filter_iocs,
    with_iocs,
)
from reliquary.core.models import AnalysisResult, Ioc
from reliquary.core.offline import enforce_offline
from reliquary.core.paths import app_dir, ensure_user_lists
from reliquary.core.pipeline import analyze_file, analyze_text, merge_results
from reliquary.core.prefs import load_prefs, save_prefs
from reliquary.core.ticket import build_message_id_block, build_ticket_template
from reliquary.gui.ioc_table import IocTable
from reliquary.gui.tabs import desired_result_tabs
from reliquary.gui.theme import (
    BTN_H,
    COLORS,
    FONT_BADGE,
    FONT_BRAND,
    FONT_CONTENT,
    FONT_IOC,
    FONT_META,
    FONT_MONO,
    FONT_SECTION,
    FONT_STATUS,
    FONT_SUMMARY,
    FONT_UI,
    FONT_UI_BODY,
    IOC_GROUPS,
    IOC_TYPE_COLORS,
    SEVERITY_COLORS,
    SEVERITY_LABELS_RU,
    VERDICT_COLORS,
    btn_primary,
    btn_secondary,
    chrome_font,
)
from reliquary.gui.tooltips import HoverTip, muted_label, vsep

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

_PLACEHOLDER = (
    "Вставьте текст тикета сюда или откройте файл.\n\n"
    ".eml .msg .pdf .html .txt .docx .xlsx .zip\n"
    "Ctrl+O — файл · Ctrl+Enter — извлечь из текста · клик по IOC — копировать"
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
    "*.7z",
    "*.rar",
)
_SUPPORTED_SUFFIXES = {g[1:].lower() for g in _SUPPORTED_GLOBS}

_CATEGORY_TYPES: dict[str, set[str]] = {
    "Сеть": set(IOC_GROUPS[0][1]),
    "Хеши": set(IOC_GROUPS[1][1]),
    "Хост": set(IOC_GROUPS[2][1]),
    "Крипто": set(IOC_GROUPS[3][1]),
}
_CAT_PREF_KEYS = {
    "Сеть": "cat_network",
    "Хеши": "cat_hashes",
    "Хост": "cat_host",
    "Крипто": "cat_crypto",
}

_EXPORT_CHOICES = (
    "CSV",
    "STIX",
    "JSON",
    "MISP",
    "OpenCTI",
    "YARA",
    "Case pack",
    "Case pack (по файлам)",
)
_COPY_FORMATS = ("type|value", "value", "csv", "defanged", "defanged|type")
_SAFE_NAME_RE = re.compile(r'[<>:"/\\|?*\x00-\x1f]+')
_TAB_HOTKEYS = ("ioc", "batch", "url", "att", "mail", "err")
_SCALE_STEPS = (0.85, 1.0, 1.15, 1.25, 1.35, 1.5)

# Filter strip: (label, var_attr, tooltip). Hide = drop noise; focus = narrow list.
_HIDE_NOISE_FILTERS = (
    (
        "прокси URL",
        "hide_rewriter",
        "Скрыть URL из SafeLinks / Proofpoint и другой прокси-шум писем",
    ),
    (
        "allowlist",
        "hide_allowlisted",
        "Скрыть IOC из allowlist.txt (известные безопасные)",
    ),
    (
        "частные IP",
        "hide_private",
        "Скрыть частные/локальные адреса (10/8, 192.168/16, …)",
    ),
)
_FOCUS_FILTERS = (
    (
        "только denylist",
        "only_denylisted",
        "Показать только IOC из denylist.txt",
    ),
    (
        "к разбору",
        "actionable_only",
        "Только полезные IOC: без прокси/allowlist/private и без «голых» имён файлов",
    ),
)


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
        self._prefs = load_prefs()
        scale = float(self._prefs.get("ui_scale") or 1.0)
        try:
            ctk.set_widget_scaling(scale)
            ctk.set_window_scaling(scale)
        except Exception:  # noqa: BLE001
            pass
        self._ui_scale = scale

        self.title(f"{__app_name__} — {__tagline__}")
        geom = str(self._prefs.get("window_geometry") or "1320x820")
        try:
            self.geometry(geom)
        except Exception:  # noqa: BLE001
            self.geometry("1320x820")
        self.minsize(1024, 680)
        self.configure(fg_color=COLORS["bg"])

        self.result: AnalysisResult | None = None
        self._batch_results: list[AnalysisResult] = []
        self._failed_paths: list[str] = []
        self._focus_source_file = ""
        self._placeholder_active = True
        self._cancel_batch = False
        self._batch_row_tags: dict[str, str] = {}
        self._search_after_id: str | None = None

        self.cat_vars = {
            name: ctk.BooleanVar(
                value=bool(self._prefs.get(_CAT_PREF_KEYS[name], True))
            )
            for name in _CATEGORY_TYPES
        }
        self.hide_rewriter = ctk.BooleanVar(value=bool(self._prefs.get("hide_rewriter", True)))
        self.hide_allowlisted = ctk.BooleanVar(
            value=bool(self._prefs.get("hide_allowlisted", True))
        )
        self.hide_private = ctk.BooleanVar(value=bool(self._prefs.get("hide_private", False)))
        self.only_denylisted = ctk.BooleanVar(
            value=bool(self._prefs.get("only_denylisted", False))
        )
        self.actionable_only = ctk.BooleanVar(
            value=bool(self._prefs.get("actionable_only", False))
        )
        self.ticket_short = ctk.BooleanVar(value=bool(self._prefs.get("ticket_short", False)))
        self._ticket_lang = str(self._prefs.get("ticket_lang") or "ru")
        self._export_choice = ctk.StringVar(
            value=str(self._prefs.get("export_choice") or "CSV")
        )
        self._copy_format = ctk.StringVar(
            value=str(self._prefs.get("copy_format") or "type|value")
        )
        self._search_var = ctk.StringVar(value="")
        self._last_dir = str(self._prefs.get("last_dir") or "") or str(app_dir())
        self._last_export_dir = str(self._prefs.get("last_export_dir") or "") or ""

        self._build()
        self._try_hook_drop()
        self._bind_global_hotkeys()
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self._search_var.trace_add("write", lambda *_: self._schedule_search_refresh())

    # ------------------------------------------------------------------ UI
    def _build(self) -> None:
        # —— Header: brand + secondary ——
        header = ctk.CTkFrame(self, fg_color=COLORS["surface"], corner_radius=0, height=42)
        header.pack(fill="x")
        header.pack_propagate(False)

        ctk.CTkLabel(
            header,
            text=__app_name__,
            font=ctk.CTkFont(family=FONT_UI, size=FONT_BRAND, weight="bold"),
            text_color=COLORS["accent"],
        ).pack(side="left", padx=(18, 10), pady=8)

        ctk.CTkLabel(
            header,
            text=f"v{__version__} · offline",
            font=ctk.CTkFont(family=FONT_UI, size=FONT_META),
            text_color=COLORS["muted"],
        ).pack(side="left", pady=8)

        self.lists_mtime = ctk.CTkLabel(
            header,
            text="",
            font=ctk.CTkFont(family=FONT_UI, size=FONT_META),
            text_color=COLORS["muted"],
        )
        self.lists_mtime.pack(side="left", padx=(14, 0), pady=10)
        self._refresh_lists_mtime()

        ctk.CTkButton(
            header, text="О программе", width=110, command=self.show_about, **btn_secondary()
        ).pack(side="right", padx=(6, 16), pady=8)
        ctk.CTkButton(
            header, text="Импорт списков", width=120, command=self.import_lists, **btn_secondary()
        ).pack(side="right", padx=(6, 0), pady=8)
        ctk.CTkButton(
            header, text="Конфиги", width=90, command=self.open_configs, **btn_secondary()
        ).pack(side="right", padx=0, pady=8)

        # —— Toolbar: источник → буфер → экспорт ——
        toolbar = ctk.CTkFrame(self, fg_color=COLORS["surface"], corner_radius=6)
        toolbar.pack(fill="x", padx=16, pady=(10, 4))
        tb = ctk.CTkFrame(toolbar, fg_color="transparent")
        tb.pack(fill="x", padx=10, pady=8)

        muted_label(tb, "Источник").pack(side="left", padx=(0, 8))
        btn_open = ctk.CTkButton(
            tb, text="Открыть файл", width=112, command=self.open_files, **btn_primary()
        )
        btn_open.pack(side="left", padx=(0, 6))
        HoverTip(btn_open, "Файл или несколько файлов (Ctrl+O)")
        btn_folder = ctk.CTkButton(
            tb, text="Папка", width=72, command=self.open_folder, **btn_secondary()
        )
        btn_folder.pack(side="left", padx=(0, 4))
        HoverTip(btn_folder, "Рекурсивно обработать все поддерживаемые файлы в папке")

        vsep(tb, height=26)

        muted_label(tb, "Буфер").pack(side="left", padx=(0, 8))
        ctk.CTkOptionMenu(
            tb,
            variable=self._copy_format,
            values=list(_COPY_FORMATS),
            width=112,
            height=BTN_H,
            font=chrome_font(),
            fg_color=COLORS["surface_alt"],
            button_color=COLORS["border"],
            button_hover_color=COLORS["accent_dim"],
            dropdown_fg_color=COLORS["surface"],
        ).pack(side="left", padx=(0, 4))
        btn_copy = ctk.CTkButton(
            tb, text="Копировать", width=100, command=self.copy_iocs, **btn_secondary()
        )
        btn_copy.pack(side="left", padx=(0, 8))
        HoverTip(btn_copy, "Скопировать видимые IOC в выбранном формате")
        btn_ticket = ctk.CTkButton(
            tb, text="Тикет", width=68, command=self.copy_ticket, **btn_secondary()
        )
        btn_ticket.pack(side="left", padx=(0, 4))
        HoverTip(btn_ticket, "Шаблон handoff в буфер (для тикета в SD/SOAR)")
        ctk.CTkCheckBox(
            tb,
            text="короткий",
            variable=self.ticket_short,
            command=self._persist_prefs,
            font=chrome_font(),
            text_color=COLORS["muted"],
            fg_color=COLORS["accent"],
            hover_color=COLORS["accent_dim"],
            border_color=COLORS["border"],
            width=78,
            checkbox_width=16,
            checkbox_height=16,
        ).pack(side="left", padx=(0, 6))
        btn_msgid = ctk.CTkButton(
            tb, text="Msg-ID", width=72, command=self.copy_message_id_block, **btn_secondary()
        )
        btn_msgid.pack(side="left")
        HoverTip(btn_msgid, "Message-ID / campaign-блок для корреляции писем")

        vsep(tb, height=26)

        muted_label(tb, "Экспорт").pack(side="left", padx=(0, 8))
        ctk.CTkOptionMenu(
            tb,
            variable=self._export_choice,
            values=list(_EXPORT_CHOICES),
            width=128,
            height=BTN_H,
            font=chrome_font(),
            fg_color=COLORS["surface_alt"],
            button_color=COLORS["border"],
            button_hover_color=COLORS["accent_dim"],
            dropdown_fg_color=COLORS["surface"],
        ).pack(side="left", padx=(0, 4))
        btn_export = ctk.CTkButton(
            tb, text="Сохранить", width=96, command=self._export_clicked, **btn_primary()
        )
        btn_export.pack(side="left", padx=(0, 6))
        HoverTip(btn_export, "Сохранить видимые IOC в выбранном формате")
        btn_att = ctk.CTkButton(
            tb, text="Вложения", width=88, command=self.save_attachments, **btn_secondary()
        )
        btn_att.pack(side="left")
        HoverTip(btn_att, "Выгрузить вложения письма на диск")

        # —— Filters: типы | скрыть шум | фокус ——
        filters = ctk.CTkFrame(self, fg_color=COLORS["surface"], corner_radius=6)
        filters.pack(fill="x", padx=16, pady=(6, 4))

        row_types = ctk.CTkFrame(filters, fg_color="transparent")
        row_types.pack(fill="x", padx=10, pady=(8, 2))

        muted_label(row_types, "Типы IOC").pack(side="left", padx=(0, 8))
        for name, var in self.cat_vars.items():
            cb = ctk.CTkCheckBox(
                row_types,
                text=name,
                variable=var,
                command=self._on_filter_change,
                font=chrome_font(),
                text_color=COLORS["text"],
                fg_color=COLORS["accent"],
                hover_color=COLORS["accent_dim"],
                border_color=COLORS["border"],
                width=70,
                checkbox_width=18,
                checkbox_height=18,
            )
            cb.pack(side="left", padx=(0, 6))

        self.search_entry = ctk.CTkEntry(
            row_types,
            textvariable=self._search_var,
            placeholder_text="Ctrl+F поиск по IOC…",
            width=170,
            height=BTN_H,
            font=chrome_font(),
            fg_color=COLORS["surface_alt"],
            border_color=COLORS["border"],
        )
        self.search_entry.pack(side="right", padx=(6, 0))
        ctk.CTkButton(
            row_types,
            text="Сброс",
            width=64,
            command=self._reset_filters,
            **btn_secondary(),
        ).pack(side="right")

        row_noise = ctk.CTkFrame(filters, fg_color="transparent")
        row_noise.pack(fill="x", padx=10, pady=(2, 4))

        muted_label(row_noise, "Скрыть шум").pack(side="left", padx=(0, 6))
        ctk.CTkLabel(
            row_noise,
            text="(✓ = убрать из списка)",
            font=ctk.CTkFont(family=FONT_UI, size=FONT_META),
            text_color=COLORS["muted"],
        ).pack(side="left", padx=(0, 8))
        for text, attr, tip in _HIDE_NOISE_FILTERS:
            cb = ctk.CTkCheckBox(
                row_noise,
                text=text,
                variable=getattr(self, attr),
                command=self._on_filter_change,
                font=chrome_font(),
                text_color=COLORS["text"],
                fg_color=COLORS["accent"],
                hover_color=COLORS["accent_dim"],
                border_color=COLORS["border"],
                width=100,
                checkbox_width=18,
                checkbox_height=18,
            )
            cb.pack(side="left", padx=(0, 6))
            HoverTip(cb, tip)

        vsep(row_noise, height=18)

        muted_label(row_noise, "Фокус").pack(side="left", padx=(0, 6))
        ctk.CTkLabel(
            row_noise,
            text="(✓ = только это)",
            font=ctk.CTkFont(family=FONT_UI, size=FONT_META),
            text_color=COLORS["muted"],
        ).pack(side="left", padx=(0, 8))
        for text, attr, tip in _FOCUS_FILTERS:
            cb = ctk.CTkCheckBox(
                row_noise,
                text=text,
                variable=getattr(self, attr),
                command=self._on_filter_change,
                font=chrome_font(),
                text_color=COLORS["text"],
                fg_color=COLORS["accent"],
                hover_color=COLORS["accent_dim"],
                border_color=COLORS["border"],
                width=118,
                checkbox_width=18,
                checkbox_height=18,
            )
            cb.pack(side="left", padx=(0, 6))
            HoverTip(cb, tip)

        self.filter_legend = ctk.CTkLabel(
            filters,
            text=(
                "Шум — типичный мусор писем (прокси URL, allowlist, частные IP). "
                "Сначала откройте файл → смотрите IOC → при необходимости включите «к разбору»."
            ),
            font=ctk.CTkFont(family=FONT_UI, size=FONT_META),
            text_color=COLORS["muted"],
            anchor="w",
        )
        self.filter_legend.pack(fill="x", padx=12, pady=(0, 8))

        self.focus_hint_row = ctk.CTkFrame(self, fg_color="transparent")
        self.focus_hint_row.pack(fill="x", padx=18, pady=(0, 2))
        self.focus_hint = ctk.CTkLabel(
            self.focus_hint_row,
            text="",
            font=ctk.CTkFont(family=FONT_UI, size=FONT_UI_BODY, weight="bold"),
            text_color=COLORS["info"],
            anchor="w",
        )
        self.focus_hint.pack(side="left", fill="x", expand=True)
        self.focus_clear_btn = ctk.CTkButton(
            self.focus_hint_row,
            text="Снять фокус",
            width=110,
            height=24,
            command=self._clear_file_focus,
            fg_color=COLORS["surface_alt"],
            hover_color=COLORS["border"],
            border_width=1,
            border_color=COLORS["border"],
            text_color=COLORS["text"],
        )
        # Hidden until a file focus is set
        self.focus_clear_btn.pack_forget()

        # —— Body: source | results ——
        body = ctk.CTkFrame(self, fg_color=COLORS["bg"])
        body.pack(fill="both", expand=True, padx=16, pady=(0, 4))
        body.grid_columnconfigure(0, weight=2, minsize=280)
        body.grid_columnconfigure(1, weight=5, minsize=520)
        body.grid_rowconfigure(0, weight=1)

        # Left: source
        left = ctk.CTkFrame(body, fg_color=COLORS["surface"], corner_radius=8)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 8))

        left_head = ctk.CTkFrame(left, fg_color="transparent")
        left_head.pack(fill="x", padx=14, pady=(12, 4))
        ctk.CTkLabel(
            left_head,
            text="Источник",
            font=ctk.CTkFont(family=FONT_UI, size=FONT_SECTION, weight="bold"),
            text_color=COLORS["text"],
        ).pack(side="left")
        self.source_meta = ctk.CTkLabel(
            left_head,
            text="",
            font=ctk.CTkFont(family=FONT_UI, size=FONT_META),
            text_color=COLORS["muted"],
        )
        self.source_meta.pack(side="right")

        self.input_box = ctk.CTkTextbox(
            left,
            fg_color=COLORS["surface_alt"],
            text_color=COLORS["muted"],
            font=ctk.CTkFont(family=FONT_MONO, size=FONT_CONTENT),
            wrap="word",
            border_width=0,
        )
        self.input_box.pack(fill="both", expand=True, padx=14, pady=(0, 8))
        self.input_box.insert("1.0", _PLACEHOLDER)
        self._bind_placeholder()

        ctk.CTkButton(
            left,
            text="Извлечь из текста  (Ctrl+Enter)",
            command=self.analyze_text_area,
            **btn_primary(),
        ).pack(fill="x", padx=14, pady=(0, 14))

        # Right: results
        right = ctk.CTkFrame(body, fg_color=COLORS["surface"], corner_radius=8)
        right.grid(row=0, column=1, sticky="nsew")

        # Compact summary bar (IOC count + verdict badge)
        summary = ctk.CTkFrame(right, fg_color=COLORS["surface_alt"], corner_radius=6, height=46)
        summary.pack(fill="x", padx=12, pady=(12, 6))
        summary.pack_propagate(False)

        self.ioc_summary_label = ctk.CTkLabel(
            summary,
            text="IOC —",
            font=ctk.CTkFont(family=FONT_UI, size=FONT_SUMMARY, weight="bold"),
            text_color=COLORS["accent"],
        )
        self.ioc_summary_label.pack(side="left", padx=(14, 12), pady=8)

        self.verdict_badge = ctk.CTkLabel(
            summary,
            text="",
            font=ctk.CTkFont(family=FONT_UI, size=FONT_BADGE, weight="bold"),
            text_color=COLORS["muted"],
        )
        self.verdict_badge.pack(side="left", padx=(0, 12), pady=8)

        self.ioc_breakdown = ctk.CTkLabel(
            summary,
            text="Откройте файл или вставьте текст",
            font=ctk.CTkFont(family=FONT_UI, size=FONT_UI_BODY),
            text_color=COLORS["muted"],
            anchor="e",
        )
        self.ioc_breakdown.pack(side="right", padx=14, pady=8)

        self.filter_hint = ctk.CTkLabel(
            right,
            text="Фильтры влияют на список, копирование и экспорт · клик по IOC копирует значение",
            font=ctk.CTkFont(family=FONT_UI, size=FONT_META),
            text_color=COLORS["muted"],
            anchor="w",
        )
        self.filter_hint.pack(fill="x", padx=14, pady=(0, 4))

        # Context tabs: only relevant facets, labels carry counts
        self._tab_host = ctk.CTkFrame(right, fg_color=COLORS["surface"])
        self._tab_host.pack(fill="both", expand=True, padx=12, pady=(0, 12))

        self._tab_key_by_label: dict[str, str] = {}
        self._tab_label_by_key: dict[str, str] = {}
        self._active_tab_key = "ioc"
        self._tab_var = ctk.StringVar(value="IOC")

        self._tab_seg = ctk.CTkSegmentedButton(
            self._tab_host,
            values=["IOC"],
            variable=self._tab_var,
            command=self._on_tab_selected,
            font=chrome_font(),
            fg_color=COLORS["surface_alt"],
            selected_color=COLORS["accent"],
            selected_hover_color=COLORS["accent_dim"],
            unselected_color=COLORS["surface_alt"],
            unselected_hover_color=COLORS["border"],
            text_color=COLORS["text"],
            height=BTN_H,
        )
        self._tab_seg.pack(fill="x", padx=2, pady=(2, 6))

        self._tab_body = ctk.CTkFrame(self._tab_host, fg_color=COLORS["surface"])
        self._tab_body.pack(fill="both", expand=True)

        self._tab_frames: dict[str, ctk.CTkFrame] = {}
        for key in ("ioc", "batch", "url", "att", "mail", "err"):
            frame = ctk.CTkFrame(self._tab_body, fg_color=COLORS["surface"])
            self._tab_frames[key] = frame

        self.ioc_empty_label = ctk.CTkLabel(
            self._tab_frames["ioc"],
            text="",
            font=ctk.CTkFont(family=FONT_UI, size=FONT_UI_BODY),
            text_color=COLORS["muted"],
            anchor="w",
        )
        self.ioc_empty_label.pack(fill="x", padx=4, pady=(0, 2))
        self.ioc_table = IocTable(
            self._tab_frames["ioc"],
            on_select=self._on_ioc_table_select,
            on_context=self._on_ioc_table_context,
        )
        self.ioc_table.pack(fill="both", expand=True)
        self.batch_box = self._make_text(self._tab_frames["batch"])
        self.url_box = self._make_text(self._tab_frames["url"])
        self.att_box = self._make_text(self._tab_frames["att"])

        mail_bar = ctk.CTkFrame(self._tab_frames["mail"], fg_color="transparent", height=32)
        mail_bar.pack(fill="x", padx=2, pady=(2, 0))
        ctk.CTkButton(
            mail_bar, text="Copy From", width=90, command=self._copy_from, **btn_secondary()
        ).pack(side="left", padx=(0, 4))
        ctk.CTkButton(
            mail_bar,
            text="Copy Msg-ID",
            width=100,
            command=self._copy_message_id,
            **btn_secondary(),
        ).pack(side="left", padx=(0, 4))
        ctk.CTkButton(
            mail_bar, text="Copy Auth", width=90, command=self._copy_auth, **btn_secondary()
        ).pack(side="left")
        self.mail_box = self._make_text(self._tab_frames["mail"])
        self.err_box = self._make_text(self._tab_frames["err"])
        self._show_tab_frame("ioc")
        self._tab_label_by_key = {"ioc": "IOC"}
        self._tab_key_by_label = {"IOC": "ioc"}

        # —— Status bar ——
        status_bar = ctk.CTkFrame(self, fg_color=COLORS["surface"], corner_radius=0, height=30)
        status_bar.pack(fill="x", side="bottom")
        status_bar.pack_propagate(False)
        self.status = ctk.CTkLabel(
            status_bar,
            text="Готов",
            font=ctk.CTkFont(family=FONT_UI, size=FONT_STATUS),
            text_color=COLORS["muted"],
            anchor="w",
        )
        self.status.pack(side="left", padx=16, pady=4)
        self._stop_btn = ctk.CTkButton(
            status_bar,
            text="Стоп",
            width=56,
            height=BTN_H,
            command=self.cancel_batch,
            fg_color=COLORS["danger"],
            hover_color="#a33c3c",
            state="disabled",
        )
        self._stop_btn.pack(side="right", padx=(4, 8), pady=4)
        self._retry_btn = ctk.CTkButton(
            status_bar,
            text="Повтор failed",
            width=110,
            height=BTN_H,
            command=self.retry_failed,
            fg_color=COLORS["surface_alt"],
            hover_color=COLORS["border"],
            border_width=1,
            border_color=COLORS["border"],
            state="disabled",
        )
        self._retry_btn.pack(side="right", padx=4, pady=4)
        ctk.CTkLabel(
            status_bar,
            text="1–6 вкладки · Ctrl+C/Shift+C · Ctrl+F · Ctrl+/− масштаб",
            font=ctk.CTkFont(family=FONT_UI, size=FONT_STATUS),
            text_color=COLORS["border"],
            anchor="e",
        ).pack(side="right", padx=8, pady=4)

        self.bind("<Control-o>", lambda _e: self.open_files())
        self.bind("<Control-O>", lambda _e: self.open_files())
        self.bind("<Control-Return>", lambda _e: self.analyze_text_area())
        self.bind("<Control-KP_Enter>", lambda _e: self.analyze_text_area())

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
        widget.bind("<Control-Return>", lambda _e: self.analyze_text_area(), add="+")

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
            "Return",
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
            font=ctk.CTkFont(family=FONT_MONO, size=FONT_IOC),
            wrap="word",
            activate_scrollbars=True,
        )
        box.pack(fill="both", expand=True, padx=2, pady=2)
        self._configure_result_tags(box)
        return box

    def _tk(self, box: ctk.CTkTextbox):
        return getattr(box, "textbox", None) or getattr(box, "_textbox", None)

    def _configure_result_tags(self, box: ctk.CTkTextbox) -> None:
        widget = self._tk(box)
        if widget is None:
            return
        base = (FONT_MONO, FONT_IOC)
        bold = (FONT_MONO, FONT_IOC, "bold")
        section = (FONT_UI, FONT_SECTION, "bold")
        widget.tag_configure(
            "section", foreground=COLORS["accent"], font=section, spacing1=8, spacing3=2
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

    def _on_ioc_table_select(self, ioc: Ioc) -> None:
        self.clipboard_clear()
        self.clipboard_append(ioc.value)
        self._set_status(f"Скопировано: {ioc.ioc_type.value} → {ioc.value[:80]}")

    def _on_ioc_table_context(self, ioc: Ioc, x_root: int, y_root: int) -> None:
        menu = tk.Menu(self, tearoff=0)
        menu.add_command(label="Копировать value", command=lambda: self._copy_one(ioc.value))
        menu.add_command(
            label="Копировать defanged",
            command=lambda: self._copy_one(defang_value(ioc.value)),
        )
        menu.add_separator()
        menu.add_command(
            label="В denylist…",
            command=lambda: self._add_ioc_to_list(ioc, "denylist.txt"),
        )
        menu.add_command(
            label="В allowlist…",
            command=lambda: self._add_ioc_to_list(ioc, "allowlist.txt"),
        )
        try:
            menu.tk_popup(x_root, y_root)
        finally:
            menu.grab_release()

    def _copy_one(self, value: str) -> None:
        self.clipboard_clear()
        self.clipboard_append(value)
        self._set_status(f"Скопировано: {value[:80]}")

    def _add_ioc_to_list(self, ioc: Ioc, list_name: str) -> None:
        from tkinter import simpledialog

        comment = simpledialog.askstring(
            __app_name__,
            f"Комментарий / тикет для {ioc.value}\n(можно пусто)",
            parent=self,
        )
        if comment is None:
            return
        added = append_list_entries(list_name, [ioc.value], comment=comment.strip())
        self._refresh_lists_mtime()
        self._set_status(f"{list_name}: +{added} ({ioc.value[:60]})")
        if added and self.result:
            # Re-tag in memory for immediate UI feedback
            tag = "denylisted" if "deny" in list_name else "allowlisted"
            if tag not in ioc.tags:
                ioc.tags.append(tag)
            self._refresh_views()

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

    def _set_status(self, text: str) -> None:
        self.status.configure(text=text)

    def _refresh_lists_mtime(self) -> None:
        allow = list_mtime_label("allowlist.txt")
        deny = list_mtime_label("denylist.txt")
        self.lists_mtime.configure(text=f"allow {allow} · deny {deny}")

    def _on_tab_selected(self, label: str) -> None:
        key = self._tab_key_by_label.get(label)
        if key:
            self._show_tab_frame(key)

    def _show_tab_frame(self, key: str) -> None:
        self._active_tab_key = key
        for k, frame in self._tab_frames.items():
            if k == key:
                frame.pack(fill="both", expand=True)
            else:
                frame.pack_forget()

    def _mail_tab_relevant(self, result: AnalysisResult) -> bool:
        rows = result.file_rows or []
        if result.source_kind not in ("email", "batch"):
            return False
        return bool(
            result.verdict
            or result.mail_identity
            or result.headers
            or result.raw_headers
            or any(r.kind == "email" for r in rows)
        )

    def _desired_tabs(
        self, result: AnalysisResult | None, filtered_count: int
    ) -> list[tuple[str, str]]:
        return desired_result_tabs(result, filtered_count)

    def _sync_result_tabs(self, result: AnalysisResult | None, filtered_count: int = 0) -> None:
        desired = self._desired_tabs(result, filtered_count)
        labels = [label for _, label in desired]
        key_by_label = {label: key for key, label in desired}
        label_by_key = {key: label for key, label in desired}

        prev_key = self._active_tab_key
        self._tab_key_by_label = key_by_label
        self._tab_label_by_key = label_by_key

        self._tab_seg.configure(values=labels)
        if prev_key in label_by_key:
            select_key = prev_key
        else:
            select_key = "ioc"
        select_label = label_by_key[select_key]
        self._tab_var.set(select_label)
        self._tab_seg.set(select_label)
        self._show_tab_frame(select_key)

    def _persist_prefs(self) -> None:
        updates = {
            "last_dir": self._last_dir,
            "last_export_dir": self._last_export_dir,
            "copy_format": self._copy_format.get(),
            "export_choice": self._export_choice.get(),
            "ticket_short": bool(self.ticket_short.get()),
            "ticket_lang": self._ticket_lang,
            "ui_scale": self._ui_scale,
            "window_geometry": self.geometry(),
            "hide_rewriter": bool(self.hide_rewriter.get()),
            "hide_allowlisted": bool(self.hide_allowlisted.get()),
            "hide_private": bool(self.hide_private.get()),
            "only_denylisted": bool(self.only_denylisted.get()),
            "actionable_only": bool(self.actionable_only.get()),
        }
        for name, var in self.cat_vars.items():
            updates[_CAT_PREF_KEYS[name]] = bool(var.get())
        save_prefs(updates)

    def _on_close(self) -> None:
        try:
            self._persist_prefs()
        except Exception:  # noqa: BLE001
            pass
        self.destroy()

    def _schedule_search_refresh(self) -> None:
        if self._search_after_id is not None:
            try:
                self.after_cancel(self._search_after_id)
            except Exception:  # noqa: BLE001
                pass
        self._search_after_id = self.after(200, self._run_search_refresh)

    def _run_search_refresh(self) -> None:
        self._search_after_id = None
        self._refresh_views()

    def _clear_file_focus(self) -> None:
        self._focus_source_file = ""
        self._refresh_views()
        self._set_status("Фокус файла снят")

    def _update_focus_hint(self) -> None:
        if self._focus_source_file:
            self.focus_hint.configure(
                text=f"Фокус файла: {self._focus_source_file}  [снять]"
            )
            if not self.focus_clear_btn.winfo_ismapped():
                self.focus_clear_btn.pack(side="right", padx=(8, 0))
        else:
            self.focus_hint.configure(text="")
            self.focus_clear_btn.pack_forget()

    def _on_filter_change(self) -> None:
        self._persist_prefs()
        self._refresh_views()

    def _bind_global_hotkeys(self) -> None:
        self.bind("<Control-f>", self._focus_search)
        self.bind("<Control-F>", self._focus_search)
        self.bind("<Control-c>", self._hotkey_copy_values)
        self.bind("<Control-C>", self._hotkey_copy_values)
        self.bind("<Control-Shift-C>", self._hotkey_copy_defanged)
        self.bind("<Control-Shift-c>", self._hotkey_copy_defanged)
        self.bind("<Control-plus>", lambda _e: self._bump_scale(1))
        self.bind("<Control-equal>", lambda _e: self._bump_scale(1))
        self.bind("<Control-minus>", lambda _e: self._bump_scale(-1))
        self.bind("<Control-KP_Add>", lambda _e: self._bump_scale(1))
        self.bind("<Control-KP_Subtract>", lambda _e: self._bump_scale(-1))
        for i, key in enumerate(_TAB_HOTKEYS, start=1):
            self.bind(str(i), lambda _e, k=key: self._hotkey_tab(k))
            self.bind(f"<Key-{i}>", lambda _e, k=key: self._hotkey_tab(k))

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
        # Don't steal copy from text widgets with selection
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
            ctk.set_window_scaling(self._ui_scale)
        except Exception:  # noqa: BLE001
            pass
        self._persist_prefs()
        self._set_status(f"Масштаб UI: {int(self._ui_scale * 100)}%")

    def cancel_batch(self) -> None:
        self._cancel_batch = True
        self._set_status("Отмена пакетной обработки…")

    def retry_failed(self) -> None:
        if not self._failed_paths:
            return
        paths = list(self._failed_paths)
        self._analyze_paths(paths)

    # ----------------------------------------------------------- filtering
    def _reset_filters(self) -> None:
        for var in self.cat_vars.values():
            var.set(True)
        self.hide_rewriter.set(True)
        self.hide_allowlisted.set(True)
        self.hide_private.set(False)
        self.only_denylisted.set(False)
        self.actionable_only.set(False)
        self._search_var.set("")
        self._focus_source_file = ""
        self._update_focus_hint()
        self._on_filter_change()

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
            "actionable_only": bool(self.actionable_only.get()),
            "search": self._search_var.get(),
            "source_file": self._focus_source_file,
        }

    def _filtered_iocs(self):
        if not self.result:
            return []
        return filter_iocs(self.result, **self._filter_kwargs())

    def _filtered_result(self) -> AnalysisResult | None:
        if not self.result:
            return None
        return with_iocs(self.result, self._filtered_iocs())

    def _refresh_views(self) -> None:
        if not self.result:
            self.ioc_summary_label.configure(text="IOC —")
            self.verdict_badge.configure(text="")
            self.ioc_breakdown.configure(text="Откройте файл или вставьте текст")
            self.filter_hint.configure(
                text="Сначала откройте файл или вставьте текст · клик по IOC копирует значение"
            )
            self.source_meta.configure(text="")
            self._sync_result_tabs(None)
            self.ioc_table.clear()
            self.ioc_empty_label.configure(
                text=(
                    "1. Откройте файл / папку или вставьте текст слева\n"
                    "2. При шуме писем оставьте «прокси URL» и «allowlist» включёнными\n"
                    "3. Нужны только важные — включите «к разбору»"
                )
            )
            self._update_focus_hint()
            return

        filtered = self._filtered_iocs()
        counts = Counter(i.ioc_type.value for i in filtered)
        total = len(filtered)
        full = len(self.result.iocs)

        self._update_focus_hint()

        if total == full:
            self.ioc_summary_label.configure(text=f"IOC {total}")
            self.filter_hint.configure(
                text=f"Все {full} · ПКМ по IOC · Ctrl+C value · Ctrl+Shift+C defanged"
            )
        else:
            self.ioc_summary_label.configure(text=f"IOC {total}/{full}")
            self.filter_hint.configure(
                text=f"Показано {total} из {full} · поиск/фильтр/фокус файла активны"
            )

        if counts:
            breakdown = " · ".join(f"{k} {v}" for k, v in sorted(counts.items()))
            self.ioc_breakdown.configure(text=breakdown, text_color=COLORS["text"])
        else:
            self.ioc_breakdown.configure(
                text="Пусто — снимите «Фокус» или ослабьте «Скрыть шум»",
                text_color=COLORS["muted"],
            )

        self._update_verdict_badge(self.result)
        self._sync_result_tabs(self.result, filtered_count=total)
        self._fill_iocs(self.result, filtered)
        self._fill_batch(self.result)
        self._fill_urls(self.result)
        self._fill_attachments(self.result)
        self._fill_mail_tab(self.result)
        self._fill_errors(self.result)

    def _update_verdict_badge(self, result: AnalysisResult) -> None:
        v = result.verdict
        if not v or result.source_kind not in ("email", "batch"):
            self.verdict_badge.configure(text="")
            return
        color = VERDICT_COLORS.get(v.level.value, COLORS["muted"])
        self.verdict_badge.configure(
            text=f"{v.level.value.upper()} · {v.score}",
            text_color=color,
        )

    # -------------------------------------------------------------- open
    def open_files(self) -> None:
        paths = filedialog.askopenfilenames(
            title=f"{__app_name__} — открыть файлы",
            initialdir=self._last_dir or None,
            filetypes=[
                (
                    "Все поддерживаемые",
                    "*.eml *.msg *.pdf *.html *.htm *.txt *.csv *.log *.docx *.xlsx *.zip *.7z *.rar",
                ),
                ("Email", "*.eml *.msg"),
                ("Office", "*.docx *.xlsx"),
                ("Архив", "*.zip *.7z *.rar"),
                ("PDF", "*.pdf"),
                ("HTML", "*.html *.htm"),
                ("Текст / тикет", "*.txt *.csv *.log *.md"),
                ("Все файлы", "*.*"),
            ],
        )
        if not paths:
            return
        self._last_dir = str(Path(paths[0]).parent)
        self._persist_prefs()
        self._analyze_paths(list(paths))

    def open_folder(self) -> None:
        folder = filedialog.askdirectory(
            title=f"{__app_name__} — папка (рекурсивно)",
            initialdir=self._last_dir or None,
        )
        if not folder:
            return
        self._last_dir = folder
        self._persist_prefs()
        paths = _collect_supported(Path(folder), recursive=True)
        if not paths:
            messagebox.showinfo(
                __app_name__,
                "В папке нет поддерживаемых файлов "
                "(.eml .msg .pdf .html .txt .docx .xlsx .zip .7z .rar).",
            )
            return
        try:
            threshold = int(self._prefs.get("folder_warn_threshold") or 80)
        except (TypeError, ValueError):
            threshold = 80
        if len(paths) > threshold:
            if not messagebox.askyesno(
                __app_name__,
                f"Найдено файлов: {len(paths)} (порог предупреждения: {threshold}).\n"
                "Продолжить пакетный разбор?",
            ):
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
        self._focus_source_file = ""
        names = ", ".join(Path(p).name for p in paths[:3])
        extra = f" (+{len(paths) - 3})" if len(paths) > 3 else ""
        self._set_status(f"Извлечение 0/{len(paths)}: {names}{extra}…")
        try:
            self._stop_btn.configure(state="normal")
        except Exception:  # noqa: BLE001
            pass
        self.update_idletasks()
        threading.Thread(target=self._run_paths, args=(paths,), daemon=True).start()

    def _run_paths(self, paths: list[str]) -> None:
        hard_errors: list[str] = []
        failed: list[str] = []
        total = len(paths)
        slots: list[AnalysisResult | None] = [None] * total
        done = [0]

        def _work(idx: int, path: str) -> tuple[int, AnalysisResult | None, str | None]:
            if self._cancel_batch:
                return idx, None, "cancelled"
            try:
                return idx, analyze_file(path), None
            except Exception as exc:  # noqa: BLE001
                return idx, None, f"{path}: {exc}"

        workers = min(4, max(1, os.cpu_count() or 1))
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            futures = [pool.submit(_work, i, p) for i, p in enumerate(paths)]
            for fut in concurrent.futures.as_completed(futures):
                idx, result, err = fut.result()
                done[0] += 1
                n = done[0]
                path = paths[idx]
                self.after(
                    0,
                    lambda i=n, t=total, p=path: self._set_status(
                        f"Извлечение {i}/{t}: {Path(p).name}"
                    ),
                )
                if err == "cancelled":
                    continue
                if err:
                    hard_errors.append(err)
                    failed.append(path)
                elif result is not None:
                    slots[idx] = result

        if self._cancel_batch:
            hard_errors.append("Пакетная обработка отменена")

        results = [r for r in slots if r is not None]

        self.after(0, lambda: self._stop_btn.configure(state="disabled"))

        if not results:
            msg = "Не удалось разобрать ни одного файла.\n" + "\n".join(hard_errors[:8])
            self.after(0, lambda: messagebox.showerror("Ошибка", msg))
            self.after(0, lambda: self._set_status("Ошибка извлечения"))
            self.after(0, lambda: self._set_failed(failed))
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
        self.after(
            0,
            lambda: self._apply_result(
                result, preload_text=True, batch_results=results, failed=failed
            ),
        )

    def _set_failed(self, failed: list[str]) -> None:
        self._failed_paths = list(failed)
        state = "normal" if failed else "disabled"
        try:
            self._retry_btn.configure(state=state)
        except Exception:  # noqa: BLE001
            pass

    def _apply_result(
        self,
        result: AnalysisResult,
        preload_text: bool,
        batch_results: list[AnalysisResult] | None = None,
        failed: list[str] | None = None,
    ) -> None:
        self.result = result
        self._batch_results = list(batch_results or ([result] if result else []))
        self._set_failed(failed or [])
        kind = result.source_kind
        name = Path(result.source_path).name if result.source_path else ""
        self.source_meta.configure(text=f"{kind} · {name}"[:48])

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
            meta_lines.extend(["=" * 40, "", preview])
            self._placeholder_active = False
            self.input_box.delete("1.0", "end")
            self.input_box.insert("1.0", "\n".join(meta_lines))
            self.input_box.configure(text_color=COLORS["text"])

        self._refresh_views()
        if "ioc" in self._tab_label_by_key:
            label = self._tab_label_by_key["ioc"]
            self._tab_var.set(label)
            self._tab_seg.set(label)
            self._show_tab_frame("ioc")
        filtered_n = len(self._filtered_iocs())
        err = f" · ошибки: {len(result.errors)}" if result.errors else ""
        self._set_status(f"Готово: {filtered_n} IOC{err}")

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

    def _copy_auth(self) -> None:
        if not self.result or not self.result.mail_identity:
            return
        mid = self.result.mail_identity
        text = f"SPF={mid.spf or '—'} DKIM={mid.dkim or '—'} DMARC={mid.dmarc or '—'}"
        self.clipboard_clear()
        self.clipboard_append(text)
        self._set_status("Auth скопирован")

    def copy_message_id_block(self) -> None:
        if not self.result:
            messagebox.showinfo(__app_name__, "Сначала извлеките IOC")
            return
        text = build_message_id_block(self.result)
        if not text.strip():
            messagebox.showinfo(__app_name__, "Message-ID не найден")
            return
        self.clipboard_clear()
        self.clipboard_append(text)
        self._set_status("Message-ID / campaign блок скопирован")

    def copy_ticket(self) -> None:
        if not self.result:
            messagebox.showinfo(__app_name__, "Сначала извлеките IOC")
            return
        short = bool(self.ticket_short.get())
        text = build_ticket_template(
            self.result,
            self._filtered_iocs(),
            defang=True,
            short=short,
            lang=self._ticket_lang,
        )
        self.clipboard_clear()
        self.clipboard_append(text)
        self._persist_prefs()
        mode = "короткий" if short else "полный"
        self._set_status(f"Шаблон тикета скопирован ({mode}, defanged)")

    # ----------------------------------------------------------- fillers
    def _fill_batch(self, result: AnalysisResult) -> None:
        self._clear_box(self.batch_box)
        self._batch_row_tags.clear()
        rows = result.file_rows or []
        if len(rows) < 2:
            self._put(self.batch_box, "Нужно ≥2 файла для пакетной таблицы\n", "empty")
            return
        self._put(
            self.batch_box,
            f"▸ Файлы  ({len(rows)})  — клик по имени → IOC этого файла\n\n",
            "section",
        )
        widget = self._tk(self.batch_box)
        for idx, row in enumerate(rows):
            name = Path(row.path).name
            tag = f"batchrow_{idx}"
            self._batch_row_tags[tag] = name
            level = (row.verdict_level or "—").upper()
            color = {
                "MALICIOUS": "danger",
                "SUSPICIOUS": "warn",
                "UNKNOWN": "info",
                "BENIGN": "ok",
            }.get(level, "muted")
            err_color = "danger" if row.errors else color
            score = f" {row.verdict_score}" if row.verdict_score is not None else ""
            self._put(self.batch_box, f"  {name}\n", "ioc_click", tag, err_color)
            self._put(self.batch_box, f"      {row.kind} · ", "muted")
            self._put(self.batch_box, f"{level}{score}", color)
            self._put(self.batch_box, f" · IOC {row.ioc_count}\n", "muted")
            if row.subject:
                self._put(self.batch_box, f"      Subject  {row.subject[:120]}\n", "meta")
            if row.sender:
                self._put(self.batch_box, f"      From     {row.sender[:120]}\n", "muted")
            if row.message_id:
                self._put(self.batch_box, f"      Msg-ID   {row.message_id}\n", "info")
            if row.top_iocs:
                self._put(self.batch_box, f"      Топ      {', '.join(row.top_iocs[:5])}\n", "value")
            if row.errors:
                self._put(
                    self.batch_box,
                    f"      Ошибки   {'; '.join(row.errors[:3])}\n",
                    "danger",
                )
            self._put(self.batch_box, "\n")
        if widget is not None:
            widget.tag_bind("ioc_click", "<Button-1>", self._on_batch_row_click)

    def _on_batch_row_click(self, event: tk.Event) -> None:  # type: ignore[type-arg]
        widget = self._tk(self.batch_box)
        if widget is None:
            return
        index = widget.index(f"@{event.x},{event.y}")
        for tag in widget.tag_names(index):
            if tag.startswith("batchrow_") and tag in self._batch_row_tags:
                name = self._batch_row_tags[tag]
                self._focus_source_file = name
                self._refresh_views()
                if "ioc" in self._tab_label_by_key:
                    label = self._tab_label_by_key["ioc"]
                    self._tab_var.set(label)
                    self._tab_seg.set(label)
                    self._show_tab_frame("ioc")
                self._set_status(f"Фокус IOC: {name}")
                return

    def _fill_iocs(self, result: AnalysisResult, filtered) -> None:
        if not filtered:
            self.ioc_table.clear()
            msg = "IOC не найдены"
            if result.errors:
                msg += f"\n! {len(result.errors)} замечаний — вкладка «Ошибки»"
            self.ioc_empty_label.configure(text=msg)
            return

        note = ""
        if result.errors:
            note = f"! {len(result.errors)} замечаний — вкладка «Ошибки»"
        self.ioc_empty_label.configure(text=note)
        self.ioc_table.set_iocs(list(filtered))

    def _fill_urls(self, result: AnalysisResult) -> None:
        self._clear_box(self.url_box)
        if not result.url_rewrites:
            self._put(self.url_box, "URL не найдены\n", "empty")
            return

        changed = sum(1 for u in result.url_rewrites if u.changed)
        self._put(
            self.url_box,
            f"▸ Rewrite  ({len(result.url_rewrites)}, развёрнуто {changed})\n",
            "section",
        )
        for u in result.url_rewrites:
            status_tag = "ok" if u.changed else "muted"
            status = "развёрнут" if u.changed else "как есть"
            self._put(self.url_box, f"  {u.rewriter}  ", "info")
            self._put(self.url_box, f"{status}\n", status_tag)
            self._put(self.url_box, "      ", "label")
            self._put(self.url_box, f"{u.original}\n", "muted" if u.changed else "value")
            if u.changed:
                self._put(self.url_box, "   →  ", "label")
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
            + (f", флаги: {risky}" if risky else "")
            + f", сохранить можно: {with_data})\n\n",
            "section",
        )
        for a in result.attachments:
            name_tag = "danger" if a.risk_flags else "value"
            self._put(self.att_box, f"  {a.filename}\n", name_tag)
            self._put(
                self.att_box,
                f"      {a.size} B · {a.mime_guess}"
                + (" · data✓" if a.data else " · только хеш")
                + "\n",
                "muted",
            )
            self._put(self.att_box, f"      SHA256  {a.sha256}\n", "value")
            if a.risk_flags:
                self._put(self.att_box, f"      флаги   {', '.join(a.risk_flags)}\n", "warn")
            if a.ole_streams:
                preview = ", ".join(a.ole_streams[:10])
                more = len(a.ole_streams) - 10
                self._put(
                    self.att_box,
                    f"      OLE     {preview}"
                    + (f" …+{more}" if more > 0 else "")
                    + "\n",
                    "info",
                )
            if a.nested_kind:
                self._put(self.att_box, f"      nested  {a.nested_kind}\n", "meta")
            if a.archive_entries:
                # Hide QR: stash lines from archive preview — show separately
                members = [e for e in a.archive_entries if not e.startswith("QR:")]
                qr_lines = [e[3:] for e in a.archive_entries if e.startswith("QR:")]
                if members:
                    preview = ", ".join(Path(e).name for e in members[:12])
                    more = len(members) - 12
                    self._put(
                        self.att_box,
                        f"      архив   {preview}"
                        + (f" …+{more}" if more > 0 else "")
                        + "\n",
                        "meta",
                    )
                if qr_lines:
                    self._put(
                        self.att_box,
                        f"      QR      {'; '.join(qr_lines[:5])}\n",
                        "danger",
                    )
            for note in a.notes[:5]:
                self._put(self.att_box, f"      — {note}\n", "muted")
            self._put(self.att_box, "\n")

    def _fill_mail_tab(self, result: AnalysisResult) -> None:
        """Verdict + identity + headers — only meaningful for email."""
        self._clear_box(self.mail_box)
        v = result.verdict
        mid = result.mail_identity

        if v and result.source_kind in ("email", "batch"):
            color_tag = {
                "malicious": "danger",
                "suspicious": "warn",
                "unknown": "info",
                "benign": "ok",
            }.get(v.level.value, "info")
            self._put(self.mail_box, "▸ Вердикт  ", "section")
            self._put(
                self.mail_box,
                f"{v.level.value.upper()} · score {v.score}\n",
                color_tag,
            )
            self._put(self.mail_box, f"  {v.summary}\n\n", "muted")
            if v.reasons:
                self._put(self.mail_box, "  Причины\n", "label")
                for r in v.reasons[:8]:
                    self._put(self.mail_box, f"    • {r}\n", "muted")
            if v.actions:
                self._put(self.mail_box, "\n  Действия\n", "label")
                for a in v.actions[:6]:
                    self._put(self.mail_box, f"    {a.priority}. {a.action}\n", "value")
                    self._put(self.mail_box, f"       {a.rationale}\n", "muted")
            self._put(self.mail_box, "\n")

        if mid:
            self._put(self.mail_box, "▸ Идентичность\n", "section")
            self._put(self.mail_box, "  From         ", "label")
            self._put(self.mail_box, f"{mid.from_header or '—'}\n", "value")
            if mid.subject:
                self._put(self.mail_box, "  Subject      ", "label")
                self._put(self.mail_box, f"{mid.subject}\n", "value")
            self._put(self.mail_box, "  Return-Path  ", "label")
            self._put(self.mail_box, f"{mid.return_path or '—'}\n", "muted")
            self._put(self.mail_box, "  Message-ID   ", "label")
            self._put(self.mail_box, f"{mid.message_id or '—'}\n", "meta")
            self._put(self.mail_box, "  Auth         ", "label")
            self._put(
                self.mail_box,
                f"SPF={mid.spf or '—'}  DKIM={mid.dkim or '—'}  DMARC={mid.dmarc or '—'}\n",
                "info",
            )
            self._put(self.mail_box, "  Hops         ", "label")
            self._put(self.mail_box, f"{mid.received_hops}\n", "value")
            self._put(self.mail_box, "\n")
            self._put(
                self.mail_box,
                "  Кнопки сверху: Copy From / Msg-ID / Auth\n\n",
                "muted",
            )

        # Per-file mail cards in batch (file_rows already carry identity snippets)
        mail_rows = [
            r
            for r in (result.file_rows or [])
            if r.kind == "email" and (r.message_id or r.subject or r.sender)
        ]
        if result.source_kind == "batch" and len(mail_rows) > 1:
            self._put(self.mail_box, f"▸ Письма в пакете  ({len(mail_rows)})\n", "section")
            for r in mail_rows:
                self._put(self.mail_box, f"  {Path(r.path).name}\n", "value")
                if r.sender:
                    self._put(self.mail_box, f"      From    {r.sender[:140]}\n", "muted")
                if r.subject:
                    self._put(self.mail_box, f"      Subject {r.subject[:140]}\n", "meta")
                if r.message_id:
                    self._put(self.mail_box, f"      Msg-ID  {r.message_id}\n", "info")
                if r.verdict_level:
                    self._put(
                        self.mail_box,
                        f"      Verdict {r.verdict_level.upper()}"
                        + (f" {r.verdict_score}" if r.verdict_score is not None else "")
                        + "\n",
                        "warn",
                    )
                self._put(self.mail_box, "\n")
            self._put(
                self.mail_box,
                "  Полный разбор заголовков — у первого письма; детали по файлам во вкладке «Пакет».\n\n",
                "muted",
            )

        if result.headers:
            alerts = [
                h for h in result.headers if h.severity.value in ("high", "critical", "medium")
            ]
            self._put(
                self.mail_box,
                f"▸ Findings  ({len(result.headers)}"
                + (f", замечаний: {len(alerts)}" if alerts else "")
                + ")\n",
                "section",
            )
            for h in result.headers:
                sev = h.severity.value
                sev_ru = SEVERITY_LABELS_RU.get(sev, sev)
                self._put(self.mail_box, f"  [{sev_ru}] ", f"sev_{sev}")
                self._put(self.mail_box, f"{h.name}\n", "value")
                self._put(self.mail_box, f"      {h.note}\n", "muted")
                self._put(self.mail_box, f"      {h.value}\n\n", "meta")
        elif result.source_kind not in ("email", "batch") and not mid and not v:
            self._put(
                self.mail_box,
                "Вкладка «Письмо» — для .eml / .msg:\n"
                "вердикт triage, From/SPF/DKIM, findings и сырые заголовки.\n",
                "empty",
            )
            return

        if mid:
            # Inline copy actions as text instructions — add real buttons in tab header
            pass

        if result.raw_headers:
            self._put(self.mail_box, "▸ Сырые заголовки\n", "section")
            for name, value in result.raw_headers.items():
                self._put(self.mail_box, f"  {name}: ", "label")
                self._put(self.mail_box, f"{value}\n", "muted")

        # Copy shortcuts at end of mail tab content via status — bind keys when mail present
        if mid and (mid.from_header or mid.message_id):
            self._put(self.mail_box, "\n", "muted")
            self._put(self.mail_box, "  [F] Copy From   [M] Copy Message-ID\n", "info")
            widget = self._tk(self.mail_box)
            if widget is not None:
                widget.bind("<Key-f>", lambda _e: self._copy_from(), add="+")
                widget.bind("<Key-F>", lambda _e: self._copy_from(), add="+")
                widget.bind("<Key-m>", lambda _e: self._copy_message_id(), add="+")
                widget.bind("<Key-M>", lambda _e: self._copy_message_id(), add="+")

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
        if fmt == "defanged":
            return "\n".join(defang_value(i.value) for i in iocs)
        if fmt == "defanged|type":
            return "\n".join(
                defang_ioc_line(i.ioc_type.value, i.value, with_type=True) for i in iocs
            )
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
            name = (
                _SAFE_NAME_RE.sub("_", att.filename or "attachment.bin").strip(" .")
                or "attachment.bin"
            )
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
        initialdir = self._last_export_dir or self._last_dir or None

        def _remember(path: str) -> None:
            self._last_export_dir = str(Path(path).parent)
            self._persist_prefs()

        dialogs = {
            "csv": (".csv", [("CSV", "*.csv")], "iocs.csv", export_csv),
            "stix": (".json", [("STIX JSON", "*.json")], "iocs_stix.json", export_stix),
        }
        if kind_l in dialogs:
            ext, ftypes, initial, fn = dialogs[kind_l]
            path = filedialog.asksaveasfilename(
                defaultextension=ext,
                filetypes=ftypes,
                initialfile=initial,
                initialdir=initialdir,
            )
            if path:
                fn(filtered, path)
                _remember(path)
                self._set_status(f"{kind_l.upper()}: {path}")
            return

        if kind_l == "json":
            path = filedialog.asksaveasfilename(
                defaultextension=".json",
                filetypes=[("JSON", "*.json")],
                initialfile="iocs_report.json",
                initialdir=initialdir,
            )
            if path:
                export_report_json(
                    filtered, path, filters_applied=self._filter_kwargs_serializable()
                )
                _remember(path)
                self._set_status(f"JSON: {path}")
            return

        if kind_l == "misp":
            path = filedialog.asksaveasfilename(
                defaultextension=".json",
                filetypes=[("MISP JSON", "*.json")],
                initialfile="iocs_misp.json",
                initialdir=initialdir,
            )
            if path:
                export_misp(filtered, path, iocs=iocs)
                _remember(path)
                self._set_status(f"MISP: {path}")
        elif kind_l == "opencti":
            path = filedialog.asksaveasfilename(
                defaultextension=".json",
                filetypes=[("OpenCTI JSON", "*.json")],
                initialfile="iocs_opencti.json",
                initialdir=initialdir,
            )
            if path:
                export_opencti(filtered, path, iocs=iocs)
                _remember(path)
                self._set_status(f"OpenCTI: {path}")
        elif kind_l == "yara":
            path = filedialog.asksaveasfilename(
                defaultextension=".yar",
                filetypes=[("YARA", "*.yar *.yara"), ("All", "*.*")],
                initialfile="ioc_extractor_iocs.yar",
                initialdir=initialdir,
            )
            if path:
                export_yara(filtered, path, iocs=iocs)
                _remember(path)
                self._set_status(f"YARA: {path}")
        elif kind_l in ("case pack", "case_pack", "casepack"):
            path = filedialog.asksaveasfilename(
                defaultextension=".zip",
                filetypes=[("Case pack ZIP", "*.zip")],
                initialfile="case_pack.zip",
                initialdir=initialdir,
            )
            if path:
                out = export_case_pack(
                    filtered,
                    path,
                    filters_applied=self._filter_kwargs_serializable(),
                    include_attachments=True,
                )
                _remember(path)
                self._set_status(f"Case pack: {out}")
        elif "по файлам" in kind_l or kind_l.endswith("(per file)"):
            if not self._batch_results:
                messagebox.showinfo(__app_name__, "Нет per-file результатов для экспорта")
                return
            path = filedialog.asksaveasfilename(
                defaultextension=".zip",
                filetypes=[("Case pack ZIP", "*.zip")],
                initialfile="case_pack_per_file.zip",
                initialdir=initialdir,
            )
            if path:
                # If focus file set — only that file; else all batch results
                results = self._batch_results
                if self._focus_source_file:
                    results = [
                        r
                        for r in self._batch_results
                        if Path(r.source_path).name == self._focus_source_file
                    ] or results
                out = export_case_pack_multi(
                    results,
                    path,
                    filters_applied=self._filter_kwargs_serializable(),
                    include_attachments=True,
                )
                _remember(path)
                self._set_status(f"Case pack (по файлам ×{len(results)}): {out}")

    def _filter_kwargs_serializable(self) -> dict:
        kw = self._filter_kwargs()
        types = kw.get("types")
        return {
            "types": sorted(types) if isinstance(types, set) else types,
            "hide_private": kw.get("hide_private"),
            "hide_rewriter": kw.get("hide_rewriter"),
            "hide_allowlisted": kw.get("hide_allowlisted"),
            "only_denylisted": kw.get("only_denylisted"),
            "actionable_only": kw.get("actionable_only"),
            "search": kw.get("search"),
            "source_file": kw.get("source_file"),
        }

    def import_lists(self) -> None:
        path = filedialog.askopenfilename(
            title="Импорт в allowlist/denylist (CSV или MISP JSON)",
            filetypes=[
                ("CSV / MISP JSON", "*.csv *.json"),
                ("CSV", "*.csv"),
                ("MISP JSON", "*.json"),
                ("Все файлы", "*.*"),
            ],
        )
        if not path:
            return
        p = Path(path)
        try:
            if p.suffix.lower() == ".json":
                entries = import_entries_from_misp(p)
            else:
                entries = import_entries_from_csv(p)
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror(__app_name__, f"Не удалось прочитать файл:\n{exc}")
            return
        if not entries:
            messagebox.showinfo(__app_name__, "Индикаторы не найдены")
            return
        target = messagebox.askyesnocancel(
            __app_name__,
            f"Найдено записей: {len(entries)}\n\n"
            "Да = denylist\nНет = allowlist\nОтмена = ничего",
        )
        if target is None:
            return
        name = "denylist.txt" if target else "allowlist.txt"
        comment = f"import:{p.name}"
        added = append_list_entries(name, entries, comment=comment)
        self._refresh_lists_mtime()
        messagebox.showinfo(
            __app_name__,
            f"В {name} добавлено: {added} (из {len(entries)}, дубликаты пропущены).\n"
            "Перезапустите анализ, чтобы теги обновились.",
        )
        self._set_status(f"Импорт в {name}: +{added}")

    def open_configs(self) -> None:
        root = ensure_user_lists()
        allow = list_file_path("allowlist.txt")
        deny = list_file_path("denylist.txt")
        ticket = root / "ticket.ini"
        self._refresh_lists_mtime()
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
                f"Папка конфигов:\n{root}\n\nallowlist:\n{allow}\ndenylist:\n{deny}\n"
                f"verdict.ini:\n{root / 'verdict.ini'}\n"
                f"ticket.ini:\n{ticket}",
            )
            return
        self._set_status(f"Конфиги: {root} (allowlist, denylist, verdict.ini, ticket.ini)")

    def show_about(self) -> None:
        allowlist = list_file_path("allowlist.txt")
        denylist = list_file_path("denylist.txt")
        root = app_dir()
        messagebox.showinfo(
            f"О программе — {__app_name__}",
            f"{__app_name__} v{__version__}\n"
            f"{__tagline__}\n\n"
            "Офлайн IOC-экстрактор для SOC.\n"
            "Сеть заблокирована (socket/DNS/SSL).\n\n"
            "С чего начать:\n"
            "  1. Открыть файл / папку или вставить текст слева\n"
            "  2. Смотреть IOC справа (типы включают/выключают группы)\n"
            "  3. «Скрыть шум» — убрать прокси URL, allowlist, частные IP\n"
            "  4. «Фокус» — только denylist или только IOC к разбору\n"
            "  5. Копировать / сохранить / Тикет\n\n"
            "Вердикт triage — только для писем (.eml / .msg);\n"
            "веса в verdict.ini рядом с exe.\n"
            "Шаблон тикета — ticket.ini рядом с exe.\n"
            "Лог ошибок — ioc_extractor_error.log рядом с exe.\n\n"
            "Горячие клавиши:\n"
            "  Ctrl+O — открыть файлы\n"
            "  Ctrl+Enter — извлечь из текста\n"
            "  Ctrl+F — поиск · клик по IOC — копировать\n"
            "  Тикет / Msg-ID — шаблоны в буфер\n\n"
            f"Папка:\n{root}\n\n"
            f"allowlist ({list_mtime_label('allowlist.txt')}):\n{allowlist}\n"
            f"denylist ({list_mtime_label('denylist.txt')}):\n{denylist}\n"
            f"ticket.ini:\n{root / 'ticket.ini'}\n"
            f"лог:\n{root / 'ioc_extractor_error.log'}",
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
