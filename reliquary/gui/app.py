"""IOC Extractor desktop GUI — extract IOCs from files and text (CustomTkinter 6)."""

from __future__ import annotations

import re
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
from reliquary.core.models import AnalysisResult
from reliquary.core.offline import enforce_offline
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
    "Форматы: .eml  .msg  .pdf  .html  .htm  .txt  .csv  .log\n"
    "Письма: IOC, URL, вложения, заголовки (From/SPF/Received…).\n"
    "Перетащите файлы в окно или откройте папку.\n\n"
    "Офлайн — без сетевых запросов."
)

_SUPPORTED_GLOBS = ("*.eml", "*.msg", "*.pdf", "*.html", "*.htm", "*.txt", "*.csv", "*.log")
_SUPPORTED_SUFFIXES = {g[1:].lower() for g in _SUPPORTED_GLOBS}

# Category → IOC type sets (multi-select filters)
_CATEGORY_TYPES: dict[str, set[str]] = {
    "Сеть": set(IOC_GROUPS[0][1]),
    "Хеши": set(IOC_GROUPS[1][1]),
    "Хост": set(IOC_GROUPS[2][1]),
    "Крипто": set(IOC_GROUPS[3][1]),
}

_EXPORT_CHOICES = (
    "CSV",
    "STIX",
    "JSON",
    "MISP",
    "OpenCTI",
    "YARA",
)

_SAFE_NAME_RE = re.compile(r'[<>:"/\\|?*\x00-\x1f]+')


class IocExtractorApp(ctk.CTk):
    def __init__(self) -> None:
        super().__init__()
        self.title(f"{__app_name__} — {__tagline__}")
        self.geometry("1280x820")
        self.minsize(1000, 700)
        self.configure(fg_color=COLORS["bg"])

        self.result: AnalysisResult | None = None
        self._placeholder_active = True

        # Types: all on by default (multi-select)
        self.cat_vars = {
            name: ctk.BooleanVar(value=True) for name in _CATEGORY_TYPES
        }
        # Noise: hide mail gateways + allowlist by default (less clutter)
        self.hide_rewriter = ctk.BooleanVar(value=True)
        self.hide_allowlisted = ctk.BooleanVar(value=True)
        self.hide_private = ctk.BooleanVar(value=False)
        self._export_choice = ctk.StringVar(value="CSV")

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
        ctk.CTkButton(
            toolbar, text="Копировать IOC", command=self.copy_iocs, width=130, **btn_kw
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
            command=self._on_export_menu,
            width=120,
            fg_color=COLORS["surface_alt"],
            button_color=COLORS["border"],
            button_hover_color=COLORS["accent_dim"],
            dropdown_fg_color=COLORS["surface"],
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

        # ---- Filters (clear Russian labels, two rows) ----
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
            text="Фильтр применяется к вкладке IOC, копированию и экспорту",
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

        for name in ("IOC", "URL", "Вложения", "Заголовки"):
            self.tabs.add(name)

        self.ioc_box = self._make_text(self.tabs.tab("IOC"))
        self.url_box = self._make_text(self.tabs.tab("URL"))
        self.att_box = self._make_text(self.tabs.tab("Вложения"))
        self.hdr_box = self._make_text(self.tabs.tab("Заголовки"))

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
        for itype, color in IOC_TYPE_COLORS.items():
            widget.tag_configure(f"type_{itype}", foreground=color, font=bold)
        for sev, color in SEVERITY_COLORS.items():
            widget.tag_configure(f"sev_{sev}", foreground=color, font=bold)

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
        self._refresh_views()

    def _selected_types(self) -> set[str] | None:
        """Union of enabled categories. None = all types (no type filter)."""
        enabled = [name for name, var in self.cat_vars.items() if var.get()]
        if not enabled:
            return set()  # nothing selected → empty list
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
                text="Фильтр применяется к вкладке IOC, копированию и экспорту"
            )
            return
        filtered = self._filtered_iocs()
        counts = Counter(i.ioc_type.value for i in filtered)
        total = len(filtered)
        full = len(self.result.iocs)
        if total == full:
            self.ioc_summary_label.configure(text=f"IOC: {total}")
            self.filter_hint.configure(
                text=f"Показаны все {full} индикаторов · фильтр → IOC / копирование / экспорт"
            )
        else:
            self.ioc_summary_label.configure(text=f"IOC: {total} из {full}")
            hidden = full - total
            self.filter_hint.configure(
                text=f"Показано {total} из {full} (скрыто {hidden}) · "
                "фильтр → IOC / копирование / экспорт"
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
        self._update_mail_card(self.result)

    # -------------------------------------------------------------- open
    def open_files(self) -> None:
        paths = filedialog.askopenfilenames(
            title=f"{__app_name__} — открыть файлы",
            filetypes=[
                ("Все поддерживаемые", "*.eml *.msg *.pdf *.html *.htm *.txt *.csv *.log"),
                ("Email", "*.eml *.msg"),
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
        folder = filedialog.askdirectory(title=f"{__app_name__} — папка")
        if not folder:
            return
        root = Path(folder)
        paths: list[str] = []
        for pattern in _SUPPORTED_GLOBS:
            paths.extend(str(p) for p in root.glob(pattern) if p.is_file())
        paths = sorted(set(paths))
        if not paths:
            messagebox.showinfo(
                __app_name__,
                "В папке нет поддерживаемых файлов "
                "(.eml .msg .pdf .html .htm .txt .csv .log).",
            )
            return
        self._analyze_paths(paths)

    def _on_drop(self, files) -> None:  # windnd callback
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
                for pattern in _SUPPORTED_GLOBS:
                    paths.extend(str(p) for p in path.glob(pattern) if p.is_file())
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
        names = ", ".join(Path(p).name for p in paths[:3])
        extra = f" (+{len(paths) - 3})" if len(paths) > 3 else ""
        self._set_status(f"Извлечение: {names}{extra}…")
        self.update_idletasks()
        threading.Thread(target=self._run_paths, args=(paths,), daemon=True).start()

    def _run_paths(self, paths: list[str]) -> None:
        try:
            results = [analyze_file(p) for p in paths]
            if len(results) == 1:
                result = results[0]
            else:
                result = merge_results(results, label=f"batch:{len(results)}")
            self.after(0, lambda: self._apply_result(result, preload_text=True))
        except Exception as exc:  # noqa: BLE001
            self.after(0, lambda: messagebox.showerror("Ошибка", str(exc)))
            self.after(0, lambda: self._set_status("Ошибка извлечения"))

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

    # -------------------------------------------------------- mail card
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
        if not filtered:
            self._put(self.ioc_box, "IOC не найдены\n", "empty")
        else:
            by_type: dict[str, list] = {}
            for ioc in filtered:
                by_type.setdefault(ioc.ioc_type.value, []).append(ioc)

            shown: set[str] = set()
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
                    self._put(self.ioc_box, f"  {t}  ", f"type_{t}")
                    self._put(self.ioc_box, f"{ioc.value}\n", "value")
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
                    self._put(self.ioc_box, f"  {t}  ", f"type_{t}")
                    self._put(self.ioc_box, f"{ioc.value}\n", "value")

        if result.errors:
            self._put(self.ioc_box, "\n▸ Ошибки\n", "section")
            for err in result.errors:
                self._put(self.ioc_box, f"  ! {err}\n", "danger")

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
            "  «Сохранить вложения» записывает файлы, у которых есть AttachmentInfo.data"
            f" (доступно: {with_data}).\n\n",
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

    # ---------------------------------------------------- copy / export
    def copy_iocs(self) -> None:
        if not self.result:
            messagebox.showinfo(__app_name__, "Сначала извлеките IOC")
            return
        values = [ioc.value for ioc in self._filtered_iocs()]
        if not values:
            messagebox.showinfo(__app_name__, "Нет IOC для копирования (проверьте фильтры)")
            return
        text = "\n".join(values)
        self.clipboard_clear()
        self.clipboard_append(text)
        self._set_status(f"Скопировано IOC: {len(values)}")

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
                "Нет вложений с данными (AttachmentInfo.data). Сохранены только хеши.",
            )

    def _on_export_menu(self, choice: str) -> None:
        self.export(choice)

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

    def show_about(self) -> None:
        allowlist = Path.cwd() / "allowlist.txt"
        messagebox.showinfo(
            f"О программе — {__app_name__}",
            f"{__app_name__} v{__version__}\n"
            f"{__tagline__}\n\n"
            "Офлайн IOC-экстрактор для SOC: письма, PDF, HTML, текст.\n"
            "Без сетевых запросов (enforce_offline).\n\n"
            "Экспорт: CSV, STIX, JSON, MISP, OpenCTI, YARA.\n\n"
            f"Пользовательский allowlist:\n{allowlist}",
        )


def run() -> None:
    enforce_offline()
    try:
        app = IocExtractorApp()
    except tk.TclError as exc:
        raise SystemExit(
            f"GUI недоступен ({exc}). Используйте CLI: python -m reliquary.cli <файл>"
        ) from exc
    app.mainloop()
