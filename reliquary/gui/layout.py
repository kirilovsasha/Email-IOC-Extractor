"""Main window layout construction — mixin for ExtractorApp."""

from __future__ import annotations

import customtkinter as ctk

from reliquary import __app_name__, __version__
from reliquary.gui.export_actions import EXPORT_CHOICES
from reliquary.gui.filters_actions import (
    FOCUS_FILTERS,
    HIDE_NOISE_FILTERS,
    TYPE_FILTER_TIPS,
)
from reliquary.gui.ioc_table import IocTable
from reliquary.gui.theme import (
    BTN_PRIMARY,
    BTN_SECONDARY,
    COLORS,
    ctk_font,
    ctk_mono,
)
from reliquary.gui.tooltips import FilterChip, HoverTip, vsep

_PLACEHOLDER = (
    "Откройте .eml / .msg или вставьте исходник письма (RFC822).\n\n"
    "Ctrl+O — письмо · Ctrl+H — тикет · Ctrl+E — экспорт · 1 — вердикт"
)

_COPY_FORMATS = ("type|value", "value", "csv", "defanged", "defanged|type")


class LayoutMixin:
    """Requires ExtractorApp state/vars; builds the main window chrome."""

    def _build(self) -> None:
        # —— Header ——
        header = ctk.CTkFrame(self, fg_color=COLORS["surface"], corner_radius=0)
        header.pack(fill="x")
        self._header = header

        self._header_name = ctk.CTkLabel(
            header,
            text=__app_name__,
            font=ctk_font("title", weight="bold"),
            text_color=COLORS["accent"],
        )
        self._header_name.pack(side="left", padx=(14, 10), pady=8)

        self._header_meta = ctk.CTkLabel(
            header,
            text=f"v{__version__}  ·  офлайн  ·  .eml / .msg / .mbox / .pst",
            font=ctk_font("caption"),
            text_color=COLORS["muted"],
        )
        self._header_meta.pack(side="left", pady=8)

        ctk.CTkButton(
            header,
            text="О программе",
            width=118,
            font=ctk_font("caption"),
            command=self.show_about,
            **BTN_SECONDARY,
        ).pack(side="right", padx=(6, 14), pady=4)
        ctk.CTkButton(
            header,
            text="Настройки",
            width=100,
            font=ctk_font("caption"),
            command=self.show_settings,
            **BTN_SECONDARY,
        ).pack(side="right", padx=(6, 0), pady=4)

        # —— Compact chrome: actions + collapsible filters (body gets the height) ——
        chrome = ctk.CTkFrame(
            self,
            fg_color=COLORS["surface"],
            corner_radius=10,
            border_width=1,
            border_color=COLORS["border"],
        )
        chrome.pack(fill="x", padx=12, pady=(4, 2))
        self._chrome = chrome

        # One short row. Titled pills used to stack into three lines and
        # ate the letter/verdict area.
        actions = ctk.CTkFrame(chrome, fg_color="transparent")
        actions.pack(fill="x", padx=6, pady=(4, 2))
        self._actions = actions

        btn_font = ctk_font("dense")
        menu_font = ctk_font("dense")
        primary = {**BTN_PRIMARY, "height": 26}
        secondary = {**BTN_SECONDARY, "height": 26}
        menu_kw = dict(
            height=26,
            font=menu_font,
            dropdown_font=menu_font,
            fg_color=COLORS["surface"],
            button_color=COLORS["border"],
            button_hover_color=COLORS["accent_dim"],
            dropdown_fg_color=COLORS["surface"],
            text_color=COLORS["text"],
            dropdown_text_color=COLORS["text"],
        )

        btn_open = ctk.CTkButton(
            actions, text="Открыть", width=76, font=btn_font, command=self.open_files, **primary
        )
        btn_open.pack(side="left", padx=(0, 4))
        HoverTip(btn_open, "Открыть .eml / .msg (Ctrl+O). Несколько файлов — пакетный вердикт")
        btn_folder = ctk.CTkButton(
            actions, text="Папка", width=60, font=btn_font, command=self.open_folder, **secondary
        )
        btn_folder.pack(side="left")
        HoverTip(btn_folder, "Рекурсивно разобрать все .eml / .msg / .mbox / .pst в папке")

        vsep(actions, height=22)

        btn_handoff = ctk.CTkButton(
            actions,
            text="В тикет",
            width=68,
            font=btn_font,
            command=self.copy_handoff,
            **secondary,
        )
        btn_handoff.pack(side="left", padx=(0, 4))
        HoverTip(btn_handoff, "Скопировать блок triage для тикета (вердикт + IOC; Msg-ID внутри текста)")
        ctk.CTkOptionMenu(
            actions,
            variable=self._copy_format,
            values=list(_COPY_FORMATS),
            width=108,
            **menu_kw,
        ).pack(side="left", padx=(0, 4))
        btn_copy = ctk.CTkButton(
            actions, text="IOC", width=46, font=btn_font, command=self.copy_iocs, **primary
        )
        btn_copy.pack(side="left")
        HoverTip(btn_copy, "Скопировать видимые IOC в выбранном формате")

        vsep(actions, height=22)

        ctk.CTkOptionMenu(
            actions,
            variable=self._export_choice,
            values=list(EXPORT_CHOICES),
            width=96,
            **menu_kw,
        ).pack(side="left", padx=(0, 4))
        btn_export = ctk.CTkButton(
            actions,
            text="Сохранить",
            width=84,
            font=btn_font,
            command=self._export_clicked,
            **primary,
        )
        btn_export.pack(side="left")
        HoverTip(
            btn_export,
            "JSON = полный отчёт с вердиктом · CSV = таблица IOC",
        )

        # Filter bar: search + primary «к разбору»; types/noise in expandable panel
        filt_bar = ctk.CTkFrame(chrome, fg_color="transparent")
        filt_bar.pack(fill="x", padx=6, pady=(0, 6))

        self.search_entry = ctk.CTkEntry(
            filt_bar,
            textvariable=self._search_var,
            placeholder_text="Поиск IOC, причин, вложений…  Ctrl+F",
            height=28,
            fg_color=COLORS["surface_alt"],
            border_color=COLORS["border"],
            corner_radius=8,
            font=ctk_font("dense"),
        )
        self._filt_bar = filt_bar
        self.search_entry.pack(side="left", fill="x", expand=True, padx=(0, 6))
        HoverTip(
            self.search_entry,
            "Поиск по IOC, причинам вердикта и именам вложений",
        )

        FilterChip(
            filt_bar,
            "к разбору",
            self.actionable_only,
            self._on_filter_change,
            tip=FOCUS_FILTERS[0][2],
            width=92,
            compact=True,
            primary=True,
        ).pack(side="left", padx=(0, 6))

        self._filters_open = ctk.BooleanVar(value=False)
        self._filt_toggle = ctk.CTkButton(
            filt_bar,
            text="Ещё ▸",
            width=78,
            height=28,
            command=self._toggle_filters_panel,
            fg_color=COLORS["surface_alt"],
            hover_color=COLORS["border"],
            border_width=1,
            border_color=COLORS["border"],
            text_color=COLORS["text"],
            corner_radius=8,
            font=ctk_font("dense"),
        )
        self._filt_toggle.pack(side="left", padx=(0, 4))
        HoverTip(
            self._filt_toggle,
            "Типы IOC и скрытие шума (SafeLinks / allowlist / локальные IP)",
        )

        ctk.CTkButton(
            filt_bar,
            text="Сброс",
            width=64,
            height=28,
            command=self._reset_filters,
            fg_color=COLORS["surface_alt"],
            hover_color=COLORS["border"],
            border_width=1,
            border_color=COLORS["border"],
            text_color=COLORS["text"],
            corner_radius=8,
            font=ctk_font("dense"),
        ).pack(side="left")

        # Child of the window, shown with place() — packing it into the
        # chrome pushed the letter and verdict panes down.
        self._filters_panel = ctk.CTkFrame(
            self,
            width=640,
            height=108,
            fg_color=COLORS["surface_alt"],
            corner_radius=8,
            border_width=1,
            border_color=COLORS["border"],
        )

        panel_inner = ctk.CTkFrame(self._filters_panel, fg_color="transparent")
        panel_inner.pack(fill="x", padx=10, pady=8)
        panel_inner.grid_columnconfigure(0, weight=1)
        panel_inner.grid_columnconfigure(1, weight=1)
        self._chips_wrap = panel_inner

        types_block = ctk.CTkFrame(panel_inner, fg_color="transparent")
        types_block.grid(row=0, column=0, sticky="nw", padx=(0, 12))
        ctk.CTkLabel(
            types_block,
            text="ТИПЫ",
            font=ctk_font("dense", weight="bold"),
            text_color=COLORS["muted"],
            anchor="w",
        ).pack(anchor="w", pady=(0, 4))
        types_row = ctk.CTkFrame(types_block, fg_color="transparent")
        types_row.pack(anchor="w")
        self._types_shell = types_block
        for name, var in self.cat_vars.items():
            FilterChip(
                types_row,
                name,
                var,
                self._on_filter_change,
                tip=TYPE_FILTER_TIPS.get(name, ""),
                width=62,
                compact=True,
            ).pack(side="left", padx=(0, 4))
        FilterChip(
            types_row,
            "все типы",
            self.full_ioc_types,
            self._on_filter_change,
            tip="Показать registry / mutex / command_line (обычно не нужны в email triage)",
            width=72,
            compact=True,
        ).pack(side="left", padx=(0, 4))

        noise_block = ctk.CTkFrame(panel_inner, fg_color="transparent")
        noise_block.grid(row=0, column=1, sticky="nw")
        ctk.CTkLabel(
            noise_block,
            text="СКРЫТЬ ШУМ",
            font=ctk_font("dense", weight="bold"),
            text_color=COLORS["muted"],
            anchor="w",
        ).pack(anchor="w", pady=(0, 4))
        noise_row = ctk.CTkFrame(noise_block, fg_color="transparent")
        noise_row.pack(anchor="w")
        self._hide_shell = noise_block
        for text, attr, tip in HIDE_NOISE_FILTERS:
            FilterChip(
                noise_row,
                text,
                getattr(self, attr),
                self._on_filter_change,
                tip=tip,
                compact=True,
            ).pack(side="left", padx=(0, 4))

        self._focus_shell = None
        self._filt_hint = ctk.CTkLabel(
            self._filters_panel,
            text="",
            font=ctk_font("dense"),
            text_color=COLORS["muted"],
            anchor="w",
        )
        self._filt_hint.pack(fill="x", padx=10, pady=(0, 6))
        self._update_filter_chrome()

        self.filter_legend = None

        self.focus_hint_row = ctk.CTkFrame(self, fg_color="transparent")
        self.focus_hint_row.pack(fill="x", padx=14, pady=(0, 0))
        self.focus_hint = ctk.CTkLabel(
            self.focus_hint_row,
            text="",
            font=ctk_font("body", weight="bold"),
            text_color=COLORS["info"],
            anchor="w",
        )
        self.focus_hint.pack(side="left", fill="x", expand=True)
        self.focus_clear_btn = ctk.CTkButton(
            self.focus_hint_row,
            text="Снять фокус",
            width=120,
            height=28,
            font=ctk_font("caption"),
            command=self._clear_file_focus,
            fg_color=COLORS["surface_alt"],
            hover_color=COLORS["border"],
            border_width=1,
            border_color=COLORS["border"],
            text_color=COLORS["text"],
        )
        self.focus_clear_btn.pack_forget()

        # —— Body: письмо слева · вердикт/доказательства справа ——
        # grid_propagate False: children (long subject, tab text) must not
        # resize the panes. Weights alone scale them with the window.
        body = ctk.CTkFrame(self, fg_color=COLORS["bg"])
        body.pack(fill="both", expand=True, padx=12, pady=(0, 10))
        body.grid_propagate(False)
        body.grid_columnconfigure(0, weight=2, minsize=200)
        body.grid_columnconfigure(1, weight=5, minsize=320)
        body.grid_rowconfigure(0, weight=1)
        self._body = body

        # Left: email source
        left = ctk.CTkFrame(body, fg_color=COLORS["surface"], corner_radius=8)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        left.grid_propagate(False)
        self._left = left

        left_head = ctk.CTkFrame(left, fg_color="transparent", height=28)
        left_head.pack(fill="x", padx=12, pady=(10, 4))
        left_head.pack_propagate(False)
        ctk.CTkLabel(
            left_head,
            text="Письмо",
            font=ctk_font("section", weight="bold"),
            text_color=COLORS["text"],
        ).pack(side="left")
        self.source_meta = ctk.CTkLabel(
            left_head,
            text="",
            font=ctk_font("caption"),
            text_color=COLORS["muted"],
            anchor="e",
        )
        self.source_meta.pack(side="right", fill="x", expand=True, padx=(8, 0))

        self.input_box = ctk.CTkTextbox(
            left,
            fg_color=COLORS["surface_alt"],
            text_color=COLORS["muted"],
            font=ctk_mono(),
            wrap="word",
            border_width=0,
        )
        self.input_box.pack(fill="both", expand=True, padx=12, pady=(0, 6))
        self.input_box.insert("1.0", _PLACEHOLDER)
        self._bind_placeholder()

        ctk.CTkButton(
            left,
            text="Разобрать  (Ctrl+Enter)",
            font=ctk_font("body"),
            command=self.analyze_text_area,
            **BTN_PRIMARY,
        ).pack(fill="x", padx=12, pady=(0, 10))

        # Right: results
        right = ctk.CTkFrame(body, fg_color=COLORS["surface"], corner_radius=8)
        right.grid(row=0, column=1, sticky="nsew")
        right.grid_propagate(False)
        self._right = right

        summary = ctk.CTkFrame(right, fg_color=COLORS["surface_alt"], corner_radius=6)
        summary.pack(fill="x", padx=10, pady=(10, 4))
        summary.grid_columnconfigure(0, weight=0)
        summary.grid_columnconfigure(1, weight=1)
        self._summary = summary

        self.verdict_badge = ctk.CTkLabel(
            summary,
            text="Вердикт —",
            font=ctk_font("hero", weight="bold"),
            text_color=COLORS["muted"],
            anchor="w",
        )
        self.verdict_badge.grid(row=0, column=0, padx=(12, 10), pady=8, sticky="w")

        self.ioc_summary_label = ctk.CTkLabel(
            summary,
            text="",
            font=ctk_font("body"),
            text_color=COLORS["accent"],
            anchor="e",
        )
        self.ioc_summary_label.grid(row=0, column=1, padx=(0, 12), pady=8, sticky="e")

        # Alias for older helpers; type breakdown lives in filter_hint, not beside badge.
        self.ioc_breakdown = self.ioc_summary_label

        self._job_row = ctk.CTkFrame(
            right, fg_color=COLORS["surface_alt"], corner_radius=6, height=36
        )
        self._job_row.pack_propagate(False)
        self.status = ctk.CTkLabel(
            self._job_row,
            text="",
            font=ctk_font("body"),
            text_color=COLORS["text"],
            anchor="w",
        )
        self.status.pack(side="left", fill="x", expand=True, padx=12, pady=6)
        self._progress = ctk.CTkProgressBar(
            self._job_row, width=120, height=10, progress_color=COLORS["accent"]
        )
        self._progress.set(0)
        self._stop_btn = ctk.CTkButton(
            self._job_row,
            text="Стоп",
            width=64,
            height=28,
            font=ctk_font("body"),
            command=self.cancel_batch,
            fg_color=COLORS["danger"],
            hover_color=COLORS["danger_hover"],
            text_color=COLORS["on_accent"],
            state="disabled",
        )
        self._retry_btn = ctk.CTkButton(
            self._job_row,
            text="Повтор ошибок",
            width=130,
            height=28,
            font=ctk_font("body"),
            command=self.retry_failed,
            fg_color=COLORS["surface_alt"],
            hover_color=COLORS["border"],
            border_width=1,
            border_color=COLORS["border"],
            text_color=COLORS["text"],
            state="disabled",
        )

        # Fixed slot: hint text may wrap, but it must not push the tabs.
        self._hint_slot = ctk.CTkFrame(right, fg_color="transparent", height=40)
        self._hint_slot.pack(fill="x", padx=12, pady=(0, 4))
        self._hint_slot.pack_propagate(False)
        self.filter_hint = ctk.CTkLabel(
            self._hint_slot,
            text=self._hint_default,
            font=ctk_font("body"),
            text_color=COLORS["muted"],
            anchor="w",
            justify="left",
            wraplength=640,
        )
        self.filter_hint.pack(fill="both", expand=True)

        # Context tabs
        self._tab_host = ctk.CTkFrame(right, fg_color=COLORS["surface"])
        self._tab_host.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        self._tab_key_by_label = {"Вердикт": "mail"}
        self._tab_label_by_key = {"mail": "Вердикт"}
        self._tab_seg_labels = ("Вердикт",)
        self._active_tab_key = "mail"
        self._tab_var = ctk.StringVar(value="Вердикт")

        self._tab_seg = ctk.CTkSegmentedButton(
            self._tab_host,
            values=["Вердикт"],
            variable=self._tab_var,
            command=self._on_tab_selected,
            fg_color=COLORS["surface_alt"],
            selected_color=COLORS["seg_selected"],
            selected_hover_color=COLORS["accent_dim"],
            unselected_color=COLORS["surface_alt"],
            unselected_hover_color=COLORS["border"],
            text_color=COLORS["text"],
            height=36,
            font=ctk_font("body"),
        )
        self._tab_seg.pack(fill="x", padx=2, pady=(2, 6))

        self._tab_body = ctk.CTkFrame(self._tab_host, fg_color=COLORS["surface"])
        self._tab_body.pack(fill="both", expand=True)

        self._tab_frames: dict[str, ctk.CTkFrame] = {}
        for key in ("mail", "att", "url", "ioc", "batch", "err"):
            frame = ctk.CTkFrame(self._tab_body, fg_color=COLORS["surface"])
            # All tabs share one grid cell; raise on switch (no pack_forget jump).
            frame.grid(row=0, column=0, sticky="nsew")
            self._tab_frames[key] = frame
        self._tab_body.grid_rowconfigure(0, weight=1)
        self._tab_body.grid_columnconfigure(0, weight=1)

        mail_bar = ctk.CTkFrame(self._tab_frames["mail"], fg_color="transparent")
        mail_bar.pack(fill="x", padx=2, pady=(2, 0))
        mail_btn_font = ctk_font("caption")
        ctk.CTkButton(
            mail_bar,
            text="From",
            width=70,
            font=mail_btn_font,
            command=self._copy_from,
            **BTN_SECONDARY,
        ).pack(side="left", padx=(0, 4))
        ctk.CTkButton(
            mail_bar,
            text="Auth",
            width=70,
            font=mail_btn_font,
            command=self._copy_auth,
            **BTN_SECONDARY,
        ).pack(side="left")
        self.mail_box = self._make_text(self._tab_frames["mail"])

        self.ioc_empty_label = ctk.CTkLabel(
            self._tab_frames["ioc"],
            text="",
            font=ctk_font("body"),
            text_color=COLORS["muted"],
            anchor="w",
            justify="left",
            wraplength=520,
        )
        self.ioc_empty_label.pack(fill="x", padx=4, pady=(0, 2))
        self.ioc_table = IocTable(
            self._tab_frames["ioc"],
            on_select=self._on_ioc_table_select,
            on_context=self._on_ioc_table_context,
            on_goto=self._goto_ioc_context,
            on_copy=self._on_ioc_table_copy,
            on_status=self._set_status,
            ui_scale=self._ui_scale,
        )
        self.ioc_table.set_density(self._ioc_density)
        self.ioc_table.pack(fill="both", expand=True)

        # Batch: filter + Treeview + optional diff text
        batch_frame = self._tab_frames["batch"]
        import tkinter.ttk as ttk

        self._batch_filter_var = ctk.StringVar(value="")
        self._batch_verdict_chip = ctk.StringVar(value="все")
        filter_row = ctk.CTkFrame(batch_frame, fg_color="transparent")
        filter_row.pack(fill="x", padx=4, pady=(4, 0))
        ctk.CTkLabel(filter_row, text="Фильтр:", font=ctk_font("dense")).pack(side="left")
        filt_entry = ctk.CTkEntry(filter_row, textvariable=self._batch_filter_var, width=160)
        filt_entry.pack(side="left", padx=6)
        filt_entry.bind("<KeyRelease>", lambda _e: self._on_batch_filter_change())
        for label, tip in (
            ("все", "Все письма пакета"),
            ("подозр.+", "suspicious + malicious"),
            ("вред.", "только malicious"),
        ):
            btn = ctk.CTkButton(
                filter_row,
                text=label,
                width=72 if label != "подозр.+" else 80,
                height=26,
                font=ctk_font("dense"),
                command=lambda v=label: self._set_batch_verdict_chip(v),
                fg_color=COLORS["surface_alt"],
                hover_color=COLORS["border"],
                border_width=1,
                border_color=COLORS["border"],
                text_color=COLORS["text"],
            )
            btn.pack(side="left", padx=2)
            HoverTip(btn, tip)
        ctk.CTkButton(
            filter_row,
            text="Экспорт среза",
            width=110,
            font=ctk_font("dense"),
            command=self._export_batch_filtered,
            **BTN_SECONDARY,
        ).pack(side="left", padx=(8, 0))
        self._batch_restore_btn = ctk.CTkButton(
            batch_frame,
            text="← К пакету",
            width=120,
            command=self._restore_batch_tree,
            **BTN_SECONDARY,
        )
        # packed only during campaign diff

        self._batch_tree_scroll = ctk.CTkFrame(batch_frame, fg_color="transparent")
        self._batch_tree_scroll.pack(fill="both", expand=True, padx=4, pady=4)
        cols = ("file", "verdict", "score", "reason", "peers")
        self.batch_tree = ttk.Treeview(
            self._batch_tree_scroll,
            columns=cols,
            show="headings",
            selectmode="browse",
            height=12,
        )
        self.batch_tree.heading("file", text="Файл", command=lambda: self._on_batch_heading_click("file"))
        self.batch_tree.heading(
            "verdict", text="Вердикт", command=lambda: self._on_batch_heading_click("verdict")
        )
        self.batch_tree.heading(
            "score", text="Балл", command=lambda: self._on_batch_heading_click("score")
        )
        self.batch_tree.heading("reason", text="Причина")
        self.batch_tree.heading("peers", text="Кампания")
        self.batch_tree.column("file", width=220, minwidth=100)
        self.batch_tree.column("verdict", width=100, minwidth=70)
        self.batch_tree.column("score", width=60, minwidth=40)
        self.batch_tree.column("reason", width=280, minwidth=80)
        self.batch_tree.column("peers", width=140, minwidth=60)
        ys = ttk.Scrollbar(
            self._batch_tree_scroll, orient="vertical", command=self.batch_tree.yview
        )
        self.batch_tree.configure(yscrollcommand=ys.set)
        self.batch_tree.pack(side="left", fill="both", expand=True)
        ys.pack(side="right", fill="y")
        self.batch_tree.bind("<<TreeviewSelect>>", self._on_batch_tree_select)
        self.batch_tree.bind("<Double-1>", self._on_batch_tree_diff)
        self._batch_sort_col = str(self._prefs.get("batch_sort_column") or "score")
        self._batch_sort_reverse = bool(self._prefs.get("batch_sort_reverse", True))
        self.batch_box = self._make_text(batch_frame)
        self.batch_box.pack_forget()  # shown only for campaign diff text

        self.url_box = self._make_text(self._tab_frames["url"])
        self.att_box = self._make_text(self._tab_frames["att"])
        self.err_box = self._make_text(self._tab_frames["err"])
        self._put(self.att_box, "Вложений нет — откройте письмо\n", "empty")
        self._put(self.url_box, "URL не найдены — откройте письмо\n", "empty")
        self._put(self.err_box, "Ошибок разбора нет\n", "empty")
        self._sync_result_tabs(None)
        self._show_tab_frame("mail")

        self.bind("<Control-o>", lambda _e: self.open_files())
        self.bind("<Control-O>", lambda _e: self.open_files())
        self.bind("<Control-Return>", lambda _e: self.analyze_text_area())
        self.bind("<Control-KP_Enter>", lambda _e: self.analyze_text_area())
        self.bind("<Escape>", self._close_filters_on_escape, add="+")
        self.bind_all("<Button-1>", self._filters_outside_click, add="+")

        # Resize only restacks the optional filter panel after the drag
        # settles. Column weights scale the panes; do not retune minsize here.
        self.bind("<Configure>", self._on_window_configure, add="+")

    def _place_summary(self, stacked: bool) -> None:
        # Summary is a fixed one-row composition (verdict + evidence count).
        # stacked flag kept for API compatibility with resize handler.
        _ = stacked
        if getattr(self, "_summary_stacked", None) is False and not stacked:
            return
        self._summary_stacked = False
        self.verdict_badge.grid(row=0, column=0, padx=(12, 10), pady=8, sticky="w")
        self.ioc_summary_label.grid(row=0, column=1, padx=(0, 12), pady=8, sticky="e")
        try:
            self.ioc_summary_label.configure(anchor="e")
        except Exception:  # noqa: BLE001
            pass

    def _try_hook_drop(self) -> None:
        try:
            import windnd  # type: ignore[import-untyped]

            windnd.hook_dropfiles(self, self._on_drop)
        except Exception:  # noqa: BLE001
            pass

