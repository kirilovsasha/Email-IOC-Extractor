"""IOC table — master/detail for SOC triage (scan list + inspector)."""

from __future__ import annotations

import tkinter as tk
from tkinter import font as tkfont
from tkinter import ttk
from typing import Callable

import customtkinter as ctk

from reliquary.core.defang import defang_value
from reliquary.core.models import Ioc
from reliquary.gui.theme import COLORS, IOC_TYPE_COLORS
from reliquary.gui.tooltips import HoverTip

_TYPE_LABEL: dict[str, str] = {
    "ipv4": "IPv4",
    "ipv6": "IPv6",
    "ip_port": "IP:port",
    "domain": "Domain",
    "url": "URL",
    "email": "Email",
    "md5": "MD5",
    "sha1": "SHA1",
    "sha256": "SHA256",
    "cve": "CVE",
    "filename": "File",
    "filepath": "Path",
    "unc": "UNC",
    "registry": "Reg",
    "mutex": "Mutex",
    "bitcoin": "BTC",
    "monero": "XMR",
    "messenger": "IM",
    "command_line": "CMD",
}

_SIGNAL_ORDER: tuple[tuple[str, str], ...] = (
    ("denylisted", "DENY"),
    ("unwrapped", "UNWRAP"),
    ("from_url", "URL"),
    ("attachment_hash", "ATT"),
    ("qr", "QR"),
    ("double_extension", "2EXT"),
    ("dangerous_extension", "EXEC"),
    ("private", "PRIV"),
    ("allowlisted", "ALLOW"),
    ("url_rewriter", "PROXY"),
    ("noise_candidate", "NOISE"),
)

# Fixed inspector height — prevents layout jump when selecting rows
_INSPECTOR_H = 118


def type_label(ioc_type: str) -> str:
    return _TYPE_LABEL.get(ioc_type, ioc_type.upper()[:8])


def signal_flags(tags: list[str]) -> str:
    tagset = set(tags)
    parts = [label for key, label in _SIGNAL_ORDER if key in tagset]
    return " · ".join(parts[:5])


def truncate_middle(text: str, max_len: int = 96) -> str:
    if len(text) <= max_len:
        return text
    keep = max_len - 1
    left = keep // 2
    right = keep - left
    return text[:left] + "…" + text[-right:]


def truncate_end(text: str, max_len: int) -> str:
    if len(text) <= max_len:
        return text
    return text[: max_len - 1] + "…"


class IocTable(ctk.CTkFrame):
    """Master list + detail inspector. Layout adapts on resize."""

    COLUMNS = ("type", "value", "flags", "file")

    def __init__(
        self,
        master: object,
        *,
        on_select: Callable[[Ioc], None] | None = None,
        on_context: Callable[[Ioc, int, int], None] | None = None,
        on_goto: Callable[[Ioc], None] | None = None,
        on_copy: Callable[[Ioc], None] | None = None,
        on_status: Callable[[str], None] | None = None,
        **kwargs: object,
    ) -> None:
        super().__init__(master, fg_color=COLORS["surface"], **kwargs)  # type: ignore[arg-type]
        self._on_select = on_select
        self._on_context = on_context
        self._on_goto = on_goto
        self._on_copy = on_copy
        self._on_status = on_status
        self._by_iid: dict[str, Ioc] = {}
        self._sort_col = "type"
        self._sort_asc = True
        self._show_file = True
        self._want_file = True
        self._resize_after: str | None = None
        self._last_width = 0
        self._meta_full = ""

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=0)

        self._build_tree()
        self._build_inspector()
        self.bind("<Configure>", self._on_resize, add="+")

    def _build_tree(self) -> None:
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        mono = (
            ("Cascadia Mono", 10)
            if self._font_exists("Cascadia Mono")
            else ("Consolas", 10)
        )
        style.configure(
            "Ioc.Treeview",
            background=COLORS["surface_alt"],
            foreground=COLORS["text"],
            fieldbackground=COLORS["surface_alt"],
            borderwidth=0,
            rowheight=28,
            font=mono,
        )
        style.configure(
            "Ioc.Treeview.Heading",
            background=COLORS["surface"],
            foreground=COLORS["muted"],
            relief="flat",
            font=("Segoe UI", 10, "bold"),
            padding=(8, 6),
        )
        style.map(
            "Ioc.Treeview",
            background=[("selected", COLORS["accent_dim"])],
            foreground=[("selected", COLORS["text"])],
        )

        wrap = ctk.CTkFrame(
            self,
            fg_color=COLORS["surface_alt"],
            corner_radius=6,
            border_width=1,
            border_color=COLORS["border"],
        )
        wrap.grid(row=0, column=0, sticky="nsew")
        wrap.grid_rowconfigure(0, weight=1)
        wrap.grid_columnconfigure(0, weight=1)
        self._tree_wrap = wrap

        self.tree = ttk.Treeview(
            wrap,
            columns=self.COLUMNS,
            show="headings",
            style="Ioc.Treeview",
            selectmode="browse",
        )
        self.tree.heading("type", text="Тип", command=lambda: self._sort_by("type"), anchor="w")
        self.tree.heading(
            "value", text="Значение", command=lambda: self._sort_by("value"), anchor="w"
        )
        self.tree.heading(
            "flags", text="Сигналы", command=lambda: self._sort_by("flags"), anchor="w"
        )
        self.tree.heading("file", text="Файл", command=lambda: self._sort_by("file"), anchor="w")

        self.tree.column("type", width=78, minwidth=56, stretch=False, anchor="w")
        self.tree.column("value", width=420, minwidth=120, stretch=True, anchor="w")
        self.tree.column("flags", width=140, minwidth=0, stretch=False, anchor="w")
        self.tree.column("file", width=100, minwidth=0, stretch=False, anchor="w")

        vsb = ttk.Scrollbar(wrap, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.grid(row=0, column=0, sticky="nsew", padx=(1, 0), pady=1)
        vsb.grid(row=0, column=1, sticky="ns", pady=1)

        self.tree.bind("<<TreeviewSelect>>", self._on_tree_select)
        self.tree.bind("<Double-1>", self._on_double)
        self.tree.bind("<Button-3>", self._on_right_click)
        self.tree.bind("<Control-c>", self._on_ctrl_c)
        self.tree.bind("<Return>", self._on_ctrl_c)

        self.tree.tag_configure("odd", background=COLORS.get("row_alt", "#151c24"))
        self.tree.tag_configure("even", background=COLORS["surface_alt"])
        for ioc_type, color in IOC_TYPE_COLORS.items():
            self.tree.tag_configure(f"t_{ioc_type}", foreground=color)

    def _build_inspector(self) -> None:
        # Fixed height + propagate off → selecting rows never resizes the table
        panel = ctk.CTkFrame(
            self,
            fg_color=COLORS["surface_alt"],
            corner_radius=6,
            border_width=1,
            border_color=COLORS["border"],
            height=_INSPECTOR_H,
        )
        panel.grid(row=1, column=0, sticky="ew", pady=(8, 0))
        panel.grid_propagate(False)
        panel.grid_columnconfigure(0, weight=1)
        panel.grid_rowconfigure(1, weight=1)
        self._inspector = panel

        top = ctk.CTkFrame(panel, fg_color="transparent")
        top.grid(row=0, column=0, sticky="ew", padx=10, pady=(8, 0))
        top.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(
            top,
            text="ДЕТАЛИ",
            font=ctk.CTkFont(size=10, weight="bold"),
            text_color=COLORS["muted"],
        ).grid(row=0, column=0, sticky="w", padx=(2, 10))

        self._detail_type = ctk.CTkLabel(
            top,
            text="—",
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            text_color=COLORS["accent"],
            anchor="w",
        )
        self._detail_type.grid(row=0, column=1, sticky="ew")

        actions = ctk.CTkFrame(top, fg_color="transparent")
        actions.grid(row=0, column=2, sticky="e", padx=(8, 0))

        self._btn_copy = ctk.CTkButton(
            actions,
            text="Копировать",
            width=96,
            height=26,
            command=self._copy_selected,
            fg_color=COLORS["accent"],
            hover_color=COLORS["accent_dim"],
            state="disabled",
        )
        self._btn_copy.pack(side="left", padx=(0, 4))
        HoverTip(self._btn_copy, "Скопировать значение (Ctrl+C / Enter)")

        self._btn_goto = ctk.CTkButton(
            actions,
            text="К фрагменту",
            width=100,
            height=26,
            command=self._goto_selected,
            fg_color=COLORS["surface"],
            hover_color=COLORS["border"],
            border_width=1,
            border_color=COLORS["border"],
            state="disabled",
        )
        self._btn_goto.pack(side="left", padx=(0, 4))
        HoverTip(self._btn_goto, "Показать фрагмент в источнике (двойной клик)")

        self._btn_defang = ctk.CTkButton(
            actions,
            text="Defang",
            width=68,
            height=26,
            command=self._copy_defanged,
            fg_color=COLORS["surface"],
            hover_color=COLORS["border"],
            border_width=1,
            border_color=COLORS["border"],
            state="disabled",
        )
        self._btn_defang.pack(side="left")
        HoverTip(self._btn_defang, "Скопировать defanged значение")

        mono = "Cascadia Mono" if self._font_exists("Cascadia Mono") else "Consolas"
        self._detail_value = ctk.CTkTextbox(
            panel,
            height=44,
            font=ctk.CTkFont(family=mono, size=12),
            text_color=COLORS["value"],
            fg_color=COLORS["surface"],
            border_width=0,
            corner_radius=4,
            activate_scrollbars=True,
            wrap="char",
        )
        self._detail_value.grid(row=1, column=0, sticky="nsew", padx=10, pady=(6, 0))
        self._detail_value.configure(state="disabled")

        self._detail_meta = ctk.CTkLabel(
            panel,
            text="",
            font=ctk.CTkFont(size=11),
            text_color=COLORS["muted"],
            anchor="w",
            justify="left",
        )
        self._detail_meta.grid(row=2, column=0, sticky="ew", padx=12, pady=(4, 8))

        self._inspector_empty()

    def _set_value_text(self, text: str, *, muted: bool = False) -> None:
        color = COLORS["muted"] if muted else COLORS["value"]
        self._detail_value.configure(state="normal", text_color=color)
        self._detail_value.delete("1.0", "end")
        self._detail_value.insert("1.0", text)
        self._detail_value.configure(state="disabled")

    def _on_resize(self, event: tk.Event) -> None:  # type: ignore[type-arg]
        if event.widget is not self:
            return
        w = int(event.width)
        if abs(w - self._last_width) < 8:
            return
        self._last_width = w
        if self._resize_after:
            try:
                self.after_cancel(self._resize_after)
            except Exception:  # noqa: BLE001
                pass
        self._resize_after = self.after(60, self._apply_responsive_layout)

    def _apply_responsive_layout(self) -> None:
        self._resize_after = None
        w = max(self.winfo_width(), 200)

        # Collapse secondary columns on narrow panes
        show_flags = w >= 520
        show_file = self._want_file and w >= 640
        self._show_file = show_file
        try:
            if show_flags:
                self.tree.column("flags", width=140, minwidth=70, stretch=False)
            else:
                self.tree.column("flags", width=0, minwidth=0, stretch=False)
            if show_file:
                self.tree.column("file", width=110, minwidth=60, stretch=False)
            else:
                self.tree.column("file", width=0, minwidth=0, stretch=False)
            self.tree.column("value", stretch=True)
        except Exception:  # noqa: BLE001
            pass

        # Keep meta to one visual line regardless of pane width
        meta_budget = max(40, (w - 40) // 7)
        tip = getattr(self, "_meta_full", "") or ""
        if tip:
            self._detail_meta.configure(text=truncate_end(tip, meta_budget))

    @staticmethod
    def _font_exists(name: str) -> bool:
        try:
            return name in tkfont.families()
        except Exception:  # noqa: BLE001
            return False

    def _inspector_empty(self) -> None:
        self._meta_full = ""
        self._detail_type.configure(text="—", text_color=COLORS["muted"])
        self._set_value_text("Выберите IOC в списке", muted=True)
        self._detail_meta.configure(
            text="Клик — выбрать · Enter/Ctrl+C — копировать · 2×клик — к фрагменту · ПКМ — меню"
        )
        for btn in (self._btn_copy, self._btn_goto, self._btn_defang):
            btn.configure(state="disabled")

    def _update_inspector(self, ioc: Ioc | None) -> None:
        if ioc is None:
            self._inspector_empty()
            return
        t = ioc.ioc_type.value
        color = IOC_TYPE_COLORS.get(t, COLORS["text"])
        self._detail_type.configure(text=f"{type_label(t)}  ·  {t}", text_color=color)
        self._set_value_text(ioc.value)

        tags = [x for x in ioc.tags if not x.startswith("file:")]
        file_tag = next((x[5:] for x in ioc.tags if x.startswith("file:")), "")
        src = (ioc.source or "").strip()
        ctx = (ioc.context or "").strip().replace("\n", " ")
        parts: list[str] = []
        if src:
            parts.append(f"источник: {src}")
        if file_tag:
            parts.append(f"файл: {file_tag}")
        if tags:
            parts.append("теги: " + ", ".join(tags[:12]))
        if ctx:
            parts.append(f"контекст: {ctx[:200]}")
        full = "  ·  ".join(parts) if parts else ""
        self._meta_full = full
        budget = max(40, (max(self.winfo_width(), 200) - 40) // 7)
        self._detail_meta.configure(text=truncate_end(full, budget) if full else "")

        for btn in (self._btn_copy, self._btn_goto, self._btn_defang):
            btn.configure(state="normal")

    def clear(self) -> None:
        self.tree.delete(*self.tree.get_children())
        self._by_iid.clear()
        self._update_inspector(None)

    def set_iocs(self, iocs: list[Ioc], *, show_file: bool | None = None) -> None:
        if show_file is not None:
            self._want_file = show_file
        self.clear()
        self._apply_responsive_layout()
        for idx, ioc in enumerate(iocs):
            file_tag = next((t[5:] for t in ioc.tags if t.startswith("file:")), "")
            iid = f"ioc{idx}"
            self._by_iid[iid] = ioc
            zebra = "odd" if idx % 2 else "even"
            type_tag = f"t_{ioc.ioc_type.value}"
            self.tree.insert(
                "",
                "end",
                iid=iid,
                values=(
                    type_label(ioc.ioc_type.value),
                    truncate_middle(ioc.value, 110),
                    signal_flags(ioc.tags),
                    file_tag if self._want_file else "",
                ),
                tags=(zebra, type_tag),
            )

    def selected_ioc(self) -> Ioc | None:
        sel = self.tree.selection()
        if not sel:
            return None
        return self._by_iid.get(sel[0])

    def _sort_by(self, col: str) -> None:
        if self._sort_col == col:
            self._sort_asc = not self._sort_asc
        else:
            self._sort_col = col
            self._sort_asc = True
        items = [(self.tree.set(k, col), k) for k in self.tree.get_children("")]
        items.sort(key=lambda t: t[0].lower(), reverse=not self._sort_asc)
        for i, (_, k) in enumerate(items):
            self.tree.move(k, "", i)
            tags = [t for t in self.tree.item(k, "tags") if t not in ("odd", "even")]
            tags.insert(0, "odd" if i % 2 else "even")
            self.tree.item(k, tags=tags)

    def _on_tree_select(self, _event: object = None) -> None:
        ioc = self.selected_ioc()
        self._update_inspector(ioc)
        if ioc and self._on_select:
            self._on_select(ioc)

    def _on_double(self, _event: object = None) -> None:
        ioc = self.selected_ioc()
        if ioc and self._on_goto:
            self._on_goto(ioc)

    def _on_right_click(self, event: tk.Event) -> None:  # type: ignore[type-arg]
        row = self.tree.identify_row(event.y)
        if row:
            self.tree.selection_set(row)
            ioc = self._by_iid.get(row)
            self._update_inspector(ioc)
            if ioc and self._on_context:
                self._on_context(ioc, event.x_root, event.y_root)

    def _on_ctrl_c(self, _event: object = None) -> str:
        self._copy_selected()
        return "break"

    def _copy_selected(self) -> None:
        ioc = self.selected_ioc()
        if not ioc:
            return
        if self._on_copy:
            self._on_copy(ioc)

    def _copy_defanged(self) -> None:
        ioc = self.selected_ioc()
        if not ioc:
            return
        text = defang_value(ioc.value)
        try:
            root = self.winfo_toplevel()
            root.clipboard_clear()
            root.clipboard_append(text)
        except Exception:  # noqa: BLE001
            return
        if self._on_status:
            self._on_status(f"Defanged: {text[:80]}")

    def _goto_selected(self) -> None:
        ioc = self.selected_ioc()
        if ioc and self._on_goto:
            self._on_goto(ioc)
