"""Virtualized-ish IOC table (ttk.Treeview) for dense SOC triage."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Callable

import customtkinter as ctk

from reliquary.core.models import Ioc
from reliquary.gui.theme import COLORS, IOC_TYPE_COLORS


class IocTable(ctk.CTkFrame):
    """Sortable table: type | value | tags | file. Click copies value."""

    COLUMNS = ("type", "value", "tags", "file")

    def __init__(
        self,
        master: object,
        *,
        on_select: Callable[[Ioc], None] | None = None,
        on_context: Callable[[Ioc, int, int], None] | None = None,
        **kwargs: object,
    ) -> None:
        super().__init__(master, fg_color=COLORS["surface"], **kwargs)  # type: ignore[arg-type]
        self._on_select = on_select
        self._on_context = on_context
        self._by_iid: dict[str, Ioc] = {}
        self._sort_col = "type"
        self._sort_asc = True

        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure(
            "Ioc.Treeview",
            background=COLORS["surface_alt"],
            foreground=COLORS["text"],
            fieldbackground=COLORS["surface_alt"],
            borderwidth=0,
            rowheight=24,
            font=("Consolas", 10),
        )
        style.configure(
            "Ioc.Treeview.Heading",
            background=COLORS["surface"],
            foreground=COLORS["muted"],
            relief="flat",
            font=("Segoe UI", 10, "bold"),
        )
        style.map(
            "Ioc.Treeview",
            background=[("selected", COLORS["accent_dim"])],
            foreground=[("selected", COLORS["text"])],
        )

        wrap = ctk.CTkFrame(self, fg_color=COLORS["surface_alt"], corner_radius=4)
        wrap.pack(fill="both", expand=True)

        self.tree = ttk.Treeview(
            wrap,
            columns=self.COLUMNS,
            show="headings",
            style="Ioc.Treeview",
            selectmode="browse",
        )
        self.tree.heading("type", text="Тип", command=lambda: self._sort_by("type"))
        self.tree.heading("value", text="Значение", command=lambda: self._sort_by("value"))
        self.tree.heading("tags", text="Теги", command=lambda: self._sort_by("tags"))
        self.tree.heading("file", text="Файл", command=lambda: self._sort_by("file"))
        self.tree.column("type", width=100, minwidth=70, stretch=False)
        self.tree.column("value", width=420, minwidth=160, stretch=True)
        self.tree.column("tags", width=160, minwidth=80, stretch=False)
        self.tree.column("file", width=140, minwidth=60, stretch=False)

        vsb = ttk.Scrollbar(wrap, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(wrap, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        wrap.grid_rowconfigure(0, weight=1)
        wrap.grid_columnconfigure(0, weight=1)

        self.tree.bind("<<TreeviewSelect>>", self._on_tree_select)
        self.tree.bind("<Double-1>", self._on_tree_select)
        self.tree.bind("<Button-3>", self._on_right_click)
        self.tree.bind("<Control-c>", self._on_ctrl_c)

        for ioc_type, color in IOC_TYPE_COLORS.items():
            self.tree.tag_configure(ioc_type, foreground=color)

    def clear(self) -> None:
        self.tree.delete(*self.tree.get_children())
        self._by_iid.clear()

    def set_iocs(self, iocs: list[Ioc]) -> None:
        self.clear()
        for idx, ioc in enumerate(iocs):
            tags = [t for t in ioc.tags if not t.startswith("file:")]
            file_tag = next((t[5:] for t in ioc.tags if t.startswith("file:")), "")
            iid = f"ioc{idx}"
            self._by_iid[iid] = ioc
            self.tree.insert(
                "",
                "end",
                iid=iid,
                values=(ioc.ioc_type.value, ioc.value, ", ".join(tags), file_tag),
                tags=(ioc.ioc_type.value,),
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

    def _on_tree_select(self, _event: object = None) -> None:
        ioc = self.selected_ioc()
        if ioc and self._on_select:
            self._on_select(ioc)

    def _on_right_click(self, event: tk.Event) -> None:  # type: ignore[type-arg]
        row = self.tree.identify_row(event.y)
        if row:
            self.tree.selection_set(row)
            ioc = self._by_iid.get(row)
            if ioc and self._on_context:
                self._on_context(ioc, event.x_root, event.y_root)

    def _on_ctrl_c(self, _event: object = None) -> str:
        ioc = self.selected_ioc()
        if ioc and self._on_select:
            self._on_select(ioc)
        return "break"
