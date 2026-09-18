"""Small GUI helpers: tooltips and muted labels."""

from __future__ import annotations

import tkinter as tk

import customtkinter as ctk

from reliquary.gui.theme import COLORS


class HoverTip:
    """Lightweight tooltip for first-run clarity on dense controls."""

    def __init__(self, widget: tk.Misc, text: str) -> None:
        self.widget = widget
        self.text = text
        self._tip: tk.Toplevel | None = None
        widget.bind("<Enter>", self._show, add="+")
        widget.bind("<Leave>", self._hide, add="+")

    def _show(self, _event: object = None) -> None:
        if self._tip is not None or not self.text:
            return
        x = self.widget.winfo_rootx() + 12
        y = self.widget.winfo_rooty() + self.widget.winfo_height() + 6
        tip = tk.Toplevel(self.widget)
        tip.wm_overrideredirect(True)
        tip.wm_geometry(f"+{x}+{y}")
        tip.attributes("-topmost", True)
        lbl = tk.Label(
            tip,
            text=self.text,
            justify="left",
            background=COLORS["surface_alt"],
            foreground=COLORS["text"],
            relief="solid",
            borderwidth=1,
            font=("Segoe UI", 9),
            padx=8,
            pady=5,
            wraplength=320,
        )
        lbl.pack()
        self._tip = tip

    def _hide(self, _event: object = None) -> None:
        if self._tip is not None:
            self._tip.destroy()
            self._tip = None


def muted_label(parent: object, text: str, *, size: int = 11) -> ctk.CTkLabel:
    return ctk.CTkLabel(
        parent,
        text=text,
        font=ctk.CTkFont(size=size, weight="bold"),
        text_color=COLORS["muted"],
    )


def vsep(parent: object, *, height: int = 22) -> None:
    ctk.CTkFrame(parent, fg_color=COLORS["border"], width=1, height=height).pack(
        side="left", padx=8
    )
