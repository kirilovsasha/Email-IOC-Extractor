"""Small GUI helpers: tooltips and muted labels."""

from __future__ import annotations

import tkinter as tk

import customtkinter as ctk

from reliquary.gui.theme import CHIP_H, CHIP_H_COMPACT, COLORS, FONT_UI, ctk_font, tk_ui


class HoverTip:
    """In-window tooltip overlay (avoids CTk DPI / Toplevel coordinate bugs)."""

    def __init__(self, widget: tk.Misc, text: str, *, delay_ms: int = 280) -> None:
        self.widget = widget
        self.text = text
        self._delay_ms = delay_ms
        self._tip: tk.Frame | None = None
        self._label: tk.Label | None = None
        self._after_id: str | None = None
        self._bind_tree(widget, is_root=True)

    def _bind_tree(self, widget: tk.Misc, *, is_root: bool = False) -> None:
        """Bind Enter/Leave/Motion on widget and CTk children (canvas/label)."""
        widget.bind("<Enter>", self._on_enter, add="+")
        widget.bind("<Motion>", self._on_motion, add="+")
        widget.bind("<Leave>", self._on_leave, add="+")
        widget.bind("<ButtonPress>", self._on_press, add="+")
        if is_root:
            widget.bind("<Destroy>", self._on_destroy, add="+")
        try:
            for child in widget.winfo_children():
                self._bind_tree(child, is_root=False)
        except Exception:  # noqa: BLE001
            pass

    def _cancel(self) -> None:
        if self._after_id is not None:
            try:
                self.widget.after_cancel(self._after_id)
            except Exception:  # noqa: BLE001
                pass
            self._after_id = None

    def _on_enter(self, _event: object = None) -> None:
        self._cancel()
        if not self.text:
            return
        self._after_id = self.widget.after(self._delay_ms, self._show)

    def _on_motion(self, _event: object = None) -> None:
        if self._tip is not None and self._tip.winfo_ismapped():
            self._place()

    def _on_leave(self, _event: object = None) -> None:
        self._cancel()
        self._after_id = self.widget.after(80, self._hide_if_left)

    def _on_press(self, _event: object = None) -> None:
        self._cancel()
        self._hide()

    def _on_destroy(self, _event: object = None) -> None:
        self._cancel()
        self._hide()

    def _pointer_over_widget(self) -> bool:
        try:
            x, y = self.widget.winfo_pointerxy()
            under = self.widget.winfo_containing(x, y)
        except Exception:  # noqa: BLE001
            return False
        cur: object | None = under
        while cur is not None:
            if cur is self.widget:
                return True
            cur = getattr(cur, "master", None)
        return False

    def _hide_if_left(self) -> None:
        self._after_id = None
        if self._pointer_over_widget():
            return
        self._hide()

    def _root(self) -> tk.Misc | None:
        try:
            return self.widget.winfo_toplevel()
        except Exception:  # noqa: BLE001
            return None

    def _ensure_tip(self, root: tk.Misc) -> None:
        if self._tip is not None:
            return
        tip = tk.Frame(
            root,
            background=COLORS["border"],
            highlightthickness=0,
            borderwidth=0,
        )
        lbl = tk.Label(
            tip,
            text=self.text,
            justify="left",
            background=COLORS["surface_alt"],
            foreground=COLORS["text"],
            font=tk_ui("tip"),
            padx=10,
            pady=6,
            wraplength=360,
            takefocus=0,
        )
        lbl.pack(padx=1, pady=1)
        self._tip = tip
        self._label = lbl

    def _place(self) -> None:
        tip = self._tip
        root = self._root()
        if tip is None or root is None:
            return
        try:
            tip.update_idletasks()
            tw = tip.winfo_reqwidth()
            th = tip.winfo_reqheight()
            # Relative coords cancel out CTk DPI scaling skew on absolutes
            x = self.widget.winfo_rootx() - root.winfo_rootx() + 8
            y = (
                self.widget.winfo_rooty()
                - root.winfo_rooty()
                + self.widget.winfo_height()
                + 6
            )
            rw = root.winfo_width()
            rh = root.winfo_height()
        except Exception:  # noqa: BLE001
            return
        if x + tw > rw - 8:
            x = max(8, rw - tw - 8)
        if y + th > rh - 8:
            y = max(
                8,
                self.widget.winfo_rooty() - root.winfo_rooty() - th - 6,
            )
        if x < 8:
            x = 8
        if y < 8:
            y = 8
        tip.place(x=int(x), y=int(y))
        tip.lift()

    def _show(self) -> None:
        self._after_id = None
        if not self.text or not self._pointer_over_widget():
            return
        root = self._root()
        if root is None:
            return
        try:
            if not self.widget.winfo_exists() or not self.widget.winfo_ismapped():
                return
        except Exception:  # noqa: BLE001
            return
        self._ensure_tip(root)
        assert self._tip is not None and self._label is not None
        self._label.configure(text=self.text)
        self._place()

    def _hide(self) -> None:
        if self._tip is not None:
            try:
                self._tip.place_forget()
            except Exception:  # noqa: BLE001
                pass


def muted_label(parent: object, text: str, *, size: int | None = None) -> ctk.CTkLabel:
    font = (
        ctk_font("label", weight="bold")
        if size is None
        else ctk.CTkFont(family=FONT_UI, size=size, weight="bold")
    )
    return ctk.CTkLabel(parent, text=text, font=font, text_color=COLORS["muted"])


def vsep(parent: object, *, height: int = 26) -> None:
    ctk.CTkFrame(parent, fg_color=COLORS["border"], width=1, height=height).pack(
        side="left", padx=8
    )


def toolbar_group(
    parent: object, title: str, *, compact: bool = False
) -> tuple[ctk.CTkFrame, ctk.CTkFrame]:
    """Pill-style action cluster. Returns (shell, body) — pack the shell."""
    shell = ctk.CTkFrame(
        parent,
        fg_color=COLORS["surface_alt"],
        corner_radius=8,
        border_width=1,
        border_color=COLORS["border"],
    )
    if compact:
        row = ctk.CTkFrame(shell, fg_color="transparent")
        row.pack(fill="x", padx=8, pady=5)
        ctk.CTkLabel(
            row,
            text=title.upper(),
            font=ctk_font("caption", weight="bold"),
            text_color=COLORS["muted"],
        ).pack(side="left", padx=(0, 8))
        body = ctk.CTkFrame(row, fg_color="transparent")
        body.pack(side="left", fill="x")
        return shell, body

    head = ctk.CTkFrame(shell, fg_color="transparent")
    head.pack(fill="x", padx=10, pady=(6, 0))
    ctk.CTkLabel(
        head,
        text=title.upper(),
        font=ctk_font("caption", weight="bold"),
        text_color=COLORS["muted"],
        anchor="w",
    ).pack(side="left")
    body = ctk.CTkFrame(shell, fg_color="transparent")
    body.pack(fill="x", padx=8, pady=(2, 8))
    return shell, body


def filter_section(
    parent: object, title: str, subtitle: str = "", *, compact: bool = False
) -> tuple[ctk.CTkFrame, ctk.CTkFrame]:
    """Filter group. Returns (shell, chips_row). compact = one inline strip."""
    if compact:
        shell = ctk.CTkFrame(parent, fg_color="transparent")
        ctk.CTkLabel(
            shell,
            text=title,
            font=ctk_font("label", weight="bold"),
            text_color=COLORS["muted"],
        ).pack(side="left", padx=(0, 6))
        chips = ctk.CTkFrame(shell, fg_color="transparent")
        chips.pack(side="left", fill="x")
        return shell, chips

    shell = ctk.CTkFrame(
        parent,
        fg_color=COLORS["surface_alt"],
        corner_radius=10,
        border_width=1,
        border_color=COLORS["border"],
    )
    head = ctk.CTkFrame(shell, fg_color="transparent")
    head.pack(fill="x", padx=12, pady=(8, 0))
    ctk.CTkLabel(
        head,
        text=title,
        font=ctk_font("body", weight="bold"),
        text_color=COLORS["text"],
        anchor="w",
    ).pack(side="left")
    if subtitle:
        ctk.CTkLabel(
            shell,
            text=subtitle,
            font=ctk_font("label"),
            text_color=COLORS["muted"],
            anchor="w",
        ).pack(fill="x", padx=12, pady=(0, 2))
    chips = ctk.CTkFrame(shell, fg_color="transparent")
    chips.pack(fill="x", padx=10, pady=(4, 10))
    return shell, chips


class FilterChip:
    """Toggle chip synced to a BooleanVar — clearer than a dense checkbox row."""

    def __init__(
        self,
        parent: object,
        text: str,
        variable: ctk.BooleanVar,
        command: object | None = None,
        *,
        tip: str = "",
        width: int = 0,
        compact: bool = False,
        primary: bool = False,
    ) -> None:
        self.var = variable
        self._command = command
        self._text = text
        self._primary = primary
        h = CHIP_H_COMPACT if compact else CHIP_H
        kwargs: dict = {
            "text": text,
            "height": h,
            "corner_radius": 10 if compact else 12,
            "border_width": 1,
            "font": ctk_font("dense" if compact else "caption", weight="bold" if primary else "normal"),
            "command": self._toggle,
        }
        if width:
            kwargs["width"] = width
        self.btn = ctk.CTkButton(parent, **kwargs)  # type: ignore[arg-type]
        self._sync()
        try:
            self.var.trace_add("write", lambda *_: self._sync())
        except Exception:  # noqa: BLE001
            pass
        try:
            root = parent.winfo_toplevel()  # type: ignore[attr-defined]
            chips = getattr(root, "_filter_chips", None)
            if chips is None:
                chips = []
                root._filter_chips = chips  # type: ignore[attr-defined]
            chips.append(self)
        except Exception:  # noqa: BLE001
            pass
        if tip:
            HoverTip(self.btn, tip)

    def pack(self, **kwargs: object) -> None:
        self.btn.pack(**kwargs)  # type: ignore[arg-type]

    def grid(self, **kwargs: object) -> None:
        self.btn.grid(**kwargs)  # type: ignore[arg-type]

    def _toggle(self) -> None:
        self.var.set(not bool(self.var.get()))
        if callable(self._command):
            self._command()

    def _sync(self) -> None:
        on = bool(self.var.get())
        if on:
            self.btn.configure(
                fg_color=COLORS["accent"] if self._primary else COLORS["accent_dim"],
                hover_color=COLORS["accent"],
                border_color=COLORS["accent"],
                text_color=COLORS["on_accent"],
            )
        else:
            self.btn.configure(
                fg_color=COLORS["surface"],
                hover_color=COLORS["border"],
                border_color=COLORS["border"],
                text_color=COLORS["muted"],
            )
