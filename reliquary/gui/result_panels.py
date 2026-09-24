"""Result tab fillers — mixin for ExtractorApp (keeps app.py thinner)."""

from __future__ import annotations

import tkinter as tk
from pathlib import Path

from reliquary.core.diff import diff_results, find_batch_peer
from reliquary.core.labels import confidence_label_ru, verdict_card_label, verdict_label_ru
from reliquary.core.models import AnalysisResult
from reliquary.core.pipeline import parser_failures
from reliquary.gui.theme import SEVERITY_LABELS_RU


def _sender_domain(sender: str) -> str:
    text = (sender or "").strip().lower()
    if "<" in text and ">" in text:
        text = text.split("<", 1)[1].split(">", 1)[0]
    if "@" not in text:
        return ""
    return text.rsplit("@", 1)[-1].strip(">").strip()


def campaign_banner_text(result: AnalysisResult) -> str:
    """One line when this mail shares a campaign_key with peers."""
    rows = list(result.file_rows or [])
    if len(rows) < 2:
        return ""
    current_path = result.source_path or ""
    mine = next((row for row in rows if row.path == current_path), None)
    if mine is None:
        current = Path(current_path).name
        named = [row for row in rows if Path(row.path).name == current]
        if len(named) == 1:
            mine = named[0]
    if mine is None or not mine.campaign_peers:
        return ""
    group = [row for row in rows if row.campaign_key and row.campaign_key == mine.campaign_key]
    if len(group) < 2:
        group = [mine]
    domains: list[str] = []
    for row in group:
        dom = _sender_domain(row.sender)
        if dom and dom not in domains:
            domains.append(dom)
    count = len(mine.campaign_peers) + 1
    if len(domains) >= 2:
        shown = ", ".join(domains[:4])
        return f"Кампания: {count} писем · From разошлись: {shown}"
    if domains:
        return f"Кампания: {count} писем · From: {domains[0]}"
    return f"Кампания: {count} писем"


class ResultPanelsMixin:
    """Requires ExtractorApp widgets: *_box, ioc_table, helpers _put/_clear_box/_tk."""

    def _fill_batch(self, result: AnalysisResult) -> None:
        tree = getattr(self, "batch_tree", None)
        rows = result.file_rows or []
        self._batch_all_rows = list(rows)
        if hasattr(self, "_batch_restore_btn"):
            try:
                self._batch_restore_btn.pack_forget()
            except tk.TclError:
                pass
        if tree is not None:
            for item in tree.get_children():
                tree.delete(item)
            self._batch_row_map = {}
            if hasattr(self, "_batch_tree_scroll"):
                self._batch_tree_scroll.pack(fill="both", expand=True, padx=4, pady=4)
            try:
                self.batch_box.pack_forget()
            except tk.TclError:
                pass
            if len(rows) < 2:
                tree.insert("", "end", values=("Нужно ≥2 файла для пакета", "", "", "", ""))
                return
            self._render_batch_rows(rows)
            return
        self._clear_box(self.batch_box)
        self._batch_row_tags.clear()
        if not hasattr(self, "_batch_diff_tags"):
            self._batch_diff_tags = {}
        self._batch_diff_tags.clear()
        if len(rows) < 2:
            self._put(self.batch_box, "Нужно ≥2 файла для таблицы пакета\n", "empty")
            return
        self._put(
            self.batch_box,
            "Пакет (текстовый режим)\n",
            "h1",
        )
        for row in rows:
            name = Path(row.path).name
            level = verdict_label_ru(row.verdict_level) if row.verdict_level else "—"
            score = f"{row.verdict_score}" if row.verdict_score is not None else "—"
            self._put(self.batch_box, f"{name}: {level} {score}\n", "body")

    def _render_batch_rows(self, rows: list) -> None:
        tree = getattr(self, "batch_tree", None)
        if tree is None:
            return
        for item in tree.get_children():
            tree.delete(item)
        self._batch_row_map = {}
        filt = ""
        if hasattr(self, "_batch_filter_var"):
            filt = str(self._batch_filter_var.get() or "").strip().lower()
        col = str(getattr(self, "_batch_sort_col", "score") or "score")
        reverse = bool(getattr(self, "_batch_sort_reverse", True))

        def _key(row):
            if col == "file":
                return Path(row.path).name.lower()
            if col == "verdict":
                return (row.verdict_level or "").lower()
            if col == "score":
                return row.verdict_score if row.verdict_score is not None else -1
            return Path(row.path).name.lower()

        ordered = sorted(rows, key=_key, reverse=reverse)
        chip = ""
        if hasattr(self, "_batch_verdict_chip"):
            chip = str(self._batch_verdict_chip.get() or "все").strip().lower()
        for row in ordered:
            name = Path(row.path).name
            level_raw = (row.verdict_level or "").lower()
            if chip in {"подозр.+", "подозр+", "suspicious+"}:
                if level_raw not in {"suspicious", "malicious"}:
                    continue
            elif chip in {"вред.", "вред", "malicious"}:
                if level_raw != "malicious":
                    continue
            level = verdict_label_ru(row.verdict_level) if row.verdict_level else "—"
            score = f"{row.verdict_score}" if row.verdict_score is not None else "—"
            reason = row.top_reason or "—"
            peers = ", ".join(row.campaign_peers[:3]) if row.campaign_peers else ""
            if filt and filt not in f"{name} {level} {score} {reason} {peers}".lower():
                continue
            iid = tree.insert("", "end", values=(name, level, score, reason, peers))
            self._batch_row_map[iid] = row
        self._highlight_open_batch_row(tree)

    def _highlight_open_batch_row(self, tree) -> None:
        """Mark the message already open on the verdict, without re-opening it."""
        current = getattr(getattr(self, "result", None), "source_path", "") or ""
        if not current:
            return
        selected = ""
        for iid, row in getattr(self, "_batch_row_map", {}).items():
            if row.path == current:
                selected = iid
                break
        if not selected:
            return
        self._batch_select_silent = True
        try:
            tree.selection_set(selected)
            tree.focus(selected)
            tree.see(selected)
        except tk.TclError:
            pass
        finally:
            self._batch_select_silent = False

    def _set_batch_verdict_chip(self, value: str) -> None:
        if hasattr(self, "_batch_verdict_chip"):
            self._batch_verdict_chip.set(value)
        self._on_batch_filter_change()

    def _visible_batch_results(self) -> list:
        """AnalysisResult subset matching current batch filter/chip (for export)."""
        rows = getattr(self, "_batch_all_rows", None) or []
        if not rows:
            return list(getattr(self, "_batch_results", None) or [])
        chip = ""
        if hasattr(self, "_batch_verdict_chip"):
            chip = str(self._batch_verdict_chip.get() or "все").strip().lower()
        filt = ""
        if hasattr(self, "_batch_filter_var"):
            filt = str(self._batch_filter_var.get() or "").strip().lower()
        wanted_paths: set[str] = set()
        for row in rows:
            level_raw = (row.verdict_level or "").lower()
            if chip in {"подозр.+", "подозр+", "suspicious+"}:
                if level_raw not in {"suspicious", "malicious"}:
                    continue
            elif chip in {"вред.", "вред", "malicious"}:
                if level_raw != "malicious":
                    continue
            name = Path(row.path).name
            level = verdict_label_ru(row.verdict_level) if row.verdict_level else "—"
            score = f"{row.verdict_score}" if row.verdict_score is not None else "—"
            reason = row.top_reason or "—"
            peers = ", ".join(row.campaign_peers[:3]) if row.campaign_peers else ""
            if filt and filt not in f"{name} {level} {score} {reason} {peers}".lower():
                continue
            wanted_paths.add(str(Path(row.path)))
        batch = list(getattr(self, "_batch_results", None) or [])
        if not wanted_paths:
            return []
        out = []
        for r in batch:
            src = str(Path(getattr(r, "source_path", None) or getattr(r, "path", "") or ""))
            if src in wanted_paths:
                out.append(r)
        return out

    def _export_batch_filtered(self) -> None:
        from tkinter import filedialog, messagebox

        from reliquary import __app_name__
        from reliquary.gui.export_actions import run_export

        subset = self._visible_batch_results()
        if not subset:
            messagebox.showinfo(__app_name__, "Нет писем в текущем срезе пакета")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("Batch CSV", "*.csv"), ("Campaign pack NDJSON", "*.ndjson")],
            initialfile="batch_filtered.csv",
            initialdir=getattr(self, "_last_export_dir", None) or None,
        )
        if not path:
            return
        kind = "campaign_pack" if path.lower().endswith(".ndjson") else "batch_csv"
        try:
            out = run_export(
                kind,
                subset[0],
                path,
                batch_results=subset,
            )
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror(__app_name__, f"Экспорт среза не удался:\n{exc}")
            return
        try:
            self._set_status(f"Срез пакета ({len(subset)}): {out}")
        except Exception:  # noqa: BLE001
            pass

    def _on_batch_heading_click(self, col: str) -> None:
        mapping = {
            "file": "file",
            "verdict": "verdict",
            "score": "score",
            "reason": "file",
            "peers": "file",
        }
        key = mapping.get(col, "score")
        if getattr(self, "_batch_sort_col", None) == key:
            self._batch_sort_reverse = not bool(getattr(self, "_batch_sort_reverse", True))
        else:
            self._batch_sort_col = key
            self._batch_sort_reverse = key == "score"
        rows = getattr(self, "_batch_all_rows", None) or []
        if rows:
            self._render_batch_rows(rows)

    def _on_batch_filter_change(self, *_args) -> None:
        rows = getattr(self, "_batch_all_rows", None) or []
        if rows:
            self._render_batch_rows(rows)

    def _restore_batch_tree(self) -> None:
        if hasattr(self, "_batch_restore_btn"):
            try:
                self._batch_restore_btn.pack_forget()
            except tk.TclError:
                pass
        if hasattr(self, "_batch_tree_scroll"):
            self._batch_tree_scroll.pack(fill="both", expand=True, padx=4, pady=4)
        try:
            self.batch_box.pack_forget()
        except tk.TclError:
            pass
        rows = getattr(self, "_batch_all_rows", None) or []
        if rows:
            self._render_batch_rows(rows)
        self._clear_box(self.batch_box)
        self._batch_row_tags.clear()
        if not hasattr(self, "_batch_diff_tags"):
            self._batch_diff_tags = {}
        self._batch_diff_tags.clear()
        if len(rows) < 2:
            self._put(self.batch_box, "Нужно ≥2 файла для таблицы пакета\n", "empty")
            return
        self._put(
            self.batch_box,
            f"▸ Сводка пакета  ({len(rows)})  — клик по имени → IOC; "
            f"«сравнить» → сравнение с peer кампании\n\n",
            "section",
        )
        self._put(
            self.batch_box,
            f"  {'Файл':<36} {'Вердикт':<14} {'Балл':>5}  Причина\n",
            "muted",
        )
        self._put(self.batch_box, "  " + "─" * 72 + "\n", "muted")
        widget = self._tk(self.batch_box)
        for idx, row in enumerate(rows):
            name = Path(row.path).name
            tag = f"batchrow_{idx}"
            self._batch_row_tags[tag] = row.path
            level_ru = verdict_label_ru(row.verdict_level) if row.verdict_level else "—"
            level_key = (row.verdict_level or "").lower()
            color = {
                "malicious": "danger",
                "suspicious": "warn",
                "unknown": "info",
                "benign": "ok",
            }.get(level_key, "muted")
            score = f"{row.verdict_score}" if row.verdict_score is not None else "—"
            reason = row.top_reason or "—"
            self._put(self.batch_box, f"  {name}  ", "ioc_click", tag, color)
            self._put(self.batch_box, f"{level_ru}  ", color)
            self._put(self.batch_box, f"{score}  ", "value")
            self._put(self.batch_box, f"{reason}\n", "meta")
            if row.campaign_peers:
                peers = ", ".join(row.campaign_peers[:4])
                more = len(row.campaign_peers) - 4
                self._put(
                    self.batch_box,
                    f"      Кампания  +{peers}"
                    + (f" …+{more}" if more > 0 else "")
                    + "\n",
                    "warn",
                )
                peer0 = row.campaign_peers[0]
                dtag = f"batchdiff_{idx}"
                self._batch_diff_tags[dtag] = (row.path, peer0)
                self._put(self.batch_box, "      ", "muted")
                self._put(
                    self.batch_box,
                    f"[сравнить с {peer0}]\n",
                    "info",
                    "diff_click",
                    dtag,
                )
            if row.subject:
                self._put(self.batch_box, f"      Тема  {row.subject[:120]}\n", "muted")
            if row.errors:
                self._put(
                    self.batch_box,
                    f"      Ошибки   {'; '.join(row.errors[:2])}\n",
                    "danger",
                )
        self._put(self.batch_box, "\n")
        if widget is not None:
            widget.tag_bind("ioc_click", "<Button-1>", self._on_batch_row_click)
            widget.tag_bind("diff_click", "<Button-1>", self._on_batch_diff_click)


    def _on_batch_tree_select(self, _event: object = None) -> None:
        if getattr(self, "_batch_select_silent", False):
            return
        tree = getattr(self, "batch_tree", None)
        if tree is None:
            return
        sel = tree.selection()
        if not sel:
            return
        row = getattr(self, "_batch_row_map", {}).get(sel[0])
        if row is None:
            return
        if hasattr(self, "_present_batch_message"):
            self._present_batch_message(row.path, preload_text=True)
            return
        self._focus_source_file = row.path
        self._update_focus_hint()
        self._refresh_views()
        self._set_status(f"Фокус: {Path(row.path).name}")

    def _on_batch_tree_motion(self, event: tk.Event) -> None:  # type: ignore[type-arg]
        tree = getattr(self, "batch_tree", None)
        tip = getattr(self, "_batch_reason_tip", None)
        if tree is None or tip is None:
            return
        iid = tree.identify_row(event.y)
        row = getattr(self, "_batch_row_map", {}).get(iid)
        if row is None:
            tip.configure(text="")
            return
        reason = row.top_reason or ""
        name = Path(row.path).name
        tip.configure(text=f"{name}: {reason}" if reason else name)

    def _on_batch_tree_diff(self, _event: object = None) -> None:
        tree = getattr(self, "batch_tree", None)
        if tree is None:
            return
        sel = tree.selection()
        if not sel:
            return
        row = getattr(self, "_batch_row_map", {}).get(sel[0])
        if row is None or not row.campaign_peers:
            self._set_status("Нет peer кампании для сравнения")
            return
        self._show_campaign_diff(row.path, row.campaign_peers[0])

    def _on_batch_diff_click(self, event: tk.Event) -> None:  # type: ignore[type-arg]
        widget = self._tk(self.batch_box)
        if widget is None:
            return
        index = widget.index(f"@{event.x},{event.y}")
        tags = getattr(self, "_batch_diff_tags", {})
        for tag in widget.tag_names(index):
            if tag.startswith("batchdiff_") and tag in tags:
                left_name, right_name = tags[tag]
                self._show_campaign_diff(left_name, right_name)
                return

    def _show_campaign_diff(self, left_name: str, right_name: str) -> None:
        batch = getattr(self, "_batch_results", []) or []
        left = find_batch_peer(batch, filename=left_name)
        right = find_batch_peer(batch, filename=right_name)
        if left is None or right is None:
            self._set_status(f"Сравнение: нет данных для {left_name} / {right_name}")
            return
        delta = diff_results(left, right)
        if hasattr(self, "_batch_tree_scroll"):
            try:
                self._batch_tree_scroll.pack_forget()
            except tk.TclError:
                pass
        try:
            self.batch_box.pack(fill="both", expand=True, padx=4, pady=4)
        except tk.TclError:
            pass
        self._clear_box(self.batch_box)
        self._put(self.batch_box, delta.to_text(), "value")
        self._put(
            self.batch_box,
            "\n  ← «К пакету» сверху или повторный разбор пакета\n",
            "muted",
        )
        if hasattr(self, "_batch_restore_btn"):
            try:
                self._batch_restore_btn.pack(fill="x", padx=4, pady=(0, 4), before=self.batch_box)
            except tk.TclError:
                try:
                    self._batch_restore_btn.pack(fill="x", padx=4, pady=2)
                except tk.TclError:
                    pass
        self._set_status(f"Сравнение: {left_name} ↔ {right_name}")

    def _on_batch_row_click(self, event: tk.Event) -> None:  # type: ignore[type-arg]
        widget = self._tk(self.batch_box)
        if widget is None:
            return
        index = widget.index(f"@{event.x},{event.y}")
        for tag in widget.tag_names(index):
            if tag.startswith("batchrow_") and tag in self._batch_row_tags:
                path = self._batch_row_tags[tag]
                if hasattr(self, "_present_batch_message"):
                    self._present_batch_message(path, preload_text=True)
                else:
                    self._focus_source_file = path
                    self._refresh_views()
                    self._set_status(f"Фокус: {Path(path).name}")
                return

    def _fill_iocs(self, result: AnalysisResult, filtered) -> None:
        if not filtered:
            self.ioc_table.clear()
            msg = "Доказательства не найдены"
            failures = parser_failures(result.errors)
            if failures:
                msg += f"  ·  {len(failures)} ошибок → вкладка «Ошибки»"
            self.ioc_empty_label.configure(text=msg)
            return

        note = ""
        failures = parser_failures(result.errors)
        if failures:
            note = f"{len(failures)} ошибок → вкладка «Ошибки»"
        self.ioc_empty_label.configure(text=note)
        show_file = bool(result.file_rows and len(result.file_rows) > 1) or (
            len(self._batch_results) > 1
        )
        self.ioc_table.set_iocs(list(filtered), show_file=show_file)

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
                if u.chain and len(u.chain) > 1:
                    self._put(self.url_box, "   цепочка  ", "label")
                    self._put(self.url_box, f"{' → '.join(u.chain)}\n", "info")
                self._put(self.url_box, "   →  ", "label")
                self._put(self.url_box, f"{u.unwrapped}\n", "value")
            self._put(self.url_box, "\n")

    def _fill_attachments(self, result: AnalysisResult) -> None:
        self._clear_box(self.att_box)
        if not result.attachments:
            self._put(self.att_box, "Вложений нет\n", "empty")
            return

        risky = sum(1 for a in result.attachments if a.risk_flags)
        self._put(
            self.att_box,
            f"▸ Вложения  ({len(result.attachments)}"
            + (f", флаги: {risky}" if risky else "")
            + ")\n\n",
            "section",
        )
        for a in result.attachments:
            name_tag = "danger" if a.risk_flags else "value"
            self._put(self.att_box, f"  {a.filename}\n", name_tag)
            self._put(
                self.att_box,
                f"      {a.size} B · {a.mime_guess}\n",
                "muted",
            )
            self._put(self.att_box, f"      SHA256  {a.sha256}\n", "value")
            if a.risk_flags:
                self._put(self.att_box, f"      флаги   {', '.join(a.risk_flags)}\n", "warn")
            if any("QR:" in n or "опциональный декодер" in n for n in (a.notes or [])):
                from reliquary.core.qr_scan import qr_decoder_available
                from reliquary.gui.i18n import t

                if not qr_decoder_available():
                    self._put(self.att_box, f"      {t('qr_lite')}\n", "warn")
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
                self._put(self.att_box, f"      вложенный тип  {a.nested_kind}\n", "meta")
            if a.archive_entries:
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
                        f"      QR      {'; '.join(qr_lines)}\n",
                        "danger",
                    )
            for note in a.notes:
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
                f"{verdict_card_label(v.level)} · score {v.score}",
                color_tag,
                "hero",
            )
            conf = getattr(v, "confidence", "") or ""
            if conf:
                conf_tag = {"high": "ok", "medium": "info", "low": "warn"}.get(conf, "info")
                self._put(
                    self.mail_box,
                    f" · уверенность {confidence_label_ru(conf)}\n",
                    conf_tag,
                    "hero",
                )
            else:
                self._put(self.mail_box, "\n", color_tag, "hero")
            self._put(self.mail_box, f"  {v.summary}\n", "value")
            note = getattr(v, "confidence_note", "") or ""
            if note:
                self._put(self.mail_box, f"  Почему: {note}\n", "muted")
            banner = campaign_banner_text(result)
            if banner:
                self._put(self.mail_box, f"  {banner}\n", "warn")
            self._put(self.mail_box, "\n", "value")
            if v.breakdown:
                self._put(self.mail_box, "  Разбор score\n", "label")
                for b in v.breakdown:
                    if b.points == 0:
                        continue
                    if b.points < 0:
                        self._put(self.mail_box, f"    {b.points:>4}  ", "ok")
                    else:
                        self._put(self.mail_box, f"    +{b.points:>3}  ", "warn")
                    self._put(self.mail_box, f"[{b.category}] ", "info")
                    self._put(self.mail_box, f"{b.reason}\n", "muted")
                self._put(self.mail_box, f"    ────  итого {v.score}/100\n\n", "value")
            elif v.reasons:
                self._put(self.mail_box, "  Причины\n", "label")
                for r in v.reasons[:8]:
                    self._put(self.mail_box, f"    • {r}\n", "muted")
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
                "  Кнопки сверху: From / Auth\n\n",
                "muted",
            )

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
                        f"      {verdict_card_label(r.verdict_level)}"
                        + (f" {r.verdict_score}" if r.verdict_score is not None else "")
                        + "\n",
                        "warn",
                    )
                self._put(self.mail_box, "\n")
            self._put(
                self.mail_box,
                "  Открыто письмо с верхней строки таблицы; детали по файлам — здесь же.\n\n",
                "muted",
            )

        if result.headers:
            alerts = [
                h for h in result.headers if h.severity.value in ("high", "critical", "medium")
            ]
            self._put(
                self.mail_box,
                f"▸ Находки  ({len(result.headers)}"
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
        elif not mid and not v and not result.headers:
            self._put(
                self.mail_box,
                "Нет данных вердикта.\n"
                "Откройте .eml / .msg — здесь появятся score, причины и разбор.\n",
                "empty",
            )
            return

        if result.raw_headers:
            self._put(self.mail_box, "▸ Сырые заголовки\n", "section")
            for name, value in result.raw_headers.items():
                self._put(self.mail_box, f"  {name}: ", "label")
                self._put(self.mail_box, f"{value}\n", "value")

        if mid and mid.from_header:
            self._put(self.mail_box, "\n", "muted")
            self._put(self.mail_box, "  [F] Копировать From   [R] Причины вердикта\n", "info")
            widget = self._tk(self.mail_box)
            if widget is not None:
                widget.bind("<Key-f>", lambda _e: self._copy_from(), add="+")
                widget.bind("<Key-F>", lambda _e: self._copy_from(), add="+")
                widget.bind("<Key-r>", lambda _e: self.copy_verdict_reasons(), add="+")
                widget.bind("<Key-R>", lambda _e: self.copy_verdict_reasons(), add="+")

    def _fill_errors(self, result: AnalysisResult) -> None:
        from reliquary.core.error_log import error_log_path

        self._clear_box(self.err_box)
        log_path = error_log_path()
        self._put(self.err_box, "▸ Журнал приложения\n", "section")
        self._put(self.err_box, f"  {log_path}\n", "meta")
        self._put(
            self.err_box,
            "  [L] Открыть каталог журнала   [R] Копировать причины вердикта\n\n",
            "info",
        )
        widget = self._tk(self.err_box)
        if widget is not None:
            widget.bind("<Key-l>", lambda _e: self._open_error_log_dir(), add="+")
            widget.bind("<Key-L>", lambda _e: self._open_error_log_dir(), add="+")
            widget.bind("<Key-r>", lambda _e: self.copy_verdict_reasons(), add="+")
            widget.bind("<Key-R>", lambda _e: self.copy_verdict_reasons(), add="+")

        notices: list[str] = []
        if not getattr(self, "_self_check_dismissed", True):
            notices.extend(list(getattr(self, "_self_check_warnings", []) or []))
        if not getattr(self, "_remarks_dismissed", True):
            notices.extend(list(getattr(self, "_extra_remarks", []) or []))
        if notices:
            self._put(self.err_box, "▸ Замечания\n", "section")
            for note in notices:
                self._put(self.err_box, f"  · {note}\n", "warn")
            self._put(self.err_box, "  [закрыть замечания]\n\n", "info", "dismiss_notes")
            widget = self._tk(self.err_box)
            if widget is not None:
                widget.tag_bind("dismiss_notes", "<Button-1>", self._dismiss_notices)
        failures = parser_failures(result.errors) if result is not None else []
        if not failures:
            if not notices:
                self._put(self.err_box, "Ошибок разбора нет\n", "ok")
            return
        self._put(
            self.err_box,
            f"▸ Ошибки разбора  ({len(failures)})\n",
            "section",
        )
        for err in failures:
            self._put(self.err_box, f"  ! {err}\n", "danger")

    def _dismiss_notices(self, _event: object = None) -> None:
        self._self_check_dismissed = True
        self._remarks_dismissed = True
        self._refresh_views(full=True)
        self._set_status("Замечания закрыты")

    def _open_error_log_dir(self) -> None:
        import os
        import subprocess
        import sys

        from reliquary.core.error_log import error_log_path

        path = error_log_path()
        folder = path.parent
        try:
            if sys.platform.startswith("win"):
                os.startfile(str(folder))  # type: ignore[attr-defined]
            elif sys.platform == "darwin":
                subprocess.Popen(["open", str(folder)])
            else:
                subprocess.Popen(["xdg-open", str(folder)])
            self._set_status(f"Каталог журнала: {folder}")
        except (OSError, AttributeError) as exc:
            self._set_status(f"Не удалось открыть каталог журнала: {exc}")
