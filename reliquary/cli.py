"""CLI — email triage with verdict; batch folder, filters, JSON/CSV/handoff export."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

from reliquary import __app_name__, __version__
from reliquary.core.analysis_options import AnalysisOptions
from reliquary.core.batch import default_max_workers, run_batch
from reliquary.core.export_hook import run_post_export_hook
from reliquary.core.exporters import export_batch_csv, export_csv, export_report_json
from reliquary.core.filter_state import FilterState
from reliquary.core.formats import collect_supported, formats_help_line, is_supported
from reliquary.core.handoff import export_handoff
from reliquary.core.offline import enforce_offline
from reliquary.core.org_profile import load_org_profile
from reliquary.core.pipeline import analyze_file, analyze_text
from reliquary.core.prefs import load_prefs


def _print_verdict(result, stream=None) -> None:
    if stream is None:
        stream = sys.stderr
    v = result.verdict
    if not v:
        print(f"\n[{__app_name__}] Вердикт: нет (не письмо или ошибка разбора)", file=stream)
        for err in result.errors[:5]:
            print(f"  ! {err}", file=stream)
        return
    print(
        f"\n[{__app_name__}] VERDICT {v.level.value.upper()}  score={v.score}/100",
        file=stream,
    )
    print(f"  {v.summary}", file=stream)
    for reason in v.reasons[:10]:
        print(f"  • {reason}", file=stream)


def _print_ioc_summary(result, stream=None) -> None:
    if stream is None:
        stream = sys.stderr
    counts = Counter(i.ioc_type.value for i in result.iocs)
    total = len(result.iocs)
    print(f"\n[{__app_name__}] IOC (доказательства): {total}", file=stream)
    if counts:
        parts = ", ".join(f"{k}={v}" for k, v in sorted(counts.items()))
        print(f"  по типам: {parts}", file=stream)
    for ioc in result.iocs[:20]:
        print(f"  - {ioc.ioc_type.value}: {ioc.value}", file=stream)
    if total > 20:
        print(f"  … и ещё {total - 20}", file=stream)


def _resolve_inputs(args: argparse.Namespace) -> list[str]:
    paths: list[str] = []
    if args.text:
        return []
    if args.path:
        p = Path(args.path)
        if p.is_dir():
            paths.extend(collect_supported(p, recursive=not args.no_recursive))
        elif p.is_file():
            paths.append(str(p))
        else:
            raise FileNotFoundError(f"Не найден путь: {p}")
    for extra in args.files or []:
        ep = Path(extra)
        if ep.is_dir():
            paths.extend(collect_supported(ep, recursive=not args.no_recursive))
        elif ep.is_file():
            paths.append(str(ep))
    seen: set[str] = set()
    out: list[str] = []
    for p in paths:
        key = str(Path(p).resolve()) if Path(p).exists() else p
        if key not in seen:
            seen.add(key)
            out.append(p)
    return [p for p in out if is_supported(p)]


def _configure_stdio() -> None:
    """Avoid UnicodeEncodeError on Windows consoles (cp1251/cp1252) in CI/cmd."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
        except Exception:  # noqa: BLE001
            pass


def main(argv: list[str] | None = None) -> int:
    _configure_stdio()
    enforce_offline()
    prefs = load_prefs()
    default_workers = int(prefs.get("max_workers") or 0) or default_max_workers()
    # Same defaults as GUI (prefs); override with --no-actionable / --no-hide-*
    def_hide_rewriter = bool(prefs.get("hide_rewriter", True))
    def_hide_allow = bool(prefs.get("hide_allowlisted", True))
    def_hide_private = bool(prefs.get("hide_private", True))
    def_actionable = bool(prefs.get("actionable_only", True))
    def_allowlist = str(prefs.get("allowlist_path") or "") or None
    def_verdict = str(prefs.get("verdict_path") or "") or None
    def_handoff_tmpl = str(prefs.get("handoff_template_path") or "") or None
    def_profile = str(prefs.get("profile_dir") or "") or None
    def_full_ioc = bool(prefs.get("full_ioc_types", False))

    parser = argparse.ArgumentParser(
        prog="reliquary",
        description=(
            f"{__app_name__} v{__version__} — offline email IOC extractor "
            f"(formats: {formats_help_line()})"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Фильтры по умолчанию совпадают с GUI (шум скрыт, «к разбору» вкл.).\n"
            "Отключить: --no-actionable --no-hide-rewriter …\n\n"
            "Примеры:\n"
            "  reliquary mail.eml\n"
            "  reliquary mail.eml --csv out.csv\n"
            "  reliquary mail.eml --no-actionable --handoff ticket.txt\n"
            "  reliquary ./inbox --json report.json --workers 4\n"
            "  reliquary mail.eml --allowlist allowlist_extra.txt\n"
            "  reliquary mail.eml --verdict verdict_extra.json\n"
            "  reliquary mail.eml --full-ioc-types\n"
        ),
    )
    parser.add_argument(
        "path",
        nargs="?",
        help="Письмо (.eml/.msg) или папка с письмами",
    )
    parser.add_argument(
        "files",
        nargs="*",
        help="Доп. письма / папки",
    )
    parser.add_argument(
        "-t",
        "--text",
        help="Разбор pasted RFC822 (.eml source) из строки",
    )
    parser.add_argument(
        "--no-recursive",
        action="store_true",
        help="При разборе папки не обходить подкаталоги",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=default_workers,
        help=f"Потоки для пакетного разбора (по умолчанию {default_workers})",
    )
    parser.add_argument(
        "--no-skip-broken",
        action="store_true",
        help="Не отбрасывать пустые/битые результаты (по умолчанию пропускаются)",
    )
    parser.add_argument(
        "--allowlist",
        dest="allowlist_path",
        default=def_allowlist,
        help=(
            "Доп. allowlist (domain/ip, по строке). "
            "Иначе — allowlist_extra.txt рядом с приложением, если есть"
        ),
    )
    parser.add_argument(
        "--verdict",
        dest="verdict_path",
        default=def_verdict,
        help=(
            "JSON override весов вердикта. "
            "Иначе — verdict_extra.json рядом с приложением, если есть"
        ),
    )
    parser.add_argument(
        "--handoff-template",
        dest="handoff_template_path",
        default=def_handoff_tmpl,
        help=(
            "Шаблон handoff с плейсхолдерами {verdict} {score} …. "
            "Иначе — handoff_extra.txt / handoff_{level}.txt рядом с приложением"
        ),
    )
    parser.add_argument(
        "--profile",
        dest="profile_dir",
        default=def_profile,
        help="Org profile: папка или .zip (allowlist/verdict/handoff/brands)",
    )

    filt = parser.add_argument_group(
        "фильтры IOC (по умолчанию как в GUI; --no-* снимает)"
    )
    filt.add_argument(
        "--hide-rewriter",
        action=argparse.BooleanOptionalAction,
        default=def_hide_rewriter,
        help="Скрыть proxy/SafeLinks URL",
    )
    filt.add_argument(
        "--hide-allowlisted",
        action=argparse.BooleanOptionalAction,
        default=def_hide_allow,
        help="Скрыть известный шум (CDN/mail)",
    )
    filt.add_argument(
        "--hide-private",
        action=argparse.BooleanOptionalAction,
        default=def_hide_private,
        help="Скрыть частные IP",
    )
    filt.add_argument(
        "--actionable",
        action=argparse.BooleanOptionalAction,
        default=def_actionable,
        help="Только «к разбору» (без шума и голых имён файлов)",
    )
    filt.add_argument("--search", default="", help="Подстрока value/type/tags/context")
    filt.add_argument(
        "--types",
        help="Список типов через запятую (ipv4,domain,url,…)",
    )
    filt.add_argument(
        "--full-ioc-types",
        action="store_true",
        default=def_full_ioc,
        help="Показать legacy IOC (registry/mutex/command_line) и крипто",
    )

    exp = parser.add_argument_group("экспорт")
    exp.add_argument("--csv", dest="csv_out", help="Экспорт CSV (UTF-8 BOM)")
    exp.add_argument("--json", dest="json_out", help="Полный отчёт JSON")
    exp.add_argument(
        "--batch-csv",
        dest="batch_csv_out",
        help="CSV по письмам (пакетный triage)",
    )
    exp.add_argument(
        "--handoff",
        dest="handoff_out",
        help="Текстовый handoff для тикета (ITSM)",
    )
    exp.add_argument(
        "--post-export-hook",
        dest="post_export_hook",
        default=str(load_prefs().get("post_export_hook") or ""),
        help=(
            "Локальная команда после экспорта (путь к файлу — последний аргумент). "
            "Иначе prefs post_export_hook"
        ),
    )
    exp.add_argument(
        "-o",
        "--stdout-json",
        action="store_true",
        help="Печатать полный JSON-отчёт в stdout",
    )
    exp.add_argument(
        "--quiet-verdict",
        action="store_true",
        help="Не печатать вердикт в stderr",
    )
    exp.add_argument(
        "--iocs-only",
        action="store_true",
        help="В stdout печатать только список IOC (JSON-массив)",
    )
    exp.add_argument(
        "--verbose",
        action="store_true",
        help="Доп. запись в error log (путь, число IOC, вердикт)",
    )

    args = parser.parse_args(argv)

    if not args.path and not args.text and not args.files:
        parser.print_help()
        return 2

    filters = FilterState.from_cli_args(args)
    opts = AnalysisOptions.from_prefs(prefs)
    opts.allowlist_path = args.allowlist_path or opts.allowlist_path
    opts.verdict_path = args.verdict_path or opts.verdict_path
    opts.handoff_template_path = args.handoff_template_path or opts.handoff_template_path
    opts.profile_dir = args.profile_dir or opts.profile_dir
    opts.max_workers = args.workers
    opts.skip_broken = not args.no_skip_broken

    profile = load_org_profile(opts.profile_dir)
    try:
        handoff_by_level = None
        if profile is not None:
            opts = opts.with_profile(profile)
            handoff_by_level = {
                k: str(v) for k, v in (profile.handoff_by_level or {}).items()
            } or None

        handoff_template_path = opts.handoff_template_path
        batch_results = None

        try:
            if args.text:
                result = analyze_text(args.text, options=opts)
            else:
                inputs = _resolve_inputs(args)
                if not inputs:
                    print(
                        "Нет писем (.eml / .msg) для разбора.",
                        file=sys.stderr,
                    )
                    return 2
                for raw in [args.path, *(args.files or [])]:
                    if not raw:
                        continue
                    rp = Path(raw)
                    if rp.is_file() and not is_supported(rp):
                        print(
                            f"Пропуск (не письмо): {rp.name} — только .eml / .msg",
                            file=sys.stderr,
                        )
                if len(inputs) == 1:
                    result = analyze_file(inputs[0], options=opts)
                    batch_results = [result]
                else:

                    def _progress(
                        done: int, total: int, name: str, eta: float | None
                    ) -> None:
                        eta_s = ""
                        if eta is not None:
                            eta_s = f" ETA {int(eta)}с"
                        print(
                            f"\r[{done}/{total}] {name}{eta_s}   ",
                            end="",
                            file=sys.stderr,
                            flush=True,
                        )

                    outcome = run_batch(
                        inputs,
                        max_workers=args.workers,
                        skip_broken=not args.no_skip_broken,
                        on_progress=_progress,
                        options=opts,
                    )
                    print(file=sys.stderr)
                    if outcome.result is None:
                        for err in outcome.errors:
                            print(err, file=sys.stderr)
                        return 1
                    result = outcome.result
                    batch_results = outcome.batch_results
                    if outcome.failed:
                        print(
                            f"Пропущено битых: {len(outcome.failed)}",
                            file=sys.stderr,
                        )
        except FileNotFoundError as exc:
            print(str(exc), file=sys.stderr)
            return 2
        except OSError as exc:
            print(f"Ошибка ввода: {exc}", file=sys.stderr)
            return 1

        filtered = filters.filtered_result(result)
        filt_meta = filters.serializable()

        hook = str(getattr(args, "post_export_hook", "") or "")
        hook_disabled = bool(prefs.get("disable_post_export_hook"))
        hook_external = bool(prefs.get("post_export_hook_allow_external"))
        if args.csv_out:
            export_csv(filtered, args.csv_out)
            print(f"CSV → {args.csv_out}", file=sys.stderr)
            msg = run_post_export_hook(
                hook,
                args.csv_out,
                allow_external=hook_external,
                disabled=hook_disabled,
            )
            if msg:
                print(f"  {msg}", file=sys.stderr)
        if args.batch_csv_out:
            export_batch_csv(result, args.batch_csv_out, batch_results=batch_results)
            print(f"Batch CSV → {args.batch_csv_out}", file=sys.stderr)
            msg = run_post_export_hook(
                hook,
                args.batch_csv_out,
                allow_external=hook_external,
                disabled=hook_disabled,
            )
            if msg:
                print(f"  {msg}", file=sys.stderr)
        if args.json_out:
            export_report_json(
                filtered,
                args.json_out,
                filters_applied=filt_meta,
                batch_results=batch_results,
            )
            print(f"JSON → {args.json_out}", file=sys.stderr)
            msg = run_post_export_hook(
                hook,
                args.json_out,
                allow_external=hook_external,
                disabled=hook_disabled,
            )
            if msg:
                print(f"  {msg}", file=sys.stderr)
        if args.handoff_out:
            export_handoff(
                filtered,
                args.handoff_out,
                iocs=filtered.iocs,
                template_path=handoff_template_path,
                handoff_by_level=handoff_by_level,
            )
            print(f"Handoff → {args.handoff_out}", file=sys.stderr)
            msg = run_post_export_hook(
                hook,
                args.handoff_out,
                allow_external=hook_external,
                disabled=hook_disabled,
            )
            if msg:
                print(f"  {msg}", file=sys.stderr)

        if result.meta and result.meta.overrides_loaded:
            ov = ", ".join(
                f"{k}={Path(v).name}" for k, v in result.meta.overrides_loaded.items()
            )
            print(f"[{__app_name__}] overrides: {ov}", file=sys.stderr)
        print(f"[{__app_name__}] v{__version__}", file=sys.stderr)

        if getattr(args, "verbose", False):
            from reliquary.core.error_log import append_error_log

            append_error_log(
                f"cli verbose: path={args.path!r} iocs={len(filtered.iocs)} "
                f"verdict={result.verdict.level.value if result.verdict else None}"
            )

        if not args.quiet_verdict:
            _print_verdict(result)
        _print_ioc_summary(filtered)

        exported = any(
            (
                args.csv_out,
                args.json_out,
                args.batch_csv_out,
                args.handoff_out,
                args.iocs_only,
            )
        )
        if args.iocs_only:
            print(
                json.dumps(
                    [i.to_dict() for i in filtered.iocs], ensure_ascii=False, indent=2
                )
            )
        elif args.stdout_json or not exported:
            if args.stdout_json:
                print(json.dumps(filtered.to_dict(), ensure_ascii=False, indent=2))
            else:
                payload = {
                    "verdict": result.verdict.to_dict() if result.verdict else None,
                    "iocs": [i.to_dict() for i in filtered.iocs],
                    "errors": list(result.errors),
                }
                print(json.dumps(payload, ensure_ascii=False, indent=2))

        return 0
    finally:
        if profile is not None:
            profile.cleanup()


if __name__ == "__main__":
    raise SystemExit(main())
