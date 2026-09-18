"""CLI — batch folder, filters, case pack, ticket (parity with GUI pipelines)."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

from reliquary import __app_name__, __version__
from reliquary.core.exporters import (
    export_case_pack,
    export_case_pack_multi,
    export_csv,
    export_misp,
    export_opencti,
    export_report_json,
    export_stix,
    export_yara,
)
from reliquary.core.filter_state import FilterState
from reliquary.core.formats import collect_supported, formats_help_line, is_supported
from reliquary.core.offline import enforce_offline
from reliquary.core.paths import ensure_user_lists
from reliquary.core.batch import default_max_workers, run_batch
from reliquary.core.pipeline import analyze_file, analyze_text
from reliquary.core.prefs import load_prefs
from reliquary.core.ticket import build_ticket_template


def _print_ioc_summary(result, stream=None) -> None:
    if stream is None:
        stream = sys.stderr
    counts = Counter(i.ioc_type.value for i in result.iocs)
    total = len(result.iocs)
    print(f"\n[{__app_name__}] IOC извлечено: {total}", file=stream)
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
    # de-dupe preserve order
    seen: set[str] = set()
    out: list[str] = []
    for p in paths:
        key = str(Path(p).resolve()) if Path(p).exists() else p
        if key not in seen:
            seen.add(key)
            out.append(p)
    if args.only_supported:
        out = [p for p in out if is_supported(p)]
    return out


def main(argv: list[str] | None = None) -> int:
    enforce_offline()
    ensure_user_lists()
    prefs = load_prefs()
    default_workers = int(prefs.get("max_workers") or 0) or default_max_workers()

    parser = argparse.ArgumentParser(
        prog="ioc-extractor",
        description=(
            f"{__app_name__} v{__version__} — offline IOC extraction for SOC "
            f"(formats: {formats_help_line()})"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Примеры:\n"
            "  ioc-extractor mail.eml --csv out.csv --actionable\n"
            "  ioc-extractor ./inbox --case-pack case.zip --workers 4\n"
            "  ioc-extractor ticket.txt --ticket - --hide-rewriter\n"
        ),
    )
    parser.add_argument(
        "path",
        nargs="?",
        help="Файл или папка с поддерживаемыми форматами",
    )
    parser.add_argument(
        "files",
        nargs="*",
        help="Доп. файлы/папки",
    )
    parser.add_argument("-t", "--text", help="Извлечь IOC из строки / тикета")
    parser.add_argument(
        "--no-recursive",
        action="store_true",
        help="При разборе папки не обходить подкаталоги",
    )
    parser.add_argument(
        "--only-supported",
        action="store_true",
        help="Игнорировать файлы с неизвестным суффиксом",
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

    # Filters (GUI parity)
    filt = parser.add_argument_group("фильтры IOC")
    filt.add_argument("--hide-rewriter", action="store_true", help="Скрыть proxy/SafeLinks URL")
    filt.add_argument("--hide-allowlisted", action="store_true", help="Скрыть allowlisted")
    filt.add_argument("--hide-private", action="store_true", help="Скрыть частные IP")
    filt.add_argument("--only-denylisted", action="store_true", help="Только denylist")
    filt.add_argument(
        "--actionable",
        action="store_true",
        help="Только «к разбору» (без шума и голых имён файлов)",
    )
    filt.add_argument("--search", default="", help="Подстрока value/type/tags/context")
    filt.add_argument(
        "--types",
        help="Список типов через запятую (ipv4,domain,url,…)",
    )

    # Exports
    exp = parser.add_argument_group("экспорт")
    exp.add_argument("--csv", dest="csv_out", help="Экспорт CSV (UTF-8 BOM)")
    exp.add_argument("--stix", dest="stix_out", help="Экспорт STIX 2.1 JSON")
    exp.add_argument("--json", dest="json_out", help="Полный отчёт JSON")
    exp.add_argument("--misp", dest="misp_out", help="Экспорт MISP event JSON")
    exp.add_argument("--opencti", dest="opencti_out", help="Экспорт OpenCTI JSON")
    exp.add_argument("--yara", dest="yara_out", help="Экспорт YARA rules")
    exp.add_argument(
        "--case-pack",
        dest="case_pack_out",
        help="Case pack ZIP (JSON+CSV+ticket+вложения)",
    )
    exp.add_argument(
        "--case-pack-multi",
        dest="case_pack_multi_out",
        help="Case pack ZIP по файлам (пакет)",
    )
    exp.add_argument(
        "--ticket",
        nargs="?",
        const="-",
        metavar="PATH",
        help="Шаблон тикета в файл или stdout (-)",
    )
    exp.add_argument(
        "--ticket-short",
        action="store_true",
        help="Короткий шаблон тикета",
    )
    exp.add_argument(
        "--ticket-lang",
        choices=("ru", "en"),
        default=None,
        help="Язык тикета (по умолчанию из ticket.ini)",
    )
    exp.add_argument(
        "-o",
        "--stdout-json",
        action="store_true",
        help="Печатать полный JSON-отчёт в stdout",
    )
    exp.add_argument(
        "--phishing",
        action="store_true",
        help="Показать доп. вердикт фишинга / triage письма",
    )
    exp.add_argument(
        "--iocs-only",
        action="store_true",
        help="В stdout печатать только список IOC (JSON-массив)",
    )

    args = parser.parse_args(argv)

    if not args.path and not args.text and not args.files:
        parser.print_help()
        return 2

    filters = FilterState.from_cli_args(args)

    batch_results: list = []
    try:
        if args.text:
            result = analyze_text(args.text)
            batch_results = [result]
        else:
            inputs = _resolve_inputs(args)
            if not inputs:
                print("Нет поддерживаемых файлов для разбора", file=sys.stderr)
                return 2
            if len(inputs) == 1:
                result = analyze_file(inputs[0])
                batch_results = [result]
            else:

                def _progress(done: int, total: int, name: str, eta: float | None) -> None:
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

    if args.csv_out:
        export_csv(filtered, args.csv_out)
        print(f"CSV → {args.csv_out}", file=sys.stderr)
    if args.stix_out:
        export_stix(filtered, args.stix_out)
        print(f"STIX → {args.stix_out}", file=sys.stderr)
    if args.json_out:
        export_report_json(filtered, args.json_out, filters_applied=filt_meta)
        print(f"JSON → {args.json_out}", file=sys.stderr)
    if args.misp_out:
        export_misp(filtered, args.misp_out, iocs=filtered.iocs)
        print(f"MISP → {args.misp_out}", file=sys.stderr)
    if args.opencti_out:
        export_opencti(filtered, args.opencti_out, iocs=filtered.iocs)
        print(f"OpenCTI → {args.opencti_out}", file=sys.stderr)
    if args.yara_out:
        export_yara(filtered, args.yara_out, iocs=filtered.iocs)
        print(f"YARA → {args.yara_out}", file=sys.stderr)
    if args.case_pack_out:
        out = export_case_pack(
            filtered, args.case_pack_out, filters_applied=filt_meta
        )
        print(f"Case pack → {out}", file=sys.stderr)
    if args.case_pack_multi_out:
        pack_src = batch_results or [filtered]
        out = export_case_pack_multi(
            pack_src, args.case_pack_multi_out, filters_applied=filt_meta
        )
        print(f"Case pack (по файлам ×{len(pack_src)}) → {out}", file=sys.stderr)
    if args.ticket is not None:
        ticket = build_ticket_template(
            filtered,
            filtered.iocs,
            defang=True,
            short=bool(args.ticket_short),
            lang=args.ticket_lang,
        )
        if args.ticket == "-":
            print(ticket)
        else:
            Path(args.ticket).write_text(ticket, encoding="utf-8")
            print(f"Ticket → {args.ticket}", file=sys.stderr)

    _print_ioc_summary(filtered)

    if args.phishing and result.verdict:
        v = result.verdict
        print(
            f"\n[фишинг/доп.] {v.level.value.upper()} score={v.score} — {v.summary}",
            file=sys.stderr,
        )
        for reason in v.reasons[:8]:
            print(f"  • {reason}", file=sys.stderr)

    exported = any(
        (
            args.csv_out,
            args.stix_out,
            args.json_out,
            args.misp_out,
            args.opencti_out,
            args.yara_out,
            args.case_pack_out,
            args.case_pack_multi_out,
            args.ticket is not None,
            args.iocs_only,
        )
    )
    if args.iocs_only:
        print(json.dumps([i.to_dict() for i in filtered.iocs], ensure_ascii=False, indent=2))
    elif args.stdout_json or not exported:
        if args.stdout_json:
            print(json.dumps(filtered.to_dict(), ensure_ascii=False, indent=2))
        elif not exported:
            print(json.dumps([i.to_dict() for i in filtered.iocs], ensure_ascii=False, indent=2))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
