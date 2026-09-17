"""CLI — IOC extraction is primary; phishing verdict is opt-in."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter

from reliquary import __app_name__, __version__
from reliquary.core.exporters import export_csv, export_report_json, export_stix
from reliquary.core.offline import enforce_offline
from reliquary.core.pipeline import analyze_file, analyze_text


def _print_ioc_summary(result, stream=sys.stderr) -> None:
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


def main(argv: list[str] | None = None) -> int:
    enforce_offline()
    parser = argparse.ArgumentParser(
        prog="reliquary",
        description=(
            f"{__app_name__} v{__version__} — offline IOC extraction for SOC "
            "(phishing check is optional)"
        ),
    )
    parser.add_argument("path", nargs="?", help="Файл (.eml/.msg/.pdf/.html/.txt)")
    parser.add_argument("-t", "--text", help="Извлечь IOC из строки / тикета")
    parser.add_argument("--csv", dest="csv_out", help="Экспорт CSV")
    parser.add_argument("--stix", dest="stix_out", help="Экспорт STIX 2.1 JSON")
    parser.add_argument("--json", dest="json_out", help="Полный отчёт JSON")
    parser.add_argument(
        "-o",
        "--stdout-json",
        action="store_true",
        help="Печатать полный JSON-отчёт в stdout",
    )
    parser.add_argument(
        "--phishing",
        action="store_true",
        help="Показать доп. вердикт фишинга / triage письма",
    )
    parser.add_argument(
        "--iocs-only",
        action="store_true",
        help="В stdout печатать только список IOC (JSON-массив)",
    )
    args = parser.parse_args(argv)

    if not args.path and not args.text:
        parser.print_help()
        return 2

    if args.text:
        result = analyze_text(args.text)
    else:
        result = analyze_file(args.path)

    if args.csv_out:
        export_csv(result, args.csv_out)
        print(f"CSV → {args.csv_out}", file=sys.stderr)
    if args.stix_out:
        export_stix(result, args.stix_out)
        print(f"STIX → {args.stix_out}", file=sys.stderr)
    if args.json_out:
        export_report_json(result, args.json_out)
        print(f"JSON → {args.json_out}", file=sys.stderr)

    _print_ioc_summary(result)

    if args.phishing and result.verdict:
        v = result.verdict
        print(
            f"\n[фишинг/доп.] {v.level.value.upper()} score={v.score} — {v.summary}",
            file=sys.stderr,
        )
        for reason in v.reasons[:8]:
            print(f"  • {reason}", file=sys.stderr)

    if args.iocs_only:
        print(json.dumps([i.to_dict() for i in result.iocs], ensure_ascii=False, indent=2))
    elif args.stdout_json or not any((args.csv_out, args.stix_out, args.json_out, args.iocs_only)):
        # Default machine output: full report still available; human summary already on stderr
        if args.stdout_json:
            print(json.dumps(result.to_dict(), ensure_ascii=False, indent=2))
        elif not any((args.csv_out, args.stix_out, args.json_out)):
            print(json.dumps([i.to_dict() for i in result.iocs], ensure_ascii=False, indent=2))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
