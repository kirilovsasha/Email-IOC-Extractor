"""CLI fallback for headless / automation use."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from reliquary import __app_name__, __version__
from reliquary.core.exporters import export_csv, export_report_json, export_stix
from reliquary.core.offline import enforce_offline
from reliquary.core.pipeline import analyze_file, analyze_text


def main(argv: list[str] | None = None) -> int:
    enforce_offline()
    parser = argparse.ArgumentParser(
        prog="reliquary",
        description=f"{__app_name__} v{__version__} — offline IOC triage for SOC",
    )
    parser.add_argument("path", nargs="?", help="Файл для анализа (.eml/.msg/.pdf/.html/.txt)")
    parser.add_argument("-t", "--text", help="Анализировать строку / тикет напрямую")
    parser.add_argument("--csv", dest="csv_out", help="Путь экспорта CSV")
    parser.add_argument("--stix", dest="stix_out", help="Путь экспорта STIX 2.1 JSON")
    parser.add_argument("--json", dest="json_out", help="Путь полного отчёта JSON")
    parser.add_argument("-o", "--stdout-json", action="store_true", help="Печатать отчёт в stdout")
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

    if args.stdout_json or not any((args.csv_out, args.stix_out, args.json_out)):
        print(json.dumps(result.to_dict(), ensure_ascii=False, indent=2))

    v = result.verdict
    if v:
        print(
            f"\n[{__app_name__}] {v.level.value.upper()} score={v.score} — {v.summary}",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
