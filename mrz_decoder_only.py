"""Standalone MRZ decoder (ICAO 9303) with CLI JSON output."""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from app.services.mrz_service import MRZService


class MRZDecoder(MRZService):
    """Standalone decoder aligned with MRZService used in KYC flows."""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Standalone MRZ decoder")
    parser.add_argument("--line", action="append", dest="lines", help="MRZ line (repeat --line for each line)")
    parser.add_argument("--file", dest="input_file", help="Text file containing MRZ lines")
    parser.add_argument("--text", dest="raw_text", default="", help="Raw OCR text containing MRZ")
    parser.add_argument("--expected", action="store_true", help="Mark MRZ as expected")
    parser.add_argument("--pretty", action="store_true", help="Pretty JSON output")
    return parser


def _read_text_from_sources(args: argparse.Namespace) -> str:
    if args.input_file:
        with open(args.input_file, "r", encoding="utf-8") as f:
            return f.read()

    if args.raw_text:
        return args.raw_text

    if not args.lines and not sys.stdin.isatty():
        return sys.stdin.read()

    return ""


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    raw_text = _read_text_from_sources(args)

    decoder = MRZDecoder()
    result = decoder.analyze(
        mrz_lines=args.lines,
        raw_text=raw_text,
        expected=args.expected,
    )

    if args.pretty:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    main()