#!/usr/bin/env python3
"""Show top visitor IPs globally or for each activated nonce."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable


DEFAULT_LOG_FILE = Path("/data/processed_visitors.jsonl")
DEFAULT_NONCE_FILE = Path("/data/nonces.json")
DETAIL_FIELDS = ("country", "city", "postal", "timezone", "org")
TABLE_HEADERS = (
    "HITS",
    "IP ADDRESS",
    "COUNTRY",
    "CITY",
    "POSTAL",
    "TIMEZONE",
    "ORGANIZATION",
)
MINIMUM_WIDTHS = (8, 39, 12, 20, 10, 24, 12)
COUNTRY_HEADERS = ("HITS", "COUNTRY")
COUNTRY_MINIMUM_WIDTHS = (8, 12)


def read_records(log_file: Path) -> Iterable[dict[str, Any]]:
    try:
        stream = log_file.open("r", encoding="utf-8")
    except FileNotFoundError:
        return

    with stream:
        for line_number, line in enumerate(stream, 1):
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                print(
                    f"Skipping invalid JSON on line {line_number} of {log_file}",
                    file=sys.stderr,
                )
                continue
            if isinstance(record, dict) and isinstance(record.get("ip"), str):
                yield record


def read_nonces(nonce_file: Path) -> dict[str, dict[str, Any]]:
    try:
        value = json.loads(nonce_file.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except json.JSONDecodeError as error:
        raise SystemExit(f"Invalid nonce registry {nonce_file}: {error}") from error

    if not isinstance(value, dict):
        raise SystemExit(f"Invalid nonce registry {nonce_file}: expected an object")
    return value


def update_details(
    details_by_ip: dict[str, dict[str, str]], record: dict[str, Any]
) -> None:
    details = details_by_ip.setdefault(record["ip"], {})
    for field in DETAIL_FIELDS:
        value = record.get(field)
        if isinstance(value, str) and value:
            details[field] = value


def write_table(
    headers: tuple[str, ...],
    rows: list[tuple[str, ...]],
    minimum_widths: tuple[int, ...],
) -> None:
    sanitized_rows = [
        tuple(" ".join(value.split()) or "-" for value in row) for row in rows
    ]
    widths = [
        max(
            minimum_widths[column],
            len(headers[column]),
            *(len(row[column]) for row in sanitized_rows),
        )
        for column in range(len(headers))
    ]

    def formatted(row: tuple[str, ...]) -> str:
        columns = [f"{row[0]:>{widths[0]}}"]
        columns.extend(
            f"{value:<{widths[index]}}" for index, value in enumerate(row[1:], 1)
        )
        return "  ".join(columns).rstrip()

    print(formatted(headers))
    print("  ".join("-" * width for width in widths))
    for row in sanitized_rows:
        print(formatted(row))


def write_ip_ranking(
    counts: Counter[str], details_by_ip: dict[str, dict[str, str]], limit: int
) -> None:
    ranked_visitors = sorted(
        counts.items(), key=lambda item: (-item[1], item[0])
    )[:limit]
    rows: list[tuple[str, ...]] = []
    for ip_address, hits in ranked_visitors:
        details = details_by_ip.get(ip_address, {})
        rows.append(
            (
                str(hits),
                ip_address,
                details.get("country", "-"),
                details.get("city", "-"),
                details.get("postal", "-"),
                details.get("timezone", "-"),
                details.get("org", "-"),
            )
        )
    write_table(TABLE_HEADERS, rows, MINIMUM_WIDTHS)


def write_country_ranking(counts: Counter[str], limit: int) -> None:
    ranked_countries = sorted(
        counts.items(), key=lambda item: (-item[1], item[0])
    )[:limit]
    rows = [(str(hits), country) for country, hits in ranked_countries]
    write_table(COUNTRY_HEADERS, rows, COUNTRY_MINIMUM_WIDTHS)


def record_country(record: dict[str, Any]) -> str:
    country = record.get("country")
    return country if isinstance(country, str) and country else "UNKNOWN"


def nonce_heading(nonce: str, metadata: dict[str, Any] | None) -> str:
    display_nonce = " ".join(nonce.split()) or "-"
    if metadata is None:
        return f"Nonce: {display_nonce} | activated: unregistered | registered hits: -"
    return (
        f"Nonce: {display_nonce} | activated: {metadata.get('activated_at', '-')} "
        f"| registered hits: {metadata.get('hit_count', 0)}"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log-file", type=Path, default=DEFAULT_LOG_FILE)
    parser.add_argument("--nonce-file", type=Path, default=DEFAULT_NONCE_FILE)
    nonce_mode = parser.add_mutually_exclusive_group()
    nonce_mode.add_argument(
        "--require-nonce",
        action="store_true",
        help="show a separate ranking for every activated nonce",
    )
    nonce_mode.add_argument(
        "--nonce",
        metavar="NONCE",
        help="show only visits containing this exact nonce",
    )
    parser.add_argument(
        "--country",
        action="store_true",
        help="aggregate requests by country instead of IP address",
    )
    parser.add_argument(
        "-n",
        "--limit",
        type=int,
        help="number of rows to show (default: 10 globally, 3 per nonce)",
    )
    args = parser.parse_args()

    if args.limit is not None and args.limit <= 0:
        parser.error("-n/--limit must be greater than zero")
    per_nonce = args.require_nonce or args.nonce is not None
    limit = args.limit if args.limit is not None else (3 if per_nonce else 10)

    nonce_registry = read_nonces(args.nonce_file) if per_nonce else {}
    active_nonces = set(nonce_registry)
    all_counts: Counter[str] = Counter()
    all_country_counts: Counter[str] = Counter()
    nonce_counts: dict[str, Counter[str]] = defaultdict(Counter)
    nonce_country_counts: dict[str, Counter[str]] = defaultdict(Counter)
    selected_nonce_counts: Counter[str] = Counter()
    selected_nonce_country_counts: Counter[str] = Counter()
    details_by_ip: dict[str, dict[str, str]] = {}

    for record in read_records(args.log_file):
        ip_address = record["ip"]
        all_counts[ip_address] += 1
        country = record_country(record)
        all_country_counts[country] += 1
        update_details(details_by_ip, record)

        nonce = record.get("nonce")
        if args.require_nonce and nonce in active_nonces:
            nonce_counts[nonce][ip_address] += 1
            nonce_country_counts[nonce][country] += 1
        if args.nonce is not None and nonce == args.nonce:
            selected_nonce_counts[ip_address] += 1
            selected_nonce_country_counts[country] += 1

    if args.nonce is not None:
        print(nonce_heading(args.nonce, nonce_registry.get(args.nonce)))
        if args.country:
            write_country_ranking(selected_nonce_country_counts, limit)
        else:
            write_ip_ranking(selected_nonce_counts, details_by_ip, limit)
        return

    if not args.require_nonce:
        if args.country:
            print(f"Top {limit} countries (all page hits)")
            write_country_ranking(all_country_counts, limit)
        else:
            print(f"Top {limit} connected IPs (all page hits)")
            write_ip_ranking(all_counts, details_by_ip, limit)
        return

    if not nonce_registry:
        print("No activated nonces found.")
        return

    ordered_nonces = sorted(
        nonce_registry,
        key=lambda nonce: (nonce_registry[nonce].get("activated_at", ""), nonce),
    )
    for index, nonce in enumerate(ordered_nonces):
        if index:
            print()
        metadata = nonce_registry[nonce]
        print(nonce_heading(nonce, metadata))
        if args.country:
            write_country_ranking(nonce_country_counts[nonce], limit)
        else:
            write_ip_ranking(nonce_counts[nonce], details_by_ip, limit)


if __name__ == "__main__":
    main()
