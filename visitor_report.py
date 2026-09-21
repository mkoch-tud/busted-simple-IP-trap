#!/usr/bin/env python3
"""Show top visitor IPs globally or for each activated nonce."""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable


DEFAULT_LOG_FILE = Path("/data/processed_visitors.jsonl")
DEFAULT_NONCE_FILE = Path("/data/nonces.json")
DETAIL_FIELDS = ("country", "city", "postal", "timezone", "org")


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


def write_ranking(
    counts: Counter[str], details_by_ip: dict[str, dict[str, str]], limit: int
) -> None:
    writer = csv.writer(sys.stdout, delimiter="\t", lineterminator="\n")
    writer.writerow(("HITS", "IP", "COUNTRY", "CITY", "POSTAL", "TIMEZONE", "ORG"))
    for ip_address, hits in sorted(counts.items(), key=lambda item: (-item[1], item[0]))[
        :limit
    ]:
        details = details_by_ip.get(ip_address, {})
        writer.writerow(
            (
                hits,
                ip_address,
                details.get("country", "-"),
                details.get("city", "-"),
                details.get("postal", "-"),
                details.get("timezone", "-"),
                details.get("org", "-"),
            )
        )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log-file", type=Path, default=DEFAULT_LOG_FILE)
    parser.add_argument("--nonce-file", type=Path, default=DEFAULT_NONCE_FILE)
    parser.add_argument(
        "--require-nonce",
        action="store_true",
        help="show the top three IPs separately for every activated nonce",
    )
    args = parser.parse_args()

    nonce_registry = read_nonces(args.nonce_file) if args.require_nonce else {}
    active_nonces = set(nonce_registry)
    all_counts: Counter[str] = Counter()
    nonce_counts: dict[str, Counter[str]] = defaultdict(Counter)
    details_by_ip: dict[str, dict[str, str]] = {}

    for record in read_records(args.log_file):
        ip_address = record["ip"]
        all_counts[ip_address] += 1
        update_details(details_by_ip, record)

        nonce = record.get("nonce")
        if args.require_nonce and nonce in active_nonces:
            nonce_counts[nonce][ip_address] += 1

    if not args.require_nonce:
        print("Top 10 connected IPs (all page hits)")
        write_ranking(all_counts, details_by_ip, 10)
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
        print(
            f"Nonce: {nonce} | activated: {metadata.get('activated_at', '-')} "
            f"| registered hits: {metadata.get('hit_count', 0)}"
        )
        write_ranking(nonce_counts[nonce], details_by_ip, 3)


if __name__ == "__main__":
    main()
