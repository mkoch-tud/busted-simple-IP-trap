#!/usr/bin/env python3
"""Continuously normalize raw visitor log entries into JSON Lines records."""

from __future__ import annotations

import argparse
import fcntl
import ipaddress
import json
import os
import secrets
import string
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator


DEFAULT_LOG_FILE = Path(os.environ.get("VISITOR_LOG", "/data/visitors.log"))
DEFAULT_OUTPUT_FILE = Path(
    os.environ.get("PROCESSED_LOG", "/data/processed_visitors.jsonl")
)
DEFAULT_STATE_FILE = Path(
    os.environ.get("PROCESSOR_STATE", "/data/.processor.offset")
)
DEFAULT_NONCE_FILE = Path(os.environ.get("NONCE_FILE", "/data/nonces.json"))
DEFAULT_NONCE_LOCK_FILE = Path(
    os.environ.get("NONCE_LOCK_FILE", "/data/.nonces.lock")
)
DEFAULT_POLL_INTERVAL = float(os.environ.get("PROCESSOR_POLL_INTERVAL", "1"))
DEFAULT_NONCE_LENGTH = int(os.environ.get("NONCE_LENGTH", "24"))
NONCE_ALPHABET = string.ascii_letters + string.digits


def parse_log_line(line: str) -> dict[str, Any] | None:
    """Extract a timestamp, IP address, and optional nonce from one log line."""
    try:
        timestamp, remainder = line.rstrip("\n").split(" IP=", 1)
    except ValueError:
        return None

    encoded_nonce: str | None = None
    if " IDENTIFIER=" in remainder:
        ip_text, encoded_nonce = remainder.split(" IDENTIFIER=", 1)
    else:
        # Compatibility with entries produced before nonce support was added.
        ip_text = remainder

    try:
        ip_address = str(ipaddress.ip_address(ip_text))
    except ValueError:
        return None

    nonce: str | None = None
    if encoded_nonce is not None:
        try:
            decoded_nonce = json.loads(encoded_nonce)
        except (json.JSONDecodeError, TypeError):
            return None
        if not isinstance(decoded_nonce, str):
            return None
        nonce = decoded_nonce or None

    return {"timestamp": timestamp, "ip": ip_address, "nonce": nonce}


def read_offset(state_file: Path) -> int:
    try:
        return max(0, int(state_file.read_text(encoding="ascii").strip()))
    except (FileNotFoundError, OSError, ValueError):
        return 0


def save_offset(state_file: Path, offset: int) -> None:
    temporary_file = state_file.with_suffix(state_file.suffix + ".new")
    temporary_file.write_text(f"{offset}\n", encoding="ascii")
    temporary_file.replace(state_file)


def append_record(output_file: Path, record: dict[str, Any]) -> None:
    with output_file.open("a", encoding="utf-8") as stream:
        json.dump(record, stream, ensure_ascii=True, separators=(",", ":"))
        stream.write("\n")
        stream.flush()


@contextmanager
def nonce_lock(lock_file: Path) -> Iterator[None]:
    lock_file.parent.mkdir(parents=True, exist_ok=True)
    with lock_file.open("a", encoding="ascii") as stream:
        fcntl.flock(stream, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(stream, fcntl.LOCK_UN)


def load_nonce_registry(nonce_file: Path) -> dict[str, dict[str, Any]]:
    try:
        content = nonce_file.read_text(encoding="utf-8")
    except FileNotFoundError:
        return {}

    try:
        registry = json.loads(content)
    except json.JSONDecodeError as error:
        raise RuntimeError(f"Invalid nonce registry {nonce_file}: {error}") from error

    if not isinstance(registry, dict):
        raise RuntimeError(f"Invalid nonce registry {nonce_file}: expected an object")
    return registry


def save_nonce_registry(
    nonce_file: Path, registry: dict[str, dict[str, Any]]
) -> None:
    nonce_file.parent.mkdir(parents=True, exist_ok=True)
    temporary_file = nonce_file.with_suffix(nonce_file.suffix + ".new")
    temporary_file.write_text(
        json.dumps(registry, ensure_ascii=True, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary_file.replace(nonce_file)


def used_nonces_from_processed_log(output_file: Path) -> set[str]:
    used: set[str] = set()
    try:
        stream = output_file.open("r", encoding="utf-8")
    except FileNotFoundError:
        return used

    with stream:
        for line in stream:
            try:
                nonce = json.loads(line).get("nonce")
            except (json.JSONDecodeError, AttributeError):
                continue
            if isinstance(nonce, str) and nonce:
                used.add(nonce)
    return used


def used_nonces_from_raw_log(log_file: Path) -> set[str]:
    used: set[str] = set()
    try:
        stream = log_file.open("r", encoding="utf-8")
    except FileNotFoundError:
        return used

    with stream:
        for line in stream:
            record = parse_log_line(line)
            if record is not None and record["nonce"]:
                used.add(record["nonce"])
    return used


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace(
        "+00:00", "Z"
    )


def activate_nonce(
    nonce_file: Path,
    lock_file: Path,
    log_file: Path,
    output_file: Path,
    length: int,
) -> str:
    """Create and persist a random nonce that has never appeared in the logs."""
    with nonce_lock(lock_file):
        registry = load_nonce_registry(nonce_file)
        used_nonces = set(registry)
        used_nonces.update(used_nonces_from_processed_log(output_file))
        used_nonces.update(used_nonces_from_raw_log(log_file))

        while True:
            generated = "".join(secrets.choice(NONCE_ALPHABET) for _ in range(length))
            if generated not in used_nonces:
                break

        registry[generated] = {
            "activated_at": utc_now(),
            "first_hit_at": None,
            "hit_count": 0,
            "last_hit_at": None,
        }
        save_nonce_registry(nonce_file, registry)
        return generated


def record_nonce_hit(
    nonce_file: Path,
    lock_file: Path,
    nonce: str | None,
    timestamp: str,
) -> None:
    if nonce is None:
        return

    with nonce_lock(lock_file):
        registry = load_nonce_registry(nonce_file)
        entry = registry.get(nonce)
        if entry is None:
            return

        entry["hit_count"] = int(entry.get("hit_count", 0)) + 1
        if entry.get("first_hit_at") is None:
            entry["first_hit_at"] = timestamp
        entry["last_hit_at"] = timestamp
        save_nonce_registry(nonce_file, registry)


def process_available(
    log_file: Path,
    output_file: Path,
    state_file: Path,
    nonce_file: Path | None = None,
    lock_file: Path | None = None,
) -> int:
    """Process complete lines currently available and return the new offset."""
    offset = read_offset(state_file)

    try:
        stream = log_file.open("r", encoding="utf-8")
    except FileNotFoundError:
        return offset

    with stream:
        stream.seek(0, os.SEEK_END)
        if stream.tell() < offset:
            # The source log was truncated or replaced.
            offset = 0
        stream.seek(offset)

        while True:
            line = stream.readline()
            if not line:
                break
            if not line.endswith("\n"):
                # Do not consume a record while another process is writing it.
                break

            record = parse_log_line(line)
            if record is None:
                print(f"Skipping malformed visitor log entry: {line.rstrip()!r}")
            else:
                append_record(output_file, record)
                if nonce_file is not None and lock_file is not None:
                    record_nonce_hit(
                        nonce_file, lock_file, record["nonce"], record["timestamp"]
                    )

            offset = stream.tell()
            save_offset(state_file, offset)

    return offset


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log-file", type=Path, default=DEFAULT_LOG_FILE)
    parser.add_argument("--output-file", type=Path, default=DEFAULT_OUTPUT_FILE)
    parser.add_argument("--state-file", type=Path, default=DEFAULT_STATE_FILE)
    parser.add_argument("--nonce-file", type=Path, default=DEFAULT_NONCE_FILE)
    parser.add_argument("--lock-file", type=Path, default=DEFAULT_NONCE_LOCK_FILE)
    parser.add_argument("--poll-interval", type=float, default=DEFAULT_POLL_INTERVAL)
    parser.add_argument("--nonce-length", type=int, default=DEFAULT_NONCE_LENGTH)
    parser.add_argument(
        "--activate-nonce",
        action="store_true",
        help="activate a unique nonce, print it, and exit",
    )
    parser.add_argument(
        "--once", action="store_true", help="process available entries and exit"
    )
    args = parser.parse_args()

    if args.poll_interval <= 0:
        parser.error("--poll-interval must be greater than zero")
    if args.nonce_length < 8:
        parser.error("--nonce-length must be at least 8")

    args.output_file.parent.mkdir(parents=True, exist_ok=True)
    args.state_file.parent.mkdir(parents=True, exist_ok=True)
    args.nonce_file.parent.mkdir(parents=True, exist_ok=True)

    if args.activate_nonce:
        print(
            activate_nonce(
                args.nonce_file,
                args.lock_file,
                args.log_file,
                args.output_file,
                args.nonce_length,
            )
        )
        return

    while True:
        process_available(
            args.log_file,
            args.output_file,
            args.state_file,
            args.nonce_file,
            args.lock_file,
        )
        if args.once:
            break
        time.sleep(args.poll_interval)


if __name__ == "__main__":
    main()
