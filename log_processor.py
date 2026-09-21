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
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
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
DEFAULT_IPINFO_TOKEN = os.environ.get("IPINFO_TOKEN", "")
DEFAULT_IPINFO_API_URL = os.environ.get(
    "IPINFO_API_URL", "https://ipinfo.io/{ip}/json"
)
DEFAULT_IPINFO_CACHE_FILE = Path(
    os.environ.get("IPINFO_CACHE_FILE", "/data/ipinfo_cache.json")
)
DEFAULT_IPINFO_TIMEOUT = float(os.environ.get("IPINFO_TIMEOUT", "5"))
DEFAULT_IPINFO_CACHE_TTL = float(os.environ.get("IPINFO_CACHE_TTL", "86400"))
NONCE_ALPHABET = string.ascii_letters + string.digits
IPINFO_FIELDS = ("country", "city", "postal", "org", "timezone")


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


def load_ipinfo_cache(cache_file: Path) -> dict[str, dict[str, Any]]:
    try:
        content = cache_file.read_text(encoding="utf-8")
    except FileNotFoundError:
        return {}

    try:
        cache = json.loads(content)
    except json.JSONDecodeError as error:
        raise RuntimeError(f"Invalid IPinfo cache {cache_file}: {error}") from error
    if not isinstance(cache, dict):
        raise RuntimeError(f"Invalid IPinfo cache {cache_file}: expected an object")
    return cache


def save_ipinfo_cache(cache_file: Path, cache: dict[str, dict[str, Any]]) -> None:
    cache_file.parent.mkdir(parents=True, exist_ok=True)
    temporary_file = cache_file.with_suffix(cache_file.suffix + ".new")
    temporary_file.write_text(
        json.dumps(cache, ensure_ascii=True, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary_file.replace(cache_file)


def normalized_ipinfo(data: dict[str, Any]) -> dict[str, str | None]:
    def text(field: str) -> str | None:
        value = data.get(field)
        return value if isinstance(value, str) and value else None

    organization = text("org")
    if organization is None:
        organization = " ".join(
            value
            for value in (text("asn"), text("as_name"))
            if value is not None
        ) or None

    return {
        "country": text("country") or text("country_code"),
        "city": text("city"),
        "postal": text("postal"),
        "org": organization,
        "timezone": text("timezone"),
    }


class IPinfoEnricher:
    def __init__(
        self,
        token: str,
        api_url: str,
        cache_file: Path,
        timeout: float,
        cache_ttl: float,
    ) -> None:
        self.token = token
        self.api_url = api_url
        self.cache_file = cache_file
        self.timeout = timeout
        self.cache_ttl = cache_ttl
        self.cache = load_ipinfo_cache(cache_file)
        self.failed_ips: set[str] = set()
        self.next_prune_at = 0.0
        self.prune_expired(force=True)

    def cache_entry_is_fresh(self, entry: dict[str, Any]) -> bool:
        cached_at = entry.get("cached_at")
        if not isinstance(cached_at, str):
            return False
        try:
            cached_time = datetime.fromisoformat(cached_at.replace("Z", "+00:00"))
        except ValueError:
            return False
        if cached_time.tzinfo is None:
            cached_time = cached_time.replace(tzinfo=timezone.utc)
        age = (datetime.now(timezone.utc) - cached_time).total_seconds()
        return 0 <= age < self.cache_ttl

    def prune_expired(self, force: bool = False) -> None:
        now = time.monotonic()
        if not force and now < self.next_prune_at:
            return
        self.next_prune_at = now + min(60.0, self.cache_ttl)

        expired = [
            ip_address
            for ip_address, entry in self.cache.items()
            if not isinstance(entry, dict) or not self.cache_entry_is_fresh(entry)
        ]
        if not expired:
            return
        for ip_address in expired:
            self.cache.pop(ip_address, None)
        save_ipinfo_cache(self.cache_file, self.cache)

    def lookup(self, ip_address: str) -> dict[str, str | None] | None:
        self.prune_expired()
        cached = self.cache.get(ip_address)
        if isinstance(cached, dict):
            return {field: cached.get(field) for field in IPINFO_FIELDS}
        if ip_address in self.failed_ips:
            return None

        if not ipaddress.ip_address(ip_address).is_global:
            return {field: None for field in IPINFO_FIELDS}

        try:
            endpoint = self.api_url.format(
                ip=urllib.parse.quote(ip_address, safe=":")
            )
        except (KeyError, ValueError) as error:
            raise RuntimeError(f"Invalid IPINFO_API_URL: {error}") from error

        separator = "&" if "?" in endpoint else "?"
        request_url = endpoint + separator + urllib.parse.urlencode(
            {"token": self.token}
        )
        request = urllib.request.Request(
            request_url,
            headers={"Accept": "application/json", "User-Agent": "busted-simple-ip-trap/1"},
        )

        failure: str | None = None
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                payload = response.read(1_000_001)
            if len(payload) > 1_000_000:
                raise ValueError("response exceeded 1 MB")
            data = json.loads(payload)
            if not isinstance(data, dict) or data.get("error"):
                raise ValueError("API returned an error or invalid object")
        except urllib.error.HTTPError as error:
            failure = f"HTTP status {error.code}"
        except urllib.error.URLError as error:
            failure = f"network error: {error.reason}"
        except (OSError, ValueError, json.JSONDecodeError) as error:
            failure = str(error)

        if failure is not None:
            self.failed_ips.add(ip_address)
            print(
                f"IPinfo lookup failed for {ip_address}: {failure}",
                file=sys.stderr,
                flush=True,
            )
            return None

        details = normalized_ipinfo(data)
        self.cache[ip_address] = {**details, "cached_at": utc_now()}
        save_ipinfo_cache(self.cache_file, self.cache)
        return details

    def enrich(self, record: dict[str, Any]) -> None:
        details = self.lookup(record["ip"])
        if details is not None:
            record.update(details)


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
    ipinfo: IPinfoEnricher | None = None,
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
                if ipinfo is not None:
                    ipinfo.enrich(record)
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
    parser.add_argument("--ipinfo-token", default=DEFAULT_IPINFO_TOKEN)
    parser.add_argument("--ipinfo-api-url", default=DEFAULT_IPINFO_API_URL)
    parser.add_argument(
        "--ipinfo-cache-file", type=Path, default=DEFAULT_IPINFO_CACHE_FILE
    )
    parser.add_argument("--ipinfo-timeout", type=float, default=DEFAULT_IPINFO_TIMEOUT)
    parser.add_argument(
        "--ipinfo-cache-ttl", type=float, default=DEFAULT_IPINFO_CACHE_TTL
    )
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
    if args.ipinfo_timeout <= 0:
        parser.error("--ipinfo-timeout must be greater than zero")
    if args.ipinfo_cache_ttl <= 0:
        parser.error("--ipinfo-cache-ttl must be greater than zero")

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

    ipinfo = None
    if args.ipinfo_token:
        ipinfo = IPinfoEnricher(
            args.ipinfo_token,
            args.ipinfo_api_url,
            args.ipinfo_cache_file,
            args.ipinfo_timeout,
            args.ipinfo_cache_ttl,
        )

    while True:
        if ipinfo is not None:
            ipinfo.prune_expired()
        process_available(
            args.log_file,
            args.output_file,
            args.state_file,
            args.nonce_file,
            args.lock_file,
            ipinfo,
        )
        if args.once:
            break
        time.sleep(args.poll_interval)


if __name__ == "__main__":
    main()
