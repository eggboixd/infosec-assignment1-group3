#!/usr/bin/env python3
"""Measure repeated downloads from a running Secure Store instance.

The script uses only Python's standard library. Register an account and upload
representative test files in the web UI first. It records client-observed full
response time and byte count; the app also records server-side crypto timings.
"""

from __future__ import annotations

import argparse
import csv
import http.cookiejar
import os
import re
import sys
import time
from html.parser import HTMLParser
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import HTTPCookieProcessor, Request, build_opener

FILE_LINK = re.compile(r"^/files/([0-9a-fA-F]{24})/download\?alg=(?:aes|des|rc4)$")
ALGORITHMS = ("aes", "des", "rc4")


class FilesParser(HTMLParser):
    """Collects (file ID, name) pairs from the /files page.

    Each file shows its name in an element with class "file-name", followed by
    its download links. That holds for the checklist slots and for the
    "Other files" table, so links are paired with the last name seen.
    """

    def __init__(self) -> None:
        super().__init__()
        self.files: dict[str, str] = {}
        self.name = ""
        self.name_tag: str | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = dict(attrs)
        if "file-name" in (a.get("class") or "").split():
            self.name, self.name_tag = "", tag
        elif tag == "a":
            match = FILE_LINK.match(a.get("href") or "")
            if match:
                self.files.setdefault(match.group(1), self.name.strip() or "(unnamed)")

    def handle_data(self, data: str) -> None:
        if self.name_tag is not None:
            self.name += data

    def handle_endtag(self, tag: str) -> None:
        if tag == self.name_tag:
            self.name_tag = None


def read_all(response, chunk_size: int = 1024 * 1024) -> int:
    total = 0
    while True:
        chunk = response.read(chunk_size)
        if not chunk:
            return total
        total += len(chunk)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default=os.getenv("SECURESTORE_URL", "http://localhost:8080"), help="app base URL")
    parser.add_argument("--username", default=os.getenv("BENCH_USERNAME"), help="registered account (or BENCH_USERNAME)")
    parser.add_argument("--password", default=os.getenv("BENCH_PASSWORD"), help="account password (or BENCH_PASSWORD)")
    parser.add_argument("--repeat", type=int, default=5, help="downloads per file and algorithm (default: 5)")
    parser.add_argument("--output", type=Path, default=Path("bench-client-results.csv"), help="CSV output path")
    args = parser.parse_args()
    if not args.username or not args.password:
        parser.error("provide --username/--password or BENCH_USERNAME/BENCH_PASSWORD")
    if args.repeat < 1:
        parser.error("--repeat must be at least 1")
    base = args.url.rstrip("/")
    opener = build_opener(HTTPCookieProcessor(http.cookiejar.CookieJar()))

    try:
        login = Request(base + "/login", data=urlencode({"username": args.username, "password": args.password}).encode(), headers={"Content-Type": "application/x-www-form-urlencoded"})
        with opener.open(login, timeout=30) as response:
            response.read()
        with opener.open(base + "/files", timeout=30) as response:
            html = response.read().decode("utf-8", "replace")
        found = FilesParser()
        found.feed(html)
        # Each file has three links; found.files keeps one entry per file ID.
        files = list(found.files.items())
        if not files:
            print("No files found. Log in and upload test files in the web UI first.", file=sys.stderr)
            return 2

        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("w", newline="", encoding="utf-8") as out:
            writer = csv.writer(out)
            writer.writerow(("file_id", "file_name", "algorithm", "iteration", "bytes", "client_total_ns", "http_status"))
            for file_id, name in files:
                for algorithm in ALGORITHMS:
                    for iteration in range(1, args.repeat + 1):
                        url = f"{base}/files/{file_id}/download?alg={algorithm}"
                        started = time.perf_counter_ns()
                        request = Request(url, headers={"Cache-Control": "no-cache"})
                        with opener.open(request, timeout=1800) as response:
                            status = response.status
                            byte_count = read_all(response)
                        elapsed = time.perf_counter_ns() - started
                        writer.writerow((file_id, name, algorithm, iteration, byte_count, elapsed, status))
                        out.flush()
                        print(f"{name}: {algorithm} {iteration}/{args.repeat}: {byte_count} bytes in {elapsed / 1e6:.3f} ms")
    except HTTPError as exc:
        print(f"HTTP {exc.code} from {exc.url}; check the account and server logs.", file=sys.stderr)
        return 1
    except (URLError, TimeoutError, OSError) as exc:
        print(f"Benchmark failed: {exc}", file=sys.stderr)
        return 1

    print(f"Client timing results saved to {args.output}")
    print("The app's /benchmarks/export.csv contains server-side crypto and total timings.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
