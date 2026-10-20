#!/usr/bin/env python3
"""Compare a keep-alive upstream with the mTLS proxy using only the stdlib."""

from __future__ import annotations

import argparse
import concurrent.futures
import http.client
import json
import math
import ssl
import statistics
import time
import urllib.parse
from dataclasses import dataclass


@dataclass(frozen=True)
class Target:
    name: str
    url: str
    ca: str | None = None
    cert: str | None = None
    key: str | None = None


def connection(target: Target) -> tuple[http.client.HTTPConnection, str]:
    parsed = urllib.parse.urlsplit(target.url)
    if not parsed.hostname or parsed.scheme not in {"http", "https"}:
        raise ValueError(f"invalid benchmark URL: {target.url}")
    path = urllib.parse.urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if parsed.scheme == "https":
        context = ssl.create_default_context(cafile=target.ca)
        if not target.cert or not target.key:
            raise ValueError("proxy benchmark requires --cert and --key")
        context.load_cert_chain(target.cert, target.key)
        return (
            http.client.HTTPSConnection(parsed.hostname, port, context=context, timeout=10),
            path,
        )
    return http.client.HTTPConnection(parsed.hostname, port, timeout=10), path


def worker(target: Target, request_count: int) -> list[tuple[float, bool]]:
    client, path = connection(target)
    results: list[tuple[float, bool]] = []
    body = b"arkion benchmark payload"
    headers = {"content-type": "application/octet-stream", "connection": "keep-alive"}
    try:
        for _ in range(request_count):
            started = time.perf_counter()
            ok = False
            try:
                client.request("POST", path, body=body, headers=headers)
                response = client.getresponse()
                response.read()
                ok = 200 <= response.status < 300
            except (OSError, http.client.HTTPException, ssl.SSLError):
                client.close()
                client, path = connection(target)
            results.append(((time.perf_counter() - started) * 1_000, ok))
    finally:
        client.close()
    return results


def percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, math.ceil(len(ordered) * fraction) - 1))
    return ordered[index]


def run(target: Target, requests: int, concurrency: int) -> dict[str, float | int | str]:
    per_worker, remainder = divmod(requests, concurrency)
    counts = [per_worker + (1 if index < remainder else 0) for index in range(concurrency)]
    started = time.perf_counter()
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
        batches = list(pool.map(lambda count: worker(target, count), counts))
    elapsed = time.perf_counter() - started
    results = [result for batch in batches for result in batch]
    latencies = [latency for latency, _ in results]
    errors = sum(not ok for _, ok in results)
    return {
        "target": target.name,
        "transport": "keep_alive_http1",
        "concurrency": concurrency,
        "requests": requests,
        "throughput_rps": round(requests / elapsed, 2),
        "p50_ms": round(percentile(latencies, 0.50), 2),
        "p95_ms": round(percentile(latencies, 0.95), 2),
        "p99_ms": round(percentile(latencies, 0.99), 2),
        "mean_ms": round(statistics.fmean(latencies), 2),
        "error_rate_percent": round(errors * 100 / requests, 3),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--direct-url", required=True)
    parser.add_argument("--proxy-url", required=True)
    parser.add_argument("--ca", required=True)
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--requests", type=int, default=1_000)
    parser.add_argument("--concurrency", default="1,10,100")
    args = parser.parse_args()
    levels = [int(value) for value in args.concurrency.split(",")]
    if args.requests <= 0 or not levels or any(level <= 0 for level in levels):
        parser.error("request and concurrency values must be positive")

    direct = Target("direct", args.direct_url)
    proxy = Target("proxy", args.proxy_url, args.ca, args.cert, args.key)
    for level in levels:
        count = max(args.requests, level)
        direct_result = run(direct, count, level)
        proxy_result = run(proxy, count, level)
        print(json.dumps(direct_result, separators=(",", ":")), flush=True)
        print(json.dumps(proxy_result, separators=(",", ":")), flush=True)
        print(
            json.dumps(
                {
                    "target": "incremental_proxy_overhead",
                    "concurrency": level,
                    "mean_ms": round(
                        float(proxy_result["mean_ms"]) - float(direct_result["mean_ms"]),
                        2,
                    ),
                    "p50_ms": round(
                        float(proxy_result["p50_ms"]) - float(direct_result["p50_ms"]),
                        2,
                    ),
                    "p95_ms": round(
                        float(proxy_result["p95_ms"]) - float(direct_result["p95_ms"]),
                        2,
                    ),
                    "p99_ms": round(
                        float(proxy_result["p99_ms"]) - float(direct_result["p99_ms"]),
                        2,
                    ),
                },
                separators=(",", ":"),
            ),
            flush=True,
        )


if __name__ == "__main__":
    main()
