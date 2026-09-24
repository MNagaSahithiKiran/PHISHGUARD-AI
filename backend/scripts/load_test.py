#!/usr/bin/env python3
"""PhishGuard AI - Controlled Concurrent Load Testing Script
Executes concurrent requests against local application endpoints.
Measures throughput, latency percentiles (p50, p95, p99), and error rates.
"""

import sys
import time
import asyncio
import numpy as np
from pathlib import Path
from httpx import AsyncClient, ASGITransport

backend_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(backend_dir))

from app.main import app


async def run_worker(client: AsyncClient, endpoint: str, num_requests: int, latencies: list, errors: list):
    for _ in range(num_requests):
        t0 = time.perf_counter()
        try:
            res = await client.get(endpoint)
            t1 = time.perf_counter()
            latencies.append((t1 - t0) * 1000)
            if res.status_code != 200:
                errors.append(res.status_code)
        except Exception as e:
            t1 = time.perf_counter()
            latencies.append((t1 - t0) * 1000)
            errors.append(str(e))


async def benchmark_concurrency(concurrency: int, total_requests: int, endpoint: str = "/api/v1/health"):
    transport = ASGITransport(app=app)
    reqs_per_worker = total_requests // concurrency

    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        latencies = []
        errors = []

        start_time = time.perf_counter()
        tasks = [
            run_worker(client, endpoint, reqs_per_worker, latencies, errors)
            for _ in range(concurrency)
        ]
        await asyncio.gather(*tasks)
        total_time = time.perf_counter() - start_time

    arr = np.array(latencies) if latencies else np.array([0])
    throughput = len(latencies) / total_time if total_time > 0 else 0

    return {
        "concurrency": concurrency,
        "total_requests": len(latencies),
        "total_time_s": round(total_time, 3),
        "throughput_rps": round(throughput, 2),
        "p50_ms": round(float(np.percentile(arr, 50)), 2),
        "p95_ms": round(float(np.percentile(arr, 95)), 2),
        "p99_ms": round(float(np.percentile(arr, 99)), 2),
        "mean_ms": round(float(np.mean(arr)), 2),
        "errors_count": len(errors),
        "success_rate_pct": round(((len(latencies) - len(errors)) / max(len(latencies), 1)) * 100, 2),
    }


async def main():
    print("=" * 70)
    print("PHISHGUARD AI - PRODUCTION LOAD TEST RUNNER")
    print("Testing In-Process ASGI Server Across Controlled Concurrency Levels")
    print("=" * 70)

    scenarios = [
        (10, 100),
        (25, 250),
        (50, 500),
    ]

    results = []
    for concurrency, total_requests in scenarios:
        print(f"\nExecuting scenario: {concurrency} concurrent workers, {total_requests} total requests...")
        stats = await benchmark_concurrency(concurrency, total_requests, endpoint="/api/v1/health")
        results.append(stats)
        print(f"  Throughput: {stats['throughput_rps']} req/s")
        print(f"  Latency: p50={stats['p50_ms']}ms, p95={stats['p95_ms']}ms, p99={stats['p99_ms']}ms")
        print(f"  Success Rate: {stats['success_rate_pct']}% (Errors: {stats['errors_count']})")

    print("\n" + "=" * 70)
    print("LOAD TEST SUMMARY RESULTS")
    print("=" * 70)
    print(f"{'Concurrency':<12} | {'Requests':<10} | {'Throughput (rps)':<18} | {'p50 (ms)':<10} | {'p95 (ms)':<10} | {'Success':<8}")
    print("-" * 75)
    for r in results:
        print(f"{r['concurrency']:<12} | {r['total_requests']:<10} | {r['throughput_rps']:<18} | {r['p50_ms']:<10} | {r['p95_ms']:<10} | {r['success_rate_pct']}%")
    print("=" * 70)


if __name__ == "__main__":
    asyncio.run(main())
