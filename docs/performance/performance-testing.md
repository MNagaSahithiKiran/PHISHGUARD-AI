# Performance Benchmarking & Load Testing Report

## 1. Methodology & Environmental Parameters
Micro-benchmarks and concurrent load testing were executed using Python 3.11/3.13 and `httpx` asynchronous clients.
* **Hardware**: x86_64, Windows host, local loopback.
* **Test Scope**:
  1. URL Lexical Feature Extraction (150 iterations on diverse legitimate & phishing URLs).
  2. DOM & HTML Heuristic Analysis (30 iterations on complex phishing forms).
  3. Database Indexed Queries (30 iterations of parameterized email lookup).
  4. Concurrent Load Testing (10, 25, 50 concurrency levels, 850 total HTTP requests).

---

## 2. Micro-Benchmark Latency Results

| Subsystem Component | Sample Size | Mean (ms) | p50 (ms) | p95 (ms) | p99 (ms) | Target SLA |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **URL Lexical Extraction** | 150 | 0.044 ms | 0.042 ms | 0.060 ms | 0.137 ms | $< 5.0\text{ ms}$ |
| **DOM / HTML Parsing** | 30 | 1.370 ms | 1.315 ms | 1.699 ms | 1.738 ms | $< 25.0\text{ ms}$ |
| **Database Indexed Query** | 30 | 1.057 ms | 0.897 ms | 1.532 ms | 3.538 ms | $< 10.0\text{ ms}$ |

---

## 3. Concurrent Load Testing Results

| Concurrency Level | Total Requests | Throughput (Req/s) | p50 Latency (ms) | p95 Latency (ms) | Error Count | Success Rate |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **10 Workers** | 100 | **230.01 req/s** | 38.95 ms | 58.74 ms | 0 | **100.0%** |
| **25 Workers** | 250 | **264.78 req/s** | 86.40 ms | 145.58 ms | 0 | **100.0%** |
| **50 Workers** | 500 | **255.31 req/s** | 168.69 ms | 427.05 ms | 0 | **100.0%** |

* Observations: Throughput scales up to $\approx 265\text{ req/s}$ on a single Uvicorn process. Sub-100ms p50 latency is maintained under moderate concurrency (up to 25 workers).
