"""Wall-clock tests that verify the pipeline really runs scanners in parallel.

These rely on `time.sleep` rather than mocked futures so a regression that
serializes the pipeline (e.g. dropping the ThreadPoolExecutor) is actually
caught by CI instead of silently passing.
"""

import time
import unittest
from unittest.mock import patch

from scanners.base import ScanContext, ScannerResult
from scanners import url_scanner
from scanners.url_scanner import scan_urls
from services.scanner_pipeline import ScannerPipeline


class _SleepScanner:
    # Test double whose `run` blocks for `delay_s` so we can measure parallelism.
    def __init__(self, name: str, delay_s: float, breakdown_key: str, value: int = 3) -> None:
        self.name = name
        self._delay_s = delay_s
        self._breakdown_key = breakdown_key
        self._value = value

    def applies(self, context: ScanContext, state: dict) -> bool:
        return True

    def run(self, context: ScanContext, state: dict) -> ScannerResult:
        time.sleep(self._delay_s)
        return ScannerResult(
            name=self.name,
            breakdown={self._breakdown_key: self._value},
        )


class _RaisingScanner:
    # Test double that always raises — used to verify one scanner failing doesn't
    # poison the rest of the phase.
    name = "keywords"

    def applies(self, context: ScanContext, state: dict) -> bool:
        return True

    def run(self, context: ScanContext, state: dict) -> ScannerResult:
        raise RuntimeError("forced failure")


class ParallelExecutionTests(unittest.TestCase):
    def test_phase1_two_scanners_runs_near_parallel_wall_time(self) -> None:
        # Sleep large enough that parallel (~1×delay) and serial (~2×delay) are
        # distinguishable even on noisy CI.
        delay = 0.22
        pipe = ScannerPipeline(
            scanners=[
                _SleepScanner("keywords", delay, "keywords", 2),
                _SleepScanner("language", delay, "language", 2),
            ]
        )
        ctx = ScanContext(
            subject="s",
            sender="",
            body="body",
            body_snippet="",
            sent_at="",
        )
        t0 = time.perf_counter()
        out = pipe.run(ctx)
        elapsed = time.perf_counter() - t0

        self.assertGreaterEqual(out["breakdown"]["keywords"], 2)
        self.assertGreaterEqual(out["breakdown"]["language"], 2)

        # Lower bound: must take at least one delay (scheduling can dip slightly under).
        self.assertGreaterEqual(elapsed, delay * 0.85)
        # Upper bound: serial would be ~2×delay; we want closer to 1×delay.
        self.assertLess(elapsed, delay * 1.65)

    def test_phase1_parallel_one_scanner_raises_other_contributes(self) -> None:
        # When one scanner raises, its breakdown stays at 0 and its sibling's
        # output still merges into the aggregate.
        pipe = ScannerPipeline(
            scanners=[
                _RaisingScanner(),
                _SleepScanner("language", 0.01, "language", 4),
            ]
        )
        ctx = ScanContext(subject="", sender="", body="x", body_snippet="", sent_at="")
        out = pipe.run(ctx)

        self.assertEqual(out["breakdown"]["keywords"], 0)
        self.assertGreaterEqual(out["breakdown"]["language"], 4)
        # Pipeline must surface a friendly info finding for the failed stage.
        self.assertTrue(
            any("internal error" in (m or "").lower() for m in out["infoFindings"]),
            msg=out["infoFindings"],
        )

    def test_url_remote_reputation_batches_run_in_parallel(self) -> None:
        # Same idea, scoped to scan_urls' internal ThreadPoolExecutor.
        urls = [f"http://example{i}.test/path" for i in range(3)]
        delay = 0.12

        def _slow_safe_row(u: str):
            _ = u
            time.sleep(delay)
            return 0, 0, 0, []

        with patch.object(url_scanner, "_safe_remote_row", side_effect=_slow_safe_row):
            t0 = time.perf_counter()
            scan_urls(urls)
            elapsed = time.perf_counter() - t0

        # Three sequential calls would be ~3×delay; we want closer to 1×delay.
        self.assertLess(elapsed, delay * 2.5)
        self.assertGreaterEqual(elapsed, delay * 0.85)


if __name__ == "__main__":
    unittest.main()
