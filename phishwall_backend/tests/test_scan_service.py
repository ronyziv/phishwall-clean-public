import unittest

from services.scan_service import analyze_email, normalize_urls


class ScanServiceTests(unittest.TestCase):
    def test_normalize_urls_falls_back_to_body_extraction(self):
        body = "Please review https://example.com/path and http://a.co now."
        urls = normalize_urls([], body)
        self.assertEqual(
            urls,
            ["https://example.com/path", "http://a.co"],
        )

    def test_analyze_email_returns_expected_top_level_fields(self):
        payload = {
            "subject": "Weekly update",
            "from": "noreply@example.com",
            "body": "Hello team",
            "body_snippet": "Hello team",
            "urls": [],
            "attachments": [],
        }
        result = analyze_email(payload)

        for key in [
            "score",
            "maliciousScore",
            "verdict",
            "riskIndicators",
            "infoFindings",
            "scoreBreakdown",
            "attachmentSummary",
            "urlSummary",
            "senderSummary",
            "languageSummary",
            "timeSummary",
        ]:
            self.assertIn(key, result)

    def test_score_breakdown_consistency(self):
        payload = {
            "subject": "Report",
            "from": "alerts@example.com",
            "body": "Open https://example.com/report",
            "body_snippet": "Open report",
            "urls": ["https://example.com/report"],
            "attachments": [],
        }
        result = analyze_email(payload)

        self.assertEqual(result["maliciousScore"], 100 - result["score"])
        self.assertEqual(result["scoreBreakdown"]["totalPenalty"], 100 - result["score"])


if __name__ == "__main__":
    unittest.main()
