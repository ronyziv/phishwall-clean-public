import unittest

from services.scan_service import analyze_email, normalize_urls
from scanners.lookalike_domain_scanner import BRANDS


class ScanServiceTests(unittest.TestCase):
    def test_impersonation_target_catalog_size(self):
        self.assertGreaterEqual(len(BRANDS), 150)

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
            "verdictReasoning",
            "recommendation",
            "riskIndicators",
            "infoFindings",
            "reasons",
            "scoreBreakdown",
            "attachmentSummary",
            "urlSummary",
            "senderSummary",
            "languageSummary",
            "timeSummary",
            "qrSummary",
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

    def test_detects_display_name_brand_domain_mismatch(self):
        payload = {
            "subject": "Security alert",
            "from": "PayPal Security <notice@paypa1-support-secure.com>",
            "body": "Please verify your account now.",
            "body_snippet": "",
            "urls": [],
            "attachments": [],
        }
        result = analyze_email(payload)
        findings_text = " ".join(result["riskIndicators"]).lower()
        self.assertIn("display name references", findings_text)
        self.assertGreater(result["scoreBreakdown"]["sender"], 0)

    def test_detects_disguised_attachment_filename(self):
        payload = {
            "subject": "Invoice attached",
            "from": "billing@example.com",
            "body": "Please open attachment.",
            "body_snippet": "",
            "urls": [],
            "attachments": [
                {"filename": "invoice.pdf.exe", "mimeType": "application/octet-stream", "contentBase64": ""}
            ],
        }
        result = analyze_email(payload)
        findings_text = " ".join(result["riskIndicators"]).lower()
        self.assertIn("disguised attachment filename pattern", findings_text)
        self.assertIn("executable attachment detected", findings_text)
        self.assertEqual(result["verdict"], "Dangerous / Do Not Open")
        self.assertIn("do not open this email", result["recommendation"].lower())

    def test_detects_qr_payload_from_image_attachment(self):
        qr_png_base64 = (
            "iVBORw0KGgoAAAANSUhEUgAAAXIAAAFyAQAAAADAX2ykAAACe0lEQVR4nO2aTWrkMBCFX40MWco36KNIN5gzzc2so+QAAXkZkHmzKMl203QyAcdjzZSgja3+Fg+KkupPiK+s9ONLOGC88cYbb7zxxj/jpa4BSCICzNtb+y+eqMf4g/lAksyARABIt6L7EuFIkrznv1uP8Qfzc/VQTp5EyIsgZIATAHXsc/UY/138PEBkdJQI95g8XV+/8R/xEv276Gsal3br/j09xh/De5IT6oGM8Cp6PgMASJaz9Rh/DF8v1qQ+6yDh9YUCuNIei5ypx/hjebXvds9SQ2f/LkwjBPD3d/DV9Bv/J7zEedCHhs6Ao0RfsyKJmxNfU7/xT1dNbj2JwKKfnHyB7gGONWciyelq+o3/ZDX7FpDZqZFraLXZPANm3y75at+QAbXlpFnvmvr6ovFzdeyr6Tf+k9UOZFL9V/cyoId02N7Mvh3z8wCRW/VViQAQsiPSeO/OV9Vv/JPFdUHN6O/dWSMt899O+Wbf3NpEIdeC1a6cVS9hs2/H/KJdX06+QOIu/3VauJR4rh7jD+FbffJnGQBtLTgijW8DwgTUssb8QjlHj/HH8i0/0qPZkROcdvpbz2HNie187pDfFaw0qppWq9aoqsZXdv92yWMfVenD7T51hTXGNvt2yWuFGZ4UGdf/Wla0Te9cVb/xH/Pb/CSZF0G6kUgjUCcpb9bf75tf5yeRbqUaOWz1Datf9crf9Rda/2gXUwOw+/cf4vlrdEQaF0Ea19Gr2eZjO+Uf/BcA9p9rp9/y3x755pieAOY6iaWjdTp/NQ8gsAw8R4/xx/JtfkOXWyc5Wv67ObH5b4/8w/yk/jzRRidL2ztFj/HGG2+88cb/D/xv2PXoukJwe74AAAAASUVORK5CYII="
        )
        payload = {
            "subject": "Monthly benefits newsletter",
            "from": "support@example.com",
            "body": "See attached image for event entry.",
            "body_snippet": "event entry details",
            "urls": [],
            "attachments": [
                {"filename": "event-pass.png", "mimeType": "image/png", "contentBase64": qr_png_base64}
            ],
        }
        result = analyze_email(payload)
        findings_text = " ".join(result["riskIndicators"]).lower()
        self.assertIn("decoded qr", findings_text)
        self.assertTrue(result["qrSummary"]["qrDetected"])
        self.assertGreater(result["scoreBreakdown"]["qr"], 0)

    def test_qr_related_link_gets_stronger_signal(self):
        payload = {
            "subject": "Security verification",
            "from": "alerts@example.com",
            "body": "Open the challenge link.",
            "body_snippet": "",
            "urls": ["https://example.com/qr-challenge.png"],
            "attachments": [],
        }
        result = analyze_email(payload)
        self.assertGreater(result["scoreBreakdown"]["qr"], 0)
        findings_text = " ".join(result["riskIndicators"]).lower()
        self.assertIn("qr-related linked resource", findings_text)

    def test_bec_not_fully_detected_when_only_lexical_signals_missing(self):
        """Casual message + Gmail + display-brand mismatch must not satisfy multi-signal BEC."""
        payload = {
            "subject": "Look at this",
            "from": "Microsoft Alerts <classmate@gmail.com>",
            "body": "Hi, check the attachments for class.",
            "body_snippet": "",
            "urls": [],
            "attachments": [],
        }
        result = analyze_email(payload)
        self.assertFalse(result["priorityThreatSummary"]["becDetected"])

    def test_detects_bec_pattern_with_finance_and_pressure(self):
        payload = {
            "subject": "Confidential: urgent wire transfer today",
            "from": "CFO Office <cfo-finance-alert@secure-payments-check.com>",
            "body": "Please process this payment immediately. Keep this confidential and reply only by email.",
            "body_snippet": "",
            "urls": [],
            "attachments": [],
        }
        result = analyze_email(payload)
        findings_text = " ".join(result["riskIndicators"]).lower()
        self.assertIn("bec-style pattern", findings_text)
        self.assertTrue(result["priorityThreatSummary"]["becDetected"])


if __name__ == "__main__":
    unittest.main()
