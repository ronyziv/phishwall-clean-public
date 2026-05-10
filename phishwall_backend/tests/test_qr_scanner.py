"""QR scanner tests.

QR_PNG_BASE64 is a real QR code that decodes to https://phish.example/login —
that's why several assertions check for that exact string in the output.
"""

import unittest

from scanners.qr_scanner import scan_qr_attachments, scan_qr_linked_resources


QR_PNG_BASE64 = (
    "iVBORw0KGgoAAAANSUhEUgAAAXIAAAFyAQAAAADAX2ykAAACe0lEQVR4nO2aTWrkMBCFX40MWco36KNIN5gzzc2so+QAAXkZkHmzKMl203QyAcdjzZSgja3+Fg+KkupPiK+s9ONLOGC88cYbb7zxxj/jpa4BSCICzNtb+y+eqMf4g/lAksyARABIt6L7EuFIkrznv1uP8Qfzc/VQTp5EyIsgZIATAHXsc/UY/138PEBkdJQI95g8XV+/8R/xEv276Gsal3br/j09xh/De5IT6oGM8Cp6PgMASJaz9Rh/DF8v1qQ+6yDh9YUCuNIei5ypx/hjebXvds9SQ2f/LkwjBPD3d/DV9Bv/J7zEedCHhs6Ao0RfsyKJmxNfU7/xT1dNbj2JwKKfnHyB7gGONWciyelq+o3/ZDX7FpDZqZFraLXZPANm3y75at+QAbXlpFnvmvr6ovFzdeyr6Tf+k9UOZFL9V/cyoId02N7Mvh3z8wCRW/VViQAQsiPSeO/OV9Vv/JPFdUHN6O/dWSMt899O+Wbf3NpEIdeC1a6cVS9hs2/H/KJdX06+QOIu/3VauJR4rh7jD+FbffJnGQBtLTgijW8DwgTUssb8QjlHj/HH8i0/0qPZkROcdvpbz2HNie187pDfFaw0qppWq9aoqsZXdv92yWMfVenD7T51hTXGNvt2yWuFGZ4UGdf/Wla0Te9cVb/xH/Pb/CSZF0G6kUgjUCcpb9bf75tf5yeRbqUaOWz1Datf9crf9Rda/2gXUwOw+/cf4vlrdEQaF0Ea19Gr2eZjO+Uf/BcA9p9rp9/y3x755pieAOY6iaWjdTp/NQ8gsAw8R4/xx/JtfkOXWyc5Wv67ObH5b4/8w/yk/jzRRidL2ztFj/HGG2+88cb/D/xv2PXoukJwe74AAAAASUVORK5CYII="
)


class QrScannerTests(unittest.TestCase):
    def test_decodes_qr_from_png_attachment(self):
        result = scan_qr_attachments(
            [{"filename": "invite.png", "mimeType": "image/png", "contentBase64": QR_PNG_BASE64}]
        )
        self.assertTrue(result["qrDetected"])
        self.assertEqual(result["decodedCount"], 1)
        self.assertGreater(result["riskPenalty"], 0)
        self.assertIn("https://phish.example/login", " ".join(result["decodedPayloads"]))

    def test_skips_non_image_attachment(self):
        # Same QR bytes, but as text/plain — the filename/mime gate should skip it
        # entirely and never reach the decoder.
        result = scan_qr_attachments(
            [{"filename": "notes.txt", "mimeType": "text/plain", "contentBase64": QR_PNG_BASE64}]
        )
        self.assertFalse(result["qrDetected"])
        self.assertEqual(result["decodedCount"], 0)
        self.assertEqual(result["riskPenalty"], 0)

    def test_qr_link_candidate_adds_stronger_than_normal_signal(self):
        result = scan_qr_linked_resources(["https://example.com/qr-challenge.png"], fetcher=lambda _: None)
        self.assertTrue(result["qrLinkedDetected"])
        self.assertGreater(result["riskPenalty"], 0)
        findings_text = " ".join(result["findings"]).lower()
        self.assertIn("qr-related linked resource detected", findings_text)

    def test_qr_link_decoding_from_fetched_resource(self):
        # Inject a fetcher that returns our QR PNG bytes, so the test stays offline
        # but still exercises the full fetch -> decode -> finding path.
        result = scan_qr_linked_resources(
            ["https://example.com/qr/challenge"],
            fetcher=lambda _: __import__("base64").b64decode(QR_PNG_BASE64),
        )
        self.assertTrue(result["qrLinkedDetected"])
        self.assertGreater(result["linkedDecodedCount"], 0)
        self.assertIn("https://phish.example/login", " ".join(result["linkedDecodedPayloads"]))


if __name__ == "__main__":
    unittest.main()
