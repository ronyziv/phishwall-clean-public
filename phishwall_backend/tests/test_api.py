import unittest

from fastapi.testclient import TestClient

from main import app


class ApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def test_health_endpoint(self):
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"status": "ok"})

    def test_scan_endpoint_success(self):
        payload = {
            "subject": "Weekly review",
            "from": "noreply@example.com",
            "body": "Hello, review your dashboard at https://example.com/dashboard",
            "body_snippet": "Review your dashboard",
            "urls": ["https://example.com/dashboard"],
            "attachments": [],
        }

        response = self.client.post("/scan", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()

        for key in ["score", "maliciousScore", "verdict", "scoreBreakdown", "riskIndicators", "infoFindings"]:
            self.assertIn(key, data)

    def test_scan_endpoint_validation_error(self):
        invalid_payload = {
            "subject": "Bad payload",
            "from": "x@example.com",
            "body": "test",
            "attachments": "not-a-list",
        }

        response = self.client.post("/scan", json=invalid_payload)
        self.assertEqual(response.status_code, 422)
        body = response.json()
        self.assertEqual(body.get("error"), "Validation error")


if __name__ == "__main__":
    unittest.main()
