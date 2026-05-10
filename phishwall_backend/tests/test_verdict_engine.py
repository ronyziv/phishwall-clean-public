"""Verdict engine tests focused on the mailbox-familiarity moderation path."""

import unittest

from services.verdict_engine import build_verdict


class VerdictEngineTrustTests(unittest.TestCase):
    def _soft_bec_spoof_fixture(self, malicious_score: int):
        # Borderline scenario: BEC detected + display-name spoof, no hard blockers.
        # Whether this lands as Suspicious vs Dangerous should depend on prior history.
        return dict(
            malicious_score=malicious_score,
            keyword_penalty=0,
            sender_summary={"ipqsFlagged": 0, "vtFlagged": 0},
            url_summary={"ipqsFlagged": 0, "gsbFlagged": 0},
            attachment_summary={"executableCount": 0},
            qr_summary={"qrDetected": False},
            priority_threat_summary={"becDetected": True},
            risk_indicators=[
                "Display name references 'X' but sender domain 'gmail.com' does not match known domains."
            ],
        )

    def test_familiar_mailbox_moderates_mid_score_bec_combo_to_suspicious(self):
        vd = build_verdict(
            sender_prior_thread_count=8,
            **self._soft_bec_spoof_fixture(52),
        )
        self.assertEqual(vd["verdict"], "Suspicious")
        self.assertTrue(vd["familiarSenderCalibration"])

    def test_same_signals_without_history_stays_more_severe(self):
        vd = build_verdict(
            sender_prior_thread_count=0,
            **self._soft_bec_spoof_fixture(52),
        )
        self.assertEqual(vd["verdict"], "Dangerous / Do Not Open")
        self.assertFalse(vd["familiarSenderCalibration"])

    def test_familiarity_does_not_overrule_executable(self):
        # Hard blockers (executable, disguised name, VT-flagged sender) must always
        # land Dangerous regardless of how much history the mailbox has.
        vd = build_verdict(
            sender_prior_thread_count=20,
            malicious_score=65,
            keyword_penalty=0,
            sender_summary={"ipqsFlagged": 0, "vtFlagged": 0},
            url_summary={"ipqsFlagged": 0, "gsbFlagged": 0},
            attachment_summary={"executableCount": 1},
            qr_summary={"qrDetected": False},
            priority_threat_summary={"becDetected": False},
            risk_indicators=["Executable attachment detected: run.exe"],
        )
        self.assertEqual(vd["verdict"], "Dangerous / Do Not Open")

    def test_familiarity_disabled_when_url_reputation_flags(self):
        # Same as above, but the blocker is a remote URL reputation hit instead of
        # an attachment — familiarity calibration must still be off.
        vd = build_verdict(
            sender_prior_thread_count=20,
            malicious_score=52,
            keyword_penalty=0,
            sender_summary={"ipqsFlagged": 0, "vtFlagged": 0},
            url_summary={"ipqsFlagged": 1, "gsbFlagged": 0},
            attachment_summary={"executableCount": 0},
            qr_summary={"qrDetected": False},
            priority_threat_summary={"becDetected": True},
            risk_indicators=["Display name references 'X' but sender domain 'gmail.com' does not match."],
        )
        self.assertEqual(vd["verdict"], "Dangerous / Do Not Open")


if __name__ == "__main__":
    unittest.main()
