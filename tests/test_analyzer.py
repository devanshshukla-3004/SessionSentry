import unittest
from sessionsentry.analyzer import analyze_assessment


class AnalyzerTests(unittest.TestCase):
    def test_secure_configuration_has_no_findings(self):
        result = analyze_assessment({
            "application": "test",
            "cookies": [{"name": "session", "purpose": "session", "secure": True, "httpOnly": True, "sameSite": "Lax"}],
            "session_config": {"rotation_on_login": True, "idle_timeout_minutes": 20, "absolute_timeout_minutes": 480, "logout_invalidates_session": True},
        })
        self.assertEqual(result["finding_count"], 0)
        self.assertEqual(result["risk_score"], 0)

    def test_flags_weak_cookie_and_session_settings(self):
        result = analyze_assessment({
            "cookies": [{"name": "session_id", "purpose": "session", "secure": False, "httpOnly": False, "sameSite": "None"}],
            "session_config": {"rotation_on_login": False, "idle_timeout_minutes": 90, "absolute_timeout_minutes": 1440, "logout_invalidates_session": False},
        })
        rule_ids = {item["rule_id"] for item in result["findings"]}
        self.assertTrue({"SS-101", "SS-102", "SS-104", "SS-201", "SS-202", "SS-203", "SS-204"}.issubset(rule_ids))
        self.assertLessEqual(result["risk_score"], 100)

    def test_non_session_cookie_is_not_audited_as_session(self):
        result = analyze_assessment({
            "cookies": [{"name": "theme", "purpose": "preference", "secure": False}],
            "session_config": {"rotation_on_login": True, "idle_timeout_minutes": 15, "absolute_timeout_minutes": 120, "logout_invalidates_session": True},
        })
        self.assertFalse(any(item["rule_id"] in {"SS-101", "SS-102"} for item in result["findings"]))

    def test_invalid_cookies_shape_is_rejected(self):
        with self.assertRaises(ValueError):
            analyze_assessment({"cookies": "not-a-list"})

    def test_unknown_configuration_is_not_assumed_safe(self):
        result = analyze_assessment({"cookies": [{"name": "session", "purpose": "session"}], "session_config": {}})
        self.assertGreater(result["finding_count"], 0)


if __name__ == "__main__":
    unittest.main()
