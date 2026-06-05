import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from main import _find_credentials_file, analyze_link, extract_links, scan_email_body


class ScannerTests(unittest.TestCase):
    def test_extracts_plain_and_html_links(self):
        body = """
        Visit https://example.com.
        <a href="http://192.168.1.5/login">secure portal</a>
        <a href="https://safe.example.org">https://visible.example.org</a>
        """

        links = extract_links(body)

        self.assertIn("https://example.com", links)
        self.assertIn("http://192.168.1.5/login", links)
        self.assertIn("https://safe.example.org", links)
        self.assertIn("https://visible.example.org", links)

    def test_flags_high_risk_ip_login_link(self):
        finding = analyze_link("http://192.168.1.5/login?account=verify")

        self.assertEqual("high", finding.level)
        self.assertIn("uses plain HTTP", finding.reasons)
        self.assertIn("uses an IP address instead of a domain", finding.reasons)

    def test_flags_shortener_as_medium_risk(self):
        finding = analyze_link("https://bit.ly/update-payment")

        self.assertEqual("medium", finding.level)
        self.assertIn("uses a URL shortener", finding.reasons)

    def test_safe_link_has_minimal_score(self):
        finding = analyze_link("https://docs.python.org/3/library/urllib.parse.html")

        self.assertEqual("minimal", finding.level)
        self.assertEqual([], finding.reasons)

    def test_scan_email_body_returns_findings_for_each_link(self):
        findings = scan_email_body("Reset here: https://security-paypal.com/verify")

        self.assertEqual(1, len(findings))
        self.assertGreater(findings[0].score, 0)

    def test_finds_default_google_client_secret_file(self):
        with TemporaryDirectory() as temp_dir:
            credentials_file = Path(temp_dir) / "client_secret_123.apps.googleusercontent.com.json"
            credentials_file.write_text("{}", encoding="utf-8")

            self.assertEqual(credentials_file, _find_credentials_file(Path(temp_dir)))


if __name__ == "__main__":
    unittest.main()
