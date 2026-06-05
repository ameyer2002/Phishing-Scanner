import argparse
import base64
import html
import json
import re
from dataclasses import dataclass, field
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse


GMAIL_SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]

SUSPICIOUS_TLDS = {
    "biz",
    "click",
    "country",
    "gq",
    "info",
    "link",
    "loan",
    "mov",
    "rest",
    "ru",
    "tk",
    "top",
    "work",
    "zip",
}

URL_SHORTENERS = {
    "bit.ly",
    "buff.ly",
    "cutt.ly",
    "goo.gl",
    "is.gd",
    "lnkd.in",
    "ow.ly",
    "rebrand.ly",
    "s.id",
    "t.co",
    "tinyurl.com",
}

PHISHING_TERMS = {
    "account",
    "bank",
    "confirm",
    "login",
    "password",
    "payment",
    "secure",
    "signin",
    "suspended",
    "update",
    "verify",
    "wallet",
}

URL_RE = re.compile(r"https?://[^\s<>'\")]+", re.IGNORECASE)
HREF_RE = re.compile(r"<a\b[^>]*?\bhref=[\"']([^\"']+)[\"'][^>]*>(.*?)</a>", re.IGNORECASE | re.DOTALL)


@dataclass
class LinkFinding:
    url: str
    score: int
    reasons: list[str] = field(default_factory=list)

    @property
    def level(self) -> str:
        if self.score >= 70:
            return "high"
        if self.score >= 40:
            return "medium"
        if self.score >= 15:
            return "low"
        return "minimal"


@dataclass
class EmailFinding:
    message_id: str
    subject: str
    sender: str
    date: str
    links: list[LinkFinding]

    @property
    def risky_links(self) -> list[LinkFinding]:
        return [link for link in self.links if link.score >= 15]


def extract_links(body: str) -> list[str]:
    links = []
    for href, text in HREF_RE.findall(body):
        clean_href = html.unescape(href).strip()
        clean_text = re.sub(r"<[^>]+>", "", html.unescape(text)).strip()
        if clean_href.startswith(("http://", "https://")):
            links.append(clean_href)
        if clean_text.startswith(("http://", "https://")):
            links.append(clean_text)

    links.extend(html.unescape(match.group(0)).rstrip(".,;:!?]") for match in URL_RE.finditer(body))
    return sorted(set(links))


def analyze_link(url: str) -> LinkFinding:
    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower().strip(".")
    path_and_query = unquote(f"{parsed.path}?{parsed.query}").lower()
    labels = [label for label in hostname.split(".") if label]
    score = 0
    reasons = []

    if parsed.scheme == "http":
        score += 20
        reasons.append("uses plain HTTP")

    if parsed.username or "@" in parsed.netloc:
        score += 35
        reasons.append("contains userinfo or @ in the address")

    if _looks_like_ip(hostname):
        score += 40
        reasons.append("uses an IP address instead of a domain")

    if hostname.startswith("xn--") or ".xn--" in hostname:
        score += 25
        reasons.append("uses punycode characters")

    if hostname in URL_SHORTENERS:
        score += 25
        reasons.append("uses a URL shortener")

    if labels and labels[-1] in SUSPICIOUS_TLDS:
        score += 20
        reasons.append(f"uses a commonly abused .{labels[-1]} domain")

    if len(labels) >= 5:
        score += 15
        reasons.append("has many nested subdomains")

    if any(term in hostname or term in path_and_query for term in PHISHING_TERMS):
        score += 15
        reasons.append("contains phishing-prone account/security words")

    if "%" in url or len(url) > 180:
        score += 10
        reasons.append("is encoded or unusually long")

    if _has_lookalike_delimiters(hostname):
        score += 10
        reasons.append("uses a domain pattern that can impersonate brands")

    return LinkFinding(url=url, score=min(score, 100), reasons=reasons)


def scan_email_body(body: str) -> list[LinkFinding]:
    return [analyze_link(url) for url in extract_links(body)]


def scan_gmail(max_results: int, query: str, login_hint: str | None = None) -> list[EmailFinding]:
    print(f"Connecting to Gmail with query {query!r}...", flush=True)
    service = _build_gmail_service(login_hint=login_hint)
    response = service.users().messages().list(userId="me", q=query, maxResults=max_results).execute()
    messages = response.get("messages", [])
    findings = []
    print(f"Found {len(messages)} message(s). Scanning links...", flush=True)

    for message in messages:
        payload = service.users().messages().get(userId="me", id=message["id"], format="full").execute()
        headers = _headers_to_dict(payload.get("payload", {}).get("headers", []))
        body = _message_body(payload.get("payload", {}))
        links = scan_email_body(body)
        if links:
            findings.append(
                EmailFinding(
                    message_id=message["id"],
                    subject=headers.get("subject", "(no subject)"),
                    sender=headers.get("from", "(unknown sender)"),
                    date=_format_date(headers.get("date", "")),
                    links=links,
                )
            )

    return findings


def print_report(findings: list[EmailFinding], show_all: bool) -> None:
    risky_messages = [finding for finding in findings if show_all or finding.risky_links]
    if not risky_messages:
        print("No suspicious links found.")
        return

    for finding in risky_messages:
        print("=" * 72)
        print(f"Subject: {finding.subject}")
        print(f"From:    {finding.sender}")
        print(f"Date:    {finding.date}")
        print(f"ID:      {finding.message_id}")
        links = finding.links if show_all else finding.risky_links
        for link in sorted(links, key=lambda item: item.score, reverse=True):
            reason_text = "; ".join(link.reasons) if link.reasons else "no obvious phishing signals"
            print(f"  [{link.level.upper():7}] {link.score:3}/100 {link.url}")
            print(f"           {reason_text}")


def _build_gmail_service(login_hint: str | None = None) -> Any:
    try:
        from google.auth.transport.requests import Request
        from google.oauth2.credentials import Credentials
        from google_auth_oauthlib.flow import InstalledAppFlow
        from googleapiclient.discovery import build
    except ImportError as exc:
        raise SystemExit(
            "Missing Gmail dependencies. Install them with:\n"
            "python -m pip install -r requirements.txt"
        ) from exc

    creds = None
    try:
        creds = Credentials.from_authorized_user_file("token.json", GMAIL_SCOPES)
    except FileNotFoundError:
        pass

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            print("Refreshing saved Gmail authorization...", flush=True)
            creds.refresh(Request())
        else:
            credentials_file = _find_credentials_file()
            print(f"Starting Gmail OAuth with {credentials_file.name}...", flush=True)
            print("A browser window should open so you can approve read-only Gmail access.", flush=True)
            flow = InstalledAppFlow.from_client_secrets_file(str(credentials_file), GMAIL_SCOPES)
            auth_kwargs = {"login_hint": login_hint} if login_hint else {}
            creds = flow.run_local_server(port=0, **auth_kwargs)
        with open("token.json", "w", encoding="utf-8") as token_file:
            token_file.write(creds.to_json())

    return build("gmail", "v1", credentials=creds)


def _find_credentials_file(base_dir: Path = Path(".")) -> Path:
    exact_match = base_dir / "credentials.json"
    if exact_match.exists():
        return exact_match

    matches = sorted(base_dir.glob("client_secret*.json"))
    if matches:
        return matches[0]

    raise SystemExit(
        "Missing Gmail OAuth credentials.\n"
        "Download your OAuth desktop-client JSON from Google Cloud and put it in this folder as "
        "credentials.json, or leave its default client_secret*.json filename."
    )


def _message_body(payload: dict[str, Any]) -> str:
    chunks = []
    stack = [payload]
    while stack:
        part = stack.pop()
        mime_type = part.get("mimeType", "")
        body_data = part.get("body", {}).get("data")
        if body_data and mime_type in {"text/plain", "text/html"}:
            chunks.append(_decode_base64url(body_data))
        stack.extend(part.get("parts", []))
    return "\n".join(chunks)


def _decode_base64url(data: str) -> str:
    padded = data + "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(padded.encode("utf-8")).decode("utf-8", errors="replace")


def _headers_to_dict(headers: list[dict[str, str]]) -> dict[str, str]:
    return {header.get("name", "").lower(): header.get("value", "") for header in headers}


def _format_date(raw_date: str) -> str:
    try:
        return parsedate_to_datetime(raw_date).isoformat()
    except (TypeError, ValueError):
        return raw_date or "(unknown date)"


def _looks_like_ip(hostname: str) -> bool:
    octets = hostname.split(".")
    return len(octets) == 4 and all(octet.isdigit() and 0 <= int(octet) <= 255 for octet in octets)


def _has_lookalike_delimiters(hostname: str) -> bool:
    return bool(re.search(r"(paypal|apple|microsoft|google|amazon|gmail|chase|venmo|zelle)[.-]", hostname))


def main() -> None:
    parser = argparse.ArgumentParser(description="Scan Gmail messages for potentially suspicious links.")
    parser.add_argument("--max", type=int, default=25, help="maximum Gmail messages to scan")
    parser.add_argument("--query", default="newer_than:7d", help="Gmail search query to scan")
    parser.add_argument("--all-links", action="store_true", help="show links with no obvious risk signals too")
    parser.add_argument("--json", action="store_true", help="print machine-readable JSON")
    parser.add_argument("--login-hint", help="email address to suggest during Google OAuth")
    args = parser.parse_args()

    findings = scan_gmail(max_results=args.max, query=args.query, login_hint=args.login_hint)
    if args.json:
        print(json.dumps(findings, default=lambda item: item.__dict__, indent=2))
    else:
        print_report(findings, show_all=args.all_links)


if __name__ == "__main__":
    main()
