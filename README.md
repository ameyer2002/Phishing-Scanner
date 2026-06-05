# Gmail Phishing Link Scanner

CLI phishing scanner in Python using the Gmail API.

This tool scans recent Gmail messages, extracts links, and scores them for common phishing signals such as plain HTTP, IP-address links, URL shorteners, suspicious top-level domains, punycode, long encoded URLs, and account/security language.

## Setup

1. Install dependencies:

   ```powershell
   python -m pip install -r requirements.txt
   ```

2. Create Gmail OAuth credentials:

   - Go to Google Cloud Console.
   - Create a project.
   - Enable the Gmail API.
   - Configure an OAuth consent screen.
   - If the app is in Testing mode, add your Gmail address under Audience/Test users.
   - Add the Gmail read-only scope: `https://www.googleapis.com/auth/gmail.readonly`.
   - Create an OAuth client ID for a desktop app.
   - Download the client secret file as `credentials.json`.
   - Place it in this folder. You can name it `credentials.json` or keep Google's default `client_secret_...json` filename.
   - Do not commit that file. The project `.gitignore` excludes `credentials.json`, `client_secret*.json`, and `token.json`.

3. Run the scanner:

   ```powershell
   python main.py --max 25 --query "newer_than:7d"
   ```

If your browser is signed into multiple Google accounts, pass the account you added as a test user:

```powershell
python main.py --max 25 --query "newer_than:7d" --login-hint "you@gmail.com"
```

The first run opens a browser for Google login and creates `token.json`. The app requests read-only Gmail access.

## Security

OAuth credential files and `token.json` are private local files. `token.json` can contain a refresh token, so treat it like a password.

This repo includes `credentials.example.json` only as a safe template. To set up your own local credentials, download your OAuth desktop-client JSON from Google Cloud and save it as `credentials.json`, or keep the default `client_secret_...json` filename.

## Useful Commands

Show every extracted link, including links with no obvious risk signals:

```powershell
python main.py --all-links
```

Return JSON:

```powershell
python main.py --json
```

Run tests:

```powershell
python -m unittest discover -p *_test.py
```

## Notes

This is a heuristic scanner, not a guarantee. Treat high-risk findings as "inspect carefully" rather than proof that a message is malicious.

## 403 Access Fixes

If the browser opens but Google shows a 403 access error:

- Make sure you are signing in with the same email address you added as a test user on the OAuth consent screen.
- In Google Cloud Console, open your project, then go to OAuth consent screen. If publishing status is Testing, add your Gmail address under Audience/Test users.
- Confirm the Gmail API is enabled for the same project that created your OAuth client JSON.
- Confirm the consent screen includes `https://www.googleapis.com/auth/gmail.readonly`.
- If your browser is defaulting to the wrong Google account, run with `--login-hint "you@gmail.com"`.
- If this is a school/work Google Workspace account, your admin may block unverified apps or Gmail scopes. Use a personal Gmail account or ask the admin to allow the app.
- After changing OAuth settings, delete `token.json` if it exists and run the scanner again.
