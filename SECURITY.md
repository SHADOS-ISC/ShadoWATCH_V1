# Security policy

## Reporting a vulnerability
Please do **not** open a public issue for security problems. Report privately through
GitHub's "Report a vulnerability" button (Security tab) or by email to the maintainer.
You will get an acknowledgement within 7 days.

## Operating ShadoWATCH safely
- **Read-only credentials.** Create a dedicated MISP user with a read-only role and an
  OpenCTI user that can only read. The dashboard never writes to either platform.
- **Keep secrets out of the repo.** Keys live only in an environment file readable by the
  service account (`chmod 600`). Rotate any key that was ever pasted into a chat, a ticket or a log.
- **Restrict who can open the page.** The generated HTML and `cti.json` contain threat data and
  have no login. Limit access by IP in your web server (for example Apache `Require ip`) or
  put the files behind your SSO/reverse proxy.
- **Use TLS** for MISP and OpenCTI in production and verify certificates. Disabling verification
  is acceptable only in a lab.
- **IOCs are shown defanged** (`hxxp`, `[.]`) to prevent accidental clicks. Copying a value copies the original.
- **No data leaves your network.** The page is self-contained (no CDN, no external fonts or scripts).

## Supported versions
Only the latest release receives fixes.
