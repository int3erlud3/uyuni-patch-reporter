# Security Policy

## Reporting a vulnerability

Please do **not** open a public issue for security problems. Use GitHub's
[private vulnerability reporting](../../security/advisories/new) for this repository
instead. You can expect an initial response within 7 days.

## Security review notes

- Read-only: the client refuses every API method outside a small allow-list of
  `list*`/`get*` calls, and the session is always logged out.
- Credentials come only from environment variables or a `0600` password file. There are no
  command-line options for credentials, and the password is masked in `repr()` and error
  messages.
- TLS verification (certificate and host name, TLS 1.2+) cannot be disabled. A private CA can
  be configured with `UYUNI_CA_FILE`.
- The XML-RPC parser is hardened with defusedxml.
- Output is safe for terminals (control characters are neutralised) and spreadsheets (CSV
  formula injection is prevented). Files are written with `O_NOFOLLOW` and mode `0640`.
- CI runs ruff, pytest, bandit, pip-audit and gitleaks. Actions are pinned to commit SHAs and run
  with `contents: read`.
