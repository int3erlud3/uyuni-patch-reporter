# uyuni-patch-reporter

[![CI](https://github.com/int3erlud3/uyuni-patch-reporter/actions/workflows/ci.yml/badge.svg)](https://github.com/int3erlud3/uyuni-patch-reporter/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.10%20%E2%80%93%203.13-blue)
![License: MIT](https://img.shields.io/badge/license-MIT-green)

A **read-only** patch compliance report for **Uyuni** and **SUSE Manager / SUSE Multi-Linux
Manager**. It reads the XML-RPC API and reports, for each registered system:

- pending patches by type: **security**, **bugfix** and **enhancement**, optionally with the
  severity of each security advisory (critical / important / moderate / low);
- **outdated** systems, i.e. systems with upgradable packages;
- systems where a **reboot is suggested** after updates;
- **stale** systems that have not checked in for N days.

Output is an aligned text table, JSON (for monitoring or automation) or CSV (for spreadsheets).
The tool cannot change anything: only an allow-list of read-only API methods can be called.

```text
                       _                _      _
   _  _ _  _ _  _ _ _ (_)___ _ __  __ _| |_ __| |_
  | || | || | || | ' \| |___| '_ \/ _` |  _/ _| ' \
   \_,_|\_, |\_,_|_||_|_|   | .__/\__,_|\__\__|_||_|
        |__/                |_|
                         _
   _ _ ___ _ __  ___ _ _| |_ ___ _ _
  | '_/ -_) '_ \/ _ \ '_|  _/ -_) '_|
  |_| \___| .__/\___/_|  \__\___|_|
          |_|

+====================================================================+
|  UYUNI PATCH REPORTER  ::  Uyuni / SUSE Manager Patch Audit        |
+--------------------------------------------------------------------+
|  Read-only report of pending patches, outdated and reboot systems  |
|  v1.0.0  -  Bastion Ops Toolkit  -  by int3erlud3                  |
+====================================================================+
```

## Example

```text
$ uyuni-patch-reporter --with-severity
Uyuni patch report - uyuni.example.com (API 25) - 2026-10-08T12:00:00+00:00
Systems: 4 | with security patches: 2 | outdated: 2 | reboot required: 1 | stale (>7d): 1
Pending: 3 security, 2 bugfix, 1 enhancement (2 distinct security advisories)

SYSTEM             ID          SECURITY   BUGFIX  ENHANCE  OTHER  TOTAL  OUTDATED  REBOOT  LAST CHECK-IN
web01.example.com  1000010001  2 (C1 I1)  1       1        0      4      yes       yes     2026-10-08 11:30
web02.example.com  1000010003  1 (I1)     0       0        1      2      yes       -       2026-09-20 08:00 STALE
db01.example.com   1000010002  0          1       0        0      1      -         -       2026-10-08 10:00
app01.example.com  1000010004  0          0       0        0      0      -         -       2026-10-08 09:00

Severity of security advisories: C critical, I important, M moderate, L low, U unspecified
```

(Synthetic data from the test suite.)

## Installation

```bash
python3 -m venv ~/.venvs/uyuni-patch-reporter
~/.venvs/uyuni-patch-reporter/bin/pip install git+https://github.com/int3erlud3/uyuni-patch-reporter.git
```

Requires Python 3.10+. The only runtime dependency is
[defusedxml](https://pypi.org/project/defusedxml/), which hardens the XML-RPC parser.

## Configuration

Credentials and the server come **only from environment variables**. There are no
command-line options for them, so they never show up in `ps` output or shell history.

| Variable | Description |
|---|---|
| `UYUNI_URL` | `https://uyuni.example.com` (the path `/rpc/api` is added). `https` is mandatory. |
| `UYUNI_USER` | API user. A dedicated account **without admin roles** is enough for reporting. |
| `UYUNI_PASSWORD_FILE` | File containing the password (must be mode `0600`). Preferred. |
| `UYUNI_PASSWORD` | The password itself, as an alternative. |
| `UYUNI_CA_FILE` | CA bundle if the server uses a private CA (e.g. the Uyuni `RHN-ORG-TRUSTED-SSL-CERT`). |
| `UYUNI_TIMEOUT` | Socket timeout in seconds (default 30). |

TLS certificate and host name verification are **always on**, with a minimum of TLS 1.2. There
is deliberately no `--insecure` option. If the server uses its own CA, point `UYUNI_CA_FILE` at
it, for example `/usr/share/rhn/RHN-ORG-TRUSTED-SSL-CERT` copied from a client.

The API user only sees systems it is allowed to manage, so the report covers exactly what the
account can see. Create a separate user for reporting rather than using an administrator
account.

## Usage

```text
uyuni-patch-reporter [-f table|json|csv] [-o FILE] [-s PATTERN ...] [--with-severity]
                     [--inactive-days N] [--fail-on never|security|reboot|outdated|any] [--no-banner]
```

```bash
export UYUNI_URL=https://uyuni.example.com UYUNI_USER=report-ro
export UYUNI_PASSWORD_FILE=~/.config/uyuni-report.pw UYUNI_CA_FILE=/etc/pki/uyuni-ca.pem

uyuni-patch-reporter                                   # table on stdout
uyuni-patch-reporter -s 'web*' -s 'db*' --with-severity
uyuni-patch-reporter -f csv -o patch-report.csv        # written with mode 0640, never follows symlinks
uyuni-patch-reporter -f json | jq '.systems[] | select(.reboot_required) | .name'
uyuni-patch-reporter -f json --fail-on security >/dev/null || echo "security patches pending"
```

| Exit code | Meaning |
|---|---|
| 0 | report produced (and the `--fail-on` condition is not met) |
| 1 | `--fail-on` condition met: security patches pending, reboot needed or systems outdated |
| 2 | usage or configuration error |
| 3 | API, TLS or connection error (e.g. wrong credentials, untrusted certificate) |

`--with-severity` makes one `errata.getDetails` call per distinct security advisory (cached).
Servers that do not report a severity show `unspecified`.

### JSON

```json
{
  "server": "uyuni.example.com",
  "api_version": "25",
  "generated_at": "2026-10-08T12:00:00+00:00",
  "summary": {"systems": 4, "with_security_patches": 2, "outdated": 2, "reboot_required": 1, "stale": 1, "...": "..."},
  "systems": [
    {"id": 1000010001, "name": "web01.example.com", "security": 2, "bugfix": 1, "enhancement": 1,
     "other": 0, "total": 4, "outdated": true, "reboot_required": true, "stale": false,
     "severity": {"critical": 1, "important": 1, "moderate": 0, "low": 0, "unspecified": 0},
     "security_advisories": ["SUSE-SU-2026:1001-1", "SUSE-SU-2026:1002-1"]}
  ]
}
```

### CSV

Columns: `system_id, name, last_checkin, security, bugfix, enhancement, other, total, outdated,
reboot_required, stale, critical, important, moderate, low, unspecified, security_advisories`.
Text cells that start with `=`, `+`, `-`, `@`, a tab or CR are prefixed with `'` to prevent
spreadsheet formula injection (CWE-1236).

## How it works

The tool uses only these API calls: `auth.login`/`auth.logout` (the session is always closed),
`api.getVersion`, `system.listSystems`, `system.getRelevantErrata`,
`system.listOutOfDateSystems`, `system.listSuggestedReboot` and, with `--with-severity`,
`errata.getDetails`. Anything else is refused by the client before a request is sent.

## Security notes

- Read-only by construction (method allow-list, tested).
- Secrets only from the environment or a `0600` file. The password is masked in `repr()` and
  never appears in error messages.
- Verified TLS only. The tests start a local HTTPS XML-RPC server and check that untrusted
  certificates and host name mismatches are rejected.
- XML parsing is hardened with `defusedxml`: no entity expansion, and gzip decoding is bounded.
- Control characters in system names are neutralised in the table output to prevent terminal
  escape injection. CSV is formula-safe.

## Development

```bash
make venv          # .venv with dev tools
make lint test security
```

CI runs ruff, pytest on Python 3.10-3.13 (78 tests, mocked API plus a local TLS server),
bandit, pip-audit, a packaging smoke test and gitleaks. GitHub Actions are pinned to commit
SHAs with `contents: read`.

## License

[MIT](LICENSE)
