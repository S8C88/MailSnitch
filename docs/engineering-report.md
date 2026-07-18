# MailSnitch — Engineering Report

## Overview

**Project:** MailSnitch
**Version:** 1.0
**Author:** Sideways 8 Security Research
**Category:** Email Security / SMTP Reconnaissance

MailSnitch probes SMTP servers for open relay configuration, VRFY user enumeration, and RCPT TO verification. Designed for internal network assessments and mail server security audits where you need to verify SMTP hardening without commercial tools.

---

## Tech Stack

### Language: Python 3.10+

Lightweight and portable. SMTP probing is inherently sequential (one connection at a time per host), so async frameworks would add complexity without benefit.

### Networking: `socket` + `smtplib` (stdlib)

`socket` for banner grabbing and raw SMTP dialogue. `smtplib` for extended SMTP operations (EHLO, STARTTLS). Both are stdlib — zero dependencies.

### Parallelism: `concurrent.futures.ThreadPoolExecutor`

Used for scanning multiple hosts concurrently. SMTP connections are I/O-bound (waiting for server responses), so threading is the right approach. Defaults to 10 workers to avoid overwhelming the scanning host's connection table.

---

## Architecture Decisions

### Why raw socket for banner grab?

`smtplib` abstracts away the conversation but gives us less control over timing and raw response parsing. Using raw sockets for the initial banner grab lets us detect non-standard SMTP implementations and capture the full banner for fingerprinting.

### Open relay detection strategy

We send a test email to a non-existent domain and check if the server accepts it for relaying. If the server says "250 OK" or "250 Accepted" for an external recipient, it's an open relay. This is the standard test and matches what every SMTP security scanner does.

### VRFY enumeration

The VRFY command is often disabled on modern MTAs, but when enabled it leaks valid usernames. We send VRFY for a list of common usernames and report which ones return "250" or "252" (verified vs. ambiguous). 550 = user not found, 252 = server says maybe (still a leak — tells attacker that the format is valid).

### RCPT TO verification

More reliable than VRFY — even when VRFY is disabled, RCPT TO usually reveals whether a mailbox exists. We use `MAIL FROM:<>` (null sender) followed by `RCPT TO:<user@domain>` to check each address.

---

## File Structure

```
MailSnitch/
├── mailsnitch.py        # SMTP scanner
├── README.md            # Usage and examples
├── LICENSE              # MIT
├── requirements.txt     # (no external deps)
├── tests/
│   └── test_mailsnitch.py
└── docs/
    └── engineering-report.md
```

---

## Limitations

1. **Rate limiting** — aggressive probing will trigger SMTP rate limits or IP blacklisting on production mail servers.
2. **GREXIT detection** — some MTAs use greylisting and will return temporary failures for all RCPT TO checks, making enumeration unreliable.
3. **STARTTLS required** — if the server enforces STARTTLS, plaintext SMTP commands won't work. We fall back but some info is lost.
4. **Not stealthy** — SMTP probing is logged on every MTA. This is detectable within seconds of the first connection.

---

## Future Work

- Add STARTTLS support for modern MTA testing.
- Implement SMTPUTF8 support for internationalized email.
- Add DMARC/DKIM/SPF record lookup for domain email posture assessment.
- Add SMTP conversation timing analysis for server fingerprinting.
