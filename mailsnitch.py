#!/usr/bin/env python3
"""
MailSnitch — SMTP/IMAP reconnaissance tool.
Checks for open relays, VRFY enumeration, user enumeration via RCPT TO.
"""

import argparse
import socket
import smtplib
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

SMTP_BANNER_TIMEOUT = 5
VRFY_TIMEOUT = 5


def check_smtp_banner(host, port=25, timeout=SMTP_BANNER_TIMEOUT):
    """Connect and grab SMTP banner."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        banner = s.recv(1024).decode("utf-8", errors="replace").strip()
        s.close()
        return (host, port, banner)
    except Exception as e:
        return (host, port, f"ERROR: {e}")


def check_open_relay(host, port=25, from_addr="test@example.com", to_addr="test@example.org", timeout=15):
    """Test if an SMTP server is an open relay."""
    try:
        s = smtplib.SMTP(host, port, timeout=timeout)
        s.ehlo_or_helo_if_needed()
        try:
            s.starttls()
            s.ehlo()
        except:
            pass
        s.mail(from_addr)
        code, msg = s.rcpt(to_addr)
        s.quit()
        is_relay = code == 250
        return (host, port, is_relay, code, msg.decode() if isinstance(msg, bytes) else msg)
    except Exception as e:
        return (host, port, False, 0, str(e))


def vrfy_user(host, user, port=25, timeout=VRFY_TIMEOUT):
    """Attempt VRFY on a single user."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        s.recv(1024)
        s.sendall(b"VRFY " + user.encode() + b"\r\n")
        resp = s.recv(1024).decode("utf-8", errors="replace").strip()
        s.sendall(b"QUIT\r\n")
        s.close()
        code = int(resp[:3]) if resp and resp[:3].isdigit() else 0
        return (user, code, resp)
    except Exception as e:
        return (user, 0, str(e))


def enumerate_users(host, userlist, port=25, max_workers=20):
    """Brute-force SMTP user enumeration via VRFY."""
    results = []
    with open(userlist) if isinstance(userlist, str) and os.path.exists(userlist) else userlist as ul:
        users = [l.strip() for l in ul if l.strip() and not l.startswith("#")]
    
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        fut_map = {ex.submit(vrfy_user, host, u, port): u for u in users}
        for fut in as_completed(fut_map):
            try:
                results.append(fut.result())
            except:
                pass
    return [r for r in results if r[1] in (250, 252)]


import os

def main():
    parser = argparse.ArgumentParser(description="MailSnitch — SMTP recon tool")
    parser.add_argument("-t", "--target", required=True, help="SMTP server host")
    parser.add_argument("-p", "--port", type=int, default=25, help="SMTP port (default: 25)")
    parser.add_argument("--banner", action="store_true", help="Grab SMTP banner")
    parser.add_argument("--relay-test", action="store_true", help="Test for open relay")
    parser.add_argument("--vrfy", help="VRFY a single user")
    parser.add_argument("--enumerate", help="File with usernames to VRFY enumerate")
    parser.add_argument("--timeout", type=int, default=10, help="Connection timeout")
    args = parser.parse_args()

    if args.banner:
        print(f"[*] Checking SMTP banner on {args.target}:{args.port}")
        host, port, banner = check_smtp_banner(args.target, args.port, args.timeout)
        print(f"  {host}:{port} -> {banner}")

    if args.relay_test:
        print(f"[*] Testing open relay on {args.target}:{args.port}")
        host, port, is_relay, code, msg = check_open_relay(args.target, args.port)
        if is_relay:
            print(f"  [!] OPEN RELAY: {host}:{port} (code {code})")
        else:
            print(f"  [-] Not an open relay: {msg}")

    if args.vrfy:
        print(f"[*] VRFY {args.vrfy} on {args.target}:{args.port}")
        user, code, resp = vrfy_user(args.target, args.vrfy, args.port, args.timeout)
        print(f"  {user}: code {code} — {resp}")

    if args.enumerate:
        print(f"[*] Enumerating users from {args.enumerate}")
        found = enumerate_users(args.target, args.enumerate, args.port)
        print(f"  Found {len(found)} valid users:")
        for u, c, r in found:
            print(f"    {u}: {r}")


if __name__ == "__main__":
    main()
