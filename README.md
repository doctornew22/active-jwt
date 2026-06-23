```markdown
#  Active-jwtbreaker

**Active JWT vulnerability tester** — sends real HTTP requests, diffs responses, and provides a clear verdict on whether your token handling is secure.  
Every `VULNERABLE` finding includes the exact crafted token so you can instantly verify and exploit.

> ⚠️ **Only use on targets you are authorised to test. Unauthorised testing is illegal.**

---

## ✨ Features

- **7 automated tests** covering the most common JWT misconfigurations:
  1. **alg:none** – signature verification bypass
  2. **KID injection** – path traversal & SQLi via key identifier
  3. **jwk embed** – self-signed public key injection
  4. **Role/identity tampering** – privilege escalation by re-signing payload
  5. **Expiry manipulation** – removing `exp` claim to test lifetime enforcement
  6. **Logout replay** – session invalidation check after logout
  7. **Baseline validation** – confirms the original token works before testing

- **Intelligent response diffing** – compares status codes, body content (login page detection), redirect URLs, and size changes to avoid false positives.
- **Multi‑location support** – works with `Authorization: Bearer` and cookies (`cookie:NAME`).
- **Coloured terminal output** – easy-to-read verdicts with payloads highlighted.
- **User‑agent rotation & random delays** to avoid simple rate‑limiting.

---

## 📦 Installation

```bash
# Clone the repository
git clone https://github.com/your-username/active_jwt.git
cd active_jwt

## Requirements

- Python 3.8+
- `requests`
-`urllib3>=1.26.0`
- `cryptography`


Install dependencies:

```bash
pip install requests cryptography
```

cryptography is only needed for the jwk embed test (RSA key generation). The tool will work without it if you skip that test.

---

🚀 Usage

```bash
python jwt_lifecycle_tester.py --token "eyJ..." --url "https://target.com/api/profile"
```

Full example

```bash
python jwt_lifecycle_tester.py \
  --token "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  --url "https://api.example.com/user/me" \
  --secret "my-secret-key" \
  --victim "admin@example.com" \
  --admin "administrator" \
  --logout-url "https://api.example.com/auth/logout" \
  --token-location "cookie:Authorization" \
  --skip jwk_embed
```

Options

Flag Description Default
--token JWT string to test (required) –
--url Protected API endpoint URL (required) –
--logout-url Logout endpoint for session invalidation test None
--secret HMAC secret – enables role/expiry tampering tests (re‑signing) None
--victim Victim identity to inject into sub/email/username etc. victim@target.com
--admin Admin role value to inject into role/isAdmin/group fields administrator
--token-location How the token is sent: bearer (header) or cookie:COOKIE_NAME bearer
--skip Skip specific tests: alg_none, kid, jwk_embed, role, expiry, logout (can list multiple) []

---

🔍 How Each Test Works

1. Baseline

The original token is sent to ensure the endpoint returns a valid 2xx response. This response becomes the reference for all subsequent tests.

2. alg:none

Modifies the header to "alg":"none" (and various case variants) and sends the token without a signature. If accepted, signature verification is broken.

3. KID Injection

If the token contains a kid (key ID), the tool tries:

· Path traversal – "../../../../../../../dev/null" with an empty secret (HS256).
· SQL injection – "x' UNION SELECT '1';--" with secret "1".
  If any variant is accepted, the server is blindly trusting the kid value to fetch keys.

4. jwk Embed

Generates a fresh RSA key‑pair, embeds the public key as a jwk header, and signs with the private key. If accepted, the server trusts attacker‑supplied keys.

5. Role & Identity Tampering

(Requires --secret)
Modifies role fields (role, isAdmin, …) and identity fields (sub, email, …), re‑signs with the known secret, and checks if the response differs (indicating escalated privileges).

6. Expiry Manipulation

(Requires --secret)
Removes the exp claim, re‑signs, and checks if the token is still accepted – revealing a missing expiry check.

7. Logout Replay

Posts to the logout URL (if given) with the original token, then reuses the same token. If still accepted, the server is not invalidating tokens on logout.

---

📊 Sample Output

```
  ╦╦ ╦╔╦╗  ╦  ╦╔═╗╔═╗╔═╗╦ ╦╔═╗╦  ╔═╗  ╔╦╗╔═╗╔═╗╔╦╗╔═╗╦═╗
  ║║║║ ║   ║  ║╠╣ ║╣ ║  ╚╦╝║   ║  ║╣    ║ ║╣ ╚═╗ ║ ║╣ ╠╦╝
  ╚╩╩╝ ╩   ╩═╝╩╚  ╚═╝╚═╝ ╩ ╚═╝╚═╝╚═╝   ╩ ╚═╝╚═╝ ╩ ╚═╝╩╚═
  Active JWT tester — sends real requests, diffs responses
  WARNING: Only use on targets you are authorized to test.

  Target  : https://api.example.com/user/me
  Location: bearer
  Header  : {"alg":"HS256","typ":"JWT"}
  Payload : {"sub":"123","user":"demo","role":"user","exp":1719000000}

  ────────────────────────────────────────────────────────────────
  BASELINE — confirming original token works
  ────────────────────────────────────────────────────────────────
    Status: 200, Body: 4231 bytes
    [OK] Baseline 2xx — proceeding

  ────────────────────────────────────────────────────────────────
  ALG:NONE — signature verification bypass
  ────────────────────────────────────────────────────────────────
    alg="none" trailing dot → HTTP 200 (rejected)
    alg="None" trailing dot → HTTP 200 (rejected)
    ...
    [SAFE] All alg:none variants rejected

  ────────────────────────────────────────────────────────────────
  KID INJECTION — path traversal / SQLi (multi-variant)
  ────────────────────────────────────────────────────────────────
    kid="../../../../../../dev/null" → HTTP 200 (rejected)
    kid="x' UNION SELECT '1';--" → HTTP 200 (rejected)
    [SAFE] All kid injection variants rejected

  ────────────────────────────────────────────────────────────────
  ROLE/IDENTITY TAMPERING — privilege escalation
  ────────────────────────────────────────────────────────────────
    role="administrator" → HTTP 200, body size 4231 → 5420 bytes
    [VULNERABLE] role="administrator" → HTTP 200, body size 4231 → 5420 bytes

    ► PAYLOAD — paste this token into your cookie/header:
    eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMiLCJ1c2VyIjoiZGVtbyIsInJvbGUiOiJhZG1pbmlzdHJhdG9yIiwiZXhwIjoxNzE5MDAwMDAwfQ.fake-sig

  ...

  ================================================================
  SUMMARY
  ================================================================
    alg_none     [SAFE]
    kid          [SAFE]
    jwk_embed    [SKIPPED]
    role         [VULNERABLE] role=administrator
    expiry       [SAFE]
    logout       [INCONCLUSIVE]

  ⚠ 1 issue(s) found: role
  Verify manually — check the payload shown above each finding.
```

Remember: This tool is for security professionals and bug bounty hunters. Always have explicit permission before testing.

```
