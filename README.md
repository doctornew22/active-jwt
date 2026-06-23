# Active JWT Breaker

A Python tool for active JWT security testing against live endpoints. This script performs several attack-style tests on a provided JWT, including:

- `alg:none` signature bypass
- `kid` header injection
- attacker-provided JWK key validation
- role and identity tampering
- token expiry manipulation
- optional logout/session invalidation replay

> WARNING: This tool sends real HTTP requests to the target. Use it only against systems you are authorized to test. The author is not responsible for any misuse or unauthorized activity.

## Requirements

- Python 3.8+
- `requests`
- `cryptography`

Install dependencies:

```bash
pip install requests cryptography
```

## Usage

```bash
python active_jwtbreaker.py \
  --token "<JWT>" \
  --url "https://target.com/protected" \
  --token-location "bearer"
```

### Required arguments

- `--token`: The JWT to test.
- `--url`: The protected endpoint URL to evaluate.

### Optional arguments

- `--logout-url`: Logout endpoint URL for session invalidation replay testing.
- `--secret`: Known or guessed HMAC secret, used for payload re-signing tests.
- `--victim`: Victim identity value to inject into the token (default: `victim@target.com`).
- `--admin`: Admin role value to inject into the token (default: `administrator`).
- `--token-location`: Where to place the token. Use `bearer` for `Authorization: Bearer <token>` or `cookie:NAME` to send it in a cookie.
- `--skip`: Skip one or more tests. Valid values: `alg_none`, `kid`, `jwk_embed`, `role`, `expiry`, `logout`.

## What the script does

1. Sends a baseline request using the original JWT.
2. Tests `alg:none` bypass variants.
3. Tests `kid` header injection and weak-signature fallback cases.
4. Tests attacker-supplied JWK embedded in the JWT header.
5. Tests role or identity field tampering when a valid secret is provided.
6. Tests expiry claim manipulation when a valid secret is provided.
7. Optionally performs logout replay testing if `--logout-url` is provided.

## Output

The script prints test headers and verdicts such as:

- `VULNERABLE`
- `SAFE`
- `INCONCLUSIVE`
- `SKIPPED`
- `ERROR`

At the end it prints a summary of all tests.

## Best practices

- Confirm the target URL is a protected endpoint that requires the provided JWT.
- Use correct token placement with `--token-location`.
- Provide `--secret` only when you know or strongly suspect the HMAC secret.
- Review all output carefully before drawing conclusions.
- Always operate within the scope of your authorization.

## Example

```bash
python active_jwtbreaker.py \
  --token "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  --url "https://target.com/api/profile" \
  --token-location "bearer" \
  --secret "mysecret" \
  --logout-url "https://target.com/logout"
```
