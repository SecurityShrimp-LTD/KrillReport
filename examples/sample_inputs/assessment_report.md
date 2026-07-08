# PayFlow API — Security Assessment (Final Report)

**Target:** PayFlow REST API (`api.payflow.example`)
**Client:** PayFlow Inc.
**Reviewer:** Alex Rivera, Jordan Lee
**Dates:** testing 2026-05-04 → 2026-05-15; report 2026-05-18
**Classification:** CONFIDENTIAL

---

## 1. Executive Summary

The PayFlow API is well-built overall, with consistent authentication and parameterized
queries throughout. The findings that matter are an **IDOR on the invoices endpoint**
(F1) and a **missing rate limit on the login endpoint** (F2).

### Findings overview

| ID | Severity | Title |
|----|----------|-------|
| F1 | High | IDOR on `/invoices/{id}` |
| F2 | Medium | No rate limiting on `/auth/login` |
| F3 | Low, robustness | Verbose error messages leak stack traces |

---

## 2. Scope & Methodology

Authenticated and unauthenticated testing of the REST API surface, following the OWASP
API Security Top 10. Automated scanning plus manual verification of every reported issue.

---

## 3. Findings

### F1 — IDOR on `/invoices/{id}` (High)

**Location:** `GET /invoices/{id}`, `InvoiceController.show`

Any authenticated user can read another tenant's invoice by incrementing the numeric id;
the handler never checks that the invoice belongs to the caller's organization.

**Impact.** Full cross-tenant disclosure of billing data (amounts, customer names, line
items) for every invoice in the system.

**Recommendation.** Enforce an ownership check (`invoice.org_id == current_user.org_id`)
before returning the record, and prefer non-sequential identifiers.

### F2 — No rate limiting on `/auth/login` (Medium)

**Location:** `POST /auth/login`
**Impact.** Unbounded credential-stuffing and password-brute-force attempts.
**Recommendation.** Add per-account and per-IP throttling with exponential backoff.

### F3 — Verbose error messages leak stack traces (Low, robustness)

Unhandled exceptions return a full stack trace and framework version in the 500 body.
Not directly exploitable, but it aids reconnaissance.

**Recommendation.** Return a generic error body in production; log details server-side.

---

## Appendix A — Tooling

Burp Suite Professional, custom Python harness, `sqlmap` (no injections found).
