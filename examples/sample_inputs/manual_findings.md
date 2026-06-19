# ACME Corporation — Web Application Assessment

## Executive Summary

The assessment of the customer portal identified two issues that require prompt
attention. Authentication controls were generally robust, but an access-control gap
allowed horizontal privilege escalation between tenant accounts.

## Insecure Direct Object Reference in Invoice API

Severity: High
CVSS: 8.1
Description:
The `/api/v1/invoices/{id}` endpoint does not verify that the authenticated user owns
the requested invoice. Incrementing the numeric `id` returned invoices belonging to
other tenants, exposing names, addresses, and amounts.

Impact: Disclosure of confidential billing data across tenant boundaries.
Remediation: Enforce per-object authorization checks server-side and use unpredictable
(UUID) identifiers.
Affected: https://portal.acme.example/api/v1/invoices/
References: https://owasp.org/Top10/A01_2021-Broken_Access_Control/

```
GET /api/v1/invoices/1043 HTTP/1.1
Authorization: Bearer <tenant-A-token>

HTTP/1.1 200 OK
{"id":1043,"tenant":"tenant-B","amount":"$4,210.00"}
```

## Session Cookie Missing Secure Attribute

Severity: Low
Description: The session cookie is set without the `Secure` flag, allowing transmission
over cleartext HTTP if the user is downgraded.
Remediation: Set `Secure`, `HttpOnly`, and `SameSite=Lax` on all session cookies.
Affected: https://portal.acme.example/
