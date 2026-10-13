# Integration Hub API Platform

This repository contains the MVP orchestration API used to prove an end-to-end
consumer-to-provider flow through the Integration Hub. It exposes a stable API
to clients and delegates benefit assessments to the downstream mock benefit
checker.

See [Pilot mock API end-to-end flow](docs/pilot-mock-api-flow.md) for the full
journey across the upstream client, Integration Hub and downstream provider,
including authentication boundaries, sequencing, errors and deployment order.

## API

- `GET /health` - unauthenticated health check
- `POST /v1/benefit-checks/assessments` - authenticated benefit assessment

The assessment response wraps the provider result with a platform request ID:

```json
{
  "requestId": "45e04790-49e1-4fa1-8158-9884f6d451f6",
  "provider": "mock-benefit-checker",
  "assessment": {
    "assessmentId": "6f0804b7-c34b-352d-9dc0-a98e2caadd1d",
    "decision": "ELIGIBLE",
    "matchedEntitlements": [
      {
        "code": "UC-HOUSING-SUPPORT",
        "title": "Universal Credit Housing Support",
        "reason": "Universal Credit claim with income at or below the mock threshold."
      }
    ],
    "riskFlags": [],
    "processedAt": "2026-08-24T12:00:00Z",
    "decisionSummary": "Eligible for 1 mocked entitlement(s)."
  }
}
```

The full request and response contract is in [openapi.yaml](openapi.yaml).

## Runtime design

API Gateway authenticates callers and invokes the Python Lambda. The Lambda
validates the public request, forwards it to the downstream API with a
correlation ID, and normalises provider failures into a stable client-facing
error format. Downstream Basic credentials are read from AWS Secrets Manager
and cached briefly; credentials and personal request fields are never logged.

Required Lambda environment variables:

| Variable | Description |
| --- | --- |
| `DOWNSTREAM_BENEFIT_CHECKER_URL` | Base URL of the downstream API |
| `DOWNSTREAM_BASIC_AUTH_SECRET_ID` | Secrets Manager secret containing `username` and `password` |
| `DOWNSTREAM_TIMEOUT_SECONDS` | Optional timeout, default `5` |
| `SECRET_CACHE_TTL_SECONDS` | Optional credential cache duration, default `300` |

## Develop and package

The Lambda uses only the Python standard library plus `boto3`, which is
provided by the AWS runtime.

```bash
python3 -m unittest discover -s tests -v
./scripts/package.sh
```

The package is written to `build/benefit-orchestrator.zip`. Terraform remains
in `modernisation-platform-environments`, with this API's infrastructure in the
per-API component
`terraform/environments/integration-hub-api/benefit-checker-api`. Shared
hosting-platform capabilities belong in the separate `platform` component.
The deployment workflow updates the Lambda code after infrastructure has
created it.

## Current downstream contract

The live downstream mock API currently returns:

- `decision` values of `ELIGIBLE`, `REFER_FOR_REVIEW`, or `NOT_ELIGIBLE`
- `matchedEntitlements` as objects with `code`, `title`, and `reason`

The orchestration API forwards that provider payload unchanged inside the
`assessment` wrapper.

## Authentication boundaries

Client credentials are validated by the API Gateway authorizer and are not
forwarded downstream. The orchestration Lambda uses a separate provider
credential from Secrets Manager. A downstream `401` or `403` is returned to
clients as a provider integration failure so internal credentials are not
exposed.


## Downstream OAuth2 client credentials

The provider client can exchange a dedicated client credential for a short-lived
OAuth2 bearer token. Set `DOWNSTREAM_AUTH_MODE=oauth2`,
`DOWNSTREAM_OAUTH2_TOKEN_URL` (HTTPS) and `DOWNSTREAM_OAUTH2_SCOPE` (for the mock:
`benefit-checks.assess`). `DOWNSTREAM_BASIC_AUTH_SECRET_ID` remains the existing
secret reference for migration: its `username` holds the OAuth2 client ID and its
`password` holds the client secret. Use a client registered for the downstream
API, not the consumer's credential.

The token endpoint uses `client_secret_basic`. Tokens are cached until 30 seconds
before expiry and refreshed after a provider 401. A 403 is not retried. OAuth2
failures never fall back to Basic. Redirects are disabled for token and provider
requests to avoid forwarding credentials to a different destination. The existing
Basic mode remains the default until the approved registration and deployment
configuration are available.

All 29 platform tests pass, including token exchange, expiry, invalid responses,
credential rejection and bearer-authenticated provider calls. These are local
mocked tests; they do not establish successful non-production OAuth2 deployment.
The downstream mock companion change validates signed tokens and enforces its
role/scope policy.

Consumer-to-platform OAuth2, mTLS and full DWP/HMRC integration verification remain
outstanding. The existing static bearer format is not OAuth2. Deployment requires
an agreed provider/client registration, claim mapping and certificate ownership;
this change alone does not complete the SOW.
