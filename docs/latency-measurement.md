# Attestation latency baseline

Measure CORPLAT-1127 before changing request routing or replay storage. These
metrics use the existing DogStatsD exporter; deploying this code does not change
attestation, retries, timeouts, signing, or analytics delivery behavior.

## Metrics

| Metric | Type | Scope |
| --- | --- | --- |
| `attestation_gateway.request.duration_seconds` | Distribution | Request entry through response creation, including extraction, errors and response timeouts |
| `attestation_gateway.request.count` | Counter | One per completed or cancelled measured request |
| `attestation_gateway.operation.duration_seconds` | Distribution | One per measured operation, including its existing retries |

Only `/c`, `/a`, and `/g` are measured. Health checks, JWKS and unknown paths are
excluded. Durations are seconds, sent as DogStatsD distributions (`d`) so
percentiles can be computed across all containers rather than averaged from
per-container percentiles.

Labels are bounded:

- `route`: `/c`, `/a`, `/g` (query strings are never included).
- `platform`: `android`, `ios`, `developer`, `client_error`, `unknown`. Classification
  follows the existing handler logic. `/c`, extraction errors and failures before
  platform inference are `unknown`; `/a` nonce consumption precedes inference.
- Request `outcome`: `success`, `client_error`, `server_error`, `timeout`, `cancelled`.
- Operation `outcome`: `success`, `error`, `cancelled`. This describes the operation's
  `Result`, not the attestation verdict: for example, `Ok(false)` from a replay lock
  is a successful Redis operation followed by a rejected HTTP request.
- `operation`: one of the names below (operation durations only).
- `env`: existing exporter tag. `region` comes from `AWS_REGION`, falling back to
  `AWS_DEFAULT_REGION` when present. Verify the deployed tags before comparing regions.

No request hashes, nonces, keys, audiences, headers, device identifiers or error
messages are used as labels. Request context is scoped to the async request and is
not automatically inherited by spawned background tasks.

| Operation | Meaning |
| --- | --- |
| `audience_authorization` | `/c` audience policy check, including Redis cache and Developer Portal lookup when required |
| `nonce_create`, `nonce_consume` | Redis nonce creation/consumption and associated serialization |
| `replay_acquire`, `replay_release` | `/g` Redis replay reservation/cleanup |
| `apple_key_register`, `apple_key_read`, `apple_counter_update` | Apple DynamoDB calls and response handling |
| `attestation_verify` | Platform verification; Android `/a` also includes risk evaluation and optional rate limiting |
| `developer_verify` | Developer-token verification, including JWKS refresh when required |
| `signing_key_fetch` | Redis-backed signing-key selection, including KMS key creation if rotation is needed |
| `token_sign` | JWT generation and KMS signing, including blocking-task scheduling |
| `kinesis_publish` | Awaited `/g` analytics delivery, including SDK/application retries and backoff |

Android `/a` background analytics is excluded because it is not awaited by the
request. The timers observe cancellation without changing it. A cancelled
operation records elapsed time until the caller drops its future; underlying
blocking work or a remote write may still finish. These samples are not the full
remote-operation latency. Keep cancellations separate from successful samples.

## Verify and collect a baseline

1. Deploy to staging and exercise successful, rejected and timeout requests. Confirm
   the new metrics, distribution type, units and tags in Datadog. Enable percentile
   aggregations for the two distributions before using p50/p95/p99 queries.
2. Check that request counts agree reasonably with traffic for these routes. The
   existing `/a` counter is after platform verification and the `/g` counter is
   before replay protection, so neither is an exact denominator for all HTTP requests.
3. After the approved production rollout, start with 24–48 hours of representative
   traffic. Compare successful latency separately from rejection and timeout rates.
4. Obtain client-side endpoint duration and platform-evidence generation time by
   geography from mobile telemetry. Server durations do not include DNS, TCP/TLS,
   the mobile-to-ALB journey, or generating evidence on the device.

Suggested Datadog dashboard queries:

```text
p50:attestation_gateway.request.duration_seconds{env:production,outcome:success} by {route,platform}
p95:attestation_gateway.request.duration_seconds{env:production,outcome:success} by {route,platform}
p99:attestation_gateway.request.duration_seconds{env:production,outcome:success} by {route,platform}
sum:attestation_gateway.request.count{env:production} by {route,outcome}.as_count()
p95:attestation_gateway.operation.duration_seconds{env:production,outcome:success} by {route,platform,operation}
```

Add operation errors/cancellations and request timeouts as separate panels. Use
`region` for later regional comparisons. Do not sum operation percentiles or
subtract p95 operation latency from p95 request latency: the samples are not paired
and operation scopes can include nested work. These metrics support attribution
and before/after comparisons, not a trace-level decomposition of individual requests.

Use the baseline to choose the first change: move awaited analytics off `/g`'s
response path if significant, benchmark an edge proxy if client/network delay
dominates, then decide which regional flow benefits actual user journeys most.
