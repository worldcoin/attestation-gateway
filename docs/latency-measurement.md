# Latency metric reference

Metrics use the existing DogStatsD exporter.

## Metrics

| Metric | Type | Scope |
| --- | --- | --- |
| `attestation_gateway.request.duration_seconds` | Distribution | Request entry through response creation, including extraction, errors and response timeouts |
| `attestation_gateway.operation.duration_seconds` | Distribution | One per measured operation, including its existing retries |

Only `/c`, `/a`, and `/g` are measured. Health checks, JWKS and unknown paths are
excluded. Durations are seconds, sent as DogStatsD distributions (`d`) so
percentiles can be computed across all containers rather than averaged from
per-container percentiles. Each request emits one duration sample; use its
`count` aggregation for request volume, including cancellations.

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
  `AWS_DEFAULT_REGION` when present; omitted when both are absent.

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

Android `/a` background analytics is excluded because it is not awaited by the
request. The timers observe cancellation without changing it. A cancelled
operation records elapsed time until the caller drops its future; underlying
blocking work or a remote write may still finish. These samples are not the full
remote-operation latency. Keep cancellations separate from successful samples.

Server timings exclude client/network latency and device evidence generation.

## Background Kinesis delivery

`/g` enqueues analytics without waiting for Kinesis. Per process: 256 queued
records, 16 MiB of retained payloads (including in-flight records), eight concurrent
publishes, and a five-second deadline from enqueue through retries. Admission is
nonblocking; a full queue or byte budget drops the event. Missing/empty stream
configuration disables publishing. Android `/a` analytics uses its existing path.

On SIGTERM/Ctrl-C, HTTP requests get up to ten seconds to finish, followed by up to
ten seconds to drain analytics. This is best-effort delivery: a process crash can
lose queued events. A timed-out write may have reached Kinesis, and retries may
produce duplicates; these properties also apply to ordinary Kinesis retries.

All names below have the `attestation_gateway.` exporter prefix. Tags are bounded;
client identifiers and report contents are never metric labels.

| Metric | Type / unit | Meaning |
| --- | --- | --- |
| `kinesis.enqueued`, `kinesis.delivered` | Counter / events | Accepted by the queue; acknowledged by Kinesis |
| `kinesis.failed` | Counter / events | `reason:publish` or `deadline`; delivery was not confirmed |
| `kinesis.dropped` | Counter / events | `reason:queue_full`, `byte_limit`, `closed`, `serialization`, `expired` (before publishing), or `cancelled` (including forced shutdown) |
| `kinesis.retries` | Counter / retries | Application retries; excludes retries inside the AWS SDK |
| `kinesis.queue_depth`, `kinesis.in_flight` | Gauge / events | Waiting records; active delivery tasks |
| `kinesis.delivery.duration_seconds` | Distribution / seconds | Queue wait plus delivery/retries, tagged `outcome:delivered`, `publish`, or `deadline` |

The former request-scoped `operation:kinesis_publish` stops emitting. The existing
`attestation_gateway.kinesis_put_failure` counter is retained for failures and
drops (with its existing exporter-prefix behavior). During shutdown, cancelled
work is counted when its task is dropped; an abrupt process kill cannot report it.
