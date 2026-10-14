# vettid-push

The VettID push gateway. It delivers **contentless wake-up pushes** to the
VettID app through Firebase Cloud Messaging (Android) and the Apple Push
Notification service (iOS), so that no vault and no relay ever holds Apple
or Google credentials. A wake tells the app only "collect from your
mailbox"; everything else happens on the phone.

- **Protocol:** PUSH-GATEWAY **0.4.5** (`docs/PUSH-GATEWAY.md` in
  [vettid.org](https://github.com/vettid/vettid.org)), reported by
  `vettid-push -version`. The vault's side is VAULT-MESSAGING §14.
- **Only caller:** a VettID vault. The gateway is tested against the
  vault's own client (`vettid-vault/vms/pushwire`, the code staging
  release 9 ships), and the §15 test vector is reproduced byte for byte.
- **No state.** There is no database, no cache and no file. What the
  gateway needs for a registration is sealed into a **wake blob** that only
  it can open and only the registering vault keeps. A breach of the
  gateway's storage yields nothing, because there is none.
- **Only genuine vaults register.** A registration carries a Nitro Enclaves
  attestation document; the gateway verifies it against the pinned AWS
  root and admits only the PCR0 of a release that the channel's signed
  release manifest lists as `active` or `deprecated`.
- **Only for a token the caller's phone holds.** Before a wake blob is
  issued, the gateway sends a random challenge code to the push token by
  push; the blob is issued only when the vault returns that code, which
  only the app holding the token receives (`POST /v1/confirm`). A vault
  cannot get a blob for a token it merely learned.
- **Blobs expire.** A wake blob is honoured for **90 days** from its
  issue, then refused like any invalid blob; the vault registers again.
- **Fixed payloads.** Every wake of a platform is byte-identical apart
  from the push token: no message, sender, name, count or cursor. A
  registration's challenge is a silent push whose only variable part is
  the random code.
- **Stack:** Go standard library `net/http`. The attestation and manifest
  verifiers, the pinned AWS Nitro root and the wire format are the vault's
  own packages (`vettid-vault/vms/nitro`, `vms/manifest`, `vms/pins`,
  `vms/pushwire`); request signatures are the relay's
  (`vettid-relay/relayauth`). FCM and APNs are spoken directly (no Google
  or Apple SDK); the AWS SDK for Go v2 is used for Secrets Manager and for
  signing the workload-identity request. No CGO; the binary is static.

## Quick start (the dev stand-in)

```sh
make build        # bin/vettid-push, bin/pushctl
PUSH_DEV_NITRO_ROOT=<base64 DER of the dev enclave's TEST Nitro root> \
PUSH_DEV_PCR0S=<pcr0 hex of the dev release> \
  ./bin/vettid-push -dev
```

`-dev` is the **gateway stand-in** of the vault's dev stack (PUSH-GATEWAY
§10.4): it accepts the dev enclave's test attestation (a test root and a
list of PCR0s instead of the AWS root and the manifest), and it **records
wakes and registration challenges instead of sending them**. It has no credentials, makes a random
blob key at start, and serves the control routes of the vault's
`internal/pushtest` stand-in on a second listener
(`PUSH_DEV_CONTROL_ADDR`, loopback by default):

```
GET  /dev/push         {registrations, wakes: [{at, platform, environment?, app_id, token_sha256, class}],
                        challenges: [{at, platform, environment?, app_id, token_sha256, code}], refusals}
POST /dev/push/fail    {status, code, retry_after?, count?}   answer the next wake(s) with this error
POST /dev/push/reseal  {count?}                               answer the next wake(s) with a reseal
POST /dev/push/reset                                          forget wakes, counts and injected answers
POST /dev/push/wait    {wakes: N, timeout_s}                  wait until N wakes are recorded (404 on timeout)
```

`registrations` counts completed registrations (a wake blob issued). A
test playing the app reads a registration's challenge code from
`challenges` and hands it to its vault. `-dev` refuses the channels `prod` and `staging`, refuses
`PUSH_SECRETS=aws`, refuses the real AWS Nitro root, seals its blobs for
the channel `dev` (they open nowhere else), and logs a warning at start.
The vault's dev stack publishes its test root as `nitro_root` in
`GET /dev/trust` (`cmd/devstack`): that value is `PUSH_DEV_NITRO_ROOT`.

## Container

```sh
make image                    # docker or podman build, VERSION = the commit
make image-repro              # two clean builds; fails unless they are the same image
docker run -p 8080:8080 -e PUSH_CHANNEL=staging -e AWS_REGION=us-east-1 \
  -e PUSH_FCM_APP_IDS=... -e PUSH_APNS_APP_IDS=... vettid-push:dev
```

- Distroless `static-debian13:nonroot` base, pinned by digest; uid/gid
  65532. The binary path is stable: **`/vettid-push`**.
- **Health check command:** `/vettid-push -healthcheck` (GETs
  `http://127.0.0.1:<port of PUSH_LISTEN_ADDR>/v1/health`, 3 s timeout,
  exit 0 on 200). For ECS: `["CMD", "/vettid-push", "-healthcheck"]`. The
  load balancer's target group checks `GET /v1/health` (200 `{}`).
- **Reproducible:** base images by digest, `-trimpath`, empty build id, no
  VCS stamping; `make image-repro` builds twice without cache with the
  commit's timestamp and compares the image ids.
- The container needs no volume and no writable file system.

## Configuration

Everything is an environment variable; none of these is secret.
Durations accept Go syntax (`90s`) or a bare integer of seconds.

| Variable | Default | Meaning |
|---|---|---|
| `PUSH_CHANNEL` | (required) | `prod` or `staging`. Selects the pinned manifest URL and manifest keys (production: keys A and B; staging: the staging key), the APNs environments (staging: `sandbox` and `production`; prod: `production` only), the blob's associated data and the default secret names. Under `-dev` it is `dev`. |
| `PUSH_LISTEN_ADDR` | `:8080` | HTTP listen address (plain HTTP behind the load balancer). |
| `PUSH_TRUST_PROXY` | `false` | `true`: the source address for the per-address limits is the **last** `X-Forwarded-For` hop, the one the load balancer (ALB) appends. Set it behind the ALB; without it every request comes from the ALB's address. |
| `PUSH_PLATFORMS` | `fcm,apns` | The platforms this gateway serves. A listed platform must have a valid secret, or the gateway does not start. A platform not listed is answered `platform_invalid`. Empty is allowed (a gateway deployed before any credentials exist). |
| `PUSH_FCM_APP_IDS` | (required with `fcm`) | Comma-separated Android application ids accepted for `fcm` (`app_invalid` otherwise). |
| `PUSH_APNS_APP_IDS` | (required with `apns`) | Comma-separated iOS bundle ids accepted for `apns`; a registration's `app_id` is its `apns-topic`. |
| `PUSH_FCM_PROJECT` | the secret's `project_id` | The Firebase project id (`vettid-staging`, `vettid-prod`). Required when the FCM secret is a workload identity federation configuration, which has no `project_id` of its own (one may be added to it instead). |
| `PUSH_SECRETS` | `aws` | Where the three secrets are read at start: `aws` (Secrets Manager), `file` (`PUSH_SECRETS_DIR`), or `env`. |
| `PUSH_SECRET_PREFIX` | `vettid-org/<channel>/push` | Secrets Manager name prefix: `<prefix>/apns`, `<prefix>/fcm`, `<prefix>/blob-keys`. |
| `PUSH_SECRETS_DIR` | | With `file`: a directory holding `apns.json`, `fcm.json`, `blob-keys.json`. |
| `AWS_REGION` | (required with `aws`) | Region of Secrets Manager, and the region whose STS endpoint signs the workload identity request. Credentials come from the standard SDK chain (the ECS task role). |
| `PUSH_METRICS_NAMESPACE` | `vettid-org/<channel>/push` | CloudWatch namespace of the EMF metric lines. |
| `PUSH_METRICS_INTERVAL` | `60s` | How often the aggregated metrics are written. |
| `PUSH_LOG_LEVEL` | `info` | `debug`, `info`, `warn` or `error`. |
| `PUSH_SHUTDOWN_TIMEOUT` | `20s` | Bound on the graceful drain after SIGTERM. |
| `PUSH_RATE_REGISTER_PER_MINUTE` | `30` | Registrations per source address (§8). |
| `PUSH_RATE_WAKE_PER_MINUTE` | `6000` | Wakes per source address (§8). |
| `PUSH_RATE_TOKEN_PER_HOUR` / `PUSH_RATE_TOKEN_BURST` | `60` / `10` | Wakes per push token (§8). |
| `PUSH_RATE_CHALLENGE_PER_HOUR` / `PUSH_RATE_CHALLENGE_BURST` | `10` / `5` | Registration challenges per push token, counted apart from its wakes. |
| `PUSH_COALESCE_WINDOW` | `2s` | A wake for a token within this time of the previous one is answered `202` without a second send (§5.2); `0` turns it off. |
| `PUSH_REPLAY_CACHE_MAX` | `200000` | Replay-cache capacity; when full, requests are shed with `rate_limited`. |
| `PUSH_DEV_NITRO_ROOT` / `PUSH_DEV_NITRO_ROOT_FILE` | | `-dev` only: the dev enclave's test Nitro root, as base64 DER or as a PEM file. |
| `PUSH_DEV_PCR0S` | | `-dev` only: comma-separated PCR0s (96 hex digits) that may register. |
| `PUSH_DEV_CONTROL_ADDR` | `127.0.0.1:8081` | `-dev` only: the control listener; empty turns it off. |

With `PUSH_SECRETS=env` the secrets are read from `PUSH_SECRET_APNS`,
`PUSH_SECRET_FCM` and `PUSH_SECRET_BLOB_KEYS` (each the secret's JSON).

The manifest URL, the manifest keys and the AWS Nitro root are **compiled
in** per channel, like the pins of a vault release; no variable changes
them.

## Secrets

Read once at start (PUSH-GATEWAY §10.2); nothing is written back. In AWS
they are encrypted under `alias/vettid-org-push`, which only the task
role may use.

| Secret | Content |
|---|---|
| `<prefix>/apns` | `{"team_id": "<10 chars>", "key_id": "<10 chars>", "p8": "<the .p8 PEM>"}` |
| `<prefix>/fcm` | Either Google's **workload identity federation** credential configuration for AWS (`"type": "external_account"`, as `gcloud iam workload-identity-pools create-cred-config --aws` writes it; it holds no secret), or a **service-account JSON key** (`"type": "service_account"`). The content selects the path. |
| `<prefix>/blob-keys` | `{"current": "<key id>", "keys": {"<key id>": "<base64 of 32 random bytes>", ...}}`; a key id is 8 lowercase hex digits (the 4 key-id bytes of a blob). |

`pushctl` prepares the blob keys. Its output **is the secret**: pipe it
straight into the secret store.

```sh
pushctl blob-keys new    | aws secretsmanager put-secret-value --secret-id vettid-org/staging/push/blob-keys --secret-string file:///dev/stdin
aws secretsmanager get-secret-value --secret-id ... --query SecretString --output text | pushctl blob-keys rotate | aws secretsmanager put-secret-value ...
pushctl blob-keys drop <key id>   # a retired key, 400 days after its rotation
pushctl blob-keys list            # key ids only, never keys
```

A rotation adds a key and makes it current; the retired keys stay in the
secret and still open blobs, and every wake under a retired key is
answered with a `reseal` that the vault stores (§4). Tasks read the
secret at start only, so a rotation takes effect with the next
deployment. Deleting a retired key after 400 days is the operator's step
(`drop`): the secret records no dates, so the gateway cannot do it.

**FCM access.** With federation the gateway signs an AWS STS
`GetCallerIdentity` request with its task-role credentials (the subject
token), exchanges it at Google's STS, and impersonates the service
account for the `firebase.messaging` scope; no Google key exists
anywhere. Inside the secret only Google's own endpoints are accepted
(`sts.googleapis.com`, `iamcredentials.googleapis.com`,
`oauth2.googleapis.com`), so a tampered secret cannot send the gateway's
credentials elsewhere. Access tokens are cached in memory and renewed
five minutes before they expire.

## Deployment notes

What a task needs (PUSH-GATEWAY §10.1):

- **Inbound:** TCP 8080 from the load balancer only. Target group health
  check `GET /v1/health`. The request header `X-VettID-Attestation` is
  about 6.5 KiB (a real NSM document), inside the ALB's 16 KiB limit for
  one header.
- **Outbound (HTTPS, 443):** `secretsmanager.<region>.amazonaws.com`;
  the channel's manifest (`staging.vettid.org` or `vettid.org`);
  `fcm.googleapis.com`; `sts.googleapis.com` and
  `iamcredentials.googleapis.com` (federation) or `oauth2.googleapis.com`
  (key); `api.push.apple.com` and, on staging,
  `api.sandbox.push.apple.com`.
- **IAM (task role):** `secretsmanager:GetSecretValue` on the three
  secrets and `kms:Decrypt` on their key. For federation the role's ARN
  is what the Google workload identity pool trusts.
- **No per-request logs anywhere:** keep ALB access logs off for the push
  host (§10.5).
- **Log group:** the task writes its log and its metric lines (CloudWatch
  embedded metric format) to stdout.
- **Stateless:** any number of tasks; the limits of §8 are per task.

Metrics (namespace `PUSH_METRICS_NAMESPACE`, one line per series and
interval, never per request):

| Metric | Dimensions | |
|---|---|---|
| `registrations` | `platform`, `outcome` | `outcome`: `ok` (the challenge was sent and a pending registration returned) or the error code |
| `challenges` | `platform`, `outcome` | a registration's challenge send: `sent`, `token_gone`, `token_invalid`, `provider_rate_limited`, `provider_unavailable`, `provider_auth`, `provider_rejected` |
| `confirmations` | `platform`, `outcome` | `outcome`: `ok` (a wake blob issued) or the error code |
| `wakes` | `platform`, `environment`, `outcome` | `outcome`: `sent`, `coalesced`, an error code, or `provider_rate_limited`, `provider_unavailable`, `provider_auth`, `provider_rejected` |
| `provider_latency_ms` | `platform` | up to 100 sampled values per interval |
| `attestation_failures` | `reason` | `missing`, `malformed`, `chain`, `signature`, `stale`, `public_key`, `user_data`, `pcr0`, `no_manifest`, `manifest_stale` |
| `rate_limited` | `scope` | `token`, `address_register`, `address_wake`, `replay_cache`, `key` (one key at its cap of live replay records), `challenge` (a token's challenge limit), `address_confirm` |
| `blob_resealed` | | |
| `blob_expired` | | a wake refused because its blob is older than 90 days (answered `blob_invalid`) |
| `manifest_refresh` | `outcome` | `ok`, `error`, `not_published` (for the "refresh failing" alarm) |
| `internal_errors` | | every `500 internal` (for the "any internal" alarm) |

The alarms of §10.5 map to: provider auth failures =
`wakes{outcome=provider_auth}`; `provider_unavailable` above 5 % =
`wakes{outcome=provider_unavailable}` over all `wakes`; any `internal` =
`internal_errors`; manifest refresh failing = `manifest_refresh{outcome=error}`;
attestation failures = `attestation_failures`.

**Proposed alarm: challenge limit.** `rate_limited{scope=challenge}`
should raise an alarm (to start with, more than 20 in an hour, summed
over platforms). A phone's own vault meets the per-token challenge limit
only when it retries far too often. Steady counts mean someone who knows
a phone's push token is spending that token's challenges, which keeps
the real phone from registering and from renewing its blob (a blob
expires after 90 days, and then the phone is not woken until it
registers again). The operator's responses are to raise
`PUSH_RATE_CHALLENGE_PER_HOUR` / `PUSH_RATE_CHALLENGE_BURST` or to block
the source address at the load balancer. The metric has no dimension
that names the token, so the alarm tells the operator that this is
happening, not to whom. The alarm, like the others, is defined in the
deployment's metric filters (vettid.org), not in this repository.

The "manifest refresh failing" alarm (1 hour) is what keeps the maximum
manifest age (7 days, below) from ever being reached: left unanswered for
a week, it ends with every registration refused (wakes go on).
`attestation_failures{reason=manifest_stale}` above zero means the limit
was reached.

## API summary

All of it is PUSH-GATEWAY §5–§7. Requests are signed per Relay Protocol
§4.1 with the registration's wake key.

| | |
|---|---|
| `POST /v1/register` + `X-VettID-Attestation` | `{platform, token, app_id, environment?}` → `202 {pending}`, after sending a challenge code to the token |
| `POST /v1/confirm` | `{pending, code}`, signed by the same wake key, within 10 minutes → `201 {wake_blob}` |
| `POST /v1/wake` | `{wake_blob, class: "notify"}` → `202 {reseal?}` |
| `GET /v1/health` | `200 {}` (unauthenticated) |

Errors are `{code, message, retry_after?}`: `401 signature_invalid`,
`timestamp_stale`, `replay_detected`; `403 attestation_invalid`,
`challenge_invalid`;
`400 bad_request`, `platform_invalid`, `app_invalid`, `token_invalid`;
`410 token_gone`, `blob_invalid`; `429 rate_limited`;
`502 provider_unavailable`; `500 internal`. A wait is given in the body's
`retry_after` and in the `Retry-After` header.

## Security notes

- **Nothing is stored.** No request writes anything. The per-token limiter
  is keyed by an HMAC of the token under a random key made at start; the
  opened record of a wake lives as long as its request.
- **Nothing is logged about a request.** The log holds starts, stops and
  errors of the service itself (a platform outage, refused credentials, a
  failing manifest refresh), each throttled to one line a minute with a
  count. There is no access log. It never holds a token, a blob, a wake
  key, an attestation document or a source address; the Go HTTP server's
  own error log, which names peer addresses, is discarded. A test
  captures everything a busy gateway writes and searches it
  (`internal/api/logging_test.go`, `cmd/vettid-push/run_test.go`).
- **No oracle.** Every blob that does not open, belongs to another channel
  or another signer, or names a key that is gone is answered with the same
  `410 blob_invalid`, an expired one included. Every refused attestation
  is the same `403`, and so is every refused confirmation (a wrong code,
  another signer, a pending registration older than 10 minutes or one
  that does not open): `403 challenge_invalid`.
- **Fixed error messages.** A message is fixed per code and never repeats
  request content. A platform's own error text is never passed on or
  logged: only its reason code, from a closed list.
- **Order of checks.** The per-address limit comes before anything is
  read; the body-size limit and the signature before the attestation; the
  attestation before the body.
- **Channels cannot cross.** A blob's associated data names its channel; a
  staging blob does not open in production even under the same key.
- **`-dev` is fenced.** See above. Test support (the fake NSM) is never
  linked into the binaries; a test checks the dependency list.
- **Credentials** are read from the secret source into memory and exist
  nowhere else: not in the image, the configuration or the repository.
  The repository holds no key at all; tests generate theirs.

## Spec interpretation notes

Points where PUSH-GATEWAY 0.4.1 left a choice or was silent, and what
this implementation does. The specification has since written each of
them down (0.4.2 to 0.4.5):

1. **A token that outgrows the blob.** §5.1 allows a 4,096-byte FCM token
   of any printable ASCII; §4 caps a blob at 6,144 bytes. A token made
   mostly of `"` or `\` doubles in the record's JSON and no longer fits.
   Such a registration is refused `400 token_invalid`. (`<`, `>` and `&`
   are not escaped; a real FCM token has none of these.)
2. **Key ids in the blob-keys secret** are 8 lowercase hex digits. The
   secret holds no dates, so the 400-day deletion of a retired key is an
   operator step.
3. **`sandbox` where the channel does not allow it** is `400 bad_request`
   (§5.1 names no code).
4. **Per-address limits come first**, before the signature (§5.2 lists
   "rate limits" as step 3; the per-token limit is applied there, since
   it needs the opened blob). Registrations are limited per address too
   (§8), which §5.1's steps do not mention.
5. **Coalescing** (§5.2 step 4) comes after the per-token limit, as the
   steps are ordered, so a coalesced wake still uses one of the token's 60
   an hour. "The previous one" is the previous wake that was **sent**: a
   wake after a failed send is sent, not answered `202`.
6. **No trusted manifest** (the site is down at start, or the channel has
   published none: production before release 1 answers 404): registrations
   are refused `403 attestation_invalid` (metric reason `no_manifest`);
   wakes work. The gateway retries every minute until it has one.
7. **A manifest that cannot be refreshed** stays trusted for **7 days
   since the last successful refresh** (§14.2 question 15, approved
   2026-10-11), then no longer: registrations are refused
   `403 attestation_invalid` (metric reason `manifest_stale`, the same
   answer as every other attestation refusal) until a refresh succeeds,
   which restores trust at once. A successful refresh is a fetch whose
   manifest verifies and passes the serial rule, the same manifest again
   included; a 404 from a channel that had published (`outcome=error`),
   a rollback or a bad signature is not one. Wakes are not affected: a
   wake opens its blob and never consults the manifest. The refresh
   stays at every 10 minutes while stale.
   `manifest_refresh{outcome=error}` raises the alarm after an hour, so
   the limit only closes the open-ended case. The age is counted on the
   task's monotonic clock and, like the serial rule, lives in memory:
   nothing is persisted, a restarted task starts from the manifest it
   then fetches (with a fresh 7 days), or with none (`no_manifest`) if
   the site cannot be reached.
8. **Platform answers beyond §7's table.** FCM `SENDER_ID_MISMATCH` and
   APNs `DeviceTokenNotForTopic` are `400 token_invalid` (the token can
   never work for this app; only a new registration helps). Any APNs
   `410` is `token_gone`. Refused credentials (APNs `403`, FCM `401`/`403`)
   and every other refusal (`BadTopic`, `TopicDisallowed`, …) are
   `502 provider_unavailable`, counted apart (`provider_auth`,
   `provider_rejected`) and logged. Every FCM `400` is taken as
   `token_invalid`, since the rest of the payload is fixed.
9. **A full replay cache** sheds requests with `429 rate_limited`, as the
   relay does. A request is checked against the cache and recorded in it
   only once its key is one the gateway knows: a wake after its blob has
   opened for the signer and its record is one the gateway would still
   seal (§5.2 step 2), a registration after its attestation has verified
   (§5.1 step 2). A request refused before that leaves no record, so
   signed requests from strangers cannot fill the cache; sent again it
   is checked afresh and is not answered `replay_detected`. A request
   refused after that (a registration's body fault, a wake at the
   per-token limit or refused by the platform) is recorded, so a retry
   must be signed anew. Freshness and the replay check use one reading
   of the clock. **One key has at most 32 live records** (twice what the
   per-token limit can admit in a record's life, plus the registration;
   more if the token limits are raised): beyond that this key's requests
   are `429 rate_limited` with the time until one expires, and nobody
   else's are affected, so one registered key cannot fill the cache
   either. The cache and these counts live in each task's memory, so
   with several tasks a request can be accepted once by each.
10. **A platform the gateway has no credentials for** is
    `platform_invalid`.
11. **Body errors** are named in the order of §5.1 step 3: platform,
    token, environment (`bad_request`), app id.
12. **Token verification and the blob's maximum age** are implemented
    ahead of the specification text, which is proposed alongside: the
    registration answers `202 {pending}` and sends the challenge, the
    confirmation issues the blob, and wakes refuse blobs older than 90
    days.

## Development

```sh
make test          # go test -p 2 ./...
make race          # go test -race -p 1 ./...
make lint          # go vet + staticcheck (pinned, via go run)
make scan          # gitleaks over history
make image         # container build
make image-repro   # two clean builds, compared
```

No test contacts a real provider, AWS or the manifest site: FCM, Google's
token endpoints, APNs (HTTP/2), Secrets Manager and the manifest are
local fakes, and every key and credential is generated when the test
runs.

Layout:

- `cmd/vettid-push`: the server; `cmd/pushctl`: the blob-keys tool.
- `internal/api`: the handlers, limits, the dev stand-in.
- `internal/blob`: wake blobs and the key ring.
- `internal/attest`: the attestation verifier, the manifest holder, the
  channel pins.
- `internal/provider`: FCM HTTP v1 (federation and service-account
  access), APNs.
- `internal/secrets`, `internal/awsx`: the secret sources.
- `internal/ratelimit`, `internal/metrics`, `internal/config`.
- `internal/nsmtest`: test support only (a fake NSM and manifest signer).

## License

AGPL-3.0-or-later. See [LICENSE](LICENSE).
