# Reconciler

The Reconciler is a standalone service that handles periodic reconciliation operations for the Directory. It runs as a separate process and can be scaled independently from the main API server.

## Architecture

The reconciler uses a task-based architecture where different reconciliation tasks can be registered and run at their configured intervals. This allows for:

- **Independent scaling**: The reconciler can be scaled separately from the API server
- **Separation of concerns**: Long-running background operations don't impact API performance
- **Extensibility**: New reconciliation tasks can be added without modifying the core service
- **Reliability**: Tasks are idempotent and handle partial failures gracefully

## Tasks

### Regsync Task

The regsync task handles synchronization from non-Zot registries. It:

1. Polls the database for pending sync operations that require regsync (non-Zot registries)
2. Negotiates credentials with the remote Directory node
3. Generates a regsync configuration file for the sync operation
4. Executes the `regsync once` command and waits for completion
5. Updates the sync status to COMPLETED or FAILED based on the result

### Indexer Task

The indexer task monitors the local OCI registry and indexes records into the search database. It:

1. Creates a snapshot of current registry tags (filtering to valid record CIDs)
2. Compares with the previous snapshot to detect new tags
3. For each new tag, pulls the record from the local store and validates it
4. Adds the record to the search database to enable search and filtering

### Name Task

The name task verifies ownership of named records and caches results. The protocol prefix of the record name selects the method:

- `https://` and `http://` names: one of the record's public keys must appear in the domain's `/.well-known/jwks.json` (RFC 7517).
- `ans://v{MAJOR}.{MINOR}.{PATCH}.{agentHost}[/path]` names: the record must carry a signature made with the agent's Agent Name Service (ANS) identity key, with the identity certificate attached (`dirctl sign --key <key> --certificate <identity-cert.pem>`). The task keeps only certificates whose key verifiably produced a signature over the record CID, so a copied certificate proves nothing. The verifier then proves the certificate through the agent's `_ans-badge` DNS record and the transparency log's status token, and checks that the log holds a signed receipt for the same agent and name.

It:

1. Queries the database for signed records with verifiable names that have no verification, a verdict older than `name.ttl` minus one `name.interval` (so a verified record is re-verified before the API stops serving it), or a scheduled retry that is due
2. For each record, collects the signers: the certificates bound to the record's signatures (a certificate counts only when its key produced the signature over the record CID) and the public keys attached to the record. When part of this evidence cannot be read, a verdict against the rest is withheld and the record is `pending`; a verdict for it stands. A referrer whose payload does not decode as a signature or public key is skipped and logged, since anyone who can push referrers can attach one; only a referrer the store cannot read counts as evidence that could not be read
3. Runs the verification method selected by the name's protocol once per record
4. Stores the result (`verified`, `failed`, or `pending`) in the database for efficient API filtering

Records whose name parses but whose protocol has no method configured (for example `ans://` names while `name.ans.enabled` is false) are skipped without writing a row and counted as `skipped` in the run summary, so enabling the method takes effect on the next run rather than after the TTL. A name that does not parse at all is a `failed` row with method `none`. Rows the method verified before it was disabled are not rewritten until it is enabled again: the API serves them until their TTL, while `dirctl search --verified` lists them until the row changes or is deleted with the statement under Operator steps.

Records that share a host (protocol prefix and domain) with one whose lookup failed transiently earlier in the same run are deferred to the next run without a row change and counted as `deferred`, so an unreachable host costs one lookup per run.

`name.record_timeout` bounds one record's attempt, including pulling its signatures and public keys from the store.

#### ANS configuration

| Key | Environment variable | Default | Description |
|-----|----------------------|---------|-------------|
| `name.ans.enabled` | `RECONCILER_NAME_ANS_ENABLED` | `false` | Verify `ans://` names |
| `name.ans.trusted_log_hosts` | `RECONCILER_NAME_ANS_TRUSTED_LOG_HOSTS` | | Transparency-log hosts (`host` or `host:port`, comma-separated in the environment) that badge records may point at; required when enabled |
| `name.ans.root_keys` | `RECONCILER_NAME_ANS_ROOT_KEYS` | | Pinned root-key lines (`origin+kid+base64`) of the trusted logs, comma-separated in the environment |
| `name.ans.allow_unpinned_root_keys` | `RECONCILER_NAME_ANS_ALLOW_UNPINNED_ROOT_KEYS` | `false` | Run without pinned keys and fetch them from each log; trust then rests on TLS to the trusted hosts |
| `name.ans.timeout` | `RECONCILER_NAME_ANS_TIMEOUT` | `10s` | Total budget for one lookup (DNS, then the log fetches); must be shorter than `name.record_timeout` |
| `name.ans.dns_server` | `RECONCILER_NAME_ANS_DNS_SERVER` | | Resolver (`host:port`) for the `_ans-badge` lookups instead of the system resolver |
| `name.ans.ca_file` | `RECONCILER_NAME_ANS_CA_FILE` | | PEM certificates added to the system roots for transparency-log connections |

Slow DNS eats into the same `name.ans.timeout` budget as the log fetches; raise it if lookups time out on a healthy log.

The reconciler needs outbound DNS for the `_ans-badge` lookups and HTTPS (port 443, or the port given in `name.ans.trusted_log_hosts`) to the trusted logs. An invalid `name.ans.*` configuration, including a `ca_file` that cannot be read, stops the reconciler at startup and with it every other task; the log line `Reconciler failed` names the cause. `ca_file` is read once at startup, so restart the reconciler after replacing the file.

#### Result states and retries

- `verified` and `failed` are verdicts. A verified row is served until `name.ttl` after the time it verified. It is re-checked one `name.interval` before that (at least half the TTL after verifying); a transient failure at a re-check within the TTL leaves it `verified` and schedules a retry. A failed row is re-checked after `name.ttl`. A revoked agent, a name that does not match the attested one, a missing or unattested certificate and an expired certificate are all `failed`.
- `pending` means the last attempt failed transiently (DNS or the transparency log unreachable, a log answering anything but a verdict, or the store could not read one of the record's signatures or public keys) and no verdict is served. The first retry lands on the next run; each further transient failure doubles the delay, up to 24 hours. A method that reports its dependency as down sets the retry time directly without counting a strike.
- When a verified record's re-check fails transiently after its TTL has passed, the record becomes `pending` and keeps the certificate fingerprint, details and verification time it last verified with until a verdict replaces them. A verified record is never demoted by a count of failures.
- A failed record whose re-check fails transiently keeps `failed` and its own error, and follows the retry schedule.
- A record that has been `pending` for 24 hours (since its creation, or since the end of its TTL for a record demoted from `verified`) becomes `failed` with `verification unavailable for 24h; last: …`; later attempts follow the retry schedule, at most one a day.
- The stored error of a `pending` row starts with `transient: `. A record whose signatures or public keys could not be read stores `could not read the record's signatures` or `could not read the record's public keys` unless the evidence that was read verifies the name; the store error is in the reconciler log. A record carrying more signatures than the task examines (256) whose examined signers did not verify the name is `pending` with a message saying so.

`dirctl naming verify` reports the stored error for `pending` and `failed` rows.

#### Diagnosing

Start with the stored result of the record:

```sh
dirctl naming verify <cid> --output json
```

Then read the reconciler log:

- `Name verification did not verify`: one line per attempt that did not verify, with `cid`, `recordName`, `method`, `error` (the stored text), `cause` (the text of this attempt's failure, which differs from `error` when a `failed` row keeps its verdict), `transient`, `status` and, when a retry was scheduled, `consecutiveFailures` and `nextAttemptAt`.
- `Name verification complete`: one line per run with the `verified`, `failed`, `transient`, `skipped`, `deferred`, `aborted` and `persistFailed` counts and `durationMs`.
- `Could not read the record's signatures` and `Could not read the record's public keys`: the store error behind a row that stores the matching text.
- `Skipping referrer that does not decode as a signature` and `Skipping referrer that does not decode as a public key`: a referrer attached to the record whose payload is not what its type says; it is ignored and never withholds a verdict. The store logs `Skipping referrer whose content does not decode` for a referrer that is not a referrer at all.
- `Withholding the verdict`: the verdict the examined evidence produced and what could not be read.
- `Rejected attached certificates`: how many certificates attached to the record's signatures were set aside and why (`unbound` means the certificate's key did not produce the signature, the copied-certificate case).
- `No attached certificate names this agent within its validity period`: the bound certificates were set aside by the ANS method, counted by reason.
- `Badge lookup failed`: the resolver's error behind an `ans dns:` row.
- `Transparency log circuit opened`: a trusted log failed repeatedly; records that depend on it are rescheduled until the circuit closes.
- `Transparency log fetch failed`: the cause of one failed fetch from a log.

Stored errors of the ANS method start with the stage that failed:

| Prefix | Meaning |
|--------|---------|
| `ans name:` | The name's version is not a valid ANS version |
| `ans dns:` | No `_ans-badge` record for the agent host (the SDK also accepts a legacy `_ra-badge` record), or the lookup timed out |
| `ans log:` | The log's circuit is open after consecutive connection failures; the row waits for the cooldown |
| `ans root-keys:` | The log's root keys could not be fetched or parsed (unpinned mode) |
| `ans badge-url:` | The badge points at a log that is not in `name.ans.trusted_log_hosts` |
| `ans status-token:` | The log did not confirm the agent as connectable (`ACTIVE`, `WARNING` or `DEPRECATED`). `HTTP 410` means the agent is revoked or otherwise terminal and `HTTP 501` that the log does not serve the route; both are `failed`. Any other HTTP status is transient and leaves the row `pending`. `signed by unknown key id` means the log signed with a key that `name.ans.root_keys` does not contain; it is transient, so update the pinned keys |
| `ans receipt:` | The agent's receipt could not be fetched or did not verify; `HTTP 503` or `HTTP 404` means the event is not yet checkpointed, which is transient and leaves the row `pending`; `signed by unknown key id` is the same stale-pinned-keys case as above |
| `ans certificate:` | The attached certificate is not the one attested for the agent, or it is expired or not yet valid |

#### Operator steps

Enable the method in two steps when `ca_file` points at a mounted Secret: create the Secret, then set `name.ans.*`. Disabling the method (`name.ans.enabled: false`) does not touch stored rows.

Rollback after removing the ANS method, so rows it verified do not stay verified until the TTL:

```sql
UPDATE name_verifications SET status='failed', error='ans method removed', verified_at=NULL, next_attempt_at=NULL, consecutive_failures=0 WHERE method='ans';
```

Force re-verification of ANS rows on the next run after fixing a bad configuration; the rows are recreated without their retry schedule:

```sql
DELETE FROM name_verifications WHERE method='ans' AND status IN ('failed','pending');
```

A revoked agent is noticed at the row's next re-check, up to `name.ttl` later. To re-check verified ANS rows on the next run instead:

```sql
UPDATE name_verifications SET next_attempt_at=CURRENT_TIMESTAMP WHERE method='ans' AND status='verified';
```

Upgrade the API server and the reconciler together (the Helm chart does). An earlier reconciler does not write `verified_at`, so a row it verifies after the API server upgrade reads as unverified until the upgraded reconciler's next run. When a later release changes the stored `ans` details schema, upgrade the API server first: it reads rows written by any earlier schema version but rejects newer ones.

### Signature Task

The signature task verifies record signatures and caches results. It:

1. Queries the database for signed records with no or expired verification (per TTL)
2. For each record, collects signatures and public keys from the store
3. Verifies each signature using shared verification logic (key-based or OIDC)
4. Upserts verification results to the database

### Metrics Task

The metrics task refreshes computed usage metrics for locally known records. It:

1. Queries the search database for all locally known record CIDs
2. For each CID, queries the routing layer for the number of distinct announcing peers
3. Persists the provider count into the `record_usage_metrics` table for use in popularity ranking

The routing layer uses an embedded Badger store that does not support concurrent multi-process access. In standalone reconciler mode the task reaches the routing layer over gRPC rather than sharing the datastore directory.

### Scan Task

The scan task runs security scanners against record artifacts and persists the results. It:

1. Queries the database for records with no recent scan result (per configured TTL)
2. For each record, pulls the full record from the store
3. Runs each configured scanner (mcp-scanner, skill-scanner) independently
4. Pushes each scanner's `ScanReport` as an OCI referrer (`agntcy.dir.security.v1.ScanReport`) attached to the record CID
5. Upserts a summary row into the `scan_reports` table for efficient TTL-based filtering

Scanner failures for one runner do not block the others. Referrer storage failures are logged as warnings and do not abort the scan.
