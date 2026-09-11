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
- `ans://v{MAJOR}.{MINOR}.{PATCH}.{agentHost}[/path]` names: the record must carry a signature made with the agent's Agent Name Service (ANS) identity key, with the identity certificate attached (`dirctl sign --key <key> --certificate <identity-cert.pem>`). The task keeps only certificates whose key verifiably produced a signature over the record CID, so a copied certificate proves nothing. The verifier then proves the certificate through the agent's `_ans-badge` DNS record and the transparency log's status token and receipt.

It:

1. Queries the database for signed records with verifiable names that have no verification, an expired one (per `name.ttl`), or a scheduled retry that is due
2. For each record, collects the signers: verified certificate signatures for `ans://` names, the attached public keys for the others
3. Runs the verification method selected by the name's protocol once per record
4. Stores the result (`verified`, `failed`, or `pending`) in the database for efficient API filtering

Records whose protocol has no method configured (for example `ans://` names while `name.ans.enabled` is false) are skipped without writing a row and counted in one warning per run, so enabling the method takes effect on the next run rather than after the TTL.

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

#### Result states and retries

- `verified` and `failed` are verdicts. They are re-checked after `name.ttl`. A revoked agent, a name that does not match the attested one, a missing or unattested certificate and an expired certificate are all `failed`.
- `pending` means no verdict yet because every attempt failed transiently (DNS or the transparency log unreachable). Retries follow the schedule the scan task uses: the first retry after `name.interval`, doubling on each further strike, capped at 24 hours. A method that reports its dependency as down sets the retry time directly without counting a strike.
- A previously verified record keeps `verified`, its certificate fingerprint and its details through transient failures until the TTL expires; only the retry state and the error change.
- After 8 consecutive transient failures the row becomes `failed` with `verification unavailable after 8 consecutive transient failures; last: …` and is retried once a day.

`dirctl naming verify` reports the stored error for `pending` and `failed` rows.

#### Operator steps

Rollback after removing the ANS method, so rows it verified do not stay verified until the TTL:

```sql
UPDATE name_verifications SET status='failed', error='ans method removed' WHERE method='ans';
```

Force re-verification of failed rows after fixing a bad configuration:

```sql
UPDATE name_verifications SET next_attempt_at=CURRENT_TIMESTAMP WHERE method='ans' AND status='failed';
```

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
