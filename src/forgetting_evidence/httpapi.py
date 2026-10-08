"""HTTP layer for deletion-request acceptance, lookup, observation and
single-request and batched reconciliation.

The service exposes eighteen business endpoints:

* ``POST /requests`` -- accept a deletion request for a tenant. The JSON
  body must carry non-empty ``tenant_id``, ``subject_id`` and
  ``idempotency_key`` strings plus a non-empty ``scopes`` array of
  distinct non-empty strings.
* ``GET /requests`` -- the tenant-scoped, paginated listing of accepted
  requests. The tenant follows the existing ``X-Tenant-Id``/query rule;
  the optional ``status`` (comma-separated distinct lifecycle statuses),
  ``created_from`` (inclusive) and ``created_to`` (exclusive) RFC3339 UTC
  bounds, ``cursor`` and ``limit`` (1..1000, default 100) query
  parameters filter and page the result. The single-line JSON body
  carries exactly ``items`` and ``next_cursor``; each item carries
  exactly ``request_id``, ``status`` and ``created_at`` in ascending
  acceptance order, and ``next_cursor`` is the opaque continuation value
  or ``null`` at the end of the listing. Any other query parameter, a
  duplicated ``status`` value or a malformed filter answers 400.
* ``GET /requests/{request_id}`` -- return the accepted request's
  receipt, scoped to the tenant identified by the ``X-Tenant-Id`` header
  (or a ``tenant_id`` query parameter). The receipt is the record frozen
  at acceptance time and always reports ``accepted``; it never changes
  when the request's status subsequently advances.
* ``GET /requests/{request_id}/status`` -- read-only observation of the
  request's current state. The single-line JSON body carries exactly
  ``request_id``, ``status`` and ``created_at`` in that order; ``status``
  is the latest persisted state while ``created_at`` stays the original
  acceptance time.
* ``GET /requests/{request_id}/execution-log`` -- read-only observation
  of the request's execution attempts. The single-line JSON body carries
  exactly ``request_id`` and ``attempts``; attempts are ordered by
  ``attempt_number`` starting at 1 and each entry carries exactly
  ``attempt_number``, ``claimed_at``, ``lease_expires_at``, ``result``
  and ``completed_at``. An unfinished attempt has ``null`` ``result`` and
  ``completed_at``; a finished attempt carries its stored ``completed``
  or ``failed`` result and completion time.
* ``GET /requests/{request_id}/tombstones`` -- read-only, paginated
  publication of the tenant's deletion proofs for one request. The
  tenant follows the existing ``X-Tenant-Id``/query rule; the only
  query parameters are ``cursor`` and ``limit`` (1..1000, default 100).
  The single-line JSON body carries exactly ``request_id``,
  ``tombstones``, ``recorded_at``, ``evidence_digest`` and
  ``next_cursor`` in that order. ``tombstones`` holds only this page's
  entries in ascending normalized-scope Unicode code point order then
  ascending ``adapter_id``; each entry carries exactly ``adapter_id``,
  ``scope``, ``operation_id``, ``outcome`` (``deleted`` or ``absent``),
  ``proof_digest`` (64 lowercase hex characters) and ``recorded_at``.
  The top-level ``recorded_at`` and ``evidence_digest`` always describe
  the whole ledger (both ``null`` when it is empty), never just the
  page; ``next_cursor`` resumes strictly after this page's last entry
  while the ledger holds a following item and is ``null`` at the end.
  An unknown or duplicated query parameter, an invalid ``limit`` or an
  empty, malformed, foreign or stale ``cursor`` answers 400; an
  invalid, unknown or cross-tenant request id answers 404; a storage
  fault or a corrupt ledger answers 503 and never a partial page or a
  pseudo digest. The read never advances state, never creates an
  attempt or a tombstone and never changes the audit chain.
* ``GET /requests/{request_id}/evidence`` -- read-only request-level
  integrity verdict. The tenant follows the existing
  ``X-Tenant-Id``/query rule and the endpoint requires the
  ``request:read`` role. The single-line JSON body carries exactly
  ``request_id``, ``status``, ``event_count``, ``chain_hash`` and
  ``verified`` in that order: ``status`` and ``event_count`` are the
  current status and state-event count from the same database snapshot,
  ``chain_hash`` is that snapshot's persisted 64-character lowercase
  hexadecimal chain head (``null`` when the persisted value is not legal
  SHA-256 text), and ``verified`` is true only when the events are
  replayed event by event from that same snapshot -- every link
  recomputes to its stored hash from the genesis predecessor, sequences
  run gap-free from zero, the final event's status equals the current
  status and the final link equals the head bound to the request row.
  All five fields come from one committed snapshot, so a status advance
  or a concurrent write can never mix two transactions in one response.
  When the request row, events and head are readable, a deleted,
  altered, inserted, reordered or cross-request/cross-tenant rebound
  event -- or a head that is not legal SHA-256 text -- still answers 200
  with ``verified`` false (and a malformed head renders ``chain_hash``
  null); it is never a storage fault. A malformed, unknown or
  cross-tenant request id answers 404; a missing or invalid tenant
  answers 400; an unreadable database or a snapshot that cannot be read
  completely answers 503. The read never creates or changes a request,
  a state event, an execution attempt, a tombstone, a receipt, a policy
  catalog or an audit anchor.
  The read also honours HTTP conditional reads: every 200 response
  carries a strong ``ETag`` of the form ``"sha256:<64 lowercase hex>"``
  computed over the exact body bytes (including the trailing newline),
  so the same evidence always yields the same tag -- across repeat
  reads, concurrent readers and process restarts -- and any body change
  (a status advance, a new event or a changed chain head) yields a
  different tag. A request may send one ``If-None-Match`` header holding
  a comma-separated list of entity tags; when any whitespace-stripped
  double-quoted tag is exactly equal to the current tag, or a tag is
  ``*``, the answer is ``304`` with no body, a zero ``Content-Length``
  and the same ``ETag`` instead of the full 200 body. Non-matching
  tags, lists where no tag matches and weak ``W/``-prefixed tags all
  receive the full 200 body. More than one ``If-None-Match`` header, an
  empty field value, a control character or a value that is neither a
  legal double-quoted entity tag nor ``*`` answers 400 with exactly
  ``invalid_request`` after authentication, tenant and request-id
  resolution but before any storage access. The 404/503 outcomes above
  still take precedence over the conditional evaluation: the tag is
  only compared once the evidence has been read, and the conditional
  read never writes to the database or changes the rendered bytes.
* ``GET /requests/{request_id}/audit-timeline`` -- read-only
  request-level status-history timeline. The tenant follows the existing
  ``X-Tenant-Id``/query rule and the endpoint requires the
  ``request:read`` role; the query string accepts no parameter other
  than ``tenant_id`` -- a duplicated key, an unknown parameter or a
  missing or empty tenant answers 400. The single-line JSON body
  carries exactly ``request_id`` and ``events``; ``events`` are the
  persisted state events in occurrence order, each carrying exactly
  ``status`` and ``occurred_at`` (a canonical UTC RFC3339
  timestamp). The first event is the ``accepted`` acceptance event;
  only genuine status changes follow -- repeating the current status
  never appends an event -- and the final event's status equals the
  current persisted status. Execution attempts, tombstones, receipts
  and audit-chain/anchor events never enter the timeline. The request
  row and the ordered events are read from one committed snapshot
  and every link, sequence, edge, timestamp and head is replayed
  from that snapshot before anything renders, so an unreadable
  database, a damaged event or a history that cannot be read
  consistently answers 503 with the single ``error`` field only --
  never a half-timeline, a fabricated event or records mixed across
  transactions. Repeated reads and reads after a restart return the
  same order and the same timestamps. The read never advances
  state, never creates an attempt, a tombstone or a receipt, never
  writes an audit-chain record, an anchor, a policy catalog or
  inspection bookkeeping, and no subject, raw scope, idempotency
  key, token, claim credential, worker, SQL text or filesystem path
  is ever exposed. A malformed, unknown or cross-tenant request id
  answers 404; other methods answer 405 with ``Allow: GET`` and
  HEAD answers 405 with no body; a deeper path stays 404.
* ``GET /requests/{request_id}/audit-diagnosis`` -- read-only diagnosis
  of the request's persisted audit chain, the reason-carrying companion
  of the evidence verdict. The tenant follows the existing
  ``X-Tenant-Id``/query rule and the endpoint requires the
  ``request:read`` role; the query string accepts no parameter other
  than ``tenant_id`` -- a duplicated key, an unknown parameter or a
  missing or invalid tenant answers 400. The single-line JSON body
  carries exactly ``request_id``, ``trusted`` and ``reasons`` in that
  order: ``request_id`` is the normalized lowercase UUID, ``reasons``
  is the deduplicated list of stable, detail-free reason codes from
  :meth:`RequestStore.diagnose_chain` for the current database
  snapshot, sorted by Unicode code point, and ``trusted`` is true only
  when ``reasons`` is empty. An unanchored chain, a failed anchor
  authentication, an anchor head mismatch, a deleted, altered,
  inserted, reordered or cross-request/cross-tenant substituted event
  still answers 200 with non-empty ``reasons`` -- a diagnosable
  integrity problem is never a read failure. Repeated reads of the same
  persisted chain without new writes return byte-identical bodies, and
  no subject, raw scope, idempotency key, execution credential, anchor
  secret, SQL text or filesystem path is ever exposed. A malformed,
  unknown or cross-tenant request id answers 404; an unreadable
  database, an incomplete snapshot or a corrupt persisted record
  answers 503. The read never repairs, backfills, recomputes or
  overwrites anything: it never creates or changes a request, a state
  event, an execution attempt, a tombstone, a receipt, an audit anchor
  or a key generation, and it never writes an audit event or creates a
  batch.
* ``GET /requests/{request_id}/audit-bundle`` -- read-only export of
  the request's settled audit chain as a portable evidence bundle. The
  tenant follows the existing ``X-Tenant-Id``/query rule and the
  endpoint requires the ``request:read`` role; the query string accepts
  no parameter other than ``tenant_id`` -- a duplicated key, an unknown
  parameter or a missing or conflicting tenant answers 400. The body is
  the verbatim single-line compact UTF-8 JSON text (with its single
  trailing newline) produced by
  :meth:`RequestStore.export_audit_bundle` from the same database
  snapshot -- never wrapped in a response object, re-ordered, indented
  or summarised. Repeated reads at the same chain head return
  byte-identical bodies; status events appended afterwards produce a
  new bundle but never change a previously rendered text, and no other
  request's events, a subject, a raw scope, an idempotency key, a claim
  credential or any anchor secret is ever exposed. A malformed, unknown
  or cross-tenant request id answers 404 with one detail-free outcome;
  a request whose audit chain has not settled, whose historical anchor
  secret is missing or whose evidence is untrusted answers 409 with
  exactly ``audit_bundle_unavailable`` and never a partial text; an
  unreadable database, a failed snapshot read or corrupt evidence
  answers 503. The read never modifies persisted evidence, never
  writes an audit event and never creates a batch.
  The export also honours HTTP conditional reads: every 200 response
  carries a strong ``ETag`` of the form ``"sha256:<64 lowercase hex>"``
  computed over the exact body bytes, so the same body always yields
  the same tag -- across repeat reads, concurrent readers and process
  restarts -- and any body change yields a different tag. A request
  may send one ``If-None-Match`` header holding a comma-separated list
  of entity tags; when any whitespace-stripped double-quoted tag is
  exactly equal to the current tag, or a tag is ``*`` and the bundle
  is exportable, the answer is ``304`` with no body, a zero
  ``Content-Length`` and the same ``ETag`` instead of the full 200
  body. Non-matching tags, lists where no tag matches and weak
  ``W/``-prefixed tags all receive the full 200 body. More than one
  ``If-None-Match`` header, an empty field value, a control character
  or a value that is neither a legal double-quoted entity tag nor
  ``*`` answers 400 with exactly ``invalid_request`` after
  authentication, tenant and query validation but before any storage
  access. The 404/409/503 outcomes above still take precedence over
  the conditional evaluation: the tag is only compared once the
  bundle has been exported, and the conditional read never writes to
  the database, generates an event or changes the exported bytes.
* ``GET /requests/{request_id}/deletion-receipt`` -- read-only
  publication of the request's already-settled deletion execution
  receipt, so a caller recovers the frozen receipt without ever
  touching a signature key. The tenant follows the existing
  ``X-Tenant-Id``/query rule and the endpoint requires the
  ``request:read`` role; the query string accepts no parameter other
  than ``tenant_id`` -- a duplicated key, an unknown parameter or a
  missing or empty tenant answers 400. The body is the verbatim
  single-line compact UTF-8 JSON text (with its single trailing
  newline) returned by :meth:`RequestStore.get_receipt` for the same
  tenant and request -- exactly ``tenant_id``, ``request_id``,
  ``created_at``, ``completed_at``, ``scope_digest``,
  ``attempt_digest`` and ``tag`` in that fixed order, never wrapped,
  re-ordered, indented or recomputed. Repeated reads, reads across a
  process rebuild, concurrent reads and reads before and after a
  receipt key rotation all return byte-identical bodies, and no
  subject, raw scope, idempotency key, signature key, key fingerprint
  or execution credential is ever exposed. A malformed, unknown or
  cross-tenant request id answers 404 with one detail-free outcome; a
  request that exists but has no settled first receipt answers 409
  with exactly ``receipt_unavailable``; an unreadable database, a
  corrupt persisted receipt or an inconsistent snapshot answers 503.
  The read never mints a receipt, never registers a key generation,
  never advances any state and never rewrites any evidence.
  The read also honours HTTP conditional reads: every 200 response
  carries a strong ``ETag`` of the form ``"sha256:<64 lowercase hex>"``
  computed over the exact body bytes (including the trailing newline),
  so the same receipt always yields the same tag -- across repeat
  reads, concurrent readers and process restarts -- and any body
  change yields a different tag. A request may send one
  ``If-None-Match`` header holding a comma-separated list of entity
  tags; when any whitespace-stripped double-quoted tag is exactly
  equal to the current tag, or a tag is ``*`` and a receipt has
  settled, the answer is ``304`` with no body, a zero
  ``Content-Length`` and the same ``ETag`` instead of the full 200
  body. Non-matching tags, lists where no tag matches and weak
  ``W/``-prefixed tags all receive the full 200 body. More than one
  ``If-None-Match`` header, an empty field value, a control character
  or a value that is neither a legal double-quoted entity tag nor
  ``*`` answers 400 with exactly ``invalid_request`` after
  authentication, tenant and query validation but before any storage
  access. The 404/409/503 outcomes above still take precedence over
  the conditional evaluation: the tag is only compared once the
  receipt has been recovered, and the conditional read never writes
  to the database or changes the rendered bytes.
* ``GET /policy-catalog/versions`` -- read-only publication of the
  tenant's policy-catalog version history, without any subject detail.
  The tenant follows the existing ``X-Tenant-Id``/query rule; the query
  string accepts no parameter other than ``tenant_id`` -- a duplicated
  key, an unknown parameter or an empty or malformed tenant answers 400.
  The body is the verbatim single-line compact UTF-8 JSON text (with its
  single trailing newline) produced by
  :meth:`RequestStore.audit_policy_catalog`: exactly ``versions`` at the
  top level, versions in ascending order, each carrying exactly
  ``version``, ``effective_at``, ``rule_count``, ``exception_count`` and
  ``status`` -- never a policy id, selector, reason, subject or any raw
  catalog content. The read never creates or advances a catalog version,
  request, attempt, tombstone, receipt or audit record, so repeated
  reads and reads after a restart return the same snapshot. A tenant
  without publications answers 200 with an empty ``versions`` array; a
  corrupt catalog or any storage failure answers 503 and never a
  partial history or a fabricated summary.
* ``POST /policy-catalog/versions`` -- the single policy-catalog
  publication entry point. The JSON body must carry exactly
  ``tenant_id``, ``rules`` and ``exceptions``: the tenant is taken from
  the body alone, and the two catalogs follow the existing retention
  format -- ``rules`` maps each policy id to exactly ``selector``,
  ``days`` and ``reason`` and must hold the whole-data ``*`` default
  rule, ``exceptions`` maps each policy id to the same three plus
  ``subject``, with policy ids unique across both catalogs. The catalogs
  are normalized with the existing selector grammar, non-boolean
  non-negative day counts and non-empty reasons before storage is
  touched. On success the single-line JSON body carries exactly
  ``version`` and ``effective_at``: the first publication is version 1,
  republishing the same normalized catalog reuses the first version and
  its effective time without writing, and a different catalog is issued
  the next consecutive version. Concurrent identical publications land
  once; concurrent publications of different catalogs have a single
  winner and every losing call answers 409 with exactly
  ``policy_catalog_conflict``. A non-object body, missing or extra
  fields, an illegal catalog shape, an out-of-range value, a missing
  default rule or a duplicated policy id answers 400 and writes nothing;
  a storage fault or a failed transaction answers 503 and never leaves
  a half-written version.
* ``GET /policy-catalog/retention-trace`` -- read-only publication of the
per-scope retention evidence for one subject under one published
catalog version, backed by
:meth:`RequestStore.resolve_retention_trace`. Published versions are
the only catalog source: the query string carries one positive
integer ``version``, one ``subject_id`` and at least one repeatable
``scope`` selector; no request body or inline catalog is accepted.
The tenant follows the existing ``X-Tenant-Id``/query rule; repeated
``scope`` keys give the ordered selector sequence and the store's
existing normalization, precedence, Unicode code point tie ordering,
cross-scope maximum and first-winner tie rules decide the trace. The
body is the verbatim single-line compact UTF-8 JSON text (with its
single trailing newline) produced by the store for the same input:
exactly ``catalog_source``, ``subject_id``, ``scopes``,
``retention_days``, ``policy_id``, ``reason``, ``exception`` and
``scope_evidence`` in that order. The only accepted parameters are a
single ``tenant_id`` (header or query), a single ``subject_id``, a
single ``version`` and one or more ``scope`` selectors; an unknown or
duplicated parameter, an empty value, an illegal subject, selector or
version, a non-empty body or a tenant-selection error answers 400; a
version that does not exist, is unpublished or belongs to another
tenant answers 404 with one detail-free outcome; a corrupt catalog,
an unreadable database or a failed snapshot answers 503 and never a
partial text. Only ``GET`` is allowed: other methods answer 405 with
``Allow: GET``, a deeper path stays 404 and ``HEAD`` answers 405
with no body.
* ``POST /requests/{request_id}/reconcile`` -- reconcile exactly one
  request's execution record against its persisted state by calling the
  storage layer's :meth:`RequestStore.reconcile_execution`. The endpoint
  takes no business parameters: a missing ``Content-Length`` or a length
  of zero means there is no body; any other body answers 400. On success
  it answers 200 with the same single-line JSON shape as the status
  read -- exactly ``request_id``, ``status`` and ``created_at`` --
  rendering the current record after reconciliation. Repeating the call
  never changes a stable terminal state, historical attempts or existing
  timestamps; concurrent calls leave the unique outcome to the store's
  atomic commit. No subject, scope, idempotency key, worker, lease
  credential or attempt detail is ever exposed.
* ``POST /reconcile`` -- reconcile the tenant's pending requests in
  resumable batches by calling the storage layer's
  :meth:`RequestStore.reconcile_batch`. The tenant follows the existing
  ``X-Tenant-Id``/query rule; the only query parameters are ``cursor``
  and ``limit`` (1..1000, default 100), each at most once. The endpoint
  takes no body: a missing ``Content-Length`` or a length of zero means
  there is no body; any other body answers 400. Without a cursor a new
  persistent batch is created; with a cursor the batch it names is
  resumed from its durably committed position, so a retry after an
  interruption continues instead of restarting and never rewrites an
  already committed item. On success the single-line JSON body carries
  exactly ``batch_id``, ``next_cursor``, ``finished`` and ``items`` in
  that order: ``next_cursor`` is the opaque continuation string while
  the sweep is incomplete and ``null`` once it is finished,
  ``finished`` is the matching boolean, and ``items`` lists this call's
  reconciled non-accepted requests in ascending acceptance order, each
  carrying exactly ``request_id`` and ``status``. An unknown or
  duplicated query parameter, a missing or empty tenant, an invalid
  ``limit``, a non-empty body or a malformed, unknown or cross-tenant
  cursor answers 400 and neither advances a batch nor changes a
  request; an unreadable database, corrupt persisted batch state or a
  failed commit answers 503 and never leaves a half-settled item.
* ``GET /audit-inspection`` -- inspect the tenant's settled audit
  chains in resumable batches by calling the storage layer's
  :meth:`RequestStore.audit_inspection`, or read one batch's
  reason-aggregated metrics back through
  :meth:`RequestStore.audit_inspection_metrics`. The tenant follows
  the existing ``X-Tenant-Id``/query rule; the only query parameters
  are ``cursor``, ``batch_id`` and ``limit`` (1..1000, default 100),
  each at most once, and ``cursor`` and ``batch_id`` are mutually
  exclusive. Without either, a new persistent batch is created; with
  a cursor the batch it names is resumed from its durably committed
  position, so a retry after an interruption continues instead of
  restarting and never re-reports an already settled item; with a
  batch id the read-only metrics are answered instead and nothing is
  created, advanced or written. A scan success carries exactly
  ``batch_id``, ``next_cursor``, ``finished`` and ``items`` in that
  order: ``next_cursor`` is the opaque continuation string while the
  sweep is incomplete and ``null`` once it is finished, ``finished``
  is the matching boolean, and ``items`` lists this call's inspected
  requests in scan order, each carrying exactly ``request_id``,
  ``verified`` and ``reason`` -- the empty string when the request
  verified, otherwise the stable, detail-free reason code. A metrics
  success carries exactly ``batch_id``, ``scanned``, ``verified``,
  ``unverified``, ``reasons``, ``next_cursor`` and ``finished`` in
  that order: ``scanned`` equals ``verified`` plus ``unverified`` and
  ``reasons`` holds one ``{"reason", "count"}`` entry per distinct
  reason code, merged across the batch's unverified items and ordered
  by Unicode code point, each count a positive integer. An unknown or
  duplicated query parameter, a missing or empty tenant, an invalid
  ``limit`` or a malformed ``cursor`` or ``batch_id`` answers 400 and
  neither creates nor advances a batch; an unknown or cross-tenant
  batch id answers 404 with one detail-free outcome; an unreadable
  database, corrupt persisted inspection bookkeeping or a failed
  commit answers 503 and never a half-settled page or a partial
  aggregate. Concurrent continuations naming the same cursor let
  exactly one call advance and return the new items while the
  competing calls answer the winner's committed progress with an
  empty item list, and a sequential retry of an already-continued
  cursor never re-reports a settled item. No subject, raw scope,
  idempotency key, worker, credential, token, secret, SQL text or
  filesystem path is ever exposed.
* ``GET /audit-health`` -- the instantaneous, tenant-scoped audit
  health summary, the HTTP public read for the storage layer's
  read-only :meth:`RequestStore.audit_health` snapshot. The request
  carries no JSON business body and the tenant follows the existing
  ``X-Tenant-Id``/``tenant_id`` query rule; the query string accepts
  no parameter other than a single ``tenant_id`` -- a duplicated key,
  an unknown parameter or a missing or empty tenant answers 400. The
  single-line JSON body carries exactly ``total``, ``statuses``,
  ``verified``, ``unverified`` and ``reasons`` in that order:
  ``total`` is the tenant's request count, ``statuses`` carries the
  four lifecycle counts (``accepted``, ``processing``, ``completed``
  and ``failed``) with explicit zeros and always sums to ``total``,
  ``verified`` and ``unverified`` are complementary and also sum to
  ``total``, and ``reasons`` is a list of ``{"reason", "count"}``
  entries -- one per distinct stable reason code, merged across the
  tenant's unverified requests, ordered by Unicode code point, each
  count a positive integer, empty when every request verifies. The
  whole summary is read from one consistent read-only transaction, so
  a concurrent submission, status advance or inspection sweep can
  never mix half-settled fields from two transactions; the read never
  creates an inspection batch, advances a cursor, writes business,
  audit, anchor or key records or otherwise mutates anything. A
  tenant that holds no requests still answers 200 with an all-zero
  snapshot, never a missing-request error. An unreadable database,
  corrupt bookkeeping or evidence or a snapshot that cannot be taken
  consistently answers 503 with the single ``error`` field only,
  never a partial snapshot, a pseudo count, a tenant, a request id, a
  path or SQL text.

The observation endpoints never advance state, create an attempt or
write any bookkeeping; they only read persisted rows, so their answers
match the persisted records after a restart. They never expose a lease
credential, worker identity, subject, scope or any other request field.
Only the two reconcile endpoints may converge execution state,
through the storage layer's existing atomic semantics.

Status advancement (:meth:`RequestStore.transition`), the execution
orchestration (:meth:`RequestStore.claim_next`,
:meth:`RequestStore.finish_claim`, :meth:`RequestStore.renew_lease`,
:meth:`RequestStore.transfer_claim`,
:meth:`RequestStore.migrate_execution_leases`) and the deletion receipts
(:meth:`RequestStore.generate_receipt`,
:meth:`RequestStore.verify_receipt`,
:meth:`RequestStore.rotate_receipt_key`) and the anchor capability
(:meth:`RequestStore.verify_chain`,
:meth:`RequestStore.rotate_anchor_key`) and the read-only inspection
summaries (:meth:`RequestStore.audit_inspection_summary` and
:meth:`RequestStore.audit_metrics`) exist only on
the storage layer and are deliberately not exposed over HTTP: over HTTP
the service opens request acceptance, the acceptance-receipt lookup, the
read-only tenant-scoped listing, the six read-only observation reads,
the read-only request-level status timeline,
the read-only audit-chain diagnosis, the read-only audit-bundle export,
the read-only deletion-receipt recovery, the single-request execution
reconciliation, the read-only
policy-catalog version history, the policy-catalog publication, the
read-only published-version retention trace, the read-only
instantaneous audit-health summary and the batched audit
inspection with its read-only per-batch metrics
described above. The
current-status lookup (:meth:`RequestStore.get_status`), the
tenant-scoped listing (:meth:`RequestStore.list_requests`), the
execution log (:meth:`RequestStore.get_execution_log`), the tombstone
page read (:meth:`RequestStore.page_deletion_tombstones`), the
single-snapshot request evidence read
(:meth:`RequestStore.get_request_evidence`), the
single-snapshot request status timeline read
(:meth:`RequestStore.get_audit_timeline`), the
read-only audit-chain diagnosis
(:meth:`RequestStore.diagnose_chain`), the
audit-bundle export
(:meth:`RequestStore.export_audit_bundle`), the
read-only deletion-receipt recovery
(:meth:`RequestStore.get_receipt`), the
single-request reconciliation
(:meth:`RequestStore.reconcile_execution`), the batched reconciliation
(:meth:`RequestStore.reconcile_batch`), the catalog version
history (:meth:`RequestStore.audit_policy_catalog`), the catalog
publication (:meth:`RequestStore.publish_policy_catalog`), the
published-version retention trace
(:meth:`RequestStore.resolve_retention_trace`), the
instantaneous audit-health snapshot
(:meth:`RequestStore.audit_health`), the batched audit inspection
(:meth:`RequestStore.audit_inspection`) and the read-only per-batch
inspection metrics (:meth:`RequestStore.audit_inspection_metrics`)
back their HTTP
endpoints but remain storage-layer methods as well.

Success responses are a single line of JSON followed by a trailing
newline. Acceptance, receipt lookup, the status read and a successful
reconcile render exactly ``request_id``, ``status`` and ``created_at``
(in that order); the same idempotent request and every lookup return
byte-identical bodies. The execution-log read renders exactly
``request_id`` and ``attempts``. The batch reconcile renders exactly
``batch_id``, ``next_cursor``, ``finished`` and ``items``, each item
rendering exactly ``request_id`` and ``status``. The audit-inspection
scan renders exactly ``batch_id``, ``next_cursor``, ``finished`` and
``items``, each item rendering exactly ``request_id``, ``verified``
and ``reason``. The audit-inspection metrics read renders the store's
verbatim single-line compact metrics text with its single trailing
newline: exactly ``batch_id``, ``scanned``, ``verified``,
``unverified``, ``reasons``, ``next_cursor`` and ``finished``, each
reason rendering exactly ``reason`` and ``count``. The
listing read renders exactly ``items`` and ``next_cursor``, each item
rendering exactly ``request_id``, ``status`` and ``created_at``. The
evidence read renders exactly ``request_id``, ``status``,
``event_count``, ``chain_hash`` and ``verified``. The
audit-timeline read renders exactly ``request_id`` and
``events``; each event renders exactly ``status`` and
``occurred_at``. The
audit-diagnosis read renders exactly ``request_id``, ``trusted`` and
``reasons``. The
audit-bundle export renders the store's verbatim single-line compact
bundle text with its single trailing newline. The
deletion-receipt read renders the store's verbatim single-line compact
receipt text with its single trailing newline: exactly ``tenant_id``,
``request_id``, ``created_at``, ``completed_at``, ``scope_digest``,
``attempt_digest`` and ``tag`` in that order. The
tombstone page read renders exactly ``request_id``, ``tombstones``,
``recorded_at``, ``evidence_digest`` and ``next_cursor``, each
tombstone rendering exactly ``adapter_id``, ``scope``, ``operation_id``,
``outcome``, ``proof_digest`` and ``recorded_at``. The policy-catalog
history read renders exactly ``versions``, each version rendering
exactly ``version``, ``effective_at``, ``rule_count``,
``exception_count`` and ``status``. The policy-catalog publication
renders exactly ``version`` and ``effective_at``. The published-version
retention-trace read renders the store's verbatim single-line compact
trace text with its single trailing newline: exactly
``catalog_source``, ``subject_id``, ``scopes``, ``retention_days``,
``policy_id``, ``reason``, ``exception`` and ``scope_evidence`` in
that order, each scope-evidence item rendering exactly ``scope``,
``level``, ``policy_id``, ``exception`` and ``retention_days``. The audit-health
snapshot renders exactly ``total``, ``statuses``, ``verified``,
``unverified`` and ``reasons``; ``statuses`` renders exactly the four
lifecycle counts in fixed order and each reason renders exactly
``reason`` and ``count``.
Error responses are single-line JSON objects with exactly one key,
``error``, holding a stable error code:

``invalid_request`` (400), ``unauthorized`` (401), ``forbidden``
(403), ``idempotency_conflict`` (409), ``policy_catalog_conflict``
(409), ``audit_bundle_unavailable`` (409), ``receipt_unavailable``
(409), ``not_found`` (404),
``method_not_allowed`` (405) and
``storage_unavailable`` (503).

Optional token authentication and role-based access control can be
enabled by passing an auth configuration (see :func:`load_auth_config`)
to :func:`build_server` / :func:`make_handler`. Without it the service
keeps the unauthenticated contract described above. When enabled every
matched business request must present ``Authorization: Bearer <token>``
for a configured principal: a missing/malformed/unknown token answers
``401 unauthorized`` and a principal lacking the role required by the
endpoint, or acting on a tenant other than its own ``tenant_id``,
answers ``403 forbidden``. ``POST /requests`` requires
``request:submit`` and the target tenant is the body's ``tenant_id``;
each request-scoped observation GET endpoint and the audit-health
read require ``request:read`` and the target tenant follows the
existing ``X-Tenant-Id``/query rule; the
single-request reconciliation ``POST /requests/{request_id}/reconcile``
requires ``request:reconcile`` and its target tenant follows the same
existing ``X-Tenant-Id``/query rule; the
batch reconciliation ``POST /reconcile`` requires
``request:reconcile`` and its target tenant follows the same existing
``X-Tenant-Id``/query rule; the
batched audit inspection ``GET /audit-inspection`` requires
``request:reconcile`` and its target tenant follows the same existing
``X-Tenant-Id``/query rule; the policy-catalog history
``GET /policy-catalog/versions`` requires ``policy:read`` and its
target tenant follows the same existing ``X-Tenant-Id``/query rule;
the published-version retention trace
``GET /policy-catalog/retention-trace`` requires ``policy:read`` and
its target tenant follows the same existing
``X-Tenant-Id``/query rule;
the policy-catalog publication ``POST /policy-catalog/versions``
requires ``policy:write`` and its target tenant is the body's
``tenant_id``.
The configuration keeps accepting the ``request:submit``,
``request:read`` and ``request:reconcile`` roles alone: a principal
without ``policy:read`` or ``policy:write`` simply cannot use the
catalog endpoints, and an
existing configuration without them never fails to load. Authentication runs after
path/method routing (unknown paths stay 404, unsupported methods stay
405) but before payload validation and any storage access.
Tokens, roles and the configuration never enter a response, a raised
exception message, a log record, the database or any stored artifact.

No subject, scope, idempotency key, lease credential, worker identity,
database error text, SQL statement or filesystem path is ever placed in
a response, a log record or a raised exception message.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import sqlite3
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from .requests import (
    AuditBundleUnavailable,
    AuditInspectionNotFound,
    IdempotencyConflict,
    PolicyCatalogConflict,
    PolicyCatalogNotFound,
    ReceiptUnavailable,
    RequestNotFound,
    RequestStore,
)

__all__ = [
    "build_server",
    "make_handler",
    "DeferredRequestStore",
    "AuthConfig",
    "AuthConfigError",
    "load_auth_config",
]

_log = logging.getLogger(__name__)

_COLLECTION_PATH = "/requests"
_ITEM_PATH_PREFIX = "/requests/"
_POLICY_CATALOG_VERSIONS_PATH = "/policy-catalog/versions"
_POLICY_CATALOG_RETENTION_TRACE_PATH = "/policy-catalog/retention-trace"
_RECONCILE_BATCH_PATH = "/reconcile"
_AUDIT_HEALTH_PATH = "/audit-health"
_AUDIT_INSPECTION_PATH = "/audit-inspection"
_STATUS_RESOURCE = "status"
_EXECUTION_LOG_RESOURCE = "execution-log"
_TOMBSTONES_RESOURCE = "tombstones"
_EVIDENCE_RESOURCE = "evidence"
_AUDIT_TIMELINE_RESOURCE = "audit-timeline"
_AUDIT_DIAGNOSIS_RESOURCE = "audit-diagnosis"
_AUDIT_BUNDLE_RESOURCE = "audit-bundle"
_DELETION_RECEIPT_RESOURCE = "deletion-receipt"
_RECONCILE_RESOURCE = "reconcile"
_TENANT_HEADER = "X-Tenant-Id"
_AUTHORIZATION_HEADER = "Authorization"
_IF_NONE_MATCH_HEADER = "If-None-Match"
_BEARER_PREFIX = "Bearer "

# Reject oversized request bodies before they reach the database layer.
_MAX_BODY_BYTES = 1 << 20  # 1 MiB

_ROLE_SUBMIT = "request:submit"
_ROLE_READ = "request:read"
_ROLE_RECONCILE = "request:reconcile"
_ROLE_POLICY_READ = "policy:read"
_ROLE_POLICY_WRITE = "policy:write"
_ALLOWED_ROLES = frozenset(
    {
        _ROLE_SUBMIT,
        _ROLE_READ,
        _ROLE_RECONCILE,
        _ROLE_POLICY_READ,
        _ROLE_POLICY_WRITE,
    }
)

# Terminal attempt results, mirrored from the execution state machine so a
# corrupt or substituted store can never serialise another value.
_TERMINAL_RESULTS = frozenset({"completed", "failed"})

# The request lifecycle statuses the tenant-scoped listing accepts in its
# ``status`` filter and may serialise in an item.
_REQUEST_STATUSES = frozenset({"accepted", "processing", "completed", "failed"})

# The fixed lifecycle edges a timeline may show between consecutive
# events, mirrored from the storage layer so a corrupt or
# substituted store can never serialise a repeated current status or an
# edge the state machine does not allow.
_TIMELINE_TRANSITIONS = {
    "accepted": frozenset({"processing", "failed"}),
    "processing": frozenset({"completed", "failed"}),
    "completed": frozenset(),
    "failed": frozenset(),
}

# The canonical UTC RFC3339 shape every timeline occurrence time
# carries: the store writes a Z suffix and a six-digit microsecond
# fraction, so two values sort lexicographically in time order and a
# malformed or substituted timestamp never serialises.
_TIMESTAMP_RFC3339_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$"
)

# The query parameters the GET /requests listing understands; anything
# else is an invalid request.
_LIST_QUERY_PARAMS = frozenset(
    {"tenant_id", "status", "created_from", "created_to", "cursor", "limit"}
)
_LIST_LIMIT_RE = re.compile(r"^[0-9]+$")

# The business scope selector grammar, mirrored from the storage layer
# so a malformed retention-trace ``scope`` parameter is rejected before
# storage is touched: ``*``, ``<collection>*`` or
# ``<collection>:<entry>`` over the restricted lower-case alphabet.
_SCOPE_NAME_PATTERN = r"[a-z0-9_.-]+"
_SCOPE_SELECTOR_RE = re.compile(
    r"\*"
    rf"|{_SCOPE_NAME_PATTERN}\*"
    rf"|{_SCOPE_NAME_PATTERN}:{_SCOPE_NAME_PATTERN}"
)

# The query parameters the GET /requests/{request_id}/tombstones page
# read understands; anything else is an invalid request. ``tenant_id``
# keeps its historical header-or-query resolution and is validated
# separately.
_TOMBSTONES_QUERY_PARAMS = frozenset({"tenant_id", "cursor", "limit"})

# The query parameters the GET /policy-catalog/versions history read
# understands: only ``tenant_id``, which keeps its historical
# header-or-query resolution and is validated separately. Any other
# parameter, or any duplicated key, is an invalid request.
_POLICY_CATALOG_QUERY_PARAMS = frozenset({"tenant_id"})

# The query parameters the GET /policy-catalog/retention-trace read
# understands: ``tenant_id`` (header-or-query, at most once),
# ``subject_id`` (exactly once), ``version`` (exactly once) and
# ``scope`` (one or more times, giving the ordered selector sequence).
# Any other parameter, a duplicated single-value key, a missing or
# blank value, or the complete absence of a scope is an invalid
# request; the selector grammar itself is re-validated by the store
# before storage is touched.
_POLICY_CATALOG_RETENTION_TRACE_QUERY_PARAMS = frozenset(
    {"tenant_id", "subject_id", "version", "scope"}
)

# The query parameters the GET /requests/{request_id}/audit-bundle
# export understands: only ``tenant_id``, which keeps its historical
# header-or-query resolution and is validated separately. Any other
# parameter, or any duplicated key, is an invalid request.
_AUDIT_BUNDLE_QUERY_PARAMS = frozenset({"tenant_id"})

# The query parameters the GET /requests/{request_id}/audit-timeline
# read understands: only ``tenant_id``, which keeps its historical
# header-or-query resolution and is validated separately. Any other
# parameter, or any duplicated key, is an invalid request.
_AUDIT_TIMELINE_QUERY_PARAMS = frozenset({"tenant_id"})

# The query parameters the GET /requests/{request_id}/audit-diagnosis
# read understands: only ``tenant_id``, which keeps its historical
# header-or-query resolution and is validated separately. Any other
# parameter, or any duplicated key, is an invalid request.
_AUDIT_DIAGNOSIS_QUERY_PARAMS = frozenset({"tenant_id"})

# The query parameters the GET /requests/{request_id}/deletion-receipt
# read understands: only ``tenant_id``, which keeps its historical
# header-or-query resolution and is validated separately. Any other
# parameter, or any duplicated key, is an invalid request.
_DELETION_RECEIPT_QUERY_PARAMS = frozenset({"tenant_id"})

# The query parameters the POST /reconcile batched reconciliation
# understands; anything else is an invalid request. ``tenant_id`` keeps
# its historical header-or-query resolution and is validated separately.
_RECONCILE_BATCH_QUERY_PARAMS = frozenset({"tenant_id", "cursor", "limit"})

# The query parameters the GET /audit-health instantaneous snapshot
# read understands: only ``tenant_id``, which keeps its historical
# header-or-query resolution and is validated separately. Any other
# parameter, or any duplicated key, is an invalid request.
_AUDIT_HEALTH_QUERY_PARAMS = frozenset({"tenant_id"})

# The query parameters the GET /audit-inspection batched inspection
# understands; anything else is an invalid request. ``tenant_id`` keeps
# its historical header-or-query resolution and is validated separately;
# ``cursor`` and ``batch_id`` are mutually exclusive.
_AUDIT_INSPECTION_QUERY_PARAMS = frozenset(
    {"tenant_id", "cursor", "batch_id", "limit"}
)

# The four request lifecycle statuses an audit-health snapshot reports,
# in fixed serialisation order, mirrored from the storage layer so a
# corrupt or substituted store can never serialise another value.
_AUDIT_HEALTH_STATUSES = ("accepted", "processing", "completed", "failed")

# The only statuses a reconciled batch item may serialise: accepted rows
# are skipped without an item and terminal rows are never swept, so an
# item is a processing request that either kept its live lease or was
# compensated to failed.
_RECONCILE_ITEM_STATUSES = frozenset({"processing", "failed"})

# The JSON body keys of the POST /policy-catalog/versions publication:
# exactly the tenant and the two catalogs, nothing else.
_POLICY_CATALOG_PUBLISH_KEYS = frozenset(
    {"tenant_id", "rules", "exceptions"}
)

# The only outcomes a deletion tombstone may serialise, mirrored from
# the storage layer so a corrupt or substituted store can never
# serialise another value.
_TOMBSTONE_OUTCOMES = frozenset({"deleted", "absent"})

# A tombstone proof digest and the whole-ledger evidence digest are 64
# lowercase hexadecimal characters.
_HEX_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")

# Shape of the UTC RFC3339 timestamps an exported audit bundle carries,
# mirrored from the storage layer's renderer.
_RFC3339_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$"
)

# The exact field sets of an exported audit bundle, mirrored from the
# storage layer so a corrupt or substituted store can never serialise a
# subject, a raw scope, an idempotency key, a credential or any secret
# material into the body.
_AUDIT_BUNDLE_FIELDS = frozenset(
    {"request_id", "status", "events", "chain", "anchors", "generations"}
)
_AUDIT_BUNDLE_EVENT_FIELDS = frozenset(
    {"seq", "status", "occurred_at", "chain_hash"}
)
_AUDIT_BUNDLE_CHAIN_FIELDS = frozenset({"tenant_id", "event_count", "head"})
_AUDIT_BUNDLE_ANCHOR_FIELDS = frozenset(
    {"seq", "anchor_hmac", "key_generation"}
)
_AUDIT_BUNDLE_GENERATION_FIELDS = frozenset(
    {"generation", "key_fingerprint", "effective_at"}
)

# The exact field set and order of a deletion receipt, mirrored from the
# storage layer's renderer so a corrupt or substituted store can never
# serialise a subject, a raw scope, an idempotency key, a credential or
# any key material into the body.
_DELETION_RECEIPT_FIELDS = (
    "tenant_id",
    "request_id",
    "created_at",
    "completed_at",
    "scope_digest",
    "attempt_digest",
    "tag",
)

# The exact field set and order of a published-version retention
# trace, mirrored from the storage layer's renderer so a corrupt or
# substituted store can never serialise an unvalidated key or value
# into the body.
_RETENTION_TRACE_FIELDS = (
    "catalog_source",
    "subject_id",
    "scopes",
    "retention_days",
    "policy_id",
    "reason",
    "exception",
    "scope_evidence",
)
_RETENTION_TRACE_EVIDENCE_FIELDS = (
    "scope",
    "level",
    "policy_id",
    "exception",
    "retention_days",
)
_RETENTION_TRACE_LEVELS = frozenset({"entry", "group", "all"})
_RETENTION_TRACE_SOURCE_PUBLISHED = "published_version"

_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)

_INVALID_REQUEST = "invalid_request"
_UNAUTHORIZED = "unauthorized"
_FORBIDDEN = "forbidden"
_NOT_FOUND = "not_found"
_METHOD_NOT_ALLOWED = "method_not_allowed"
_IDEMPOTENCY_CONFLICT = "idempotency_conflict"
_POLICY_CATALOG_CONFLICT = "policy_catalog_conflict"
_AUDIT_BUNDLE_UNAVAILABLE = "audit_bundle_unavailable"
_RECEIPT_UNAVAILABLE = "receipt_unavailable"
_STORAGE_UNAVAILABLE = "storage_unavailable"


def _is_nonneg_int(value: object) -> bool:
    # bool is a subclass of int and 1.0 == 1: only exact integers count.
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _is_positive_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 1


class _BadRequest(Exception):
    """Internal signal for malformed or rejected client input."""


class _StorageUnavailable(Exception):
    """Internal signal: the backing database cannot be opened or used."""


class AuthConfigError(Exception):
    """The auth configuration file is missing, unreadable or invalid.

    The message is a fixed marker; it never quotes the offending token,
    path or configuration content.
    """


class AuthConfig:
    """Parsed, immutable bearer-token principals for RBAC.

    Principals map a non-empty bearer token to their tenant id and a set
    of roles. Tokens and roles are kept in process memory only and are
    never logged or persisted by this module.
    """

    def __init__(self, principals: list[dict]):
        # ``principals`` has already passed :func:`load_auth_config`; copy
        # into an immutable token -> (tenant_id, frozenset(roles)) map.
        by_token: dict[str, tuple[str, frozenset[str]]] = {}
        for principal in principals:
            by_token[principal["token"]] = (
                principal["tenant_id"],
                frozenset(principal["roles"]),
            )
        self._by_token = by_token

    def authenticate(self, token: str) -> tuple[str, frozenset[str]] | None:
        """Return ``(tenant_id, roles)`` for *token*, or ``None`` if unknown."""
        return self._by_token.get(token)


def load_auth_config(path: str) -> AuthConfig:
    """Read and validate the auth configuration file once, at startup.

    The file must be a UTF-8 JSON object with a ``principals`` array;
    each principal is an object carrying non-empty ``token`` and
    ``tenant_id`` strings plus a non-empty ``roles`` array of distinct
    values drawn from ``request:submit``, ``request:read``,
    ``request:reconcile``, ``policy:read`` and ``policy:write``. Tokens
    must be unique across principals. Any
    deviation -- including an unreadable or non-UTF-8 file, malformed
    JSON, a missing ``principals`` key or a principal missing/typing-wrong
    one of the required keys -- raises :class:`AuthConfigError` so the
    caller can refuse to bind.
    """
    # Suppress exception chaining ("from None"): the underlying OSError
    # carries the filesystem path and a decode/JSON error may quote file
    # content, neither of which may reach a raised exception message.
    try:
        with open(path, "rb") as handle:
            raw = handle.read()
    except OSError:
        raise AuthConfigError("auth_config_invalid") from None
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise AuthConfigError("auth_config_invalid") from None

    principals = _validate_auth_config(parsed)
    return AuthConfig(principals)


def _validate_auth_config(parsed: object) -> list[dict]:
    if not isinstance(parsed, dict) or "principals" not in parsed:
        raise AuthConfigError("auth_config_invalid")
    raw_principals = parsed["principals"]
    if not isinstance(raw_principals, list):
        raise AuthConfigError("auth_config_invalid")

    principals: list[dict] = []
    seen_tokens: set[str] = set()
    for entry in raw_principals:
        # Only the three specified keys are validated; their presence,
        # types and value domains are mandatory.
        if not isinstance(entry, dict) or not {
            "token",
            "tenant_id",
            "roles",
        } <= set(entry):
            raise AuthConfigError("auth_config_invalid")
        token = entry["token"]
        tenant_id = entry["tenant_id"]
        roles = entry["roles"]
        if not isinstance(token, str) or not token:
            raise AuthConfigError("auth_config_invalid")
        if not isinstance(tenant_id, str) or not tenant_id:
            raise AuthConfigError("auth_config_invalid")
        if not isinstance(roles, list) or not roles:
            raise AuthConfigError("auth_config_invalid")
        if not all(isinstance(role, str) for role in roles):
            raise AuthConfigError("auth_config_invalid")
        if len(set(roles)) != len(roles) or not set(roles) <= _ALLOWED_ROLES:
            raise AuthConfigError("auth_config_invalid")
        if token in seen_tokens:
            raise AuthConfigError("auth_config_invalid")
        seen_tokens.add(token)
        principals.append(
            {"token": token, "tenant_id": tenant_id, "roles": roles}
        )
    return principals


class DeferredRequestStore:
    """Lazily (re)initialising :class:`RequestStore` wrapper.

    Opening the store and creating the required tables is attempted once
    at construction (service startup); if the database cannot be created
    -- an unwritable path, a corrupt file, an I/O error -- startup still
    succeeds and every business call retries initialization, failing the
    single request with the stable ``storage_unavailable`` outcome. This
    keeps "database cannot be created" indistinguishable from "database
    became unusable": both answer HTTP 503 instead of taking the whole
    service down, and a storage path repaired at runtime heals on the
    next request without a restart.
    """

    def __init__(self, db_path: str):
        self._db_path = db_path
        self._lock = threading.Lock()
        self._store: RequestStore | None = None
        try:
            self._store = RequestStore(db_path)
        except (OSError, sqlite3.Error, RuntimeError):
            _log.warning("storage unavailable at startup")

    def _ready(self) -> RequestStore:
        if self._store is not None:
            return self._store
        with self._lock:
            if self._store is None:
                try:
                    self._store = RequestStore(self._db_path)
                except (OSError, sqlite3.Error, RuntimeError):
                    raise _StorageUnavailable
            return self._store

    def submit(self, tenant_id, subject_id, scopes, idempotency_key):
        return self._ready().submit(tenant_id, subject_id, scopes, idempotency_key)

    def get(self, tenant_id, request_id):
        return self._ready().get(tenant_id, request_id)

    def get_status(self, tenant_id, request_id):
        # Serves the read-only GET /requests/{request_id}/status endpoint.
        return self._ready().get_status(tenant_id, request_id)

    def list_requests(
        self,
        tenant_id,
        statuses=None,
        created_from=None,
        created_to=None,
        cursor=None,
        limit=None,
    ):
        # Serves the read-only GET /requests tenant-scoped listing.
        return self._ready().list_requests(
            tenant_id, statuses, created_from, created_to, cursor, limit
        )

    def transition(self, tenant_id, request_id, target_status):
        # Storage-layer only; not routed over HTTP, but proxied so this
        # wrapper stays a faithful RequestStore substitute.
        return self._ready().transition(
            tenant_id, request_id, target_status
        )

    def claim_next(self, tenant_id, worker_id, lease_seconds):
        # Execution orchestration is storage-layer only; like the status
        # machine it is never routed over HTTP.
        return self._ready().claim_next(tenant_id, worker_id, lease_seconds)

    def finish_claim(self, tenant_id, request_id, claim_token, result):
        return self._ready().finish_claim(
            tenant_id, request_id, claim_token, result
        )

    def renew_lease(self, tenant_id, request_id, claim_token, lease_seconds):
        # Lease renewal is storage-layer only; like the rest of the
        # execution orchestration it is never routed over HTTP.
        return self._ready().renew_lease(
            tenant_id, request_id, claim_token, lease_seconds
        )

    def transfer_claim(self, tenant_id, request_id, claim_token, lease_seconds):
        # The secure lease handover is storage-layer only; like the rest
        # of the execution orchestration it is never routed over HTTP.
        return self._ready().transfer_claim(
            tenant_id, request_id, claim_token, lease_seconds
        )

    def get_execution_log(self, tenant_id, request_id):
        # Serves the read-only GET /requests/{request_id}/execution-log
        # endpoint; strictly read-only, like get_status.
        return self._ready().get_execution_log(tenant_id, request_id)

    def page_deletion_tombstones(
        self, tenant_id, request_id, cursor=None, limit=None
    ):
        # Serves the read-only GET /requests/{request_id}/tombstones
        # endpoint; strictly read-only, like get_status.
        return self._ready().page_deletion_tombstones(
            tenant_id, request_id, cursor, limit
        )

    def reconcile_execution(self, tenant_id, request_id):
        # Backs the POST /requests/{request_id}/reconcile endpoint; the
        # store's atomic commit decides the unique reconciliation outcome.
        return self._ready().reconcile_execution(tenant_id, request_id)

    def reconcile_batch(self, tenant_id, cursor=None, limit=None):
        # Backs the POST /reconcile endpoint; the store's per-item atomic
        # commits decide the unique reconciliation outcome.
        return self._ready().reconcile_batch(tenant_id, cursor, limit)

    def migrate_execution_leases(self, tenant_id, cursor=None, limit=None):
        # The recoverable legacy-lease migration is storage-layer only;
        # like the rest of the execution orchestration it is never routed
        # over HTTP and exposes no new endpoint.
        return self._ready().migrate_execution_leases(
            tenant_id, cursor, limit
        )

    def verify_chain(self, tenant_id=None, request_id=None):
        # Full-chain anchor verification is storage-layer only; never
        # routed over HTTP.
        return self._ready().verify_chain(tenant_id, request_id)

    def diagnose_chain(self, tenant_id=None, request_id=None):
        # Serves the read-only GET /requests/{request_id}/audit-diagnosis
        # endpoint; the diagnosis only reports the stable reason codes
        # for the persisted chain and never repairs anything.
        return self._ready().diagnose_chain(tenant_id, request_id)

    def audit_inspection(self, tenant_id, cursor=None, limit=None):
        # Serves the GET /audit-inspection scan endpoint; the sweep is
        # read-only for every audit, anchor and key record and only the
        # store's inspection bookkeeping tables are written.
        return self._ready().audit_inspection(tenant_id, cursor, limit)

    def audit_inspection_summary(self, tenant_id, batch_id):
        # The read-only inspection summary is storage-layer only; never
        # routed over HTTP and never writes anything.
        return self._ready().audit_inspection_summary(tenant_id, batch_id)

    def audit_inspection_metrics(self, tenant_id, batch_id):
        # Serves the read-only GET /audit-inspection metrics query; the
        # aggregate is assembled from one consistent read-only
        # transaction and the read never creates a batch, advances a
        # cursor or writes anything.
        return self._ready().audit_inspection_metrics(tenant_id, batch_id)

    def audit_policy_catalog(self, tenant_id):
        # Serves the read-only GET /policy-catalog/versions endpoint;
        # strictly read-only, like get_status.
        return self._ready().audit_policy_catalog(tenant_id)

    def publish_policy_catalog(self, tenant_id, rules, exceptions):
        # Serves the POST /policy-catalog/versions publication endpoint;
        # the store's atomic commit decides the unique version outcome.
        return self._ready().publish_policy_catalog(
            tenant_id, rules, exceptions
        )

    def resolve_retention_trace(
        self, tenant_id, subject_id, scopes, version
    ):
        # Serves the read-only
        # GET /policy-catalog/retention-trace endpoint; the published
        # version is the sole catalog source and the read never writes.
        return self._ready().resolve_retention_trace(
            tenant_id,
            subject_id,
            scopes,
            version=version,
        )

    def get_request_evidence(self, tenant_id, request_id):
        # Serves the read-only GET /requests/{request_id}/evidence
        # endpoint; the current status, event count, persisted chain head
        # and verification verdict come from one committed snapshot and
        # the read never writes anything.
        return self._ready().get_request_evidence(tenant_id, request_id)

    def get_audit_timeline(self, tenant_id, request_id):
        # Serves the read-only GET /requests/{request_id}/audit-timeline
        # endpoint; the current status and the ordered state-event
        # timeline come from one committed snapshot, the read only
        # succeeds when that history is whole and it never writes
        # anything.
        return self._ready().get_audit_timeline(tenant_id, request_id)

    def export_audit_bundle(self, tenant_id, request_id):
        # Serves the read-only GET /requests/{request_id}/audit-bundle
        # endpoint; the settled chain is frozen from one committed
        # snapshot and the read never writes anything.
        return self._ready().export_audit_bundle(tenant_id, request_id)

    def get_receipt(self, tenant_id, request_id):
        # Serves the read-only GET /requests/{request_id}/deletion-receipt
        # endpoint; the settled first receipt is recovered byte-for-byte
        # without any signature key and the read never writes anything.
        return self._ready().get_receipt(tenant_id, request_id)

    def audit_health(self, tenant_id):
        # Serves the read-only GET /audit-health endpoint; the
        # instantaneous tenant snapshot is read from one committed
        # read-only transaction by the store and the read never creates
        # a batch, advances a cursor or writes anything.
        return self._ready().audit_health(tenant_id)


def _normalize_request_id(value: str) -> str:
    """Validate a request id as a UUID and return its canonical text."""
    if not _UUID_RE.match(value):
        raise _BadRequest("invalid request id")
    # Accept upper-case spellings but look the store up under the same
    # canonical form uuid4() rows were written with.
    return value.lower()


def build_server(
    store,
    host: str = "127.0.0.1",
    port: int = 8080,
    auth: AuthConfig | None = None,
) -> ThreadingHTTPServer:
    """Build (but do not start) the threaded HTTP server bound to *host*:*port*.

    With *auth* ``None`` (the default) the server keeps its
    unauthenticated contract; pass a loaded :class:`AuthConfig` to
    require bearer-token authentication and RBAC on the business
    endpoints.
    """
    handler = make_handler(store, auth)
    server = ThreadingHTTPServer((host, port), handler)
    # Worker threads must not keep the process alive on shutdown.
    server.daemon_threads = True
    return server


def make_handler(
    store: RequestStore,
    auth: AuthConfig | None = None,
) -> type[BaseHTTPRequestHandler]:
    """Build a handler class closed over *store* and optional *auth*."""

    class _DeletionRequestHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        # Do not advertise the runtime version.
        server_version = "forgetting-evidence/0.1"
        sys_version = ""

        def version_string(self) -> str:  # type: ignore[override]
            # BaseHTTPRequestHandler joins server/sys versions with a
            # space; with an empty sys version that leaves a trailing
            # space, so render the fixed token verbatim.
            return self.server_version

        # -- routing ---------------------------------------------------

        def _route(self) -> tuple[str | None, str | None]:
            path = urlsplit(self.path).path
            if path == _COLLECTION_PATH:
                return "collection", None
            if path == _POLICY_CATALOG_VERSIONS_PATH:
                return "policy_catalog_versions", None
            if path == _POLICY_CATALOG_RETENTION_TRACE_PATH:
                return "policy_catalog_retention_trace", None
            if path == _RECONCILE_BATCH_PATH:
                return "reconcile_batch", None
            if path == _AUDIT_HEALTH_PATH:
                return "audit_health", None
            if path == _AUDIT_INSPECTION_PATH:
                return "audit_inspection", None
            if path.startswith(_ITEM_PATH_PREFIX):
                segment = path[len(_ITEM_PATH_PREFIX) :]
                # Empty or nested segments do not name a request.
                if segment and "/" not in segment:
                    return "item", segment
                # The eight read-only observability sub-resources live
                # under a request id: /requests/{id}/status,
                # /requests/{id}/execution-log,
                # /requests/{id}/tombstones,
                # /requests/{id}/evidence,
                # /requests/{id}/audit-timeline,
                # /requests/{id}/audit-diagnosis,
                # /requests/{id}/audit-bundle and
                # /requests/{id}/deletion-receipt, alongside the single
                # reconciliation action /requests/{id}/reconcile. Deeper
                # nesting or any other suffix stays an unknown path (404).
                if "/" in segment:
                    item_id, suffix = segment.split("/", 1)
                    if item_id and "/" not in suffix:
                        if suffix == _STATUS_RESOURCE:
                            return "status", item_id
                        if suffix == _EXECUTION_LOG_RESOURCE:
                            return "execution_log", item_id
                        if suffix == _TOMBSTONES_RESOURCE:
                            return "tombstones", item_id
                        if suffix == _EVIDENCE_RESOURCE:
                            return "evidence", item_id
                        if suffix == _AUDIT_TIMELINE_RESOURCE:
                            return "audit_timeline", item_id
                        if suffix == _AUDIT_DIAGNOSIS_RESOURCE:
                            return "audit_diagnosis", item_id
                        if suffix == _AUDIT_BUNDLE_RESOURCE:
                            return "audit_bundle", item_id
                        if suffix == _DELETION_RECEIPT_RESOURCE:
                            return "deletion_receipt", item_id
                        if suffix == _RECONCILE_RESOURCE:
                            return "reconcile", item_id
            return None, None

        # -- method entry points --------------------------------------

        def do_POST(self) -> None:  # noqa: N802 - http.server naming
            self._guard(self._handle_post)

        def do_GET(self) -> None:  # noqa: N802 - http.server naming
            self._guard(self._handle_get)

        def do_HEAD(self) -> None:  # noqa: N802 - http.server naming
            # HEAD receives the same 405/404 routing as other unsupported
            # verbs, with headers but no body.
            self._guard(lambda: self._handle_unsupported_method(headless=True))

        def do_PUT(self) -> None:  # noqa: N802 - http.server naming
            self._guard(self._handle_unsupported_method)

        def do_DELETE(self) -> None:  # noqa: N802 - http.server naming
            self._guard(self._handle_unsupported_method)

        def do_PATCH(self) -> None:  # noqa: N802 - http.server naming
            self._guard(self._handle_unsupported_method)

        def do_OPTIONS(self) -> None:  # noqa: N802 - http.server naming
            self._guard(self._handle_unsupported_method)

        def handle_expect_100(self) -> bool:  # type: ignore[override]
            # Honour "Expect: 100-continue" so clients (e.g. curl with a
            # large body) send the payload instead of waiting for a
            # 100-continue that never arrives.
            return True

        def _guard(self, handler) -> None:
            try:
                handler()
            except _BadRequest:
                self._safe_error(400, _INVALID_REQUEST)
            except Exception:
                # A defect in request handling must surface as the
                # stable storage code only; never let http.server print a
                # traceback (which could quote SQL or paths) to stderr.
                _log.warning("request failed: %s", _STORAGE_UNAVAILABLE)
                self._safe_error(503, _STORAGE_UNAVAILABLE)

        def _handle_unsupported_method(self, headless: bool = False) -> None:
            kind, _ = self._route()
            if kind is None:
                self._reply_error(404, _NOT_FOUND, headless=headless)
            else:
                # The collection accepts POST (acceptance) and GET (the
                # tenant-scoped listing); the policy-catalog path accepts
                # POST (publication) and GET (the version history); the
                # item and the read-only sub-resources are GET-only; the
                # single-request and batched reconcile actions are
                # POST-only.
                if kind == "collection":
                    allowed = "GET, POST"
                elif kind == "policy_catalog_versions":
                    allowed = "GET, POST"
                elif kind in ("reconcile", "reconcile_batch"):
                    allowed = "POST"
                else:
                    allowed = "GET"
                self._reply_error(
                    405, _METHOD_NOT_ALLOWED, allowed=allowed, headless=headless
                )

        # -- authentication / authorization ----------------------------

        def _authorize(self, required_role: str) -> tuple[str, frozenset[str]] | None:
            """Authenticate the bearer token and check *required_role*.

            Returns the principal's ``(tenant_id, roles)`` on success.
            Replies ``401 unauthorized`` for a missing, malformed or
            unknown credential and ``403 forbidden`` when the role is
            absent; returns ``None`` in either case. No token material is
            ever logged or quoted in the response.
            """
            if auth is None:
                # Unauthenticated deployment: no principal and no gate.
                return ("", frozenset())
            header = self.headers.get(_AUTHORIZATION_HEADER)
            if header is None or not header.startswith(_BEARER_PREFIX):
                self._auth_rejected(401, _UNAUTHORIZED)
                return None
            token = header[len(_BEARER_PREFIX) :]
            if not token:
                self._auth_rejected(401, _UNAUTHORIZED)
                return None
            principal = auth.authenticate(token)
            if principal is None:
                self._auth_rejected(401, _UNAUTHORIZED)
                return None
            tenant_id, roles = principal
            if required_role not in roles:
                self._auth_rejected(403, _FORBIDDEN)
                return None
            return tenant_id, roles

        def _auth_rejected(self, status: int, code: str) -> None:
            # A rejected POST has not consumed its request body, so the
            # connection cannot serve another pipelined request; close it
            # after the error to keep keep-alive framing intact.
            if self.command == "POST":
                self.close_connection = True
            self._reply_error(status, code)

        def _tenant_allowed(
            self, principal_tenant: str, target_tenant: str
        ) -> bool:
            if auth is None:
                return True
            if target_tenant != principal_tenant:
                self._reply_error(403, _FORBIDDEN)
                return False
            return True

        def _handle_post(self) -> None:
            kind, segment = self._route()
            if kind is None:
                self._reply_error(404, _NOT_FOUND)
                return
            if kind == "reconcile":
                assert segment is not None
                self._serve_reconcile(segment)
                return
            if kind == "reconcile_batch":
                self._serve_reconcile_batch()
                return
            if kind == "policy_catalog_versions":
                self._serve_policy_catalog_publish()
                return
            if kind != "collection":
                self._reply_error(405, _METHOD_NOT_ALLOWED, allowed="GET")
                return
            # Authentication precedes payload validation and storage.
            principal = self._authorize(_ROLE_SUBMIT)
            if principal is None:
                return
            payload = self._read_json_object()
            tenant_id = _require_string(payload, "tenant_id")
            # The body's tenant is the authorization target; a principal
            # may only submit for its own tenant.
            if not self._tenant_allowed(principal[0], tenant_id):
                return
            subject_id = _require_string(payload, "subject_id")
            idempotency_key = _require_string(payload, "idempotency_key")
            scopes = _require_scopes(payload)
            try:
                receipt = store.submit(
                    tenant_id, subject_id, scopes, idempotency_key
                )
            except ValueError:
                # Defence in depth: the HTTP validation above is
                # authoritative, but a rejected store call writes nothing
                # and maps to the same client error.
                self._reply_error(400, _INVALID_REQUEST)
                return
            except IdempotencyConflict:
                self._reply_error(409, _IDEMPOTENCY_CONFLICT)
                return
            except _StorageUnavailable:
                _log.warning("request rejected: %s", _STORAGE_UNAVAILABLE)
                self._reply_error(503, _STORAGE_UNAVAILABLE)
                return
            except (sqlite3.Error, RuntimeError, OSError):
                # The store deliberately raises fixed-text RuntimeErrors;
                # sqlite/OSError text (locks, malformed images, paths)
                # must never reach the client.
                _log.warning("request rejected: %s", _STORAGE_UNAVAILABLE)
                self._reply_error(503, _STORAGE_UNAVAILABLE)
                return
            self._reply_receipt(200, receipt)

        def _handle_get(self) -> None:
            kind, segment = self._route()
            if kind is None:
                self._reply_error(404, _NOT_FOUND)
                return
            if kind == "collection":
                # The tenant-scoped, paginated listing of accepted
                # requests; read-only like the item observations.
                self._serve_list()
                return
            if kind == "policy_catalog_versions":
                # The read-only policy-catalog version history.
                self._serve_policy_catalog_versions()
                return
            if kind == "policy_catalog_retention_trace":
                # The read-only published-version per-scope retention
                # trace; strictly read-only like the version history.
                self._serve_policy_catalog_retention_trace()
                return
            if kind == "reconcile":
                # The reconciliation action is POST-only.
                self._reply_error(
                    405, _METHOD_NOT_ALLOWED, allowed="POST"
                )
                return
            if kind == "reconcile_batch":
                # The batched reconciliation action is POST-only.
                self._reply_error(
                    405, _METHOD_NOT_ALLOWED, allowed="POST"
                )
                return
            if kind == "audit_health":
                # The instantaneous, tenant-scoped health snapshot;
                # read-only like the other observation reads.
                self._serve_audit_health()
                return
            if kind == "audit_inspection":
                # The batched audit-inspection sweep and its read-only
                # per-batch metrics; the scan only writes the store's
                # inspection bookkeeping, the metrics query writes
                # nothing at all.
                self._serve_audit_inspection()
                return
            # item (acceptance receipt), status, execution_log,
            # tombstones, evidence, audit_timeline, audit_diagnosis,
            # audit_bundle and deletion_receipt are the nine GET-only
            # reads; authorization, tenant/id resolution and the
            # resulting error ordering are shared by all of them.
            assert segment is not None
            resolved = self._resolve_read(segment)
            if resolved is None:
                return
            tenant_id, request_id = resolved
            if kind == "item":
                self._serve_receipt(tenant_id, request_id)
            elif kind == "status":
                self._serve_status(tenant_id, request_id)
            elif kind == "execution_log":
                self._serve_execution_log(tenant_id, request_id)
            elif kind == "evidence":
                self._serve_evidence(tenant_id, request_id)
            elif kind == "audit_timeline":
                self._serve_audit_timeline(tenant_id, request_id)
            elif kind == "audit_diagnosis":
                self._serve_audit_diagnosis(tenant_id, request_id)
            elif kind == "audit_bundle":
                self._serve_audit_bundle(tenant_id, request_id)
            elif kind == "deletion_receipt":
                self._serve_deletion_receipt(tenant_id, request_id)
            else:
                self._serve_tombstones(tenant_id, request_id)

        def _resolve_read(self, segment: str) -> tuple[str, str] | None:
            """Authorize and resolve ``(tenant_id, request_id)`` for a GET.

            Thin wrapper over :meth:`_resolve_tenant_request` for the
            ``request:read`` role.
            """
            return self._resolve_tenant_request(segment, _ROLE_READ)

        def _resolve_tenant_request(
            self, segment: str, required_role: str
        ) -> tuple[str, str] | None:
            """Authorize and resolve ``(tenant_id, request_id)``.

            Returns ``None`` after already replying. Authentication runs
            before request-id validation and storage; with auth enabled the
            full tenant authorization completes before the id shape is even
            inspected, while the unauthenticated contract keeps its
            historical id-shape-before-tenant order.
            """
            principal = self._authorize(required_role)
            if principal is None:
                return None
            if auth is not None:
                # With auth enabled the full authorization -- including
                # resolving the target tenant and matching it -- completes
                # before request-id syntax is even inspected, so a foreign
                # principal cannot reach id validation or storage.
                try:
                    tenant_id = self._tenant_id()
                except _BadRequest:
                    self._reply_error(400, _INVALID_REQUEST)
                    return None
                if not self._tenant_allowed(principal[0], tenant_id):
                    return None
                try:
                    request_id = _normalize_request_id(segment)
                except _BadRequest:
                    # Unknown and malformed ids share one outcome.
                    self._reply_error(404, _NOT_FOUND)
                    return None
            else:
                # Unauthenticated contract keeps its historical order:
                # request-id shape is checked before the tenant header.
                try:
                    request_id = _normalize_request_id(segment)
                except _BadRequest:
                    self._reply_error(404, _NOT_FOUND)
                    return None
                try:
                    tenant_id = self._tenant_id()
                except _BadRequest:
                    self._reply_error(400, _INVALID_REQUEST)
                    return None
            return tenant_id, request_id

        def _serve_receipt(self, tenant_id: str, request_id: str) -> None:
            try:
                record = store.get(tenant_id, request_id)
            except RequestNotFound:
                # Missing ids and cross-tenant lookups are indistinguishable.
                self._reply_error(404, _NOT_FOUND)
                return
            except ValueError:
                self._reply_error(400, _INVALID_REQUEST)
                return
            except _StorageUnavailable:
                _log.warning("request rejected: %s", _STORAGE_UNAVAILABLE)
                self._reply_error(503, _STORAGE_UNAVAILABLE)
                return
            except (sqlite3.Error, RuntimeError, OSError):
                _log.warning("request rejected: %s", _STORAGE_UNAVAILABLE)
                self._reply_error(503, _STORAGE_UNAVAILABLE)
                return
            self._reply_receipt(200, record)

        def _serve_status(self, tenant_id: str, request_id: str) -> None:
            try:
                record = store.get_status(tenant_id, request_id)
            except RequestNotFound:
                self._reply_error(404, _NOT_FOUND)
                return
            except ValueError:
                self._reply_error(400, _INVALID_REQUEST)
                return
            except _StorageUnavailable:
                _log.warning("request rejected: %s", _STORAGE_UNAVAILABLE)
                self._reply_error(503, _STORAGE_UNAVAILABLE)
                return
            except (sqlite3.Error, RuntimeError, OSError):
                # Corrupt persisted rows surface as fixed-text RuntimeErrors.
                _log.warning("request rejected: %s", _STORAGE_UNAVAILABLE)
                self._reply_error(503, _STORAGE_UNAVAILABLE)
                return
            self._reply_status(record)

        def _serve_execution_log(self, tenant_id: str, request_id: str) -> None:
            try:
                attempts = store.get_execution_log(tenant_id, request_id)
            except RequestNotFound:
                self._reply_error(404, _NOT_FOUND)
                return
            except ValueError:
                self._reply_error(400, _INVALID_REQUEST)
                return
            except _StorageUnavailable:
                _log.warning("request rejected: %s", _STORAGE_UNAVAILABLE)
                self._reply_error(503, _STORAGE_UNAVAILABLE)
                return
            except (sqlite3.Error, RuntimeError, OSError):
                # Corrupt attempt rows surface as fixed-text OSErrors.
                _log.warning("request rejected: %s", _STORAGE_UNAVAILABLE)
                self._reply_error(503, _STORAGE_UNAVAILABLE)
                return
            self._reply_execution_log(request_id, attempts)

        def _serve_evidence(self, tenant_id: str, request_id: str) -> None:
            # The evidence read shares the other GET reads'
            # authorization and tenant/id resolution (done by the
            # caller); the If-None-Match header validation runs here,
            # before storage is touched. The store produces status,
            # event count, the persisted chain head and the verification
            # verdict from one committed snapshot; a tampered chain is
            # still a successful read with verified false, never a
            # storage fault.
            try:
                if_none_match = self._if_none_match_tags()
            except _BadRequest:
                self._reply_error(400, _INVALID_REQUEST)
                return
            try:
                record = store.get_request_evidence(tenant_id, request_id)
            except RequestNotFound:
                # Missing ids and cross-tenant lookups are indistinguishable.
                self._reply_error(404, _NOT_FOUND)
                return
            except ValueError:
                self._reply_error(400, _INVALID_REQUEST)
                return
            except _StorageUnavailable:
                _log.warning("request rejected: %s", _STORAGE_UNAVAILABLE)
                self._reply_error(503, _STORAGE_UNAVAILABLE)
                return
            except (sqlite3.Error, RuntimeError, OSError):
                # An unreadable database or a snapshot that cannot be read
                # completely surfaces as the fixed-text storage error.
                _log.warning("request rejected: %s", _STORAGE_UNAVAILABLE)
                self._reply_error(503, _STORAGE_UNAVAILABLE)
                return
            self._reply_evidence(record, if_none_match)

        def _serve_audit_timeline(self, tenant_id: str, request_id: str) -> None:
            # The timeline read shares the other GET reads'
            # authorization and tenant/id resolution (done by the
            # caller); the tenant-only query gate runs here, before
            # storage is touched. The store produces the current status
            # and the whole ordered state-event timeline from one
            # committed snapshot and only renders once that history is
            # whole; a damaged event, a split current status or an
            # unreadable snapshot is a storage fault, never a partial,
            # forged or mixed-transaction response. The read never
            # advances state and never creates an attempt, a tombstone,
            # a receipt, an audit-chain record, an anchor, a policy
            # catalog or inspection bookkeeping.
            try:
                self._audit_timeline_query_gate()
            except _BadRequest:
                self._reply_error(400, _INVALID_REQUEST)
                return
            try:
                timeline = store.get_audit_timeline(tenant_id, request_id)
            except RequestNotFound:
                # Malformed, unknown and cross-tenant ids share one
                # detail-free outcome.
                self._reply_error(404, _NOT_FOUND)
                return
            except ValueError:
                # Defence in depth: the HTTP resolution above is
                # authoritative, but a rejected store call reads nothing
                # and maps to the same client error.
                self._reply_error(400, _INVALID_REQUEST)
                return
            except _StorageUnavailable:
                _log.warning("request rejected: %s", _STORAGE_UNAVAILABLE)
                self._reply_error(503, _STORAGE_UNAVAILABLE)
                return
            except (sqlite3.Error, RuntimeError, OSError):
                # An unreadable database, corrupt state events or a
                # history that cannot be read consistently surfaces as
                # the fixed-text storage error; sqlite text (locks,
                # malformed images, paths) must never reach the
                # client, and no half-timeline is ever rendered.
                _log.warning("request rejected: %s", _STORAGE_UNAVAILABLE)
                self._reply_error(503, _STORAGE_UNAVAILABLE)
                return
            self._reply_audit_timeline(timeline)

        def _audit_timeline_query_gate(self) -> None:
            """Reject any query parameter other than a single ``tenant_id``.

            The timeline read takes no business parameters;
            ``tenant_id`` keeps its historical header-or-query
            resolution in ``_tenant_id``. An unknown parameter or
            any duplicated key (including ``tenant_id`` itself) is a
            bad request.
            """
            params = parse_qs(urlsplit(self.path).query, keep_blank_values=True)
            if not set(params) <= _AUDIT_TIMELINE_QUERY_PARAMS:
                raise _BadRequest("unknown query parameter")
            for values in params.values():
                if len(values) != 1:
                    raise _BadRequest("duplicate query parameter")

        def _serve_audit_diagnosis(self, tenant_id: str, request_id: str) -> None:
            # The audit-diagnosis read shares the other GET reads'
            # authorization and tenant/id resolution (done by the
            # caller); the tenant-only query gate runs here, before
            # storage is touched. The store's read-only chain diagnosis
            # reports the stable reason codes for the persisted evidence;
            # an untrusted chain is still a successful read with
            # non-empty reasons, never a storage fault.
            try:
                self._audit_diagnosis_query_gate()
            except _BadRequest:
                self._reply_error(400, _INVALID_REQUEST)
                return
            try:
                reasons = store.diagnose_chain(tenant_id, request_id)
            except RequestNotFound:
                # Missing ids and cross-tenant lookups are indistinguishable.
                self._reply_error(404, _NOT_FOUND)
                return
            except ValueError:
                # Defence in depth: the HTTP validation above is
                # authoritative, but a rejected store call reads nothing
                # and maps to the same client error.
                self._reply_error(400, _INVALID_REQUEST)
                return
            except _StorageUnavailable:
                _log.warning("request rejected: %s", _STORAGE_UNAVAILABLE)
                self._reply_error(503, _STORAGE_UNAVAILABLE)
                return
            except (sqlite3.Error, RuntimeError, OSError):
                # An unreadable database, an incomplete snapshot or a
                # corrupt persisted record surfaces as the fixed-text
                # storage error; sqlite text (locks, malformed images,
                # paths) must never reach the client.
                _log.warning("request rejected: %s", _STORAGE_UNAVAILABLE)
                self._reply_error(503, _STORAGE_UNAVAILABLE)
                return
            self._reply_audit_diagnosis(request_id, reasons)

        def _audit_diagnosis_query_gate(self) -> None:
            """Reject any query parameter other than a single ``tenant_id``.

            The diagnosis read takes no business parameters; ``tenant_id``
            keeps its historical header-or-query resolution in
            ``_tenant_id``. An unknown parameter or any duplicated key
            (including ``tenant_id`` itself) is a bad request.
            """
            params = parse_qs(urlsplit(self.path).query, keep_blank_values=True)
            if not set(params) <= _AUDIT_DIAGNOSIS_QUERY_PARAMS:
                raise _BadRequest("unknown query parameter")
            for values in params.values():
                if len(values) != 1:
                    raise _BadRequest("duplicate query parameter")

        def _serve_audit_bundle(self, tenant_id: str, request_id: str) -> None:
            # The audit-bundle export shares the other GET reads'
            # authorization and tenant/id resolution (done by the
            # caller); the tenant-only query gate and the If-None-Match
            # header validation run here, before storage is touched.
            # The store freezes the settled chain from one committed
            # snapshot; the read never writes anything.
            try:
                self._audit_bundle_query_gate()
                if_none_match = self._if_none_match_tags()
            except _BadRequest:
                self._reply_error(400, _INVALID_REQUEST)
                return
            try:
                text = store.export_audit_bundle(tenant_id, request_id)
            except RequestNotFound:
                # Malformed, unknown and cross-tenant ids share one
                # detail-free outcome.
                self._reply_error(404, _NOT_FOUND)
                return
            except ValueError:
                # Defence in depth: the HTTP validation above is
                # authoritative, but a rejected store call reads nothing
                # and maps to the same client error.
                self._reply_error(400, _INVALID_REQUEST)
                return
            except AuditBundleUnavailable:
                # The chain has not settled, a required historical
                # anchor secret is missing or the evidence is untrusted:
                # never a partial bundle.
                self._reply_error(409, _AUDIT_BUNDLE_UNAVAILABLE)
                return
            except _StorageUnavailable:
                _log.warning("request rejected: %s", _STORAGE_UNAVAILABLE)
                self._reply_error(503, _STORAGE_UNAVAILABLE)
                return
            except (sqlite3.Error, RuntimeError, OSError):
                # An unreadable database or a failed snapshot read
                # surfaces as the fixed-text storage error; sqlite text
                # (locks, malformed images, paths) must never reach the
                # client.
                _log.warning("request rejected: %s", _STORAGE_UNAVAILABLE)
                self._reply_error(503, _STORAGE_UNAVAILABLE)
                return
            self._reply_audit_bundle(text, if_none_match)

        def _if_none_match_tags(self) -> list[str] | None:
            """Validate the optional ``If-None-Match`` header into tags.

            Returns ``None`` when the header is absent. A single header
            carries a comma-separated list whose entries -- after
            stripping surrounding whitespace -- must each be ``*`` or a
            legal (optionally weak) double-quoted entity tag. More than
            one header, an empty field value, a control character or
            any other shape is a bad request rejected before storage is
            touched.
            """
            values = self.headers.get_all(_IF_NONE_MATCH_HEADER)
            if values is None:
                return None
            if len(values) != 1:
                raise _BadRequest("multiple If-None-Match headers")
            value = values[0].strip(" \t")
            if not value:
                raise _BadRequest("empty If-None-Match")
            # Horizontal tab is list whitespace; every other control
            # character (and DEL) is rejected outright.
            if any(
                (ord(char) < 0x20 and char != "\t") or ord(char) == 0x7F
                for char in value
            ):
                raise _BadRequest("control character in If-None-Match")
            tags: list[str] = []
            pos = 0
            end = len(value)
            while True:
                start = pos
                if value.startswith("W/", pos):
                    pos += 2
                if pos < end and value[pos] == '"':
                    close = value.find('"', pos + 1)
                    if close == -1:
                        raise _BadRequest("invalid entity tag")
                    inner = value[pos + 1 : close]
                    # etagc excludes DQUOTE (structural here) and SP;
                    # control characters were rejected above.
                    if any(ord(char) <= 0x20 for char in inner):
                        raise _BadRequest("invalid entity tag")
                    pos = close + 1
                elif pos == start and pos < end and value[pos] == "*":
                    pos += 1
                else:
                    raise _BadRequest("invalid entity tag")
                tags.append(value[start:pos])
                # Optional whitespace, then the next comma or the end.
                while pos < end and value[pos] in " \t":
                    pos += 1
                if pos == end:
                    break
                if value[pos] != ",":
                    raise _BadRequest("invalid entity tag list")
                pos += 1
                while pos < end and value[pos] in " \t":
                    pos += 1
                if pos == end:
                    # A trailing comma leaves an empty field.
                    raise _BadRequest("empty entity tag")
            return tags

        def _audit_bundle_query_gate(self) -> None:
            """Reject any query parameter other than a single ``tenant_id``.

            The export takes no business parameters; ``tenant_id`` keeps
            its historical header-or-query resolution in ``_tenant_id``.
            An unknown parameter or any duplicated key (including
            ``tenant_id`` itself) is a bad request.
            """
            params = parse_qs(urlsplit(self.path).query, keep_blank_values=True)
            if not set(params) <= _AUDIT_BUNDLE_QUERY_PARAMS:
                raise _BadRequest("unknown query parameter")
            for values in params.values():
                if len(values) != 1:
                    raise _BadRequest("duplicate query parameter")

        def _serve_deletion_receipt(self, tenant_id: str, request_id: str) -> None:
            # The deletion-receipt read shares the other GET reads'
            # authorization and tenant/id resolution (done by the
            # caller); the tenant-only query gate and the If-None-Match
            # header validation run here, before storage is touched.
            # The store recovers the already-settled first receipt
            # strictly read-only: the read never mints a receipt, never
            # registers a key generation and never advances any state,
            # and no signature key is presented.
            try:
                self._deletion_receipt_query_gate()
                if_none_match = self._if_none_match_tags()
            except _BadRequest:
                self._reply_error(400, _INVALID_REQUEST)
                return
            try:
                text = store.get_receipt(tenant_id, request_id)
            except RequestNotFound:
                # Malformed, unknown and cross-tenant ids share one
                # detail-free outcome.
                self._reply_error(404, _NOT_FOUND)
                return
            except ValueError:
                # Defence in depth: the HTTP validation above is
                # authoritative, but a rejected store call reads nothing
                # and maps to the same client error.
                self._reply_error(400, _INVALID_REQUEST)
                return
            except ReceiptUnavailable:
                # The request exists but no first receipt has settled:
                # accepted, processing, failed or completed without a
                # settled execution record all share this one outcome.
                self._reply_error(409, _RECEIPT_UNAVAILABLE)
                return
            except _StorageUnavailable:
                _log.warning("request rejected: %s", _STORAGE_UNAVAILABLE)
                self._reply_error(503, _STORAGE_UNAVAILABLE)
                return
            except (sqlite3.Error, RuntimeError, OSError):
                # An unreadable database, a corrupt persisted receipt or
                # a snapshot that cannot be taken consistently surfaces
                # as the fixed-text storage error; sqlite text (locks,
                # malformed images, paths) must never reach the client.
                _log.warning("request rejected: %s", _STORAGE_UNAVAILABLE)
                self._reply_error(503, _STORAGE_UNAVAILABLE)
                return
            self._reply_deletion_receipt(text, if_none_match)

        def _deletion_receipt_query_gate(self) -> None:
            """Reject any query parameter other than a single ``tenant_id``.

            The receipt read takes no business parameters; ``tenant_id``
            keeps its historical header-or-query resolution in
            ``_tenant_id``. An unknown parameter or any duplicated key
            (including ``tenant_id`` itself) is a bad request.
            """
            params = parse_qs(urlsplit(self.path).query, keep_blank_values=True)
            if not set(params) <= _DELETION_RECEIPT_QUERY_PARAMS:
                raise _BadRequest("unknown query parameter")
            for values in params.values():
                if len(values) != 1:
                    raise _BadRequest("duplicate query parameter")

        def _reply_deletion_receipt(
            self, text: object, if_none_match: list[str] | None = None
        ) -> None:
            # The body is the store's verbatim single-line compact JSON
            # text with its single trailing newline. It is still
            # re-validated field by field before it is emitted: a
            # corrupt or substituted store must never serialise a
            # subject, a raw scope, an idempotency key, a worker, a
            # credential, a key fingerprint or any key material into the
            # body, and a malformed receipt surfaces as the stable
            # storage code, never as a partial text.
            if (
                not isinstance(text, str)
                or not text.endswith("\n")
                or text.endswith("\n\n")
                or "\n" in text[:-1]
                or "\r" in text
            ):
                raise RuntimeError("malformed deletion receipt from store")
            try:
                payload = json.loads(text[:-1])
            except ValueError:
                raise RuntimeError("malformed deletion receipt from store") from None
            if not isinstance(payload, dict) or set(payload) != set(
                _DELETION_RECEIPT_FIELDS
            ):
                raise RuntimeError("malformed deletion receipt from store")
            for name in _DELETION_RECEIPT_FIELDS:
                value = payload[name]
                if not isinstance(value, str) or not value:
                    raise RuntimeError("malformed deletion receipt from store")
            for name in ("created_at", "completed_at"):
                if not _RFC3339_RE.match(payload[name]):
                    raise RuntimeError("malformed deletion receipt from store")
            for name in ("scope_digest", "attempt_digest", "tag"):
                if not _HEX_DIGEST_RE.match(payload[name]):
                    raise RuntimeError("malformed deletion receipt from store")
            # The emitted bytes must be exactly the compact single-line
            # rendering of the validated payload in the fixed field
            # order; anything else (extra whitespace, a reserialised
            # duplicate key, a reordered field) is not the store's
            # verbatim text.
            canonical = (
                json.dumps(
                    {name: payload[name] for name in _DELETION_RECEIPT_FIELDS},
                    ensure_ascii=False,
                    separators=(",", ":"),
                )
                + "\n"
            )
            if text != canonical:
                raise RuntimeError("malformed deletion receipt from store")
            body = text.encode("utf-8")
            # The strong ETag is the SHA-256 of the exact body bytes, so
            # the same bytes always yield the same tag -- across repeat
            # reads, concurrent readers and process restarts -- and any
            # byte change yields a different tag.
            etag = '"sha256:' + hashlib.sha256(body).hexdigest() + '"'
            if if_none_match is not None and _entity_tags_match(
                if_none_match, etag
            ):
                self._reply_not_modified(etag)
                return
            self._write_body(200, body, etag=etag)

        def _serve_tombstones(self, tenant_id: str, request_id: str) -> None:
            # The tombstone page read shares the other GET reads'
            # authorization and tenant/id resolution (done by the
            # caller); the page-specific query parameters are validated
            # here, before storage is touched.
            try:
                page_args = self._tombstone_page_args()
            except _BadRequest:
                self._reply_error(400, _INVALID_REQUEST)
                return
            try:
                page = store.page_deletion_tombstones(
                    tenant_id, request_id, **page_args
                )
            except RequestNotFound:
                # Missing ids and cross-tenant lookups are indistinguishable.
                self._reply_error(404, _NOT_FOUND)
                return
            except ValueError:
                # The store's fixed-text page ValueError covers every
                # invalid limit or cursor shape, including a cursor bound
                # to another tenant, another request or a stale snapshot.
                self._reply_error(400, _INVALID_REQUEST)
                return
            except _StorageUnavailable:
                _log.warning("request rejected: %s", _STORAGE_UNAVAILABLE)
                self._reply_error(503, _STORAGE_UNAVAILABLE)
                return
            except (sqlite3.Error, RuntimeError, OSError):
                # A corrupt tombstone or finish record surfaces as the
                # fixed-text OSError; no partial page or pseudo digest is
                # ever rendered.
                _log.warning("request rejected: %s", _STORAGE_UNAVAILABLE)
                self._reply_error(503, _STORAGE_UNAVAILABLE)
                return
            self._reply_tombstone_page(page)

        def _tombstone_page_args(self) -> dict[str, object]:
            """Validate the tombstone-page query string into store arguments.

            Only ``tenant_id``, ``cursor`` and ``limit`` may appear
            (``tenant_id`` keeps its historical header-or-query
            resolution in ``_tenant_id``); ``cursor`` and ``limit`` may
            each appear at most once. Every other shape is a bad
            request; the store re-validates the values themselves as
            defence in depth.
            """
            params = parse_qs(urlsplit(self.path).query, keep_blank_values=True)
            if not set(params) <= _TOMBSTONES_QUERY_PARAMS:
                raise _BadRequest("unknown query parameter")
            page_args: dict[str, object] = {}
            for name in ("cursor", "limit"):
                values = params.get(name)
                if values is None:
                    continue
                if len(values) != 1:
                    raise _BadRequest(f"duplicate {name}")
                value = values[0]
                if name == "limit":
                    # Far more digits than the 1..1000 domain can ever
                    # hold is a bad request, not a storage fault (and an
                    # unbounded digit string must never reach int()).
                    if not _LIST_LIMIT_RE.match(value) or len(value) > 10:
                        raise _BadRequest("invalid limit")
                    page_args["limit"] = int(value)
                elif not value:
                    raise _BadRequest("invalid cursor")
                else:
                    page_args["cursor"] = value
            return page_args

        def _serve_reconcile(self, segment: str) -> None:
            # The single-request reconcile shares the read endpoints'
            # authorization and tenant/id resolution: authentication first,
            # then the tenant (header or query) and its match against the
            # principal, then request-id syntax. The reconcile-specific
            # empty-body gate runs only afterwards, so a wrong credential
            # never gets to probe ids or payload shape.
            resolved = self._resolve_tenant_request(segment, _ROLE_RECONCILE)
            if resolved is None:
                return
            tenant_id, request_id = resolved
            try:
                self._read_empty_body()
            except _BadRequest:
                # A rejected body has been consumed (or the connection is
                # marked for close when it cannot be) before the error.
                self._reply_error(400, _INVALID_REQUEST)
                return
            try:
                record = store.reconcile_execution(tenant_id, request_id)
            except RequestNotFound:
                # Missing ids and cross-tenant lookups are indistinguishable.
                self._reply_error(404, _NOT_FOUND)
                return
            except ValueError:
                # Defence in depth: the HTTP resolution above is
                # authoritative, but a rejected store call converges
                # nothing and maps to the same client error.
                self._reply_error(400, _INVALID_REQUEST)
                return
            except _StorageUnavailable:
                _log.warning("request rejected: %s", _STORAGE_UNAVAILABLE)
                self._reply_error(503, _STORAGE_UNAVAILABLE)
                return
            except (sqlite3.Error, RuntimeError, OSError):
                # A failed atomic commit or a corrupt execution record
                # surfaces as fixed-text RuntimeError/OSError; sqlite text
                # (locks, malformed images, paths) must never reach the
                # client, and the store guarantees no half-converged row.
                _log.warning("request rejected: %s", _STORAGE_UNAVAILABLE)
                self._reply_error(503, _STORAGE_UNAVAILABLE)
                return
            # The reconciled record has the identical fixed shape and
            # field order as the status read: request_id, status,
            # created_at, nothing else.
            self._reply_status(record)

        def _serve_reconcile_batch(self) -> None:
            # The batched reconcile shares the read endpoints'
            # authorization and tenant resolution: authentication first,
            # then the tenant (header or query) and its match against the
            # principal, then the query-parameter gate and the empty-body
            # gate, then storage. A rejected call never creates or
            # advances a batch and never changes a request.
            principal = self._authorize(_ROLE_RECONCILE)
            if principal is None:
                return
            try:
                tenant_id = self._tenant_id()
            except _BadRequest:
                self._reply_error(400, _INVALID_REQUEST)
                return
            if not self._tenant_allowed(principal[0], tenant_id):
                return
            try:
                batch_args = self._reconcile_batch_args()
                self._read_empty_body()
            except _BadRequest:
                # A rejected body has been consumed (or the connection is
                # marked for close when it cannot be) before the error.
                self._reply_error(400, _INVALID_REQUEST)
                return
            try:
                result = store.reconcile_batch(tenant_id, **batch_args)
            except ValueError:
                # The store's fixed-text batch ValueError covers every
                # invalid limit or cursor shape, including a cursor bound
                # to another tenant or a batch that never existed.
                self._reply_error(400, _INVALID_REQUEST)
                return
            except _StorageUnavailable:
                _log.warning("request rejected: %s", _STORAGE_UNAVAILABLE)
                self._reply_error(503, _STORAGE_UNAVAILABLE)
                return
            except (sqlite3.Error, RuntimeError, OSError):
                # Corrupt persisted batch state and every storage fault
                # surface as the fixed-text OSError; sqlite text (locks,
                # malformed images, paths) must never reach the client,
                # and the store guarantees no half-settled item.
                _log.warning("request rejected: %s", _STORAGE_UNAVAILABLE)
                self._reply_error(503, _STORAGE_UNAVAILABLE)
                return
            self._reply_reconcile_batch(result)

        def _reconcile_batch_args(self) -> dict[str, object]:
            """Validate the batch-reconcile query string into store arguments.

            Only ``tenant_id``, ``cursor`` and ``limit`` may appear, each
            at most once (``tenant_id`` keeps its historical
            header-or-query resolution in ``_tenant_id``). Every other
            shape is a bad request; the store re-validates the values
            themselves as defence in depth.
            """
            params = parse_qs(urlsplit(self.path).query, keep_blank_values=True)
            if not set(params) <= _RECONCILE_BATCH_QUERY_PARAMS:
                raise _BadRequest("unknown query parameter")
            batch_args: dict[str, object] = {}
            for name in ("tenant_id", "cursor", "limit"):
                values = params.get(name)
                if values is None:
                    continue
                if len(values) != 1:
                    raise _BadRequest(f"duplicate {name}")
                value = values[0]
                if name == "limit":
                    # Far more digits than the 1..1000 domain can ever
                    # hold is a bad request, not a storage fault (and an
                    # unbounded digit string must never reach int()).
                    if not _LIST_LIMIT_RE.match(value) or len(value) > 10:
                        raise _BadRequest("invalid limit")
                    batch_args["limit"] = int(value)
                elif name == "cursor":
                    if not value:
                        raise _BadRequest("invalid cursor")
                    batch_args["cursor"] = value
            return batch_args

        def _serve_list(self) -> None:
            # The tenant-scoped listing shares the read endpoints'
            # authorization and tenant resolution: authentication first,
            # then the tenant (header or query) and its match against the
            # principal, then query-parameter validation, then storage.
            principal = self._authorize(_ROLE_READ)
            if principal is None:
                return
            try:
                tenant_id = self._tenant_id()
            except _BadRequest:
                self._reply_error(400, _INVALID_REQUEST)
                return
            if not self._tenant_allowed(principal[0], tenant_id):
                return
            try:
                filters = self._list_filters()
            except _BadRequest:
                self._reply_error(400, _INVALID_REQUEST)
                return
            try:
                page = store.list_requests(tenant_id, **filters)
            except ValueError:
                # The store's fixed-text listing ValueError covers every
                # invalid filter, limit or cursor shape.
                self._reply_error(400, _INVALID_REQUEST)
                return
            except _StorageUnavailable:
                _log.warning("request rejected: %s", _STORAGE_UNAVAILABLE)
                self._reply_error(503, _STORAGE_UNAVAILABLE)
                return
            except (sqlite3.Error, RuntimeError, OSError):
                # Corrupt persisted rows surface as fixed-text OSErrors.
                _log.warning("request rejected: %s", _STORAGE_UNAVAILABLE)
                self._reply_error(503, _STORAGE_UNAVAILABLE)
                return
            self._reply_listing(page)

        def _list_filters(self) -> dict[str, object]:
            """Validate the listing query string into store arguments.

            Only ``tenant_id``, ``status``, ``created_from``,
            ``created_to``, ``cursor`` and ``limit`` may appear, each at
            most once (``tenant_id`` keeps its historical
            header-or-query resolution in ``_tenant_id``). ``status`` is
            a comma-separated list of distinct lifecycle statuses. Every
            other shape is a bad request; the store re-validates the
            values themselves as defence in depth.
            """
            params = parse_qs(urlsplit(self.path).query, keep_blank_values=True)
            if not set(params) <= _LIST_QUERY_PARAMS:
                raise _BadRequest("unknown query parameter")
            filters: dict[str, object] = {}
            for name in ("status", "created_from", "created_to", "cursor", "limit"):
                values = params.get(name)
                if values is None:
                    continue
                if len(values) != 1:
                    raise _BadRequest(f"duplicate {name}")
                value = values[0]
                if name == "status":
                    filters["statuses"] = self._parse_status_filter(value)
                elif name == "limit":
                    # Far more digits than the 1..1000 domain can ever
                    # hold is a bad request, not a storage fault (and an
                    # unbounded digit string must never reach int()).
                    if not _LIST_LIMIT_RE.match(value) or len(value) > 10:
                        raise _BadRequest("invalid limit")
                    filters["limit"] = int(value)
                elif not value:
                    raise _BadRequest(f"invalid {name}")
                else:
                    filters[name] = value
            return filters

        def _parse_status_filter(self, value: str) -> list[str]:
            if not value:
                raise _BadRequest("invalid status")
            statuses = value.split(",")
            if any(status not in _REQUEST_STATUSES for status in statuses):
                raise _BadRequest("invalid status")
            if len(set(statuses)) != len(statuses):
                raise _BadRequest("duplicate status")
            return statuses

        def _audit_health_query_gate(self) -> None:
            """Reject any query parameter other than a single ``tenant_id``.

            The health snapshot takes no business parameters;
            ``tenant_id`` keeps its historical header-or-query
            resolution in ``_tenant_id``. An unknown parameter or any
            duplicated key (including ``tenant_id`` itself) is a bad
            request.
            """
            params = parse_qs(urlsplit(self.path).query, keep_blank_values=True)
            if not set(params) <= _AUDIT_HEALTH_QUERY_PARAMS:
                raise _BadRequest("unknown query parameter")
            for values in params.values():
                if len(values) != 1:
                    raise _BadRequest("duplicate query parameter")

        def _serve_audit_health(self) -> None:
            # The instantaneous health snapshot shares the read
            # endpoints' authorization and tenant resolution:
            # authentication first, then the tenant (header or query)
            # and its match against the principal, then the
            # tenant-only query gate, then storage. The store reads the
            # whole snapshot from one consistent read-only
            # transaction; the read never creates a batch, advances a
            # cursor or writes any business, audit, anchor or key
            # record. A tenant that holds no requests is still a
            # successful read of an all-zero snapshot, never a missing
            # request.
            principal = self._authorize(_ROLE_READ)
            if principal is None:
                return
            try:
                tenant_id = self._tenant_id()
            except _BadRequest:
                self._reply_error(400, _INVALID_REQUEST)
                return
            if not self._tenant_allowed(principal[0], tenant_id):
                return
            try:
                self._audit_health_query_gate()
            except _BadRequest:
                self._reply_error(400, _INVALID_REQUEST)
                return
            try:
                snapshot = store.audit_health(tenant_id)
            except ValueError:
                # Defence in depth: the HTTP resolution above is
                # authoritative, but a rejected store call reads
                # nothing and maps to the same client error.
                self._reply_error(400, _INVALID_REQUEST)
                return
            except _StorageUnavailable:
                _log.warning("request rejected: %s", _STORAGE_UNAVAILABLE)
                self._reply_error(503, _STORAGE_UNAVAILABLE)
                return
            except (sqlite3.Error, RuntimeError, OSError):
                # An unreadable database, corrupt bookkeeping or
                # evidence, or a snapshot that cannot be taken
                # consistently surfaces as the fixed-text storage
                # error; sqlite text (locks, malformed images, paths)
                # must never reach the client, and no partial snapshot
                # or pseudo count is ever rendered.
                _log.warning("request rejected: %s", _STORAGE_UNAVAILABLE)
                self._reply_error(503, _STORAGE_UNAVAILABLE)
                return
            self._reply_audit_health(snapshot)

        def _reply_audit_health(self, snapshot: object) -> None:
            # Whitelist and re-render every field: even a store
            # substitute that returned extra keys could not leak a
            # subject, a raw scope, an idempotency key, a request id,
            # a credential or any other request field into the body.
            # Shapes and types are re-checked, the four status buckets
            # are rendered in fixed order and the count invariants are
            # re-proved here, so a corrupt snapshot never serialises
            # into a partially-formed or self-contradictory summary.
            # Field order is fixed: total, statuses, verified,
            # unverified, reasons; each reason renders exactly
            # reason and count.
            if not isinstance(snapshot, dict) or set(snapshot) != {
                "total",
                "statuses",
                "verified",
                "unverified",
                "reasons",
            }:
                raise RuntimeError("malformed audit health from store")
            total = snapshot["total"]
            statuses = snapshot["statuses"]
            verified = snapshot["verified"]
            unverified = snapshot["unverified"]
            reasons = snapshot["reasons"]
            if not _is_nonneg_int(total) or not isinstance(statuses, dict):
                raise RuntimeError("malformed audit health from store")
            if list(statuses) != list(_AUDIT_HEALTH_STATUSES):
                raise RuntimeError("malformed audit health from store")
            rendered_statuses: dict[str, int] = {}
            for name in _AUDIT_HEALTH_STATUSES:
                count = statuses[name]
                if not _is_nonneg_int(count):
                    raise RuntimeError("malformed audit health from store")
                rendered_statuses[name] = count
            if not _is_nonneg_int(verified) or not _is_nonneg_int(unverified):
                raise RuntimeError("malformed audit health from store")
            # The four lifecycle buckets partition the population and
            # the trust tally covers every request exactly once.
            if total != sum(rendered_statuses.values()):
                raise RuntimeError("malformed audit health from store")
            if total != verified + unverified:
                raise RuntimeError("malformed audit health from store")
            if not isinstance(reasons, list):
                raise RuntimeError("malformed audit health from store")
            rendered_reasons: list[dict[str, object]] = []
            merged = 0
            previous: str | None = None
            for entry in reasons:
                if not isinstance(entry, dict) or set(entry) != {
                    "reason",
                    "count",
                }:
                    raise RuntimeError("malformed audit health from store")
                reason = entry["reason"]
                count = entry["count"]
                if (
                    not isinstance(reason, str)
                    or not reason
                    or not _is_positive_int(count)
                ):
                    raise RuntimeError("malformed audit health from store")
                # One entry per reason, ascending by Unicode code point.
                if previous is not None and previous >= reason:
                    raise RuntimeError("malformed audit health from store")
                previous = reason
                merged += count
                rendered_reasons.append({"reason": reason, "count": count})
            # The reason buckets partition the unverified population.
            if merged != unverified:
                raise RuntimeError("malformed audit health from store")
            body = (
                json.dumps(
                    {
                        "total": total,
                        "statuses": rendered_statuses,
                        "verified": verified,
                        "unverified": unverified,
                        "reasons": rendered_reasons,
                    },
                    ensure_ascii=False,
                    separators=(",", ":"),
                )
                + "\n"
            ).encode("utf-8")
            self._write_body(200, body)

        def _serve_audit_inspection(self) -> None:
            # The batched audit inspection shares the reconcile
            # endpoints' authorization and tenant resolution:
            # authentication first (the minimal ``request:reconcile``
            # role, limited to the principal's own tenant), then the
            # tenant (header or query) and its match against the
            # principal, then the query-parameter gate, then storage.
            # Without a cursor or batch id the store creates a new
            # persistent batch; with a cursor the named batch is
            # resumed from its durably committed position; with a
            # batch id the read-only metrics are answered instead and
            # nothing is created, advanced or written.
            principal = self._authorize(_ROLE_RECONCILE)
            if principal is None:
                return
            try:
                tenant_id = self._tenant_id()
            except _BadRequest:
                self._reply_error(400, _INVALID_REQUEST)
                return
            if not self._tenant_allowed(principal[0], tenant_id):
                return
            try:
                inspection_args = self._audit_inspection_args()
            except _BadRequest:
                self._reply_error(400, _INVALID_REQUEST)
                return
            batch_id = inspection_args.pop("batch_id", None)
            if batch_id is not None:
                self._serve_audit_inspection_metrics(tenant_id, batch_id)
                return
            try:
                result = store.audit_inspection(tenant_id, **inspection_args)
            except ValueError:
                # The store's fixed-text ValueError covers every
                # invalid limit or cursor shape, including a cursor
                # bound to another tenant or a batch that never
                # existed; a rejected call never writes anything.
                self._reply_error(400, _INVALID_REQUEST)
                return
            except _StorageUnavailable:
                _log.warning("request rejected: %s", _STORAGE_UNAVAILABLE)
                self._reply_error(503, _STORAGE_UNAVAILABLE)
                return
            except (sqlite3.Error, RuntimeError, OSError):
                # Corrupt persisted inspection bookkeeping and every
                # storage fault surface as the fixed-text OSError;
                # sqlite text (locks, malformed images, paths) must
                # never reach the client, and the store guarantees no
                # half-settled page.
                _log.warning("request rejected: %s", _STORAGE_UNAVAILABLE)
                self._reply_error(503, _STORAGE_UNAVAILABLE)
                return
            self._reply_audit_inspection(result)

        def _serve_audit_inspection_metrics(
            self, tenant_id: str, batch_id: str
        ) -> None:
            # The metrics query is strictly read-only: it never creates
            # a batch, never advances a cursor and never writes any
            # business, audit, anchor, key or inspection record. The
            # store assembles the whole aggregate from one consistent
            # read-only transaction, so a concurrent page advance can
            # never mix half-settled fields into the response.
            try:
                text = store.audit_inspection_metrics(tenant_id, batch_id)
            except AuditInspectionNotFound:
                # A missing batch and another tenant's batch share one
                # indistinguishable, detail-free outcome.
                self._reply_error(404, _NOT_FOUND)
                return
            except ValueError:
                # Defence in depth: the HTTP validation above is
                # authoritative, but a rejected store call reads
                # nothing and maps to the same client error.
                self._reply_error(400, _INVALID_REQUEST)
                return
            except _StorageUnavailable:
                _log.warning("request rejected: %s", _STORAGE_UNAVAILABLE)
                self._reply_error(503, _STORAGE_UNAVAILABLE)
                return
            except (sqlite3.Error, RuntimeError, OSError):
                # An unreadable database, corrupt inspection
                # bookkeeping or a snapshot that cannot be taken
                # consistently surfaces as the fixed-text storage
                # error; sqlite text (locks, malformed images, paths)
                # must never reach the client, and no partial
                # aggregate is ever rendered.
                _log.warning("request rejected: %s", _STORAGE_UNAVAILABLE)
                self._reply_error(503, _STORAGE_UNAVAILABLE)
                return
            self._reply_audit_inspection_metrics(text)

        def _audit_inspection_args(self) -> dict[str, object]:
            """Validate the inspection query string into store arguments.

            Only ``tenant_id``, ``cursor``, ``batch_id`` and ``limit``
            may appear, each at most once (``tenant_id`` keeps its
            historical header-or-query resolution in ``_tenant_id``);
            ``cursor`` and ``batch_id`` are mutually exclusive. Every
            other shape is a bad request; the store re-validates the
            values themselves as defence in depth.
            """
            params = parse_qs(urlsplit(self.path).query, keep_blank_values=True)
            if not set(params) <= _AUDIT_INSPECTION_QUERY_PARAMS:
                raise _BadRequest("unknown query parameter")
            inspection_args: dict[str, object] = {}
            for name in ("tenant_id", "cursor", "batch_id", "limit"):
                values = params.get(name)
                if values is None:
                    continue
                if len(values) != 1:
                    raise _BadRequest(f"duplicate {name}")
                value = values[0]
                if name == "limit":
                    # Far more digits than the 1..1000 domain can ever
                    # hold is a bad request, not a storage fault (and an
                    # unbounded digit string must never reach int()).
                    if not _LIST_LIMIT_RE.match(value) or len(value) > 10:
                        raise _BadRequest("invalid limit")
                    inspection_args["limit"] = int(value)
                elif name == "cursor":
                    if not value:
                        raise _BadRequest("invalid cursor")
                    inspection_args["cursor"] = value
                elif name == "batch_id":
                    if not value:
                        raise _BadRequest("invalid batch_id")
                    inspection_args["batch_id"] = value
            if "cursor" in inspection_args and "batch_id" in inspection_args:
                raise _BadRequest("cursor and batch_id are mutually exclusive")
            return inspection_args

        def _serve_policy_catalog_versions(self) -> None:
            # The catalog history shares the read endpoints'
            # authorization and tenant resolution: authentication first,
            # then the tenant (header or query) and its match against
            # the principal, then the query-string gate, then storage.
            principal = self._authorize(_ROLE_POLICY_READ)
            if principal is None:
                return
            try:
                tenant_id = self._tenant_id()
            except _BadRequest:
                self._reply_error(400, _INVALID_REQUEST)
                return
            if not self._tenant_allowed(principal[0], tenant_id):
                return
            try:
                self._policy_catalog_query_gate()
            except _BadRequest:
                self._reply_error(400, _INVALID_REQUEST)
                return
            try:
                text = store.audit_policy_catalog(tenant_id)
            except ValueError:
                # Defence in depth: the HTTP validation above is
                # authoritative, but a rejected store call reads nothing
                # and maps to the same client error.
                self._reply_error(400, _INVALID_REQUEST)
                return
            except _StorageUnavailable:
                _log.warning("request rejected: %s", _STORAGE_UNAVAILABLE)
                self._reply_error(503, _STORAGE_UNAVAILABLE)
                return
            except (sqlite3.Error, RuntimeError, OSError):
                # A corrupt catalog or an unusable database surfaces as
                # the fixed-text OSError; no partial history or
                # fabricated summary is ever rendered.
                _log.warning("request rejected: %s", _STORAGE_UNAVAILABLE)
                self._reply_error(503, _STORAGE_UNAVAILABLE)
                return
            self._reply_policy_catalog_audit(text)

        def _policy_catalog_query_gate(self) -> None:
            """Reject any query parameter other than a single ``tenant_id``.

            The history read takes no business parameters; ``tenant_id``
            keeps its historical header-or-query resolution in
            ``_tenant_id``. An unknown parameter or any duplicated key
            (including ``tenant_id`` itself) is a bad request.
            """
            params = parse_qs(urlsplit(self.path).query, keep_blank_values=True)
            if not set(params) <= _POLICY_CATALOG_QUERY_PARAMS:
                raise _BadRequest("unknown query parameter")
            for values in params.values():
                if len(values) != 1:
                    raise _BadRequest("duplicate query parameter")

        def _serve_policy_catalog_retention_trace(self) -> None:
            # The published-version retention trace shares the catalog
            # history's authorization and tenant resolution:
            # authentication first (the minimal ``policy:read`` role,
            # limited to the principal's own tenant), then the tenant
            # (header or query) and its match against the principal,
            # then the query-parameter gate and the empty-body gate,
            # then storage. A published version is the sole catalog
            # source: no body and no inline catalog is ever accepted,
            # and the read never writes anything.
            principal = self._authorize(_ROLE_POLICY_READ)
            if principal is None:
                return
            try:
                tenant_id = self._tenant_id()
            except _BadRequest:
                self._reply_error(400, _INVALID_REQUEST)
                return
            if not self._tenant_allowed(principal[0], tenant_id):
                return
            try:
                trace_args = self._retention_trace_query_args()
                self._read_empty_body()
            except _BadRequest:
                # A rejected body has been consumed (or the connection
                # is marked for close when it cannot be) before the
                # error.
                self._reply_error(400, _INVALID_REQUEST)
                return
            try:
                text = store.resolve_retention_trace(
                    tenant_id,
                    trace_args["subject_id"],
                    trace_args["scopes"],
                    version=trace_args["version"],
                )
            except PolicyCatalogNotFound:
                # A missing, unpublished or cross-tenant version shares
                # one indistinguishable, detail-free outcome.
                self._reply_error(404, _NOT_FOUND)
                return
            except ValueError:
                # Defence in depth: the HTTP validation above is
                # authoritative, but an illegal subject, selector or
                # version the store rejects reads nothing and maps to
                # the same client error.
                self._reply_error(400, _INVALID_REQUEST)
                return
            except _StorageUnavailable:
                _log.warning("request rejected: %s", _STORAGE_UNAVAILABLE)
                self._reply_error(503, _STORAGE_UNAVAILABLE)
                return
            except (sqlite3.Error, RuntimeError, OSError):
                # A corrupt catalog, an unreadable database or a
                # snapshot that cannot complete surfaces as the
                # fixed-text storage error; sqlite text (locks,
                # malformed images, paths) must never reach the
                # client, and no partial trace is ever rendered.
                _log.warning("request rejected: %s", _STORAGE_UNAVAILABLE)
                self._reply_error(503, _STORAGE_UNAVAILABLE)
                return
            self._reply_retention_trace(text)

        def _retention_trace_query_args(self) -> dict[str, object]:
            """Validate the retention-trace query string into arguments.

            Only ``tenant_id``, ``subject_id``, ``version`` and
            ``scope`` may appear (``tenant_id`` keeps its historical
            header-or-query resolution in ``_tenant_id``).
            ``subject_id`` and ``version`` must each appear exactly
            once with a non-blank/positive value and ``scope`` at
            least once; the repeated ``scope`` keys give the ordered
            selector sequence. Every other shape is a bad request; the
            store re-validates the values themselves -- including the
            selector grammar and exact-duplicate scopes -- as defence
            in depth.
            """
            params = parse_qs(urlsplit(self.path).query, keep_blank_values=True)
            if not set(params) <= _POLICY_CATALOG_RETENTION_TRACE_QUERY_PARAMS:
                raise _BadRequest("unknown query parameter")
            tenant_values = params.get("tenant_id")
            if tenant_values is not None and len(tenant_values) != 1:
                raise _BadRequest("duplicate tenant_id")
            subject_values = params.get("subject_id")
            if subject_values is None or len(subject_values) != 1:
                raise _BadRequest("subject_id required once")
            subject_id = subject_values[0]
            if not subject_id.strip():
                raise _BadRequest("invalid subject_id")
            version_values = params.get("version")
            if version_values is None or len(version_values) != 1:
                raise _BadRequest("version required once")
            version_text = version_values[0]
            # A positive integer version; a digit string far longer than
            # the consecutive per-tenant scheme can ever reach is a bad
            # request, not a storage lookup. Capping at 18 digits also
            # keeps the parsed value inside SQLite's signed 64-bit
            # binding range, so an oversized value can never raise an
            # OverflowError at the store boundary.
            if not _LIST_LIMIT_RE.match(version_text) or len(version_text) > 18:
                raise _BadRequest("invalid version")
            version = int(version_text)
            if version < 1:
                raise _BadRequest("invalid version")
            scope_values = params.get("scope")
            if not scope_values:
                raise _BadRequest("scope required")
            scopes: list[str] = []
            for scope in scope_values:
                if not scope or _SCOPE_SELECTOR_RE.fullmatch(scope) is None:
                    raise _BadRequest("invalid scope")
                scopes.append(scope)
            return {
                "subject_id": subject_id,
                "version": version,
                "scopes": scopes,
            }

        def _serve_policy_catalog_publish(self) -> None:
            # The publication endpoint shares the acceptance endpoint's
            # ordering: authentication first, then the JSON body, then
            # the body tenant's match against the principal, then the
            # catalog shape, then storage. The tenant is taken from the
            # body alone; neither the header nor the query string names
            # a tenant here.
            principal = self._authorize(_ROLE_POLICY_WRITE)
            if principal is None:
                return
            payload = self._read_json_object()
            tenant_id = _require_string(payload, "tenant_id")
            # The body's tenant is the authorization target; a principal
            # may only publish for its own tenant.
            if not self._tenant_allowed(principal[0], tenant_id):
                return
            if set(payload) != _POLICY_CATALOG_PUBLISH_KEYS:
                raise _BadRequest("unexpected catalog fields")
            try:
                result = store.publish_policy_catalog(
                    tenant_id, payload["rules"], payload["exceptions"]
                )
            except ValueError:
                # An illegal catalog shape -- a bad selector, day count
                # or reason, a missing default rule or a duplicated
                # policy id -- is rejected before storage is touched and
                # writes nothing.
                self._reply_error(400, _INVALID_REQUEST)
                return
            except PolicyCatalogConflict:
                # A concurrent publication of a different catalog won
                # the version slot; this call never lands.
                self._reply_error(409, _POLICY_CATALOG_CONFLICT)
                return
            except _StorageUnavailable:
                _log.warning("request rejected: %s", _STORAGE_UNAVAILABLE)
                self._reply_error(503, _STORAGE_UNAVAILABLE)
                return
            except (sqlite3.Error, RuntimeError, OSError):
                # A corrupt catalog record or a failed atomic commit
                # surfaces as the fixed-text OSError; a half-written
                # version is never visible.
                _log.warning("request rejected: %s", _STORAGE_UNAVAILABLE)
                self._reply_error(503, _STORAGE_UNAVAILABLE)
                return
            self._reply_policy_catalog_publication(result)

        # -- input parsing ---------------------------------------------

        def _tenant_id(self) -> str:
            header = self.headers.get(_TENANT_HEADER)
            if header is not None:
                tenant = header.strip()
                if tenant:
                    return tenant
            query = parse_qs(urlsplit(self.path).query).get("tenant_id")
            if query:
                tenant = query[-1].strip()
                if tenant:
                    return tenant
            raise _BadRequest("missing tenant")

        def _read_json_object(self) -> dict:
            body = self._read_body()
            try:
                parsed = json.loads(body.decode("utf-8"))
            except (UnicodeDecodeError, ValueError):
                raise _BadRequest("invalid json body")
            if not isinstance(parsed, dict):
                raise _BadRequest("body must be a JSON object")
            return parsed

        def _read_body(self) -> bytes:
            raw_length = self.headers.get("Content-Length")
            if raw_length is None:
                raise _BadRequest("missing content length")
            try:
                length = int(raw_length)
            except (TypeError, ValueError):
                raise _BadRequest("invalid content length")
            if length < 0 or length > _MAX_BODY_BYTES:
                # Leave the oversized tail unread and close the
                # connection so keep-alive cannot desync the next request.
                self.close_connection = True
                raise _BadRequest("body too large")
            try:
                return self.rfile.read(length)
            except OSError:
                raise _BadRequest("unreadable body")

        def _read_empty_body(self) -> None:
            """Require an absent or empty body on a parameterless POST.

            A missing ``Content-Length`` (and no transfer coding) or a
            declared length of zero means there is no body; anything else
            is a client error. A bounded non-empty body is drained first so
            the connection can still serve the next request; an unbounded,
            malformed or unreadable framing closes the connection instead
            of risking a desync.
            """
            # A coded body (chunked or any other transfer coding) is never
            # an empty body and cannot be drained safely here; reject it
            # regardless of any accompanying Content-Length.
            if self.headers.get("Transfer-Encoding") is not None:
                self.close_connection = True
                raise _BadRequest("body must be empty")
            raw_length = self.headers.get("Content-Length")
            if raw_length is None:
                return
            try:
                length = int(raw_length)
            except (TypeError, ValueError):
                self.close_connection = True
                raise _BadRequest("invalid content length")
            if length < 0:
                self.close_connection = True
                raise _BadRequest("invalid content length")
            if length == 0:
                return
            if length > _MAX_BODY_BYTES:
                # Leave the oversized tail unread and close the
                # connection so keep-alive cannot desync the next request.
                self.close_connection = True
                raise _BadRequest("body must be empty")
            try:
                self.rfile.read(length)
            except OSError:
                self.close_connection = True
                raise _BadRequest("unreadable body")
            raise _BadRequest("body must be empty")

        # -- responses --------------------------------------------------

        def _reply_receipt(self, status: int, receipt: dict[str, str]) -> None:
            if set(receipt) != {"request_id", "status", "created_at"}:
                # Corrupt persisted rows must never be presented as a
                # receipt.
                raise RuntimeError("malformed receipt from store")
            body = (
                json.dumps(
                    {
                        "request_id": receipt["request_id"],
                        "status": receipt["status"],
                        "created_at": receipt["created_at"],
                    },
                    ensure_ascii=False,
                    separators=(",", ":"),
                )
                + "\n"
            ).encode("utf-8")
            self._write_body(status, body)

        def _reply_status(self, record: dict[str, str]) -> None:
            # The current-status record has the identical fixed shape and
            # field order as the acceptance receipt; only the status value
            # differs. Reuse the same strict renderer.
            self._reply_receipt(200, record)

        def _reply_reconcile_batch(self, result: object) -> None:
            # Whitelist and re-render every field: even a store substitute
            # that returned extra keys could not leak a subject, a scope,
            # an idempotency key, a worker, a credential or any other
            # request field into the body. Shapes and types are re-checked
            # so a corrupt result never serialises into a partially-formed
            # record. Field order is fixed: batch_id, next_cursor,
            # finished, items; each item renders exactly request_id and
            # status.
            if not isinstance(result, dict) or set(result) != {
                "batch_id",
                "next_cursor",
                "finished",
                "items",
            }:
                raise RuntimeError("malformed reconcile batch from store")
            batch_id = result["batch_id"]
            next_cursor = result["next_cursor"]
            finished = result["finished"]
            items = result["items"]
            if (
                not isinstance(batch_id, str)
                or not batch_id
                or not isinstance(finished, bool)
                or not isinstance(items, list)
            ):
                raise RuntimeError("malformed reconcile batch from store")
            if next_cursor is not None and (
                not isinstance(next_cursor, str) or not next_cursor
            ):
                raise RuntimeError("malformed reconcile batch from store")
            # A finished sweep carries no continuation cursor; an
            # unfinished one always does.
            if finished != (next_cursor is None):
                raise RuntimeError("malformed reconcile batch from store")
            rendered_items: list[dict[str, str]] = []
            for item in items:
                if not isinstance(item, dict) or set(item) != {
                    "request_id",
                    "status",
                }:
                    raise RuntimeError("malformed reconcile batch from store")
                request_id = item["request_id"]
                status = item["status"]
                if (
                    not isinstance(request_id, str)
                    or not request_id
                    or not isinstance(status, str)
                    or status not in _RECONCILE_ITEM_STATUSES
                ):
                    raise RuntimeError("malformed reconcile batch from store")
                rendered_items.append(
                    {"request_id": request_id, "status": status}
                )
            body = (
                json.dumps(
                    {
                        "batch_id": batch_id,
                        "next_cursor": next_cursor,
                        "finished": finished,
                        "items": rendered_items,
                    },
                    ensure_ascii=False,
                    separators=(",", ":"),
                )
                + "\n"
            ).encode("utf-8")
            self._write_body(200, body)

        def _reply_audit_inspection(self, result: object) -> None:
            # Whitelist and re-render every field: even a store
            # substitute that returned extra keys could not leak a
            # subject, a raw scope, an idempotency key, a worker, a
            # credential or any other request field into the body.
            # Shapes and types are re-checked so a corrupt result never
            # serialises into a partially-formed record. Field order is
            # fixed: batch_id, next_cursor, finished, items; each item
            # renders exactly request_id, verified and reason.
            if not isinstance(result, dict) or set(result) != {
                "batch_id",
                "next_cursor",
                "finished",
                "items",
            }:
                raise RuntimeError("malformed audit inspection from store")
            batch_id = result["batch_id"]
            next_cursor = result["next_cursor"]
            finished = result["finished"]
            items = result["items"]
            if (
                not isinstance(batch_id, str)
                or not batch_id
                or not isinstance(finished, bool)
                or not isinstance(items, list)
            ):
                raise RuntimeError("malformed audit inspection from store")
            if next_cursor is not None and (
                not isinstance(next_cursor, str) or not next_cursor
            ):
                raise RuntimeError("malformed audit inspection from store")
            # A finished sweep carries no continuation cursor; an
            # unfinished one always does.
            if finished != (next_cursor is None):
                raise RuntimeError("malformed audit inspection from store")
            rendered_items: list[dict[str, object]] = []
            for item in items:
                if not isinstance(item, dict) or set(item) != {
                    "request_id",
                    "verified",
                    "reason",
                }:
                    raise RuntimeError("malformed audit inspection from store")
                request_id = item["request_id"]
                verified = item["verified"]
                reason = item["reason"]
                if (
                    not isinstance(request_id, str)
                    or not request_id
                    or not isinstance(verified, bool)
                    or not isinstance(reason, str)
                ):
                    raise RuntimeError("malformed audit inspection from store")
                # A verified item carries the empty reason; an
                # unverified one always carries a stable reason code.
                if verified != (not reason):
                    raise RuntimeError("malformed audit inspection from store")
                rendered_items.append(
                    {
                        "request_id": request_id,
                        "verified": verified,
                        "reason": reason,
                    }
                )
            body = (
                json.dumps(
                    {
                        "batch_id": batch_id,
                        "next_cursor": next_cursor,
                        "finished": finished,
                        "items": rendered_items,
                    },
                    ensure_ascii=False,
                    separators=(",", ":"),
                )
                + "\n"
            ).encode("utf-8")
            self._write_body(200, body)

        def _reply_audit_inspection_metrics(self, text: object) -> None:
            # The body is the store's verbatim single-line compact JSON
            # text with its single trailing newline. It is still
            # re-validated field by field before it is emitted: a
            # corrupt or substituted store must never serialise a
            # subject, a raw scope, an idempotency key, a worker, a
            # credential, SQL text or a path into the body, and a
            # malformed aggregate surfaces as the stable storage code,
            # never as a partial metrics text.
            if (
                not isinstance(text, str)
                or not text.endswith("\n")
                or text.endswith("\n\n")
                or "\n" in text[:-1]
                or "\r" in text
            ):
                raise RuntimeError("malformed inspection metrics from store")
            try:
                payload = json.loads(text[:-1])
            except ValueError:
                raise RuntimeError(
                    "malformed inspection metrics from store"
                ) from None
            if not isinstance(payload, dict) or set(payload) != {
                "batch_id",
                "scanned",
                "verified",
                "unverified",
                "reasons",
                "next_cursor",
                "finished",
            }:
                raise RuntimeError("malformed inspection metrics from store")
            batch_id = payload["batch_id"]
            scanned = payload["scanned"]
            verified = payload["verified"]
            unverified = payload["unverified"]
            reasons = payload["reasons"]
            next_cursor = payload["next_cursor"]
            finished = payload["finished"]
            if (
                not isinstance(batch_id, str)
                or not batch_id
                or not _is_nonneg_int(scanned)
                or not _is_nonneg_int(verified)
                or not _is_nonneg_int(unverified)
                or not isinstance(reasons, list)
                or not isinstance(finished, bool)
            ):
                raise RuntimeError("malformed inspection metrics from store")
            # The trust tally covers every scanned item exactly once.
            if scanned != verified + unverified:
                raise RuntimeError("malformed inspection metrics from store")
            if next_cursor is not None and (
                not isinstance(next_cursor, str) or not next_cursor
            ):
                raise RuntimeError("malformed inspection metrics from store")
            # A finished batch carries no continuation cursor; an
            # unfinished one always does.
            if finished != (next_cursor is None):
                raise RuntimeError("malformed inspection metrics from store")
            merged = 0
            previous: str | None = None
            for entry in reasons:
                if not isinstance(entry, dict) or set(entry) != {
                    "reason",
                    "count",
                }:
                    raise RuntimeError("malformed inspection metrics from store")
                reason = entry["reason"]
                count = entry["count"]
                if (
                    not isinstance(reason, str)
                    or not reason
                    or not _is_positive_int(count)
                ):
                    raise RuntimeError("malformed inspection metrics from store")
                # One entry per reason, ascending by Unicode code point.
                if previous is not None and previous >= reason:
                    raise RuntimeError("malformed inspection metrics from store")
                previous = reason
                merged += count
            # The reason buckets partition the unverified population.
            if merged != unverified:
                raise RuntimeError("malformed inspection metrics from store")
            # The emitted bytes must be exactly the compact single-line
            # rendering of the validated payload; anything else (extra
            # whitespace, a reserialised duplicate key, a non-canonical
            # number) is not the store's verbatim text.
            canonical = (
                json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
                + "\n"
            )
            if text != canonical:
                raise RuntimeError("malformed inspection metrics from store")
            self._write_body(200, text.encode("utf-8"))

        def _reply_execution_log(
            self, request_id: str, attempts: list[dict[str, object]]
        ) -> None:
            if not isinstance(request_id, str) or not request_id:
                raise RuntimeError("malformed execution log from store")
            if not isinstance(attempts, list):
                raise RuntimeError("malformed execution log from store")
            rendered_attempts: list[dict[str, object]] = []
            for index, attempt in enumerate(attempts, start=1):
                rendered_attempts.append(self._project_attempt(attempt, index))
            body = (
                json.dumps(
                    {"request_id": request_id, "attempts": rendered_attempts},
                    ensure_ascii=False,
                    separators=(",", ":"),
                )
                + "\n"
            ).encode("utf-8")
            self._write_body(200, body)

        def _project_attempt(
            self, attempt: object, expected_number: int
        ) -> dict[str, object]:
            # Whitelist and re-render every field: even a store substitute
            # that returned extra keys could not leak a claim token, worker
            # identity, subject or scope into the body. Numbering and types
            # are re-checked so a corrupt row never serialises into a
            # partially-formed record.
            allowed = {
                "attempt_number",
                "claimed_at",
                "lease_expires_at",
                "result",
                "completed_at",
            }
            if not isinstance(attempt, dict) or set(attempt) != allowed:
                raise RuntimeError("malformed attempt from store")
            number = attempt["attempt_number"]
            claimed_at = attempt["claimed_at"]
            lease_expires_at = attempt["lease_expires_at"]
            result = attempt["result"]
            completed_at = attempt["completed_at"]
            if (
                not isinstance(number, int)
                or isinstance(number, bool)
                or number != expected_number
                or not isinstance(claimed_at, str)
                or not claimed_at
                or not isinstance(lease_expires_at, str)
                or not lease_expires_at
            ):
                raise RuntimeError("malformed attempt from store")
            if result is not None and (
                not isinstance(result, str) or result not in _TERMINAL_RESULTS
            ):
                raise RuntimeError("malformed attempt from store")
            if completed_at is not None and (
                not isinstance(completed_at, str) or not completed_at
            ):
                raise RuntimeError("malformed attempt from store")
            # result and completed_at are set together at finish time.
            if (result is None) != (completed_at is None):
                raise RuntimeError("malformed attempt from store")
            return {
                "attempt_number": number,
                "claimed_at": claimed_at,
                "lease_expires_at": lease_expires_at,
                "result": result,
                "completed_at": completed_at,
            }

        def _reply_evidence(
            self, record: object, if_none_match: list[str] | None = None
        ) -> None:
            # Whitelist and re-render every field: even a store substitute
            # that returned extra keys could not leak a subject, a scope,
            # an idempotency key, an occurred-at value, a credential or any
            # other request field into the body. Shapes and types are
            # re-checked so a corrupt snapshot never serialises into a
            # partially-formed verdict. Field order is fixed:
            # request_id, status, event_count, chain_hash, verified.
            if not isinstance(record, dict) or set(record) != {
                "request_id",
                "status",
                "event_count",
                "chain_hash",
                "verified",
            }:
                raise RuntimeError("malformed evidence from store")
            request_id = record["request_id"]
            status = record["status"]
            event_count = record["event_count"]
            chain_hash = record["chain_hash"]
            verified = record["verified"]
            if (
                not isinstance(request_id, str)
                or not request_id
                or not isinstance(status, str)
                or not status
                or not isinstance(event_count, int)
                or isinstance(event_count, bool)
                or event_count < 0
                or not isinstance(verified, bool)
            ):
                raise RuntimeError("malformed evidence from store")
            # A persisted head that is not legal SHA-256 text is rendered
            # as null; anything non-null must be 64 lowercase hex chars.
            if chain_hash is not None and (
                not isinstance(chain_hash, str)
                or not _HEX_DIGEST_RE.match(chain_hash)
            ):
                raise RuntimeError("malformed evidence from store")
            body = (
                json.dumps(
                    {
                        "request_id": request_id,
                        "status": status,
                        "event_count": event_count,
                        "chain_hash": chain_hash,
                        "verified": verified,
                    },
                    ensure_ascii=False,
                    separators=(",", ":"),
                )
                + "\n"
            ).encode("utf-8")
            # The strong ETag is the SHA-256 of the exact body bytes, so
            # the same bytes always yield the same tag -- across repeat
            # reads, concurrent readers and process restarts -- and any
            # byte change yields a different tag.
            etag = '"sha256:' + hashlib.sha256(body).hexdigest() + '"'
            if if_none_match is not None and _entity_tags_match(
                if_none_match, etag
            ):
                self._reply_not_modified(etag)
                return
            self._write_body(200, body, etag=etag)

        def _reply_audit_timeline(self, timeline: object) -> None:
            # Whitelist and re-render every field: even a store
            # substitute that returned extra keys could not leak a
            # subject, a raw scope, an idempotency key, an attempt,
            # a tombstone, a receipt, an anchor, a credential or any
            # other request field into the body. Shapes and value
            # domains are re-checked so a corrupt timeline never
            # serialises into a partially-formed or fabricated
            # history. Field order is fixed: request_id, events;
            # each event renders exactly status and occurred_at.
            if not isinstance(timeline, dict) or set(timeline) != {
                "request_id",
                "events",
            }:
                raise RuntimeError("malformed audit timeline from store")
            request_id = timeline["request_id"]
            events = timeline["events"]
            if (
                not isinstance(request_id, str)
                or not _UUID_RE.match(request_id)
                or not isinstance(events, list)
                or not events
            ):
                raise RuntimeError("malformed audit timeline from store")
            rendered_events: list[dict[str, str]] = []
            previous_occurred_at: str | None = None
            for index, event in enumerate(events):
                if not isinstance(event, dict) or set(event) != {
                    "status",
                    "occurred_at",
                }:
                    raise RuntimeError("malformed audit timeline from store")
                status = event["status"]
                occurred_at = event["occurred_at"]
                if (
                    not isinstance(status, str)
                    or status not in _REQUEST_STATUSES
                    or not isinstance(occurred_at, str)
                    or not _TIMESTAMP_RFC3339_RE.match(occurred_at)
                ):
                    raise RuntimeError("malformed audit timeline from store")
                if index == 0:
                    # The first event is always the acceptance event.
                    if status != "accepted":
                        raise RuntimeError(
                            "malformed audit timeline from store"
                        )
                else:
                    # Later events record only genuine lifecycle edges;
                    # a repeated current status is never appended.
                    if (
                        status
                        not in _TIMELINE_TRANSITIONS[
                            rendered_events[-1]["status"]
                        ]
                    ):
                        raise RuntimeError(
                            "malformed audit timeline from store"
                        )
                # Occurrence times never go backwards.
                if (
                    previous_occurred_at is not None
                    and occurred_at < previous_occurred_at
                ):
                    raise RuntimeError("malformed audit timeline from store")
                previous_occurred_at = occurred_at
                rendered_events.append(
                    {"status": status, "occurred_at": occurred_at}
                )
            body = (
                json.dumps(
                    {"request_id": request_id, "events": rendered_events},
                    ensure_ascii=False,
                    separators=(",", ":"),
                )
                + "\n"
            ).encode("utf-8")
            self._write_body(200, body)

        def _reply_audit_diagnosis(self, request_id: str, reasons: object) -> None:
            # Whitelist and re-render every field: even a store
            # substitute that returned extra keys could not leak a
            # subject, a raw scope, an idempotency key, a credential, an
            # anchor secret, SQL text or a path into the body -- the
            # request id is the normalized path segment and the reasons
            # are re-validated as detail-free codes. The emitted reasons
            # are deduplicated and sorted by Unicode code point so the
            # body is byte-identical for the same persisted chain, and
            # ``trusted`` is true only when no reason remains. Field
            # order is fixed: request_id, trusted, reasons.
            if not isinstance(reasons, list):
                raise RuntimeError("malformed audit diagnosis from store")
            for reason in reasons:
                if not isinstance(reason, str) or not reason:
                    raise RuntimeError("malformed audit diagnosis from store")
            stable_reasons = sorted(set(reasons))
            body = (
                json.dumps(
                    {
                        "request_id": request_id,
                        "trusted": not stable_reasons,
                        "reasons": stable_reasons,
                    },
                    ensure_ascii=False,
                    separators=(",", ":"),
                )
                + "\n"
            ).encode("utf-8")
            self._write_body(200, body)

        def _reply_audit_bundle(
            self, text: object, if_none_match: list[str] | None = None
        ) -> None:
            # The body is the store's verbatim single-line compact JSON
            # text with its single trailing newline. It is still
            # re-validated field by field before it is emitted: a
            # corrupt or substituted store must never serialise a
            # subject, a raw scope, an idempotency key, a worker, a
            # claim credential or any secret material into the body, and
            # a malformed bundle surfaces as the stable storage code,
            # never as a partial export.
            if (
                not isinstance(text, str)
                or not text.endswith("\n")
                or text.endswith("\n\n")
                or "\n" in text[:-1]
                or "\r" in text
            ):
                raise RuntimeError("malformed audit bundle from store")
            try:
                payload = json.loads(text[:-1])
            except ValueError:
                raise RuntimeError("malformed audit bundle from store") from None
            self._validate_audit_bundle_payload(payload)
            # The emitted bytes must be exactly the compact single-line
            # rendering of the validated payload; anything else (extra
            # whitespace, a reserialised duplicate key, a non-canonical
            # number) is not the store's verbatim text.
            canonical = (
                json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
                + "\n"
            )
            if text != canonical:
                raise RuntimeError("malformed audit bundle from store")
            body = text.encode("utf-8")
            # The strong ETag is the SHA-256 of the exact body bytes, so
            # the same bytes always yield the same tag -- across repeat
            # reads, concurrent readers and process restarts -- and any
            # byte change yields a different tag.
            etag = '"sha256:' + hashlib.sha256(body).hexdigest() + '"'
            if if_none_match is not None and _entity_tags_match(
                if_none_match, etag
            ):
                self._reply_not_modified(etag)
                return
            self._write_body(200, body, etag=etag)

        def _reply_not_modified(self, etag: str) -> None:
            # A conditional hit: no body, a zero Content-Length and the
            # same strong ETag the full 200 response would carry.
            try:
                self.send_response(304)
                self.send_header("ETag", etag)
                self.send_header("Content-Length", "0")
                if self.close_connection:
                    self.send_header("Connection", "close")
                self.end_headers()
            except OSError:
                # The client went away mid-response; nothing to report.
                self.close_connection = True

        def _validate_audit_bundle_payload(self, payload: object) -> None:
            # Whitelist and re-check every field of the bundle shape the
            # storage layer renders: exactly request_id, status, events,
            # chain, anchors and generations, each with its own fixed
            # field set and value domains.
            if not isinstance(payload, dict) or set(payload) != _AUDIT_BUNDLE_FIELDS:
                raise RuntimeError("malformed audit bundle from store")
            request_id = payload["request_id"]
            status = payload["status"]
            if (
                not isinstance(request_id, str)
                or not request_id
                or not isinstance(status, str)
                or status not in _REQUEST_STATUSES
            ):
                raise RuntimeError("malformed audit bundle from store")
            events = payload["events"]
            if not isinstance(events, list) or not events:
                raise RuntimeError("malformed audit bundle from store")
            for event in events:
                if not isinstance(event, dict) or set(event) != (
                    _AUDIT_BUNDLE_EVENT_FIELDS
                ):
                    raise RuntimeError("malformed audit bundle from store")
                if (
                    not _is_nonneg_int(event["seq"])
                    or not isinstance(event["status"], str)
                    or event["status"] not in _REQUEST_STATUSES
                    or not isinstance(event["occurred_at"], str)
                    or not _RFC3339_RE.match(event["occurred_at"])
                    or not isinstance(event["chain_hash"], str)
                    or not _HEX_DIGEST_RE.match(event["chain_hash"])
                ):
                    raise RuntimeError("malformed audit bundle from store")
            chain = payload["chain"]
            if not isinstance(chain, dict) or set(chain) != (
                _AUDIT_BUNDLE_CHAIN_FIELDS
            ):
                raise RuntimeError("malformed audit bundle from store")
            if (
                not isinstance(chain["tenant_id"], str)
                or not chain["tenant_id"]
                or not _is_positive_int(chain["event_count"])
                or not isinstance(chain["head"], str)
                or not _HEX_DIGEST_RE.match(chain["head"])
            ):
                raise RuntimeError("malformed audit bundle from store")
            anchors = payload["anchors"]
            if not isinstance(anchors, list) or not anchors:
                raise RuntimeError("malformed audit bundle from store")
            for anchor in anchors:
                if not isinstance(anchor, dict) or set(anchor) != (
                    _AUDIT_BUNDLE_ANCHOR_FIELDS
                ):
                    raise RuntimeError("malformed audit bundle from store")
                key_generation = anchor["key_generation"]
                if (
                    not _is_nonneg_int(anchor["seq"])
                    or not isinstance(anchor["anchor_hmac"], str)
                    or not _HEX_DIGEST_RE.match(anchor["anchor_hmac"])
                    # Null is the legacy generation-1 attribution; any
                    # present value must be a positive integer naming a
                    # generation.
                    or not (
                        key_generation is None
                        or _is_positive_int(key_generation)
                    )
                ):
                    raise RuntimeError("malformed audit bundle from store")
            generations = payload["generations"]
            if not isinstance(generations, list):
                raise RuntimeError("malformed audit bundle from store")
            for record in generations:
                if not isinstance(record, dict) or set(record) != (
                    _AUDIT_BUNDLE_GENERATION_FIELDS
                ):
                    raise RuntimeError("malformed audit bundle from store")
                if (
                    not _is_positive_int(record["generation"])
                    or not isinstance(record["key_fingerprint"], str)
                    or not _HEX_DIGEST_RE.match(record["key_fingerprint"])
                    or not isinstance(record["effective_at"], str)
                    or not _RFC3339_RE.match(record["effective_at"])
                ):
                    raise RuntimeError("malformed audit bundle from store")

        def _reply_listing(self, page: object) -> None:
            # Whitelist and re-render every field: even a store substitute
            # that returned extra keys could not leak a subject, a scope,
            # an idempotency key or any other request field into the body.
            # Shapes and types are re-checked so a corrupt page never
            # serialises into a partially-formed record.
            if not isinstance(page, dict) or set(page) != {"items", "next_cursor"}:
                raise RuntimeError("malformed listing from store")
            items = page["items"]
            next_cursor = page["next_cursor"]
            if not isinstance(items, list):
                raise RuntimeError("malformed listing from store")
            if next_cursor is not None and (
                not isinstance(next_cursor, str) or not next_cursor
            ):
                raise RuntimeError("malformed listing from store")
            rendered_items: list[dict[str, str]] = []
            for item in items:
                if not isinstance(item, dict) or set(item) != {
                    "request_id",
                    "status",
                    "created_at",
                }:
                    raise RuntimeError("malformed listing from store")
                request_id = item["request_id"]
                status = item["status"]
                created_at = item["created_at"]
                if (
                    not isinstance(request_id, str)
                    or not request_id
                    or not isinstance(status, str)
                    or status not in _REQUEST_STATUSES
                    or not isinstance(created_at, str)
                    or not created_at
                ):
                    raise RuntimeError("malformed listing from store")
                rendered_items.append(
                    {
                        "request_id": request_id,
                        "status": status,
                        "created_at": created_at,
                    }
                )
            body = (
                json.dumps(
                    {"items": rendered_items, "next_cursor": next_cursor},
                    ensure_ascii=False,
                    separators=(",", ":"),
                )
                + "\n"
            ).encode("utf-8")
            self._write_body(200, body)

        def _reply_tombstone_page(self, page: object) -> None:
            # Whitelist and re-render every field: even a store
            # substitute that returned extra keys could not leak a
            # subject, a raw object, a proof body, an idempotency key, a
            # worker identity or a credential into the body. Shapes and
            # types are re-checked so a corrupt page never serialises
            # into a partially-formed record.
            if not isinstance(page, dict) or set(page) != {
                "request_id",
                "tombstones",
                "recorded_at",
                "evidence_digest",
                "next_cursor",
            }:
                raise RuntimeError("malformed tombstone page from store")
            request_id = page["request_id"]
            tombstones = page["tombstones"]
            recorded_at = page["recorded_at"]
            evidence_digest = page["evidence_digest"]
            next_cursor = page["next_cursor"]
            if (
                not isinstance(request_id, str)
                or not request_id
                or not isinstance(tombstones, list)
            ):
                raise RuntimeError("malformed tombstone page from store")
            if recorded_at is not None and (
                not isinstance(recorded_at, str) or not recorded_at
            ):
                raise RuntimeError("malformed tombstone page from store")
            if evidence_digest is not None and (
                not isinstance(evidence_digest, str)
                or not _HEX_DIGEST_RE.match(evidence_digest)
            ):
                raise RuntimeError("malformed tombstone page from store")
            if next_cursor is not None and (
                not isinstance(next_cursor, str) or not next_cursor
            ):
                raise RuntimeError("malformed tombstone page from store")
            rendered_tombstones: list[dict[str, str]] = []
            for tombstone in tombstones:
                if not isinstance(tombstone, dict) or set(tombstone) != {
                    "adapter_id",
                    "scope",
                    "operation_id",
                    "outcome",
                    "proof_digest",
                    "recorded_at",
                }:
                    raise RuntimeError("malformed tombstone from store")
                adapter_id = tombstone["adapter_id"]
                scope = tombstone["scope"]
                operation_id = tombstone["operation_id"]
                outcome = tombstone["outcome"]
                proof_digest = tombstone["proof_digest"]
                entry_recorded_at = tombstone["recorded_at"]
                if (
                    not isinstance(adapter_id, str)
                    or not adapter_id
                    or not isinstance(scope, str)
                    or not scope
                    or not isinstance(operation_id, str)
                    or not operation_id
                    or not isinstance(outcome, str)
                    or outcome not in _TOMBSTONE_OUTCOMES
                    or not isinstance(proof_digest, str)
                    or not _HEX_DIGEST_RE.match(proof_digest)
                    or not isinstance(entry_recorded_at, str)
                    or not entry_recorded_at
                ):
                    raise RuntimeError("malformed tombstone from store")
                rendered_tombstones.append(
                    {
                        "adapter_id": adapter_id,
                        "scope": scope,
                        "operation_id": operation_id,
                        "outcome": outcome,
                        "proof_digest": proof_digest,
                        "recorded_at": entry_recorded_at,
                    }
                )
            body = (
                json.dumps(
                    {
                        "request_id": request_id,
                        "tombstones": rendered_tombstones,
                        "recorded_at": recorded_at,
                        "evidence_digest": evidence_digest,
                        "next_cursor": next_cursor,
                    },
                    ensure_ascii=False,
                    separators=(",", ":"),
                )
                + "\n"
            ).encode("utf-8")
            self._write_body(200, body)

        def _reply_policy_catalog_audit(self, text: object) -> None:
            # The body is the store's verbatim single-line compact JSON
            # text with its single trailing newline. It is still
            # re-validated field by field before it is emitted: a
            # corrupt or substituted store must never serialise a policy
            # id, a selector, a reason, a subject or any raw catalog
            # content into the body, and a malformed history surfaces as
            # the stable storage code, never as a partial summary.
            if (
                not isinstance(text, str)
                or not text.endswith("\n")
                or "\n" in text[:-1]
                or "\r" in text
            ):
                raise RuntimeError("malformed catalog audit from store")
            try:
                payload = json.loads(text[:-1])
            except ValueError:
                raise RuntimeError("malformed catalog audit from store") from None
            if not isinstance(payload, dict) or set(payload) != {"versions"}:
                raise RuntimeError("malformed catalog audit from store")
            versions = payload["versions"]
            if not isinstance(versions, list):
                raise RuntimeError("malformed catalog audit from store")
            for expected, entry in enumerate(versions, start=1):
                if not isinstance(entry, dict) or set(entry) != {
                    "version",
                    "effective_at",
                    "rule_count",
                    "exception_count",
                    "status",
                }:
                    raise RuntimeError("malformed catalog audit from store")
                version = entry["version"]
                effective_at = entry["effective_at"]
                rule_count = entry["rule_count"]
                exception_count = entry["exception_count"]
                status = entry["status"]
                if (
                    not isinstance(version, int)
                    or isinstance(version, bool)
                    # Versions ascend gap-free from one.
                    or version != expected
                    or not isinstance(effective_at, str)
                    or not effective_at
                    or not isinstance(rule_count, int)
                    or isinstance(rule_count, bool)
                    or rule_count < 0
                    or not isinstance(exception_count, int)
                    or isinstance(exception_count, bool)
                    or exception_count < 0
                    or not isinstance(status, bool)
                ):
                    raise RuntimeError("malformed catalog audit from store")
            # The emitted bytes must be exactly the compact single-line
            # rendering of the validated payload; anything else (extra
            # whitespace, a reserialised duplicate key, a non-canonical
            # number) is not the store's verbatim text.
            canonical = (
                json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
                + "\n"
            )
            if text != canonical:
                raise RuntimeError("malformed catalog audit from store")
            self._write_body(200, text.encode("utf-8"))

        def _reply_retention_trace(self, text: object) -> None:
            # The body is the store's verbatim single-line compact JSON
            # trace text with its single trailing newline. It is still
            # re-validated field by field before it is emitted: a
            # corrupt or substituted store must never serialise an
            # unvalidated key, an inline-catalog source label, a raw
            # scope sequence or any foreign content into the body, and
            # a malformed trace surfaces as the stable storage code,
            # never as a partial text.
            if (
                not isinstance(text, str)
                or not text.endswith("\n")
                or text.endswith("\n\n")
                or "\n" in text[:-1]
                or "\r" in text
            ):
                raise RuntimeError("malformed retention trace from store")
            try:
                payload = json.loads(text[:-1])
            except ValueError:
                raise RuntimeError(
                    "malformed retention trace from store"
                ) from None
            if not isinstance(payload, dict) or set(payload) != set(
                _RETENTION_TRACE_FIELDS
            ):
                raise RuntimeError("malformed retention trace from store")
            catalog_source = payload["catalog_source"]
            subject_id = payload["subject_id"]
            scopes = payload["scopes"]
            retention_days = payload["retention_days"]
            policy_id = payload["policy_id"]
            reason = payload["reason"]
            exception = payload["exception"]
            scope_evidence = payload["scope_evidence"]
            # This endpoint publishes published-version evidence only;
            # the inline call-time catalog source is never served.
            if catalog_source != _RETENTION_TRACE_SOURCE_PUBLISHED:
                raise RuntimeError("malformed retention trace from store")
            if not isinstance(subject_id, str) or not subject_id.strip():
                raise RuntimeError("malformed retention trace from store")
            if not isinstance(scopes, list) or not scopes:
                raise RuntimeError("malformed retention trace from store")
            for scope in scopes:
                if (
                    not isinstance(scope, str)
                    or not scope
                    or _SCOPE_SELECTOR_RE.fullmatch(scope) is None
                ):
                    raise RuntimeError("malformed retention trace from store")
            if (
                not _is_nonneg_int(retention_days)
                or not isinstance(policy_id, str)
                or not policy_id
                or not isinstance(reason, str)
                or not reason
                or not isinstance(exception, bool)
                or not isinstance(scope_evidence, list)
                or len(scope_evidence) != len(scopes)
            ):
                raise RuntimeError("malformed retention trace from store")
            for index, item in enumerate(scope_evidence):
                if not isinstance(item, dict) or set(item) != set(
                    _RETENTION_TRACE_EVIDENCE_FIELDS
                ):
                    raise RuntimeError("malformed retention trace from store")
                item_scope = item["scope"]
                level = item["level"]
                item_policy_id = item["policy_id"]
                item_exception = item["exception"]
                item_days = item["retention_days"]
                if (
                    not isinstance(item_scope, str)
                    # One evidence item per normalized scope, in order.
                    or item_scope != scopes[index]
                    or level not in _RETENTION_TRACE_LEVELS
                    or not isinstance(item_policy_id, str)
                    or not item_policy_id
                    or not isinstance(item_exception, bool)
                    or not _is_nonneg_int(item_days)
                ):
                    raise RuntimeError("malformed retention trace from store")
            # The emitted bytes must be exactly the compact single-line
            # rendering of the validated payload in the fixed field
            # order; anything else (extra whitespace, a reserialised
            # duplicate key, a reordered field) is not the store's
            # verbatim text.
            canonical = (
                json.dumps(
                    {name: payload[name] for name in _RETENTION_TRACE_FIELDS},
                    ensure_ascii=False,
                    separators=(",", ":"),
                )
                + "\n"
            )
            if text != canonical:
                raise RuntimeError("malformed retention trace from store")
            self._write_body(200, text.encode("utf-8"))

        def _reply_policy_catalog_publication(self, result: object) -> None:
            # Whitelist and re-render every field: even a store
            # substitute that returned extra keys could not leak a
            # policy id, a selector, a reason, a subject or any raw
            # catalog content into the body. Shapes and types are
            # re-checked so a corrupt result never serialises into a
            # partially-formed record. Field order is fixed: version,
            # effective_at.
            if not isinstance(result, dict) or set(result) != {
                "version",
                "effective_at",
            }:
                raise RuntimeError("malformed publication from store")
            version = result["version"]
            effective_at = result["effective_at"]
            if (
                not isinstance(version, int)
                or isinstance(version, bool)
                or version < 1
                or not isinstance(effective_at, str)
                or not effective_at
            ):
                raise RuntimeError("malformed publication from store")
            body = (
                json.dumps(
                    {"version": version, "effective_at": effective_at},
                    ensure_ascii=False,
                    separators=(",", ":"),
                )
                + "\n"
            ).encode("utf-8")
            self._write_body(200, body)

        def _reply_error(
            self,
            status: int,
            code: str,
            allowed: str | None = None,
            headless: bool = False,
        ) -> None:
            body = (
                json.dumps({"error": code}, ensure_ascii=False, separators=(",", ":"))
                + "\n"
            ).encode("utf-8")
            self._write_body(status, body, allowed=allowed, headless=headless)

        def _write_body(
            self,
            status: int,
            body: bytes,
            allowed: str | None = None,
            headless: bool = False,
            etag: str | None = None,
        ) -> None:
            try:
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                if allowed is not None:
                    self.send_header("Allow", allowed)
                if etag is not None:
                    self.send_header("ETag", etag)
                self.send_header("Content-Length", str(len(body)))
                if self.close_connection:
                    # Tell the client explicitly when a request left an
                    # unread body (e.g. an auth rejection before parsing)
                    # so it does not pipeline another request.
                    self.send_header("Connection", "close")
                self.end_headers()
                if not headless:
                    self.wfile.write(body)
            except OSError:
                # The client went away mid-response; nothing to report.
                self.close_connection = True

        def _safe_error(self, status: int, code: str) -> None:
            try:
                self._reply_error(status, code)
            except Exception:
                self.close_connection = True

        # Protocol-level errors (bad request line, unrecognised verbs
        # that never resolve to a do_* method) must use the same JSON
        # error shape and stable codes instead of http.server's HTML
        # 400/501 responses.
        def send_error(self, code, message=None, explain=None):  # type: ignore[override]
            if code == 501:
                # Even an unrecognised verb must honour the
                # unknown-path (404) vs known-path (405) distinction.
                self._handle_unsupported_method()
            elif code == 404:
                self._safe_error(404, _NOT_FOUND)
            elif 400 <= code < 500:
                self._safe_error(400, _INVALID_REQUEST)
            else:
                self._safe_error(503, _STORAGE_UNAVAILABLE)

        # Never emit request lines (paths carry request ids) or default
        # stack traces as access logs; failures are logged by code only.
        def log_message(self, format: str, *args) -> None:  # noqa: A002
            return

    return _DeletionRequestHandler


def _entity_tags_match(tags: list[str], etag: str) -> bool:
    """Strong comparison of validated ``If-None-Match`` tags against *etag*.

    ``*`` matches any currently exportable representation; a
    double-quoted tag matches only on exact equality with the current
    strong tag; weak ``W/``-prefixed tags never match the strong
    comparison and are skipped.
    """
    for tag in tags:
        if tag == "*":
            return True
        if tag.startswith("W/"):
            continue
        if tag == etag:
            return True
    return False


def _require_string(payload: dict, key: str) -> str:
    if key not in payload:
        raise _BadRequest(f"missing {key}")
    value = payload[key]
    if not isinstance(value, str) or not value:
        raise _BadRequest(f"invalid {key}")
    return value


def _require_scopes(payload: dict) -> list[str]:
    if "scopes" not in payload:
        raise _BadRequest("missing scopes")
    scopes = payload["scopes"]
    if not isinstance(scopes, list):
        raise _BadRequest("invalid scopes")
    if not scopes or not all(isinstance(item, str) and item for item in scopes):
        raise _BadRequest("invalid scopes")
    if len(set(scopes)) != len(scopes):
        raise _BadRequest("duplicate scopes")
    return scopes
