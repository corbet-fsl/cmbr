# cmbr implemented contract

cmbr composes community enrolment (cnrl), passkeys (ckyh), handles and leases
(crgs), pins (cpns), and legal restrictions (clbs). cplc alone decides admission;
cmty wires the facades. Leaves own their cryptography, lifecycle transitions and
atomic writes. Services select trusted storage/verifiers and authenticate routes.
No raw gate evidence, secrets, login times, request logs or history are retained.

Membership and its legal gate share one private clock observation floor. Every
valid interior sample is retained, including samples made while checking an
expiring legal restriction. Negative or unsupported timestamps and backwards
observations permanently refuse the current facade with `Unavailable`; later
wall-clock correction does not clear that state. Clones share it. This state is
RAM only and does not replace the caller's trusted clock or durable records.
Sampling is serialized synchronously so thread scheduling cannot manufacture a
backwards observation. Returned confirmation keeps its latest observed floor and
the original exclusive deadline and `Instant` lifetime, without reanchoring.

## Admission and identity

`admit` and `lapse` require cplc's policy owner, opaque `VerifiedSnapshot` and
cgts `CheckedGates`. The member's current stored lifecycle supplies the crbk
membership state. cplc checks publication freshness, scope, effective epoch,
revocations and exact gate bindings. Raw snapshots, gate arrays and caller-built
positive decisions cannot enter this API. cmbr contains no policy evaluator.
Admission requires the reserved handle, a current legal check and a bounded lease.
`Config::lease_months` is 1–24; requests beyond current month plus that bound fail.
The stored lease is coarse through the end of its calendar month.

Every authenticated operation checks the exact credential ID carried by ckyh's
opaque Authentication against its current unrevoked record. Supplying another
credential ID cannot rescue a session from a revoked passkey. Revoking the last
passkey permanently releases the lifecycle; it does not erase a retained handle.
Credential-first and discoverable login delegate verification/counters to ckyh and records no login
time. UUIDs and pseudonyms are service-authenticated community-local bindings.

## Initial creation provenance

Both ordinary `begin_registration` and seeded `begin_initial_registration` use
Keyhole's atomic first-only insertion. The seeded path receives a caller-owned
nonzero 32-byte opaque per-community commitment before the original WebAuthn
ceremony. Neither additional keys nor legacy records can acquire a replacement
commitment. No raw root, signed publication, private evidence or signing authority
is accepted by this integration.

Authenticated `initial_creation` and `bind_initial_publication` require the exact
original key and the host's ORIGINAL session/ceremony exclusive expiry. The
Keyhole transaction checks current key ownership/revocation and immutable digest
binding; equal retry succeeds, a different winner refuses. Membership rechecks
the actual enrolment, legal restriction, latest wall-clock floor and original
monotonic bound after awaits, including after a durable bind. A refused response
does not erase a committed winner. Fresh original-key authentication can read it
after a lost reply; absent private candidate/evidence is never reconstructed.

The nonclone, nonserializable `InitialCreationState` retains the exact member
lease, authentication, owner instance and original expiry. Call
`check_initial_creation` after host awaits, then sample the host clock and call
`is_current` synchronously before projecting only opaque seed/publication and
checked time. The host must also check its current session and policy; these
metadata are not admission or signing capabilities. A failed or cancelled check
poisons that sealed result. Drop it before another member-lock operation; do not
reenter session operations that acquire the same lease. Store transactions fence
first registration and publication across pools; the RAM member queue alone
does not establish cross-process first-key uniqueness.

After a successful actual publication bind, any failed completion check returns
`Unavailable`: the host must report reconciliation, since the durable winner may
already exist. This includes expiry, rollback, revocation and legal/lifecycle
changes before output. Known prewrite invalid-input and atomic conflict refusals
retain their categories. Neither an uncertain reply nor a cancellation clears
the winning metadata or authorizes another publication.

## No return and lobby

The product rule is **NO RETURN**. Expired registration, loss of all passkeys,
self-ban and permanent termination leave a permanent pseudonym tombstone. That
person can never join this community again, including under another passkey UUID.
Global uniqueness fingerprints are also burned permanently and never released.
There is no recovery override, recycle or identity-deletion route.

`lobby` reads a pure cnrl view and cplc's decision. It never applies a policy,
lapses an admitted member, expires a row, cleans claims or renews a lease.
A negative lobby response leaves stored admission unchanged; `lapse` is explicit.
Before registration expires the response always carries its exclusive UTC-day
deadline and warning that expiration permanently prevents rejoining. With exactly
one live passkey it recommends registering a second device or using a synced
passkey. Clients must present these warnings. Periodic maintenance owns expiry
and claim cleanup even if a member never opens the lobby.

## Concurrency and failure

There is no community-wide lock or durable Busy marker. Mutations serialize by
community/member UUID in a short-lived process queue shared across facade
instances; unrelated members proceed independently. Authentication reads, lobby,
handle availability, member and pin reads do not acquire that queue or a database
write transaction. crgs's read capability refuses writes. Services share one crlt
pool and configure sufficient connection leases for concurrent operations.

Reservation and admission use owned Tokio tasks. Once started, caller cancellation
does not interrupt their cross-leaf completion. Queue guards release on success,
error, cancellation and process exit. Storage/clock failures cannot leave a
member or community locked. Leaf CAS revisions and unique indexes fence competing
writes across processes. A mutation may still have an uncertain remote result:
read current leaf state and retry with fresh authorization. Partial registration
receipts can be reconciled from committed ckyh records by explicit synchronization.

There is no synthetic positive recovery decision. A register row alone cannot
readmit a lapsed member. After a process loss or failed admission, a retry must
obtain current cplc authorization. If a pending registration expires before it
finishes, the permanent no-return rule applies. All facades' service writers must
respect the owning APIs; raw database administration remains privileged.

## Probation and credential facts

The first completed admission initializes `probation_until` from the authenticated
crbk `membership.probation_days` setting (default 14), at a UTC-day boundary.
It never slides on renewal. After it passes, issuance or bounded maintenance
removes the deadline; the initialized row remains so probation cannot restart.
No admission or login timestamp is saved. cplc reads this source to select the
crbk new/established credential caps (defaults 1/30 days); callers choose no class.

The `MembershipSource` implementation reads live admitted state, passkeys, legal
eligibility, probation and the register's exclusive lease end. Its per-member
lease guard survives through cplc signing, so revocation cannot race that check.
Pending, lapsed, terminal, keyless or incomplete membership never produces a
credential. Signing is refused while an unforwarded revocation is pending.

## Revocations

Security changes write a durable revocation request before changing the leaf.
cmty drains `revocations`, advances cplc's epoch, publishes fresh trust/revocation
state, then acknowledges the exact generation. Advancing the epoch invalidates
all old community credentials, including any removed device key. A newer event
cannot be erased by an older acknowledgement, including after a prior drain.
Conservative invalidation after a failed leaf operation is safe. Generation rows
remain, without times or event history, to prevent acknowledgement replay.
Permanent member revocations additionally belong in cplc's revoked-member set.

## Pins and storage

Pin values and salts stay on devices. cpns owns fingerprint algorithms, exact
expected digest/revision checks and change authorization. Initial pins never
overwrite an existing field. Changes require an already spent token bound to the
entire cpns Change; unproven balance extensions remain disabled in cgts.

| Table | Current content | Index |
|---|---|---|
| cmbr_probation | Pseudonym and optional day probation end | community_id, subject; expiry index |
| cmbr_revocations | Pseudonym, monotonic generation and pending bit | community_id, subject; pending index |

Other tables remain leaf-owned. All queries are community-scoped and indexed;
crlt enforces plans. Services own migrations, secret provisioning and one database
per community. The old coordination table is not used and must not be treated as
an active lock during migration. Apply the new schema through a new service-owned
migration when upgrading an existing database. Errors and Debug diagnostics omit
member identifiers and provider/SQL details. No leaf writers are re-exported.

## Validation

GitHub Actions runs formatting, strict Clippy, real WebAuthn ceremonies, actual
libSQL transactions, rulebook and signing flows, opaque witness rejection,
concurrent reads, cancelled cross-leaf work, storage/clock errors, revoked-session
checks, no-return cases, probation and durable revocation tests. CI rejects
floating or duplicated corbet dependency revisions. No Cargo runs locally.
Optional Turso tests require an explicitly configured disposable database.

Pins accept only `PinV2`, an explicitly versioned device submission carrying the
community, pseudonym and field. The facade compares that context to the current
authentication and requested field before storage. Raw fingerprints and version
one submissions are refused. `PinV2::seal` is a device-side cpns v2 helper; values
and salts never enter membership storage. A wire digest alone cannot prove its
algorithm: cgrd authenticates the signed context and verifies the v2 opening,
without v1 fallback. Tests cover storage through real signed cgrd verification,
v1 rejection and every context substitution.

The production membership constructor fixes the pin adapter to cgts's
`PinSpendVerifier`; services cannot substitute a caller-written accepting
verifier. `change_pin` binds the actual authenticated community/member, field,
old digest/revision and v2 replacement before asking cgts for `SpentChange`.
Only that opaque witness reaches cpns's atomic compare-and-exchange. The unproven
cblc extension currently makes every such request fail closed; no token or pin
mutation occurs. Tests repeat invalid evidence across facade restart and confirm
the original revision/digest remain unchanged. Successful spend/replay tests
remain blocked on the real cblc extension circuit, not replaced by a fake verifier.

`begin_login` requires the credential ID saved by the wallet at registration.
It uses ckyh's uniform credential-first challenge for known, unknown and revoked
keys. A bare UUID cannot reveal whether a person registered. The browser response
is still verified by WebAuthn and the exact credential is rechecked on every
subsequent authenticated call. Starting a login takes no write lock.

Legal orders retain their authority-signed start/end precision in clbs: rounding
would alter when the order legally applies and invalidate its authenticated
payload. These are authorization intervals, not member activity records.
WebAuthn ceremony timeouts are short-lived protocol state. Probation, registration
expiry, leases and signed community credentials retain their coarse time rules.

An explicit admitted-to-lapsed transition queues its generation-tagged revocation
before committing the lifecycle change. Repeated lapse does not create a second
event. The cmty relay publishes the epoch before acknowledging that event.

## Additional passkeys

A passkey ecosystem is a device. A member with a valid UV-authenticated session
can register another UV-required passkey for the same membership through
`begin_additional_registration` / `finish_additional_registration`. The service
binds the single-use server state to the initiating session and checks its expiry.
cmbr rechecks the exact key, member and live lifecycle at both boundaries; ckyh
atomically refuses insertion if the authorizing key was revoked. Addition preserves
the pseudonym, handle, lease, pins and probation. No manual approval is involved.

Revocation invalidates sessions of that key immediately. A remaining passkey keeps
the same membership usable. Losing or removing every passkey releases it
permanently: no recovery, and NO RETURN under a fresh registration identifier.

## Discoverable sign-in and Keyhole

`begin_discoverable_login()` needs no member UUID or credential ID. It returns
ckyh's options unchanged: a fresh challenge, empty allow-list and required UV.
`finish_login` consumes either kind of pending login, delegates verification and
atomic counter/revocation checks to ckyh, and returns the existing membership to
the lobby. It rechecks current lifecycle and exact credential just as for
credential-first login; it never creates a member, extends a lease, resets
probation or records a login date. The user handle is not authority by itself.
The service bounds, throttles, expires and binds pending ceremonies to clients.

Creation now requests resident credentials. All server options pass unchanged
through the service to device-side Passkeys (`cpky`); only Passkeys adds its local
PRF input. Server-side Keyhole (`ckyh`) rejects PRF-bearing responses.
Passkeys must strip the entire PRF extension before sending a response. Deserialize
responses directly into ckyh's guarded wire types: parsing into upstream types
first would discard the extension before it can be refused. Both registration
(including additional keys) and both login paths use those same guarded types.
PRF and vault restoration stay on the device; see ckyh's Keyhole contract.

## Passkey-bound signing authority

`authorize_device_key` requires an opaque verified authentication and a current
member session at the service boundary. Under the member serialization lease it
rechecks the exact credential, legal restrictions and lifecycle, then binds
that credential's single actual lineage device Ed25519 key. The same key is
idempotent; a different key cannot replace it. The service must expose this as
an explicit authenticated device operation; raw credential-request keys are not
an instruction to authorize themselves.

A new binding is serialized with issuance and leaves existing credentials valid.
It never emits a public epoch change: ordinary registration and device additions
must not become trust-feed activity signals. Key removal retains the existing
durable revocation outbox. `current_device_keys` filters each binding against
the current unrevoked credentials on every read, so
passkey removal refuses further authority immediately, even before storage cleanup
or device synchronization. It supplies current server authority to the pairing
adapter; that adapter must additionally verify the exact ckmg root, epoch, lineage
and pairing intent. No server operation handles a root secret or PRF.

Append `DEVICE_KEYS_SCHEMA` after the application's entire previous migration
history. The six existing `SCHEMAS` entries, including the historical `cpky` name,
are unchanged. Bindings persist only public keys and the already-held local
credential/pseudonym relationship, never names or activity timestamps.

Native pin changes retain a private `PendingPinChange` with the actual member
queue, authenticated passkey, exact field/revision/fingerprint and exclusive
session/policy deadline. The same accounting worker retains it while rechecking
the historical native spend. Completion consumes only the matching sealed
capability and rechecks actual key, lifecycle and legal owners under CPNS's
immediate write transaction. These reads use the same database through another
pooled connection; one connection refuses at the existing pool deadline.
The application and Membership use the same shared observed clock. A changed
time after legal observation refuses instead of reusing an earlier green view.
Late commit replies require reconciliation, never another accounting spend.

Native account callers retain the opaque `SourceLease` returned by the original
membership source. Its `check_source` method re-reads actual passkey, lifecycle,
register, device and legal owners without cleanup writes or reacquiring the
member lock. The caller must hold the same database's existing writer barrier;
all reads must remain in the native commit's observed second and original lease
lifetime. An error or cancellation invalidates the old lease. A pool without an
available read connection refuses within its configured timeout.

Community creation has an explicit separate `CREATION_SCHEMA`, appended after
the application's existing migration history. An absent phase refuses admission.
The trusted creation host initializes `Creating` only from the original verified
recipient-bound BootstrapRoot entitlement; this creates no member or role.
`admit_first_root` re-verifies its original COSE under the retained current target
Policy, evaluates the full configured gates at their original checked time, and
stages lifecycle, Root admission, receipt spend, probation and `Active` in one
transaction. Ordinary `admit_current` requires an already active phase in that
same writer. Unsupported atomic probation storage refuses.

Both admission paths retain the original session and member guard, and require
actual current passkey, legal and Policy reads in the writer's observed second.
The original gate receipt deadlines are never renewed. A postcommit failed cut
is uncertain (`Unavailable`); an exact first-Root retry reads the original effect
without consuming again or extending its lease. Legacy adoption is an explicit
trusted host operation that checks a genuinely admitted current Root through
the original owners under the same writer. It records a distinct `LegacyActive`
state without inventing a receipt, role or admission event.
