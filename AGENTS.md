# cmbr agent notes

Work in a lane (`~/agents/scratch/lane-new <lane>`); never edit `~/agents/scratch/ws`.
Run commands from the lane root (`<lane>/ws`); `<lane>` below is your lane name.

Build and test (quote the verdict line, never infer from a pipe):
- `~/agents/scratch/cbuild <lane> test -p cmbr` — native suite, green
  (lib `136`, membership `10`, roles `4`, first_seat `2`, doc `3` passed;
  turso `0` + `1` ignored without `TURSO_URL`/`TURSO_TOKEN`), exit 0;
  long, background it
- `~/agents/scratch/cbuild <lane> fmt -p cmbr -- --check` — must be clean
- Full gate (clippy `--locked`, passkey-controls scripts, first-party and
  100% coverage checks, separate locked verification) runs in CI only:
  `.ci/verify.sh`.

Land: `cargo fmt` in touched repos, rebase on main (never force-push),
`cbuild <lane> xtask land --dry`, then `xtask land`.

Invariants (rule -> enforcing test):
- Last-key loss, expiry and self-ban end in permanent `Released`, never rejoin
  -> `src/membership/tests.rs::last_key_revocation_releases_but_preserves_committed_retention`
- Revocation stops sessions at once; no cross-credential rescue
  -> `src/membership/tests.rs::revoked_authentication_cannot_change_pins_or_revoke_the_remaining_key`
- Lobby is a pure read: never admits, lapses or extends
  -> `src/membership/tests.rs::pure_lobby_keeps_admission_and_returns_irreversible_expiry_warnings`
- Per-member queue, no community-wide or durable lock; reads take no write lock
  -> `src/membership/tests.rs::different_members_log_in_and_read_lobbies_concurrently_without_writes`
- Legal restriction/self-ban blocks admit, device add/activate and issuance
  -> `src/membership/source/tests.rs::independent_legal_writer_blocks_the_member_for_every_action`
- No raw gate data: `admit`/`lapse` take only verified snapshots and checked gates
  -> `tests/membership.rs::complete_membership_round_trip`
- Pins are `PinV2`-only; unproven spends fail closed, even after restart
  -> `tests/membership.rs::unproven_pin_spends_cannot_change_state_even_after_restart`
- Discoverable login restores only; rechecks revocation and expiry
  -> `tests/discoverable.rs::restore_returns_the_existing_membership_and_rechecks_revocation_and_expiry`

Pointers: `src/membership/`, `src/storage.rs`, `docs/CONTRACT.md`,
`docs/COVERAGE.md`, `.ci/verify.sh`.
Commits: explicit paths, imperative, author per `~/agents/AGENT.md`; no AI trailers.
`publish=false`; FSL-1.1-ALv2; no GPL/AGPL-only deps; never publish to a registry.
