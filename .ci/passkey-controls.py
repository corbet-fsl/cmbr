#!/usr/bin/env python3
"""Require the real named regression when listing authorization is removed."""
import os
from pathlib import Path
import re
import subprocess

SOURCE = "src/membership.rs"
TARGET = "membership/tests"
TEST = "membership::tests::last_key_revocation_releases_but_preserves_committed_retention"
CONTROLS = ((b'pub async fn passkeys(&self, auth: &Authentication) -> Result<Vec<ckyh::StoredPasskey>> {\n        let _guard = crate::storage::member_lock(self.storage.community(), auth.member()).await;\n        let row = self.authenticated(auth, self.now()?).await?;', b'pub async fn passkeys(&self, auth: &Authentication) -> Result<Vec<ckyh::StoredPasskey>> {\n        let _guard = crate::storage::member_lock(self.storage.community(), auth.member()).await;\n        let row = self.enrol.view(auth.member(), self.now()?).await?;', 'membership passkey listing requires current scoped authentication'),)

def run():
    result = subprocess.run(
        ["cargo", "test", "--locked", "--lib", TEST,
         "--", "--exact", "--nocapture"], capture_output=True, text=True,
        timeout=900,
        env={**os.environ, "CARGO_TERM_COLOR": "never", "RUST_BACKTRACE": "0"},
    )
    return result.returncode, result.stdout + result.stderr


def exact_result(output, result):
    return re.search(r"^test " + re.escape(TEST) + r" \.\.\. " + result + r"$",
                     output, re.M) is not None


def baseline(status, output):
    return (status == 0 and exact_result(output, "ok")
            and "test result: ok. 1 passed; 0 failed; 0 ignored;" in output)


def assertion(status, output, marker):
    # Build failures, unrelated assertions and zero selected tests cannot qualify.
    return (status == 101 and exact_result(output, "FAILED")
            and "test result: FAILED. 0 passed; 1 failed; 0 ignored;" in output
            and re.search(r"thread '" + re.escape(TEST)
                          + r"'(?: \([0-9]+\))? panicked at src/"
                          + re.escape(TARGET) + r"\.rs:[0-9]+:[0-9]+:", output)
            and marker in output and "error[E" not in output
            and "could not compile" not in output)


def main():
    path = Path(SOURCE)
    original = path.read_bytes()
    for before, after, marker in CONTROLS:
        if original.count(before) != 1:
            raise SystemExit("Passkey listing control source drift: " + marker)
        status, output = run()
        if not baseline(status, output):
            print(output)
            raise SystemExit("Passkey listing control needs a passing exact baseline")
        try:
            path.write_bytes(original.replace(before, after))
            status, output = run()
            if not assertion(status, output, marker):
                print(output)
                raise SystemExit("Unauthenticated listing did not fail its named assertion")
            print("Unauthenticated listing rejected by named assertion: " + marker)
        finally:
            path.write_bytes(original)
        if path.read_bytes() != original:
            raise SystemExit("Passkey listing control source restoration failed")


if __name__ == "__main__":
    main()
