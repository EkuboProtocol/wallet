# Native Linux acceptance

The full native milestone in `.github/workflows/ci.yml` automatically runs
`contrib/accept-installed-linux.py` on its disposable `ubuntu-24.04` runner.
The script consumes the **production** service and enrollment helper, built
without test hooks. It installs the current fixed-path service assets, creates
a unique synthetic owner and the distinct `ekubo-wallet-v2` service account,
and runs the installed enrollment helper's `--owner` flow.

## What the installed check proves

- Real systemd provisioning and service units, using the real system D-Bus and
  separate kernel UIDs; no session bus substituted for the system bus.
- Production root installer, generated enrollment and wrapping key, authenticated
  ciphertext handoff, owner Secret Service persistence/readback, publication,
  and the normal owner's custody unlock. The owner has a private session bus
  and gnome-keyring containing only synthetic test data.
- Successful unlocked readiness: `setup-complete`, the live service MCP socket,
  initialize, tools/list and wallet_get_legal. A bus name alone is insufficient.
- A long-lived private owner SystemBus connection authenticates the service's
  unique name against its installed UID, subscribes for `DesktopSessionReady`,
  and calls the production `HoldDesktopSession` method on that same peer. Only
  its nonce-matched unicast signal permits the coordinator to test MCP admission.
  The peer remains connected throughout the checks; after restart/resume a new
  authenticated peer acquires a new held lease and readiness signal.
- The held owner peer calls the real `create_account` RPC for one generated
  `installed-ci` account, verifies the public account inventory, then verifies
  identical inventory after restart. Its sealed account credential is included
  in the persistence fingerprints and owner read/write-denial checks. No private
  key is exported and no external-chain signing is performed.
- A focused real dpkg install/reinstall of the production service assets and
  preinst/postinst hooks, with a populated profile explicitly stopped before
  reinstall. The fixture removes the generated activation file to exercise
  protected-metadata regeneration, verifies the unit remains stopped after
  `try-restart`, then calls `StartServiceByName` as the ordinary owner. This uses
  a disposable `ekubo-wallet-v2-activation-acceptance` package, not the full desktop
  release artifact. It is followed by the installed `--resume-owner`
  connection/unlock, another live MCP read, a new service PID, and identical
  enrollment metadata, wrapping key, sealed database key and setup marker.
  Before that owner reconnect, the restarted service must not expose MCP.
- Actual owner `open(2)` attempts for read and write of protected credential,
  enrollment and database files fail with `EACCES`. Missing files fail the test.
- A synthetic 1.x database-file sentinel and legacy credential sentinel survive
  fresh setup and restart. No pre-existing keys are read or imported.

**Human-presence limitation:** a temporary narrowly scoped Polkit rule grants
the synthetic owner consent for the exact installed root helper invocation and
the v2 human-presence action. This tests production requests, caller binding,
credential creation and activation; it is **not evidence of an actual human
gesture, login-session agent, password challenge or biometric prompt**. Those
remain interactive native acceptance. The rule is never a package asset.

## Commands

Safe on a development host (no installation or Cargo build):

```sh
python3 contrib/accept-installed-linux.py --check-guards
python3 contrib/linux-service/install-profile_test.py
pipx run ruff==0.16.4 check contrib/accept-installed-linux.py contrib/verify-mcp-bridge.py
```

Parent/coordinator targeted regression commands:

```sh
cargo test --locked -p ekubo-wallet-core --all-features --lib credential_store::tests::recovers_after_secret_service_startup_and_restart -- --exact --ignored --nocapture
cargo test --locked -p mcp-bridge --bin ekubo-wallet-v2-mcp-bridge offline_protocol_identities_are_v2
# On macOS (the process reliability harness is cfg(target_os = "macos")):
cargo test --locked -p mcp-bridge --test reliability_test -- --nocapture
```

Only inside a **disposable GitHub-hosted Linux runner** with real systemd,
system D-Bus, Polkit/pkexec, Python 3, python3-dbus, python3-gi, gnome-keyring,
libsecret-tools and gdbus:

```sh
cargo build --locked -p ekubo-wallet-service --bins --no-default-features --jobs 1
sudo env GITHUB_ACTIONS="$GITHUB_ACTIONS" RUNNER_ENVIRONMENT="$RUNNER_ENVIRONMENT" RUNNER_OS="$RUNNER_OS" \
  python3 contrib/accept-installed-linux.py --run-disposable "$PWD/target/debug"
```

Do not manufacture these environment values on a development machine. The
harness requires root, explicit opt-in, all three runner markers, Linux and
systemd PID 1. It refuses existing v2 roots (including dangling symlinks),
units, installed assets, runtime configuration, service account/group and its
synthetic owner paths before installation. Binaries are copied with exclusive
creation. Cleanup stops only this owner's units, kills only fixture processes,
and removes only fixture-created files, roots and accounts. Diagnostics include
the synthetic session log and exact units' journal on failure. Never run the
installation portion on the main host, even with sudo access.

GitHub's Ubuntu image build script
[`configure-system.sh`](https://github.com/actions/runner-images/blob/main/images/ubuntu/scripts/build/configure-system.sh)
applies `chmod -R 777 /usr/share`. After all read-only preflight checks, the
disposable fixture temporarily hardens only `/usr/share`, `/usr/share/dbus-1`
and `/usr/share/dbus-1/system-services` when they are real root:root directories
with exactly mode `0777`. Already protected ancestors are left alone; other
unsafe ownership, modes or symlinks are refused. Preflight reports each exact
ancestor's UID, GID, mode, device and inode and checks `/` and `/usr` too.
Pinned directory descriptors are revalidated before mutation, and original modes
are restored in `finally` after cleanup, with unchanged ownership and identity
verified. Nothing is recursively normalized. Production installer ancestry
validation remains strict and has no runner exception.

Migration acceptance has been removed: v2 is standalone and users migrate manually on-chain. There is no automated 1.x import step.
