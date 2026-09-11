#!/usr/bin/env python3
"""Synthetic cross-user migration on disposable GitHub Linux runners only."""

import argparse
from contextlib import ExitStack
import json
import os
from pathlib import Path
import pwd
import shutil
import signal
import subprocess
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]


def run(arguments, **kwargs):
    return subprocess.run(arguments, check=True, timeout=30, **kwargs)


def reload_policy():
    run(["busctl", "--system", "call", "org.freedesktop.DBus", "/org/freedesktop/DBus",
         "org.freedesktop.DBus", "ReloadConfig"], stdout=subprocess.DEVNULL)


def remove_policy(path):
    path.unlink()
    reload_policy()


def create_account(stack, name):
    try:
        pwd.getpwnam(name)
    except KeyError:
        pass
    else:
        raise RuntimeError("Refusing an existing fixture account")
    run(["useradd", "--system", "--user-group", "--no-create-home",
         "--shell", "/usr/sbin/nologin", name])
    stack.callback(run, ["userdel", name])
    return pwd.getpwnam(name)


def configure(stack, owner, account, profile):
    roots = [Path("/etc/ekubo-wallet"), Path("/var/lib/ekubo-wallet")]
    if any(path.exists() or path.is_symlink() for path in roots):
        raise RuntimeError("Refusing existing wallet service configuration or storage")
    for root in roots:
        root.mkdir(mode=0o755)
        stack.callback(shutil.rmtree, root)
        (root / "pending").mkdir(mode=0o755)
    configuration = roots[0] / "pending" / f"{owner}.json"
    configuration.write_text(json.dumps({"owner_uid": owner, "service_uid": account.pw_uid,
                                         "profile_id": str(profile)}))
    configuration.chmod(0o644)
    private = roots[1] / "pending" / str(profile)
    private.mkdir(mode=0o700)
    os.chown(private, account.pw_uid, account.pw_gid)
    lock = private / "service.lock"
    lock.touch(mode=0o600)
    os.chown(lock, account.pw_uid, account.pw_gid)
    policy = Path("/etc/dbus-1/system.d") / f"org.ekubo.Wallet.Fixture.{profile.hex}.conf"
    # Keep the production policy except for this invocation's isolated account.
    content = (ROOT / "contrib/linux-service/org.ekubo.Wallet.Provision.conf").read_text()
    with policy.open("x") as output:
        output.write(content.replace('user="ekubo-wallet"', f'user="{account.pw_name}"'))
    stack.callback(remove_policy, policy)
    policy.chmod(0o644)
    reload_policy()
    return private


def stop_fixture(process):
    if process.poll() is None:
        # The still-live child owns this new process group; no system daemon is stopped.
        os.killpg(process.pid, signal.SIGTERM)
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=10)


def wait_ready(process, owner):
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("Synthetic service exited before readiness")
        reply = run(["busctl", "--system", "call", "org.freedesktop.DBus",
                     "/org/freedesktop/DBus", "org.freedesktop.DBus", "NameHasOwner",
                     "s", f"org.ekubo.Wallet.Provision.u{owner}"], capture_output=True, text=True)
        if reply.stdout.strip() == "b true":
            return
        time.sleep(0.25)
    raise RuntimeError("Synthetic service did not acquire its bus name")


def check_raw_denial(private, owner):
    files = list(private.glob("custody-stage-*-key-database"))
    if len(files) != 1 or files[0].stat().st_size == 0:
        raise RuntimeError("Expected one nonempty service-created credential stage")
    code = """import errno, os, sys
for flags in (os.O_RDONLY, os.O_WRONLY):
    try:
        fd = os.open(sys.argv[1], flags)
    except OSError as error:
        if error.errno != errno.EACCES:
            raise
    else:
        os.close(fd)
        raise RuntimeError('ordinary owner opened service credentials')
"""
    run(["runuser", "--user", pwd.getpwuid(owner).pw_name, "--",
         "python3", "-c", code, str(files[0])])


def exercise(binary, owner):
    with ExitStack() as stack:
        profile = uuid.uuid4()
        account = create_account(stack, "ewfixture" + profile.hex[:10])
        private = configure(stack, owner, account, profile)
        directory = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="ekubo-migration-", dir="/run")))
        directory.chmod(0o755)
        executable = directory / "migration-fixture"
        shutil.copyfile(binary, executable)
        executable.chmod(0o755)
        log_path = directory / "service.log"
        log = stack.enter_context(log_path.open("w"))
        process = subprocess.Popen(["runuser", "--user", account.pw_name, "--",
                                    str(executable), "service", str(owner)],
                                   stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        stack.callback(stop_fixture, process)
        try:
            wait_ready(process, owner)
            subprocess.run([str(executable), "client", str(owner)], check=True, timeout=420)
            check_raw_denial(private, owner)
        finally:
            stop_fixture(process)
            log.flush()
            print(log_path.read_text())
        print("Production Linux cross-user transfer/recovery and ordinary-owner raw file denial passed.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture-binary", required=True, type=Path)
    args = parser.parse_args()
    if (os.environ.get("GITHUB_ACTIONS") != "true" or os.environ.get("RUNNER_OS") != "Linux"
            or os.getuid() != 0 or os.geteuid() != 0):
        raise RuntimeError("Requires privileged installer context on disposable GitHub Linux CI")
    owner = int(os.environ.get("SUDO_UID", "0"))
    if owner == 0:
        raise RuntimeError("Requires the original non-root runner owner")
    exercise(args.fixture_binary.resolve(strict=True), owner)


if __name__ == "__main__":
    main()
