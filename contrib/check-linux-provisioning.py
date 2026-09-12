#!/usr/bin/env python3
"""Synthetic cross-user migration on disposable GitHub Linux runners only."""

import argparse
from contextlib import ExitStack
import json
import os
from pathlib import Path
import pwd
import re
import signal
import shutil
import subprocess
import tempfile
import time
import uuid

from linux_relay_owner_fixture import read_line

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


def remove_unit(path):
    path.unlink()
    run(["systemctl", "daemon-reload"])


def stop_fixture(unit):
    # Only the unique unit created by this fixture; never stop a system daemon.
    subprocess.run(["systemctl", "stop", unit], check=True, timeout=45)


def fixture_unit_content(account_name, executable):
    content = (ROOT / "contrib/linux-service/ekubo-wallet-provision@.service").read_text()
    content = content.replace("User=ekubo-wallet", f"User={account_name}")
    content = content.replace("Group=ekubo-wallet", f"Group={account_name}")
    content = content.replace(
        "ExecStart=/usr/lib/ekubo-wallet/ekubo-wallet-service --provision-owner-uid %i",
        f'ExecStart="{executable}" service %i',
    )
    # systemd does not inherit the invoking runner's environment. These enable
    # only the fixture executable's guard, not an alternate production host.
    content += "\nEnvironment=GITHUB_ACTIONS=true\nEnvironment=RUNNER_OS=Linux\n"
    return content


def install_fixture_unit(stack, account, executable, profile, owner):
    template = f"ekubo-wallet-provision-fixture-{profile.hex}@.service"
    unit = template.replace("@.service", f"@{owner}.service")
    path = Path("/run/systemd/system") / template
    content = fixture_unit_content(account.pw_name, executable)
    with path.open("x") as output:
        output.write(content)
    stack.callback(remove_unit, path)
    path.chmod(0o644)
    run(["systemctl", "daemon-reload"])
    stack.callback(stop_fixture, unit)
    return unit


def wait_ready(unit, owner):
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        status = subprocess.run(["systemctl", "is-active", "--quiet", unit], check=False, timeout=30)
        if status.returncode != 0:
            raise RuntimeError("Synthetic systemd service exited before readiness")
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


def stop_owner(child):
    if child.poll() is None:
        os.killpg(child.pid, signal.SIGTERM)
        try:
            child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(child.pid, signal.SIGKILL)
            child.wait(timeout=5)


def start_owner(stack, executable, owner, source):
    child = subprocess.Popen(["runuser", "--user", pwd.getpwuid(owner).pw_name, "--",
                              "python3", str(ROOT / "contrib/linux_relay_owner_fixture.py"), str(executable),
                              "source-owner" if source else "relay-owner"],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, start_new_session=True)
    stack.callback(stop_owner, child)
    name = read_line(child, 30)
    if re.fullmatch(r":[0-9]+\.[0-9]+", name) is None:
        raise RuntimeError("owner relay returned an invalid unique name")
    return child, name


def exercise(binary, owner, source=False):
    with ExitStack() as stack:
        profile = uuid.uuid4()
        account = create_account(stack, "ewfixture" + profile.hex[:10])
        private = configure(stack, owner, account, profile)
        directory = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="ekubo-migration-", dir="/run")))
        directory.chmod(0o755)
        executable = directory / "migration-fixture"
        shutil.copyfile(binary, executable)
        executable.chmod(0o755)
        unit = install_fixture_unit(stack, account, executable, profile, owner)
        try:
            subprocess.run(["systemctl", "start", unit], check=True, timeout=45)
            wait_ready(unit, owner)
            owner_process, recipient = start_owner(stack, executable, owner, source)
            variable = "EKUBO_FIXTURE_SOURCE_RECIPIENT" if source else "EKUBO_FIXTURE_RELAY_RECIPIENT"
            environment = dict(os.environ, **{variable: recipient})
            subprocess.run([str(executable), "source-client" if source else "client", str(owner)],
                           env=environment, check=True, timeout=420)
            if source:
                recover_source(executable, owner_process, owner, unit)
            owner_process.stdin.write(b"finish\n")
            owner_process.stdin.flush()
            if owner_process.wait(timeout=15) != 0:
                raise RuntimeError("owner relay verification failed")
            check_raw_denial(private, owner)
            stop_fixture(unit)
            subprocess.run([str(executable), "verify-prepared", str(owner)], check=True, timeout=60)
        finally:
            stop_fixture(unit)
            run(["journalctl", "--unit", unit, "--no-pager", "--output", "cat"])
        label = "owner-keyring source forwarding" if source else "migration/recovery"
        print(f"Production Linux systemd {label} and ordinary-owner raw file denial passed.")


def recover_source(executable, child, owner, unit):
    child.stdin.write(b"recover\n")
    child.stdin.flush()
    recipient = read_line(child, 30)
    if re.fullmatch(r":[0-9]+\.[0-9]+", recipient) is None:
        raise RuntimeError("owner recovery returned an invalid unique name")
    subprocess.run(["systemctl", "restart", unit], check=True, timeout=45)
    wait_ready(unit, owner)
    subprocess.run([str(executable), "source-recover", str(owner)],
                   env=dict(os.environ, EKUBO_FIXTURE_SOURCE_RECIPIENT=recipient),
                   check=True, timeout=420)
    child.stdin.write(b"recover-cutover\n")
    child.stdin.flush()
    recipient = read_line(child, 30)
    if re.fullmatch(r":[0-9]+\.[0-9]+", recipient) is None:
        raise RuntimeError("owner cutover recovery returned an invalid unique name")
    subprocess.run([str(executable), "source-recover-cutover", str(owner)],
                   env=dict(os.environ, EKUBO_FIXTURE_SOURCE_RECIPIENT=recipient),
                   check=True, timeout=420)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture-binary", required=True, type=Path)
    args = parser.parse_args()
    if (os.environ.get("GITHUB_ACTIONS") != "true" or os.environ.get("RUNNER_OS") != "Linux"
            or os.getuid() != 0 or os.geteuid() != 0):
        raise RuntimeError("Requires privileged installer context on disposable GitHub Linux CI")
    if Path("/proc/1/comm").read_text().strip() != "systemd":
        raise RuntimeError("Requires the disposable runner's systemd manager")
    owner = int(os.environ.get("SUDO_UID", "0"))
    if owner == 0:
        raise RuntimeError("Requires the original non-root runner owner")
    exercise(args.fixture_binary.resolve(strict=True), owner)
    exercise(args.fixture_binary.resolve(strict=True), owner, source=True)


if __name__ == "__main__":
    main()
