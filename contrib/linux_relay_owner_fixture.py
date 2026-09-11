#!/usr/bin/env python3
"""Run one synthetic owner relay endpoint with a private bus and keyring."""

from contextlib import ExitStack
import os
from pathlib import Path
import selectors
import subprocess
import sys
import tempfile
import time


def stop(child):
    if child.poll() is None:
        child.terminate()
        try:
            child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait(timeout=5)


def read_line(child, timeout):
    deadline = time.monotonic() + timeout
    data = bytearray()
    with selectors.DefaultSelector() as selector:
        selector.register(child.stdout, selectors.EVENT_READ)
        while time.monotonic() < deadline:
            if not selector.select(max(0, deadline - time.monotonic())):
                break
            chunk = os.read(child.stdout.fileno(), 256)
            if not chunk:
                raise RuntimeError("fixture process exited before readiness")
            data.extend(chunk)
            if len(data) > 256:
                raise RuntimeError("fixture readiness line is oversized")
            if b"\n" in data:
                return data.split(b"\n", 1)[0].decode("utf-8")
    raise RuntimeError("fixture readiness timed out")


def private_bus(stack, directory):
    configuration = directory / "bus.conf"
    configuration.write_text(f'''<busconfig><type>session</type>
<listen>unix:path={directory}/bus</listen><auth>EXTERNAL</auth>
<policy context="default"><allow send_destination="*"/>
<allow receive_sender="*"/><allow own="*"/></policy></busconfig>''')
    bus = subprocess.Popen(["dbus-daemon", "--nofork", "--print-address=1",
                            "--config-file", str(configuration)], stdout=subprocess.PIPE)
    stack.callback(stop, bus)
    return read_line(bus, 10)


def start_keyring(stack, directory, environment):
    daemon = subprocess.Popen(["gnome-keyring-daemon", "--foreground", "--components=secrets",
                               "--unlock", "--control-directory", str(directory / "control")],
                              env=environment, stdin=subprocess.PIPE,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    stack.callback(stop, daemon)
    daemon.stdin.write(b"isolated-relay-fixture-password")
    daemon.stdin.close()
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if daemon.poll() is not None:
            raise RuntimeError("private fixture keyring exited")
        result = subprocess.run(["busctl", "--address=" + environment["DBUS_SESSION_BUS_ADDRESS"],
                                 "call", "org.freedesktop.DBus", "/org/freedesktop/DBus",
                                 "org.freedesktop.DBus", "GetNameOwner", "s", "org.freedesktop.secrets"],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2)
        if result.returncode == 0:
            return
        time.sleep(0.05)
    raise RuntimeError("private fixture keyring did not become ready")


def main():
    if (os.environ.get("GITHUB_ACTIONS") != "true" or os.environ.get("RUNNER_OS") != "Linux"
            or os.getuid() == 0 or os.getuid() != os.geteuid()):
        raise RuntimeError("Requires an ordinary owner on disposable GitHub Linux CI")
    if len(sys.argv) != 3 or sys.argv[2] not in ("relay-owner", "source-owner"):
        raise RuntimeError("expected fixture executable and owner mode")
    executable = Path(sys.argv[1]).resolve(strict=True)
    with ExitStack() as stack:
        directory = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="ekubo-relay-")))
        environment = os.environ.copy()
        for name in ("GNOME_KEYRING_CONTROL", "DISPLAY", "WAYLAND_DISPLAY"):
            environment.pop(name, None)
        for name, child in (("XDG_DATA_HOME", "data"), ("XDG_RUNTIME_DIR", "runtime")):
            path = directory / child
            path.mkdir(mode=0o700)
            environment[name] = str(path)
        environment["DBUS_SESSION_BUS_ADDRESS"] = private_bus(stack, directory)
        environment["EKUBO_FIXTURE_ISOLATED_RELAY"] = str(directory)
        environment["EKUBO_WALLET_HOME"] = str(directory / "wallet")
        start_keyring(stack, directory, environment)
        subprocess.run([str(executable), sys.argv[2], str(os.getuid())], env=environment,
                       check=True, timeout=480)


if __name__ == "__main__":
    main()
