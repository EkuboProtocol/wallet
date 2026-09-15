#!/usr/bin/env python3
"""Destructive acceptance ONLY on an empty, disposable GitHub-hosted Linux runner.

Installs production binaries/assets at their real fixed paths. The sole fake is
Polkit consent for a unique synthetic owner, not the bus, custody or enrollment.
"""

import hashlib
import grp
from contextlib import contextmanager
import json
import os
from pathlib import Path
import pwd
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import uuid

REPO = Path(__file__).resolve().parent.parent
LIB = Path('/usr/lib/ekubo-wallet-v2')
ROOTS = [LIB, Path('/etc/ekubo-wallet-v2'), Path('/var/lib/ekubo-wallet-v2'),
         Path('/run/ekubo-wallet-v2')]
SERVICE = 'ekubo-wallet-v2'
ACCEPTANCE_PACKAGE = 'ekubo-wallet-v2-activation-acceptance'
RUNNER_SHARE_PATHS = tuple(map(Path, ['/usr/share', '/usr/share/dbus-1',
                                    '/usr/share/dbus-1/system-services']))
UNITS = ['ekubo-wallet-v2@.service', 'ekubo-wallet-v2-provision@.service']
FAULT_DIR = Path('/run/ekubo-wallet-v2/acceptance-fault')
ASSETS = {
    **{f'linux-service/{name}': Path('/usr/lib/systemd/system') / name for name in UNITS},
    **{f'linux-service/org.ekubo.Wallet2.{kind}.conf':
       Path(f'/usr/share/dbus-1/system.d/org.ekubo.Wallet2.{kind}.conf')
       for kind in ['Owner', 'Provision']},
    'linux-service/ekubo-wallet-v2.sysusers': Path('/usr/lib/sysusers.d/ekubo-wallet-v2.conf'),
    'linux-service/ekubo-wallet-v2.tmpfiles': Path('/usr/lib/tmpfiles.d/ekubo-wallet-v2.conf'),
    'polkit/com.ekubo.wallet.v2.policy': Path('/usr/share/polkit-1/actions/com.ekubo.wallet.v2.policy'),
    'linux-service/org.ekubo.Wallet2.Owner.service.in': LIB / 'org.ekubo.Wallet2.Owner.service.in',
}


def require_runner(env, uid, platform, explicit):
    if not (explicit and uid == 0 and platform == 'linux'
            and env.get('GITHUB_ACTIONS') == 'true'
            and env.get('RUNNER_ENVIRONMENT') == 'github-hosted'
            and env.get('RUNNER_OS') == 'Linux'):
        raise RuntimeError('REFUSED: requires an explicit disposable mode, root, and a GitHub-hosted Linux runner')


def absent(paths):
    for path in paths:
        if os.path.lexists(path):
            raise RuntimeError(f'REFUSED: pre-existing fixture path: {path}')


def run(*args, **kwargs):
    return subprocess.run(args, check=True, timeout=120, **kwargs)


def install(source, target, created, mode=0o644):
    # O_EXCL rejects even dangling symlinks after preflight. Record ownership
    # before copying so cleanup includes partial files after any copy failure.
    with target.open('xb') as output:
        created.append(target)
        with source.open('rb') as source_file:
            shutil.copyfileobj(source_file, output)
        os.fchmod(output.fileno(), mode)


def unused_accounts(owner, include_service=True):
    for lookup, kind in [(pwd.getpwnam, 'account'), (grp.getgrnam, 'group')]:
        for name in ([SERVICE, owner] if include_service else [owner]):
            try:
                lookup(name)
            except KeyError:
                continue
            raise RuntimeError(f'REFUSED: existing {kind} {name}')


def absent_activation_fixture():
    if list(Path('/usr/share/dbus-1/system-services').glob('org.ekubo.Wallet2.Owner.u*.service')):
        raise RuntimeError('REFUSED: existing v2 activation files')
    if subprocess.run(['dpkg-query', '-W', ACCEPTANCE_PACKAGE], capture_output=True).returncode == 0:
        raise RuntimeError('REFUSED: existing acceptance package')


def directory_identity(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode)


def runner_directory_mode(path, info):
    """Only the image's documented root:root 0777 share tree is repairable."""
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_gid != 0:
        raise RuntimeError(f'REFUSED: unexpected runner directory identity: {path}')
    mode = stat.S_IMODE(info.st_mode)
    if path in RUNNER_SHARE_PATHS and mode == 0o777:
        return 0o755
    if mode & 0o022:
        raise RuntimeError(f'REFUSED: unexpected runner directory mode: {path}')
    return mode


def inspect_runner_activation_ancestors():
    # actions/runner-images images/ubuntu/scripts/build/configure-system.sh
    # chmods /usr/share recursively to 777. Never copy that trust exception into
    # the shipped installer, or recursively change any runner directory here.
    snapshots = []
    for path in [Path('/'), Path('/usr'), *RUNNER_SHARE_PATHS]:
        info = path.lstat()
        print(f'Activation ancestor {path}: uid={info.st_uid} gid={info.st_gid} '
              f'mode={stat.S_IMODE(info.st_mode):04o} dev={info.st_dev} ino={info.st_ino}', flush=True)
        mode = runner_directory_mode(path, info)
        snapshots.append((path, info, mode))
    return snapshots


@contextmanager
def hardened_runner_activation_ancestors(snapshots):
    require_runner(os.environ, os.geteuid(), sys.platform, True)
    changed = []
    try:
        for path, expected, mode in snapshots:
            fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                if directory_identity(os.fstat(fd)) != directory_identity(expected):
                    raise RuntimeError(f'REFUSED: runner ancestor changed after preflight: {path}')
                if mode != stat.S_IMODE(expected.st_mode):
                    changed.append((os.dup(fd), path, expected))
                    os.fchmod(fd, mode)
                    print(f'Temporarily hardened exact runner directory {path} to {mode:04o}', flush=True)
            finally:
                os.close(fd)
        yield
    finally:
        failures = []
        for fd, path, original in reversed(changed):
            try:
                os.fchmod(fd, stat.S_IMODE(original.st_mode))
                if directory_identity(os.fstat(fd)) != directory_identity(original):
                    raise RuntimeError(f'Runner ancestor restoration mismatch: {path}')
                print(f'Restored {path}: uid={original.st_uid} gid={original.st_gid} '
                      f'mode={stat.S_IMODE(original.st_mode):04o}', flush=True)
            except OSError as error:
                failures.append(error)
            except RuntimeError as error:
                failures.append(error)
            finally:
                os.close(fd)
        if failures:
            raise RuntimeError('Could not restore all runner activation ancestors') from failures[0]


def preflight(binary_dir, owner, home, rule, migration):
    require_runner(os.environ, os.geteuid(), sys.platform, True)
    if Path('/proc/1/comm').read_text().strip() != 'systemd':
        raise RuntimeError('REFUSED: PID 1 must be real systemd')
    absent([*ROOTS, *ASSETS.values(), home, rule])
    absent_activation_fixture()
    for base in ['/etc/systemd/system', '/run/systemd/system', '/usr/lib/systemd/system']:
        if list(Path(base).glob('ekubo-wallet-v2*')):
            raise RuntimeError(f'REFUSED: existing v2 units in {base}')
    if list(Path('/etc/tmpfiles.d').glob('ekubo-wallet-v2*')):
        raise RuntimeError('REFUSED: existing v2 runtime configuration')
    unused_accounts(owner)
    for binary in ['ekubo-wallet-service', 'ekubo-wallet-v2-enroll']:
        if not os.access(binary_dir / binary, os.X_OK):
            raise RuntimeError(f'Missing production binary: {binary_dir / binary}')
    if migration:
        for name in ['linux-move-fixture', 'linux-move-client']:
            if not os.access(binary_dir / 'examples' / name, os.X_OK):
                raise RuntimeError(f'Missing acceptance example: {name}')
    run('systemctl', 'is-active', 'dbus.service')
    return inspect_runner_activation_ancestors()


def policy(owner, uid, migration=False):
    # pkexec still runs the fixed root installer with the real endpoint's unique
    # bus name; the normal helper persists/readbacks the real opaque envelope.
    fault = '''
        // Import is the first service-side move challenge; Complete is second.
        // Source-process challenges have no polkit.message detail. Block at
        // Complete until the root coordinator kills this service, breaking the
        // actual transport. The next service process may resume the receipt.
        if (action.lookup("polkit.message") === "move the reviewed legacy profile to v2 and retire its verified, unshared 1.x account credentials" && ++serviceMoveCalls === 2) {
            polkit.spawn(["/usr/bin/python3", "/usr/lib/ekubo-wallet-v2/acceptance-fault.py"]);
            return polkit.Result.NO;
        }
''' if migration else ''
    return f'''// DISPOSABLE CI ONLY: synthetic consent, never a shipped policy.
var serviceMoveCalls = 0;
polkit.addRule(function(action, subject) {{
    if (subject.user !== "{owner}") return polkit.Result.NOT_HANDLED;
    if (action.id === "com.ekubo.wallet.v2.human-presence") {{
        {fault}
        return polkit.Result.YES;
    }}
    if (action.id === "org.freedesktop.policykit.exec" &&
        action.lookup("program") === "{LIB}/install-profile" &&
        (new RegExp("^{LIB}/install-profile {uid} :[0-9]+\\\\.[0-9]+$").test(action.lookup("command_line")) ||
         action.lookup("command_line") === "{LIB}/install-profile --resume {uid}"))
        return polkit.Result.YES;
    // The shipped policy pins install-profile to its dedicated action via
    // exec.path, so pkexec resolves here instead of the generic exec action
    // above. Grant the exact same command lines under the pinned action id.
    if (action.id === "org.ekubo.wallet.v2.install-profile" &&
        action.lookup("program") === "{LIB}/install-profile" &&
        (new RegExp("^{LIB}/install-profile {uid} :[0-9]+\\\\.[0-9]+$").test(action.lookup("command_line")) ||
         action.lookup("command_line") === "{LIB}/install-profile --resume {uid}"))
        return polkit.Result.YES;
    return polkit.Result.NOT_HANDLED;
}});
'''


FAULT_HANDSHAKE = r'''
from pathlib import Path
import time

# Root creates this private directory for polkitd. The synthetic owner cannot
# forge the barrier. No key, receipt or database ever passes through this helper.
root = Path("/run/ekubo-wallet-v2/acceptance-fault")
(root / "entered").touch(exist_ok=False)
deadline = time.monotonic() + 30
while not (root / "release").exists():
    if time.monotonic() >= deadline:
        raise SystemExit("coordinator did not break the service transport")
    time.sleep(0.01)
'''


OWNER_SESSION = r'''
set -eu
umask 077
wait_file() {
    for attempt in $(seq 1 900); do
        test ! -f "$HOME/$1" || return 0
        sleep 0.1
    done
    return 1
}
mkdir -p "$XDG_DATA_HOME" "$XDG_RUNTIME_DIR" "$HOME/control"
printf '%s' 'ci-only-keyring-password' | gnome-keyring-daemon --foreground --components=secrets --unlock --control-directory "$HOME/control" &
keyring=$!
trap 'kill "$keyring" 2>/dev/null || true; wait "$keyring" 2>/dev/null || true' EXIT
for attempt in $(seq 1 100); do
    if gdbus call --session --dest org.freedesktop.DBus --object-path /org/freedesktop/DBus --method org.freedesktop.DBus.NameHasOwner org.freedesktop.secrets | grep -q true; then break; fi
    sleep 0.1
done
if test "$ACCEPTANCE_MODE" = fresh; then
    mkdir -p "$XDG_DATA_HOME/ekubo-wallet"
    printf '%s' 'synthetic-v1-database-sentinel' > "$XDG_DATA_HOME/ekubo-wallet/wallet.db"
    printf '%s' 'synthetic-v1-credential-sentinel' | secret-tool store --label='Disposable v1 sentinel' service org.ekubo.wallet.db username default
else
    /usr/lib/ekubo-wallet-v2/linux-move-fixture create
fi
if test "$ACCEPTANCE_MODE" = sentinel; then
    touch "$HOME/enrolled"
    wait_file finish
    /usr/lib/ekubo-wallet-v2/linux-move-fixture verify
    exit 0
fi
/usr/lib/ekubo-wallet-v2/ekubo-wallet-v2-enroll --owner
if test "$ACCEPTANCE_MODE" = move; then
    /usr/lib/ekubo-wallet-v2/linux-move-fixture verify
    /usr/lib/ekubo-wallet-v2/linux-move-client interrupt
    touch "$HOME/move-pending"
    wait_file move-resume
    /usr/lib/ekubo-wallet-v2/ekubo-wallet-v2-enroll --resume-owner
    /usr/lib/ekubo-wallet-v2/linux-move-client resume
fi
/usr/bin/python3 "$HOME/hold-owner.py" enrolled restart
/usr/lib/ekubo-wallet-v2/ekubo-wallet-v2-enroll --resume-owner
/usr/bin/python3 "$HOME/hold-owner.py" restarted finish
if test "$ACCEPTANCE_MODE" = fresh; then
    test "$(secret-tool lookup service org.ekubo.wallet.db username default)" = synthetic-v1-credential-sentinel
    test "$(cat "$XDG_DATA_HOME/ekubo-wallet/wallet.db")" = synthetic-v1-database-sentinel
fi
'''


OWNER_LEASE = r'''
import json
import os
from pathlib import Path
import sys
import time
import uuid

import dbus
from dbus.mainloop.glib import DBusGMainLoop
from gi.repository import GLib

home = Path.home()
uid = os.getuid()
assert uid != 0 and home.name.startswith("ewv2-ci-")
phase, release = sys.argv[1:]
assert (phase, release) in [("enrolled", "restart"), ("restarted", "finish")]
metadata_path = Path(f"/etc/ekubo-wallet-v2/owners/{uid}.json")
assert metadata_path.stat().st_uid == 0 and not metadata_path.stat().st_mode & 0o022
metadata = json.loads(metadata_path.read_text())
assert metadata["owner_uid"] == uid and metadata["service_uid"] not in [0, uid]
DBusGMainLoop(set_as_default=True)
bus = dbus.SystemBus(private=True)
try:
    registry = dbus.Interface(bus.get_object("org.freedesktop.DBus", "/org/freedesktop/DBus"), "org.freedesktop.DBus")
    service = str(registry.GetNameOwner(f"org.ekubo.Wallet2.Owner.u{uid}"))
    assert int(registry.GetConnectionUnixUser(service)) == metadata["service_uid"]
    path = "/org/ekubo/Wallet2/Owner"
    interface = "org.ekubo.Wallet2.Owner1"
    owner = dbus.Interface(bus.get_object(service, path, introspect=False), interface)
    nonce = str(uuid.uuid4())
    loop = GLib.MainLoop()
    outcome = []
    def ready(value, sender=None):
        assert str(value) == nonce and sender == service
        outcome.append("ready")
        loop.quit()
    def failed(error="HoldDesktopSession returned before release"):
        outcome.append(str(error))
        loop.quit()
    # Subscribe on the SAME private connection before issuing the held call.
    # The service's readiness signal is unicast to this unique bus peer.
    watch = bus.add_signal_receiver(ready, signal_name="DesktopSessionReady",
                                   dbus_interface=interface, bus_name=service,
                                   path=path, arg0=nonce, sender_keyword="sender")
    timer = GLib.timeout_add_seconds(30, lambda: failed("desktop lease readiness timed out"))
    pending = owner.HoldDesktopSession(nonce, reply_handler=failed,
                                      error_handler=failed, timeout=180)
    loop.run()
    GLib.source_remove(timer)
    assert outcome == ["ready"], outcome
    def call(method, params=None):
        request = dict(method=method)
        if params is not None:
            request["params"] = params
        return json.loads(str(owner.Call(json.dumps(request), timeout=30)))
    inventory_file = home / "public-inventory.json"
    if os.environ["ACCEPTANCE_MODE"] == "move":
        expected = json.loads((home / "move-expected.json").read_text())
        assert call("accounts") == expected["accounts"]
        assert call("policy", dict(wallet_id="moved-ci")) == expected["policy"]
        assert call("legacy_move_status")["state"] == "complete"
        inventory_file.write_text(json.dumps(expected["accounts"]))
    elif phase == "enrolled":
        assert call("accounts") == []
        account = call("create_account", dict(wallet_id="installed-ci"))
        assert account["id"] == "installed-ci"
        assert len(account["address"]) == 42 and account["address"] != "0x" + "0" * 40
        inventory = call("accounts")
        assert inventory == [account]
        inventory_file.write_text(json.dumps(inventory))
    else:
        assert call("accounts") == json.loads(inventory_file.read_text())
    # Readiness means the authenticated Hold lease is active AND the public
    # account inventory operation completed on the real owner dispatcher.
    (home / phase).touch()
    deadline = time.monotonic() + 90
    while not (home / release).exists():
        if time.monotonic() >= deadline:
            raise RuntimeError("coordinator did not release desktop lease")
        time.sleep(0.05)
finally:
    bus.close()
'''


def wait_marker(home, name, process):
    deadline = time.monotonic() + 90
    while not (home / name).exists():
        if process.poll() is not None:
            raise RuntimeError(f'Owner exited {process.returncode} before {name}')
        if time.monotonic() >= deadline:
            raise RuntimeError(f'Timed out before {name}')
        time.sleep(0.1)


def fingerprint(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def inspect_active(owner, uid, service_uid):
    unit = f'ekubo-wallet-v2@{uid}.service'
    pid = int(run('systemctl', 'show', unit, '--property=MainPID', '--value',
                  capture_output=True, text=True).stdout)
    if pid <= 0 or Path(f'/proc/{pid}').stat().st_uid != service_uid:
        raise RuntimeError('Service is not running under its distinct installed UID')
    data = Path(f'/var/lib/ekubo-wallet-v2/{uid}')
    protected = [data / name for name in ['wrapping.key', 'custody.json', 'key-database',
                                         'wallet.db', 'setup-complete']]
    inventory = json.loads((Path('/home') / owner / 'public-inventory.json').read_text())
    protected.extend(data / f'key-account-{uuid.UUID(account["instance_id"])}' for account in inventory)
    for path in protected:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != service_uid or info.st_mode & 0o077:
            raise RuntimeError(f'Unprotected or missing service record: {path.name}')
    # Execute real open(2) as the owner. ENOENT is failure, not permission denial.
    run('runuser', '-u', owner, '--', 'python3', '-c', '''
import os, sys
for path in sys.argv[1:]:
    for flags in [os.O_RDONLY, os.O_WRONLY]:
        try:
            fd = os.open(path, flags)
        except PermissionError:
            continue
        else:
            os.close(fd)
            raise SystemExit("owner accessed protected service file")
''', *map(str, protected))
    # Real MCP reads prove the unlocked runtime was published, beyond Type=dbus
    # bootstrap readiness. Only the fixture's newly generated account exists;
    # no private key is exported or imported.
    run('runuser', '-u', owner, '--', 'python3', '-c', '''
import json, socket, struct, sys
with socket.socket(socket.AF_UNIX) as sock:
    sock.settimeout(10)
    sock.connect(sys.argv[1])
    _, peer_uid, _ = struct.unpack("3i", sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    assert peer_uid == int(sys.argv[2])
    with sock.makefile("rwb") as wire:
        def send(value):
            wire.write(json.dumps(value).encode() + b"\\n")
            wire.flush()
        def request(id, method, params):
            send(dict(jsonrpc="2.0", id=id, method=method, params=params))
            while True:
                reply = json.loads(wire.readline())
                if reply.get("id") == id:
                    assert "error" not in reply, reply
                    return reply["result"]
        send(dict(client="codex"))
        result = request(1, "initialize", dict(protocolVersion="2025-11-25", capabilities={}, clientInfo=dict(name="installed-ci", version="1")))
        assert "serverInfo" in result
        send(dict(jsonrpc="2.0", method="notifications/initialized"))
        tools = request(2, "tools/list", {})["tools"]
        assert any(tool["name"] == "wallet_get_legal" for tool in tools)
        legal = request(3, "tools/call", dict(name="wallet_get_legal", arguments={}))
        assert not legal.get("isError", False), legal
''', f'/run/ekubo-wallet-v2/{uid}/mcp.sock', str(service_uid))
    return pid, {path.name: fingerprint(path) for path in protected if path.name != 'wallet.db'}


def delete_account(name):
    run('userdel', name)
    try:
        grp.getgrnam(name)
    except KeyError:
        return  # userdel may already remove its private primary group.
    run('groupdel', name)


def cleanup(created, owner, uid, home, account_created, service_created):
    if uid is not None:
        for unit in [f'ekubo-wallet-v2@{uid}.service', f'ekubo-wallet-v2-provision@{uid}.service']:
            subprocess.run(['systemctl', 'disable', '--now', unit], check=False, timeout=40)
            subprocess.run(['systemctl', 'reset-failed', unit], check=False, timeout=10)
        Path(f'/etc/tmpfiles.d/ekubo-wallet-v2-{uid}.conf').unlink(missing_ok=True)
        Path(f'/usr/share/dbus-1/system-services/org.ekubo.Wallet2.Owner.u{uid}.service').unlink(missing_ok=True)
    for path in reversed(created):
        if path.is_dir() and not path.is_symlink():
            shutil.rmtree(path)
        else:
            path.unlink(missing_ok=True)
    if account_created:
        subprocess.run(['pkill', '-u', owner], check=False)
        delete_account(owner)
        shutil.rmtree(home)
    if service_created:
        delete_account(SERVICE)
    run('systemctl', 'daemon-reload')
    run('systemctl', 'reload', 'dbus.service')


def stop_session(process):
    if process is None or process.poll() is not None:
        return
    os.killpg(process.pid, signal.SIGTERM)
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait()


def reinstall_and_activate(owner, uid):
    # A focused real dpkg payload, with the production installer/template and
    # maintainer hooks. No Rust build or production desktop package is needed.
    with tempfile.TemporaryDirectory(prefix='ewv2-reinstall-') as temporary:
        root = Path(temporary) / 'root'
        for source in [*ASSETS.values(), LIB / 'install-profile',
                       LIB / 'ekubo-wallet-service', LIB / 'ekubo-wallet-v2-enroll']:
            target = root / source.relative_to('/')
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
        control = root / 'DEBIAN'
        control.mkdir()
        (control / 'control').write_text(
            f'Package: {ACCEPTANCE_PACKAGE}\nVersion: 1\nArchitecture: all\n'
            'Maintainer: Acceptance <noreply@ekubo.org>\nDescription: Disposable activation acceptance\n')
        for hook in ['preinst', 'postinst']:
            shutil.copy2(REPO / f'contrib/deb-v2-{hook}', control / hook)
            (control / hook).chmod(0o755)
        package = Path(temporary) / 'acceptance.deb'
        run('dpkg-deb', '--build', str(root), str(package))
        run('dpkg', '--install', str(package))
        unit = f'ekubo-wallet-v2@{uid}.service'
        run('systemctl', 'stop', unit)
        activation = Path(f'/usr/share/dbus-1/system-services/org.ekubo.Wallet2.Owner.u{uid}.service')
        original = activation.read_bytes()
        # Model an older package/profile with no published activation asset.
        activation.unlink()
        run('dpkg', '--install', str(package))
        assert activation.read_bytes() == original
        assert run('systemctl', 'show', unit, '--property=ActiveState', '--value',
                   capture_output=True, text=True).stdout.strip() == 'inactive'
        run('runuser', '-u', owner, '--', 'python3', '-c', '''
import dbus, sys
bus = dbus.SystemBus()
registry = dbus.Interface(bus.get_object("org.freedesktop.DBus", "/org/freedesktop/DBus"), "org.freedesktop.DBus")
assert registry.StartServiceByName("org.ekubo.Wallet2.Owner.u" + sys.argv[1], 0) == 1
''', str(uid))
        run('systemctl', 'is-active', unit)


def restart_and_compare(owner, uid, service_uid, home, process):
    first_pid, before = inspect_active(owner, uid, service_uid)
    metadata = Path(f'/etc/ekubo-wallet-v2/owners/{uid}.json')
    identity = json.loads(metadata.read_text())
    if identity['owner_uid'] != uid or identity['service_uid'] != service_uid:
        raise RuntimeError('Published enrollment identity mismatch')
    before_metadata = fingerprint(metadata)
    reinstall_and_activate(owner, uid)
    # The bus name is now available, but no authority may reopen itself from
    # service-local data alone. A stale socket inode is not an unlocked runtime.
    run('runuser', '-u', owner, '--', 'python3', '-c', '''
import socket, sys
with socket.socket(socket.AF_UNIX) as sock:
    sock.settimeout(5)
    try:
        sock.connect(sys.argv[1])
    except (ConnectionRefusedError, FileNotFoundError):
        pass
    else:
        raise SystemExit("service exposed MCP before owner relay unlock")
''', f'/run/ekubo-wallet-v2/{uid}/mcp.sock')
    (home / 'restart').touch()
    wait_marker(home, 'restarted', process)
    second_pid, after = inspect_active(owner, uid, service_uid)
    if first_pid == second_pid or before != after or fingerprint(metadata) != before_metadata:
        raise RuntimeError('Restart did not preserve the enrolled service custody')


def start_owner_session(owner, home, mode):
    with (home / 'owner-session.log').open('w') as log:
        return subprocess.Popen([
            'runuser', '-u', owner, '--', 'env', '-i', 'PATH=/usr/bin:/bin',
            f'HOME={home}', f'USER={owner}', f'LOGNAME={owner}',
            f'XDG_DATA_HOME={home}/data', f'XDG_RUNTIME_DIR={home}/runtime',
            f'ACCEPTANCE_MODE={mode}', 'EKUBO_INSTALLED_ACCEPTANCE=1',
            'dbus-run-session', '--', 'bash', '-c', OWNER_SESSION,
        ], stdout=log, stderr=subprocess.STDOUT, start_new_session=True)


@contextmanager
def unmigrated_sentinel(migration):
    if not migration:
        yield
        return
    owner = f'ewv2-ci-{uuid.uuid4().hex[:12]}'
    home = Path('/home') / owner
    absent([home])
    unused_accounts(owner, include_service=False)
    process = None
    created = False
    try:
        run('useradd', '--create-home', '--home-dir', str(home), '--shell', '/bin/bash', owner)
        created = True
        process = start_owner_session(owner, home, 'sentinel')
        wait_marker(home, 'enrolled', process)
        yield
        (home / 'finish').touch()
        if process.wait(timeout=15) != 0:
            raise RuntimeError('Unmigrated owner source/credentials changed')
        print('PASS: second synthetic owner retains its real legacy database and both legacy credentials')
    except BaseException:
        if (home / 'owner-session.log').exists():
            print((home / 'owner-session.log').read_text(), file=sys.stderr)
        raise
    finally:
        stop_session(process)
        if created:
            subprocess.run(['pkill', '-u', owner], check=False)
            delete_account(owner)
            shutil.rmtree(home)


def run_owner_checks(owner, uid, service_uid, home, migration):
    process = start_owner_session(owner, home, 'move' if migration else 'fresh')
    try:
        if migration:
            # Complete is blocked in the real native challenge after source
            # retirement. Kill the exact systemd unit before releasing Polkit.
            wait_marker(FAULT_DIR, 'entered', process)
            run('systemctl', 'kill', '--signal=KILL', f'ekubo-wallet-v2@{uid}.service')
            (FAULT_DIR / 'release').touch()
            # The source client verifies missing old credentials and the exact
            # encrypted backup, then exits following the real transport error.
            wait_marker(home, 'move-pending', process)
            run('systemctl', 'restart', f'ekubo-wallet-v2@{uid}.service')
            (home / 'move-resume').touch()
        wait_marker(home, 'enrolled', process)
        restart_and_compare(owner, uid, service_uid, home, process)
        (home / 'finish').touch()
        if process.wait(timeout=10) != 0:
            raise RuntimeError('Owner session did not complete successfully')
    finally:
        stop_session(process)


def install_fault_fixture(created):
    polkit = pwd.getpwnam('polkitd')
    FAULT_DIR.mkdir(mode=0o700)
    os.chown(FAULT_DIR, polkit.pw_uid, polkit.pw_gid)
    # Parent ROOTS already owns cleanup of this directory and any handshake
    # files created by polkitd. The program itself is root-owned and immutable
    # to both fixture owners and to polkitd.
    helper = LIB / 'acceptance-fault.py'
    with helper.open('x') as output:
        created.append(helper)
        output.write(FAULT_HANDSHAKE)
        os.fchmod(output.fileno(), 0o644)


def acceptance(binary_dir, migration=False):
    owner = f'ewv2-ci-{uuid.uuid4().hex[:12]}'
    home = Path('/home') / owner
    rule = Path('/etc/polkit-1/rules.d') / f'00-{owner}.rules'
    snapshots = preflight(binary_dir, owner, home, rule, migration)
    with hardened_runner_activation_ancestors(snapshots):
        acceptance_fixture(binary_dir, owner, home, rule, migration)


def acceptance_fixture(binary_dir, owner, home, rule, migration):
    created = []
    account_created = service_created = False
    uid = None
    try:
        run('systemctl', 'start', 'polkit.service')
        run('useradd', '--create-home', '--home-dir', str(home), '--shell', '/bin/bash', owner)
        account_created = True
        uid = pwd.getpwnam(owner).pw_uid
        for path in ROOTS:
            path.mkdir(mode=0o755)
            created.append(path)
        for source, target in ASSETS.items():
            install(REPO / 'contrib' / source, target, created)
        for name in ['ekubo-wallet-service', 'ekubo-wallet-v2-enroll']:
            install(binary_dir / name, LIB / name, created, 0o755)
        if migration:
            for name in ['linux-move-fixture', 'linux-move-client']:
                install(binary_dir / 'examples' / name, LIB / name, created, 0o755)
            install_fault_fixture(created)
        install(REPO / 'contrib/linux-service/install-profile', LIB / 'install-profile', created, 0o755)
        run('systemd-sysusers', '/usr/lib/sysusers.d/ekubo-wallet-v2.conf')
        service_created = True
        service_uid = pwd.getpwnam(SERVICE).pw_uid
        if service_uid in [0, uid]:
            raise RuntimeError('Owner and service must have distinct non-root UIDs')
        with rule.open('x') as output:
            created.append(rule)
            output.write(policy(owner, uid, migration))
        run('systemd-tmpfiles', '--create', '/usr/lib/tmpfiles.d/ekubo-wallet-v2.conf')
        run('systemctl', 'daemon-reload')
        run('systemctl', 'reload', 'dbus.service')
        # Explicit reload completion makes policy installation deterministic;
        # only this disposable runner's Polkit daemon is restarted.
        run('systemctl', 'restart', 'polkit.service')
        helper = home / 'hold-owner.py'
        with helper.open('x') as output:
            created.append(helper)
            output.write(OWNER_LEASE)
            os.fchmod(output.fileno(), 0o644)
        with unmigrated_sentinel(migration):
            run_owner_checks(owner, uid, service_uid, home, migration)
        print('PASS: installed production custody, held lease, account/policy persistence, MCP reads, restart and owner file denial. Polkit consent was synthetic.')
    except BaseException:
        if (home / 'owner-session.log').exists():
            print((home / 'owner-session.log').read_text(), file=sys.stderr)
        if uid is not None:
            subprocess.run(['journalctl', '--no-pager', '-n', '100', '-u', f'ekubo-wallet-v2@{uid}.service',
                            '-u', f'ekubo-wallet-v2-provision@{uid}.service'], check=False)
        raise
    finally:
        cleanup(created, owner, uid, home, account_created, service_created)
        subprocess.run(['dpkg', '--remove', ACCEPTANCE_PACKAGE], check=False, timeout=120)


def check_runner_directory_guards():
    def info(mode, uid=0, gid=0):
        return os.stat_result((mode, 1, 1, 1, uid, gid, 0, 0, 0, 0))

    for path in RUNNER_SHARE_PATHS:
        assert runner_directory_mode(path, info(stat.S_IFDIR | 0o777)) == 0o755
        assert runner_directory_mode(path, info(stat.S_IFDIR | 0o755)) == 0o755
    invalid = [(Path('/usr'), info(stat.S_IFDIR | 0o777)),
               (Path('/usr/share/other'), info(stat.S_IFDIR | 0o777)),
               (Path('/usr/share'), info(stat.S_IFDIR | 0o775)),
               (Path('/usr/share'), info(stat.S_IFDIR | 0o1777)),
               (Path('/usr/share'), info(stat.S_IFDIR | 0o777, uid=1001)),
               (Path('/usr/share'), info(stat.S_IFDIR | 0o777, gid=1001)),
               (Path('/usr/share'), info(stat.S_IFLNK | 0o777))]
    for path, metadata in invalid:
        try:
            runner_directory_mode(path, metadata)
        except RuntimeError:
            continue
        raise AssertionError('Unexpected runner directory accepted for normalization')


def check_guards():
    check_runner_directory_guards()
    good = dict(GITHUB_ACTIONS='true', RUNNER_ENVIRONMENT='github-hosted', RUNNER_OS='Linux')
    require_runner(good, 0, 'linux', True)
    cases = [({}, 0, 'linux', True), (good, 1000, 'linux', True),
             (good, 0, 'darwin', True), (good, 0, 'linux', False),
             ({**good, 'RUNNER_ENVIRONMENT': 'self-hosted'}, 0, 'linux', True)]
    for args in cases:
        try:
            require_runner(*args)
        except RuntimeError:
            continue
        raise AssertionError('unsafe runner accepted')
    with tempfile.TemporaryDirectory(prefix='ewv2-guards-') as temp:
        path = Path(temp) / 'entry'
        absent([path])
        for kind in ['file', 'directory', 'dangling-symlink']:
            if kind == 'file':
                path.touch()
            elif kind == 'directory':
                path.mkdir()
            else:
                path.symlink_to(Path(temp) / 'missing')
            try:
                absent([path])
            except RuntimeError:
                pass
            else:
                raise AssertionError(f'pre-existing {kind} accepted')
            if kind == 'directory':
                path.rmdir()
            else:
                path.unlink()
    subprocess.run(['bash', '-n'], input=OWNER_SESSION, text=True, check=True)
    compile(OWNER_LEASE, 'hold-owner.py', 'exec')
    compile(FAULT_HANDSHAKE, 'acceptance-fault.py', 'exec')
    print('PASS: runner/explicit opt-in/root/platform and pre-existing path guards; owner shell/lease syntax')


def interrupted(signum, _frame):
    raise SystemExit(f'Acceptance interrupted by signal {signum}; cleaning fixture')


if __name__ == '__main__':
    if sys.argv[1:] == ['--check-guards']:
        check_guards()
    else:
        require_runner(os.environ, os.geteuid(), sys.platform,
                       len(sys.argv) == 3 and sys.argv[1] in ['--run-disposable', '--run-migration-disposable'])
        signal.signal(signal.SIGTERM, interrupted)
        acceptance(Path(sys.argv[2]).resolve(), sys.argv[1] == '--run-migration-disposable')
