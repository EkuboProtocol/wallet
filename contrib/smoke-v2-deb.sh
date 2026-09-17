#!/bin/bash
# Actual package-manager lifecycle; enrollment/native authorization is a separate gate.
set -euo pipefail
[[ "${GITHUB_ACTIONS:-}" = true && "${RUNNER_OS:-}" = Linux && $EUID = 0 ]]
deb="$(realpath "$1")"
test "$(dpkg-deb -f "$deb" Package)" = ekubo-wallet-v2
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
snapshot() {
    for path in /usr/bin/ekubo-wallet /usr/bin/ekubo-wallet-mcp-bridge /etc/ekubo-wallet /var/lib/ekubo-wallet /usr/share/polkit-1/actions/com.ekubo.wallet.policy; do
        if [ -e "$path" ]; then
            find "$path" -type f -exec sha256sum {} +
        fi
    done | sort
}
snapshot > "$work/legacy-before"
apt-get install -y "$deb"
test -x /usr/bin/ekubo-wallet-v2
test -x /usr/bin/ekubo-wallet-v2-mcp-bridge
for binary in ekubo-wallet-service ekubo-wallet-v2-enroll install-profile; do
    test "$(stat -c '%u:%g:%a' "/usr/lib/ekubo-wallet-v2/$binary")" = 0:0:755
done
systemd-analyze verify /usr/lib/systemd/system/ekubo-wallet-v2@.service /usr/lib/systemd/system/ekubo-wallet-v2-provision@.service
test -f /usr/share/dbus-1/system.d/org.ekubo.Wallet2.Owner.conf
test -f /usr/share/dbus-1/system.d/org.ekubo.Wallet2.Provision.conf
test -f /usr/share/polkit-1/actions/com.ekubo.wallet.v2.policy
getent passwd ekubo-wallet-v2
# Reinstall must not initialize a profile or relay.
dpkg -i "$deb"
dpkg -r ekubo-wallet-v2
test ! -e /usr/bin/ekubo-wallet-v2
snapshot > "$work/legacy-after"
diff -u "$work/legacy-before" "$work/legacy-after"
printf '%s\n' 'Actual DEB install/reinstall/remove passed; owner enrollment and populated-profile upgrades still require acceptance.'
