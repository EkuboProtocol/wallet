#!/bin/bash
# Real pacman lifecycle and ELF loading, confined to the dedicated CI container.
set -euxo pipefail
[[ ${WALLET_ARCH_DISPOSABLE_CI:-} = 1 && $EUID = 0 && -e /.dockerenv ]]
[[ $(cat /proc/1/comm) = systemd ]]
[[ ! -e /etc/ekubo-wallet-v2 && ! -e /var/lib/ekubo-wallet-v2 ]]
packages=(/packages/ekubo-wallet-v2-*.pkg.tar.zst)
[[ ${#packages[@]} = 1 ]]
systemctl start dbus-broker.service polkit.service
pacman -U --noconfirm "${packages[0]}"
pacman -Qkk ekubo-wallet-v2
for binary in /usr/bin/ekubo-wallet-v2 /usr/bin/ekubo-wallet-v2-mcp-bridge \
    /usr/lib/ekubo-wallet-v2/ekubo-wallet-service /usr/lib/ekubo-wallet-v2/ekubo-wallet-v2-enroll; do
    [[ $(stat -c '%u:%g:%a' "$binary") = 0:0:755 ]]
    dependencies=$(ldd "$binary")
    printf '%s\n' "$dependencies"
    if [[ "$dependencies" = *'not found'* ]]; then exit 1; fi
done
# The desktop intentionally has no CLI, including --version. Exercise its ELF
# loader without opening a display, and require the actual argument refusal.
status=0
desktop_output=$(ekubo-wallet-v2 --version 2>&1) || status=$?
[[ $status = 2 && "$desktop_output" = 'Ekubo Wallet does not accept command-line operations.' ]]
python3 /checks/verify-mcp-bridge.py /usr/bin/ekubo-wallet-v2-mcp-bridge "$BUILD_VERSION"
systemd-analyze verify /usr/lib/systemd/system/ekubo-wallet-v2@.service \
    /usr/lib/systemd/system/ekubo-wallet-v2-provision@.service
getent passwd ekubo-wallet-v2
[[ -f /usr/share/polkit-1/actions/com.ekubo.wallet.v2.policy ]]
[[ -f /usr/share/dbus-1/system.d/org.ekubo.Wallet2.Owner.conf ]]
# Protected public identity is enough to exercise reinstall activation repair;
# this synthetic profile contains no wallet, key, or owner authorization.
service_uid=$(id -u ekubo-wallet-v2)
printf '{"owner_uid":1000,"service_uid":%s,"profile_id":"3ef47d8d-5b40-4928-9b02-563326084bab"}\n' \
    "$service_uid" > /etc/ekubo-wallet-v2/owners/1000.json
chmod 644 /etc/ekubo-wallet-v2/owners/1000.json
pacman -U --noconfirm "${packages[0]}"
activation=/usr/share/dbus-1/system-services/org.ekubo.Wallet2.Owner.u1000.service
[[ $(stat -c '%u:%g:%a' "$activation") = 0:0:644 ]]
grep -Fx 'SystemdService=ekubo-wallet-v2@1000.service' "$activation"
! systemctl is-active --quiet ekubo-wallet-v2@1000.service
pacman -R --noconfirm ekubo-wallet-v2
[[ ! -e /usr/bin/ekubo-wallet-v2 ]]
[[ -f /etc/ekubo-wallet-v2/owners/1000.json && -f "$activation" ]]
printf '%s\n' 'Arch package install/reinstall/remove, ELF loading, and activation repair passed.'
