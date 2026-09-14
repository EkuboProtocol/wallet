#!/bin/bash
# Use the already-built release payload; Arch packaging does not rebuild Rust.
set -euo pipefail
[[ "${GITHUB_ACTIONS:-}" = true && "${RUNNER_ENVIRONMENT:-}" = github-hosted && "${RUNNER_OS:-}" = Linux ]]
root="$(git rev-parse --show-toplevel)"
name="wallet-arch-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}"
image="$name:local"
cleanup() {
    if [[ ${1:-0} != 0 ]]; then
        docker logs "$name" 2>&1 || true
        docker exec "$name" journalctl --no-pager -n 80 2>&1 || true
    fi
    docker rm -f "$name" >/dev/null 2>&1 || true
    docker image rm "$image" >/dev/null 2>&1 || true
}
trap 'cleanup "$?"' EXIT
docker build --build-arg "BUILD_UID=$(id -u)" -t "$image" "$root/contrib/arch-ci"
docker run --rm --user "$(id -u)" \
    -e "SOURCE_DATE_EPOCH=$(git log -1 --format=%ct)" \
    --mount "type=bind,src=$root,dst=/workspace,readonly" \
    --mount "type=bind,src=$root/target/release,dst=/workspace/target/release" \
    --workdir /workspace "$image" python3 contrib/build-v2-packages.py arch
# A disposable PID-1 systemd container gives pacman real systemd/D-Bus hooks.
# No host runtime, credentials, bus, home, or cgroup directory is bind-mounted.
docker run -d --name "$name" --privileged --cgroupns=private \
    --tmpfs /run --tmpfs /run/lock --stop-signal SIGRTMIN+3 \
    -e container=docker -e WALLET_ARCH_DISPOSABLE_CI=1 \
    --mount "type=bind,src=$root/target/release,dst=/packages,readonly" \
    --mount "type=bind,src=$root/contrib,dst=/checks,readonly" \
    "$image" /sbin/init
# Docker returns once PID 1 starts, before systemd has opened its control socket.
for attempt in {1..60}; do
    if docker exec "$name" test -S /run/systemd/private; then break; fi
    sleep 1
done
docker exec "$name" test -S /run/systemd/private
docker exec "$name" bash /checks/smoke-v2-arch.sh
docker exec --user "$(id -u)" "$name" python3 /checks/linux-service-policy_test.py -v
