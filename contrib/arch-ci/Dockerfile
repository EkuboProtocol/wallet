# Pinned 2026-09-14 (archlinux-docker rev c5dc9bf314fc3e93e3e4a62fff9da1d24374c777);
# repin deliberately with `docker buildx imagetools inspect archlinux:base`.
FROM archlinux:base@sha256:204e91950fd364961088a01773eee9012243b7e965fed42b1d82d12416190782
ARG BUILD_UID=1001
RUN sed -i '/^NoExtract[[:space:]]*=/d' /etc/pacman.conf \
    && pacman -Syu --noconfirm --needed base-devel python zstd \
    alsa-lib fontconfig glib2 libx11 libxcb libxkbcommon libxkbcommon-x11 \
    wayland openssl zlib xdotool libsecret dbus-broker-units polkit systemd python-dbus python-gobject \
    && useradd --uid "$BUILD_UID" --create-home builder \
    && systemctl enable dbus-broker.service
