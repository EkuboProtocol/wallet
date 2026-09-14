FROM archlinux:base
ARG BUILD_UID=1001
RUN pacman -Syu --noconfirm --needed base-devel python zstd \
    alsa-lib fontconfig glib2 libx11 libxcb libxkbcommon libxkbcommon-x11 \
    wayland openssl zlib xdotool libsecret dbus-broker-units polkit systemd \
    && useradd --uid "$BUILD_UID" --create-home builder \
    && systemctl enable dbus-broker.service
