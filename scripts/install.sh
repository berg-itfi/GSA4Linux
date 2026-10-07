#!/usr/bin/env bash
# Manual installer (non-.deb). Run as root from the repo root: sudo scripts/install.sh
# Prefer the .deb (packaging/build-deb.sh) when you can; this is the from-source path.
set -euo pipefail
cd "$(dirname "$0")/.."
[ "$(id -u)" -eq 0 ] || { echo "run as root (sudo scripts/install.sh)"; exit 1; }

PREFIX=/opt/gsa4linux-dotnet

echo "== publishing =="
rm -rf publish
for p in Daemon Agent Tray; do
    dotnet publish "src/Gsa4Linux.$p/Gsa4Linux.$p.csproj" -c Release -o publish --nologo
done

echo "== service user =="
id gsa4linux >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin gsa4linux

echo "== files =="
mkdir -p "$PREFIX"
cp -r publish/* "$PREFIX/"
chmod +x "$PREFIX/gsa4linuxd" "$PREFIX/gsa4linux-agent" "$PREFIX/gsa4linux-tray"
install -m0644 systemd/gsa4linuxd.service /etc/systemd/system/
install -d /usr/lib/systemd/user
install -m0644 systemd/gsa4linux-agent.service systemd/gsa4linux-tray.service /usr/lib/systemd/user/
install -m0755 scripts/ila-status /usr/bin/gsa4linux-ila-status
install -m0755 scripts/gsa4linux-set-user /usr/bin/gsa4linux-set-user

echo "== lock sockets to the installing user =="
if [ -n "${SUDO_UID:-}" ] && printf '%s' "$SUDO_UID" | grep -qE '^[0-9]+$' && [ "$SUDO_UID" -ge 1000 ]; then
    mkdir -p /etc/systemd/system/gsa4linuxd.service.d
    printf '[Service]\nEnvironment=GSA4LINUX_UID=%s\n' "$SUDO_UID" \
        > /etc/systemd/system/gsa4linuxd.service.d/10-uid.conf
    echo "   locked to uid $SUDO_UID"
else
    echo "   could not detect your uid; run 'sudo gsa4linux-set-user <you>' afterwards"
fi

echo "== enable =="
systemctl daemon-reload
systemctl enable --now gsa4linuxd.service
systemctl --global enable gsa4linux-agent.service gsa4linux-tray.service
echo "done. Start your session services now with:"
echo "   systemctl --user start gsa4linux-agent.service gsa4linux-tray.service"
