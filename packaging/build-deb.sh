#!/usr/bin/env bash
# Build the gsa4linux .deb. Usage: packaging/build-deb.sh [version]
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION="${1:-0.1.0}"
ARCH="$(dpkg --print-architecture)"
PKG="gsa4linux_${VERSION}_${ARCH}"
ROOT="dist/${PKG}"

echo "== publishing (framework-dependent) =="
rm -rf publish
for p in Daemon Agent Tray; do
    dotnet publish "src/Gsa4Linux.${p}/Gsa4Linux.${p}.csproj" -c Release -o publish --nologo -v q
done

echo "== assembling package tree =="
rm -rf "dist"
install -d "${ROOT}/DEBIAN" \
          "${ROOT}/opt/gsa4linux-dotnet" \
          "${ROOT}/etc/systemd/system" \
          "${ROOT}/usr/lib/systemd/user" \
          "${ROOT}/usr/bin"

cp -r publish/* "${ROOT}/opt/gsa4linux-dotnet/"
chmod +x "${ROOT}/opt/gsa4linux-dotnet/gsa4linuxd" \
         "${ROOT}/opt/gsa4linux-dotnet/gsa4linux-agent" \
         "${ROOT}/opt/gsa4linux-dotnet/gsa4linux-tray"
install -m0644 systemd/gsa4linuxd.service      "${ROOT}/etc/systemd/system/"
install -m0644 systemd/gsa4linux-agent.service "${ROOT}/usr/lib/systemd/user/"
install -m0644 systemd/gsa4linux-tray.service  "${ROOT}/usr/lib/systemd/user/"
install -m0755 scripts/ila-status              "${ROOT}/usr/bin/gsa4linux-ila-status"
install -m0755 scripts/gsa4linux-set-user      "${ROOT}/usr/bin/gsa4linux-set-user"

echo "== control + maintainer scripts =="
SIZE="$(du -sk "${ROOT}" | cut -f1)"
sed -e "s/@VERSION@/${VERSION}/" -e "s/@ARCH@/${ARCH}/" -e "s/@SIZE@/${SIZE}/" \
    packaging/debian/control > "${ROOT}/DEBIAN/control"
install -m0755 packaging/debian/postinst packaging/debian/prerm packaging/debian/postrm "${ROOT}/DEBIAN/"

echo "== building =="
dpkg-deb --root-owner-group --build "${ROOT}" "dist/${PKG}.deb" >/dev/null
echo "built dist/${PKG}.deb"
dpkg-deb --info "dist/${PKG}.deb" | sed -n '/Package:/,/Description:/p'
