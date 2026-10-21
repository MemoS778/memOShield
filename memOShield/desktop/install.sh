#!/bin/sh
set -eu
base=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
dest="${XDG_DATA_HOME:-$HOME/.local/share}/memoshield"
mkdir -p "$dest/app" "$dest/gnome" "$HOME/.local/bin" "${XDG_DATA_HOME:-$HOME/.local/share}/applications"
install -m 0644 "$base/app/main.js" "$base/app/style.css" "$dest/app/"
install -m 0644 "$base/gnome/client.js" "$dest/gnome/"
printf '#!/bin/sh\nexec gjs -m "%s/app/main.js" "$@"\n' "$dest" > "$HOME/.local/bin/memoshield-desktop"
chmod 0755 "$HOME/.local/bin/memoshield-desktop"
cat > "${XDG_DATA_HOME:-$HOME/.local/share}/applications/io.github.MemoS778.memOShield.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=memOShield
Comment=Yerel güvenlik kontrol merkezi
Exec="$HOME/.local/bin/memoshield-desktop"
Icon=security-high-symbolic
Terminal=false
Categories=System;Security;
StartupNotify=true
EOF
