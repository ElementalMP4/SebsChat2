#!/bin/bash

set -euo pipefail

APP_NAME="sebschat"
VERSION="1.0.0"
ARCH="amd64"
REPO_URL="https://github.com/ElementalMP4/SebsChat2.git"

TMP_BUILD_DIR="$(mktemp -d)"
PKG_ROOT="$TMP_BUILD_DIR/${APP_NAME}-${VERSION}"
DEB_FILE="${APP_NAME}_${VERSION}_${ARCH}.deb"

echo "📦 Creating build environment..."
mkdir -p "$PKG_ROOT/DEBIAN"
mkdir -p "$PKG_ROOT/opt/$APP_NAME"
mkdir -p "$PKG_ROOT/etc/systemd/system"

# Control file
cat > "$PKG_ROOT/DEBIAN/control" <<EOF
Package: $APP_NAME
Version: $VERSION
Section: base
Priority: optional
Architecture: $ARCH
Maintainer: Your Name <you@example.com>
Description: SebsChat server application
EOF

# Clone and build server
echo "📥 Cloning and building the app..."
git clone "$REPO_URL" "$TMP_BUILD_DIR/src"
pushd "$TMP_BUILD_DIR/src/server" >/dev/null
go build -o "$PKG_ROOT/opt/$APP_NAME/$APP_NAME"
popd >/dev/null

# Create systemd service file
cat > "$PKG_ROOT/etc/systemd/system/$APP_NAME.service" <<EOF
[Unit]
Description=SebsChat service
After=network.target

[Service]
Type=simple
User=$APP_NAME
Group=$APP_NAME
WorkingDirectory=/opt/$APP_NAME
ExecStart=/opt/$APP_NAME/$APP_NAME
EnvironmentFile=-/opt/$APP_NAME/.env
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# Post-installation
cat > "$PKG_ROOT/DEBIAN/postinst" <<'EOF'
#!/bin/bash
set -e

if ! id sebschat &>/dev/null; then
    useradd --system --no-create-home --shell /usr/sbin/nologin sebschat
fi

systemctl daemon-reload
systemctl enable sebschat.service
systemctl restart sebschat.service
EOF
chmod 755 "$PKG_ROOT/DEBIAN/postinst"

# Post-removal
cat > "$PKG_ROOT/DEBIAN/postrm" <<'EOF'
#!/bin/bash
set -e
systemctl stop sebschat.service || true
systemctl disable sebschat.service || true
systemctl daemon-reload
EOF
chmod 755 "$PKG_ROOT/DEBIAN/postrm"

# Build the .deb
echo "🛠️ Building .deb package..."
dpkg-deb --build "$PKG_ROOT" "$DEB_FILE"

echo "✅ Package built: ./$DEB_FILE"

# Cleanup
rm -rf "$TMP_BUILD_DIR"
