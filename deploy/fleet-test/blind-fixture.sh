fixture=acceptance-queue
mkdir -p "$tmp/deb/DEBIAN" "$tmp/deb/lib/systemd/system"
cat > "$tmp/deb/DEBIAN/control" <<CONTROL
Package: $fixture
Version: 1
Architecture: all
Maintainer: Fleet acceptance <fleet@localhost>
Description: Disposable queue worker fixture
CONTROL
cat > "$tmp/deb/lib/systemd/system/$fixture.service" <<'UNIT'
[Service]
Type=simple
ExecStart=/usr/bin/sleep infinity
UNIT
dpkg-deb --build "$tmp/deb" "$tmp/fixture.deb"
dpkg -i "$tmp/fixture.deb"
systemctl daemon-reload
systemctl start "$fixture.service"
