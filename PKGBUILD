# Maintainer: NateDog <47695509+NModlin@users.noreply.github.com>
pkgname=madhatter-drop
pkgver=1.0.0
pkgrel=1
pkgdesc="P2P Delta Sync Tool with Wayland Tray Support"
arch=('any')
url="https://github.com/NModlin/madhatterDrop"
license=('MIT')
depends=('rsync' 'inotify-tools')
optdepends=('python-pyqt6: for system tray icon' 'libnotify: for desktop notifications')
makedepends=('git')
source=("git+${url}.git")
sha256sums=('SKIP')

package() {
    cd "$srcdir/madhatterDrop"

    # Install directories
    install -d "$pkgdir/usr/bin"
    install -d "$pkgdir/usr/share/madhatter"
    install -d "$pkgdir/usr/share/madhatter/icons"
    install -d "$pkgdir/usr/lib/systemd/user"
    install -d "$pkgdir/usr/share/applications"

    # Install Files
    install -m 755 sync_madhatter.sh "$pkgdir/usr/bin/madhatter-sync"
    
    # Install Python script and icons
    install -m 644 madhatter_tray.py "$pkgdir/usr/share/madhatter/madhatter_tray.py"
    install -m 644 icons/*.png "$pkgdir/usr/share/madhatter/icons/"
    
    # Install Service
    install -m 644 madhatter-sync.service "$pkgdir/usr/lib/systemd/user/"
    
    # Install Desktop Entry
    install -m 644 madhatter-tray.desktop "$pkgdir/usr/share/applications/"

    # Install License
    install -Dm 644 LICENSE "$pkgdir/usr/share/licenses/$pkgname/LICENSE"
    
    # Create wrapper for tray app
    echo '#!/bin/sh' > "$pkgdir/usr/bin/madhatter-tray"
    echo 'exec python3 /usr/share/madhatter/madhatter_tray.py "$@"' >> "$pkgdir/usr/bin/madhatter-tray"
    chmod 755 "$pkgdir/usr/bin/madhatter-tray"
}
