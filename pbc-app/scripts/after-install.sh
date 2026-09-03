#!/bin/bash
# postinst du .deb PBC
# 1. Le sandbox Chromium d'Electron exige SUID root.
chown root:root /opt/PBC/chrome-sandbox
chmod 4755 /opt/PBC/chrome-sandbox
# 2. Rafraîchir les bases bureau pour que le raccourci PBC apparaisse
#    immédiatement dans le menu (sans reconnexion).
update-desktop-database /usr/share/applications 2>/dev/null || true
gtk-update-icon-cache -f -t /usr/share/icons/hicolor 2>/dev/null || true
xdg-desktop-menu forceupdate 2>/dev/null || true
exit 0
