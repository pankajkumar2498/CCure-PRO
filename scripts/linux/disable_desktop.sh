#!/usr/bin/env bash
# Boot this VM to a text console instead of the GNOME desktop.
#
# The desktop is not part of the deployment — every service runs in Docker and
# the VM is reached over SSH (VS Code Remote SSH, scp, the pgAdmin/DBeaver
# tunnel) — but Ubuntu's installer left GNOME, GDM and a TigerVNC server in
# place. Together they hold 1–2 GB of the VM's 15 GB and put a VNC listener on
# 0.0.0.0:5901, which nothing here needs.
#
# This keeps the packages and changes only what starts: reversible with one
# command, and a desktop can still be started by hand for a one-off.
#
#   sudo scripts/linux/disable_desktop.sh          # takes effect at next boot
#   sudo systemctl isolate multi-user.target      # …or stop the desktop now
#   sudo systemctl set-default graphical.target   # undo
#
# The VNC server on :5901 was started by hand inside the desktop session
# (`vncserver :1 -localhost no`), not by a unit, so it ends with the session.
# If it is running now:  vncserver -kill :1   (as the user who started it).

set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "run with sudo" >&2
    exit 1
fi

before="$(systemctl get-default)"
systemctl set-default multi-user.target
echo "default target: $before -> $(systemctl get-default)"

# GDM is what draws the login screen; without graphical.target it is not
# pulled in, but disabling it as well means an `apt upgrade` that re-enables
# the alias cannot bring the desktop back by surprise.
if systemctl list-unit-files gdm.service >/dev/null 2>&1; then
    systemctl disable gdm.service 2>/dev/null || true
    echo "gdm.service: $(systemctl is-enabled gdm.service 2>/dev/null || echo not-installed)"
fi

echo
echo "The desktop stops at the next reboot. To stop it now (ends any GNOME or"
echo "VNC session; SSH and Docker are unaffected):"
echo "    sudo systemctl isolate multi-user.target"
echo
echo "── Firewall as it stands (for the record) ──"
ufw status verbose 2>/dev/null || echo "ufw not installed"
