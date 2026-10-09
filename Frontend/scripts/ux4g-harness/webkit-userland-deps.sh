#!/usr/bin/env bash
# webkit-userland-deps.sh — make Playwright's WebKit launch on a host where you cannot
# `sudo npx playwright install-deps` (Ubuntu 24.04).
#
#   Frontend/scripts/ux4g-harness/webkit-userland-deps.sh
#   PLAYWRIGHT_SKIP_VALIDATE_HOST_REQUIREMENTS=1 npm run test:browser
#
# The supported method is `sudo npx playwright install-deps` (or the `apt-get install`
# line Playwright prints). Use this only where that is not possible. It needs no root:
# it downloads the missing .deb files with `apt-get download`, unpacks them with
# `dpkg -x`, and copies the libraries into the WebKit bundle's own `sys/lib`
# directory, which the bundle's launcher puts on LD_LIBRARY_PATH. Nothing outside
# ~/.cache is touched, and nothing is installed system-wide.
#
# Why PLAYWRIGHT_SKIP_VALIDATE_HOST_REQUIREMENTS=1 is still needed: Playwright's
# pre-flight check looks for libx264.so in the *system* ldconfig cache, which only a
# system install can satisfy; the library is used for H.264 media playback only. The
# check is skipped, not the tests: the browser must still launch and render for any
# test to pass.
#
# Undo: delete ~/.cache/ccure-webkit-libs and the files it copied (listed in
# ~/.cache/ccure-webkit-libs/copied.txt).
set -euo pipefail

PKGS=(libevent-2.1-7t64 libgstreamer-plugins-bad1.0-0 libflite1 libavif16 gstreamer1.0-libav
  libdav1d7 libgav1-1 librav1e0 libsvtav1enc1d1 libyuv0 libx264-164)
BASE="$HOME/.cache/ccure-webkit-libs"
WK="$(ls -d "$HOME"/.cache/ms-playwright/webkit-*/ 2>/dev/null | tail -1)"
[[ -n "$WK" ]] || { echo "no Playwright WebKit in ~/.cache/ms-playwright; run: npx playwright install webkit" >&2; exit 1; }
SYS="$WK/minibrowser-wpe/sys/lib"
[[ -d "$SYS" ]] || { echo "unexpected WebKit bundle layout: $SYS missing" >&2; exit 1; }

mkdir -p "$BASE/debs" "$BASE/root"
(cd "$BASE/debs" && apt-get download "${PKGS[@]}")
for deb in "$BASE"/debs/*.deb; do dpkg -x "$deb" "$BASE/root"; done
LIB="$BASE/root/usr/lib/x86_64-linux-gnu"
ln -sf libx264.so.164 "$LIB/libx264.so"
: > "$BASE/copied.txt"
for f in "$LIB"/*.so*; do
  [[ -e "$SYS/$(basename "$f")" ]] || { cp -a "$f" "$SYS/"; basename "$f" >> "$BASE/copied.txt"; }
done
echo "copied $(wc -l < "$BASE/copied.txt") libraries into $SYS"
