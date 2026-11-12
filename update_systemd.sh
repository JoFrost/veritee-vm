#!/bin/bash 
set -e

# This version of systemd properly uses SOURCE_DATE_EPOCH when copying files, allowing reproducible builds to work...
apt-get build-dep --assume-yes --no-install-recommends systemd=257.9-1~deb13u1
apt-get install --assume-yes --no-install-recommends libfdisk-dev=2.41-5 libtss2-dev=4.1.3-1.2

SYSTEMD_COMMIT=147c30b613960bc24595435bd902a5c4beb5aba9
git init systemd
git -C systemd remote add origin https://github.com/systemd/systemd
git -C systemd fetch --depth=1 origin "$SYSTEMD_COMMIT"
git -C systemd checkout --detach FETCH_HEAD
test "$(git -C systemd rev-parse HEAD)" = "$SYSTEMD_COMMIT"
meson setup systemd/build systemd \
  -D repart=true \
  -D efi=true \
  -D bootloader=true \
  -D ukify=true \
  -D firstboot=true \
  -D blkid=true \
  -D openssl=true \
  -D tpm2=true
BINARIES=(
  bootctl
  systemctl
  systemd-dissect
  systemd-firstboot
  systemd-measure
  systemd-nspawn
  systemd-repart
  ukify
)
ninja -C systemd/build ${BINARIES[@]}
for BINARY in "${BINARIES[@]}"; do
  ln -svf $PWD/systemd/build/$BINARY /usr/bin/$BINARY
  $BINARY --version
done