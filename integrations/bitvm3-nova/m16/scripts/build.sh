#!/bin/bash
# Builds the M16 host script (and through build.rs the guest ELF) in WSL, as guest A was built.
set -e
export PATH=/root/.sp1/bin:/root/.cargo/bin:/usr/local/bin:/usr/bin:/bin
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
mkdir -p /root/nb3/m16
rsync -a --delete --exclude target $REPO/m16/sp1/ /root/nb3/m16/sp1/
cd /root/nb3/m16/sp1/script
cargo build --release 2>&1 | grep -vE '^\s+(Compiling|Downloaded|Downloading)' | tail -8
/root/nb3/m16/sp1/script/target/release/m16-nova-spv-script elf /root/nb3/m16/m16.elf
