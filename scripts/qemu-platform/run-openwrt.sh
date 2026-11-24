#!/bin/sh
set -eu
here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
root=${1:?Укажите экземпляр диска OpenWrt ext4 для записи}
kernel=${2:?Укажите ядро OpenWrt}
opt=${3:?Укажите рабочий opt-диск}
logs=${4:?Укажите каталог журналов}
mkdir -p "$logs"
"${DEBUGFS:-debugfs}" -w -R "write $here/openwrt-init /etc/init.d/r2o-lab" "$root"
"${DEBUGFS:-debugfs}" -w -R 'symlink /etc/rc.d/S98r2o-lab ../init.d/r2o-lab' "$root"
for phase in FIRST SECOND; do
    timeout 900 "${QEMU_X86:-qemu-system-x86_64}" -nodefaults -nographic -serial stdio \
        -monitor none -L "${QEMU_DATA_DIR:-/usr/share/qemu}" \
        -bios "${QEMU_X86_BIOS:-/usr/share/seabios/bios-256k.bin}" -m 256 -smp 2 \
        -kernel "$kernel" -drive "file=$root,format=raw,if=ide" \
        -drive "file=$opt,format=raw,if=ide" -nic none -no-reboot \
        -append 'root=/dev/sda console=ttyS0 rw loglevel=4' >"$logs/OpenWrt-$phase.log" 2>&1
    grep -q "OPENWRT_${phase}_BOOT_PASS" "$logs/OpenWrt-$phase.log"
    grep -q 'OPENWRT_ACCEPTANCE_EXIT=0' "$logs/OpenWrt-$phase.log"
done
