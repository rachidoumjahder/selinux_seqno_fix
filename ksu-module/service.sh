#!/system/bin/sh

MODDIR="${0%/*}"
KO="$MODDIR/selinux_seqno_fix.ko"
MODULE_DIR="/sys/module/selinux_seqno_fix"
LOG="$MODDIR/load.log"

log_msg() {
  echo "$(date '+%Y-%m-%d %H:%M:%S') $*" >> "$LOG"
}

: > "$LOG"
log_msg "kernel=$(uname -r)"

if [ -d "$MODULE_DIR" ]; then
  log_msg "module already loaded"
  exit 0
fi

if [ ! -r "$KO" ]; then
  log_msg "missing ko: $KO"
  exit 1
fi

if insmod "$KO" >> "$LOG" 2>&1; then
  log_msg "insmod ok"
  dmesg | grep selinux_seqno_fix | tail -n 10 >> "$LOG" 2>/dev/null
else
  rc=$?
  log_msg "insmod failed rc=$rc"
  dmesg | tail -n 40 >> "$LOG" 2>/dev/null
  exit "$rc"
fi
