#!/system/bin/sh

MODDIR="${0%/*}"
KO="$MODDIR/selinux_status_repair.ko"
MODULE_DIR="/sys/module/selinux_status_repair"
LOG="$MODDIR/load.log"

log_msg() {
  echo "$(date '+%Y-%m-%d %H:%M:%S') $*" >> "$LOG"
}

ensure_enforcing() {
  if [ -r /sys/fs/selinux/enforce ] && [ "$(cat /sys/fs/selinux/enforce)" != "1" ]; then
    if echo 1 > /sys/fs/selinux/enforce 2>/dev/null; then
      log_msg "SELinux enforcing enabled"
    else
      log_msg "failed to enable SELinux enforcing"
    fi
  fi
}

: > "$LOG"
log_msg "kernel=$(uname -r)"

if [ -d "$MODULE_DIR" ]; then
  log_msg "module already loaded"
  ensure_enforcing
  exit 0
fi

if [ ! -r "$KO" ]; then
  log_msg "missing ko: $KO"
  exit 1
fi

if insmod "$KO" >> "$LOG" 2>&1; then
  log_msg "insmod ok"
  ensure_enforcing
  dmesg | grep selinux_status_repair | tail -n 10 >> "$LOG" 2>/dev/null
else
  rc=$?
  log_msg "insmod failed rc=$rc"
  dmesg | tail -n 40 >> "$LOG" 2>/dev/null
  exit "$rc"
fi
