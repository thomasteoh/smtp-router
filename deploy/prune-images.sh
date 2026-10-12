#!/usr/bin/env bash
# Weekly disk-space prune for the solo VM (runs as the deploy user).
# Frees space by removing dangling/unused container images and stale /tmp files.
# Safe: `podman image prune -a -f` never removes an image in use by a running
# container; /tmp files are removed only if older than 3 days.
set -uo pipefail

LOG=/home/deploy/.local/share/podman-prune/prune.log
mkdir -p "$(dirname "$LOG")"

before=$(du -s /home/deploy/.local/share/containers/storage 2>/dev/null | cut -f1)

# 1) Remove dangling/unused images (never in-use images).
podman image prune -a -f >>"$LOG" 2>&1

# 2) Clear stale /tmp files older than 3 days (skip the active test dirs).
find /tmp -mindepth 1 -maxdepth 1 -type f -mtime +3 -delete 2>/dev/null || true

after=$(du -s /home/deploy/.local/share/containers/storage 2>/dev/null | cut -f1)
freed=$((before - after))

# 3) Log + report disk state.
{
  echo "--- prune $(date -Is) ---"
  echo "storage before: ${before}K  after: ${after}K  freed: ${freed}K"
  df -h / | tail -1
} >>"$LOG" 2>&1

# 4) Alert to the Discord home channel if disk crosses 80%.
used=$(df -h / | awk 'NR==2 {print $5}' | tr -d '%')
if [ "$used" -ge 80 ]; then
  echo "solo.harmonicr.com: disk ${used}% used after prune (freed ${freed}K)" >&2
  exit 1
fi

exit 0
