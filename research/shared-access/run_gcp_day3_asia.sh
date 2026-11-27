#!/usr/bin/env bash
# GCP Day 3 (asia-southeast1) timing-margin qualification runner + 3-day mix_qualification.py gate.
# Must be run on UTC day 2026-11-28 or later so Day 1 (2026-11-26), Day 2 (2026-11-27),
# and Day 3 (2026-11-28+) span three strictly distinct UTC calendar days.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
GCLOUD="${GCLOUD:-/home/debian/tools/wayqo-cloud/google-cloud-sdk/bin/gcloud}"
export CLOUDSDK_CONFIG="${CLOUDSDK_CONFIG:-/home/debian/.config/gcloud-wayqo}"
PROJECT="wayqo-testing-20261016"
ZONE="asia-southeast1-a"
VM="cpvpn-qual-261128-asia"
SEED="${SEED:-2026112801}"
TODAY_UTC="$(date -u +%Y-%m-%d)"

if [[ "$TODAY_UTC" < "2026-11-28" ]]; then
  echo "Refusing Day 3 run on $TODAY_UTC UTC: mix_qualification.py requires a 3rd distinct UTC calendar day (>= 2026-11-28)." >&2
  exit 1
fi

cleanup() {
  echo "=== Tearing down disposable $VM and restarting cypherpunk-build ==="
  "$GCLOUD" compute instances delete "$VM" --project="$PROJECT" --zone="$ZONE" --quiet 2>/dev/null || true
  "$GCLOUD" compute instances start cypherpunk-build --project="$PROJECT" --zone=europe-west4-a --quiet 2>/dev/null || true
}
trap cleanup EXIT

echo "=== 1. Stop cypherpunk-build to free vCPU quota ==="
"$GCLOUD" compute instances stop cypherpunk-build --project="$PROJECT" --zone=europe-west4-a --quiet || true

echo "=== 2. Create disposable Debian 13 VM $VM ($ZONE, IAP-only, no service account) ==="
"$GCLOUD" compute instances create "$VM" \
  --project="$PROJECT" --zone="$ZONE" \
  --machine-type=e2-standard-4 \
  --image-family=debian-13 --image-project=debian-cloud \
  --boot-disk-size=40GB \
  --tags=wayqo-test-ssh \
  --no-service-account --no-scopes

echo "=== 3. Wait for SSH via IAP ==="
for _ in $(seq 1 30); do
  if "$GCLOUD" compute ssh "$VM" --project="$PROJECT" --zone="$ZONE" --tunnel-through-iap --command="true" 2>/dev/null; then
    break
  fi
  sleep 5
done

echo "=== 4. Upload repo tarball + prebuilt Katzenpost binaries and run mix_lab timing-margin (seed $SEED, baseline 300s) ==="
TARBALL="/tmp/cpvpn-day3-src.tar.gz"
git -C "$ROOT" archive --format=tar.gz -o "$TARBALL" HEAD
"$GCLOUD" compute scp "$TARBALL" "$VM:/tmp/cpvpn-src.tar.gz" --project="$PROJECT" --zone="$ZONE" --tunnel-through-iap
rm -f "$TARBALL"
KP_BIN_LOCAL="${KP_BIN_LOCAL:-/home/debian/vm/advanced-vpn/katzenpost/bin}"
if [ -x "$KP_BIN_LOCAL/kpclientd" ]; then
  tar -C "$KP_BIN_LOCAL" -czf /tmp/kp-bin.tar.gz .
  "$GCLOUD" compute scp /tmp/kp-bin.tar.gz "$VM:/tmp/kp-bin.tar.gz" --project="$PROJECT" --zone="$ZONE" --tunnel-through-iap
  rm -f /tmp/kp-bin.tar.gz
fi

cat > /tmp/remote_run_asia.sh <<'RUNEOF'
#!/usr/bin/env bash
set -euo pipefail
SEED_ARG="$1"
trap 'rc=$?; echo "$rc" > /tmp/run_asia.rc; exit "$rc"' EXIT
sudo docker run --rm --privileged \
  -v /tmp/kp-bin:/kp/bin:ro \
  -v /tmp/repo/tools:/lab/tools:ro \
  -v /tmp/trial-asia:/out \
  cpvpn-mixlab:2 \
  python3 /lab/tools/mix_lab.py --bin /kp/bin --out /out --profile timing-margin --seed "$SEED_ARG" --baseline-seconds 300
python3 /tmp/repo/tools/mix_holdout.py /tmp/trial-asia --out /tmp/SHARED_ACCESS_GCP_ASIA_20261128.json --require-margin
sudo rm -rf /tmp/trial-asia /tmp/kp-bin /tmp/repo /tmp/cpvpn-src.tar.gz /tmp/kp-bin.tar.gz
RUNEOF
chmod +x /tmp/remote_run_asia.sh
"$GCLOUD" compute scp /tmp/remote_run_asia.sh "$VM:/tmp/remote_run_asia.sh" --project="$PROJECT" --zone="$ZONE" --tunnel-through-iap
rm -f /tmp/remote_run_asia.sh

"$GCLOUD" compute ssh "$VM" --project="$PROJECT" --zone="$ZONE" --tunnel-through-iap --command="
set -euo pipefail
sudo apt-get update -qq
sudo apt-get install -y -qq docker.io python3 iproute2 tcpdump ca-certificates >/dev/null
mkdir -p /tmp/repo /tmp/trial-asia /tmp/kp-bin
tar -xzf /tmp/cpvpn-src.tar.gz -C /tmp/repo
if [ -f /tmp/kp-bin.tar.gz ]; then
  tar -xzf /tmp/kp-bin.tar.gz -C /tmp/kp-bin
else
  cd /tmp/repo && bash third_party/katzenpost/build.sh /tmp/kp-bin
fi
cd /tmp/repo
sudo docker build -t cpvpn-mixlab:2 -f tools/mix_lab.Dockerfile tools
chmod +x /tmp/remote_run_asia.sh
rm -f /tmp/run_asia.rc /tmp/run_asia.log
nohup /tmp/remote_run_asia.sh $SEED > /tmp/run_asia.log 2>&1 < /dev/null &
echo Detached_PID=\$!
"

echo "=== 4b. Polling detached trial on $VM until complete ==="
for i in $(seq 1 80); do
  rc="$("$GCLOUD" compute ssh "$VM" --project="$PROJECT" --zone="$ZONE" --tunnel-through-iap --command="cat /tmp/run_asia.rc 2>/dev/null || echo PENDING" 2>/dev/null | tr -d '\r\n' || echo "SSH_RETRY")"
  if [ "$rc" = "0" ]; then
    echo "Detached Day 3 trial succeeded!"
    break
  elif [ "$rc" != "PENDING" ] && [ "$rc" != "SSH_RETRY" ]; then
    echo "Detached Day 3 trial FAILED with rc=$rc" >&2
    "$GCLOUD" compute ssh "$VM" --project="$PROJECT" --zone="$ZONE" --tunnel-through-iap --command="tail -n 60 /tmp/run_asia.log" || true
    exit 1
  fi
  if (( i % 4 == 0 )); then
    "$GCLOUD" compute ssh "$VM" --project="$PROJECT" --zone="$ZONE" --tunnel-through-iap --command="tail -n 5 /tmp/run_asia.log 2>/dev/null || true" 2>/dev/null || true
  fi
  sleep 45
done
rc_final="$("$GCLOUD" compute ssh "$VM" --project="$PROJECT" --zone="$ZONE" --tunnel-through-iap --command="cat /tmp/run_asia.rc 2>/dev/null || echo TIMEOUT" | tr -d '\r\n')"
if [ "$rc_final" != "0" ]; then
  echo "Day 3 trial did not succeed (status: $rc_final)" >&2
  exit 1
fi

"$GCLOUD" compute scp "$VM:/tmp/SHARED_ACCESS_GCP_ASIA_20261128.json" \
  "$ROOT/docs/evidence/SHARED_ACCESS_GCP_ASIA_20261128.json" \
  --project="$PROJECT" --zone="$ZONE" --tunnel-through-iap

echo "=== 5. Run 3-day mix_qualification.py ==="
cat > /tmp/gcp-3day-manifest.json <<EOF
[
  {"region": "us-central1", "report": "$ROOT/docs/evidence/SHARED_ACCESS_GCP_US_20261126.json"},
  {"region": "europe-west3", "report": "$ROOT/docs/evidence/SHARED_ACCESS_GCP_EU_20261127_R2.json"},
  {"region": "asia-southeast1", "report": "$ROOT/docs/evidence/SHARED_ACCESS_GCP_ASIA_20261128.json"}
]
EOF
"$ROOT/.venv/bin/python" "$ROOT/tools/mix_qualification.py" /tmp/gcp-3day-manifest.json \
  --out "$ROOT/docs/evidence/SHARED_ACCESS_GCP_QUALIFICATION_20261128.json"
rm -f /tmp/gcp-3day-manifest.json
echo "=== DAY 3 QUALIFICATION PASSED ==="
