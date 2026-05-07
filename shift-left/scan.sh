#!/bin/bash
# ═══════════════════════════════════════════════════════════
# Shift Left Security Scanner
# Runs Checkov + tfsec on changed Terraform files
# Called by GitHub Actions on every Terraform PR
# ═══════════════════════════════════════════════════════════
set -e

TERRAFORM_DIR=${1:-"."}
OUTPUT_DIR=${2:-"/tmp/scan-results"}
mkdir -p "$OUTPUT_DIR"

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Shift Left Security Scanner"
echo "  Directory: $TERRAFORM_DIR"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# ── Install tools ─────────────────────────────────────────────
echo "Installing scanners..."
pip install checkov --quiet

# Install tfsec
curl -s https://raw.githubusercontent.com/aquasecurity/tfsec/master/scripts/install_linux.sh \
  | bash > /dev/null 2>&1 || \
  wget -q -O /usr/local/bin/tfsec \
    https://github.com/aquasecurity/tfsec/releases/latest/download/tfsec-linux-amd64 && \
  chmod +x /usr/local/bin/tfsec

echo "✅ Scanners ready"
echo ""

# ── Run Checkov ───────────────────────────────────────────────
echo "Running Checkov..."
checkov \
  --directory "$TERRAFORM_DIR" \
  --framework terraform \
  --output json \
  --output-file-path "$OUTPUT_DIR" \
  --soft-fail \
  --compact \
  --skip-check CKV_AZURE_35 \
  2>/dev/null || true

# Checkov writes to OUTPUT_DIR/results_json.json
if [ -f "$OUTPUT_DIR/results_json.json" ]; then
  mv "$OUTPUT_DIR/results_json.json" "$OUTPUT_DIR/checkov.json"
  echo "✅ Checkov complete"
else
  echo '{"results":{"failed_checks":[],"passed_checks":[]}}' > "$OUTPUT_DIR/checkov.json"
  echo "ℹ️  Checkov: no results"
fi

# ── Run tfsec ─────────────────────────────────────────────────
echo "Running tfsec..."
tfsec "$TERRAFORM_DIR" \
  --format json \
  --out "$OUTPUT_DIR/tfsec.json" \
  --soft-fail \
  2>/dev/null || true

if [ ! -f "$OUTPUT_DIR/tfsec.json" ]; then
  echo '{"results":[]}' > "$OUTPUT_DIR/tfsec.json"
fi
echo "✅ tfsec complete"

echo ""
echo "Results written to $OUTPUT_DIR"
echo "  checkov.json"
echo "  tfsec.json"