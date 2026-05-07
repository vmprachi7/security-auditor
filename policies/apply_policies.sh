#!/bin/bash
# ═══════════════════════════════════════════════════════════
# Apply Azure Policy definitions to subscription
# Run once after repo setup
# ═══════════════════════════════════════════════════════════
set -e

SUBSCRIPTION_ID=${ARM_SUBSCRIPTION_ID:-$(az account show --query id -o tsv)}
SCOPE="/subscriptions/$SUBSCRIPTION_ID"

echo "Applying Azure Policies to: $SCOPE"
echo ""

# ── Policy 1: Deny storage with public access ─────────────
echo "1. Deny storage accounts with public blob access..."
POLICY_ID=$(az policy definition create \
  --name "deny-storage-public-access" \
  --display-name "Deny storage accounts with public blob access" \
  --description "Blocks storage accounts that allow public blob access" \
  --rules policies/deny_storage_public_access.json \
  --mode All \
  --query id -o tsv)

az policy assignment create \
  --name "deny-storage-public-access" \
  --display-name "Deny storage accounts with public blob access" \
  --policy "$POLICY_ID" \
  --scope "$SCOPE" \
  --output none

echo "   ✅ Applied"

# ── Policy 2: Require owner tag ───────────────────────────
echo "2. Require owner tag on resource groups (Audit mode)..."
POLICY_ID=$(az policy definition create \
  --name "require-owner-tag" \
  --display-name "Require owner tag on resource groups" \
  --description "Resource groups must have an owner tag" \
  --rules policies/require_resource_tags.json \
  --params '{"effect":{"type":"String","defaultValue":"Audit"}}' \
  --mode All \
  --query id -o tsv)

az policy assignment create \
  --name "require-owner-tag" \
  --display-name "Require owner tag on resource groups" \
  --policy "$POLICY_ID" \
  --scope "$SCOPE" \
  --params '{"effect":{"value":"Audit"}}' \
  --output none

echo "   ✅ Applied (Audit mode — logs violations, does not block)"

# ── Verify ────────────────────────────────────────────────
echo ""
echo "Verifying policy assignments..."
az policy assignment list \
  --scope "$SCOPE" \
  --query "[].{Name:name, DisplayName:displayName}" \
  --output table

echo ""
echo "✅ Policies applied"
echo ""
echo "Note: Policies take 5-30 minutes to evaluate existing resources."
echo "Check compliance at:"
echo "  portal.azure.com → Policy → Compliance"