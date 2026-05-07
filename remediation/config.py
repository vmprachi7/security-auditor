"""
Central configuration for security-auditor.
Reads from environment variables / .env file.
"""
import os
from dotenv import load_dotenv

load_dotenv()

# ── Azure ─────────────────────────────────────────────────────
AZURE_SUBSCRIPTION_ID = os.getenv("AZURE_SUBSCRIPTION_ID", "")
AZURE_TENANT_ID       = os.getenv("AZURE_TENANT_ID", "")
AZURE_CLIENT_ID       = os.getenv("AZURE_CLIENT_ID", "")
AZURE_CLIENT_SECRET   = os.getenv("AZURE_CLIENT_SECRET", "")

# ── AI ────────────────────────────────────────────────────────
GROQ_API_KEY  = os.getenv("GROQ_API_KEY", "")
AI_MODEL      = "llama-3.1-8b-instant"
AI_MAX_TOKENS = 2048

# ── GitHub ────────────────────────────────────────────────────
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")
GITHUB_REPO  = os.getenv("GITHUB_REPO", "vmprachi7/security-auditor")

# ── Scanner behaviour ─────────────────────────────────────────
# How many days of Azure Monitor logs to check for dependency analysis
DEPENDENCY_LOOKBACK_DAYS = int(os.getenv("DEPENDENCY_LOOKBACK_DAYS", "30"))

# Risk thresholds
RISK_LOW    = "LOW"
RISK_MEDIUM = "MEDIUM"
RISK_HIGH   = "HIGH"

# Use mock data for local testing (no Azure credentials needed)
USE_MOCK_DATA = os.getenv("USE_MOCK_DATA", "false").lower() == "true"


def validate() -> list[str]:
    """Returns list of missing required config values."""
    if USE_MOCK_DATA:
        missing = []
        if not GITHUB_TOKEN:
            missing.append("GITHUB_TOKEN")
        if not GROQ_API_KEY:
            missing.append("GROQ_API_KEY")
        return missing

    missing = []
    for var in [
        "AZURE_SUBSCRIPTION_ID", "AZURE_TENANT_ID",
        "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET",
        "GROQ_API_KEY", "GITHUB_TOKEN"
    ]:
        if not os.getenv(var):
            missing.append(var)
    return missing


def get_credential():
    """Returns Azure credential object."""
    from azure.identity import ClientSecretCredential
    return ClientSecretCredential(
        tenant_id=AZURE_TENANT_ID,
        client_id=AZURE_CLIENT_ID,
        client_secret=AZURE_CLIENT_SECRET,
    )