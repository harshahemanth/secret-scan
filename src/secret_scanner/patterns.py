# src/secret_scanner/patterns.py

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class SecretPattern:
    """A single secret detection rule."""
    rule_id: str
    name: str
    severity: str        # "error", "warning", "note"
    pattern: str         # raw regex string
    description: str
    case_insensitive: bool = False


# Pattern registry — ordered from most specific to most generic.
# This ordering matters for span-based deduplication: when two rules
# match the same text span, the first (more specific) rule wins.
PATTERNS: list[SecretPattern] = [
    # ── AWS ──────────────────────────────────────────────────────────
    SecretPattern(
        rule_id="aws-access-key-assignment",
        name="AWS Access Key Assignment",
        severity="error",
        pattern=r'(?:AWS|aws)_?(?:ACCESS_KEY_ID|ACCESS_KEY|ACCESSKEY)\s*[:=]\s*["\']?(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[0-9A-Z]{16}["\']?',
        description="AWS access key ID assigned to a variable or config key.",
    ),
    SecretPattern(
        rule_id="aws-access-key-id",
        name="AWS Access Key ID",
        severity="error",
        pattern=r'(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[0-9A-Z]{16}',
        description="AWS access key IDs start with AKIA, ASIA, etc. followed by 16 uppercase alphanumeric characters.",
    ),
    SecretPattern(
        rule_id="aws-secret-access-key",
        name="AWS Secret Access Key",
        severity="error",
        pattern=r'(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[:=]\s*["\']?[A-Za-z0-9/+=]{40}["\']?',
        description="AWS secret access key (40-character base64 string).",
    ),
    SecretPattern(
        rule_id="aws-generic-key",
        name="AWS Generic Key",
        severity="warning",
        pattern=r'aws_?(?:secret|access)?_?key\s*[:=]\s*["\']?[A-Za-z0-9/+=]{16,}["\']?',
        description="Generic AWS key assignment.",
        case_insensitive=True,
    ),

    # ── GitHub ───────────────────────────────────────────────────────
    SecretPattern(
        rule_id="github-personal-access-token",
        name="GitHub Personal Access Token",
        severity="error",
        pattern=r'ghp_[A-Za-z0-9]{36}',
        description="GitHub personal access token (classic).",
    ),
    SecretPattern(
        rule_id="github-oauth-token",
        name="GitHub OAuth Token",
        severity="error",
        pattern=r'gho_[A-Za-z0-9]{36}',
        description="GitHub OAuth access token.",
    ),
    SecretPattern(
        rule_id="github-app-token",
        name="GitHub App Token",
        severity="error",
        pattern=r'ghs_[A-Za-z0-9]{36}',
        description="GitHub App installation access token.",
    ),
    SecretPattern(
        rule_id="github-refresh-token",
        name="GitHub Refresh Token",
        severity="error",
        pattern=r'ghr_[A-Za-z0-9]{36}',
        description="GitHub refresh token.",
    ),
    SecretPattern(
        rule_id="github-fine-grained-pat",
        name="GitHub Fine-Grained PAT",
        severity="error",
        pattern=r'github_pat_[A-Za-z0-9_]{22,}',
        description="GitHub fine-grained personal access token.",
    ),

    # ── Slack ────────────────────────────────────────────────────────
    SecretPattern(
        rule_id="slack-bot-token",
        name="Slack Bot Token",
        severity="error",
        pattern=r'xoxb-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24}',
        description="Slack bot user OAuth token.",
    ),
    SecretPattern(
        rule_id="slack-user-token",
        name="Slack User Token",
        severity="error",
        pattern=r'xoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[a-f0-9]{32}',
        description="Slack user OAuth token.",
    ),

    # ── Stripe (specific before generic sk-) ─────────────────────────
    SecretPattern(
        rule_id="stripe-secret-key-live",
        name="Stripe Live Secret Key",
        severity="error",
        pattern=r'sk_live_[A-Za-z0-9]{24,}',
        description="Stripe live secret API key.",
    ),
    SecretPattern(
        rule_id="stripe-publishable-key-live",
        name="Stripe Live Publishable Key",
        severity="warning",
        pattern=r'pk_live_[A-Za-z0-9]{24,}',
        description="Stripe live publishable API key.",
    ),
    SecretPattern(
        rule_id="stripe-restricted-key-live",
        name="Stripe Live Restricted Key",
        severity="error",
        pattern=r'rk_live_[A-Za-z0-9]{24,}',
        description="Stripe live restricted API key.",
    ),
    SecretPattern(
        rule_id="stripe-secret-key-test",
        name="Stripe Test Secret Key",
        severity="note",
        pattern=r'sk_test_[A-Za-z0-9]{24,}',
        description="Stripe test secret API key.",
    ),
    SecretPattern(
        rule_id="stripe-publishable-key-test",
        name="Stripe Test Publishable Key",
        severity="note",
        pattern=r'pk_test_[A-Za-z0-9]{24,}',
        description="Stripe test publishable API key.",
    ),
    SecretPattern(
        rule_id="stripe-restricted-key-test",
        name="Stripe Test Restricted Key",
        severity="note",
        pattern=r'rk_test_[A-Za-z0-9]{24,}',
        description="Stripe test restricted API key.",
    ),

    # ── Google ───────────────────────────────────────────────────────
    SecretPattern(
        rule_id="google-api-key",
        name="Google API Key",
        severity="error",
        pattern=r'AIza[A-Za-z0-9_-]{35}',
        description="Google API key starting with AIza.",
    ),

    # ── npm / PyPI ───────────────────────────────────────────────────
    SecretPattern(
        rule_id="npm-access-token",
        name="npm Access Token",
        severity="error",
        pattern=r'npm_[A-Za-z0-9]{36}',
        description="npm access token.",
    ),
    SecretPattern(
        rule_id="pypi-api-token",
        name="PyPI API Token",
        severity="error",
        pattern=r'pypi-[A-Za-z0-9_-]{50,}',
        description="PyPI API token.",
    ),

    # ── Twilio ───────────────────────────────────────────────────────
    SecretPattern(
        rule_id="twilio-api-key",
        name="Twilio API Key",
        severity="error",
        pattern=r'SK[0-9a-fA-F]{32}',
        description="Twilio API key (SK + 32 hex characters).",
    ),

    # ── SendGrid ─────────────────────────────────────────────────────
    SecretPattern(
        rule_id="sendgrid-api-key",
        name="SendGrid API Key",
        severity="error",
        pattern=r'SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}',
        description="SendGrid API key.",
    ),

    # ── Heroku ───────────────────────────────────────────────────────
    SecretPattern(
        rule_id="heroku-api-key",
        name="Heroku API Key",
        severity="error",
        pattern=r'(?:HEROKU_API_KEY|heroku_api_key)\s*[:=]\s*["\']?[0-9a-fA-F-]{36,}["\']?',
        description="Heroku API key assignment.",
    ),

    # ── HashiCorp Vault ──────────────────────────────────────────────
    SecretPattern(
        rule_id="vault-token",
        name="HashiCorp Vault Token",
        severity="error",
        pattern=r'hvs\.[A-Za-z0-9_-]{24,}',
        description="HashiCorp Vault service token.",
    ),

    # ── Azure ────────────────────────────────────────────────────────
    SecretPattern(
        rule_id="azure-storage-key",
        name="Azure Storage Key",
        severity="error",
        pattern=r'Azure_Storage_(?:AccountName|AccountKey|key|Key|KEY|AccessKey|ACCESSKEY|SasToken)[^\n]+',
        description="Azure storage account credential.",
        case_insensitive=True,
    ),
    SecretPattern(
        rule_id="azure-account-key",
        name="Azure Account Key",
        severity="error",
        pattern=r'AccountKey=\S{10,}',
        description="Azure account key assignment.",
    ),
    SecretPattern(
        rule_id="client-secret-value",
        name="Client Secret Value",
        severity="error",
        pattern=r'ClientSecret"\svalue=.+',
        description="Client secret value in configuration.",
    ),

    # ── Database connection strings ──────────────────────────────────
    SecretPattern(
        rule_id="database-connection-string",
        name="Database Connection String",
        severity="warning",
        pattern=r'(?:mongodb|postgres|mysql|jdbc|redis|ftp|smtp)[\s_\-=:][A-Za-z0-9+=._-]{10,}',
        description="Database or service connection string.",
        case_insensitive=True,
    ),

    # ── Private keys ─────────────────────────────────────────────────
    SecretPattern(
        rule_id="private-key-block",
        name="Private Key Block",
        severity="error",
        pattern=r'-----BEGIN\s(?:RSA|DSA|EC|PGP|OPENSSH)\sPRIVATE\sKEY-----',
        description="PEM-encoded private key header.",
    ),
    SecretPattern(
        rule_id="generic-private-key",
        name="Generic Private Key Block",
        severity="error",
        pattern=r'-----BEGIN PRIVATE KEY-----',
        description="Generic PEM private key header.",
    ),
    SecretPattern(
        rule_id="ssh-rsa-key",
        name="SSH RSA Public Key",
        severity="note",
        pattern=r'ssh-rsa\s+[A-Za-z0-9+/=]+',
        description="SSH RSA public key.",
    ),

    # ── Generic secrets (broad, keep last) ───────────────────────────
    SecretPattern(
        rule_id="generic-access-key",
        name="Generic Access Key Assignment",
        severity="warning",
        pattern=r'(?:AccessKey|ACCESSKEY|ACCESS_KEY|Access_key)=\S{10,}',
        description="Generic access key assignment.",
    ),
    SecretPattern(
        rule_id="secret-key-base",
        name="Secret Key Base",
        severity="warning",
        pattern=r'secret_key_base:\s.[A-Za-z0-9_.-]{12,}',
        description="Rails secret_key_base value.",
        case_insensitive=True,
    ),
    SecretPattern(
        rule_id="bearer-token",
        name="Bearer Token",
        severity="error",
        pattern=r'Bearer\s\S{12,}',
        description="HTTP Bearer authentication token.",
    ),
    SecretPattern(
        rule_id="api-key-token",
        name="API Key/Token Assignment",
        severity="warning",
        pattern=r'api[_-](?:key|token)(?::|=).?[A-Za-z0-9_.-]{10,}',
        description="Generic API key or token assignment.",
        case_insensitive=True,
    ),
    SecretPattern(
        rule_id="password-assignment",
        name="Password Assignment",
        severity="warning",
        pattern=r'(?:password|passwd|pwd)\s*[:=]\s*["\']?[^\s"\']{8,}',
        description="Password assigned in source code or config.",
        case_insensitive=True,
    ),
    SecretPattern(
        rule_id="generic-secret",
        name="Generic Secret Assignment",
        severity="warning",
        pattern=r'secret(?:\s|:|=).+[A-Za-z0-9_.-]{12,}',
        description="Generic secret value assignment.",
        case_insensitive=True,
    ),
    SecretPattern(
        rule_id="jwt-token",
        name="JWT Token",
        severity="warning",
        pattern=r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}',
        description="JSON Web Token (JWT).",
    ),

    # ── OpenAI (generic sk- last, after Stripe-specific sk_live/sk_test) ─
    SecretPattern(
        rule_id="openai-api-key-assignment",
        name="OpenAI API Key Assignment",
        severity="error",
        pattern=r'(?:OPENAI_API_KEY|openai_api_key)\s*[:=]\s*["\']?sk-[A-Za-z0-9]{20,}["\']?',
        description="OpenAI API key assigned to a variable.",
    ),
    SecretPattern(
        rule_id="openai-api-key",
        name="OpenAI API Key",
        severity="error",
        pattern=r'sk-[A-Za-z0-9]{20,}',
        description="OpenAI API key starting with sk-.",
    ),
]


def get_patterns() -> list[SecretPattern]:
    """Return all registered secret patterns."""
    return list(PATTERNS)


def compile_patterns() -> list[tuple[SecretPattern, re.Pattern]]:
    """Compile all patterns and return (metadata, compiled_regex) pairs."""
    compiled = []
    for sp in PATTERNS:
        flags = re.IGNORECASE if sp.case_insensitive else 0
        try:
            compiled.append((sp, re.compile(sp.pattern, flags)))
        except re.error as e:
            raise ValueError(f"Invalid regex in rule {sp.rule_id!r}: {e}") from e
    return compiled


def build_pattern() -> re.Pattern:
    """Backward-compatible: returns a single combined pattern.

    Deprecated — use compile_patterns() for named pattern matching.
    """
    combined = "|".join(f"(?:{sp.pattern})" for sp in PATTERNS)
    return re.compile(combined, re.IGNORECASE)
