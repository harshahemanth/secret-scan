# tests/test_patterns.py

from secret_scanner.patterns import compile_patterns, get_patterns


def _matches_rule(text: str, rule_id: str) -> bool:
    """Check if text matches a specific rule."""
    for sp, compiled in compile_patterns():
        if sp.rule_id == rule_id:
            return compiled.search(text) is not None
    raise ValueError(f"Unknown rule_id: {rule_id}")


def _all_matching_rules(text: str) -> list[str]:
    """Return all rule_ids that match the given text."""
    results = []
    for sp, compiled in compile_patterns():
        if compiled.search(text):
            results.append(sp.rule_id)
    return results


# ── AWS ──────────────────────────────────────────────────────────────


class TestAWSPatterns:
    def test_aws_access_key_id_detected(self):
        assert _matches_rule("AKIA1234567890ABCDEF", "aws-access-key-id")

    def test_aws_access_key_id_too_short(self):
        assert not _matches_rule("AKIA123", "aws-access-key-id")

    def test_aws_access_key_assignment(self):
        assert _matches_rule("AWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF", "aws-access-key-assignment")

    def test_aws_secret_key(self):
        key = "A" * 40
        assert _matches_rule(f"AWS_SECRET_ACCESS_KEY={key}", "aws-secret-access-key")

    def test_aws_secret_key_too_short(self):
        assert not _matches_rule("AWS_SECRET_ACCESS_KEY=short", "aws-secret-access-key")

    def test_aws_asia_prefix(self):
        assert _matches_rule("ASIA1234567890ABCDEF", "aws-access-key-id")

    def test_random_text_no_match(self):
        assert not _matches_rule("hello world", "aws-access-key-id")


# ── GitHub ───────────────────────────────────────────────────────────


class TestGitHubPatterns:
    def test_github_pat(self):
        assert _matches_rule("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij", "github-personal-access-token")

    def test_github_pat_too_short(self):
        assert not _matches_rule("ghp_short", "github-personal-access-token")

    def test_github_oauth(self):
        assert _matches_rule("gho_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij", "github-oauth-token")

    def test_github_app_token(self):
        assert _matches_rule("ghs_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij", "github-app-token")

    def test_github_refresh_token(self):
        assert _matches_rule("ghr_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij", "github-refresh-token")

    def test_github_fine_grained(self):
        assert _matches_rule("github_pat_ABCDEFGHIJKLMNOPQRSTUV12", "github-fine-grained-pat")

    def test_github_fine_grained_too_short(self):
        assert not _matches_rule("github_pat_short", "github-fine-grained-pat")


# ── Slack ────────────────────────────────────────────────────────────


class TestSlackPatterns:
    def test_slack_bot_token(self):
        # Build token dynamically to avoid GitHub push protection
        token = "xoxb" + "-1234567890-1234567890-" + "A" * 24
        assert _matches_rule(token, "slack-bot-token")

    def test_slack_bot_token_wrong_prefix(self):
        token = "xoxz" + "-1234567890-1234567890-" + "A" * 24
        assert not _matches_rule(token, "slack-bot-token")

    def test_slack_user_token(self):
        # Build token dynamically to avoid GitHub push protection
        token = "xoxp" + "-1234567890-1234567890-1234567890-" + "a0" * 16
        assert _matches_rule(token, "slack-user-token")


# ── Stripe ───────────────────────────────────────────────────────────


class TestStripePatterns:
    def test_stripe_live_secret(self):
        assert _matches_rule("sk_live_" + "A" * 24, "stripe-secret-key-live")

    def test_stripe_test_secret(self):
        assert _matches_rule("sk_test_" + "A" * 24, "stripe-secret-key-test")

    def test_stripe_live_publishable(self):
        assert _matches_rule("pk_live_" + "A" * 24, "stripe-publishable-key-live")

    def test_stripe_test_publishable(self):
        assert _matches_rule("pk_test_" + "A" * 24, "stripe-publishable-key-test")

    def test_stripe_live_restricted(self):
        assert _matches_rule("rk_live_" + "A" * 24, "stripe-restricted-key-live")

    def test_stripe_test_restricted(self):
        assert _matches_rule("rk_test_" + "A" * 24, "stripe-restricted-key-test")

    def test_stripe_key_too_short(self):
        assert not _matches_rule("sk_live_short", "stripe-secret-key-live")

    def test_stripe_detected_alongside_openai(self):
        # sk_live_ should match Stripe-specific rule
        rules = _all_matching_rules("sk_live_" + "A" * 24)
        assert "stripe-secret-key-live" in rules


# ── Google ───────────────────────────────────────────────────────────


class TestGooglePatterns:
    def test_google_api_key(self):
        assert _matches_rule("AIzaSyB" + "A" * 32, "google-api-key")

    def test_google_api_key_wrong_prefix(self):
        assert not _matches_rule("AIzb" + "A" * 35, "google-api-key")

    def test_google_api_key_too_short(self):
        assert not _matches_rule("AIzaSyBshort", "google-api-key")


# ── npm / PyPI ───────────────────────────────────────────────────────


class TestPackageRegistryPatterns:
    def test_npm_token(self):
        assert _matches_rule("npm_" + "A" * 36, "npm-access-token")

    def test_npm_token_too_short(self):
        assert not _matches_rule("npm_short", "npm-access-token")

    def test_pypi_token(self):
        assert _matches_rule("pypi-" + "A" * 50, "pypi-api-token")

    def test_pypi_token_too_short(self):
        assert not _matches_rule("pypi-short", "pypi-api-token")


# ── Twilio ───────────────────────────────────────────────────────────


class TestTwilioPatterns:
    def test_twilio_api_key(self):
        assert _matches_rule("SK" + "a" * 32, "twilio-api-key")

    def test_twilio_api_key_too_short(self):
        assert not _matches_rule("SK" + "a" * 10, "twilio-api-key")


# ── SendGrid ─────────────────────────────────────────────────────────


class TestSendGridPatterns:
    def test_sendgrid_api_key(self):
        assert _matches_rule("SG." + "A" * 22 + "." + "A" * 43, "sendgrid-api-key")

    def test_sendgrid_wrong_format(self):
        assert not _matches_rule("SG.short.short", "sendgrid-api-key")


# ── Heroku ───────────────────────────────────────────────────────────


class TestHerokuPatterns:
    def test_heroku_api_key_assignment(self):
        assert _matches_rule(
            "HEROKU_API_KEY=abcdef01-2345-6789-abcd-ef0123456789",
            "heroku-api-key",
        )

    def test_standalone_uuid_not_matched(self):
        # Plain UUIDs should NOT match (assignment context required)
        assert not _matches_rule(
            "abcdef01-2345-6789-abcd-ef0123456789",
            "heroku-api-key",
        )


# ── Vault ────────────────────────────────────────────────────────────


class TestVaultPatterns:
    def test_vault_token(self):
        assert _matches_rule("hvs." + "A" * 24, "vault-token")

    def test_vault_token_too_short(self):
        assert not _matches_rule("hvs.short", "vault-token")


# ── Existing patterns preserved ──────────────────────────────────────


class TestExistingPatterns:
    def test_password_assignment(self):
        assert _matches_rule("password=supersecret123", "password-assignment")

    def test_password_short_not_matched(self):
        assert not _matches_rule("password=short", "password-assignment")

    def test_bearer_token(self):
        assert _matches_rule("Bearer eyJhbGciOiJIUzI1NiJ9", "bearer-token")

    def test_jwt_token(self):
        assert _matches_rule(
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
            "jwt-token",
        )

    def test_private_key_block(self):
        assert _matches_rule("-----BEGIN RSA PRIVATE KEY-----", "private-key-block")

    def test_generic_private_key(self):
        assert _matches_rule("-----BEGIN PRIVATE KEY-----", "generic-private-key")

    def test_openai_key(self):
        assert _matches_rule("sk-ABCDEFGHIJKLMNOPQRSTUV123456", "openai-api-key")

    def test_openai_key_assignment(self):
        assert _matches_rule(
            'OPENAI_API_KEY="sk-ABCDEFGHIJKLMNOPQRSTUV123456"',
            "openai-api-key-assignment",
        )

    def test_azure_storage_key(self):
        assert _matches_rule("Azure_Storage_AccountKey=abc123def456", "azure-storage-key")

    def test_database_connection_string(self):
        assert _matches_rule("mongodb=userpassword1234567", "database-connection-string")

    def test_ssh_rsa_key(self):
        assert _matches_rule("ssh-rsa AAAAB3NzaC1yc2EAAAADAQ", "ssh-rsa-key")

    def test_api_key_token_assignment(self):
        assert _matches_rule("api_key=abcdef1234567890", "api-key-token")


# ── Meta: registry integrity ─────────────────────────────────────────


class TestPatternRegistry:
    def test_all_patterns_have_required_fields(self):
        for sp in get_patterns():
            assert sp.rule_id, f"Missing rule_id"
            assert sp.name, f"Missing name for {sp.rule_id}"
            assert sp.severity in ("error", "warning", "note"), (
                f"Invalid severity '{sp.severity}' for {sp.rule_id}"
            )
            assert sp.pattern, f"Missing pattern for {sp.rule_id}"
            assert sp.description, f"Missing description for {sp.rule_id}"

    def test_all_rule_ids_unique(self):
        ids = [sp.rule_id for sp in get_patterns()]
        assert len(ids) == len(set(ids)), "Duplicate rule IDs found"

    def test_all_patterns_compile(self):
        compiled = compile_patterns()
        assert len(compiled) == len(get_patterns())

    def test_build_pattern_backward_compat(self):
        from secret_scanner.patterns import build_pattern
        pat = build_pattern()
        # Should match a basic password pattern
        assert pat.search("password=test12345678")
