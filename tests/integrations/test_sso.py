"""
Tests for integrations.sso module.
"""

import pytest

from integrations.sso import SSOIntegrationEngine, get_sso_engine, SSOUserInfo


class TestSSOIntegrationEngine:
    def setup_method(self):
        self.sso = SSOIntegrationEngine()

    def test_configure_saml(self):
        config = self.sso.configure_saml(
            provider_id="okta-test",
            name="Okta Test",
            metadata_url="https://okta.example.com/metadata",
            entity_id="codeshield-ai",
            sso_url="https://okta.example.com/sso",
            x509_cert="-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
        )
        assert config.provider_id == "okta-test"
        assert config.provider_type == "saml"
        assert config.sso_url == "https://okta.example.com/sso"

    def test_configure_oidc(self):
        config = self.sso.configure_oidc(
            provider_id="google-test",
            name="Google Workspace",
            client_id="client-123",
            client_secret="secret-456",
            authorization_endpoint="https://accounts.google.com/o/oauth2/auth",
            token_endpoint="https://oauth2.googleapis.com/token",
            userinfo_endpoint="https://openidconnect.googleapis.com/v1/userinfo",
            issuer="https://accounts.google.com",
        )
        assert config.provider_id == "google-test"
        assert config.provider_type == "oidc"
        assert config.client_id == "client-123"

    def test_configure_ldap(self):
        config = self.sso.configure_ldap(
            provider_id="ad-test",
            name="Corporate AD",
            ldap_server="ldap.corp.com",
            base_dn="dc=corp,dc=com",
            bind_dn="cn=admin,dc=corp,dc=com",
            bind_password="admin-pass",
        )
        assert config.provider_id == "ad-test"
        assert config.provider_type == "ldap"
        assert config.ldap_server == "ldap.corp.com"

    def test_list_providers(self):
        self.sso.configure_saml(provider_id="s1", name="S1", sso_url="https://test.com")
        self.sso.configure_oidc(provider_id="o1", name="O1",
                                client_id="c", client_secret="s",
                                authorization_endpoint="https://a.com",
                                token_endpoint="https://t.com",
                                userinfo_endpoint="https://u.com",
                                issuer="https://i.com")
        providers = self.sso.list_providers()
        assert len(providers) == 2

    def test_get_provider(self):
        self.sso.configure_saml(provider_id="test", name="Test", sso_url="https://test.com")
        found = self.sso.get_provider("test")
        assert found is not None
        assert found.name == "Test"
        not_found = self.sso.get_provider("nonexistent")
        assert not_found is None

    def test_remove_provider(self):
        self.sso.configure_saml(provider_id="remove-me", name="R", sso_url="https://test.com")
        assert self.sso.remove_provider("remove-me") is True
        assert self.sso.get_provider("remove-me") is None
        assert self.sso.remove_provider("nonexistent") is False

    def test_provision_user(self):
        sso_user = SSOUserInfo(
            provider_id="google-test",
            provider_type="oidc",
            subject_id="12345",
            email="user@corp.com",
            full_name="Test User",
            first_name="Test",
            last_name="User",
            groups=["developers"],
            roles=["developer"],
        )
        result = self.sso.provision_user(sso_user)
        assert result["email"] == "user@corp.com"
        assert result["full_name"] == "Test User"
        assert result["sso_provider"] == "google-test"
        assert "provisioned_at" in result

    def test_cleanup_expired_states(self):
        self.sso._login_states["state-1"] = {
            "nonce": "n1", "provider_id": "p1",
            "redirect_uri": "https://example.com",
            "created_at": __import__("datetime").datetime.now(__import__("datetime").timezone.utc) - __import__("datetime").timedelta(minutes=60),
        }
        count = self.sso.cleanup_expired_states(max_age_minutes=30)
        assert count == 1
        assert "state-1" not in self.sso._login_states

    def test_initiate_saml_login(self):
        self.sso.configure_saml(
            provider_id="saml-p", name="SAML",
            sso_url="https://idp.example.com/sso",
            entity_id="sp-entity-id",
        )
        result = self.sso.initiate_saml_login("saml-p")
        assert "sso_url" in result
        assert "saml_request" in result

    def test_initiate_oidc_login(self):
        self.sso.configure_oidc(
            provider_id="oidc-p", name="OIDC",
            client_id="c1", client_secret="s1",
            authorization_endpoint="https://auth.example.com",
            token_endpoint="https://token.example.com",
            userinfo_endpoint="https://user.example.com",
            issuer="https://issuer.example.com",
        )
        result = self.sso.initiate_oidc_login("oidc-p", "https://callback.example.com")
        assert "authorization_url" in result
        assert "state" in result

    def test_simulate_ldap_auth(self):
        config = self.sso.configure_ldap(
            provider_id="ldap-sim", name="LDAP Sim",
            ldap_server="ldap.example.com",
            base_dn="dc=example,dc=com",
            bind_dn="cn=admin", bind_password="pass",
        )
        result = self.sso._simulate_ldap_auth(config, "testuser")
        assert result.email == "testuser@example.com"
        assert result.provider_type == "ldap"

    def test_singleton(self):
        e1 = get_sso_engine()
        e2 = get_sso_engine()
        assert e1 is e2
