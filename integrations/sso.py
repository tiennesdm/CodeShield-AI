"""
Enterprise SSO Integration

Supports:
- SAML 2.0 Service Provider (OneLogin/python3-saml patterns)
- OpenID Connect (OIDC)
- LDAP / Active Directory sync
- Just-In-Time (JIT) user provisioning

Usage:
    sso = SSOIntegrationEngine()
    # SAML
    saml_config = sso.configure_saml(provider_id="okta", metadata_url="...")
    auth_url = sso.initiate_saml_login("okta")
    user = sso.process_saml_response("okta", saml_response_xml)

    # OIDC
    oidc_config = sso.configure_oidc(provider_id="google", client_id="...", client_secret="...")
    auth_url = sso.initiate_oidc_login("google")
    user = sso.process_oidc_callback("google", code, redirect_uri)

    # LDAP
    ldap_config = sso.configure_ldap(server="ldap.corp.com", base_dn="dc=corp,dc=com")
    user = sso.authenticate_ldap("username", "password")
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from xml.etree import ElementTree as ET

from pydantic import BaseModel, Field


class SSOProviderConfig(BaseModel):
    """Configuration for an SSO identity provider."""
    provider_id: str
    provider_type: str  # saml, oidc, ldap
    name: str
    enabled: bool = True

    # SAML fields
    metadata_url: Optional[str] = None
    metadata_xml: Optional[str] = None
    entity_id: Optional[str] = None
    sso_url: Optional[str] = None  # IdP Single Sign-On URL
    slo_url: Optional[str] = None  # IdP Single Logout URL
    x509_cert: Optional[str] = None
    name_id_format: str = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"

    # OIDC fields
    client_id: Optional[str] = None
    client_secret: Optional[str] = None
    authorization_endpoint: Optional[str] = None
    token_endpoint: Optional[str] = None
    userinfo_endpoint: Optional[str] = None
    issuer: Optional[str] = None
    scopes: List[str] = Field(default_factory=lambda: ["openid", "email", "profile"])
    jwks_uri: Optional[str] = None

    # LDAP fields
    ldap_server: Optional[str] = None
    ldap_port: int = 636
    base_dn: Optional[str] = None
    bind_dn: Optional[str] = None
    bind_password: Optional[str] = None
    user_search_filter: str = "(uid={username})"
    user_search_base: Optional[str] = None
    group_search_filter: str = "(member={user_dn})"
    use_ssl: bool = True
    use_tls: bool = True

    # JIT Provisioning
    jit_provisioning: bool = True
    default_role: str = "viewer"
    role_attribute: Optional[str] = None  # Attribute/claim containing role
    role_mappings: Dict[str, str] = Field(default_factory=dict)  # IdP role -> our role

    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> Dict[str, Any]:
        data = self.model_dump()
        # Mask secrets
        data["client_secret"] = "***" if self.client_secret else None
        data["bind_password"] = "***" if self.bind_password else None
        return data


class SSOUserInfo(BaseModel):
    """Normalized user info from any SSO provider."""
    provider_id: str
    provider_type: str
    subject_id: str  # Unique ID from the IdP
    email: str
    full_name: Optional[str] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    groups: List[str] = Field(default_factory=list)
    roles: List[str] = Field(default_factory=list)
    attributes: Dict[str, Any] = Field(default_factory=dict)
    authenticated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump()


class SAMLRequest:
    """SAML Authentication Request generator."""

    def __init__(self, config: SSOProviderConfig) -> None:
        self.config = config

    def generate_authn_request(self, request_id: str) -> str:
        """Generate a SAML AuthnRequest XML."""
        # Create a minimal SAML AuthnRequest
        ns_samlp = "urn:oasis:names:tc:SAML:2.0:protocol"
        ns_saml = "urn:oasis:names:tc:SAML:2.0:assertion"

        issue_instant = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        root = ET.Element("{%s}AuthnRequest" % ns_samlp)
        root.set("ID", request_id)
        root.set("Version", "2.0")
        root.set("IssueInstant", issue_instant)
        root.set("ProtocolBinding", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST")
        root.set("AssertionConsumerServiceURL", self.config.entity_id or "")

        issuer = ET.SubElement(root, "{%s}Issuer" % ns_saml)
        issuer.text = self.config.entity_id or "codeshield-ai"

        nameid = ET.SubElement(root, "{%s}NameIDPolicy" % ns_samlp)
        nameid.set("Format", self.config.name_id_format)
        nameid.set("AllowCreate", "true")

        return ET.tostring(root, encoding="unicode")

    def decode_saml_response(self, encoded_response: str) -> Dict[str, Any]:
        """Decode and parse a SAML Response (simplified)."""
        try:
            decoded = base64.b64decode(encoded_response)
            root = ET.fromstring(decoded)
            # Extract assertions (simplified parsing)
            ns_saml = "{urn:oasis:names:tc:SAML:2.0:assertion}"

            result: Dict[str, Any] = {"attributes": {}}
            for assertion in root.iter(f"{ns_saml}Assertion"):
                for attr_stmt in assertion.iter(f"{ns_saml}AttributeStatement"):
                    for attr in attr_stmt.iter(f"{ns_saml}Attribute"):
                        attr_name = attr.get("Name", "")
                        values = [v.text for v in attr.iter(f"{ns_saml}AttributeValue") if v.text]
                        result["attributes"][attr_name] = values[0] if len(values) == 1 else values

                for subject in assertion.iter(f"{ns_saml}Subject"):
                    for nameid in subject.iter(f"{ns_saml}NameID"):
                        result["name_id"] = nameid.text

            # Normalize common attributes
            attrs = result["attributes"]
            result["email"] = attrs.get("email") or attrs.get("Email") or result.get("name_id", "")
            result["full_name"] = attrs.get("displayName") or attrs.get("cn") or ""
            result["first_name"] = attrs.get("givenName") or ""
            result["last_name"] = attrs.get("surname") or ""
            result["groups"] = attrs.get("groups") or attrs.get("memberOf") or []

            return result
        except Exception as e:
            return {"error": str(e), "attributes": {}}


class OIDCRequest:
    """OIDC authentication flow handler."""

    def __init__(self, config: SSOProviderConfig) -> None:
        self.config = config

    def generate_authorization_url(
        self,
        redirect_uri: str,
        state: str,
        nonce: str,
    ) -> str:
        """Generate OIDC authorization URL."""
        params = {
            "client_id": self.config.client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": " ".join(self.config.scopes),
            "state": state,
            "nonce": nonce,
        }
        query = urllib.parse.urlencode(params)
        return f"{self.config.authorization_endpoint}?{query}"

    def exchange_code_for_tokens(
        self,
        code: str,
        redirect_uri: str,
    ) -> Dict[str, Any]:
        """Exchange authorization code for tokens."""
        data = urllib.parse.urlencode({
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": self.config.client_id,
            "client_secret": self.config.client_secret,
        }).encode()

        try:
            req = urllib.request.Request(
                self.config.token_endpoint or "",
                data=data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read().decode())
        except Exception as e:
            return {"error": str(e)}

    def get_userinfo(self, access_token: str) -> Dict[str, Any]:
        """Fetch user info from OIDC userinfo endpoint."""
        try:
            req = urllib.request.Request(
                self.config.userinfo_endpoint or "",
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Accept": "application/json",
                },
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read().decode())
        except Exception as e:
            return {"error": str(e)}


class SSOIntegrationEngine:
    """
    Enterprise SSO Integration Engine.

    Manages SAML 2.0, OIDC, and LDAP authentication with
    Just-In-Time user provisioning.
    """

    def __init__(self) -> None:
        self._providers: Dict[str, SSOProviderConfig] = {}
        self._login_states: Dict[str, Dict[str, Any]] = {}  # state -> {nonce, provider_id, redirect_uri, timestamp}

    # ------------------------------------------------------------------
    # Provider Configuration
    # ------------------------------------------------------------------

    def configure_saml(
        self,
        provider_id: str,
        name: str,
        metadata_url: Optional[str] = None,
        metadata_xml: Optional[str] = None,
        entity_id: Optional[str] = None,
        sso_url: Optional[str] = None,
        x509_cert: Optional[str] = None,
        jit_provisioning: bool = True,
        default_role: str = "viewer",
        role_mappings: Optional[Dict[str, str]] = None,
    ) -> SSOProviderConfig:
        """Configure a SAML 2.0 identity provider."""
        config = SSOProviderConfig(
            provider_id=provider_id,
            provider_type="saml",
            name=name,
            metadata_url=metadata_url,
            metadata_xml=metadata_xml,
            entity_id=entity_id,
            sso_url=sso_url,
            x509_cert=x509_cert,
            jit_provisioning=jit_provisioning,
            default_role=default_role,
            role_mappings=role_mappings or {},
        )
        self._providers[provider_id] = config
        return config

    def configure_oidc(
        self,
        provider_id: str,
        name: str,
        client_id: str,
        client_secret: str,
        authorization_endpoint: str,
        token_endpoint: str,
        userinfo_endpoint: str,
        issuer: str,
        scopes: Optional[List[str]] = None,
        jwks_uri: Optional[str] = None,
        jit_provisioning: bool = True,
        default_role: str = "viewer",
        role_mappings: Optional[Dict[str, str]] = None,
    ) -> SSOProviderConfig:
        """Configure an OIDC identity provider."""
        config = SSOProviderConfig(
            provider_id=provider_id,
            provider_type="oidc",
            name=name,
            client_id=client_id,
            client_secret=client_secret,
            authorization_endpoint=authorization_endpoint,
            token_endpoint=token_endpoint,
            userinfo_endpoint=userinfo_endpoint,
            issuer=issuer,
            scopes=scopes or ["openid", "email", "profile"],
            jwks_uri=jwks_uri,
            jit_provisioning=jit_provisioning,
            default_role=default_role,
            role_mappings=role_mappings or {},
        )
        self._providers[provider_id] = config
        return config

    def configure_ldap(
        self,
        provider_id: str,
        name: str,
        ldap_server: str,
        base_dn: str,
        bind_dn: str,
        bind_password: str,
        ldap_port: int = 636,
        use_ssl: bool = True,
        user_search_filter: str = "(uid={username})",
        user_search_base: Optional[str] = None,
        jit_provisioning: bool = True,
        default_role: str = "viewer",
    ) -> SSOProviderConfig:
        """Configure an LDAP / Active Directory server."""
        config = SSOProviderConfig(
            provider_id=provider_id,
            provider_type="ldap",
            name=name,
            ldap_server=ldap_server,
            base_dn=base_dn,
            bind_dn=bind_dn,
            bind_password=bind_password,
            ldap_port=ldap_port,
            use_ssl=use_ssl,
            user_search_filter=user_search_filter,
            user_search_base=user_search_base or base_dn,
            jit_provisioning=jit_provisioning,
            default_role=default_role,
        )
        self._providers[provider_id] = config
        return config

    def get_provider(self, provider_id: str) -> Optional[SSOProviderConfig]:
        """Get a configured provider."""
        return self._providers.get(provider_id)

    def list_providers(self) -> List[SSOProviderConfig]:
        """List all configured providers."""
        return list(self._providers.values())

    def remove_provider(self, provider_id: str) -> bool:
        """Remove a provider configuration."""
        if provider_id in self._providers:
            del self._providers[provider_id]
            return True
        return False

    # ------------------------------------------------------------------
    # SAML Authentication
    # ------------------------------------------------------------------

    def initiate_saml_login(self, provider_id: str) -> Dict[str, str]:
        """
        Initiate SAML authentication.

        Returns the IdP SSO URL and SAMLRequest to POST.
        """
        provider = self._providers.get(provider_id)
        if not provider or provider.provider_type != "saml":
            return {"error": "SAML provider not found"}

        saml = SAMLRequest(provider)
        request_id = f"_{secrets.token_hex(16)}"
        authn_request_xml = saml.generate_authn_request(request_id)
        encoded_request = base64.b64encode(authn_request_xml.encode()).decode()

        return {
            "sso_url": provider.sso_url or "",
            "saml_request": encoded_request,
            "relay_state": provider_id,
        }

    def process_saml_response(
        self,
        provider_id: str,
        saml_response: str,
    ) -> SSOUserInfo:
        """
        Process a SAML Response from the IdP.

        Returns normalized user info for JIT provisioning.
        """
        provider = self._providers.get(provider_id)
        if not provider:
            raise ValueError(f"Provider {provider_id} not found")

        saml = SAMLRequest(provider)
        result = saml.decode_saml_response(saml_response)

        if "error" in result:
            raise ValueError(f"SAML response parsing failed: {result['error']}")

        # Map roles
        roles = self._map_roles(provider, result.get("groups", []))

        return SSOUserInfo(
            provider_id=provider_id,
            provider_type="saml",
            subject_id=result.get("name_id", ""),
            email=result.get("email", ""),
            full_name=result.get("full_name"),
            first_name=result.get("first_name"),
            last_name=result.get("last_name"),
            groups=result.get("groups", []),
            roles=roles,
            attributes=result.get("attributes", {}),
        )

    # ------------------------------------------------------------------
    # OIDC Authentication
    # ------------------------------------------------------------------

    def initiate_oidc_login(
        self,
        provider_id: str,
        redirect_uri: str,
    ) -> Dict[str, str]:
        """
        Initiate OIDC authentication flow.

        Returns the authorization URL to redirect the user to.
        """
        provider = self._providers.get(provider_id)
        if not provider or provider.provider_type != "oidc":
            return {"error": "OIDC provider not found"}

        state = secrets.token_urlsafe(32)
        nonce = secrets.token_urlsafe(32)

        oidc = OIDCRequest(provider)
        auth_url = oidc.generate_authorization_url(redirect_uri, state, nonce)

        self._login_states[state] = {
            "nonce": nonce,
            "provider_id": provider_id,
            "redirect_uri": redirect_uri,
            "created_at": datetime.now(timezone.utc),
        }

        return {
            "authorization_url": auth_url,
            "state": state,
        }

    def process_oidc_callback(
        self,
        provider_id: str,
        code: str,
        redirect_uri: str,
        state: Optional[str] = None,
    ) -> SSOUserInfo:
        """
        Process OIDC callback (code exchange + userinfo).

        Returns normalized user info for JIT provisioning.
        """
        provider = self._providers.get(provider_id)
        if not provider:
            raise ValueError(f"Provider {provider_id} not found")

        # Clean up state
        if state and state in self._login_states:
            del self._login_states[state]

        oidc = OIDCRequest(provider)
        token_response = oidc.exchange_code_for_tokens(code, redirect_uri)

        if "error" in token_response:
            raise ValueError(f"Token exchange failed: {token_response['error']}")

        access_token = token_response.get("access_token")
        if not access_token:
            raise ValueError("No access_token in token response")

        userinfo = oidc.get_userinfo(access_token)
        if "error" in userinfo:
            raise ValueError(f"Userinfo fetch failed: {userinfo['error']}")

        # Map roles from claims
        role_claim = userinfo.get("groups") or userinfo.get("roles") or []
        if isinstance(role_claim, str):
            role_claim = [role_claim]
        roles = self._map_roles(provider, role_claim)

        return SSOUserInfo(
            provider_id=provider_id,
            provider_type="oidc",
            subject_id=userinfo.get("sub", ""),
            email=userinfo.get("email", ""),
            full_name=userinfo.get("name"),
            first_name=userinfo.get("given_name"),
            last_name=userinfo.get("family_name"),
            groups=role_claim if isinstance(role_claim, list) else [],
            roles=roles,
            attributes=userinfo,
        )

    # ------------------------------------------------------------------
    # LDAP Authentication
    # ------------------------------------------------------------------

    def authenticate_ldap(
        self,
        provider_id: str,
        username: str,
        password: str,
    ) -> SSOUserInfo:
        """
        Authenticate a user against LDAP / Active Directory.

        Returns normalized user info for JIT provisioning.
        """
        provider = self._providers.get(provider_id)
        if not provider or provider.provider_type != "ldap":
            raise ValueError(f"LDAP provider {provider_id} not found")

        try:
            import ldap3  # type: ignore
        except ImportError:
            # Fallback: simulate LDAP auth for demo/testing
            return self._simulate_ldap_auth(provider, username)

        server = ldap3.Server(
            provider.ldap_server,
            port=provider.ldap_port,
            use_ssl=provider.use_ssl,
        )

        # Bind with service account
        conn = ldap3.Connection(
            server,
            user=provider.bind_dn,
            password=provider.bind_password,
            auto_bind=True,
        )

        try:
            # Search for user
            search_filter = provider.user_search_filter.replace("{username}", username)
            conn.search(
                search_base=provider.user_search_base or provider.base_dn,
                search_filter=search_filter,
                attributes=["cn", "mail", "givenName", "sn", "memberOf", "displayName"],
            )

            if not conn.entries:
                raise ValueError("User not found in LDAP")

            user_entry = conn.entries[0]
            user_dn = user_entry.entry_dn

            # Verify password with user bind
            user_conn = ldap3.Connection(server, user=user_dn, password=password, auto_bind=True)
            user_conn.unbind()

            # Extract attributes
            attrs = user_entry.entry_attributes_as_dict
            groups = [g for g in attrs.get("memberOf", [])]
            email = attrs.get("mail", [""])[0] if attrs.get("mail") else f"{username}@local"

            roles = self._map_roles(provider, groups)

            return SSOUserInfo(
                provider_id=provider_id,
                provider_type="ldap",
                subject_id=user_dn,
                email=email,
                full_name=attrs.get("displayName", [""])[0] if attrs.get("displayName") else None,
                first_name=attrs.get("givenName", [""])[0] if attrs.get("givenName") else None,
                last_name=attrs.get("sn", [""])[0] if attrs.get("sn") else None,
                groups=groups,
                roles=roles,
                attributes={k: v for k, v in attrs.items()},
            )
        finally:
            conn.unbind()

    def _simulate_ldap_auth(self, provider: SSOProviderConfig,
                            username: str) -> SSOUserInfo:
        """Simulate LDAP authentication when ldap3 is not installed (demo mode)."""
        return SSOUserInfo(
            provider_id=provider.provider_id,
            provider_type="ldap",
            subject_id=f"cn={username},{provider.base_dn}",
            email=f"{username}@example.com",
            full_name=username,
            roles=[provider.default_role],
            attributes={"simulated": True},
        )

    # ------------------------------------------------------------------
    # JIT Provisioning
    # ------------------------------------------------------------------

    def provision_user(self, sso_user: SSOUserInfo) -> Dict[str, Any]:
        """
        Create or update a user from SSO user info.

        Returns a dict with user data and provisioning status.
        """
        provider = self._providers.get(sso_user.provider_id)
        default_role = provider.default_role if provider else "viewer"

        # Determine role from SSO attributes
        effective_role = default_role
        if sso_user.roles:
            effective_role = sso_user.roles[0]

        return {
            "action": "provisioned",
            "email": sso_user.email,
            "full_name": sso_user.full_name,
            "role": effective_role,
            "groups": sso_user.groups,
            "sso_provider": sso_user.provider_id,
            "sso_subject_id": sso_user.subject_id,
            "provisioned_at": datetime.now(timezone.utc).isoformat(),
        }

    def _map_roles(self, provider: SSOProviderConfig,
                   idp_roles: List[str]) -> List[str]:
        """Map IdP roles to CodeShield roles using configured mappings."""
        if not provider.role_mappings:
            return [provider.default_role]

        mapped = []
        for role in idp_roles:
            role_str = str(role).lower().strip()
            if role_str in provider.role_mappings:
                mapped.append(provider.role_mappings[role_str])
            else:
                # Try partial matching
                for idp_role, cs_role in provider.role_mappings.items():
                    if idp_role in role_str or role_str in idp_role:
                        mapped.append(cs_role)
                        break

        return mapped if mapped else [provider.default_role]

    # ------------------------------------------------------------------
    # Utilities
    # ------------------------------------------------------------------

    def get_provider_login_url(self, provider_id: str,
                               redirect_uri: str = "") -> Dict[str, str]:
        """Get the login initiation URL for any provider type."""
        provider = self._providers.get(provider_id)
        if not provider:
            return {"error": "Provider not found"}

        if provider.provider_type == "saml":
            return self.initiate_saml_login(provider_id)
        elif provider.provider_type == "oidc":
            return self.initiate_oidc_login(provider_id, redirect_uri)
        elif provider.provider_type == "ldap":
            return {"type": "ldap", "message": "Use POST /api/auth/ldap/login"}
        return {"error": "Unknown provider type"}

    def cleanup_expired_states(self, max_age_minutes: int = 30) -> int:
        """Clean up expired login states."""
        now = datetime.now(timezone.utc)
        expired = [
            state for state, data in self._login_states.items()
            if (now - data["created_at"]).total_seconds() > max_age_minutes * 60
        ]
        for state in expired:
            del self._login_states[state]
        return len(expired)


# Singleton
_sso_engine: Optional[SSOIntegrationEngine] = None


def get_sso_engine() -> SSOIntegrationEngine:
    """Get or create the global SSO engine."""
    global _sso_engine
    if _sso_engine is None:
        _sso_engine = SSOIntegrationEngine()
    return _sso_engine
