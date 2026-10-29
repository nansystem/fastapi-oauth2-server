import pytest

from app.services.oauth_service import OAuthService


def test_authorization_code_is_redirect_bound_and_single_use(monkeypatch):
    monkeypatch.setattr(OAuthService, "_auth_codes", {})
    monkeypatch.setattr(OAuthService, "_tokens", {})
    redirect_uri = "https://client.example/callback"
    code = OAuthService.generate_authorization_code(
        client_id="client123",
        user_id="user-1",
        redirect_uri=redirect_uri,
        scope="profile email",
    )

    with pytest.raises(ValueError, match="Redirect URI mismatch"):
        OAuthService.exchange_code_for_token(
            code, client_id="client123", redirect_uri="https://attacker.example/callback"
        )

    token = OAuthService.exchange_code_for_token(
        code, client_id="client123", redirect_uri=redirect_uri
    )

    assert token["token_type"] == "Bearer"
    assert token["scope"] == "profile email"
    assert OAuthService.validate_token(token["access_token"], "profile")["user_id"] == "user-1"

    with pytest.raises(ValueError, match="Invalid authorization code"):
        OAuthService.exchange_code_for_token(
            code, client_id="client123", redirect_uri=redirect_uri
        )
