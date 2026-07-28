"""Opaque high-entropy refresh-token adapter."""

import hashlib
import secrets

from app.modules.users.application.ports.refresh_token_manager import GeneratedRefreshToken


class SecureRefreshTokenManager:
    """Generate 384-bit opaque secrets and deterministic SHA-256 storage hashes."""

    def generate(self) -> GeneratedRefreshToken:
        token = secrets.token_urlsafe(48)
        return GeneratedRefreshToken(token=token, token_hash=self.hash(token))

    def __repr__(self) -> str:
        """Return a representation without generated secret state."""
        return f"{type(self).__name__}()"

    def hash(self, token: str) -> str:
        if not isinstance(token, str) or not token:
            raise ValueError("Refresh token input is invalid.")
        return hashlib.sha256(token.encode("utf-8")).hexdigest()
