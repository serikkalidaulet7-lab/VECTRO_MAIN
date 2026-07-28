"""User persistence and external-system adapters."""

from app.modules.users.infrastructure.clock import UtcClock
from app.modules.users.infrastructure.persistence import (
    SqlAlchemyPasswordCredentialRepository,
    SqlAlchemyRefreshSessionRepository,
    SqlAlchemyUserRepository,
)
from app.modules.users.infrastructure.security import (
    Argon2PasswordHasher,
    JwtAccessTokenIssuer,
    JwtAccessTokenValidator,
    SecureRefreshTokenManager,
    get_dummy_password_hash,
)

__all__ = [
    "Argon2PasswordHasher",
    "JwtAccessTokenIssuer",
    "JwtAccessTokenValidator",
    "SecureRefreshTokenManager",
    "SqlAlchemyPasswordCredentialRepository",
    "SqlAlchemyRefreshSessionRepository",
    "SqlAlchemyUserRepository",
    "UtcClock",
    "get_dummy_password_hash",
]
