"""Opaque refresh-token generation and hashing contract."""

from dataclasses import dataclass, field
from typing import Protocol


@dataclass(frozen=True, slots=True)
class GeneratedRefreshToken:
    """One raw client token paired with its persistence-safe hash."""

    token: str = field(repr=False)
    token_hash: str = field(repr=False)


class RefreshTokenManager(Protocol):
    def generate(self) -> GeneratedRefreshToken: ...
    def hash(self, token: str) -> str: ...
