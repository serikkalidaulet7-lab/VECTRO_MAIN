"""User persistence and external-system adapters."""

from app.modules.users.infrastructure.persistence.repository import SqlAlchemyUserRepository

__all__ = ["SqlAlchemyUserRepository"]
