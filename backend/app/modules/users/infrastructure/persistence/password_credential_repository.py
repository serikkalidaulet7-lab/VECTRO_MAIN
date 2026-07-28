"""SQLAlchemy repository adapter for password credentials."""

from sqlalchemy.ext.asyncio import AsyncSession

from app.modules.users.domain import PasswordCredential, UserId
from app.modules.users.infrastructure.persistence.password_credential_mapper import (
    PasswordCredentialMapper,
)
from app.modules.users.infrastructure.persistence.password_credential_models import (
    PasswordCredentialModel,
)


class SqlAlchemyPasswordCredentialRepository:
    """Persist password credentials through an injected asynchronous SQLAlchemy session."""

    def __init__(self, session: AsyncSession) -> None:
        """Initialize the repository with a transaction-scoped database session."""
        self._session = session

    async def get_by_user_id(self, user_id: UserId) -> PasswordCredential | None:
        """Return a domain credential for a user, if one exists."""
        model = await self._session.get(PasswordCredentialModel, user_id.value)
        return PasswordCredentialMapper.to_domain(model) if model is not None else None

    async def save(self, credential: PasswordCredential) -> None:
        """Stage a credential insert or update without committing the transaction."""
        model = await self._session.get(PasswordCredentialModel, credential.user_id.value)
        if model is None:
            self._session.add(PasswordCredentialMapper.from_domain(credential))
        else:
            PasswordCredentialMapper.update_model(model, credential)

        await self._session.flush()
