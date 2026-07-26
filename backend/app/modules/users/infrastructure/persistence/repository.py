"""SQLAlchemy repository adapter for the Users application port."""

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.modules.users.domain import EmailAddress, User
from app.modules.users.infrastructure.persistence.mapper import UserMapper
from app.modules.users.infrastructure.persistence.models import UserModel


class SqlAlchemyUserRepository:
    """Persist user entities through an injected asynchronous SQLAlchemy session."""

    def __init__(self, session: AsyncSession) -> None:
        """Initialize the repository with a transaction-scoped database session."""
        self._session = session

    async def get_by_email(self, email: EmailAddress) -> User | None:
        """Return a domain user for a normalized email address, if one exists."""
        statement = select(UserModel).where(UserModel.email == email.value)
        model = await self._session.scalar(statement)

        return UserMapper.to_domain(model) if model is not None else None

    async def save(self, user: User) -> None:
        """Stage a user insert or update without committing the surrounding transaction."""
        model = await self._session.get(UserModel, user.id.value)
        if model is None:
            self._session.add(UserMapper.from_domain(user))
            return

        UserMapper.update_model(model, user)
