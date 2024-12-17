import datetime
import os
from sqlalchemy import DateTime, Integer, String, Text, func, ForeignKey
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncAttrs

POSTGRES_USER = os.getenv("POSTGRES_USER", "postgres")
POSTGRES_PASSWORD = os.getenv("POSTGRES_PASSWORD", "12341")
POSTGRES_DB = os.getenv("POSTGRES_DB", "netology_aiohttp")
POSTGRES_HOST = os.getenv("POSTGRES_HOST", "127.0.0.1")
POSTGRES_PORT = os.getenv("POSTGRES_PORT", "5431")


POSTGRES_DSN = (
    f"postgresql+asyncpg://"
    f"{POSTGRES_USER}:{POSTGRES_PASSWORD}@"
    f"{POSTGRES_HOST}:{POSTGRES_PORT}/"
    f"{POSTGRES_DB}"
)

engine = create_async_engine(POSTGRES_DSN)
Session = async_sessionmaker(bind=engine, expire_on_commit=False)


class Base(DeclarativeBase, AsyncAttrs):

    @property
    def id_dict(self):
        return {"id": self.id}


class User(Base):

    __tablename__ = "user"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    password: Mapped[str] = mapped_column(String(100), nullable=False)
    registration_time: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    adverts = relationship("Advert", back_populates="owner", cascade="all, delete", passive_deletes=True)
    @property
    def dict(self):
        return {
            "id": self.id,
            "email": self.email,
            "registration_time": self.registration_time.isoformat(),
        }


class Advert(Base):

    __tablename__ = "advert"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(255), unique=False, nullable=False)
    description: Mapped[str] = mapped_column(Text, unique=False, nullable=False)
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    owner_id: Mapped[int] = mapped_column(Integer, ForeignKey('user.id', ondelete="CASCADE"), nullable=False)
    owner = relationship("User", back_populates="adverts")

    @property
    def dict(self):
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "created_at": self.created_at.isoformat(),
            "owner_id": self.owner_id,
            "owner_email": self.owner.email,
        }


async def init_orm():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def close_orm():
    await engine.dispose()