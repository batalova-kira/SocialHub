from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base

SQLALCHEMY_DATABASE_URL = "sqlite+aiosqlite:///./socialhub.db"

# Створення асинхронного двигуна
engine = create_async_engine(
    SQLALCHEMY_DATABASE_URL,
    echo=True  # Логування SQL-запитів (опційно)
)

AsyncSessionLocal = sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False
)

Base = declarative_base()