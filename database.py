from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
import os

DB_URL = os.environ.get('DATABASE_URL', 'sqlite:///ufdr.db')
engine = create_engine(
    DB_URL, 
    connect_args={
        "check_same_thread": False,
        "timeout": 30
    },
    pool_pre_ping=True,
    pool_recycle=3600
)

SessionLocal = sessionmaker(
    autocommit=False, 
    autoflush=False, 
    bind=engine,
    expire_on_commit=False
)

Base = declarative_base()
