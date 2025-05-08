from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from dotenv import load_dotenv
import os

# Load environment variables from .env file
load_dotenv()

# Create engine
engine = create_engine(os.getenv("DATABASE_URL"))

# Create session
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False, autocommit=False, autoflush=False)

# Base class for models to inherit
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()