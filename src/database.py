# src/database.py
"""
Database configuration using SQLAlchemy and dotenv for Elderly Care Home Alert Engine.
This file sets up the engine, session maker, and base declarative class.
"""
import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Load the database path from environment variables
DB_PATH = os.getenv("DB_PATH", "sqlite:///./rules.db")

# Create SQLAlchemy engine
engine = create_engine(DB_PATH, connect_args={"check_same_thread": False})

# Create session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base class for ORM models
Base = declarative_base()

# Dependency to get DB session
# (Used in FastAPI routes)
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Initialize database tables
def init_db():
    """Create all database tables if they don't exist"""
    from . import models  # Import models here to avoid circular imports
    Base.metadata.create_all(bind=engine)