"""
init_db.py

Initialize the database by creating all tables.
"""

from .database import engine
from .models import Base

def create_tables():
    """Create all database tables."""
    Base.metadata.create_all(bind=engine)
    print("✅ Database tables created successfully!")

if __name__ == "__main__":
    create_tables()
