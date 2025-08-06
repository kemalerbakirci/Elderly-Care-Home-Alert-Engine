"""
conftest.py

Test configuration file that sets up test database and fixtures.
"""

import pytest
import tempfile
import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from fastapi.testclient import TestClient

from src.main import app
from src.database import get_db, Base
from src import models

@pytest.fixture(scope="function")
def test_db():
    """Create a test database for each test function"""
    # Create a temporary database file
    with tempfile.NamedTemporaryFile(delete=False, suffix='.db') as temp_file:
        temp_db_path = temp_file.name
    
    # Create engine for test database
    engine = create_engine(f"sqlite:///{temp_db_path}", connect_args={"check_same_thread": False})
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    
    # Create all tables
    Base.metadata.create_all(bind=engine)
    
    # Override the get_db dependency
    def override_get_db():
        try:
            db = TestingSessionLocal()
            yield db
        finally:
            db.close()
    
    app.dependency_overrides[get_db] = override_get_db
    
    # Return the session for tests that need direct DB access
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()
        # Clean up
        app.dependency_overrides.clear()
        os.unlink(temp_db_path)

@pytest.fixture(scope="function")
def client(test_db):
    """Create a test client with isolated database"""
    return TestClient(app)
