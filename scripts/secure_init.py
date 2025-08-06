#!/usr/bin/env python3
"""
secure_init.py

Secure initialization script for the Elderly Care Home Alert Engine.
Creates default admin user and applies security configurations.
"""

import os
import sys
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Add src to path
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from src.database import Base
from src.models import User, AuditLog
from src.security import get_password_hash
from datetime import datetime

def create_secure_database():
    """Initialize database with security tables and default admin user"""
    
    # Database configuration
    db_path = os.getenv("DB_PATH", "sqlite:///./data/rules.db")
    engine = create_engine(db_path)
    
    # Create all tables
    Base.metadata.create_all(bind=engine)
    
    # Create session
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = SessionLocal()
    
    try:
        # Check if admin user already exists
        admin_user = db.query(User).filter(User.username == "admin").first()
        
        if not admin_user:
            # Create default admin user
            admin_password = os.getenv("ADMIN_PASSWORD", "AdminPass123!")
            hashed_password = get_password_hash(admin_password)
            
            admin_user = User(
                username="admin",
                email="admin@elderlycare.local",
                hashed_password=hashed_password,
                role="admin",
                is_active=True
            )
            
            db.add(admin_user)
            db.commit()
            db.refresh(admin_user)
            
            # Log admin creation
            audit_log = AuditLog(
                user_id=admin_user.id,
                action="CREATE_ADMIN_USER",
                ip_address="127.0.0.1",
                success=True,
                details="Default admin user created during initialization"
            )
            db.add(audit_log)
            db.commit()
            
            print("✅ Default admin user created:")
            print(f"   Username: admin")
            print(f"   Password: {admin_password}")
            print("   ⚠️  IMPORTANT: Change the default password immediately!")
        else:
            print("ℹ️  Admin user already exists")
        
        # Create other default users if needed
        users_to_create = [
            ("operator", "operator@elderlycare.local", "operator", "OperatorPass123!"),
            ("viewer", "viewer@elderlycare.local", "viewer", "ViewerPass123!")
        ]
        
        for username, email, role, password in users_to_create:
            existing_user = db.query(User).filter(User.username == username).first()
            if not existing_user:
                hashed_password = get_password_hash(password)
                user = User(
                    username=username,
                    email=email,
                    hashed_password=hashed_password,
                    role=role,
                    is_active=True
                )
                db.add(user)
                print(f"✅ Created {role} user: {username}")
        
        db.commit()
        print("✅ Database initialization completed successfully")
        
    except Exception as e:
        print(f"❌ Error during database initialization: {e}")
        db.rollback()
        raise
    finally:
        db.close()

def setup_file_permissions():
    """Set secure file permissions"""
    try:
        # Secure .env file
        if os.path.exists('.env'):
            os.chmod('.env', 0o600)
            print("✅ Secured .env file permissions")
        
        # Secure data directory
        if not os.path.exists('data'):
            os.makedirs('data', mode=0o750)
        os.chmod('data', 0o750)
        print("✅ Secured data directory permissions")
        
        # Secure logs directory
        if not os.path.exists('logs'):
            os.makedirs('logs', mode=0o750)
        os.chmod('logs', 0o750)
        print("✅ Secured logs directory permissions")
        
    except Exception as e:
        print(f"⚠️  Warning: Could not set file permissions: {e}")

def validate_security_config():
    """Validate security configuration"""
    issues = []
    
    # Check JWT secret
    jwt_secret = os.getenv("JWT_SECRET_KEY", "")
    if len(jwt_secret) < 32:
        issues.append("JWT_SECRET_KEY should be at least 32 characters")
    
    # Check debug mode
    if os.getenv("DEBUG", "false").lower() == "true":
        issues.append("DEBUG mode is enabled - disable in production")
    
    # Check environment
    if os.getenv("ENVIRONMENT") != "production":
        issues.append("ENVIRONMENT should be set to 'production'")
    
    # Check allowed hosts
    allowed_hosts = os.getenv("ALLOWED_HOSTS", "")
    if "localhost" in allowed_hosts and os.getenv("ENVIRONMENT") == "production":
        issues.append("Remove localhost from ALLOWED_HOSTS in production")
    
    if issues:
        print("\n⚠️  Security Configuration Issues:")
        for issue in issues:
            print(f"   • {issue}")
        print()
    else:
        print("✅ Security configuration validation passed")

def main():
    """Main initialization function"""
    print("🔒 Elderly Care Home Alert Engine - Secure Initialization")
    print("=" * 60)
    
    # Load environment variables
    from dotenv import load_dotenv
    load_dotenv()
    
    # Setup file permissions
    setup_file_permissions()
    
    # Initialize secure database
    create_secure_database()
    
    # Validate security configuration
    validate_security_config()
    
    print("\n✅ Secure initialization completed!")
    print("\n📋 Next Steps:")
    print("   1. Change default passwords immediately")
    print("   2. Configure TLS/SSL certificates for production")
    print("   3. Set up proper firewall rules")
    print("   4. Configure backup and monitoring")
    print("   5. Review and update security configurations")

if __name__ == "__main__":
    main()
