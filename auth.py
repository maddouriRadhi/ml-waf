"""
Authentication Module for ML-WAF
User management and authentication functionality
"""

import hashlib
import secrets
from datetime import datetime, timedelta
from database_config import db_manager
import logging

logger = logging.getLogger(__name__)

class AuthManager:
    """Authentication manager for user handling"""
    
    def __init__(self):
        self.db_manager = db_manager
        self.create_users_table()
        self.create_default_admin()
    
    def create_users_table(self):
        """Create users table if it doesn't exist"""
        try:
            query = """
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                email VARCHAR(100) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                salt VARCHAR(32) NOT NULL,
                role VARCHAR(20) DEFAULT 'user',
                is_active BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP,
                login_attempts INTEGER DEFAULT 0,
                locked_until TIMESTAMP
            );
            """
            self.db_manager.execute_query(query, fetch=False)
            logger.info("Users table created or already exists")
            return True
        except Exception as e:
            logger.error(f"Error creating users table: {e}")
            return False
    
    def create_default_admin(self):
        """Create default admin user if it doesn't exist"""
        try:
            # Check if admin user exists
            query = "SELECT id FROM users WHERE username = %s"
            result = self.db_manager.execute_query(query, ('admin',))
            
            if not result:
                # Create admin user with default password
                self.create_user(
                    username='admin',
                    email='admin@waf.local',
                    password='admin123',
                    role='admin'
                )
                logger.info("Default admin user created (username: admin, password: admin123)")
            return True
        except Exception as e:
            logger.error(f"Error creating default admin: {e}")
            return False
    
    def hash_password(self, password, salt=None):
        """Hash password with salt"""
        if salt is None:
            salt = secrets.token_hex(16)
        
        password_hash = hashlib.sha256((password + salt).encode()).hexdigest()
        return password_hash, salt
    
    def create_user(self, username, email, password, role='user'):
        """Create a new user"""
        try:
            password_hash, salt = self.hash_password(password)
            
            query = """
            INSERT INTO users (username, email, password_hash, salt, role)
            VALUES (%s, %s, %s, %s, %s)
            """
            params = (username, email, password_hash, salt, role)
            self.db_manager.execute_query(query, params, fetch=False)
            
            logger.info(f"User '{username}' created successfully")
            return True
        except Exception as e:
            logger.error(f"Error creating user: {e}")
            return False
    
    def authenticate_user(self, username, password):
        """Authenticate user credentials"""
        try:
            # Check if user is locked
            query = """
            SELECT id, username, email, password_hash, salt, role, is_active, 
                   login_attempts, locked_until, last_login
            FROM users WHERE username = %s
            """
            result = self.db_manager.execute_query(query, (username,))
            
            if not result:
                return False, "Invalid username or password"
            
            user = result[0]
            
            # Check if user is active
            if not user['is_active']:
                return False, "Account is disabled"
            
            # Check if account is locked
            if user['locked_until'] and datetime.now() < user['locked_until']:
                return False, "Account is temporarily locked"
            
            # Verify password
            password_hash, salt = self.hash_password(password, user['salt'])
            
            if password_hash != user['password_hash']:
                # Increment login attempts
                self.increment_login_attempts(user['id'])
                return False, "Invalid username or password"
            
            # Reset login attempts and update last login
            self.reset_login_attempts(user['id'])
            self.update_last_login(user['id'])
            
            return user, "Login successful"
            
        except Exception as e:
            logger.error(f"Authentication error: {e}")
            return False, "Authentication failed"
    
    def increment_login_attempts(self, user_id):
        """Increment login attempts and lock account if necessary"""
        try:
            query = """
            UPDATE users 
            SET login_attempts = login_attempts + 1,
                locked_until = CASE 
                    WHEN login_attempts >= 4 THEN CURRENT_TIMESTAMP + INTERVAL '30 minutes'
                    ELSE NULL 
                END
            WHERE id = %s
            """
            self.db_manager.execute_query(query, (user_id,), fetch=False)
        except Exception as e:
            logger.error(f"Error incrementing login attempts: {e}")
    
    def reset_login_attempts(self, user_id):
        """Reset login attempts after successful login"""
        try:
            query = """
            UPDATE users 
            SET login_attempts = 0, locked_until = NULL
            WHERE id = %s
            """
            self.db_manager.execute_query(query, (user_id,), fetch=False)
        except Exception as e:
            logger.error(f"Error resetting login attempts: {e}")
    
    def update_last_login(self, user_id):
        """Update last login timestamp"""
        try:
            query = "UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = %s"
            self.db_manager.execute_query(query, (user_id,), fetch=False)
        except Exception as e:
            logger.error(f"Error updating last login: {e}")
    
    def get_user_by_id(self, user_id):
        """Get user by ID"""
        try:
            query = """
            SELECT id, username, email, role, is_active, created_at, last_login
            FROM users WHERE id = %s
            """
            result = self.db_manager.execute_query(query, (user_id,))
            return result[0] if result else None
        except Exception as e:
            logger.error(f"Error getting user by ID: {e}")
            return None
    
    def get_user_by_username(self, username):
        """Get user by username"""
        try:
            query = """
            SELECT id, username, email, role, is_active, created_at, last_login
            FROM users WHERE username = %s
            """
            result = self.db_manager.execute_query(query, (username,))
            return result[0] if result else None
        except Exception as e:
            logger.error(f"Error getting user by username: {e}")
            return None
    
    def change_password(self, user_id, new_password):
        """Change user password"""
        try:
            password_hash, salt = self.hash_password(new_password)
            
            query = """
            UPDATE users 
            SET password_hash = %s, salt = %s, login_attempts = 0, locked_until = NULL
            WHERE id = %s
            """
            params = (password_hash, salt, user_id)
            self.db_manager.execute_query(query, params, fetch=False)
            
            logger.info(f"Password changed for user ID: {user_id}")
            return True
        except Exception as e:
            logger.error(f"Error changing password: {e}")
            return False

# Global auth manager instance
auth_manager = AuthManager()
