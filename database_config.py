"""
PostgreSQL Database Configuration for ML-WAF
Connection management and database utilities
"""

import os
import psycopg2
from psycopg2.extras import RealDictCursor
from sqlalchemy import create_engine, MetaData
from sqlalchemy.orm import sessionmaker
from contextlib import contextmanager
import logging

# PostgreSQL Database Configuration
DB_CONFIG = {
    'host': os.environ.get('DB_HOST', 'localhost'),
    'port': os.environ.get('DB_PORT', '5432'),
    'database': os.environ.get('DB_NAME', 'waf_database'),
    'user': os.environ.get('DB_USER', 'postgres'),
    'password': os.environ.get('DB_PASSWORD', 'admin')
}

# Database URL for SQLAlchemy
DATABASE_URL = f"postgresql://{DB_CONFIG['user']}:{DB_CONFIG['password']}@{DB_CONFIG['host']}:{DB_CONFIG['port']}/{DB_CONFIG['database']}"

class PostgreSQLManager:
    """PostgreSQL database manager for ML-WAF"""
    
    def __init__(self):
        self.engine = create_engine(DATABASE_URL)
        self.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)
        self.logger = logging.getLogger(__name__)
    
    @contextmanager
    def get_connection(self):
        """Get a database connection context manager"""
        conn = None
        try:
            conn = psycopg2.connect(**DB_CONFIG)
            conn.autocommit = False
            yield conn
        except Exception as e:
            if conn:
                conn.rollback()
            self.logger.error(f"Database connection error: {e}")
            raise
        finally:
            if conn:
                conn.close()
    
    @contextmanager
    def get_cursor(self, cursor_factory=RealDictCursor):
        """Get a database cursor context manager"""
        with self.get_connection() as conn:
            try:
                cursor = conn.cursor(cursor_factory=cursor_factory)
                yield cursor
                conn.commit()
            except Exception as e:
                conn.rollback()
                self.logger.error(f"Database cursor error: {e}")
                raise
            finally:
                cursor.close()
    
    def test_connection(self):
        """Test database connection"""
        try:
            with self.get_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute("SELECT version();")
                    version = cursor.fetchone()
                    self.logger.info(f"Connected to PostgreSQL: {version[0]}")
                    return True
        except Exception as e:
            self.logger.error(f"Failed to connect to PostgreSQL: {e}")
            return False
    
    def execute_query(self, query, params=None, fetch=True):
        """Execute a SQL query"""
        try:
            with self.get_cursor() as cursor:
                cursor.execute(query, params)
                if fetch:
                    if cursor.description:
                        return cursor.fetchall()
                    return []
                return cursor.rowcount
        except Exception as e:
            self.logger.error(f"Query execution error: {e}")
            raise
    
    def execute_many(self, query, params_list):
        """Execute a query with multiple parameter sets"""
        try:
            with self.get_cursor() as cursor:
                cursor.executemany(query, params_list)
                return cursor.rowcount
        except Exception as e:
            self.logger.error(f"Batch execution error: {e}")
            raise

# Global database manager instance
db_manager = PostgreSQLManager()

# Convenience functions
def get_db_session():
    """Get a database session"""
    session = db_manager.SessionLocal()
    try:
        yield session
    finally:
        session.close()

def init_database():
    """Initialize database tables"""
    try:
        # This will be expanded based on the specific tables needed
        with db_manager.get_connection() as conn:
            with conn.cursor() as cursor:
                # Create extensions if needed
                cursor.execute("CREATE EXTENSION IF NOT EXISTS \"uuid-ossp\";")
                conn.commit()
        return True
    except Exception as e:
        logging.error(f"Database initialization error: {e}")
        return False
