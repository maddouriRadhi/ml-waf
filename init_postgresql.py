#!/usr/bin/env python3
"""
PostgreSQL Database Initialization Script for ML-WAF
Sets up the database with the specified credentials (postgres/admin)
"""

import psycopg2
import os
import logging
from database_config import DB_CONFIG, db_manager

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def create_database():
    """Create the database if it doesn't exist"""
    try:
        # Connect to PostgreSQL server (without specifying database)
        conn = psycopg2.connect(
            host=DB_CONFIG['host'],
            port=DB_CONFIG['port'],
            user=DB_CONFIG['user'],
            password=DB_CONFIG['password'],
            database='postgres'  # Default database
        )
        conn.autocommit = True
        cursor = conn.cursor()
        
        # Create database if it doesn't exist
        cursor.execute(f"SELECT 1 FROM pg_database WHERE datname = '{DB_CONFIG['database']}'")
        if not cursor.fetchone():
            cursor.execute(f'CREATE DATABASE {DB_CONFIG["database"]}')
            logger.info(f"Database '{DB_CONFIG['database']}' created successfully")
        else:
            logger.info(f"Database '{DB_CONFIG['database']}' already exists")
        
        cursor.close()
        conn.close()
        return True
    except Exception as e:
        logger.error(f"Error creating database: {e}")
        return False

def initialize_tables():
    """Initialize all database tables and indexes"""
    try:
        logger.info("Initializing database tables...")
        
        # Test connection first
        if not db_manager.test_connection():
            logger.error("Failed to connect to database")
            return False
        
        # Initialize database (this will create tables and indexes)
        from logger_module import WAFLogger
        waf_logger = WAFLogger()
        
        logger.info("Database tables initialized successfully")
        return True
    except Exception as e:
        logger.error(f"Error initializing tables: {e}")
        return False

def setup_permissions():
    """Set up appropriate permissions for the database"""
    try:
        logger.info("Setting up database permissions...")
        
        # Connect to the database
        conn = psycopg2.connect(**DB_CONFIG)
        conn.autocommit = True
        cursor = conn.cursor()
        
        # Grant necessary permissions
        cursor.execute(f"GRANT ALL PRIVILEGES ON DATABASE {DB_CONFIG['database']} TO {DB_CONFIG['user']}")
        
        cursor.close()
        conn.close()
        
        logger.info("Database permissions set successfully")
        return True
    except Exception as e:
        logger.error(f"Error setting permissions: {e}")
        return False

def main():
    """Main initialization function"""
    logger.info("Starting PostgreSQL database initialization for ML-WAF")
    logger.info(f"Database: {DB_CONFIG['database']}")
    logger.info(f"User: {DB_CONFIG['user']}")
    logger.info(f"Host: {DB_CONFIG['host']}:{DB_CONFIG['port']}")
    
    # Step 1: Create database
    if not create_database():
        logger.error("Failed to create database")
        return False
    
    # Step 2: Initialize tables
    if not initialize_tables():
        logger.error("Failed to initialize tables")
        return False
    
    # Step 3: Setup permissions
    if not setup_permissions():
        logger.error("Failed to setup permissions")
        return False
    
    logger.info("PostgreSQL database initialization completed successfully!")
    return True

if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)
