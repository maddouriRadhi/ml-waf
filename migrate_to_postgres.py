#!/usr/bin/env python3
"""
Database Migration Script: SQLite3 to PostgreSQL
Migrates all data from SQLite database to PostgreSQL
"""

import sqlite3
import psycopg2
from psycopg2.extras import RealDictCursor
import os
import sys
from datetime import datetime
import logging

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# SQLite database path
SQLITE_DB_PATH = 'logs/waf.db'

# PostgreSQL configuration (from database_config.py)
DB_CONFIG = {
    'host': os.environ.get('DB_HOST', 'localhost'),
    'port': os.environ.get('DB_PORT', '5432'),
    'database': os.environ.get('DB_NAME', 'waf_database'),
    'user': os.environ.get('DB_USER', 'postgres'),
    'password': os.environ.get('DB_PASSWORD', 'admin')
}

class DatabaseMigrator:
    def __init__(self):
        self.sqlite_conn = None
        self.postgres_conn = None
        
    def connect_sqlite(self):
        """Connect to SQLite database"""
        try:
            if not os.path.exists(SQLITE_DB_PATH):
                logger.error(f"SQLite database not found at {SQLITE_DB_PATH}")
                return False
                
            self.sqlite_conn = sqlite3.connect(SQLITE_DB_PATH)
            self.sqlite_conn.row_factory = sqlite3.Row
            logger.info("Connected to SQLite database")
            return True
        except Exception as e:
            logger.error(f"Failed to connect to SQLite: {e}")
            return False
    
    def connect_postgres(self):
        """Connect to PostgreSQL database"""
        try:
            self.postgres_conn = psycopg2.connect(**DB_CONFIG)
            self.postgres_conn.autocommit = False
            logger.info("Connected to PostgreSQL database")
            return True
        except Exception as e:
            logger.error(f"Failed to connect to PostgreSQL: {e}")
            logger.error("Please ensure PostgreSQL is running and accessible with the configured credentials")
            return False
    
    def create_postgres_tables(self):
        """Create PostgreSQL tables with proper schema"""
        try:
            with self.postgres_conn.cursor() as cursor:
                # Create users table (if not exists)
                cursor.execute("""
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
                """)
                
                # Create requests table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS requests (
                        id SERIAL PRIMARY KEY,
                        timestamp TIMESTAMP NOT NULL,
                        ip VARCHAR(45) NOT NULL,
                        method VARCHAR(10),
                        url TEXT,
                        host VARCHAR(255),
                        ml_score REAL,
                        decision TEXT,
                        reason TEXT,
                        user_agent TEXT,
                        request_data TEXT
                    );
                """)
                
                # Create alerts table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS alerts (
                        id SERIAL PRIMARY KEY,
                        timestamp TIMESTAMP NOT NULL,
                        ip VARCHAR(45) NOT NULL,
                        alert_type TEXT,
                        severity TEXT,
                        message TEXT
                    );
                """)
                
                # Create indexes for better performance
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_requests_timestamp ON requests(timestamp)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_requests_ip ON requests(ip)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_ip ON alerts(ip)")
                
                self.postgres_conn.commit()
                logger.info("PostgreSQL tables created successfully")
                return True
                
        except Exception as e:
            self.postgres_conn.rollback()
            logger.error(f"Failed to create PostgreSQL tables: {e}")
            return False
    
    def migrate_users(self):
        """Migrate users table from SQLite to PostgreSQL"""
        try:
            sqlite_cursor = self.sqlite_conn.cursor()
            
            # Check if users table exists
            sqlite_cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
            if not sqlite_cursor.fetchone():
                logger.info("No users table found in SQLite database - skipping user migration")
                return True
            
            sqlite_cursor.execute("SELECT * FROM users")
            users = sqlite_cursor.fetchall()
            
            if not users:
                logger.info("No users found in SQLite database")
                return True
            
            with self.postgres_conn.cursor() as pg_cursor:
                for user in users:
                    pg_cursor.execute("""
                        INSERT INTO users 
                        (id, username, email, password_hash, salt, role, is_active, 
                         created_at, last_login, login_attempts, locked_until)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT (id) DO NOTHING
                    """, (
                        user['id'],
                        user['username'],
                        user['email'],
                        user['password_hash'],
                        user['salt'],
                        user['role'],
                        user['is_active'],
                        user['created_at'],
                        user['last_login'],
                        user['login_attempts'],
                        user['locked_until']
                    ))
                
                self.postgres_conn.commit()
                logger.info(f"Migrated {len(users)} users to PostgreSQL")
                return True
                
        except Exception as e:
            self.postgres_conn.rollback()
            logger.error(f"Failed to migrate users: {e}")
            return False
    
    def migrate_requests(self):
        """Migrate requests table from SQLite to PostgreSQL"""
        try:
            sqlite_cursor = self.sqlite_conn.cursor()
            sqlite_cursor.execute("SELECT * FROM requests")
            requests = sqlite_cursor.fetchall()
            
            if not requests:
                logger.info("No requests found in SQLite database")
                return True
            
            with self.postgres_conn.cursor() as pg_cursor:
                for request in requests:
                    pg_cursor.execute("""
                        INSERT INTO requests 
                        (id, timestamp, ip, method, url, host, ml_score, decision, 
                         reason, user_agent, request_data)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT (id) DO NOTHING
                    """, (
                        request['id'],
                        request['timestamp'],
                        request['ip'],
                        request['method'],
                        request['url'],
                        request['host'],
                        request['ml_score'],
                        request['decision'],
                        request['reason'],
                        request['user_agent'],
                        request['request_data']
                    ))
                
                self.postgres_conn.commit()
                logger.info(f"Migrated {len(requests)} requests to PostgreSQL")
                return True
                
        except Exception as e:
            self.postgres_conn.rollback()
            logger.error(f"Failed to migrate requests: {e}")
            return False
    
    def migrate_alerts(self):
        """Migrate alerts table from SQLite to PostgreSQL"""
        try:
            sqlite_cursor = self.sqlite_conn.cursor()
            sqlite_cursor.execute("SELECT * FROM alerts")
            alerts = sqlite_cursor.fetchall()
            
            if not alerts:
                logger.info("No alerts found in SQLite database")
                return True
            
            with self.postgres_conn.cursor() as pg_cursor:
                for alert in alerts:
                    pg_cursor.execute("""
                        INSERT INTO alerts 
                        (id, timestamp, ip, alert_type, severity, message)
                        VALUES (%s, %s, %s, %s, %s, %s)
                        ON CONFLICT (id) DO NOTHING
                    """, (
                        alert['id'],
                        alert['timestamp'],
                        alert['ip'],
                        alert['alert_type'],
                        alert['severity'],
                        alert['message']
                    ))
                
                self.postgres_conn.commit()
                logger.info(f"Migrated {len(alerts)} alerts to PostgreSQL")
                return True
                
        except Exception as e:
            self.postgres_conn.rollback()
            logger.error(f"Failed to migrate alerts: {e}")
            return False
    
    def get_sqlite_stats(self):
        """Get statistics from SQLite database"""
        try:
            sqlite_cursor = self.sqlite_conn.cursor()
            
            # Count tables and records
            stats = {}
            
            sqlite_cursor.execute("SELECT COUNT(*) FROM requests")
            stats['requests'] = sqlite_cursor.fetchone()[0]
            
            sqlite_cursor.execute("SELECT COUNT(*) FROM alerts")
            stats['alerts'] = sqlite_cursor.fetchone()[0]
            
            sqlite_cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0] for row in sqlite_cursor.fetchall()]
            stats['tables'] = tables
            
            return stats
            
        except Exception as e:
            logger.error(f"Failed to get SQLite stats: {e}")
            return {}
    
    def get_postgres_stats(self):
        """Get statistics from PostgreSQL database"""
        try:
            with self.postgres_conn.cursor() as cursor:
                stats = {}
                
                cursor.execute("SELECT COUNT(*) FROM requests")
                stats['requests'] = cursor.fetchone()[0]
                
                cursor.execute("SELECT COUNT(*) FROM alerts")
                stats['alerts'] = cursor.fetchone()[0]
                
                cursor.execute("SELECT tablename FROM pg_tables WHERE schemaname = 'public'")
                tables = [row[0] for row in cursor.fetchall()]
                stats['tables'] = tables
                
                return stats
                
        except Exception as e:
            logger.error(f"Failed to get PostgreSQL stats: {e}")
            return {}
    
    def migrate_all(self):
        """Perform complete migration"""
        logger.info("Starting database migration from SQLite to PostgreSQL")
        
        # Connect to both databases
        if not self.connect_sqlite():
            return False
        
        if not self.connect_postgres():
            return False
        
        try:
            # Show SQLite stats
            sqlite_stats = self.get_sqlite_stats()
            logger.info(f"SQLite database stats: {sqlite_stats}")
            
            # Create PostgreSQL tables
            if not self.create_postgres_tables():
                return False
            
            # Migrate data
            migration_steps = [
                ("users", self.migrate_users),
                ("requests", self.migrate_requests),
                ("alerts", self.migrate_alerts)
            ]
            
            for table_name, migrate_func in migration_steps:
                logger.info(f"Migrating {table_name}...")
                if not migrate_func():
                    logger.error(f"Failed to migrate {table_name}")
                    return False
            
            # Verify migration
            postgres_stats = self.get_postgres_stats()
            logger.info(f"PostgreSQL database stats: {postgres_stats}")
            
            logger.info("Migration completed successfully!")
            return True
            
        except Exception as e:
            logger.error(f"Migration failed: {e}")
            return False
        
        finally:
            # Close connections
            if self.sqlite_conn:
                self.sqlite_conn.close()
            if self.postgres_conn:
                self.postgres_conn.close()
    
    def backup_sqlite(self):
        """Create a backup of the SQLite database"""
        try:
            backup_path = f"logs/waf_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db"
            
            # Read SQLite database and create backup
            source = sqlite3.connect(SQLITE_DB_PATH)
            backup = sqlite3.connect(backup_path)
            
            source.backup(backup)
            
            source.close()
            backup.close()
            
            logger.info(f"SQLite database backed up to: {backup_path}")
            return backup_path
            
        except Exception as e:
            logger.error(f"Failed to backup SQLite database: {e}")
            return None

def main():
    """Main migration function"""
    print("=" * 60)
    print("SQLite to PostgreSQL Migration Tool")
    print("=" * 60)
    
    migrator = DatabaseMigrator()
    
    # Check if SQLite database exists
    if not os.path.exists(SQLITE_DB_PATH):
        print(f"Error: SQLite database not found at {SQLITE_DB_PATH}")
        print("Please ensure the WAF application has been run at least once to create the database.")
        return False
    
    # Create backup
    print("\n1. Creating backup of SQLite database...")
    backup_path = migrator.backup_sqlite()
    if not backup_path:
        print("Failed to create backup. Aborting migration.")
        return False
    
    # Perform migration
    print("\n2. Starting migration...")
    if migrator.migrate_all():
        print("\n3. Migration completed successfully!")
        print(f"\nNext steps:")
        print(f"1. Update the logger_module.py to use PostgreSQL instead of SQLite")
        print(f"2. Test the application with the new PostgreSQL database")
        print(f"3. If everything works, you can safely remove the SQLite database")
        print(f"4. Keep the backup file: {backup_path}")
        return True
    else:
        print("\n3. Migration failed!")
        print("Please check the error messages above and fix any issues.")
        print("Your original SQLite database is unchanged.")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
