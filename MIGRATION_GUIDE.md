# SQLite to PostgreSQL Migration Guide

This guide will help you migrate your ML-WAF database from SQLite3 to PostgreSQL for better performance, scalability, and production readiness.

## 🚀 Migration Overview

The migration process involves:
1. Setting up PostgreSQL database
2. Running the migration script to transfer data
3. Updating the application configuration
4. Testing the new setup

## 📋 Prerequisites

### 1. PostgreSQL Server
Ensure you have PostgreSQL installed and running:
- **Windows**: Download from [postgresql.org](https://www.postgresql.org/download/windows/)
- **Default credentials**: postgres/admin (configurable in `database_config.py`)

### 2. Python Dependencies
The required packages are already in `requirements.txt`:
```
psycopg2-binary==2.9.7
sqlalchemy==2.0.21
```

## 🗄️ Database Configuration

Current PostgreSQL configuration (in `database_config.py`):
```python
DB_CONFIG = {
    'host': 'localhost',
    'port': '5432',
    'database': 'waf_database',
    'user': 'postgres',
    'password': 'admin'
}
```

## 📝 Migration Steps

### Step 1: Install PostgreSQL
```bash
# On Windows (using chocolatey)
choco install postgresql

# Or download from https://www.postgresql.org/download/windows/
```

### Step 2: Start PostgreSQL Service
```bash
# Start PostgreSQL service
net start postgresql-x64-14  # Version may vary
```

### Step 3: Initialize PostgreSQL Database
```bash
python init_postgresql.py
```

### Step 4: Run Migration Script
```bash
python migrate_to_postgres.py
```

### Step 5: Verify Migration
The migration script will:
- ✅ Create a backup of your SQLite database
- ✅ Migrate all tables (users, requests, alerts)
- ✅ Preserve data integrity
- ✅ Create proper indexes
- ✅ Provide migration statistics

## 🔧 Configuration Updates

### Database Configuration
The application is already configured to use PostgreSQL. The `logger_module.py` has been updated to:
- Use PostgreSQL instead of SQLite
- Maintain the same API interface
- Support all existing functionality

### Environment Variables (Optional)
You can override database settings using environment variables:
```bash
set DB_HOST=localhost
set DB_PORT=5432
set DB_NAME=waf_database
set DB_USER=postgres
set DB_PASSWORD=admin
```

## 📊 Data Migration Details

### Tables Migrated
1. **users** - User accounts and authentication
2. **requests** - WAF request logs
3. **alerts** - Security alerts

### Data Types Converted
- `INTEGER PRIMARY KEY AUTOINCREMENT` → `SERIAL PRIMARY KEY`
- `datetime('now', '-N days')` → `NOW() - INTERVAL 'N days'`
- SQLite `?` placeholders → PostgreSQL `%s` placeholders

### Indexes Created
- `idx_requests_timestamp` - For time-based queries
- `idx_requests_ip` - For IP-based filtering
- `idx_alerts_timestamp` - For alert timeline
- `idx_alerts_ip` - For IP-based alert filtering

## 🧪 Testing the Migration

### 1. Test Database Connection
```python
from database_config import db_manager
print(db_manager.test_connection())  # Should return True
```

### 2. Test Logger
```python
from logger_module import WAFLogger
logger = WAFLogger()
logs = logger.get_recent_logs(10)
print(f"Retrieved {len(logs)} logs")
```

### 3. Test Authentication
```python
from auth import auth_manager
user, message = auth_manager.authenticate_user('admin', 'admin123')
print(f"Auth result: {user is not None}")
```

## 🚨 Troubleshooting

### Common Issues

#### 1. Connection Refused
```
Error: could not connect to server
```
**Solution**: Ensure PostgreSQL is running and accessible on localhost:5432

#### 2. Authentication Failed
```
Error: password authentication failed for user "postgres"
```
**Solution**: Verify PostgreSQL credentials in `database_config.py`

#### 3. Database Doesn't Exist
```
Error: database "waf_database" does not exist
```
**Solution**: Run `python init_postgresql.py` first

#### 4. Permission Denied
```
Error: permission denied for database
```
**Solution**: Grant proper permissions to the database user

### Migration Script Issues

#### SQLite Database Not Found
```
Error: SQLite database not found at logs/waf.db
```
**Solution**: Run the ML-WAF application at least once to create the SQLite database

#### Migration Fails Midway
The migration script creates backups automatically. Check the error logs and:
1. Fix the underlying issue
2. Restore from backup if needed
3. Re-run the migration

## 🔄 Rolling Back

If you need to rollback to SQLite:

1. **Stop the application**
2. **Restore logger_module.py** from backup
3. **Move the backup SQLite database** back to `logs/waf.db`
4. **Restart the application**

## 📈 Benefits of PostgreSQL

### Performance
- ✅ Better concurrent access handling
- ✅ Optimized query execution
- ✅ Efficient indexing strategies

### Scalability
- ✅ Supports larger datasets
- ✅ Better memory management
- ✅ Connection pooling

### Production Ready
- ✅ ACID compliance
- ✅ Point-in-time recovery
- ✅ Replication support
- ✅ Advanced security features

### Features
- ✅ Full-text search
- ✅ JSON support
- ✅ Advanced analytics
- ✅ Stored procedures

## 🛠️ Maintenance

### Regular Tasks
1. **Monitor database size**
2. **Set up automated backups**
3. **Monitor performance metrics**
4. **Update statistics regularly**

### Backup Commands
```bash
# Full backup
pg_dump -h localhost -U postgres waf_database > backup.sql

# Restore backup
psql -h localhost -U postgres waf_database < backup.sql
```

## 📞 Support

If you encounter issues during migration:

1. Check the PostgreSQL logs
2. Verify network connectivity
3. Ensure proper permissions
4. Review the migration script output

## ✅ Migration Checklist

- [ ] PostgreSQL installed and running
- [ ] Database credentials configured
- [ ] `init_postgresql.py` executed successfully
- [ ] `migrate_to_postgres.py` completed without errors
- [ ] Application starts without issues
- [ ] Dashboard loads correctly
- [ ] Historical data visible in logs
- [ ] New data being written to PostgreSQL
- [ ] Authentication working properly

---

**🎉 Migration Complete!** Your ML-WAF is now running on PostgreSQL with improved performance and scalability.
