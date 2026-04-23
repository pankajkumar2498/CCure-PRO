# SQLite → PostgreSQL Migration Guide

## Overview

Your CCure Audit PRO project is now configured to support both SQLite (development) and PostgreSQL (production). The application code requires **no schema redesign** because SQLAlchemy handles database portability automatically.

---

## Prerequisites

### 1. Install PostgreSQL
- **Windows**: [Download PostgreSQL](https://www.postgresql.org/download/windows/)
- **macOS**: `brew install postgresql@15`
- **Linux (Ubuntu)**: `sudo apt-get install postgresql postgresql-contrib`

### 2. Create Database & User

```bash
# Connect to PostgreSQL as admin
psql -U postgres

# Run these commands in psql:
CREATE DATABASE ccure_db;
CREATE USER ccure_user WITH PASSWORD 'ccure_password';
ALTER ROLE ccure_user SET client_encoding TO 'utf8';
ALTER ROLE ccure_user SET default_transaction_isolation TO 'read committed';
ALTER ROLE ccure_user SET default_transaction_deferrable TO on;
ALTER ROLE ccure_user SET timezone TO 'UTC';
GRANT ALL PRIVILEGES ON DATABASE ccure_db TO ccure_user;
\q
```

---

## Migration Steps

### Step 1: Update Python Dependencies

```bash
cd Backend
pip install -r requirements.txt
```

This installs:
- `psycopg2-binary==2.9.9` (PostgreSQL adapter)
- `python-dotenv==1.0.0` (environment config)

### Step 2: Set Up Environment Configuration

1. Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```

2. Edit `.env` and configure your PostgreSQL connection:
```ini
DATABASE_URL=postgresql://ccure_user:ccure_password@localhost:5432/ccure_db
JWT_SECRET_KEY=your-super-secret-key-here
LOG_LEVEL=INFO
```

**For AWS RDS example:**
```ini
DATABASE_URL=postgresql://admin:password@mydb.c123xyz.us-east-1.rds.amazonaws.com:5432/ccure_db
```

### Step 3: Migrate Your Data (If Needed)

If you have existing SQLite data you want to keep:

#### Option A: Export from SQLite → Import to PostgreSQL
```bash
# 1. Export SQLite data as SQL
sqlite3 Backend/ccure_users.db .dump > ccure_backup.sql

# 2. Create tables in PostgreSQL (app will do this)
# 3. Import data (you may need to adjust some SQL syntax)
```

#### Option B: Start Fresh with PostgreSQL
Simply delete your SQLite database and let the app create new PostgreSQL tables:
```bash
rm Backend/ccure_users.db
```

### Step 4: Start the Backend

```bash
cd Backend
python -m uvicorn main:app --reload
```

The app will automatically:
- Read `DATABASE_URL` from `.env`
- Create all tables in PostgreSQL
- Run any schema migrations in `ensure_auth_schema()` and `ensure_scan_schema()`

### Step 5: Verify the Migration

```bash
# Connect to PostgreSQL and verify tables
psql -U ccure_user -d ccure_db

# Inside psql, run:
\dt
\l
```

You should see:
```
 public | users                      | table | ccure_user
 public | refresh_token_sessions     | table | ccure_user
 public | scans                      | table | ccure_user
 public | scan_phase_results         | table | ccure_user
```

---

## Database Configuration Details

### SQLite (Development)
```ini
DATABASE_URL=sqlite:///./ccure_users.db
```
- File-based, no external server needed
- Good for local testing
- Limited concurrency

### PostgreSQL (Production)
```ini
DATABASE_URL=postgresql://user:password@host:port/database
```
- Server-based, scalable
- Supports multiple concurrent connections
- Connection pooling configured automatically

---

## Key Configuration Features

Your new `config.py` provides:

### Database Pooling (PostgreSQL only)
```python
"pool_size": 10,              # Max idle connections
"max_overflow": 20,           # Additional connections allowed  
"pool_recycle": 3600,         # Recycle old connections
"pool_pre_ping": True,        # Test connections before use
```

### Database Detection
```python
from config import AppConfig

if AppConfig.is_postgresql():
    # PostgreSQL-specific logic
else:
    # SQLite-specific logic
```

---

## Troubleshooting

### Error: "psycopg2: can't adapt type 'datetime.datetime'"
**Solution**: Ensure `sqlalchemy==2.0.30` is installed
```bash
pip install --upgrade sqlalchemy==2.0.30
```

### Error: "database 'ccure_db' does not exist"
**Solution**: Create the database first
```bash
psql -U postgres -c "CREATE DATABASE ccure_db;"
psql -U postgres -c "CREATE USER ccure_user WITH PASSWORD 'ccure_password';"
psql -U postgres -c "GRANT ALL PRIVILEGES ON DATABASE ccure_db TO ccure_user;"
```

### Error: "could not translate host name to address"
**Solution**: Check your DATABASE_URL hostname
```bash
# Test connection
psql -h localhost -U ccure_user -d ccure_db
```

### Error: "FATAL: Ident authentication failed"
**Solution**: Verify user/password in `.env`
```bash
# Correct format:
DATABASE_URL=postgresql://username:password@localhost:5432/dbname
```

---

## Performance Tips for PostgreSQL

### Connection Pooling
The app automatically enables connection pooling. For high-traffic scenarios, consider:
```python
# In config.py - adjust these values:
"pool_size": 20,        # Increase for more connections
"max_overflow": 30,     # Allow burst connections
```

### Query Optimization
PostgreSQL has excellent query analysis tools:
```sql
-- Explain a slow query
EXPLAIN ANALYZE SELECT * FROM scans WHERE user_id = 1;
```

### Backup Strategy
```bash
# Full database backup
pg_dump -U ccure_user -d ccure_db > ccure_backup.sql

# Restore from backup
psql -U ccure_user -d ccure_db < ccure_backup.sql
```

---

## Environment-Specific Configurations

### Development (.env)
```ini
DATABASE_URL=postgresql://ccure_user:password@localhost:5432/ccure_db
LOG_LEVEL=DEBUG
NMAP_TIMEOUT=600
```

### Staging (.env.staging)
```ini
DATABASE_URL=postgresql://user:pass@staging-db.example.com:5432/ccure_staging
LOG_LEVEL=INFO
NMAP_TIMEOUT=900
```

### Production (.env.production)
```ini
DATABASE_URL=postgresql://user:pass@prod-db.example.com:5432/ccure_prod
LOG_LEVEL=WARNING
NMAP_TIMEOUT=1200
```

Then load the correct file:
```bash
export $(cat .env.production | xargs)
python -m uvicorn main:app --host 0.0.0.0 --port 8000
```

---

## Summary

✅ **No schema redesign needed** — SQLAlchemy handles everything  
✅ **Backward compatible** — SQLite still works for development  
✅ **Production-ready** — PostgreSQL with connection pooling  
✅ **Easy switching** — Just change `DATABASE_URL` environment variable  

Your app now supports enterprise-grade database infrastructure!
