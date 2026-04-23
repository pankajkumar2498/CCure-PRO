# SQLite → PostgreSQL Migration - Changes Summary

## What Changed?

### 1. **New Files Created**

#### Backend/config.py
- Centralized configuration management
- Loads environment variables from `.env` file
- Handles both SQLite and PostgreSQL configurations
- Provides database engine kwargs based on database type
- Helper methods: `is_sqlite()`, `is_postgresql()`

#### Backend/.env.example
- Template for environment configuration
- Shows how to set DATABASE_URL for both SQLite and PostgreSQL
- Includes other configuration options (JWT, logging, etc.)

#### Backend/POSTGRESQL_MIGRATION.md
- Complete step-by-step migration guide
- Troubleshooting section
- Performance tips
- Database creation commands

### 2. **Updated Files**

#### Backend/requirements.txt
**Added:**
- `psycopg2-binary==2.9.9` — PostgreSQL adapter
- `python-dotenv==1.0.0` — Environment variable management

#### Backend/auth/models.py
**Changes:**
- Now imports `config.AppConfig` instead of using `os.getenv()`
- Uses `AppConfig.DATABASE_URL` and `AppConfig.DATABASE_ENGINE_KWARGS`
- `ensure_auth_schema()` now handles both SQLite and PostgreSQL SQL syntax
  - Uses `TIMESTAMP` for PostgreSQL, `DATETIME` for SQLite
  - Detects database type using `AppConfig.is_postgresql()`

#### Backend/scans/models.py
**Changes:**
- Updated docstring (no longer mentions hardcoded SQLite file)
- Imports `AppConfig` from config module
- `ensure_scan_schema()` now handles both database dialects:
  - Boolean defaults: `true` for PostgreSQL, `0` for SQLite
  - PRIMARY KEY syntax differences
  - Creates tables with correct dialect

---

## Database Architecture

### Before (SQLite Only)
```
DATABASE_URL=sqlite:///./ccure_users.db
(hardcoded in auth/models.py)
```

### After (SQLite + PostgreSQL)
```
SQLite:       DATABASE_URL=sqlite:///./ccure_users.db
PostgreSQL:   DATABASE_URL=postgresql://user:pass@host:5432/db
(configurable via .env)
```

---

## No Schema Changes Required!

Your database tables remain exactly the same:

```
users
├── id (Primary Key)
├── username
├── email
├── password_hash
├── created_at
└── updated_at

refresh_token_sessions
├── id (Primary Key)
├── user_id (Foreign Key → users.id)
├── token_jti
├── token_hash
├── issued_at
├── expires_at
├── revoked_at
└── replaced_by

scans
├── id (Primary Key)
├── user_id (Foreign Key → users.id)
├── target
├── targets_json
├── scan_type
├── pipeline_mode
├── phase
├── status
├── results
├── summary
├── report_json_path
├── report_xml_path
├── failure_reason
├── scan_duration
├── is_archived
├── archived_at
├── is_deleted
├── deleted_at
├── created_at
└── updated_at

scan_phase_results
├── id (Primary Key)
├── scan_id (Foreign Key → scans.id)
├── phase_key
├── phase_order
├── payload
├── created_at
└── updated_at
```

SQLAlchemy automatically handles:
- ✅ Type conversions (DATETIME → TIMESTAMP, etc.)
- ✅ Constraint syntax differences
- ✅ Auto-increment ID syntax
- ✅ Boolean field handling
- ✅ Index creation

---

## How It Works

### 1. Environment Configuration Flow
```
.env file
    ↓
config.py (AppConfig class)
    ↓
auth/models.py (create_engine)
    ↓
scans/models.py (schema migrations)
```

### 2. Database Type Detection
```python
from config import AppConfig

# Check which database is being used
if AppConfig.is_postgresql():
    # Use PostgreSQL-specific SQL
else:
    # Use SQLite-specific SQL
```

### 3. Connection Pooling (PostgreSQL Only)
```python
AppConfig.DATABASE_ENGINE_KWARGS = {
    "pool_pre_ping": True,       # Health check before use
    "pool_size": 10,             # Idle connections
    "max_overflow": 20,          # Burst connections
    "pool_recycle": 3600,        # Recycle old connections
}
```

---

## Migration Checklist

- [ ] **Update dependencies**: `pip install -r requirements.txt`
- [ ] **Create `.env` file**: `cp .env.example .env`
- [ ] **Edit `.env`**: Set `DATABASE_URL` to PostgreSQL connection string
- [ ] **Create PostgreSQL database**: Run commands from POSTGRESQL_MIGRATION.md
- [ ] **Start backend**: `python -m uvicorn main:app --reload`
- [ ] **Verify tables**: Connect to PostgreSQL and run `\dt`
- [ ] **Test API**: Make a test request to `/` endpoint

---

## Production Deployment Tips

### 1. Use AWS RDS PostgreSQL
```
DATABASE_URL=postgresql://admin:password@mydb.c123xyz.us-east-1.rds.amazonaws.com:5432/ccure_db
```

### 2. Use Environment Secrets
```bash
# Store in GitHub Secrets / environment variable manager
export DATABASE_URL=postgresql://...
```

### 3. Enable Connection Pooling
Already configured in `config.py` - works automatically!

### 4. Regular Backups
```bash
# Daily backup script
pg_dump -U ccure_user -d ccure_db > backup-$(date +%Y%m%d).sql
```

---

## Rollback to SQLite

If you need to go back to SQLite during development:

```ini
# Edit .env
DATABASE_URL=sqlite:///./ccure_users.db
```

That's it! Just change one line and restart.

---

## Summary

| Aspect | Before | After |
|--------|--------|-------|
| **Database** | SQLite only | SQLite + PostgreSQL |
| **Configuration** | Hardcoded | Environment variables |
| **Schema** | No changes | ✅ No changes needed |
| **Production Ready** | ❌ Limited | ✅ Enterprise-grade |
| **Scalability** | Single file | Distributed server |
| **Connection Pooling** | ❌ None | ✅ Automatic |
| **Multi-user Support** | Limited | ✅ Full support |

Your application is now ready for production deployment! 🚀
