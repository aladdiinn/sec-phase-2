from flask import Flask
from flask_sqlalchemy import SQLAlchemy  # type: ignore
from sqlalchemy import text

# Initialize the SQLAlchemy object
db = SQLAlchemy()


def _safe_alter(session, sql: str):
    """Execute a single ALTER TABLE / CREATE INDEX statement safely.
    Each statement is isolated in its own savepoint so that one failure
    does not abort the entire migration transaction.
    """
    try:
        session.execute(text(sql))
        session.commit()
    except Exception as e:
        session.rollback()
        # Only log if it's not a harmless "already exists" / "duplicate column" error
        msg = str(e).lower()
        if "already exists" not in msg and "duplicate column" not in msg:
            print(f"[db-migration] WARNING: {e}")


def init_db(app: Flask):
    """
    Initialises the database schema.
    1. Creates any missing tables from ORM models (db.create_all).
    2. Applies ALTER TABLE migrations for every column added after initial deploy.
       Each statement is isolated — one failure will NOT block the rest.
    """
    with app.app_context():
        # ── 1. Create missing tables ───────────────────────────────────────────
        db.create_all()

        # ── 2. Per-column migrations ────────────────────────────────────────────
        s = db.session   # shorthand

        # ── users ──────────────────────────────────────────────────────────────
        _safe_alter(s, "ALTER TABLE users ADD COLUMN IF NOT EXISTS username VARCHAR(128) UNIQUE")
        _safe_alter(s, "ALTER TABLE users ADD COLUMN IF NOT EXISTS full_name VARCHAR(255)")
        _safe_alter(s, "ALTER TABLE users ADD COLUMN IF NOT EXISTS role VARCHAR(32) DEFAULT 'normal' NOT NULL")
        _safe_alter(s, "ALTER TABLE users ADD COLUMN IF NOT EXISTS is_admin BOOLEAN DEFAULT FALSE NOT NULL")
        _safe_alter(s, "ALTER TABLE users ADD COLUMN IF NOT EXISTS is_active BOOLEAN DEFAULT TRUE NOT NULL")
        _safe_alter(s, "ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login TIMESTAMP WITH TIME ZONE")
        _safe_alter(s, "ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_enabled BOOLEAN DEFAULT FALSE NOT NULL")
        _safe_alter(s, "ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_secret VARCHAR(64)")
        _safe_alter(s, "ALTER TABLE users ADD COLUMN IF NOT EXISTS created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()")

        # ── servers ─────────────────────────────────────────────────────────────
        _safe_alter(s, "ALTER TABLE servers ADD COLUMN IF NOT EXISTS ip_address VARCHAR(64)")
        _safe_alter(s, "ALTER TABLE servers ADD COLUMN IF NOT EXISTS os_info VARCHAR(255)")
        _safe_alter(s, "ALTER TABLE servers ADD COLUMN IF NOT EXISTS status VARCHAR(32) DEFAULT 'unknown'")
        _safe_alter(s, "ALTER TABLE servers ADD COLUMN IF NOT EXISTS role VARCHAR(32) DEFAULT 'none'")
        _safe_alter(s, "ALTER TABLE servers ADD COLUMN IF NOT EXISTS site VARCHAR(32) DEFAULT 'DC'")
        _safe_alter(s, "ALTER TABLE servers ADD COLUMN IF NOT EXISTS cluster_id VARCHAR(128)")
        _safe_alter(s, "ALTER TABLE servers ADD COLUMN IF NOT EXISTS is_maintenance BOOLEAN DEFAULT FALSE NOT NULL")
        _safe_alter(s, "ALTER TABLE servers ADD COLUMN IF NOT EXISTS maintenance_until TIMESTAMP WITH TIME ZONE")
        _safe_alter(s, "ALTER TABLE servers ADD COLUMN IF NOT EXISTS managed_services TEXT")
        _safe_alter(s, "ALTER TABLE servers ADD COLUMN IF NOT EXISTS last_seen TIMESTAMP WITH TIME ZONE")
        _safe_alter(s, "ALTER TABLE servers ADD COLUMN IF NOT EXISTS registered_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()")

        # ── events ──────────────────────────────────────────────────────────────
        _safe_alter(s, "ALTER TABLE events ADD COLUMN IF NOT EXISTS source VARCHAR(128)")
        _safe_alter(s, "ALTER TABLE events ADD COLUMN IF NOT EXISTS raw_data TEXT")

        # ── alerts ──────────────────────────────────────────────────────────────
        _safe_alter(s, "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS event_id INTEGER")
        _safe_alter(s, "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS mitre_tactic VARCHAR(128)")
        _safe_alter(s, "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS mitre_technique VARCHAR(128)")
        _safe_alter(s, "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS score INTEGER DEFAULT 0 NOT NULL")
        _safe_alter(s, "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS auto_promoted BOOLEAN DEFAULT FALSE NOT NULL")
        _safe_alter(s, "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS case_id INTEGER")
        _safe_alter(s, "ALTER TABLE alerts ADD COLUMN IF NOT EXISTS resolved_at TIMESTAMP WITH TIME ZONE")

        # ── alert_rules ─────────────────────────────────────────────────────────
        _safe_alter(s, "ALTER TABLE alert_rules ADD COLUMN IF NOT EXISTS playbook_id INTEGER")
        _safe_alter(s, "ALTER TABLE alert_rules ADD COLUMN IF NOT EXISTS threshold INTEGER DEFAULT 1")
        _safe_alter(s, 'ALTER TABLE alert_rules ADD COLUMN IF NOT EXISTS "window" INTEGER DEFAULT 60')
        _safe_alter(s, "ALTER TABLE alert_rules ADD COLUMN IF NOT EXISTS is_active BOOLEAN DEFAULT TRUE")

        # ── audit_logs ──────────────────────────────────────────────────────────
        _safe_alter(s, "ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS details TEXT")
        _safe_alter(s, "ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS ip_address VARCHAR(45)")
        _safe_alter(s, "ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS user_agent TEXT")

        # ── threat_indicators ───────────────────────────────────────────────────
        _safe_alter(s, "ALTER TABLE threat_indicators ADD COLUMN IF NOT EXISTS is_blocked BOOLEAN DEFAULT FALSE")

        # ── playbooks ───────────────────────────────────────────────────────────
        _safe_alter(s, "ALTER TABLE playbooks ADD COLUMN IF NOT EXISTS description TEXT")
        _safe_alter(s, "ALTER TABLE playbooks ADD COLUMN IF NOT EXISTS actions TEXT")
        _safe_alter(s, "ALTER TABLE playbooks ADD COLUMN IF NOT EXISTS is_active BOOLEAN DEFAULT TRUE")
        _safe_alter(s, "ALTER TABLE playbooks ADD COLUMN IF NOT EXISTS created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()")

        # ── cases ───────────────────────────────────────────────────────────────
        _safe_alter(s, "ALTER TABLE cases ADD COLUMN IF NOT EXISTS summary TEXT")
        _safe_alter(s, "ALTER TABLE cases ADD COLUMN IF NOT EXISTS assignee_id INTEGER")
        _safe_alter(s, "ALTER TABLE cases ADD COLUMN IF NOT EXISTS due_at TIMESTAMP WITH TIME ZONE")
        _safe_alter(s, "ALTER TABLE cases ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP WITH TIME ZONE")

        # ── notifications ───────────────────────────────────────────────────────
        _safe_alter(s, "ALTER TABLE notifications ADD COLUMN IF NOT EXISTS case_id INTEGER")
        _safe_alter(s, "ALTER TABLE notifications ADD COLUMN IF NOT EXISTS is_read BOOLEAN DEFAULT FALSE NOT NULL")

        # ── blocked_ips ─────────────────────────────────────────────────────────
        _safe_alter(s, "ALTER TABLE blocked_ips ADD COLUMN IF NOT EXISTS ttl_hours INTEGER")
        _safe_alter(s, "ALTER TABLE blocked_ips ADD COLUMN IF NOT EXISTS expires_at TIMESTAMP WITH TIME ZONE")
        _safe_alter(s, "ALTER TABLE blocked_ips ADD COLUMN IF NOT EXISTS firewalls TEXT")
        _safe_alter(s, "ALTER TABLE blocked_ips ADD COLUMN IF NOT EXISTS status VARCHAR(32) DEFAULT 'active'")
        _safe_alter(s, "ALTER TABLE blocked_ips ADD COLUMN IF NOT EXISTS incident_id INTEGER")

        # ── jira_configs ────────────────────────────────────────────────────────
        _safe_alter(s, "ALTER TABLE jira_configs ADD COLUMN IF NOT EXISTS provider VARCHAR(32) DEFAULT 'jira_cloud'")
        _safe_alter(s, "ALTER TABLE jira_configs ADD COLUMN IF NOT EXISTS auto_create VARCHAR(32) DEFAULT 'critical'")
        _safe_alter(s, "ALTER TABLE jira_configs ADD COLUMN IF NOT EXISTS status_map TEXT")
        _safe_alter(s, "ALTER TABLE jira_configs ADD COLUMN IF NOT EXISTS is_enabled BOOLEAN DEFAULT FALSE")
        _safe_alter(s, "ALTER TABLE jira_configs ADD COLUMN IF NOT EXISTS issue_type VARCHAR(64) DEFAULT 'Bug'")

        # ── case_tickets ─────────────────────────────────────────────────────────
        _safe_alter(s, "ALTER TABLE case_tickets ADD COLUMN IF NOT EXISTS ticket_url VARCHAR(512)")
        _safe_alter(s, "ALTER TABLE case_tickets ADD COLUMN IF NOT EXISTS ticket_status VARCHAR(64) DEFAULT 'Open'")
        _safe_alter(s, "ALTER TABLE case_tickets ADD COLUMN IF NOT EXISTS provider VARCHAR(32) DEFAULT 'jira_cloud'")
        _safe_alter(s, "ALTER TABLE case_tickets ADD COLUMN IF NOT EXISTS last_synced TIMESTAMP WITH TIME ZONE")
        _safe_alter(s, "ALTER TABLE case_tickets ADD COLUMN IF NOT EXISTS sync_error TEXT")

        # ── notification_routes ─────────────────────────────────────────────────
        _safe_alter(s, "ALTER TABLE notification_routes ADD COLUMN IF NOT EXISTS match_value VARCHAR(128)")
        _safe_alter(s, "ALTER TABLE notification_routes ADD COLUMN IF NOT EXISTS is_active BOOLEAN DEFAULT TRUE")

        # ── ── ── Performance Indexes ── ── ──────────────────────────────────────
        _safe_alter(s, "CREATE INDEX IF NOT EXISTS idx_events_server_id ON events(server_id)")
        _safe_alter(s, "CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(created_at DESC)")
        _safe_alter(s, "CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity)")
        _safe_alter(s, "CREATE INDEX IF NOT EXISTS idx_alerts_server_id ON alerts(server_id)")
        _safe_alter(s, "CREATE INDEX IF NOT EXISTS idx_alerts_is_resolved ON alerts(is_resolved)")
        _safe_alter(s, "CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp DESC)")
        _safe_alter(s, "CREATE INDEX IF NOT EXISTS idx_threat_indicators_value ON threat_indicators(value)")

        print("[db-migration] Schema migration complete.")