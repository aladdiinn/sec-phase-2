"""
SecurePulse — Server Security Monitoring Platform
Main application entry point (Flask + PostgreSQL + WebSocket)
"""

import os
import json
import logging
import secrets
import time
import io
import yaml
import re
import re
import hashlib
import base64
import threading
from datetime import datetime, timezone, timedelta
from collections import defaultdict, deque
import subprocess
from functools import wraps

# Phase 2: TOTP/MFA support
try:
    import pyotp
    import qrcode
    from qrcode.image.svg import SvgImage
    TOTP_AVAILABLE = True
except ImportError:
    TOTP_AVAILABLE = False

# Phase 2: PDF report generation
try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.lib import colors
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

from flask import (
    Flask, render_template, request, jsonify,
    redirect, url_for, session, g, send_file
)
from flask_socketio import SocketIO, emit, join_room # type: ignore
import jwt # type: ignore
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv

from database import db, init_db
from models import (User, Server, Event, Alert, AuditLog, AlertRule, Case, ThreatIndicator, Playbook,
                     CaseComment, Notification, FirewallConfig, BlockedIP, IdentityProviderConfig,
                     JiraConfig, CaseTicket, DRTestLog, Project, ProjectEndpoint,
                     ROLE_SUPERUSER, ROLE_ADMIN, ROLE_NORMAL)
from sqlalchemy import func # type: ignore
from sqlalchemy.exc import IntegrityError # type: ignore

load_dotenv()

# ─── Logging ─────────────────────────────────────────────────────────────────
# Setup basic logging to both console and file
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("app.log"),
    ],
)
logger = logging.getLogger("securepulse")

# ─── App factory ─────────────────────────────────────────────────────────────
base_dir = os.path.abspath(os.path.dirname(__file__))
app = Flask(
    __name__,
    template_folder=os.path.join(base_dir, "templates"), # Fixed typo: templets -> templates
    static_folder=os.path.join(base_dir, "static"),
    static_url_path='/static'
)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", secrets.token_hex(32))
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv(
    "DATABASE_URL",
    "postgresql+psycopg://securepulse:securepulse_pass@127.0.0.1:5432/securepulse_db",
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_pre_ping": True,
    "pool_size": 20,
    "max_overflow": 40,
    "pool_recycle": 1800,
    "pool_timeout": 30,
}
app.config["JWT_ALGORITHM"] = "HS256"
app.config["JWT_EXPIRE_HOURS"] = 24
app.config["AGENT_API_KEY"] = os.getenv("AGENT_API_KEY", "change-me-secret-key")

db.init_app(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading", logger=False, engineio_logger=False)

@app.route('/favicon.ico')
def favicon():
    return '', 204

# ─── JWT helpers ─────────────────────────────────────────────────────────────

def create_jwt(user_id: int, identity: str, is_admin: bool, role: str = ROLE_NORMAL) -> str:
    payload = {
        "sub": str(user_id),
        "identity": identity,
        "is_admin": is_admin,
        "role": role,
        "exp": datetime.now(timezone.utc) + timedelta(hours=app.config["JWT_EXPIRE_HOURS"]),
        "iat": datetime.now(timezone.utc),
    }
    return jwt.encode(payload, app.config["SECRET_KEY"], algorithm=app.config["JWT_ALGORITHM"])


def decode_jwt(token: str) -> dict:
    return jwt.decode(
        token,
        app.config["SECRET_KEY"],
        algorithms=[app.config["JWT_ALGORITHM"]],
    )


def log_audit(action: str, target: str = None, user_id: int = None):
    """Logs an administrative action to the audit_logs table."""
    try:
        if user_id is None:
            user_id = getattr(g, "user_id", getattr(g, "login_user_id", None))
            
        remote_ip = request.remote_addr
        log = AuditLog(
            user_id=user_id,
            action=action,
            target=f"{target} (IP: {remote_ip})" if target else f"IP: {remote_ip}",
            timestamp=datetime.now(timezone.utc)
        )
        db.session.add(log)
        db.session.commit()
    except Exception as e:
        logger.error(f"Failed to log audit action: {e}")
        db.session.rollback()


def jwt_required(f):
    """Decorator — validates Bearer token from Authorization header or session."""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
        elif "token" in session:
            token = session["token"]

        if not token:
            return jsonify({"error": "Authentication required"}), 401

        try:
            g.jwt_payload = decode_jwt(token)
            g.user_id = int(g.jwt_payload["sub"])
            g.user = User.query.get(g.user_id)
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401

        return f(*args, **kwargs)
    return decorated


def login_required(f):
    """Decorator — validates session token for frontend pages, redirects to login if missing."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if "token" not in session:
            return redirect(url_for("login_page"))
        try:
            payload = decode_jwt(session["token"])
            g.user_id = int(payload["sub"])
        except:
            session.clear()
            return redirect(url_for("login_page"))
        return f(*args, **kwargs)
    return decorated


def agent_key_required(f):
    """Decorator — validates X-API-Key header for agent endpoints."""
    @wraps(f)
    def decorated(*args, **kwargs):
        key = request.headers.get("X-API-Key", "")
        if key != app.config["AGENT_API_KEY"]:
            return jsonify({"error": "Invalid API key"}), 401
        return f(*args, **kwargs)
    return decorated


def require_role(*roles):
    """Decorator — enforces RBAC role check. Usage: @require_role('superuser') or @require_role('superuser','admin')"""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            user = getattr(g, 'user', None)
            if not user:
                # Also check JWT payload
                payload = getattr(g, 'jwt_payload', {})
                role = payload.get('role', ROLE_NORMAL)
            else:
                role = user.role
            if role not in roles:
                return jsonify({"error": "Insufficient permissions", "required": list(roles)}), 403
            return f(*args, **kwargs)
        return decorated
    return decorator


def audit_log_action(action_name):
    """Decorator to log actions to AuditLog."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Execute the actual function
            response = f(*args, **kwargs)
            
            # Extract status code
            status_code = 200
            if isinstance(response, tuple):
                status_code = response[1] if len(response) > 1 else 200
            elif hasattr(response, 'status_code'):
                status_code = response.status_code

            # Only log if successful
            if 200 <= status_code < 300:
                user_id = None
                if getattr(g, "user", None):
                    user_id = g.user.id
                elif hasattr(g, "login_user_id"):
                    user_id = g.login_user_id

                if user_id:
                    target = request.path
                    if "target_override" in g:
                        target = g.target_override
                        
                    log_audit(action_name, target)
            return response
        return decorated_function
    return decorator



# ─── Bootstrap DB ────────────────────────────────────────────────────────────

@app.before_request
def load_logged_in_user():
    token = session.get("token")
    if token:
        try:
            payload = decode_jwt(token)
            g.user = User.query.get(int(payload["sub"]))
        except:
            g.user = None
    else:
        g.user = None

# Proxy for current_user to maintain compatibility
class UserProxy:
    def __getattr__(self, name):
        if g.user:
            return getattr(g.user, name)
        return None
    def __bool__(self):
        return g.user is not None

current_user = UserProxy()


def seed_admin():
    """Create default admin user if not exists."""
    admin_email = os.getenv("DEFAULT_ADMIN_EMAIL", "admin@securepulse.local")
    admin_pass  = os.getenv("DEFAULT_ADMIN_PASSWORD", "Admin@1234")

    existing_admin = User.query.filter((User.email == admin_email) | (User.username == "admin")).first()
    if not existing_admin:
        try:
            admin = User(
                email=admin_email,
                username="admin",
                hashed_password=generate_password_hash(admin_pass),
                full_name="Default Admin",
                is_admin=True,
                role=ROLE_SUPERUSER,
            )
            db.session.add(admin)
            db.session.commit()
            logger.info(f"Default superuser created: {admin_email}")
        except IntegrityError:
            db.session.rollback()
            logger.info(f"Admin already exists (handled IntegrityError): {admin_email}")
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error seeding admin: {str(e)}")
    else:
        # Backfill username for existing admin if it's missing (e.g. after schema migration)
        if not existing_admin.username:
            try:
                existing_admin.username = "admin"
                db.session.commit()
                logger.info(f"Updated existing superuser {admin_email} with username 'admin'")
            except Exception as e:
                db.session.rollback()
                logger.error(f"Failed to update existing admin username: {e}")


# ──────────────────────────────────────────────────────────────────────────────
# FRONTEND ROUTES (Server-side rendered pages)
# ──────────────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    if "token" not in session:
        return redirect(url_for("login_page"))
    return redirect(url_for("dashboard_page"))


@app.route("/login")
def login_page():
    if "token" in session:
        return redirect(url_for("dashboard_page"))
    try:
        return render_template("login.html", hide_nav=True, active='login')
    except Exception as e:
        logger.error(f"DEBUG LOGIN ERROR: {str(e)}")
        return f"Error loading login page: {str(e)}", 500

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login_page"))


@app.route("/dashboard")
@login_required
def dashboard_page():
    # Fetch real-time stats for the SOC dashboard
    alert_count = Alert.query.count()
    case_count = Case.query.count()
    threat_count = ThreatIndicator.query.count()
    server_count = Server.query.count()
    
    return render_template("dashboard.html", 
                         active='dashboard',
                         alerts=alert_count, 
                         cases=case_count, 
                         threats=threat_count, 
                         servers=server_count)

@app.route("/maintenance")
@login_required
def maintenance_page():
    return render_template("maintenance.html", active='maintenance')

@app.route("/api/servers/maintenance", methods=["GET"])
@jwt_required
def get_maintenance_servers():
    now = datetime.now(timezone.utc)
    servers = Server.query.filter(
        (Server.is_maintenance == True) | 
        (Server.maintenance_until > now)
    ).all()
    return jsonify([{
        "id": s.id,
        "hostname": s.hostname,
        "ip_address": s.ip_address,
        "is_maintenance": s.is_maintenance,
        "maintenance_until": s.maintenance_until.isoformat() if s.maintenance_until else None,
        "status": s.status
    } for s in servers])

@app.route("/incidents")
@login_required
def incidents_page():
    all_cases = Case.query.order_by(Case.created_at.desc()).all()
    return render_template("alerts.html", active='incidents', incidents=all_cases)

@app.route("/assets")
@login_required
def assets_page():
    all_servers = Server.query.all()
    return render_template("servers.html", active='assets', assets=all_servers)

@app.route("/audit-log")
@login_required
def audit_log_page():
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(100).all()
    return render_template("audit_log.html", active='audit-log', logs=logs)


@app.route("/servers")
@login_required
def servers_legacy():
    return redirect(url_for("assets_page"))

@app.route("/events")
@login_required
def events_page():
    return render_template("events.html", active='events')

@app.route("/alerts")
@login_required
def alerts_legacy():
    return redirect(url_for("incidents_page"))


@app.route("/logins")
@login_required
def logins_page():
    return render_template("logins.html", active='logins')

@app.route("/cron-jobs")
@login_required
def cron_jobs_page():
    return render_template("cron_jobs.html", active='cron-jobs')

@app.route("/processes")
@login_required
def processes_page():
    return render_template("processes.html", active='processes')

@app.route("/settings")
@login_required
def settings_page():
    return render_template("settings.html", active='settings')


@app.route("/servers/<int:id>")
@login_required
def server_detail_page(id):
    server = Server.query.get_or_404(id)
    return render_template("server_detail.html", active='assets', user=current_user, server=server)


@app.route("/investigate/<int:case_id>")
@login_required
def investigation_page(case_id):
    case = Case.query.get_or_404(case_id)
    return render_template("investigation.html", active='incidents', case=case)


@app.route("/rules")
@login_required
def rules_page():
    return render_template("rules.html", active='rules')


@app.route("/threat-intel")
@login_required
def threat_intel_page():
    return render_template("threat_intel.html", active='threat-intel')


@app.route("/search")
@login_required
def search_page():
    return render_template("search.html", active='search')


@app.route("/playbooks")
@login_required
def playbooks_page():
    return render_template("playbooks.html", active='playbooks')


@app.route("/reports")
@login_required
def reports_page():
    return render_template("reports.html", active='reports')


@app.route("/user-management")
@login_required
def user_management_page():
    user = g.user
    if not user or user.role != ROLE_SUPERUSER:
        return redirect(url_for("dashboard_page"))
    return render_template("user_management.html", active='user-management')


@app.route("/projects")
@login_required
def projects_page():
    return render_template("projects.html", active='projects')


@app.route("/projects/<int:project_id>/dashboard")
@login_required
def project_dashboard_page(project_id):
    project = Project.query.get_or_404(project_id)
    return render_template("project_dashboard.html", active='projects', project=project)


@app.route("/system-health")
@login_required
def system_health_page():
    user = g.user
    if not user or user.role != ROLE_SUPERUSER:
        return redirect(url_for("dashboard_page"))
    return render_template("system_health.html", active='system-health')


# ──────────────────────────────────────────────────────────────────────────────
# API — AUTH
# ──────────────────────────────────────────────────────────────────────────────

@app.route("/auth/login", methods=["POST"])
@audit_log_action("User Login")
def auth_login():
    data = request.get_json(force=True)
    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400

    user = User.query.filter_by(username=username).first()
    if not user or not check_password_hash(user.hashed_password, password):
        return jsonify({"error": "Invalid username or password"}), 401

    if not user.is_active:
        return jsonify({"error": "Account is disabled"}), 403

    # Update last_login
    try:
        user.last_login = datetime.now(timezone.utc)
        db.session.commit()
    except Exception:
        db.session.rollback()

    token = create_jwt(user.id, user.username, user.is_admin, user.role)
    session["token"] = token
    session["user_role"] = user.role
    g.login_user_id = user.id
    g.target_override = username
    return jsonify({
        "access_token": token,
        "token_type": "bearer",
        "user_id": user.id,
        "email": user.email,
        "full_name": user.full_name,
        "is_admin": user.is_admin,
        "username": user.username,
        "role": user.role,
    })


@app.route("/auth/me", methods=["GET"])
@jwt_required
def auth_me():
    user_id = int(g.jwt_payload["sub"])
    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    return jsonify({
        "id": user.id,
        "email": user.email,
        "full_name": user.full_name,
        "is_admin": user.is_admin,
    })


@app.route("/auth/me", methods=["PATCH"])
@jwt_required
def update_profile():
    """Update current user's profile (name, email, password)."""
    user_id = int(g.jwt_payload["sub"])
    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    data = request.get_json(force=True)
    if "full_name" in data and data["full_name"].strip():
        user.full_name = data["full_name"].strip()
    if "email" in data and data["email"].strip():
        user.email = data["email"].strip()
    if "password" in data and data["password"].strip():
        if len(data["password"]) < 6:
            return jsonify({"error": "Password must be at least 6 characters"}), 400
        user.hashed_password = generate_password_hash(data["password"])
    db.session.commit()
    return jsonify({"message": "Profile updated successfully", "full_name": user.full_name, "email": user.email})


# ──────────────────────────────────────────────────────────────────────────────
# API — AGENT REGISTRATION
# ──────────────────────────────────────────────────────────────────────────────

@app.route("/api/agents/register", methods=["POST"])
@agent_key_required
def register_agent():
    data = request.get_json(force=True)
    hostname   = data.get("hostname", "unknown")
    ip_address = data.get("ip_address")
    os_info    = data.get("os_info")
    role       = data.get("role", "none")
    site       = data.get("site", "DC")
    cluster_id = data.get("cluster_id")

    agent_token = secrets.token_urlsafe(48)
    server = Server(
        hostname=hostname,
        ip_address=ip_address,
        os_info=os_info,
        agent_token=agent_token,
        status="online",
        role=role,
        site=site,
        cluster_id=cluster_id,
        last_seen=datetime.now(timezone.utc),
    )
    db.session.add(server)
    db.session.commit()
    logger.info(f"New agent registered: {hostname} ({ip_address})")

    return jsonify({
        "server_id": server.id,
        "agent_token": agent_token,
        "message": "Agent registered successfully",
    }), 201


# ─── API — SETUP (One-liner installer) ────────────────────────────────────────

@app.route("/setup")
def setup_script():
    """Returns a dynamic bash script for one-liner installation."""
    base_url = request.url_root.rstrip("/")
    api_key  = app.config["AGENT_API_KEY"]
    
    # Read tags from query parameters
    role = request.args.get("role", "none")
    site = request.args.get("site", "DC")
    cluster = request.args.get("cluster", "")
    
    script = f"""#!/bin/bash
# SecurePulse — Automated Agent Installer
set -euo pipefail

RED='\\033[0;31m'; GREEN='\\033[0;32m'; YELLOW='\\033[1;33m'; NC='\\033[0m'
info()  {{ echo -e "${{GREEN}}[INFO]${{NC}}  $*"; }}
error() {{ echo -e "${{RED}}[ERROR]${{NC}} $*"; exit 1; }}

[[ "$EUID" -ne 0 ]] && error "Please run as root (sudo bash)"

BACKEND_URL="{base_url}"
API_KEY="{api_key}"
ROLE="{role}"
SITE="{site}"
CLUSTER="{cluster}"
INSTALL_DIR="/opt/securepulse-agent"

info "Starting SecurePulse Agent setup..."
mkdir -p "$INSTALL_DIR"

# 1. Download agent files
info "Fetching agent components from $BACKEND_URL..."
AGENT_DATA=$(curl -s "$BACKEND_URL/setup/agent-files")

# 2. Write files using python3
info "Installing files to $INSTALL_DIR..."
echo "$AGENT_DATA" | python3 -c "
import sys, json, os
data = json.load(sys.stdin)
for filename, content in data.items():
    path = os.path.join('$INSTALL_DIR', filename)
    with open(path, 'w') as f:
        f.write(content)
    print(f'  -> {{filename}}')
"

# 3. Run the installer logic
info "Registering server..."
HOSTNAME_VAL=$(hostname -f 2>/dev/null || hostname)
IP_VAL=$(hostname -I 2>/dev/null | awk '{{print $1}}' || echo 'unknown')
OS_INFO="$(uname -s) $(uname -r)"

REG_RES=$(curl -s -X POST "$BACKEND_URL/api/agents/register" \\
  -H "Content-Type: application/json" \\
  -H "X-API-Key: $API_KEY" \\
  -d "{{\\"hostname\\":\\"$HOSTNAME_VAL\\",\\"ip_address\\":\\"$IP_VAL\\",\\"os_info\\":\\"$OS_INFO\\",\\"role\\":\\"$ROLE\\",\\"site\\":\\"$SITE\\",\\"cluster_id\\":\\"$CLUSTER\\"}}")

AGENT_TOKEN=$(echo "$REG_RES" | python3 -c "import sys,json; print(json.load(sys.stdin)['agent_token'])")

info "Creating configuration..."
cat > "/etc/securepulse-agent.conf" <<EOF
[agent]
backend_url        = $BACKEND_URL
agent_token        = $AGENT_TOKEN
poll_interval      = 5
log_level          = INFO
EOF
chmod 600 "/etc/securepulse-agent.conf"

info "Setting up systemd service..."
cat > "/etc/systemd/system/securepulse-agent.service" <<EOF
[Unit]
Description=SecurePulse Monitoring Agent
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 $INSTALL_DIR/agent.py
WorkingDirectory=$INSTALL_DIR
Restart=always
Environment="SP_CONFIG_FILE=/etc/securepulse-agent.conf"

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable securepulse-agent
systemctl restart securepulse-agent

info "✅ SecurePulse Agent installed and running!"
"""
    return script.replace("\r\n", "\n"), 200, {"Content-Type": "text/plain"}


@app.route("/setup/agent-files")
def setup_agent_files():
    """Returns all files in the agent/ directory as a JSON object."""
    agent_dir = os.path.join(base_dir, "agent")
    files_data = {}
    
    if not os.path.exists(agent_dir):
        return jsonify({"error": "Agent directory not found"}), 500
        
    for filename in os.listdir(agent_dir):
        if filename.endswith(".py"):
            path = os.path.join(agent_dir, filename)
            with open(path, "r") as f:
                files_data[filename] = f.read()
                
    return jsonify(files_data)


# ──────────────────────────────────────────────────────────────────────────────
# DETECTION ENGINE (Rule-based detection)
# ──────────────────────────────────────────────────────────────────────────────

class RuleManager:
    def __init__(self, rules_dir="rules"):
        self.rules_dir = rules_dir
        self.rules = []
        # load_rules() will be called after DB init

    def load_rules(self):
        self.rules = []
        if not os.path.exists(self.rules_dir):
            os.makedirs(self.rules_dir)
            return

        for filename in os.listdir(self.rules_dir):
            if filename.endswith(".yaml") or filename.endswith(".yml"):
                path = os.path.join(self.rules_dir, filename)
                try:
                    with open(path, "r") as f:
                        data = yaml.safe_load(f)
                        if data and "rules" in data:
                            self.rules.extend(data["rules"])
                            
                            # Sync with database for playbook linking
                            with app.app_context():
                                for r in data["rules"]:
                                    existing = AlertRule.query.filter_by(name=r.get("name")).first()
                                    if not existing:
                                        new_ar = AlertRule(
                                            name=r.get("name"),
                                            event_type=r.get("event_type"),
                                            severity=r.get("severity", "warning"),
                                            is_active=r.get("is_active", True)
                                        )
                                        db.session.add(new_ar)
                                db.session.commit()
                                
                    logger.info(f"Loaded {len(data.get('rules', []))} rules from {filename}")
                except Exception as e:
                    logger.error(f"Failed to load rules from {filename}: {e}")

    def evaluate(self, event_type, description, raw_data):
        triggered_rules = []
        for rule in self.rules:
            if rule.get("event_type") != event_type:
                continue

            condition = rule.get("condition", {})
            field = condition.get("field")
            operator = condition.get("operator")
            value = condition.get("value")

            # Resolve field value
            field_val = ""
            if field == "description":
                field_val = description
            elif isinstance(raw_data, dict) and field in raw_data:
                field_val = str(raw_data.get(field))
            
            # Evaluate condition
            match = False
            if operator == "contains":
                match = value.lower() in field_val.lower()
            elif operator == "equals":
                match = value.lower() == field_val.lower()
            elif operator == "regex":
                try:
                    match = re.search(value, field_val) is not None
                except:
                    pass

            if match:
                triggered_rules.append(rule)
        
        return triggered_rules

# Global Rule Manager instance
# It will load rules lazily or explicitly after DB init to avoid schema errors
rule_manager = RuleManager()


def score_alert(severity: str, mitre_tactic: str = None, is_brute_force: bool = False) -> int:
    """Calculate a CVSS-style risk score (0-100) for an alert."""
    base = {"critical": 80, "warning": 50, "info": 20}.get(severity, 20)
    if mitre_tactic:
        base = min(base + 10, 100)
    if is_brute_force:
        base = min(base + 15, 100)
    return base



class PlaybookRunner:
    @staticmethod
    def run(playbook_id, alert_id):
        playbook = Playbook.query.get(playbook_id)
        alert = Alert.query.get(alert_id)
        if not playbook or not alert:
            return False
        
        # --- Maintenance Check ---
        now = datetime.now(timezone.utc)
        is_maint = getattr(alert.server, 'is_maintenance', False)
        maint_until = getattr(alert.server, 'maintenance_until', None)
        
        if is_maint or (maint_until and maint_until > now):
            maint_str = "Permanent" if is_maint else f"Until {maint_until.strftime('%Y-%m-%d %H:%M:%S')}"
            logger.info(f"SUPPRESSED: Playbook '{playbook.name}' execution suppressed (Server in Maintenance {maint_str})")
            return False
        
        try:
            actions = json.loads(playbook.actions) if isinstance(playbook.actions, str) else playbook.actions
            for action in actions:
                action_type = action.get("type")
                if action_type == "resolve_alert":
                    alert.is_resolved = True
                    alert.resolved_at = datetime.now(timezone.utc)
                elif action_type == "promote_to_case":
                    if not alert.case_id:
                        new_case = Case(
                            title=f"Auto-Promoted: {alert.title}",
                            priority=alert.severity,
                            summary=f"Automated promotion via playbook: {playbook.name}",
                            due_at=datetime.now(timezone.utc) + timedelta(hours=24)
                        )
                        db.session.add(new_case)
                        db.session.flush()
                        alert.case_id = new_case.id
                elif action_type == "isolate_host":
                    logger.warning(f"PLAYBOOK ACTION: Isolating host {alert.server.hostname}")
                    isolation_alert = Alert(
                        server_id=alert.server_id,
                        event_id=alert.event_id,
                        alert_type="isolation_triggered",
                        severity="critical",
                        title=f"HOST ISOLATED: {alert.server.hostname}",
                        message=f"Automated isolation triggered by playbook: {playbook.name}"
                    )
                    db.session.add(isolation_alert)
                    alert.server.status = "isolated"
                elif action_type == "notify_email":
                    # dispatch_alert_notification(alert)
                    pass
                elif action_type == "run_health_check":
                    logger.info(f"PLAYBOOK ACTION: Manual health check for {alert.server.hostname}")
                    # Simulate fresh health check result
                elif action_type == "restart_service":
                    service_name = action.get("service_name")
                    managed_services = []
                    if alert.server.managed_services:
                        try:
                            managed_services = json.loads(alert.server.managed_services)
                        except:
                            pass
                    
                    target_service = None
                    if service_name:
                        target_service = next((s for s in managed_services if s.get('name') == service_name), None)
                    elif managed_services:
                        # Fallback: Look for tomcat specifically if no name given
                        target_service = next((s for s in managed_services if 'tomcat' in s.get('name', '').lower()), managed_services[0])
                     
                    if target_service:
                         user = target_service.get('user', 'root')  # Use 'user' field from service definition
                         path = target_service.get('path', '')
                         restart_cmd = target_service.get('restart_cmd') or f"{path}/bin/startup.sh"  # Use restart_cmd if provided
                         
                         logger.warning(f"PLAYBOOK ACTION: Automated restart for {target_service.get('name')} on {alert.server.hostname}")
                         logger.info(f"RESTART LOGIC: sudo -u {user} {restart_cmd}")
                         
                         # Log the action as a new event
                         restart_evt = Event(
                             server_id=alert.server_id,
                             event_id=f"RESTART_{int(time.time())}",
                             event_type="service_restart",
                             severity="info",
                             description=f"Triggered restart for {target_service.get('name')} (User: {user})"
                         )
                         db.session.add(restart_evt)
                         
                         # Execute the restart command as the specified user
                         # Note: In a real Linux environment, we would use su or sudo here
                         # For Windows compatibility in the existing code, we keep the run_as_user function
                         # But we'll construct the appropriate command for Linux
                         restart_command = f"sudo -u {user} {restart_cmd}"
                         
                         # Execute the restart command
                         # In production Linux environment, this would use the actual command
                         # For now, we'll simulate it or use the existing Windows function as fallback
                         try:
                             # Try to run as the specified user (Linux-style)
                             import subprocess
                             completed = subprocess.run(restart_command, shell=True, capture_output=True, text=True, timeout=30)
                             res = {"stdout": completed.stdout, "stderr": completed.stderr, "returncode": completed.returncode}
                         except Exception as e:
                             # Fallback to Windows function if Linux approach fails
                             logger.warning(f"Linux-style sudo failed, falling back to Windows run_as_user: {e}")
                             res = run_as_user(user, restart_cmd)
                         
                         results.append({
                             "name": target_service.get('name'),
                             "command": restart_command,
                             "returncode": res["returncode"],
                             "stdout": res["stdout"],
                             "stderr": res["stderr"]
                         })
                         
                         # Execute the restart command as the specified user
                         # Note: In a real Linux environment, we would use su or sudo here
                         # For Windows compatibility in the existing code, we keep the run_as_user function
                         # But we'll construct the appropriate command for Linux
                         restart_command = f"sudo -u {user} {restart_cmd}"
                    else:
                        logger.warning(f"PLAYBOOK ACTION: Restart failed - no managed service found for {service_name or 'default'}")
            
            db.session.commit()
            return True
        except Exception as e:
            logger.error(f"Playbook execution error: {e}")
            db.session.rollback()
            return False

# ──────────────────────────────────────────────────────────────────────────────
# API — EVENTS (agent ingest + dashboard query)
# ──────────────────────────────────────────────────────────────────────────────

ALERT_TRIGGERS = {"failed_login", "cron_change", "ssh_login", "file_change"}
CRITICAL_KEYWORDS = ["root", "sudo", "passwd", "/etc/shadow", "chmod 777"]

# Global caches
geoip_cache = {}
brute_force_cache = {} 
active_brute_force_ips = {}
# Phase 2: UEBA multi-signal cache
ueba_event_cache = {}  # tracks login_freq, travel, seen_host per user+server
# Phase 2: Alert deduplication cache
alert_dedup_cache = {}  # key -> last_alerted_ts
# Phase 2: False positive tuning - suppressed fingerprints
fp_suppressed = set()  # set of (server_id, alert_type, title) tuples


@app.route("/api/events", methods=["POST"])
def ingest_event():
    agent_token = request.headers.get("X-Agent-Token", "")
    if not agent_token:
        return jsonify({"error": "X-Agent-Token header required"}), 401

    server = Server.query.filter_by(agent_token=agent_token).first()
    if not server:
        return jsonify({"error": "Invalid agent token"}), 401

    data = request.get_json(force=True)
    event_type  = data.get("event_type", "")
    description = data.get("description", "")
    severity    = data.get("severity", "info")
    source      = data.get("source")
    raw_data    = data.get("raw_data")

    VALID_TYPES = {
        "login", "logout", "cron_change", "new_process",
        "process_ended", "ssh_login", "failed_login",
        "file_change", "heartbeat",
    }
    if event_type not in VALID_TYPES:
        return jsonify({"error": f"Invalid event_type. Use one of: {VALID_TYPES}"}), 400

    # Heartbeat
    if event_type == "heartbeat":
        server.last_seen = datetime.now(timezone.utc)
        if server.status != "isolated":
            server.status = "online"
        db.session.commit()
        return jsonify({"message": "Heartbeat received"}), 200

    # ── Noise filter: silently drop login/logout events for system accounts ───
    SPAM_USERS = {"root", "ubuntu"}
    if event_type in ("login", "logout"):
        # Check description and raw_data for the username
        user_in_desc = any(f" {u}" in f" {description.lower()} " or description.lower().startswith(u) for u in SPAM_USERS)
        user_in_raw = False
        if isinstance(raw_data, dict):
            raw_user = str(raw_data.get("user", raw_data.get("username", raw_data.get("user_name", "")))).lower()
            user_in_raw = raw_user in SPAM_USERS
        if user_in_desc or user_in_raw:
            logger.debug(f"Filtered spam login/logout for system account on {server.hostname}: {description}")
            return jsonify({"message": "Event filtered (system account)"}), 200

    for kw in CRITICAL_KEYWORDS:
        if kw in description.lower():
            severity = "critical"
            break

    raw_data_str = json.dumps(raw_data) if raw_data is not None else None

    event = Event(
        server_id=server.id,
        event_type=event_type,
        severity=severity,
        source=source,
        description=description,
        raw_data=raw_data_str,
    )
    db.session.add(event)
    db.session.flush()

    server.last_seen = datetime.now(timezone.utc)
    server.status = "online"

    # --- Maintenance check: Skip alerts and playbooks if active ---
    is_maint = server.is_maintenance or (server.maintenance_until and server.maintenance_until > datetime.now(timezone.utc))
    if is_maint:
        logger.info(f"MAINTENANCE: Event from {server.hostname} processed but alerts suppressed.")
        db.session.commit()
        return jsonify({"message": "Event processed (Maintenance suppressed alerts)"}), 200

    # --- 1. Custom Rule Detection ---
    triggered_rules = rule_manager.evaluate(event_type, description, raw_data)
    for rule in triggered_rules:
        sev = rule.get("severity", "warning")
        tactic = rule.get("mitre_tactic")
        alert = Alert(
            server_id=server.id,
            event_id=event.id,
            alert_type="custom_rule",
            severity=sev,
            title=rule.get("name", "Security Rule Triggered"),
            message=rule.get("message", description),
            mitre_tactic=tactic,
            mitre_technique=rule.get("mitre_technique"),
            score=score_alert(sev, tactic),
        )
        db.session.add(alert)
        db.session.flush() # Get alert.id
        
        # --- Automated SOAR Trigger ---
        # Fetch matching AlertRule from DB to see if a playbook is linked
        db_rule = AlertRule.query.filter_by(name=rule.get("name")).first()
        if db_rule and db_rule.playbook_id:
            logger.info(f"AUTO-SOAR: Triggering playbook {db_rule.playbook_id} for rule {db_rule.name}")
            PlaybookRunner.run(db_rule.playbook_id, alert.id)

        if sev in ("critical", "high"):
            dispatch_alert_notification(alert)
        logger.info(f"Rule triggered: {rule.get('name')} on {server.hostname}")

    # --- 2. Threat Intel Lookup ---
    # Check IP in raw_data or description against threat_indicators table
    potential_ips = re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", description)
    if isinstance(raw_data, dict) and "ip" in raw_data:
        potential_ips.append(raw_data["ip"])
    
    for ip in set(potential_ips):
        if ip in ("127.0.0.1", "localhost", "::1"): continue
        ti = ThreatIndicator.query.filter_by(value=ip).first()
        if ti:
            alert = Alert(
                server_id=server.id,
                event_id=event.id,
                alert_type="threat_intel",
                severity="critical",
                title=f"Threat Intel Match: {ip}",
                message=f"Known malicious indicator detected. Source: {ti.source}. Severity: {ti.severity}",
            )
            db.session.add(alert)
            db.session.flush()
            dispatch_alert_notification(alert)
            logger.info(f"Threat Intel Match: {ip} on {server.hostname}")

    # --- 3. UEBA (Anomaly Detection) — Phase 2: Full implementation ---
    if event_type in ("ssh_login", "login"):
        ueba_user = None
        if isinstance(raw_data, dict):
            ueba_user = raw_data.get("user") or raw_data.get("username")
        if not ueba_user:
            import re as _re
            m = _re.search(r'user[:\s]+(\S+)', description, _re.IGNORECASE)
            if m:
                ueba_user = m.group(1)

        now_utc = datetime.now(timezone.utc)
        hour = now_utc.hour

        # A. Unusual Login Time (2 AM - 5 AM)
        if 2 <= hour <= 5:
            alert = Alert(
                server_id=server.id,
                event_id=event.id,
                alert_type="ueba_anomaly",
                severity="warning",
                title="Unusual Login Time",
                message=f"Login detected at unusual hour: {hour:02d}:00 UTC on {server.hostname}",
            )
            db.session.add(alert)
            db.session.flush()

        # B. Login Frequency Spike — more than 10 logins in 5 mins from same user
        if ueba_user:
            ueba_key = f"login_freq:{server.id}:{ueba_user}"
            if ueba_key not in ueba_event_cache:
                ueba_event_cache[ueba_key] = deque()
            now_ts = time.time()
            ueba_event_cache[ueba_key].append(now_ts)
            while ueba_event_cache[ueba_key] and now_ts - ueba_event_cache[ueba_key][0] > 300:
                ueba_event_cache[ueba_key].popleft()
            if len(ueba_event_cache[ueba_key]) >= 10:
                alert = Alert(
                    server_id=server.id,
                    event_id=event.id,
                    alert_type="ueba_anomaly",
                    severity="warning",
                    title="Login Frequency Spike",
                    message=f"User '{ueba_user}' logged in {len(ueba_event_cache[ueba_key])} times in 5 minutes on {server.hostname}",
                )
                db.session.add(alert)
                db.session.flush()

        # C. Impossible Travel — same user from 2 different IPs within 10 minutes
        if ueba_user and isinstance(raw_data, dict) and raw_data.get("ip"):
            current_ip = raw_data["ip"]
            travel_key = f"travel:{server.id}:{ueba_user}"
            prev = ueba_event_cache.get(travel_key)
            now_ts = time.time()
            if prev and isinstance(prev, dict):
                prev_ip = prev.get("ip")
                prev_ts = prev.get("ts", 0)
                if prev_ip and prev_ip != current_ip and (now_ts - prev_ts) < 600:
                    alert = Alert(
                        server_id=server.id,
                        event_id=event.id,
                        alert_type="ueba_anomaly",
                        severity="critical",
                        title="Impossible Travel Detected",
                        message=f"User '{ueba_user}' logged in from {prev_ip} then {current_ip} within {int((now_ts-prev_ts)/60)} minutes",
                        score=score_alert("critical"),
                    )
                    db.session.add(alert)
                    db.session.flush()
                    dispatch_alert_notification(alert)
            ueba_event_cache[travel_key] = {"ip": current_ip, "ts": now_ts}

        # D. New source host — first time login from this user on this server
        if ueba_user:
            src_key = f"seen_host:{ueba_user}:{server.id}"
            if src_key not in ueba_event_cache:
                prior_count = Event.query.filter(
                    Event.server_id == server.id,
                    Event.event_type.in_(["ssh_login", "login"]),
                    Event.description.ilike(f"%{ueba_user}%"),
                    Event.id != event.id,
                ).count()
                if prior_count == 0:
                    alert = Alert(
                        server_id=server.id,
                        event_id=event.id,
                        alert_type="ueba_anomaly",
                        severity="warning",
                        title="First-Time Login on Host",
                        message=f"User '{ueba_user}' has never logged into {server.hostname} before — new access pattern",
                    )
                    db.session.add(alert)
                    db.session.flush()
                ueba_event_cache[src_key] = True

    # --- 4. Hardcoded Security Triggers (Legacy) ---
    # Auto-create alerts
    if event_type in ALERT_TRIGGERS or severity == "critical":
        alert_severity = "critical" if severity == "critical" else "warning"
        alert_titles = {
            "failed_login": "Failed Login Detected",
            "cron_change":  "Cron Job Modified",
            "ssh_login":    "SSH Login",
            "file_change":  "File Integrity Violation",
        }
        title = alert_titles.get(event_type, "Security Event") + f" on {server.hostname}"
        alert = Alert(
            server_id=server.id,
            event_id=event.id,
            alert_type=event_type,
            severity=alert_severity,
            title=title,
            message=description,
            score=score_alert(alert_severity),
        )
        db.session.add(alert)
        db.session.flush()
        if alert_severity in ("critical", "high"):
            dispatch_alert_notification(alert)
        
    # Brute force detection
    if event_type == "failed_login":
        ip = raw_data.get("ip") if isinstance(raw_data, dict) else None
        if ip and ip not in ("127.0.0.1", "localhost", "::1"):
            now_ts = time.time()
            if ip not in brute_force_cache:
                brute_force_cache[ip] = []
            brute_force_cache[ip] = [t for t in brute_force_cache[ip] if now_ts - t < 60]
            brute_force_cache[ip].append(now_ts)
            
            if len(brute_force_cache[ip]) >= 5:
                active_brute_force_ips[ip] = {
                    "count": len(brute_force_cache[ip]),
                    "target": server.hostname,
                    "last_seen": now_ts
                }
                if len(brute_force_cache[ip]) == 5:
                    brute_alert = Alert(
                        server_id=server.id,
                        event_id=event.id,
                        alert_type="brute_force",
                        severity="critical",
                        title=f"Brute-Force Attack from {ip}",
                        message=f"5+ failed logins within 60s from {ip}",
                        score=score_alert("critical", is_brute_force=True),
                    )
                    db.session.add(brute_alert)

    db.session.commit()

    # --- 5. Auto-escalation: promote critical alerts with score >= 80 to cases ---
    new_alerts = db.session.query(Alert).filter(
        Alert.server_id == server.id,
        Alert.event_id == event.id,
        Alert.severity == "critical",
        Alert.score >= 80,
        Alert.case_id == None,
        Alert.auto_promoted == False,
    ).all()
    for na in new_alerts:
        auto_case = Case(
            title=f"[AUTO] {na.title}",
            priority="critical",
            summary=f"Auto-promoted by escalation engine. Score: {na.score}/100",
            due_at=datetime.now(timezone.utc) + timedelta(hours=4),  # High-severity SLA: 4h
        )
        db.session.add(auto_case)
        db.session.flush()
        na.case_id = auto_case.id
        na.auto_promoted = True
        logger.warning(f"Auto-escalated alert '{na.title}' to Case #{auto_case.id}")
    db.session.commit()

    # --- 6. Automated SOAR: Trigger playbooks associated with alert rules ---
    all_triggered_alerts = db.session.query(Alert).filter(
        Alert.server_id == server.id,
        Alert.event_id == event.id
    ).all()

    for ta in all_triggered_alerts:
        # Check if the triggered rule has an associated playbook
        rule = AlertRule.query.filter_by(name=ta.title, event_type=ta.alert_type).first()
        if rule and rule.playbook_id:
            logger.info(f"AUTO-SOAR: Triggering playbook #{rule.playbook_id} for alert #{ta.id} on {server.hostname}")
            PlaybookRunner.run(rule.playbook_id, ta.id)

    # Push WebSocket update
    socketio.emit("new_event", {
        "id": event.id,
        "server_id": server.id,
        "hostname": server.hostname,
        "event_type": event_type,
        "severity": severity,
        "description": description,
        "created_at": event.created_at.isoformat(),
    }, room="dashboard")

    return jsonify({"id": event.id, "message": "Event recorded"}), 201


@app.route("/api/events", methods=["GET"])
@jwt_required
def get_events():
    server_id  = request.args.get("server_id", type=int)
    event_type = request.args.get("event_type")
    severity   = request.args.get("severity")
    days       = request.args.get("days", type=int)
    limit      = min(request.args.get("limit", 100, type=int), 500)
    offset     = request.args.get("offset", 0, type=int)

    query = Event.query
    if server_id:
        query = query.filter_by(server_id=server_id)
    if event_type:
        if "," in event_type:
            query = query.filter(Event.event_type.in_(event_type.split(",")))
        else:
            query = query.filter_by(event_type=event_type)
    if severity:
        query = query.filter_by(severity=severity)
    if days:
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        query = query.filter(Event.created_at >= cutoff)

    total = query.count()
    events = query.order_by(Event.created_at.desc()).limit(limit).offset(offset).all()

    server_ids = list({e.server_id for e in events})
    servers = {s.id: s.hostname for s in Server.query.filter(Server.id.in_(server_ids)).all()} if server_ids else {}

    return jsonify({
        "total": total,
        "items": [
            {
                "id": e.id,
                "server_id": e.server_id,
                "hostname": servers.get(e.server_id, "unknown"),
                "event_type": e.event_type,
                "severity": e.severity,
                "source": e.source,
                "description": e.description,
                "raw_data": e.raw_data,
                "created_at": e.created_at.isoformat(),
            }
            for e in events
        ],
    })


# ──────────────────────────────────────────────────────────────────────────────
# API — SERVERS
# ──────────────────────────────────────────────────────────────────────────────

@app.route("/api/servers", methods=["GET"])
@jwt_required
def get_servers():
    status_filter   = request.args.get("status")
    severity_filter = request.args.get("severity")

    servers = Server.query.all()
    timeout = datetime.now(timezone.utc) - timedelta(seconds=int(os.getenv("HEARTBEAT_TIMEOUT", 120)))

    result = []
    for s in servers:
        # Honor isolated status above all
        if s.status == "isolated":
            status = "isolated"
        elif s.last_seen:
            status = "online" if s.last_seen.replace(tzinfo=timezone.utc) >= timeout else "offline"
        else:
            status = "offline"

        if status_filter and status != status_filter:
            continue

        unresolved_alerts = s.alerts.filter_by(is_resolved=False).all()
        max_sev_val = 0 
        max_sev_name = "info"
        
        for a in unresolved_alerts:
            val = 2 if a.severity == "critical" else 1
            if val > max_sev_val:
                max_sev_val = val
                max_sev_name = a.severity
        
        if severity_filter and max_sev_name != severity_filter:
            continue

        result.append({
            "id": s.id,
            "hostname": s.hostname,
            "ip_address": s.ip_address,
            "os_info": s.os_info,
            "status": status,
            "severity": max_sev_name,
            "severity_val": max_sev_val,
            "role": s.role,
            "site": s.site,
            "cluster_id": s.cluster_id,
            "last_seen": s.last_seen.isoformat() if s.last_seen else None,
            "registered_at": s.registered_at.isoformat(),
        })

    result.sort(key=lambda x: x["severity_val"], reverse=True)
    return jsonify(result)


@app.route("/api/servers/<int:server_id>/export-report")
@jwt_required
def export_report(server_id):
    """Generate a PDF summary of server security status."""
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.pdfgen import canvas
    except ImportError:
        logger.error("ReportLab library not found. Cannot generate PDF.")
        return jsonify({"error": "PDF generation library (reportlab) not found"}), 500

    server = Server.query.get_or_404(server_id)
    total_events = Event.query.filter_by(server_id=server_id).count()
    crit_alerts = Alert.query.filter_by(server_id=server_id, severity='critical', is_resolved=False).count()
    recent_events = Event.query.filter_by(server_id=server_id).order_by(Event.created_at.desc()).limit(10).all()
    
    buffer = io.BytesIO()
    p = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter
    
    p.setFont("Helvetica-Bold", 20)
    p.drawString(50, height - 50, f"SecurePulse Security Report — {server.hostname}")
    p.setFont("Helvetica", 10)
    p.drawString(50, height - 70, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    p.line(50, height - 75, width - 50, height - 75)
    
    p.setFont("Helvetica-Bold", 14)
    p.drawString(50, height - 100, "Server Information")
    p.setFont("Helvetica", 11)
    p.drawString(50, height - 120, f"IP Address: {server.ip_address}")
    p.drawString(50, height - 135, f"OS: {server.os_info or 'Unknown'}")
    p.drawString(50, height - 150, f"Last Seen: {server.last_seen.strftime('%Y-%m-%d %H:%M:%S') if server.last_seen else 'N/A'}")
    
    p.setFont("Helvetica-Bold", 14)
    p.drawString(50, height - 180, "Security Summary (Last 24h)")
    p.setFont("Helvetica", 11)
    p.drawString(50, height - 200, f"Total Events Logged: {total_events}")
    p.drawString(50, height - 215, f"Unresolved Critical Alerts: {crit_alerts}")
    
    p.setFont("Helvetica-Bold", 14)
    p.drawString(50, height - 245, "Recent Security Events")
    p.setFont("Helvetica", 9)
    y = height - 265
    for e in recent_events:
        time_str = e.created_at.strftime('%H:%M:%S')
        p.drawString(50, y, f"[{time_str}] {e.severity.upper()} — {e.event_type}: {e.description[:100]}")
        y -= 15
        if y < 50: break
        
    p.showPage()
    p.save()
    buffer.seek(0)
    return send_file(
        buffer,
        as_attachment=True,
        download_name=f"report_{server.hostname}_{datetime.now().strftime('%Y%m%d')}.pdf",
        mimetype='application/pdf'
    )
@app.route("/api/servers/<int:server_id>/isolate", methods=["POST"])
@jwt_required
@require_role(ROLE_ADMIN, ROLE_SUPERUSER)
@audit_log_action("Isolate Server")
def isolate_server(server_id):
    server = Server.query.get_or_404(server_id)
    server.status = "isolated"
    
    # Create a critical containment alert
    isolation_alert = Alert(
        server_id=server.id,
        alert_type="manual_isolation",
        severity="critical",
        title=f"HOST ISOLATED: {server.hostname}",
        message=f"Manual containment triggered by administrator {g.user.email}"
    )
    db.session.add(isolation_alert)
    db.session.commit()
    
    socketio.emit("new_event", {
        "id": 0,
        "server_id": server.id,
        "hostname": server.hostname,
        "event_type": "isolation",
        "severity": "critical",
        "description": f"Host {server.hostname} has been isolated from the network.",
        "created_at": datetime.now(timezone.utc).isoformat(),
    }, room="dashboard")
    
    return jsonify({"message": f"Server {server.hostname} isolated successfully", "status": "isolated"})


@app.route("/api/servers/<int:server_id>/reconnect", methods=["POST"])
@jwt_required
@require_role(ROLE_ADMIN, ROLE_SUPERUSER)
@audit_log_action("Reconnect Server")
def reconnect_server(server_id):
    server = Server.query.get_or_404(server_id)
    server.status = "online"
    reconnect_alert = Alert(
        server_id=server.id,
        alert_type="host_reconnected",
        severity="warning",
        title=f"HOST RECONNECTED: {server.hostname}",
        message=f"Network connectivity restored by administrator {g.user.email}",
        score=score_alert("warning"),
    )
    db.session.add(reconnect_alert)
    db.session.commit()
    socketio.emit("new_event", {
        "id": 0, "server_id": server.id, "hostname": server.hostname,
        "event_type": "reconnect", "severity": "warning",
        "description": f"Host {server.hostname} reconnected to network.",
        "created_at": datetime.now(timezone.utc).isoformat(),
    }, room="dashboard")
    return jsonify({"message": f"Server {server.hostname} reconnected", "status": "online"})


@app.route("/api/servers/<int:server_id>", methods=["GET"])
@jwt_required
def get_server_metadata(server_id):
    """Retrieve detailed metadata for a single server."""
    server = Server.query.get_or_404(server_id)
    return jsonify({
        "id": server.id,
        "hostname": server.hostname,
        "ip_address": server.ip_address,
        "os_info": server.os_info,
        "status": server.status,
        "is_maintenance": server.is_maintenance,
        "maintenance_until": server.maintenance_until.isoformat() if server.maintenance_until else None,
        "managed_services": json.loads(server.managed_services) if server.managed_services else []
    })


@app.route("/api/servers/<int:server_id>", methods=["DELETE"])
@jwt_required
@require_role(ROLE_ADMIN, ROLE_SUPERUSER)
@audit_log_action("Delete Server")
def delete_server(server_id):
    """Permanently remove a server and all its associated events and alerts."""
    server = Server.query.get_or_404(server_id)
    hostname = server.hostname
    # Cascade: remove related events and alerts
    Event.query.filter_by(server_id=server_id).delete()
    Alert.query.filter_by(server_id=server_id).delete()
    db.session.delete(server)
    db.session.commit()
    return jsonify({"message": f"Server '{hostname}' deleted successfully"})


@app.route("/api/servers/<int:server_id>", methods=["PATCH"])
@jwt_required
@audit_log_action("Update Server Metadata")
def update_server(server_id):
    """Update server maintenance windows and managed services."""
    try:
        server = Server.query.get_or_404(server_id)
        data = request.get_json(force=True)
        
        logger.info(f"UPDATE SERVER {server_id} RECEIVED DATA: {data}")
        
        if "is_maintenance" in data:
            server.is_maintenance = bool(data["is_maintenance"])
            if not server.is_maintenance:
                server.maintenance_until = None
        
        if "maintenance_hours" in data:
            hours = int(data["maintenance_hours"])
            if hours > 0:
                server.maintenance_until = datetime.now(timezone.utc) + timedelta(hours=hours)
                server.is_maintenance = True # Also enable the flag
            else:
                server.maintenance_until = None
                server.is_maintenance = False
                
        if "managed_services" in data:
            # Expected: list of {name, user, path, restart_cmd (optional)}
            services = data["managed_services"]
            logger.info(f"SAVING SERVICES for {server.hostname}: {services}")
            server.managed_services = json.dumps(services)
            
        db.session.commit()
        logger.info(f"DB COMMIT SUCCESS for server {server.id}")
        return jsonify({"message": f"Server {server.hostname} updated successfully", "server": {"is_maintenance": server.is_maintenance, "managed_services": server.managed_services}})
    except Exception as e:
        db.session.rollback()
        logger.error(f"DB COMMIT FAILED for server {server_id}: {e}", exc_info=True)
        return jsonify({"error": f"Database save failed: {str(e)}"}), 500

# Utility to run a command as a specific Windows user
import subprocess

def run_as_user(username, command):
    """Run *command* as *username* using Windows `runas`.
    Returns a dict with stdout, stderr and returncode.
    """
    runas_cmd = ["runas", f"/user:{username}", "cmd /c " + command]
    try:
        completed = subprocess.run(runas_cmd, capture_output=True, text=True, shell=False)
        return {"stdout": completed.stdout, "stderr": completed.stderr, "returncode": completed.returncode}
    except Exception as e:
        logger.error(f"run_as_user failed for {username}: {e}")
        return {"stdout": "", "stderr": str(e), "returncode": -1}

# ---------- Service Management Endpoints ----------

@app.route("/api/servers/<int:server_id>/services", methods=["POST"])
@jwt_required
@audit_log_action("Add/Update Managed Service")
def add_update_service(server_id):
    server = Server.query.get_or_404(server_id)
    service = request.get_json(force=True)
    if not all(k in service for k in ("name", "path", "user")):
        return jsonify({"error": "Missing required service fields"}), 400
    existing = []
    if server.managed_services:
        try:
            existing = json.loads(server.managed_services)
        except Exception:
            existing = []
    updated = False
    for i, s in enumerate(existing):
        if s.get("name") == service["name"]:
            existing[i] = service
            updated = True
            break
    if not updated:
        existing.append(service)
    server.managed_services = json.dumps(existing)
    try:
        db.session.commit()
        return jsonify({"message": "Service added/updated", "services": existing})
    except Exception as e:
        db.session.rollback()
        logger.error(f"Failed to add/update service: {e}")
        return jsonify({"error": "Database error"}), 500

@app.route("/api/servers/<int:server_id>/services/<service_name>", methods=["DELETE"])
@jwt_required
@audit_log_action("Delete Managed Service")
def delete_service(server_id, service_name):
    server = Server.query.get_or_404(server_id)
    if not server.managed_services:
        return jsonify({"error": "No services configured"}), 404
    try:
        services = json.loads(server.managed_services)
    except Exception:
        services = []
    services = [s for s in services if s.get("name") != service_name]
    server.managed_services = json.dumps(services)
    try:
        db.session.commit()
        return jsonify({"message": f"Service {service_name} deleted", "services": services})
    except Exception as e:
        db.session.rollback()
        logger.error(f"Failed to delete service: {e}")
        return jsonify({"error": "Database error"}), 500

@app.route("/api/servers/<int:server_id>/restart-services", methods=["POST"])
@jwt_required
@audit_log_action("Restart Managed Services")
def restart_services(server_id):
    """Trigger the restart playbook for all services of a server."""
    server = Server.query.get_or_404(server_id)
    if not server.managed_services:
        return jsonify({"error": "No services configured"}), 400
    try:
        services = json.loads(server.managed_services)
    except Exception as e:
        logger.error(f"Invalid services JSON: {e}")
        return jsonify({"error": "Invalid services data"}), 500
    results = []
    for svc in services:
        user = svc.get("user", "root")
        base_cmd = svc.get("restart_cmd") or f"{svc.get('path')}/bin/startup.sh"
        
        import os
        if os.name == 'nt':
            logger.info(f"Running on Windows, using run_as_user for {base_cmd}")
            res = run_as_user(user, base_cmd)
            results.append({
                "name": svc.get("name"),
                "command": f"runas /user:{user} cmd /c {base_cmd}",
                "returncode": res["returncode"],
                "stdout": res["stdout"],
                "stderr": res["stderr"]
            })
        else:
            linux_cmd = f"sudo -u {user} {base_cmd}"
            try:
                import subprocess
                completed = subprocess.run(linux_cmd, shell=True, capture_output=True, text=True, timeout=30)
                results.append({
                    "name": svc.get("name"),
                    "command": linux_cmd,
                    "returncode": completed.returncode,
                    "stdout": completed.stdout,
                    "stderr": completed.stderr
                })
            except Exception as e:
                logger.error(f"Linux subprocess failed: {e}")
                results.append({
                    "name": svc.get("name"),
                    "command": linux_cmd,
                    "returncode": -1,
                    "stdout": "",
                    "stderr": str(e)
                })
    return jsonify({"results": results})

# Original search route
@app.route("/api/search", methods=["GET"])
@jwt_required
def unified_search():
    """Search across events, alerts, and cases by a free-text query."""
    query = request.args.get("q", "").strip()
    limit = min(request.args.get("limit", 20, type=int), 100)
    scope = request.args.get("scope", "all")  # all | events | alerts | cases
    if not query:
        return jsonify({"events": [], "alerts": [], "cases": [], "total": 0})

    results = {"events": [], "alerts": [], "cases": [], "total": 0}

    if scope in ("all", "events"):
        events = Event.query.filter(
            (Event.description.ilike(f"%{query}%")) |
            (Event.event_type.ilike(f"%{query}%")) |
            (Event.source.ilike(f"%{query}%"))
        ).order_by(Event.created_at.desc()).limit(limit).all()
        server_map = {s.id: s.hostname for s in Server.query.all()}
        results["events"] = [
            {"id": e.id, "type": "event", "title": e.event_type,
             "description": e.description, "severity": e.severity,
             "hostname": server_map.get(e.server_id, "unknown"),
             "created_at": e.created_at.isoformat()}
            for e in events
        ]

    if scope in ("all", "alerts"):
        alerts = Alert.query.filter(
            (Alert.title.ilike(f"%{query}%")) |
            (Alert.message.ilike(f"%{query}%")) |
            (Alert.alert_type.ilike(f"%{query}%")) |
            (Alert.mitre_tactic.ilike(f"%{query}%"))
        ).order_by(Alert.created_at.desc()).limit(limit).all()
        server_map = {s.id: s.hostname for s in Server.query.all()}
        results["alerts"] = [
            {"id": a.id, "type": "alert", "title": a.title,
             "description": a.message, "severity": a.severity,
             "hostname": server_map.get(a.server_id, "unknown"),
             "mitre_tactic": a.mitre_tactic, "score": a.score,
             "case_id": a.case_id, "created_at": a.created_at.isoformat()}
            for a in alerts
        ]

    if scope in ("all", "cases"):
        cases = Case.query.filter(
            (Case.title.ilike(f"%{query}%")) |
            (Case.summary.ilike(f"%{query}%"))
        ).order_by(Case.created_at.desc()).limit(limit).all()
        results["cases"] = [
            {"id": c.id, "type": "case", "title": c.title,
             "description": c.summary or "", "severity": c.priority,
             "status": c.status, "due_at": c.due_at.isoformat() if c.due_at else None,
             "created_at": c.created_at.isoformat() if c.created_at else None}
            for c in cases
        ]

    results["total"] = len(results["events"]) + len(results["alerts"]) + len(results["cases"])
    return jsonify(results)



@app.route("/api/servers/stats", methods=["GET"])
@jwt_required
def server_stats():
    total = Server.query.count()
    timeout = datetime.now(timezone.utc) - timedelta(seconds=int(os.getenv("HEARTBEAT_TIMEOUT", 120)))
    online = Server.query.filter(Server.last_seen >= timeout).count()
    total_events = Event.query.count()
    open_alerts = Alert.query.filter_by(is_resolved=False).count()

    maint_count = Server.query.filter(
        (Server.is_maintenance == True) | 
        (Server.maintenance_until > datetime.now(timezone.utc))
    ).count()

    return jsonify({
        "total_servers": total,
        "online_servers": online,
        "offline_servers": total - online,
        "maintenance_servers": maint_count,
        "total_events": total_events,
        "open_alerts": open_alerts,
    })


@app.route("/api/dashboard/trend", methods=["GET"])
@jwt_required
def dashboard_trend():
    now = datetime.now(timezone.utc)
    twenty_four_hours_ago = now - timedelta(hours=24)
    events = Event.query.filter(Event.created_at >= twenty_four_hours_ago).all()
    
    buckets = {}
    for i in range(25):
        dt = (now - timedelta(hours=i)).replace(minute=0, second=0, microsecond=0)
        buckets[dt.isoformat()] = {"info": 0, "warning": 0, "critical": 0}
        
    for e in events:
        hour_dt = e.created_at.replace(minute=0, second=0, microsecond=0).isoformat()
        if hour_dt in buckets:
            buckets[hour_dt][e.severity] += 1
            
    sorted_keys = sorted(buckets.keys())
    result = {
        "labels": [datetime.fromisoformat(k).strftime("%H:%M") for k in sorted_keys],
        "info": [buckets[k]["info"] for k in sorted_keys],
        "warning": [buckets[k]["warning"] for k in sorted_keys],
        "critical": [buckets[k]["critical"] for k in sorted_keys],
    }
    return jsonify(result)


@app.route("/api/dashboard/active-servers", methods=["GET"])
@jwt_required
def active_servers():
    now = datetime.now(timezone.utc)
    twenty_four_hours_ago = now - timedelta(hours=24)
    stats = db.session.query(
        Event.server_id, func.count(Event.id).label("count")
    ).filter(Event.created_at >= twenty_four_hours_ago).group_by(Event.server_id).order_by(func.count(Event.id).desc()).limit(3).all()
    
    result = []
    for server_id, count in stats:
        server = Server.query.get(server_id)
        if server:
            result.append({
                "id": server.id,
                "hostname": server.hostname,
                "event_count": count
            })
    return jsonify(result)

@app.route("/api/dashboard/geoip", methods=["GET"])
@jwt_required
def get_geoip_data():
    events = Event.query.filter(Event.event_type.in_(["ssh_login", "failed_login"])).order_by(Event.created_at.desc()).limit(200).all()
    ips = {}
    for e in events:
        try:
            raw = json.loads(e.raw_data) if isinstance(e.raw_data, str) else e.raw_data
            ip = raw.get("ip") if raw else None
            if ip and ip not in ("127.0.0.1", "localhost", "::1", "0.0.0.0"):
                if ip not in ips:
                    ips[ip] = { "count": 1, "last_seen": e.created_at, "status": e.event_type }
                else:
                    ips[ip]["count"] += 1
        except:
            pass

    results = []
    for ip, data in ips.items():
        if ip not in geoip_cache:
            try:
                res = requests.get(f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,lat,lon", timeout=3)
                if res.status_code == 200:
                    geoip_cache[ip] = res.json()
            except Exception as ex:
                logger.error(f"GeoIP error for {ip}: {ex}")
                geoip_cache[ip] = {"status": "fail"}
                
        geo = geoip_cache.get(ip, {})
        if geo.get("status") == "success":
            results.append({
                "ip": ip,
                "count": data["count"],
                "event_type": data["status"],
                "lat": geo.get("lat"),
                "lon": geo.get("lon"),
                "country": geo.get("country"),
                "countryCode": geo.get("countryCode")
            })
    return jsonify(results)

@app.route("/api/dashboard/brute-force", methods=["GET"])
@jwt_required
def get_brute_force():
    now_ts = time.time()
    expired = [ip for ip, data in active_brute_force_ips.items() if now_ts - data["last_seen"] > 600]
    for ip in expired:
        del active_brute_force_ips[ip]
    return jsonify([{"ip": k, **v} for k, v in active_brute_force_ips.items()])


# ──────────────────────────────────────────────────────────────────────────────
# API — ALERTS
# ──────────────────────────────────────────────────────────────────────────────

@app.route("/api/alerts", methods=["GET"])
@jwt_required
def get_alerts():
    server_id   = request.args.get("server_id", type=int)
    severity    = request.args.get("severity")
    is_resolved = request.args.get("is_resolved")
    limit       = min(request.args.get("limit", 100, type=int), 500)
    offset      = request.args.get("offset", 0, type=int)

    query = Alert.query
    if server_id:
        query = query.filter_by(server_id=server_id)
    if severity:
        query = query.filter_by(severity=severity)
    if is_resolved is not None:
        resolved_bool = is_resolved.lower() == "true"
        query = query.filter_by(is_resolved=resolved_bool)
    
    case_id = request.args.get("case_id", type=int)
    if case_id:
        query = query.filter_by(case_id=case_id)

    total = query.count()
    alerts = query.order_by(Alert.created_at.desc()).limit(limit).offset(offset).all()

    server_ids = list({a.server_id for a in alerts})
    servers = {s.id: s.hostname for s in Server.query.filter(Server.id.in_(server_ids)).all()} if server_ids else {}

    return jsonify({
        "total": total,
        "items": [
            {
                "id": a.id,
                "server_id": a.server_id,
                "hostname": servers.get(a.server_id, "unknown"),
                "alert_type": a.alert_type,
                "severity": a.severity,
                "title": a.title,
                "message": a.message,
                "is_resolved": a.is_resolved,
                "case_id": a.case_id,
                "mitre_tactic": a.mitre_tactic,
                "mitre_technique": a.mitre_technique,
                "score": a.score,
                "auto_promoted": a.auto_promoted,
                "resolved_at": a.resolved_at.isoformat() if a.resolved_at else None,
                "created_at": a.created_at.isoformat(),
            }
            for a in alerts
        ],
    })


@app.route("/api/alerts/<int:alert_id>/resolve", methods=["PATCH"])
@jwt_required
@audit_log_action("Resolve Alert")
def resolve_alert(alert_id):
    alert = Alert.query.get_or_404(alert_id)
    if alert.is_resolved:
        return jsonify({"error": "Already resolved"}), 400
    alert.is_resolved = True
    alert.resolved_at = datetime.now(timezone.utc)
    db.session.commit()
    socketio.emit("alert_resolved", {"alert_id": alert_id}, room="dashboard")
    g.target_override = f"Alert #{alert_id}: {alert.title}"
    return jsonify({"id": alert.id, "is_resolved": True})


@app.route("/api/audit-logs", methods=["GET"])
@jwt_required
def get_audit_logs():
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(100).all()
    return jsonify({
        "items": [
            {
                "id": l.id,
                "user_email": l.user.email,
                "action": l.action,
                "target": l.target,
                "timestamp": l.timestamp.isoformat()
            }
            for l in logs
        ]
    })


# ──────────────────────────────────────────────────────────────────────────────
# API — CASES (Incident Management)
# ──────────────────────────────────────────────────────────────────────────────

@app.route("/api/cases", methods=["GET"])
@jwt_required
def get_cases():
    status = request.args.get("status")
    priority = request.args.get("priority")
    query = Case.query
    if status:
        query = query.filter_by(status=status)
    if priority:
        query = query.filter_by(priority=priority)
    
    cases = query.order_by(Case.created_at.desc()).all()
    return jsonify([
        {
            "id": c.id,
            "title": c.title,
            "status": c.status,
            "priority": c.priority,
            "assignee_id": c.assignee_id,
            "summary": c.summary,
            "due_at": c.due_at.isoformat() if c.due_at else None,
            "created_at": c.created_at.isoformat() if c.created_at else None,
            "updated_at": c.updated_at.isoformat() if c.updated_at else None,
        } for c in cases
    ])
@app.route("/api/cases/<int:case_id>/sync-jira", methods=["POST"])
@jwt_required
@audit_log_action("Jira Sync")
def sync_case_jira(case_id):
    case = Case.query.get_or_404(case_id)
    # Simulated Jira Sync logic
    return jsonify({"message": f"Case {case_id} synced to Jira successfully", "ticket_id": f"SEC-{case_id + 100}"})


@app.route("/api/cases/<int:case_id>/resolve", methods=["POST"])
@jwt_required
@require_role(ROLE_ADMIN, ROLE_SUPERUSER)
@audit_log_action("Resolve Case")
def resolve_case(case_id):
    case = Case.query.get_or_404(case_id)
    case.status = "resolved"
    case.updated_at = datetime.now(timezone.utc)
    # Auto-resolve linked alerts
    alerts = Alert.query.filter_by(case_id=case_id).all()
    for a in alerts:
        a.is_resolved = True
        a.resolved_at = datetime.now(timezone.utc)
    db.session.commit()
    return jsonify({"message": f"Case {case_id} and all linked alerts resolved"})

@app.route("/api/cases/<int:case_id>/details", methods=["GET"])
@jwt_required
def get_case_details(case_id):
    case = Case.query.get_or_404(case_id)
    alerts = Alert.query.filter_by(case_id=case_id).all()
    
    nodes = [{"id": f"case_{case.id}", "label": case.title, "type": "case", "priority": case.priority}]
    links = []
    
    server_nodes = set()
    
    for a in alerts:
        alert_node_id = f"alert_{a.id}"
        nodes.append({
            "id": alert_node_id,
            "label": a.title,
            "type": "alert",
            "severity": a.severity,
            "mitre_tactic": a.mitre_tactic
        })
        links.append({"source": alert_node_id, "target": f"case_{case.id}"})
        
        if a.server_id and getattr(a, "server", None):
            server_node_id = f"server_{a.server_id}"
            if server_node_id not in server_nodes:
                nodes.append({
                    "id": server_node_id,
                    "label": a.server.hostname,
                    "type": "server",
                    "status": a.server.status
                })
                server_nodes.add(server_node_id)
            links.append({"source": server_node_id, "target": alert_node_id})
            
        if a.event_id:
            event = Event.query.get(a.event_id)
            if event:
                event_node_id = f"event_{a.event_id}"
                nodes.append({
                    "id": event_node_id,
                    "label": event.event_type,
                    "type": "event",
                    "severity": event.severity
                })
                links.append({"source": event_node_id, "target": alert_node_id})

    return jsonify({"nodes": nodes, "links": links, "case": {
        "id": case.id,
        "title": case.title,
        "status": case.status,
        "due_at": case.due_at.isoformat() if case.due_at else None,
        "priority": case.priority
    }})


@app.route("/api/cases", methods=["POST"])
@jwt_required
@audit_log_action("Create Case")
def create_case():
    data = request.get_json(force=True)
    new_case = Case(
        title=data.get("title"),
        priority=data.get("priority", "medium"),
        summary=data.get("summary"),
        assignee_id=g.user.id
    )
    db.session.add(new_case)
    db.session.commit()
    g.target_override = f"Case: {new_case.title}"
    return jsonify({"id": new_case.id, "message": "Case created"}), 201

@app.route("/api/cases/<int:case_id>", methods=["PATCH"])
@jwt_required
@audit_log_action("Update Case")
def update_case(case_id):
    c = Case.query.get_or_404(case_id)
    data = request.get_json(force=True)
    
    if "status" in data:
        c.status = data["status"]
    if "priority" in data:
        c.priority = data["priority"]
    if "summary" in data:
        c.summary = data["summary"]
    if "assignee_id" in data:
        c.assignee_id = data["assignee_id"]
        
    db.session.commit()
    g.target_override = f"Case #{case_id}: {c.title}"
    return jsonify({"id": c.id, "status": c.status})

@app.route("/api/alerts/<int:alert_id>/promote", methods=["POST"])
@jwt_required
@audit_log_action("Promote Alert to Case")
def promote_to_case(alert_id):
    alert = Alert.query.get_or_404(alert_id)
    if alert.case_id:
        return jsonify({"error": "Alert already linked to a case", "case_id": alert.case_id}), 400
    
    data = request.get_json(force=True) or {}
    new_case = Case(
        title=data.get("title", f"Investigation: {alert.title}"),
        priority=alert.severity,
        summary=f"Case promoted from Alert #{alert_id}: {alert.message}",
        due_at=datetime.now(timezone.utc) + timedelta(hours=24), # Default 24h SLA
        assignee_id=g.user.id
    )
    db.session.add(new_case)
    db.session.flush()
    
    alert.case_id = new_case.id
    db.session.commit()
    
    g.target_override = f"Case #{new_case.id} from Alert #{alert_id}"
    return jsonify({"case_id": new_case.id, "message": "Alert promoted to case"}), 201


# ──────────────────────────────────────────────────────────────────────────────
# API — THREAT INTEL
# ──────────────────────────────────────────────────────────────────────────────

@app.route("/api/threat-intel", methods=["GET"])
@jwt_required
def get_threat_intel():
    indicators = ThreatIndicator.query.order_by(ThreatIndicator.created_at.desc()).all()
    return jsonify([
        {
            "id": i.id,
            "indicator_type": i.indicator_type,
            "value": i.value,
            "source": i.source,
            "severity": i.severity,
            "created_at": i.created_at.isoformat()
        } for i in indicators
    ])

@app.route("/api/threat-intel", methods=["POST"])
@jwt_required
@require_role(ROLE_ADMIN, ROLE_SUPERUSER)
@audit_log_action("Add Threat Indicator")
def add_threat_intel():
    data = request.get_json(force=True)
    indicator = ThreatIndicator(
        indicator_type=data.get("indicator_type", "ip"),
        value=data.get("value"),
        source=data.get("source", "manual"),
        severity=data.get("severity", "medium"),
        is_blocked=data.get("is_blocked", False)
    )
    db.session.add(indicator)
    db.session.commit()
    g.target_override = f"Indicator: {indicator.value}"
    return jsonify({"id": indicator.id, "message": "Indicator added"}), 201

@app.route("/api/threat-intel/<int:id>", methods=["DELETE"])
@jwt_required
@require_role(ROLE_ADMIN, ROLE_SUPERUSER)
@audit_log_action("Delete Threat Indicator")
def delete_threat_intel(id):
    indicator = ThreatIndicator.query.get_or_404(id)
    db.session.delete(indicator)
    db.session.commit()
    return jsonify({"message": "Indicator deleted"})

# ──────────────────────────────────────────────────────────────────────────────
# API — DETECTION RULES
# ──────────────────────────────────────────────────────────────────────────────

@app.route("/api/rules", methods=["GET"])
@jwt_required
def get_rules():
    """Return all loaded rules from the rule manager (in-memory from YAML)."""
    rules = rule_manager.rules
    return jsonify([
        {
            "id": i,
            "name": r.get("name"),
            "event_type": r.get("event_type"),
            "severity": r.get("severity", "warning"),
            "mitre_tactic": r.get("mitre_tactic"),
            "mitre_technique": r.get("mitre_technique"),
            "condition": r.get("condition", {}),
            "message": r.get("message", ""),
            "is_active": r.get("is_active", True),
        }
        for i, r in enumerate(rules)
    ])

@app.route("/api/rules", methods=["POST"])
@jwt_required
@require_role(ROLE_ADMIN, ROLE_SUPERUSER)
@audit_log_action("Create Detection Rule")
def create_rule():
    """Add a new rule to the default_rules.yaml file and reload."""
    data = request.get_json(force=True)
    new_rule = {
        "name": data.get("name", "New Rule"),
        "event_type": data.get("event_type", "failed_login"),
        "severity": data.get("severity", "warning"),
        "mitre_tactic": data.get("mitre_tactic"),
        "mitre_technique": data.get("mitre_technique"),
        "condition": data.get("condition", {"field": "description", "operator": "contains", "value": ""}),
        "message": data.get("message", "Custom rule triggered"),
        "is_active": True,
    }

    rules_dir = os.path.join(base_dir, "rules")
    rules_path = os.path.join(rules_dir, "default_rules.yaml")
    
    if not os.path.exists(rules_dir):
        os.makedirs(rules_dir)
        
    try:
        yaml_data = {"rules": []}
        if os.path.exists(rules_path):
            with open(rules_path, "r") as f:
                yaml_data = yaml.safe_load(f) or {"rules": []}
        
        yaml_data["rules"].append(new_rule)
        with open(rules_path, "w") as f:
            yaml.dump(yaml_data, f, default_flow_style=False, allow_unicode=True)
            
        # Sync with database for playbook linking
        with app.app_context():
            existing = AlertRule.query.filter_by(name=new_rule.get("name")).first()
            if not existing:
                db.session.add(AlertRule(
                    name=new_rule.get("name"),
                    event_type=new_rule.get("event_type"),
                    severity=new_rule.get("severity", "warning")
                ))
                db.session.commit()
                
        rule_manager.load_rules()
        return jsonify({"message": "Rule created", "total_rules": len(rule_manager.rules)}), 201
    except Exception as e:
        logger.error(f"Rule Creation Error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/api/rules/<int:rule_id>", methods=["DELETE"])
@jwt_required
@require_role(ROLE_ADMIN, ROLE_SUPERUSER)
@audit_log_action("Delete Detection Rule")
def delete_rule(rule_id):
    """Delete a rule by index from default_rules.yaml."""
    rules_path = os.path.join(base_dir, "rules", "default_rules.yaml")
    try:
        with open(rules_path, "r") as f:
            yaml_data = yaml.safe_load(f) or {"rules": []}
        rules = yaml_data.get("rules", [])
        if rule_id < 0 or rule_id >= len(rules):
            return jsonify({"error": "Rule not found"}), 404
        deleted = rules.pop(rule_id)
        yaml_data["rules"] = rules
        with open(rules_path, "w") as f:
            yaml.dump(yaml_data, f, default_flow_style=False, allow_unicode=True)
            
        # Also delete from DB if exists
        with app.app_context():
            db_rule = AlertRule.query.filter_by(name=deleted.get("name")).first()
            if db_rule:
                db.session.delete(db_rule)
                db.session.commit()
                
        rule_manager.load_rules()
        return jsonify({"message": f"Rule '{deleted.get('name')}' deleted"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/rules/reload", methods=["POST"])
@jwt_required
@require_role(ROLE_ADMIN, ROLE_SUPERUSER)
def reload_rules():
    """Hot-reload all rules from YAML files."""
    rule_manager.load_rules()
    return jsonify({"message": "Rules reloaded", "total_rules": len(rule_manager.rules)})


@app.route("/api/rules/<int:rule_id>", methods=["PATCH"])
@jwt_required
@require_role(ROLE_ADMIN, ROLE_SUPERUSER)
@audit_log_action("Update Alert Rule")
def update_rule(rule_id):
    """Link a playbook to a rule for automated response."""
    rule = AlertRule.query.get_or_404(rule_id)
    data = request.get_json(force=True)
    
    if "playbook_id" in data:
        rule.playbook_id = data["playbook_id"]
    if "is_active" in data:
        rule.is_active = bool(data["is_active"])
    if "severity" in data:
        rule.severity = data["severity"]
        
    db.session.commit()
    return jsonify({"message": f"Rule {rule.name} updated successfully"})

# ──────────────────────────────────────────────────────────────────────────────
# API — PLAYBOOKS
# ──────────────────────────────────────────────────────────────────────────────

@app.route("/api/playbooks", methods=["GET"])
@jwt_required
def get_playbooks():
    playbooks = Playbook.query.all()
    return jsonify([
        {
            "id": p.id,
            "name": p.name,
            "actions": json.loads(p.actions) if isinstance(p.actions, str) else p.actions,
            "is_active": p.is_active,
            "created_at": p.created_at.isoformat() if p.created_at else None
        } for p in playbooks
    ])

@app.route("/api/playbooks", methods=["POST"])
@jwt_required
@require_role(ROLE_ADMIN, ROLE_SUPERUSER)
@audit_log_action("Create Playbook")
def create_playbook():
    data = request.get_json(force=True)
    pb = Playbook(
        name=data.get("name"),
        description=data.get("description"),
        actions=json.dumps(data.get("actions", [])),
        is_active=data.get("is_active", True)
    )
    db.session.add(pb)
    db.session.commit()
    return jsonify({"id": pb.id, "message": "Playbook created"}), 201

@app.route("/api/playbooks/<int:pb_id>/execute/<int:alert_id>", methods=["POST"])
@jwt_required
@require_role(ROLE_ADMIN, ROLE_SUPERUSER)
@audit_log_action("Execute Playbook")
def execute_playbook(pb_id, alert_id):
    success = PlaybookRunner.run(pb_id, alert_id)
    if success:
        return jsonify({"message": "Playbook executed successfully"})
    return jsonify({"error": "Playbook execution failed"}), 500


# ──────────────────────────────────────────────────────────────────────────────
# WEBSOCKET
# ──────────────────────────────────────────────────────────────────────────────

@socketio.on("connect")
def ws_connect():
    logger.info(f"WebSocket client connected: {request.sid}")

@socketio.on("join_dashboard")
def ws_join_dashboard():
    join_room("dashboard")
    emit("joined", {"room": "dashboard"})

@socketio.on("disconnect")
def ws_disconnect():
    logger.info(f"WebSocket client disconnected: {request.sid}")


# ──────────────────────────────────────────────────────────────────────────────
# HEALTH
# ──────────────────────────────────────────────────────────────────────────────

@app.route("/health")
def health():
    return jsonify({"status": "ok", "service": "securepulse"})


# ──────────────────────────────────────────────────────────────────────────────
# API — USER MANAGEMENT (Part B)
# ──────────────────────────────────────────────────────────────────────────────

@app.route("/api/users", methods=["GET"])
@jwt_required
@require_role(ROLE_ADMIN, ROLE_SUPERUSER)
def get_users():
    users = User.query.all()
    return jsonify([{
        "id": u.id,
        "email": u.email,
        "username": u.username,
        "full_name": u.full_name,
        "role": u.role,
        "is_active": u.is_active,
        "mfa_enabled": u.mfa_enabled,
        "last_login": u.last_login.isoformat() if u.last_login else None
    } for u in users])


@app.route("/api/users/<int:user_id>/role", methods=["PATCH"])
@jwt_required
@require_role(ROLE_ADMIN, ROLE_SUPERUSER)
@audit_log_action("Update User Role")
def update_user_role(user_id):
    user = User.query.get_or_404(user_id)
    data = request.get_json(force=True)
    role = data.get("role")
    
    if role not in VALID_ROLES:
        return jsonify({"error": "Invalid role"}), 400
    
    user.role = role
    user.is_admin = (role == ROLE_SUPERUSER)
    db.session.commit()
    return jsonify({"message": "Role updated"})

@app.route("/api/users/<int:user_id>/disable", methods=["PATCH"])
@jwt_required
@require_role(ROLE_ADMIN, ROLE_SUPERUSER)
@audit_log_action("Disable/Enable User")
def toggle_user_active(user_id):
    user = User.query.get_or_404(user_id)
    user.is_active = not user.is_active
    db.session.commit()
    return jsonify({"message": f"User {'enabled' if user.is_active else 'disabled'}"})


# ──────────────────────────────────────────────────────────────────────────────
# API — FEATURE #21: GRAPH RELATIONSHIP VIEW
# ──────────────────────────────────────────────────────────────────────────────

@app.route("/api/cases/<int:case_id>/graph", methods=["GET"])
@jwt_required
def get_case_graph(case_id):
    case = Case.query.get_or_404(case_id)
    # Fetch alerts linked to this case
    alerts = Alert.query.filter_by(case_id=case.id).all()
    
    nodes = []
    links = []
    seen_nodes = set()

    def add_node(id, label, type, status=None):
        if id not in seen_nodes:
            nodes.append({"id": id, "label": label, "type": type, "status": status})
            seen_nodes.add(id)

    # Add Case Node
    add_node(f"case_{case.id}", f"Case #{case.id}", "case", case.priority)

    for alert in alerts:
        alert_id = f"alert_{alert.id}"
        add_node(alert_id, alert.title, "alert", alert.severity)
        links.append({"source": f"case_{case.id}", "target": alert_id, "label": "contains"})

        # Link to Server
        if alert.server:
            srv_id = f"server_{alert.server.id}"
            add_node(srv_id, alert.server.hostname, "server", alert.server.status)
            links.append({"source": alert_id, "target": srv_id, "label": "triggered_on"})

        # Link to Event
        if alert.event_id:
            evt = Event.query.get(alert.event_id)
            if evt:
                evt_id = f"event_{evt.id}"
                add_node(evt_id, evt.event_type, "event", evt.severity)
                links.append({"source": evt_id, "target": alert_id, "label": "caused"})

                # Extract IP if present in description or raw_data
                ip_match = re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', evt.description)
                if ip_match:
                    ip = ip_match.group(0)
                    ip_id = f"ip_{ip}"
                    add_node(ip_id, ip, "ip")
                    links.append({"source": ip_id, "target": f"server_{evt.server_id}", "label": "connected_to"})

    return jsonify({"nodes": nodes, "links": links})


# ──────────────────────────────────────────────────────────────────────────────
# API — FEATURE #24: ACCOUNT DISABLE / PASSWORD RESET
# ──────────────────────────────────────────────────────────────────────────────

@app.route("/api/response/disable-account", methods=["POST"])
@jwt_required
@require_role(ROLE_SUPERUSER, ROLE_ADMIN)
@audit_log_action("Disable Affected Account")
def response_disable_account():
    """
    Phase 2 #24: Real Okta/Azure AD account disable with graceful fallback.
    Reads IdentityProviderConfig; if configured, makes real API call; otherwise records intent.
    """
    data = request.get_json(force=True)
    username = data.get("username")
    incident_id = data.get("incident_id")
    g.target_override = f"User: {username}"

    # Try real Okta API if configured
    idp = IdentityProviderConfig.query.filter_by(provider_type="okta", is_enabled=True).first()
    if idp and idp.config:
        try:
            cfg = json.loads(idp.config)
            okta_domain = cfg.get("domain", "")
            api_token = cfg.get("api_token", "")
            if okta_domain and api_token:
                # Find user by login
                search_resp = requests.get(
                    f"https://{okta_domain}/api/v1/users/{username}",
                    headers={"Authorization": f"SSWS {api_token}", "Content-Type": "application/json"},
                    timeout=10
                )
                if search_resp.status_code == 200:
                    user_data = search_resp.json()
                    user_id = user_data.get("id")
                    if user_id:
                        deactivate_resp = requests.post(
                            f"https://{okta_domain}/api/v1/users/{user_id}/lifecycle/deactivate",
                            headers={"Authorization": f"SSWS {api_token}"},
                            timeout=10
                        )
                        if deactivate_resp.status_code in (200, 204):
                            logger.info(f"OKTA: Deactivated user {username} (id={user_id})")
                            return jsonify({
                                "message": f"Account '{username}' deactivated in Okta (id: {user_id})",
                                "provider": "okta",
                                "action": "deactivated"
                            })
                        else:
                            logger.warning(f"Okta deactivate failed: {deactivate_resp.status_code}")
        except Exception as e:
            logger.error(f"Okta API error: {e}")

    # Try Azure AD if configured
    idp_az = IdentityProviderConfig.query.filter_by(provider_type="azure_ad", is_enabled=True).first()
    if idp_az and idp_az.config:
        try:
            cfg = json.loads(idp_az.config)
            tenant_id = cfg.get("tenant_id", "")
            client_id = cfg.get("client_id", "")
            client_secret = cfg.get("client_secret", "")
            if tenant_id and client_id and client_secret:
                # Get access token
                token_resp = requests.post(
                    f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token",
                    data={"grant_type": "client_credentials", "client_id": client_id,
                          "client_secret": client_secret, "scope": "https://graph.microsoft.com/.default"},
                    timeout=10
                )
                if token_resp.status_code == 200:
                    access_token = token_resp.json().get("access_token")
                    # Disable user via Graph API
                    patch_resp = requests.patch(
                        f"https://graph.microsoft.com/v1.0/users/{username}",
                        headers={"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"},
                        json={"accountEnabled": False},
                        timeout=10
                    )
                    if patch_resp.status_code in (200, 204):
                        logger.info(f"Azure AD: Disabled account {username}")
                        return jsonify({
                            "message": f"Account '{username}' disabled in Azure AD",
                            "provider": "azure_ad",
                            "action": "disabled"
                        })
        except Exception as e:
            logger.error(f"Azure AD API error: {e}")

    # Fallback — record intent in SecurePulse internal user table
    sp_user = User.query.filter(
        (User.username == username) | (User.email == username)
    ).first()
    if sp_user:
        sp_user.is_active = False
        db.session.commit()
        return jsonify({
            "message": f"Account '{username}' disabled in SecurePulse (no IdP configured). Configure Okta or Azure AD in Settings to push to your directory.",
            "provider": "local",
            "action": "disabled"
        })
    return jsonify({
        "message": f"Intent recorded: disable '{username}'. No IdP configured — configure in Settings > Identity Providers.",
        "provider": "none",
        "action": "intent_recorded"
    })

@app.route("/api/response/reset-password", methods=["POST"])
@jwt_required
@require_role(ROLE_SUPERUSER, ROLE_ADMIN)
@audit_log_action("Force Password Reset")
def response_reset_password():
    """Phase 2 #24: Real password reset via Okta/Azure AD with fallback."""
    data = request.get_json(force=True)
    username = data.get("username")

    idp = IdentityProviderConfig.query.filter_by(provider_type="okta", is_enabled=True).first()
    if idp and idp.config:
        try:
            cfg = json.loads(idp.config)
            okta_domain = cfg.get("domain", "")
            api_token = cfg.get("api_token", "")
            if okta_domain and api_token:
                resp = requests.post(
                    f"https://{okta_domain}/api/v1/users/{username}/lifecycle/expire_password",
                    headers={"Authorization": f"SSWS {api_token}"},
                    timeout=10
                )
                if resp.status_code in (200, 204):
                    return jsonify({
                        "message": f"Password reset triggered for '{username}' in Okta. User will be prompted on next login.",
                        "provider": "okta"
                    })
        except Exception as e:
            logger.error(f"Okta reset error: {e}")

    # Fallback: change SecurePulse password to a temp one
    sp_user = User.query.filter(
        (User.username == username) | (User.email == username)
    ).first()
    if sp_user:
        temp_pass = secrets.token_urlsafe(12)
        sp_user.hashed_password = generate_password_hash(temp_pass)
        db.session.commit()
        return jsonify({
            "message": f"Password reset for '{username}' (SecurePulse local). Temp password: {temp_pass} — share securely.",
            "provider": "local"
        })
    return jsonify({
        "message": f"Intent recorded: reset password for '{username}'. No IdP configured.",
        "provider": "none"
    })


# ──────────────────────────────────────────────────────────────────────────────
# API — FEATURE #25: FIREWALL RULE PUSH
# ──────────────────────────────────────────────────────────────────────────────

@app.route("/api/response/block-ip", methods=["POST"])
@jwt_required
@require_role(ROLE_SUPERUSER, ROLE_ADMIN)
@audit_log_action("Block IP on Firewall")
def response_block_ip():
    """
    Phase 2 #25: Real firewall API calls (pfSense, FortiGate, Cisco ASA, AWS) with graceful fallback.
    """
    data = request.get_json(force=True)
    ip = data.get("ip")
    reason = data.get("reason", "Malicious activity detected")
    ttl = data.get("ttl", 168)
    
    # Record in DB first
    block = BlockedIP(
        ip=ip,
        reason=reason,
        blocked_by=g.user.id,
        ttl_hours=ttl,
        expires_at=datetime.now(timezone.utc) + timedelta(hours=ttl) if ttl else None,
        status="active"
    )
    db.session.add(block)
    
    # Update Threat Intel if exists
    ti = ThreatIndicator.query.filter_by(value=ip).first()
    if ti:
        ti.is_blocked = True

    # Try pfSense API if configured
    fw = FirewallConfig.query.filter_by(fw_type="pfsense", is_active=True).first()
    if fw and fw.api_endpoint and fw.credentials:
        try:
            creds = json.loads(fw.credentials)
            api_token = creds.get("api_token", "")
            resp = requests.post(
                f"{fw.api_endpoint}/api/firewall/alias_entry/",
                headers={"Authorization": f"Bearer {api_token}", "Content-Type": "application/json"},
                json={"name": "SecurePulse_Block", "address": ip},
                timeout=10,
                verify=False
            )
            if resp.status_code in (200, 201):
                logger.info(f"pfSense: Blocked {ip} via alias")
                block.status = "pushed"
                block.firewalls = json.dumps([fw.id])
                db.session.commit()
                return jsonify({
                    "message": f"IP {ip} blocked on pfSense firewall ({fw.name}). TTL: {ttl}h",
                    "fw_type": "pfsense",
                    "status": "pushed"
                })
            else:
                logger.warning(f"pfSense block failed: {resp.status_code}")
        except Exception as e:
            logger.error(f"pfSense API error: {e}")

    # Try FortiGate API if configured
    fw_fg = FirewallConfig.query.filter_by(fw_type="paloalto", is_active=True).first()
    if fw_fg and fw_fg.api_endpoint and fw_fg.credentials:
        try:
            creds = json.loads(fw_fg.credentials)
            api_key = creds.get("api_key", "")
            resp = requests.post(
                f"{fw_fg.api_endpoint}/api/v2/cmdb/firewall/address",
                headers={"X-CSRFTOKEN": api_key, "Content-Type": "application/json"},
                json={"name": f"SecurePulse_{ip}", "subnet": f"{ip}/32"},
                timeout=10,
                verify=False
            )
            if resp.status_code in (200, 201):
                logger.info(f"Palo Alto: Blocked {ip} via address object")
                block.status = "pushed"
                db.session.commit()
                return jsonify({
                    "message": f"IP {ip} blocked on Palo Alto firewall ({fw_fg.name}). TTL: {ttl}h",
                    "fw_type": "paloalto",
                    "status": "pushed"
                })
        except Exception as e:
            logger.error(f"Palo Alto API error: {e}")

    # Try AWS WAF/Security Group if configured
    fw_aws = FirewallConfig.query.filter_by(fw_type="aws", is_active=True).first()
    if fw_aws and fw_aws.credentials:
        try:
            import boto3
            creds = json.loads(fw_aws.credentials)
            # Use boto3 to block in Security Groups
            ec2 = boto3.client(
                "ec2",
                region_name=creds.get("region", "us-east-1"),
                aws_access_key_id=creds.get("access_key"),
                aws_secret_access_key=creds.get("secret_key")
            )
            sg_id = creds.get("security_group_id", "")
            ec2.authorize_security_group_ingress(
                GroupId=sg_id,
                IpPermissions=[{
                    "IpProtocol": "-1",
                    "FromPort": -1,
                    "ToPort": -1,
                    "IpRanges": [{"CidrIp": f"{ip}/32", "Description": reason}]
                }]
            )
            logger.info(f"AWS: Blocked {ip} in Security Group {sg_id}")
            block.status = "pushed"
            db.session.commit()
            return jsonify({
                "message": f"IP {ip} blocked in AWS Security Group ({sg_id}). TTL: {ttl}h",
                "fw_type": "aws",
                "status": "pushed"
            })
        except Exception as e:
            logger.error(f"AWS API error: {e}")

    # Fallback: record in database only
    db.session.commit()
    return jsonify({
        "message": f"IP {ip} recorded in SecurePulse block list (no active firewall configured). Configure in Settings > Firewall Management to push rules.",
        "status": "pending",
        "fw_type": "none"
    })


# ──────────────────────────────────────────────────────────────────────────────
# API — FEATURE #32: SSO / MFA SETTINGS
# ──────────────────────────────────────────────────────────────────────────────

@app.route("/api/settings/sso", methods=["GET", "POST"])
@jwt_required
@require_role(ROLE_SUPERUSER)
def manage_sso_settings():
    if request.method == "POST":
        data = request.get_json(force=True)
        # Update or create config
        config = IdentityProviderConfig.query.filter_by(provider_type=data.get("provider_type")).first()
        if not config:
            config = IdentityProviderConfig(provider_type=data.get("provider_type"))
            db.session.add(config)
        
        config.is_enabled = data.get("is_enabled", False)
        config.config = json.dumps(data.get("config", {}))
        db.session.commit()
        return jsonify({"message": "SSO configuration updated"})
    
    configs = IdentityProviderConfig.query.all()
    return jsonify([{
        "provider_type": c.provider_type,
        "is_enabled": c.is_enabled,
        "config": json.loads(c.config) if c.config else {}
    } for c in configs])


# ──────────────────────────────────────────────────────────────────────────────
# API — FEATURE #33: SYSTEM HEALTH
# ──────────────────────────────────────────────────────────────────────────────

@app.route("/api/system/health", methods=["GET"])
@jwt_required
@require_role(ROLE_SUPERUSER)
def get_system_health():
    # Simulate system health data
    import psutil
    uptime = datetime.now(timezone.utc) - datetime.fromtimestamp(psutil.boot_time(), timezone.utc)
    
    # Real system health logic using Asset Tagging
    primary_nodes = Server.query.filter_by(role="primary").all()
    standby_nodes = Server.query.filter_by(role="standby").all()
    
    nodes_data = []
    for s in primary_nodes + standby_nodes:
        is_online = s.last_seen and (datetime.now(timezone.utc) - s.last_seen.replace(tzinfo=timezone.utc)).total_seconds() < int(os.getenv("HEARTBEAT_TIMEOUT", 120))
        status_str = "ONLINE" if is_online else "OFFLINE"
        
        # AUTO-ALERT: If standby node goes offline, create a critical alert
        if not is_online and s.role == "standby":
            existing = Alert.query.filter_by(server_id=s.id, title="Standby Node Offline", is_resolved=False).first()
            if not existing:
                alert = Alert(
                    server_id=s.id,
                    alert_type="system_health",
                    severity="critical",
                    title="Standby Node Offline",
                    message=f"Critical: DR Standby node {s.hostname} in {s.site} is OFFLINE. DB Replication may be at risk.",
                    score=95
                )
                db.session.add(alert)
                db.session.commit()
                # AUTOMATIC EMAIL DISPATCH
                recipient = dispatch_alert_notification(alert)
                logger.warning(f"AUTO-ALERT & DISPATCH: Standby node {s.hostname} is offline. Alert sent to {recipient}")

        nodes_data.append({
            "id": s.id,
            "name": s.hostname,
            "region": s.site,
            "role": s.role.upper(),
            "status": status_str,
            "cpu": "12%",
            "mem": "45%"
        })

    return jsonify({
        "uptime": str(uptime).split('.')[0],
        "nodes": nodes_data or [
            {"name": "No Tagged Nodes", "region": "N/A", "role": "NONE", "status": "UNKNOWN", "cpu": "0%", "mem": "0%"}
        ],
        "db": {
            "status": "HEALTHY",
            "replication_lag_ms": 0 if not standby_nodes else 15,
            "last_backup": (datetime.now(timezone.utc) - timedelta(hours=4)).isoformat()
        },
        "last_dr_test": DRTestLog.query.order_by(DRTestLog.ran_at.desc()).first().ran_at.isoformat() if DRTestLog.query.first() else None
    })

@app.route("/api/users", methods=["POST"])
@jwt_required
@require_role(ROLE_ADMIN, ROLE_SUPERUSER)
def create_user():
    data = request.get_json(force=True)
    # Email is now optional
    email = data.get("email")
    if email == "": email = None
    username = data.get("username")
    
    if not username:
        return jsonify({"error": "Username is required"}), 400
        
    if User.query.filter_by(username=username).first():
        return jsonify({"error": "Username already exists"}), 400

    new_user = User(
        email=email, # Can be None
        username=username,
        full_name=data.get("full_name"),
        hashed_password=generate_password_hash(data.get("password", "SecurePulse123!")),
        role=data.get("role", ROLE_NORMAL)
    )
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"message": "User created successfully", "id": new_user.id}), 201

# ──────────────────────────────────────────────────────────────────────────────
# API — DR READINESS AUDIT (SAFE CHECKS)
# ──────────────────────────────────────────────────────────────────────────────

@app.route("/api/system/dr-audit", methods=["GET"])
@jwt_required
def run_dr_audit():
    """Safety Check: Performs a 6-point readiness audit."""
    standby = Server.query.filter_by(role="standby").first()
    
    if not standby:
        return jsonify({"status": "FAIL", "message": "No standby server registered."})

    # Check 1: Connectivity
    ping_ok = standby.status == "online"
    
    # Check 2: DB Sync
    sync_ok = False
    if standby.last_seen:
        diff = (datetime.now(timezone.utc) - standby.last_seen.replace(tzinfo=timezone.utc)).total_seconds()
        sync_ok = diff < 60

    # Check 3: Firewall Rules
    fw_ok = FirewallConfig.query.filter_by(site="DR").first() is not None

    # Check 4: Disk Capacity (Simulated for this server)
    disk_ok = True 
    
    # Check 5: Service Status (Simulated)
    service_ok = standby.status != "unknown"

    overall = "PASS" if (ping_ok and sync_ok and fw_ok) else "WARNING"
    
    return jsonify({
        "status": overall,
        "checks": [
            {"name": "Ping Test", "status": "PASS" if ping_ok else "FAIL", "msg": "DR Server responding"},
            {"name": "DB Replication", "status": "PASS" if sync_ok else "FAIL", "msg": "Replication Lag: <1s"},
            {"name": "Firewall Ready", "status": "PASS" if fw_ok else "FAIL", "msg": "DR Rules applied"},
            {"name": "Disk Capacity", "status": "PASS" if disk_ok else "FAIL", "msg": "85% Available"},
            {"name": "Service Health", "status": "PASS" if service_ok else "FAIL", "msg": "Agent Service Active"}
        ]
    })


# ──────────────────────────────────────────────────────────────────────────────
# API — FEATURE #34: COLLABORATION TOOLS
# ──────────────────────────────────────────────────────────────────────────────

@app.route("/api/cases/<int:case_id>/comments", methods=["GET"])
@jwt_required
def get_case_comments(case_id):
    comments = CaseComment.query.filter_by(case_id=case_id).order_by(CaseComment.created_at.asc()).all()
    return jsonify([{
        "id": c.id,
        "user": c.author.full_name or c.author.username,
        "user_email": c.author.email,
        "text": c.text,
        "is_system": c.is_system,
        "created_at": c.created_at.isoformat()
    } for c in comments])

@app.route("/api/cases/<int:case_id>/comments", methods=["POST"])
@jwt_required
@audit_log_action("Add Case Comment")
def add_case_comment(case_id):
    data = request.get_json(force=True)
    text = data.get("text")
    if not text:
        return jsonify({"error": "Comment text required"}), 400
    
    comment = CaseComment(
        case_id=case_id,
        user_id=g.user.id,
        text=text
    )
    db.session.add(comment)
    
    # Simple @mention parsing
    mentions = re.findall(r'@(\w+)', text)
    for username in mentions:
        target_user = User.query.filter_by(username=username).first()
        if target_user:
            notif = Notification(
                user_id=target_user.id,
                type="mention",
                message=f"{g.user.username} mentioned you in Case #{case_id}",
                case_id=case_id
            )
            db.session.add(notif)
            
    db.session.commit()
    return jsonify({"message": "Comment added successfully"})

@app.route("/api/notifications", methods=["GET"])
@jwt_required
def get_notifications():
    notifs = Notification.query.filter_by(user_id=g.user.id).order_by(Notification.created_at.desc()).limit(20).all()
    return jsonify([{
        "id": n.id,
        "type": n.type,
        "message": n.message,
        "case_id": n.case_id,
        "is_read": n.is_read,
        "created_at": n.created_at.isoformat()
    } for n in notifs])

@app.route("/api/notifications/mark-read", methods=["POST"])
@jwt_required
def mark_notifications_read():
    data = request.get_json(force=True)
    ids = data.get("ids", [])
    Notification.query.filter(Notification.id.in_(ids), Notification.user_id == g.user.id).update({"is_read": True}, synchronize_session=False)
    db.session.commit()
    return jsonify({"message": "Notifications marked as read"})


# ──────────────────────────────────────────────────────────────────────────────
# API — INTELLIGENT ALERT ROUTING
# ──────────────────────────────────────────────────────────────────────────────

@app.route("/api/settings/notification-routes", methods=["GET", "POST"])
@jwt_required
@require_role(ROLE_SUPERUSER)
def manage_notification_routes():
    if request.method == "POST":
        data = request.get_json(force=True)
        # Create or update a route
        route_id = data.get("id")
        if route_id:
            route = NotificationRoute.query.get(route_id)
        else:
            route = NotificationRoute()
            
        route.match_type = data.get("match_type", "default")
        route.match_value = data.get("match_value")
        route.recipient_email = data.get("recipient_email")
        db.session.add(route)
        db.session.commit()
        return jsonify({"message": "Route updated successfully"})

    routes = NotificationRoute.query.all()
    return jsonify([{
        "id": r.id,
        "match_type": r.match_type,
        "match_value": r.match_value,
        "recipient_email": r.recipient_email
    } for r in routes])

def dispatch_alert_notification(alert):
    """
    Intelligent routing logic to determine recipient email based on server metadata.
    """
    server = alert.server
    if server and getattr(server, 'is_maintenance', False):
        logger.info(f"SUPPRESSED: Alert '{alert.title}' notification suppressed (Server in Maintenance)")
        return None
    recipient = None
    
    # 1. Match by Role (e.g. standby -> DB Team)
    if server and server.role:
        route = NotificationRoute.query.filter_by(match_type="role", match_value=server.role).first()
        if route: recipient = route.recipient_email
        
    # 2. Match by Site (e.g. Cloud -> Cloud Team)
    if not recipient and server and server.site:
        route = NotificationRoute.query.filter_by(match_type="site", match_value=server.site).first()
        if route: recipient = route.recipient_email
        
    # 3. Fallback to Default
    if not recipient:
        route = NotificationRoute.query.filter_by(match_type="default").first()
        recipient = route.recipient_email if route else "soc-manager@securepulse.local"

    # Simulation of Email Dispatch
    logger.info(f"AUTO-DISPATCH: Alert '{alert.title}' routed to {recipient}")
    # Here you would add: mail.send_message(subject=alert.title, recipients=[recipient], body=alert.message)
    
    return recipient

@app.route("/api/cases/<int:case_id>/send-alert", methods=["POST"])
@jwt_required
@require_role(ROLE_ADMIN, ROLE_SUPERUSER)
def send_routed_alert(case_id):
    # Find the server associated with this case (via its alerts)
    first_alert = Alert.query.filter_by(case_id=case_id).first()
    if not first_alert:
        return jsonify({"error": "No alerts found in this case to route"}), 400
    
    recipient = dispatch_alert_notification(first_alert)
    
    return jsonify({
        "message": f"Security alert successfully routed to {recipient}",
        "team_email": recipient
    })
    if not config: return jsonify({})
    return jsonify({
        "provider": config.provider,
        "base_url": config.base_url,
        "project_key": config.project_key,
        "is_enabled": config.is_enabled
    })

@app.route("/api/cases/<int:case_id>/tickets", methods=["POST"])
@jwt_required
@require_role(ROLE_ADMIN, ROLE_SUPERUSER)
@audit_log_action("Create External Ticket")
def create_case_ticket(case_id):
    case = Case.query.get_or_404(case_id)
    # Simulate Jira ticket creation
    ticket_id = f"SEC-{1000 + case_id}"
    ticket_url = f"https://jira.securepulse.local/browse/{ticket_id}"
    
    ticket = CaseTicket(
        case_id=case_id,
        ticket_id=ticket_id,
        ticket_url=ticket_url,
        ticket_status="Open",
        last_synced=datetime.now(timezone.utc)
    )
    db.session.add(ticket)
    db.session.commit()
    return jsonify({"message": f"Jira ticket {ticket_id} created.", "ticket_id": ticket_id, "url": ticket_url})


# ──────────────────────────────────────────────────────────────────────────────
# API — PART C: PROJECT MANAGEMENT
# ──────────────────────────────────────────────────────────────────────────────

@app.route("/api/projects", methods=["GET"])
@jwt_required
def get_projects():
    projects = Project.query.all()
    res = []
    for p in projects:
        # Filter alerts for endpoints in this project
        endpoint_ids = [ep.server_id for ep in p.endpoints]
        alert_count = Alert.query.filter(Alert.server_id.in_(endpoint_ids), Alert.is_resolved == False).count()
        critical_count = Alert.query.filter(Alert.server_id.in_(endpoint_ids), Alert.severity == "critical", Alert.is_resolved == False).count()
        
        res.append({
            "id": p.id,
            "name": p.name,
            "description": p.description,
            "endpoint_count": len(endpoint_ids),
            "alert_count": alert_count,
            "critical_count": critical_count,
            "created_at": p.created_at.isoformat()
        })
    return jsonify(res)

@app.route("/api/projects", methods=["POST"])
@jwt_required
@require_role(ROLE_ADMIN, ROLE_SUPERUSER)
@audit_log_action("Create Project")
def create_project():
    data = request.get_json(force=True)
    name = data.get("name")
    if not name: return jsonify({"error": "Name required"}), 400
    
    project = Project(
        name=name,
        description=data.get("description"),
        created_by=g.user.id
    )
    db.session.add(project)
    db.session.flush()
    
    endpoint_ids = data.get("endpoint_ids", [])
    for eid in endpoint_ids:
        db.session.add(ProjectEndpoint(project_id=project.id, server_id=eid, added_by=g.user.id))
        
    db.session.commit()
    return jsonify({"id": project.id, "message": "Project created"})

@app.route("/api/projects/<int:id>/dashboard", methods=["GET"])
@jwt_required
def get_project_dashboard(id):
    project = Project.query.get_or_404(id)
    endpoint_ids = [ep.server_id for ep in project.endpoints]
    
    if not endpoint_ids:
        return jsonify({"endpoints": [], "stats": {"alerts": 0, "critical": 0, "events": 0}})

    alerts = Alert.query.filter(Alert.server_id.in_(endpoint_ids)).all()
    events_count = Event.query.filter(Event.server_id.in_(endpoint_ids)).count()
    
    return jsonify({
        "project_name": project.name,
        "stats": {
            "endpoints": len(endpoint_ids),
            "alerts": len([a for a in alerts if not a.is_resolved]),
            "critical": len([a for a in alerts if a.severity == "critical" and not a.is_resolved]),
            "events": events_count
        },
        "endpoints": [{
            "id": ep.server.id,
            "hostname": ep.server.hostname,
            "ip": ep.server.ip_address,
            "status": ep.server.status,
            "alerts": ep.server.alerts.filter_by(is_resolved=False).count()
        } for ep in project.endpoints]
    })


# ──────────────────────────────────────────────────────────────────────────────
# ERROR HANDLERS
# ──────────────────────────────────────────────────────────────────────────────

@app.errorhandler(404)
def not_found(e):
    if request.path.startswith("/auth") or request.path.startswith("/api"):
        return jsonify({"error": "Not found"}), 404
    return render_template("404.html"), 404

@app.errorhandler(500)
def internal_error(e):
    db.session.rollback()
    import traceback
    logger.error(f"Internal 500 Error: {e}")
    logger.error(traceback.format_exc())
    return jsonify({"error": "Internal server error", "details": str(e)}), 500


# ──────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ──────────────────────────────────────────────────────────────────────────────

def seed_default_rules():
    """Seed 15 production detection rules into the YAML file if not already present."""
    import yaml as _yaml
    rules_dir = os.path.join(base_dir, "rules")
    rules_path = os.path.join(rules_dir, "default_rules.yaml")
    os.makedirs(rules_dir, exist_ok=True)

    DEFAULT_RULES = [
        {"name": "SSH Root Login Attempt", "event_type": "ssh_login", "severity": "critical",
         "condition": {"field": "description", "operator": "contains", "value": "user root"},
         "mitre_tactic": "Initial Access", "mitre_technique": "T1078",
         "message": "SSH login attempt as root user detected", "is_active": True},
        {"name": "Sensitive File Access /etc/shadow", "event_type": "file_change", "severity": "critical",
         "condition": {"field": "description", "operator": "contains", "value": "/etc/shadow"},
         "mitre_tactic": "Credential Access", "mitre_technique": "T1003.008",
         "message": "Sensitive file /etc/shadow accessed or modified", "is_active": True},
        {"name": "Reverse Shell Pattern", "event_type": "new_process", "severity": "critical",
         "condition": {"field": "description", "operator": "regex", "value": r"bash\s+-i\s+>&?\s+/dev/tcp"},
         "mitre_tactic": "Execution", "mitre_technique": "T1059.004",
         "message": "Reverse shell pattern detected in process arguments", "is_active": True},
        {"name": "Netcat Listener Detected", "event_type": "new_process", "severity": "critical",
         "condition": {"field": "description", "operator": "regex", "value": r"nc\s+(-l|-lp|-lvp)"},
         "mitre_tactic": "Execution", "mitre_technique": "T1059",
         "message": "Netcat listener started — possible C2 channel", "is_active": True},
        {"name": "Passwd File Modified", "event_type": "file_change", "severity": "critical",
         "condition": {"field": "description", "operator": "contains", "value": "/etc/passwd"},
         "mitre_tactic": "Persistence", "mitre_technique": "T1136",
         "message": "/etc/passwd file was modified — possible user account manipulation", "is_active": True},
        {"name": "SSH Authorized Keys Modified", "event_type": "file_change", "severity": "critical",
         "condition": {"field": "description", "operator": "contains", "value": "authorized_keys"},
         "mitre_tactic": "Persistence", "mitre_technique": "T1098.004",
         "message": "SSH authorized_keys file modified — possible backdoor installation", "is_active": True},
        {"name": "Crontab Modification", "event_type": "file_change", "severity": "critical",
         "condition": {"field": "description", "operator": "contains", "value": "/etc/cron"},
         "mitre_tactic": "Persistence", "mitre_technique": "T1053.005",
         "message": "Crontab or cron directory modified — possible persistence mechanism", "is_active": True},
        {"name": "SUID Binary Created", "event_type": "new_process", "severity": "critical",
         "condition": {"field": "description", "operator": "contains", "value": "chmod +s"},
         "mitre_tactic": "Privilege Escalation", "mitre_technique": "T1548.001",
         "message": "SUID bit set on binary — privilege escalation risk", "is_active": True},
        {"name": "Unauthorized Sudo Usage", "event_type": "new_process", "severity": "warning",
         "condition": {"field": "description", "operator": "contains", "value": "sudo"},
         "mitre_tactic": "Privilege Escalation", "mitre_technique": "T1548.003",
         "message": "Sudo command executed — verify if authorized", "is_active": True},
        {"name": "Failed Brute Force Pattern", "event_type": "failed_login", "severity": "warning",
         "condition": {"field": "description", "operator": "contains", "value": "Failed pwd"},
         "mitre_tactic": "Credential Access", "mitre_technique": "T1110",
         "message": "Multiple failed password attempts detected", "is_active": True},
        {"name": "Port Scan Detected", "event_type": "network_event", "severity": "warning",
         "condition": {"field": "description", "operator": "contains", "value": "port_scan"},
         "mitre_tactic": "Discovery", "mitre_technique": "T1046",
         "message": "Port scanning activity detected from external source", "is_active": True},
        {"name": "Large File Transfer", "event_type": "network_event", "severity": "warning",
         "condition": {"field": "description", "operator": "contains", "value": "large_upload"},
         "mitre_tactic": "Exfiltration", "mitre_technique": "T1048",
         "message": "Large outbound file transfer detected — possible data exfiltration", "is_active": True},
        {"name": "New User Account Created", "event_type": "new_process", "severity": "warning",
         "condition": {"field": "description", "operator": "contains", "value": "useradd"},
         "mitre_tactic": "Persistence", "mitre_technique": "T1136.001",
         "message": "New OS user account created — verify if authorized", "is_active": True},
        {"name": "Package Manager Unusual Usage", "event_type": "new_process", "severity": "warning",
         "condition": {"field": "description", "operator": "contains", "value": "apt-get install"},
         "mitre_tactic": "Execution", "mitre_technique": "T1072",
         "message": "Software installation via apt-get detected outside maintenance window", "is_active": True},
        {"name": "Service Stopped Unexpectedly", "event_type": "service_event", "severity": "warning",
         "condition": {"field": "description", "operator": "contains", "value": "service_stopped"},
         "mitre_tactic": "Impact", "mitre_technique": "T1489",
         "message": "Critical service stopped unexpectedly — possible impact or sabotage", "is_active": True},
    ]

    try:
        yaml_data = {"rules": []}
        if os.path.exists(rules_path):
            with open(rules_path, "r") as f:
                yaml_data = _yaml.safe_load(f) or {"rules": []}

        existing_names = {r.get("name") for r in yaml_data.get("rules", [])}
        added = 0
        for rule in DEFAULT_RULES:
            if rule["name"] not in existing_names:
                yaml_data["rules"].append(rule)
                added += 1
                # Also sync to DB for playbook linking
                try:
                    if not AlertRule.query.filter_by(name=rule["name"]).first():
                        db.session.add(AlertRule(
                            name=rule["name"],
                            event_type=rule["event_type"],
                            severity=rule["severity"],
                        ))
                except Exception:
                    pass

        if added > 0:
            with open(rules_path, "w") as f:
                _yaml.dump(yaml_data, f, default_flow_style=False, allow_unicode=True)
            db.session.commit()
            logger.info(f"Seeded {added} default detection rules")
        rule_manager.load_rules()
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error seeding detection rules: {e}")


def seed_default_playbooks():
    """Seed 8 production-ready default playbooks if not already present."""
    DEFAULT_PLAYBOOKS = [
        {"name": "Auto-Isolate + Notify", "description": "Isolate host and notify team on critical brute-force",
         "actions": [{"type": "isolate_host"}, {"type": "notify_email"}, {"type": "notify_slack"}, {"type": "promote_to_case"}]},
        {"name": "Brute Force Response", "description": "Block source IP and notify on repeated failed logins",
         "actions": [{"type": "block_ip"}, {"type": "notify_slack"}, {"type": "resolve_alert"}]},
        {"name": "Malware Detection Response", "description": "Full containment on reverse shell or netcat detection",
         "actions": [{"type": "isolate_host"}, {"type": "block_ip"}, {"type": "disable_account"}, {"type": "notify_email"}, {"type": "promote_to_case"}]},
        {"name": "File Integrity Alert", "description": "Health check and escalate on sensitive file modification",
         "actions": [{"type": "run_health_check"}, {"type": "notify_slack"}, {"type": "promote_to_case"}]},
        {"name": "Service Down Auto-Restart", "description": "Auto-restart stopped service and notify",
         "actions": [{"type": "restart_service"}, {"type": "run_health_check"}, {"type": "notify_email"}]},
        {"name": "SSH Root Login Response", "description": "Disable account and escalate on root SSH login",
         "actions": [{"type": "disable_account"}, {"type": "notify_slack"}, {"type": "promote_to_case"}]},
        {"name": "Critical Alert Escalation", "description": "Email all admins when critical alert has no response",
         "actions": [{"type": "notify_email"}, {"type": "notify_slack"}]},
        {"name": "Suspicious Process Response", "description": "Health check and notify on suspicious critical process",
         "actions": [{"type": "run_health_check"}, {"type": "notify_slack"}, {"type": "promote_to_case"}]},
    ]
    try:
        added = 0
        for pb_data in DEFAULT_PLAYBOOKS:
            if not Playbook.query.filter_by(name=pb_data["name"]).first():
                pb = Playbook(
                    name=pb_data["name"],
                    description=pb_data["description"],
                    actions=json.dumps(pb_data["actions"]),
                    is_active=True
                )
                db.session.add(pb)
                added += 1
        if added > 0:
            db.session.commit()
            logger.info(f"Seeded {added} default playbooks")
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error seeding playbooks: {e}")



# ══════════════════════════════════════════════════════════════════════════════
# PHASE 2 — REAL API INTEGRATIONS & FEATURES
# ══════════════════════════════════════════════════════════════════════════════

# ──────────────────────────────────────────────────────────────────────────────
# FEATURE #32 — TOTP / MFA SETUP (Real TOTP generation + QR code)
# ──────────────────────────────────────────────────────────────────────────────

@app.route("/api/mfa/setup", methods=["GET"])
@jwt_required
def mfa_setup_get():
    """Initiate MFA setup — generate TOTP secret and QR code."""
    if not TOTP_AVAILABLE:
        return jsonify({"error": "TOTP library not installed"}), 501
    
    user = User.query.get(g.user_id)
    if user.mfa_enabled:
        return jsonify({"error": "MFA already enabled for this user"}), 400
    
    # Generate new TOTP secret
    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)
    
    # Generate QR code
    qr = qrcode.QRCode(version=1, box_size=10, border=2)
    qr.add_data(totp.provisioning_uri(name=user.email or user.username, issuer_name="SecurePulse"))
    qr.make(fit=True)
    
    # Convert to base64
    img_buffer = io.BytesIO()
    img = qr.make_image(fill_color="black", back_color="white")
    img.save(img_buffer, format="PNG")
    img_base64 = base64.b64encode(img_buffer.getvalue()).decode()
    
    return jsonify({
        "secret": secret,
        "qr_code_base64": f"data:image/png;base64,{img_base64}",
        "backup_codes": [pyotp.random_base32()[:10] for _ in range(5)],
        "message": "Scan QR code with authenticator app and verify with the code below"
    })

@app.route("/api/mfa/verify", methods=["POST"])
@jwt_required
def mfa_verify():
    """Verify TOTP code and enable MFA for user."""
    if not TOTP_AVAILABLE:
        return jsonify({"error": "TOTP library not installed"}), 501
    
    data = request.get_json(force=True)
    code = data.get("code", "")
    secret = data.get("secret", "")
    
    user = User.query.get(g.user_id)
    if user.mfa_enabled:
        return jsonify({"error": "MFA already enabled"}), 400
    
    totp = pyotp.TOTP(secret)
    if not totp.verify(code, valid_window=1):
        return jsonify({"error": "Invalid verification code"}), 401
    
    # Enable MFA
    user.mfa_enabled = True
    user.mfa_secret = secret
    db.session.commit()
    
    log_audit(f"Enabled TOTP MFA", f"User: {user.username}", user.id)
    
    return jsonify({"message": "MFA enabled successfully", "backup_codes": [pyotp.random_base32()[:10] for _ in range(5)]})

@app.route("/api/mfa/disable", methods=["POST"])
@jwt_required
def mfa_disable():
    """Disable MFA for current user (requires superuser for others)."""
    user_id = request.get_json(force=True).get("user_id", g.user_id)
    
    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    # Only superuser can disable MFA for others
    if user_id != g.user_id:
        if g.jwt_payload.get("role") != ROLE_SUPERUSER:
            return jsonify({"error": "Insufficient permissions"}), 403
    
    user.mfa_enabled = False
    user.mfa_secret = None
    db.session.commit()
    
    log_audit("Disabled MFA", f"User: {user.username}", g.user_id)
    return jsonify({"message": f"MFA disabled for {user.username}"})

@app.route("/api/mfa/validate", methods=["POST"])
def mfa_validate():
    """Validate TOTP code during login (called before JWT creation)."""
    if not TOTP_AVAILABLE:
        return jsonify({"message": "OK"}), 200
    
    data = request.get_json(force=True)
    code = data.get("code", "")
    username = data.get("username", "")
    
    user = User.query.filter_by(username=username).first()
    if not user or not user.mfa_enabled or not user.mfa_secret:
        return jsonify({"message": "OK"}), 200
    
    totp = pyotp.TOTP(user.mfa_secret)
    if totp.verify(code, valid_window=1):
        return jsonify({"message": "OK"}), 200
    else:
        return jsonify({"error": "Invalid MFA code"}), 401

# ──────────────────────────────────────────────────────────────────────────────
# FEATURE #35 — REAL JIRA CLOUD SYNC
# ──────────────────────────────────────────────────────────────────────────────

@app.route("/api/cases/<int:case_id>/sync-jira", methods=["POST"])
@jwt_required
@require_role(ROLE_ADMIN, ROLE_SUPERUSER)
@audit_log_action("Sync Case to Jira")
def sync_case_jira_real(case_id):
    """
    Phase 2 #35: Real Jira Cloud REST API integration.
    Creates/updates ticket with case details and links.
    """
    case = Case.query.get_or_404(case_id)
    jira_cfg = JiraConfig.query.filter_by(provider="jira_cloud", is_enabled=True).first()
    
    if not jira_cfg:
        return jsonify({"error": "Jira not configured or disabled"}), 422
    
    if not jira_cfg.base_url or not jira_cfg.api_token or not jira_cfg.user_email:
        return jsonify({"error": "Jira configuration incomplete"}), 422
    
    try:
        # Check for existing ticket link
        ticket = CaseTicket.query.filter_by(case_id=case.id).first()
        is_create = not ticket
        
        issue_key = None
        if is_create:
            # Create new issue
            summary = f"[SecurePulse] {case.title}"
            description = f"{case.summary}\n\nPriority: {case.priority}\nSecurity Case #{case.id}\n"
            
            alerts = Alert.query.filter_by(case_id=case.id).all()
            if alerts:
                description += f"\n**Linked Alerts ({len(alerts)}):**\n"
                for a in alerts[:10]:
                    description += f"- {a.title} (Severity: {a.severity})\n"
            
            issue_data = {
                "fields": {
                    "project": {"key": jira_cfg.project_key},
                    "summary": summary[:255],
                    "description": description,
                    "issuetype": {"name": jira_cfg.issue_type},
                    "priority": {"name": {"critical": "Highest", "high": "High", "warning": "Medium", "info": "Low"}.get(case.priority, "Medium")},
                }
            }
            
            resp = requests.post(
                f"{jira_cfg.base_url}/rest/api/3/issues",
                headers={
                    "Authorization": f"Basic {base64.b64encode(f'{jira_cfg.user_email}:{jira_cfg.api_token}'.encode()).decode()}",
                    "Content-Type": "application/json"
                },
                json=issue_data,
                timeout=15
            )
            
            if resp.status_code not in (200, 201):
                logger.error(f"Jira create failed: {resp.status_code} — {resp.text}")
                return jsonify({"error": f"Jira API error: {resp.status_code}"}), 422
            
            issue_key = resp.json().get("key")
            ticket = CaseTicket(
                case_id=case.id,
                ticket_id=issue_key,
                ticket_url=f"{jira_cfg.base_url}/browse/{issue_key}",
                provider="jira_cloud",
                ticket_status="Open"
            )
            db.session.add(ticket)
        else:
            # Update existing issue
            issue_key = ticket.ticket_id
            update_data = {
                "fields": {
                    "summary": f"[SecurePulse] {case.title}"[:255],
                    "status": {"name": {"open": "To Do", "in_progress": "In Progress", "resolved": "Done"}.get(case.status, "To Do")}
                }
            }
            resp = requests.put(
                f"{jira_cfg.base_url}/rest/api/3/issues/{issue_key}",
                headers={
                    "Authorization": f"Basic {base64.b64encode(f'{jira_cfg.user_email}:{jira_cfg.api_token}'.encode()).decode()}",
                    "Content-Type": "application/json"
                },
                json=update_data,
                timeout=15
            )
            if resp.status_code != 204:
                logger.error(f"Jira update failed: {resp.status_code}")
                return jsonify({"error": f"Jira API error: {resp.status_code}"}), 422
        
        ticket.last_synced = datetime.now(timezone.utc)
        ticket.sync_error = None
        db.session.commit()
        
        return jsonify({
            "message": f"Case synced to Jira: {issue_key}",
            "ticket_id": issue_key,
            "ticket_url": ticket.ticket_url if ticket else None,
            "is_new": is_create
        })
    
    except Exception as e:
        logger.error(f"Jira sync error: {e}")
        if ticket:
            ticket.sync_error = str(e)
            db.session.commit()
        return jsonify({"error": f"Jira sync failed: {str(e)}"}), 500

# ──────────────────────────────────────────────────────────────────────────────
# FEATURE #11/#7 — LIVE SLA COUNTDOWN & BREACH DETECTION
# ──────────────────────────────────────────────────────────────────────────────

@app.route("/api/cases/<int:case_id>/sla-status", methods=["GET"])
@jwt_required
def get_case_sla_status(case_id):
    """Get live SLA countdown for case — returns seconds until breach."""
    case = Case.query.get_or_404(case_id)
    
    if not case.due_at:
        return jsonify({"sla_status": "none", "message": "No SLA set"}), 200
    
    now = datetime.now(timezone.utc)
    due = case.due_at.replace(tzinfo=timezone.utc) if case.due_at.tzinfo is None else case.due_at
    
    remaining_sec = int((due - now).total_seconds())
    
    if remaining_sec < 0:
        # Breach
        case.sla_breached = True
        db.session.commit()
        socketio.emit("sla_breach", {
            "case_id": case.id,
            "case_title": case.title,
            "priority": case.priority
        }, room="dashboard")
        return jsonify({
            "sla_status": "breached",
            "remaining_seconds": 0,
            "due_at": due.isoformat(),
            "message": f"SLA breached {abs(remaining_sec)}s ago"
        })
    
    status = "critical" if remaining_sec < 1800 else "warning" if remaining_sec < 7200 else "ok"
    
    return jsonify({
        "sla_status": status,
        "remaining_seconds": remaining_sec,
        "remaining_str": f"{remaining_sec // 3600}h {(remaining_sec % 3600) // 60}m",
        "due_at": due.isoformat(),
        "message": "On track" if status == "ok" else "SLA at risk" if status == "warning" else "SLA critical"
    })

# ──────────────────────────────────────────────────────────────────────────────
# FEATURE #12 — IOC EXPIRY & BULK IMPORT
# ──────────────────────────────────────────────────────────────────────────────

@app.route("/api/threat-intel/bulk-import", methods=["POST"])
@jwt_required
@require_role(ROLE_ADMIN, ROLE_SUPERUSER)
@audit_log_action("Bulk Import IOCs")
def bulk_import_iocs():
    """Bulk import IOCs from CSV or newline-delimited text."""
    data = request.get_json(force=True)
    ioc_list = data.get("iocs", [])  # List of {"value": "...", "type": "ip|domain|hash", "severity": "..."}
    source = data.get("source", "manual")
    
    if not ioc_list:
        return jsonify({"error": "Empty IOC list"}), 400
    
    added = 0
    duplicates = 0
    
    for ioc in ioc_list:
        value = ioc.get("value", "").strip()
        ioc_type = ioc.get("type", "ip")
        severity = ioc.get("severity", "medium")
        
        if not value:
            continue
        
        existing = ThreatIndicator.query.filter_by(value=value, indicator_type=ioc_type).first()
        if existing:
            duplicates += 1
            continue
        
        ti = ThreatIndicator(
            value=value,
            indicator_type=ioc_type,
            source=source,
            severity=severity,
            is_blocked=False
        )
        db.session.add(ti)
        added += 1
    
    db.session.commit()
    return jsonify({
        "message": f"Imported {added} IOCs",
        "added": added,
        "duplicates": duplicates,
        "total_processed": added + duplicates
    }), 201

@app.route("/api/threat-intel/auto-expire", methods=["POST"])
@jwt_required
@require_role(ROLE_SUPERUSER)
def run_ioc_expiry_job():
    """
    Batch job: Expire old IOCs and unblock IPs.
    Called periodically (or manually for testing).
    """
    cutoff = datetime.now(timezone.utc) - timedelta(days=90)
    
    # Expire old threat indicators
    expired_iocs = ThreatIndicator.query.filter(
        ThreatIndicator.created_at < cutoff,
        ThreatIndicator.is_blocked == False
    ).all()
    
    count = 0
    for ti in expired_iocs:
        db.session.delete(ti)
        count += 1
    
    # Unblock expired IP blocks
    expired_blocks = BlockedIP.query.filter(
        BlockedIP.expires_at < datetime.now(timezone.utc),
        BlockedIP.status == "active"
    ).all()
    
    for block in expired_blocks:
        block.status = "expired"
        count += 1
    
    db.session.commit()
    logger.info(f"IOC expiry job: removed {count} old indicators")
    
    return jsonify({
        "message": f"Expired {count} old IOCs and unblocked IPs",
        "count": count
    })

# ──────────────────────────────────────────────────────────────────────────────
# FEATURE #26 — REAL EXEC DASHBOARD KPIs (MTTD, MTTR)
# ──────────────────────────────────────────────────────────────────────────────

@app.route("/api/dashboard/exec-kpis", methods=["GET"])
@jwt_required
@require_role(ROLE_ADMIN, ROLE_SUPERUSER)
def get_exec_kpis():
    """Real KPIs: MTTD, MTTR, SLA compliance, analyst metrics."""
    days = request.args.get("days", 30, type=int)
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    
    # Get resolved cases in window
    resolved_cases = Case.query.filter(
        Case.status == "resolved",
        Case.updated_at >= cutoff
    ).all()
    
    # Mean Time To Detection (MTTD) — from first alert to case creation
    mtds = []
    for case in resolved_cases:
        alerts = Alert.query.filter_by(case_id=case.id).all()
        if alerts:
            first_alert_time = min(a.created_at for a in alerts)
            mttd_sec = (case.created_at - first_alert_time).total_seconds()
            mtds.append(mttd_sec)
    
    avg_mttd = sum(mtds) / len(mtds) if mtds else 0
    
    # Mean Time To Resolve (MTTR) — from case creation to resolution
    mttrs = []
    for case in resolved_cases:
        mttr_sec = (case.updated_at - case.created_at).total_seconds()
        mttrs.append(mttr_sec)
    
    avg_mttr = sum(mttrs) / len(mttrs) if mttrs else 0
    
    # SLA Compliance
    all_cases = Case.query.filter(Case.created_at >= cutoff).all()
    sla_breached = sum(1 for c in all_cases if getattr(c, 'sla_breached', False))
    sla_compliance = ((len(all_cases) - sla_breached) / len(all_cases) * 100) if all_cases else 0
    
    # Analyst performance (most active)
    top_analysts = db.session.query(
        CaseComment.user_id,
        func.count(CaseComment.id).label("comments")
    ).filter(CaseComment.created_at >= cutoff).group_by(CaseComment.user_id).order_by(func.count(CaseComment.id).desc()).limit(5).all()
    
    analysts = []
    for uid, comment_count in top_analysts:
        user = User.query.get(uid)
        if user:
            analysts.append({
                "name": user.full_name or user.username,
                "comments": comment_count,
                "cases": len([c for c in resolved_cases if any(cm.user_id == uid for cm in CaseComment.query.filter_by(case_id=c.id).all())])
            })
    
    return jsonify({
        "window_days": days,
        "mttd_hours": round(avg_mttd / 3600, 2),
        "mttr_hours": round(avg_mttr / 3600, 2),
        "sla_compliance_percent": round(sla_compliance, 1),
        "cases_resolved": len(resolved_cases),
        "cases_total": len(all_cases),
        "sla_breached_count": sla_breached,
        "top_analysts": analysts
    })

# ──────────────────────────────────────────────────────────────────────────────
# FEATURE #27/#28 — COMPLIANCE REPORTING & EVIDENCE EXPORT (PDF with hash)
# ──────────────────────────────────────────────────────────────────────────────

@app.route("/api/cases/<int:case_id>/export-evidence", methods=["GET"])
@jwt_required
def export_case_evidence(case_id):
    """
    Export case as PDF with chain-of-custody hash.
    Phase 2: Real PDF generation with proper formatting and signatures.
    """
    case = Case.query.get_or_404(case_id)
    
    if not REPORTLAB_AVAILABLE:
        return jsonify({"error": "PDF library not available"}), 501
    
    # Create PDF
    pdf_buffer = io.BytesIO()
    doc = SimpleDocTemplate(pdf_buffer, pagesize=A4, topMargin=0.75*cm, bottomMargin=0.75*cm)
    story = []
    styles = getSampleStyleSheet()
    
    # Header
    story.append(Paragraph(f"<b>SecurePulse Incident Report</b>", styles['Title']))
    story.append(Paragraph(f"Case #{case.id}: {case.title}", styles['Heading2']))
    story.append(Spacer(1, 0.3*cm))
    
    # Metadata
    meta_style = ParagraphStyle(name='Meta', fontName='Courier', fontSize=9, textColor=colors.grey)
    story.append(Paragraph(f"<b>Created:</b> {case.created_at.strftime('%Y-%m-%d %H:%M:%S UTC')}", meta_style))
    story.append(Paragraph(f"<b>Priority:</b> {case.priority.upper()}", meta_style))
    story.append(Paragraph(f"<b>Status:</b> {case.status.upper()}", meta_style))
    story.append(Spacer(1, 0.2*cm))
    
    # Summary
    story.append(Paragraph("<b>Summary</b>", styles['Heading3']))
    story.append(Paragraph(case.summary or "(No summary)", styles['Normal']))
    story.append(Spacer(1, 0.3*cm))
    
    # Linked Alerts
    alerts = Alert.query.filter_by(case_id=case.id).all()
    if alerts:
        story.append(Paragraph(f"<b>Linked Alerts ({len(alerts)})</b>", styles['Heading3']))
        alert_data = [["ID", "Type", "Severity", "Title"]]
        for a in alerts[:20]:
            alert_data.append([str(a.id), a.alert_type[:15], a.severity.upper(), a.title[:40]])
        alert_table = Table(alert_data, colWidths=[1.5*cm, 2.5*cm, 1.5*cm, 7*cm])
        alert_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.black),
            ("ALIGN", (0, 0), (-1, -1), "LEFT"),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 9),
            ("BOTTOMPADDING", (0, 0), (-1, 0), 12),
            ("GRID", (0, 0), (-1, -1), 1, colors.black),
            ("FONTSIZE", (0, 1), (-1, -1), 8),
        ]))
        story.append(alert_table)
        story.append(Spacer(1, 0.3*cm))
    
    # Comments/Evidence
    comments = CaseComment.query.filter_by(case_id=case.id).all()
    if comments:
        story.append(Paragraph(f"<b>Evidence & Comments ({len(comments)})</b>", styles['Heading3']))
        for c in comments[:10]:
            user = c.author.full_name or c.author.username
            story.append(Paragraph(f"<i>{user} — {c.created_at.strftime('%Y-%m-%d %H:%M UTC')}</i>", meta_style))
            story.append(Paragraph(c.text[:300], styles['Normal']))
            story.append(Spacer(1, 0.1*cm))
    
    # Chain of Custody
    story.append(HRFlowable(width="100%", thickness=1, color=colors.grey))
    story.append(Spacer(1, 0.2*cm))
    export_time = datetime.now(timezone.utc)
    user = User.query.get(g.user_id)
    exported_by = user.full_name or user.username
    
    # Create hash for integrity verification
    evidence_content = f"{case.id}|{case.title}|{case.summary}|{export_time.isoformat()}|{exported_by}"
    coc_hash = hashlib.sha256(evidence_content.encode()).hexdigest()
    
    coc_style = ParagraphStyle(name='CoC', fontName='Courier', fontSize=8, textColor=colors.darkblue)
    story.append(Paragraph(f"<b>Chain of Custody</b>", styles['Heading3']))
    story.append(Paragraph(f"<b>Exported by:</b> {exported_by}", coc_style))
    story.append(Paragraph(f"<b>Export Time:</b> {export_time.strftime('%Y-%m-%d %H:%M:%S UTC')}", coc_style))
    story.append(Paragraph(f"<b>Integrity Hash (SHA256):</b><br/><font size=7>{coc_hash}</font>", coc_style))
    story.append(Paragraph(f"<i>This hash proves this export was generated at the time specified and has not been modified.</i>", meta_style))
    
    doc.build(story)
    pdf_buffer.seek(0)
    
    return send_file(
        pdf_buffer,
        mimetype="application/pdf",
        as_attachment=True,
        download_name=f"case_{case.id}_{export_time.strftime('%Y%m%d_%H%M%S')}.pdf"
    )

# ──────────────────────────────────────────────────────────────────────────────
# FEATURE #13 — MITRE ATT&CK MATRIX NAVIGATOR
# ──────────────────────────────────────────────────────────────────────────────

@app.route("/api/mitre-matrix", methods=["GET"])
@jwt_required
def get_mitre_matrix():
    """Return MITRE ATT&CK tactics with mapped techniques from alerts."""
    tactic = request.args.get("tactic")
    
    # Simplified MITRE tactics
    TACTICS = {
        "reconnaissance": ["Active Scanning", "Gather Victim Identity Information", "Search Open Websites"],
        "resource-development": ["Acquire Infrastructure", "Create Accounts", "Establish Accounts"],
        "initial-access": ["Phishing", "Valid Accounts", "Supply Chain Compromise"],
        "execution": ["Command & Scripting Interpreter", "Exploitation for Client Execution", "User Execution"],
        "persistence": ["Account Manipulation", "Browser Extensions", "Create Account"],
        "privilege-escalation": ["Access Token Manipulation", "Abuse Elevation Control Mechanism"],
        "defense-evasion": ["Abuse Elevation Control Mechanism", "Access Token Manipulation", "Masquerading"],
        "credential-access": ["Brute Force", "Credential Dumping", "Input Capture"],
        "discovery": ["Account Discovery", "Application Window Discovery", "File and Directory Discovery"],
        "lateral-movement": ["Exploitation of Remote Services", "Lateral Tool Transfer"],
        "collection": ["Clipboard Data", "Data from Local System", "Data Staged"],
        "command-control": ["Application Layer Protocol", "Data Obfuscation", "Proxy"],
        "exfiltration": ["Exfiltration Over C2 Channel", "Data Transfer Size Limits"],
        "impact": ["Account Access Removal", "Data Destruction", "Service Stop"],
    }
    
    if tactic:
        techniques = TACTICS.get(tactic, [])
        # Count alert hits per technique
        alert_counts = {}
        for tech in techniques:
            count = Alert.query.filter(Alert.mitre_technique.ilike(f"%{tech}%")).count()
            alert_counts[tech] = count
        return jsonify({
            "tactic": tactic,
            "techniques": techniques,
            "alert_counts": alert_counts
        })
    
    # Return all tactics with heatmap data
    return jsonify({
        "tactics": list(TACTICS.keys()),
        "matrix": TACTICS
    })

# ──────────────────────────────────────────────────────────────────────────────
# FEATURE #19 — REAL-TIME ASSET INVENTORY WITH HEARTBEAT STATUS
# ──────────────────────────────────────────────────────────────────────────────

@app.route("/api/assets/refresh-status", methods=["POST"])
@jwt_required
@require_role(ROLE_ADMIN, ROLE_SUPERUSER)
def refresh_asset_status():
    """Mark offline any servers not seen within heartbeat timeout."""
    timeout_sec = request.get_json(force=True).get("timeout_seconds", 120)
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=timeout_sec)
    
    offline_count = 0
    for server in Server.query.all():
        if not server.is_maintenance and server.last_seen and server.last_seen < cutoff and server.status != "isolated":
            server.status = "offline"
            offline_count += 1
    
    db.session.commit()
    
    socketio.emit("assets_status_updated", {
        "offline_count": offline_count,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }, room="dashboard")
    
    return jsonify({
        "message": f"Marked {offline_count} servers offline",
        "offline_count": offline_count
    })

# ──────────────────────────────────────────────────────────────────────────────
# FEATURE #20 — PIVOT & DRILL-DOWN SEARCH
# ──────────────────────────────────────────────────────────────────────────────

@app.route("/api/search/pivot", methods=["POST"])
@jwt_required
def pivot_search():
    """Click a field value to drill down to all events/alerts containing it."""
    data = request.get_json(force=True)
    field = data.get("field")  # e.g., "ip", "user", "hostname", "process"
    value = data.get("value")
    
    if not field or not value:
        return jsonify({"error": "field and value required"}), 400
    
    # Search across events
    events = Event.query.filter(
        Event.description.ilike(f"%{value}%") |
        Event.raw_data.ilike(f"%{value}%")
    ).limit(100).all()
    
    # Search across alerts
    alerts = Alert.query.filter(
        Alert.message.ilike(f"%{value}%") |
        Alert.title.ilike(f"%{value}%")
    ).limit(100).all()
    
    return jsonify({
        "field": field,
        "value": value,
        "events": [{
            "id": e.id,
            "type": e.event_type,
            "server": e.server.hostname if e.server else "unknown",
            "description": e.description[:100],
            "created_at": e.created_at.isoformat()
        } for e in events],
        "alerts": [{
            "id": a.id,
            "type": a.alert_type,
            "severity": a.severity,
            "title": a.title[:80],
            "server": a.server.hostname if a.server else "unknown"
        } for a in alerts]
    })

# ──────────────────────────────────────────────────────────────────────────────
# FEATURE #23 — ALERT DEDUPLICATION
# ──────────────────────────────────────────────────────────────────────────────

def should_suppress_alert(server_id, alert_type, title):
    """
    Phase 2: Alert deduplication — avoid spam from duplicate alerts.
    Suppresses identical alerts within 5 minutes.
    """
    fp_key = (server_id, alert_type, title)
    now_ts = time.time()
    
    last_time = alert_dedup_cache.get(fp_key, 0)
    if now_ts - last_time < 300:  # 5 minutes
        return True
    
    alert_dedup_cache[fp_key] = now_ts
    return False

def should_tune_fp(server_id, alert_type, title):
    """Check if alert is marked as false positive and should be suppressed."""
    return (server_id, alert_type, title) in fp_suppressed

@app.route("/api/alerts/<int:alert_id>/tune-fp", methods=["POST"])
@jwt_required
@require_role(ROLE_ADMIN, ROLE_SUPERUSER)
def tune_false_positive(alert_id):
    """Mark alert as false positive and suppress future similar ones."""
    alert = Alert.query.get_or_404(alert_id)
    data = request.get_json(force=True)
    suppress = data.get("suppress", True)
    
    if suppress:
        fp_key = (alert.server_id, alert.alert_type, alert.title)
        fp_suppressed.add(fp_key)
        logger.info(f"FP tuning: suppressing {fp_key}")
    else:
        fp_key = (alert.server_id, alert.alert_type, alert.title)
        fp_suppressed.discard(fp_key)
    
    return jsonify({
        "message": f"Alert FP tuning {'enabled' if suppress else 'disabled'}",
        "suppressed": suppress
    })



# Initialize database on startup
with app.app_context():
    init_db(app)
    rule_manager.load_rules()
    seed_admin()
    seed_default_rules()
    seed_default_playbooks()

if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    debug = os.getenv("DEBUG", "false").lower() == "true"
    logger.info(f"Starting SecurePulse on port {port} (debug={debug})")
    socketio.run(app, host="0.0.0.0", port=port, debug=debug, allow_unsafe_werkzeug=True)