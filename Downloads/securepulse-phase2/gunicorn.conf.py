# gunicorn.conf.py — SecurePulse Production Config
#
# Python 3.14 does NOT support eventlet or gevent yet.
# Use gthread worker which handles WebSocket via threading (Flask-SocketIO threading mode).
#
# Run with:
#   gunicorn --config gunicorn.conf.py app:app
#
# Or directly:
#   gunicorn --worker-class gthread --workers 1 --threads 8 --bind 0.0.0.0:5000 --timeout 120 app:app

# ── Worker class: gthread for Python 3.14 + Flask-SocketIO threading mode ──
worker_class = "gthread"
workers = 1        # Must be 1 for SocketIO session consistency
threads = 100      # Increased to 100 to handle concurrent HTTP requests + multiple long-polling WebSocket connections without starvation

# ── Bind ───────────────────────────────────────────────────────────
bind = "0.0.0.0:5000"

# ── Timeouts ───────────────────────────────────────────────────────
# WebSocket connections are long-lived; must be high
timeout = 300
keepalive = 75
graceful_timeout = 30

# ── Logging ────────────────────────────────────────────────────────
import os
_log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
os.makedirs(_log_dir, exist_ok=True)

accesslog = os.path.join(_log_dir, "access.log")
errorlog  = os.path.join(_log_dir, "error.log")
loglevel  = "info"

# ── Misc ───────────────────────────────────────────────────────────
preload_app = True
daemon = False
