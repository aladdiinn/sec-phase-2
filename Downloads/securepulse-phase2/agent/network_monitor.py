"""
agent/network_monitor.py — SecurePulse Agent
Monitors active network connections using psutil.
Sends a network_event for each new outbound connection to a remote IP.
"""

import time
import logging
import threading
import socket

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

from sender import send_event

logger = logging.getLogger("sp_agent.network_monitor")

POLL_SECONDS = 2

class NetworkMonitor(threading.Thread):
    def __init__(self, cfg: dict):
        super().__init__(name="network_monitor", daemon=True)
        self.cfg      = cfg
        self.interval = POLL_SECONDS
        self._stop    = threading.Event()
        self.seen_connections = set()

    def stop(self):
        self._stop.set()

    def run(self):
        if not HAS_PSUTIL:
            logger.error("psutil not installed — network monitor disabled.")
            return

        logger.info(f"Network monitor started (poll every {self.interval}s)")
        
        # Baseline
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'ESTABLISHED' and conn.remote_address:
                    self.seen_connections.add((conn.remote_address.ip, conn.remote_address.port))
        except (psutil.AccessDenied, Exception) as e:
            logger.warning(f"Initial network baseline failed: {e}")

        while not self._stop.is_set():
            self._stop.wait(self.interval)
            if self._stop.is_set():
                break

            try:
                current_conns = psutil.net_connections(kind='inet')
                for conn in current_conns:
                    if conn.status == 'ESTABLISHED' and conn.remote_address:
                        remote_ip = conn.remote_address.ip
                        remote_port = conn.remote_address.port
                        
                        # Ignore local/loopback
                        if remote_ip in ("127.0.0.1", "::1", "0.0.0.0"):
                            continue
                            
                        conn_key = (remote_ip, remote_port)
                        if conn_key not in self.seen_connections:
                            logger.info(f"New outbound connection: {remote_ip}:{remote_port} (PID {conn.pid})")
                            
                            # Try to get process name
                            proc_name = "unknown"
                            try:
                                proc_name = psutil.Process(conn.pid).name() if conn.pid else "unknown"
                            except: pass

                            send_event(
                                self.cfg,
                                event_type="network_event",
                                description=f"Outbound connection detected: {remote_ip}:{remote_port} by {proc_name} (PID {conn.pid})",
                                severity="info",
                                source="network_monitor",
                                raw_data={
                                    "remote_ip": remote_ip,
                                    "remote_port": remote_port,
                                    "pid": conn.pid,
                                    "proc_name": proc_name,
                                    "ip": remote_ip  # Ensure backend finds it in raw_data too
                                },
                            )
                            self.seen_connections.add(conn_key)
                
                # Prune old connections from seen_connections that are no longer active
                active_keys = set()
                for conn in current_conns:
                    if conn.status == 'ESTABLISHED' and conn.remote_address:
                        active_keys.add((conn.remote_address.ip, conn.remote_address.port))
                
                # We only keep established ones in seen to avoid re-alerting if it flaps, 
                # but we should probably keep them for a while.
                # For now, let's just keep growing the set or implement a proper TTL.
                # To keep it simple, we'll only alert once per (IP, Port) per agent session.
                
            except (psutil.AccessDenied, Exception) as e:
                logger.warning(f"Error polling network connections: {e}")

        logger.info("Network monitor stopped")
