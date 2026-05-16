#!/usr/bin/env python3
"""
IPDS Pro — Intrusion Prevention & Detection System
====================================================
Unified production backend (merged from app.py + main.py).

Features:
  1.  Multi-condition, context-aware signatures (false positive reduction)
  2.  Threat scoring per IP with weighted categories
  3.  Score decay over time + time-windowed behavior tracking
  4.  Attack correlation (multi-vector → CRITICAL alert)
  5.  HTTP protocol awareness (method / path / headers / body parsing)
  6.  Strike-based blocking: warn → temp block (5 min) → permanent block
  7.  BPF kernel-level filter + rate limiter per suspicious IP
  8.  Modular classes (DetectionEngine, ResponseEngine, MetricsTracker, …)
  9.  JSON structured logging + MetricsTracker (pps, aps, top attackers)
  10. Live Threat Scores tab + Correlations tab in HTML dashboard
  11. Suricata EVE-compatible JSONL logging (logs/ipds_eve.jsonl)
      — event_type: traffic | alert | block
      — deterministic flow_id (SHA-256 5-tuple), full HTTP sub-object,
        alert section with severity/action/threat_score, block expiry timestamps
      — SIEM-ready (Elastic, Splunk, Graylog)
  12. Geo Intelligence — GeoLite2 city/ASN lookup, TOR/VPN/cloud detection,
      per-IP attack tracking, live geo dashboard push
  13. Linux iptables bidirectional blocking (INPUT + OUTPUT rules)
  14. Severity/category colour maps for Qt-native detail pane fallback

Run as Administrator (Windows) or sudo (Linux) for firewall access.
"""

import csv
import hashlib
import html as _html
import ipaddress
import json
import logging
import os
import platform
import re
import sqlite3
import struct
import subprocess
import sys
import time
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from threading import Event, Lock, Timer
from typing import Optional

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QStatusBar, QSystemTrayIcon, QMenu,
    QMessageBox, QComboBox, QFrame, QInputDialog
)
from PyQt6.QtWebEngineWidgets import QWebEngineView
from PyQt6.QtWebEngineCore import QWebEngineSettings
from PyQt6.QtCore import Qt, QUrl, QTimer, pyqtSignal, QObject, QThread
from PyQt6.QtGui import QColor, QPalette

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
    from scapy.arch.windows import get_windows_if_list
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False

# ── System monitoring (psutil + optional GPU) ──────────────────────────────────
try:
    import psutil
    PSUTIL_OK = True
except ImportError:
    PSUTIL_OK = False

try:
    import GPUtil
    GPUTIL_OK = True
except ImportError:
    GPUTIL_OK = False

try:
    import pynvml
    pynvml.nvmlInit()
    PYNVML_OK = True
except Exception:
    PYNVML_OK = False

# ══════════════════════════════════════════════════════════════════════════════
#  LOGGING SETUP — rotating file + JSON structured log
# ══════════════════════════════════════════════════════════════════════════════
os.makedirs("logs", exist_ok=True)


class _JSONFormatter(logging.Formatter):
    def format(self, record):
        obj = {
            "ts":    datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "msg":   record.getMessage(),
        }
        if record.exc_info:
            obj["exc"] = self.formatException(record.exc_info)
        return json.dumps(obj)


log = logging.getLogger("IPDS")
log.setLevel(logging.DEBUG)
# Human-readable rotating log — explicit UTF-8 encoding for Windows cp1252 safety
_fh = RotatingFileHandler(
    "logs/ipds.log", maxBytes=5 * 1024 * 1024, backupCount=5,
    encoding="utf-8")
_fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
_fh.setLevel(logging.INFO)
log.addHandler(_fh)
# JSON structured log (for SIEM tools) — explicit UTF-8 encoding
_jh = RotatingFileHandler(
    "logs/ipds_structured.jsonl", maxBytes=10 * 1024 * 1024, backupCount=3,
    encoding="utf-8")
_jh.setFormatter(_JSONFormatter())
_jh.setLevel(logging.WARNING)
log.addHandler(_jh)
# Stream handler: force UTF-8 on Windows to avoid cp1252 UnicodeEncodeError
import io as _io
_sh = logging.StreamHandler(
    stream=_io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    if hasattr(sys.stdout, "buffer") else sys.stdout
)
_sh.setLevel(logging.WARNING)
_sh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
log.addHandler(_sh)



# ══════════════════════════════════════════════════════════════════════════════
#  EVE LOGGER — Suricata-compatible JSON Lines structured logging
#  Writes logs/ipds_eve.jsonl  (one JSON object per line, SIEM-ingestible)
#
#  Three event_type values:
#    "traffic" — every packet seen by the engine (flow metadata + payload snip)
#    "alert"   — every rule match / threshold trigger
#    "block"   — whenever an IP is temporarily or permanently blocked
#
#  Public API (module-level singleton  eve_log):
#    eve_log.log_traffic(pkt)
#    eve_log.log_alerts(pkt, alerts)
#    eve_log.log_block(ip, reason, permanent, *, src_port, dst_ip, dst_port, proto)
# ══════════════════════════════════════════════════════════════════════════════

# ── EVE constants ─────────────────────────────────────────────────────────────
_EVE_FILE         = os.path.join("logs", "ipds_eve.jsonl")
_EVE_MAX_BYTES    = 20 * 1024 * 1024   # 20 MB per file, then rotate
_EVE_BACKUPS      = 5
_EVE_MAX_PAYLOAD  = 256                # bytes kept in payload_printable
_EVE_MAX_BODY     = 512                # bytes kept in http.http_request_body_printable

# Severity label → Suricata integer (1=highest)
_EVE_SEV_MAP = {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 3, "LOW": 4}

# IPDS action → Suricata action string
_EVE_ACT_MAP = {
    "PERM_BLOCK": "blocked",
    "TEMP_BLOCK": "blocked",
    "ALERT":      "allowed",
    "MONITOR":    "allowed",
    "LOG":        "allowed",
}

# Headers safe to include in EVE output (no credentials/tokens)
_EVE_SAFE_HEADERS = {
    "accept", "accept-encoding", "accept-language",
    "cache-control", "connection", "origin", "referer",
    "x-forwarded-for", "x-real-ip",
}


def _eve_ts_now() -> str:
    """Current UTC time in Suricata EVE ISO-8601 format (µs precision)."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f+0000")


def _eve_flow_id(src: str, sport: int, dst: str, dport: int, proto: str) -> int:
    """
    Deterministic unsigned 64-bit flow ID from SHA-256 of the 5-tuple.
    Same connection always maps to the same ID within a session.
    """
    key = f"{src}:{sport}-{dst}:{dport}/{proto.upper()}"
    digest = hashlib.sha256(key.encode()).digest()
    return struct.unpack_from(">Q", digest)[0]


def _eve_build_http(http: Optional[dict]) -> Optional[dict]:
    """Convert HTTPParser.parse() output → Suricata-style http sub-object."""
    if not http:
        return None
    sec: dict = {}
    if http.get("host"):
        sec["hostname"] = http["host"]
    if http.get("path"):
        sec["url"] = http["path"]
    if http.get("method"):
        sec["http_method"] = http["method"].upper()
    ua = http.get("user_agent", "")
    if ua:
        sec["http_user_agent"] = ua[:512]
    headers = http.get("headers", {})
    ct = headers.get("content-type", "")
    if ct:
        sec["http_content_type"] = ct
    cl = headers.get("content-length", "")
    if cl:
        try:
            sec["length"] = int(cl)
        except ValueError:
            pass
    safe_h = {k: v for k, v in headers.items() if k.lower() in _EVE_SAFE_HEADERS}
    if safe_h:
        sec["request_headers"] = safe_h
    body = http.get("body", "")
    if body:
        sec["http_request_body_printable"] = body[:_EVE_MAX_BODY]
    return sec or None


class _EveJsonlWriter:
    """Thread-safe rotating JSON-Lines writer (bypasses logging.Formatter)."""

    def __init__(self, path: str, max_bytes: int, backup_count: int):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        self._lock        = Lock()
        self._path        = path
        self._max_bytes   = max_bytes
        self._backup_count = backup_count
        self._fh          = open(path, "a", encoding="utf-8")  # noqa: WPS515

    def write(self, obj: dict) -> None:
        line = json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
        with self._lock:
            self._fh.write(line + "\n")
            self._fh.flush()
            # Manual size-based rotation
            try:
                if self._fh.tell() >= self._max_bytes > 0:
                    self._fh.close()
                    # Rotate: .jsonl → .jsonl.1 → .jsonl.2 …
                    for i in range(self._backup_count - 1, 0, -1):
                        src = f"{self._path}.{i}"
                        dst = f"{self._path}.{i + 1}"
                        if os.path.exists(src):
                            os.replace(src, dst)
                    if os.path.exists(self._path):
                        os.replace(self._path, f"{self._path}.1")
                    self._fh = open(self._path, "a", encoding="utf-8")
            except Exception:
                pass  # rotation failure is non-fatal — keep logging

    def close(self) -> None:
        with self._lock:
            try:
                self._fh.close()
            except Exception:
                pass


class EveLogger:
    """
    Suricata EVE-compatible JSON Lines logger for IPDS Pro.

    Instantiated once as the module-level singleton  eve_log.
    Called from three places in the packet pipeline:

      1.  CaptureWorker._handle()      → eve_log.log_traffic(pkt)
      2.  CaptureWorker._handle()      → eve_log.log_alerts(pkt, alerts)
      3.  ResponseEngine._block()      → eve_log.log_block(ip, reason, permanent)
    """

    def __init__(
        self,
        path:         str = _EVE_FILE,
        max_bytes:    int = _EVE_MAX_BYTES,
        backup_count: int = _EVE_BACKUPS,
    ):
        self._writer = _EveJsonlWriter(path, max_bytes, backup_count)

    # ── Public methods ────────────────────────────────────────────────────────

    def log_traffic(self, pkt: dict) -> None:
        """Write a 'traffic' event for every packet entering the engine."""
        self._writer.write(self._base(pkt, "traffic"))

    def log_alerts(self, pkt: dict, alerts: list) -> None:
        """Write one 'alert' event per matched rule / threshold trigger."""
        for alert in alerts:
            rec = self._base(pkt, "alert")
            rec["alert"] = self._alert_sec(alert)
            http_sec = _eve_build_http(pkt.get("http") or alert.get("http"))
            if http_sec:
                rec["http"] = http_sec
            self._writer.write(rec)

    def log_block(
        self,
        ip:        str,
        reason:    str,
        permanent: bool,
        *,
        src_port:  int = 0,
        dst_ip:    str = "",
        dst_port:  int = 0,
        proto:     str = "IP",
    ) -> None:
        """Write a 'block' event when ResponseEngine blocks an IP."""
        now = _eve_ts_now()
        expires = (
            None if permanent
            else datetime.fromtimestamp(
                time.time() + TEMP_BLOCK_SECS, tz=timezone.utc
            ).strftime("%Y-%m-%dT%H:%M:%S.%f+0000")
        )
        rec: dict = {
            "timestamp":  now,
            "event_type": "block",
            "flow_id":    _eve_flow_id(ip, src_port, dst_ip, dst_port, proto),
            "src_ip":     ip,
            "src_port":   src_port,
            "dest_ip":    dst_ip,
            "dest_port":  dst_port,
            "proto":      proto.upper(),
            "block": {
                "blocked":    True,
                "block_type": "permanent" if permanent else "temporary",
                "reason":     reason,
                "expires":    expires,
                "blocked_at": now,
            },
        }
        self._writer.write(rec)

    def close(self) -> None:
        """Flush and close the underlying file handle."""
        self._writer.close()

    # ── Private helpers ───────────────────────────────────────────────────────

    def _base(self, pkt: dict, event_type: str) -> dict:
        """Fields common to all event types."""
        src   = pkt.get("src",   "")
        sport = int(pkt.get("sport", 0))
        dst   = pkt.get("dst",   "")
        dport = int(pkt.get("dport", 0))
        proto = pkt.get("proto", "IP").upper()

        rec: dict = {
            "timestamp":  _eve_ts_now(),
            "event_type": event_type,
            "flow_id":    _eve_flow_id(src, sport, dst, dport, proto),
            "src_ip":     src,
            "src_port":   sport,
            "dest_ip":    dst,
            "dest_port":  dport,
            "proto":      proto,
        }
        if pkt.get("tcp_flags"):
            rec["tcp_flags"] = pkt["tcp_flags"]
        if pkt.get("size"):
            rec["pkt_len"] = pkt["size"]
        if pkt.get("blocked"):
            rec["blocked_source"] = True

        payload = pkt.get("payload", "")
        if payload:
            snip = payload[:_EVE_MAX_PAYLOAD]
            rec["payload_printable"] = snip
            # Include hex for binary/non-printable content
            if any(ord(c) < 32 and c not in "\r\n\t" for c in snip):
                rec["payload_hex"] = snip.encode("utf-8", errors="replace").hex()
        return rec

    @staticmethod
    def _alert_sec(alert: dict) -> dict:
        """Build the Suricata-style alert sub-object."""
        sev_str = alert.get("sev", "MEDIUM").upper()
        action  = alert.get("action", "MONITOR")
        sec: dict = {
            "signature_id":    int(alert.get("sid", 0)),
            "signature":       alert.get("msg", ""),
            "category":        alert.get("cat", ""),
            "severity":        _EVE_SEV_MAP.get(sev_str, 3),
            "severity_label":  sev_str,
            "action":          _EVE_ACT_MAP.get(action, "allowed"),
            "action_label":    action,
            "threat_score":    round(float(alert.get("threat_score", 0.0)), 1),
            "risk_level":      alert.get("risk_level", "LOW"),
        }
        if alert.get("correlation"):
            sec["correlation"] = alert["correlation"]
        return sec


# Module-level singleton — import and use directly
eve_log = EveLogger()


# ══════════════════════════════════════════════════════════════════════════════
#  SIGNATURES & DETECTION ENGINE — imported from signatures_improved.py
#  (Drop-in replacement: all constants, rules, and DetectionEngine live there)
# ══════════════════════════════════════════════════════════════════════════════
# ── Geo Intelligence module (drop-in, same folder as app.py) ──────────────────
try:
    from geo_intelligence import build_geo_intel, geo_dashboard_js
    GEO_OK = True
except ImportError:
    GEO_OK = False
    log.warning("geo_intelligence.py not found — Geo Intel tab disabled. "
                "Place geo_intelligence.py in the same folder as app.py.")

from signatures_improved import (
    SCORE_ALERT, SCORE_TEMP_BLOCK, SCORE_PERM_BLOCK,
    TEMP_BLOCK_SECS, DECAY_INTERVAL, DECAY_RATE,
    SCORE_WEIGHTS, CORRELATION_RULES,
    SIGNATURES, THRESHOLD_SIGS,
    IPProfile,          # dataclass used by ResponseEngine/Database
    DetectionEngine,    # replaces the class that was defined here
)

# ── Severity / category colour maps (used by Qt detail pane & dashboard) ──────
# Kept from legacy main.py — safe to reference from any UI or logging code.
SEV_COLORS: dict[str, str] = {
    "CRITICAL": "#ff0040",
    "HIGH":     "#ff4444",
    "MEDIUM":   "#ffaa00",
    "LOW":      "#00cc88",
    "INFO":     "#00aaff",
}
CAT_COLORS: dict[str, str] = {
    "SQLi":         "#ff4444",
    "XSS":          "#ffaa00",
    "CMDi":         "#cc44ff",
    "DirTraversal": "#00aaff",
    "DoS":          "#00cc88",
    "BruteForce":   "#ff8800",
    "PortScan":     "#58a6ff",
    "C2":           "#ff0040",
}


# ════════

# ══════════════════════════════════════════════════════════════════════════════
#  HTTP PARSER
# ══════════════════════════════════════════════════════════════════════════════
class HTTPParser:
    _RE = re.compile(
        r"^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|TRACE|CONNECT|DEBUG|TRACK)"
        r"\s+(\S+)\s+HTTP/[\d.]+\r?\n", re.IGNORECASE)

    @classmethod
    def parse(cls, payload: str) -> Optional[dict]:
        if not payload:
            return None
        m = cls._RE.match(payload)
        if not m:
            return None
        result = {"method": m.group(1).upper(), "path": m.group(2),
                  "user_agent": "", "host": "", "body": "", "headers": {}}
        lines = payload.split("\n")
        body_start = 0
        for i, line in enumerate(lines[1:], 1):
            line = line.strip()
            if not line:
                body_start = i + 1
                break
            if ":" in line:
                k, _, v = line.partition(":")
                k = k.strip().lower()
                result["headers"][k] = v.strip()
                if k == "user-agent": result["user_agent"] = v.strip()
                if k == "host":       result["host"]       = v.strip()
        if body_start:
            result["body"] = "\n".join(lines[body_start:])
        return result

    @classmethod
    def anomaly(cls, h: dict) -> Optional[str]:
        if h["method"] in {"TRACE", "TRACK", "DEBUG"}:
            return f"Non-standard HTTP method: {h['method']}"
        if len(h.get("user_agent", "")) > 512:
            return "Oversized User-Agent"
        if not h.get("user_agent") and h["method"] in {"GET", "POST"}:
            return "Missing User-Agent (scanner/bot)"
        if len(h["path"]) > 2048:
            return "Abnormally long URL path"
        return None


# ══════════════════════════════════════════════════════════════════════════════
#  DETECTION ENGINE  (drop-in replacement)
# ══════════════════════════════════════════════════════════════════════════════
# IPProfile and DetectionEngine are imported from signatures_improved above.




# ══════════════════════════════════════════════════════════════════════════════
#  DATABASE  — thread-safe SQLite
# ══════════════════════════════════════════════════════════════════════════════
class Database:
    def __init__(self):
        self._lock = Lock()
        self.conn  = sqlite3.connect("logs/ipds.db", check_same_thread=False)
        with self._lock:
            self.conn.executescript("""
                CREATE TABLE IF NOT EXISTS alerts(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts TEXT, src TEXT, dst TEXT, proto TEXT, dport INTEGER,
                    sid TEXT, msg TEXT, sev TEXT, cat TEXT,
                    score REAL DEFAULT 0, action TEXT, payload TEXT, http_path TEXT);
                CREATE TABLE IF NOT EXISTS blocked(
                    ip TEXT PRIMARY KEY, reason TEXT, ts TEXT, btype TEXT DEFAULT 'AUTO');
                CREATE TABLE IF NOT EXISTS packets(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT, src_ip TEXT, dst_ip TEXT,
                    protocol TEXT, src_port INTEGER, dst_port INTEGER,
                    payload TEXT, matched_sid TEXT, severity TEXT);
                CREATE INDEX IF NOT EXISTS idx_alerts_src ON alerts(src);
                CREATE INDEX IF NOT EXISTS idx_packets_src ON packets(src_ip);
            """)
            # ── Migrate existing DB: add columns that may be missing ──────────
            existing_cols = {
                row[1] for row in
                self.conn.execute("PRAGMA table_info(alerts)").fetchall()
            }
            for col, defn in [("score",        "REAL    DEFAULT 0"),
                               ("action",       "TEXT    DEFAULT ''"),
                               ("payload",      "TEXT    DEFAULT ''"),
                               ("http_path",    "TEXT    DEFAULT ''"),
                               ("threat_score", "INTEGER DEFAULT 0"),
                               ("correlation",  "TEXT    DEFAULT ''")]:
                if col not in existing_cols:
                    self.conn.execute(
                        f"ALTER TABLE alerts ADD COLUMN {col} {defn}")
            self.conn.commit()

    def save_packet(self, p: dict):
        """Persist every captured packet to the packets table (raw log).

        Ported from legacy main.py — useful for full PCAP-style auditing
        and forensic replay.  Payload is capped at 300 bytes to bound DB size.
        """
        with self._lock:
            self.conn.execute(
                "INSERT INTO packets"
                "(timestamp,src_ip,dst_ip,protocol,src_port,dst_port,"
                "payload,matched_sid,severity) VALUES(?,?,?,?,?,?,?,?,?)",
                (p.get("time", ""), p.get("src", ""), p.get("dst", ""),
                 p.get("proto", ""),
                 p.get("sport", 0), p.get("dport", 0),
                 p.get("payload", "")[:300],
                 p.get("sid", ""), p.get("sev", "")))
            self.conn.commit()

    def save_alert(self, p: dict, a: dict):
        http_path    = a.get("http", {}).get("path", "") if a.get("http") else ""
        threat_score = int(round(a.get("threat_score", 0)))
        correlation  = json.dumps(a.get("correlation", "")) if a.get("correlation") else ""
        log.debug("save_alert | src=%s | sid=%s | threat_score=%d | correlation=%r",
                  p.get("src"), a.get("sid"), threat_score, correlation)
        with self._lock:
            self.conn.execute(
                "INSERT INTO alerts(ts,src,dst,proto,dport,sid,msg,sev,cat,"
                "score,action,payload,http_path,threat_score,correlation) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (p.get("time",""), p.get("src",""), p.get("dst",""), p.get("proto",""),
                 p.get("dport",0), a.get("sid",""), a.get("msg",""),
                 a.get("sev",""), a.get("cat",""),
                 round(a.get("threat_score",0),1), a.get("action",""),
                 p.get("payload","")[:300], http_path,
                 threat_score, correlation))
            self.conn.commit()
        log.warning(json.dumps({
            "event":"ALERT","sid":a.get("sid"),"msg":a.get("msg"),
            "cat":a.get("cat"),"sev":a.get("sev"),"src":p.get("src"),
            "threat_score":threat_score,"correlation":correlation,
            "action":a.get("action")}))

    def block(self, ip, reason, btype="AUTO"):
        with self._lock:
            self.conn.execute(
                "INSERT OR REPLACE INTO blocked VALUES(?,?,?,?)",
                (ip, reason,
                 datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
                 btype))
            self.conn.commit()

    def unblock(self, ip):
        with self._lock:
            self.conn.execute("DELETE FROM blocked WHERE ip=?", (ip,))
            self.conn.commit()

    def get_blocked(self):
        with self._lock:
            return self.conn.execute("SELECT ip,reason,ts FROM blocked").fetchall()

    def get_top_attackers(self, n=10):
        with self._lock:
            return self.conn.execute(
                "SELECT src,COUNT(*) c,MAX(score) s FROM alerts "
                "GROUP BY src ORDER BY c DESC LIMIT ?", (n,)).fetchall()

    def get_cat_counts(self):
        with self._lock:
            return self.conn.execute(
                "SELECT cat,COUNT(*) FROM alerts GROUP BY cat ORDER BY 2 DESC").fetchall()

    def export_csv(self, path="logs/alerts_export.csv"):
        with self._lock:
            rows = self.conn.execute("SELECT * FROM alerts ORDER BY id DESC").fetchall()
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["id","ts","src","dst","proto","dport","sid","msg",
                        "sev","cat","score","action","payload","http_path"])
            w.writerows(rows)
        return path


# ══════════════════════════════════════════════════════════════════════════════
#  RATE LIMITER — token bucket per IP
# ══════════════════════════════════════════════════════════════════════════════
class RateLimiter:
    BUCKET = 20   # max tokens
    REFILL = 5    # tokens/second

    def __init__(self):
        self._b:    dict = {}
        self._lock  = Lock()

    def allow(self, ip: str) -> bool:
        with self._lock:
            now = time.time()
            if ip not in self._b:
                self._b[ip] = {"t": self.BUCKET, "ts": now}
            b = self._b[ip]
            b["t"] = min(self.BUCKET, b["t"] + (now - b["ts"]) * self.REFILL)
            b["ts"] = now
            if b["t"] >= 1:
                b["t"] -= 1
                return True
            return False

    def cleanup(self):
        with self._lock:
            now   = time.time()
            stale = [ip for ip, b in self._b.items() if now - b["ts"] > 60]
            for ip in stale:
                del self._b[ip]


# ══════════════════════════════════════════════════════════════════════════════
#  IP BLOCKER — Windows Firewall / Linux iptables
# ══════════════════════════════════════════════════════════════════════════════
class IPBlocker:
    """Firewall integration: Windows netsh / Linux iptables.

    Merged improvement from legacy main.py:
      - Linux now blocks both INPUT *and* OUTPUT (bidirectional) so spoofed
        reply traffic from a blocked host is also dropped at the kernel.
      - Windows behaviour is unchanged (netsh INPUT rule is sufficient there).
    """
    OS = platform.system()

    @classmethod
    def _valid(cls, ip: str) -> bool:
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            log.error(f"Invalid IP rejected: {ip!r}")
            return False

    @classmethod
    def block(cls, ip: str):
        if not cls._valid(ip): return
        try:
            if cls.OS == "Windows":
                subprocess.run(
                    ["netsh","advfirewall","firewall","add","rule",
                     f"name=IPDS_BLOCK_{ip}","dir=in","action=block",f"remoteip={ip}"],
                    check=True, capture_output=True, creationflags=0x08000000)
            elif cls.OS == "Linux":
                # Block inbound traffic from this IP
                subprocess.run(["iptables","-I","INPUT","1","-s",ip,"-j","DROP"],
                               check=True, capture_output=True)
                # Also block outbound traffic to this IP (bidirectional)
                subprocess.run(["iptables","-I","OUTPUT","1","-d",ip,"-j","DROP"],
                               capture_output=True)
            log.info(f"[FIREWALL] Blocked {ip}")
        except Exception as e:
            log.error(f"Block failed {ip}: {e}")

    @classmethod
    def unblock(cls, ip: str):
        if not cls._valid(ip): return
        try:
            if cls.OS == "Windows":
                subprocess.run(
                    ["netsh","advfirewall","firewall","delete","rule",
                     f"name=IPDS_BLOCK_{ip}"],
                    capture_output=True, creationflags=0x08000000)
            elif cls.OS == "Linux":
                subprocess.run(["iptables","-D","INPUT","-s",ip,"-j","DROP"],
                               capture_output=True)
                subprocess.run(["iptables","-D","OUTPUT","-d",ip,"-j","DROP"],
                               capture_output=True)
            log.info(f"[FIREWALL] Unblocked {ip}")
        except Exception as e:
            log.error(f"Unblock failed {ip}: {e}")


# ══════════════════════════════════════════════════════════════════════════════
#  RESPONSE ENGINE — strike system + temp/perm blocks + whitelist
# ══════════════════════════════════════════════════════════════════════════════
class ResponseEngine:
    STRIKE_TEMP = 2
    STRIKE_PERM = 4

    _DEFAULT_WHITELIST = ["127.0.0.0/8", "169.254.0.0/16"]

    def __init__(self, db: Database, on_block=None, on_unblock=None):
        self._db         = db
        self._on_block   = on_block
        self._on_unblock = on_unblock
        self._lock       = Lock()
        self._strikes:   dict[str, int]   = {}
        self._timers:    dict[str, Timer] = {}
        self._blocked:   set              = set(r[0] for r in db.get_blocked())
        self._wl:        list             = []
        self._rl         = RateLimiter()

        for cidr in self._DEFAULT_WHITELIST:
            try: self._wl.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError: pass

    def respond(self, ip: str, action: str, reason: str = ""):
        if not IPBlocker._valid(ip) or self._whitelisted(ip): return
        with self._lock:
            if action in ("PERM_BLOCK", "TEMP_BLOCK"):
                self._block(ip, reason, permanent=(action == "PERM_BLOCK"))
            elif action == "ALERT":
                self._strike(ip, reason)

    def manual_block(self, ip: str, reason="Manual"):
        if not IPBlocker._valid(ip): return
        with self._lock:
            self._block(ip, reason, permanent=True)

    def manual_unblock(self, ip: str):
        if not IPBlocker._valid(ip): return
        with self._lock:
            self._unblock(ip)

    def whitelist_add(self, cidr: str):
        try:
            self._wl.append(ipaddress.ip_network(cidr, strict=False))
            log.info(f"[WHITELIST] {cidr}")
        except ValueError as e:
            log.error(f"Bad whitelist entry: {e}")

    def is_blocked(self, ip: str) -> bool:
        return ip in self._blocked

    def blocked_set(self) -> set:
        return set(self._blocked)

    def rate_limiter(self) -> RateLimiter:
        return self._rl

    def _block(self, ip, reason, permanent):
        if ip in self._blocked: return
        self._blocked.add(ip)
        self._db.block(ip, reason, "PERM" if permanent else "TEMP")
        IPBlocker.block(ip)
        # ── EVE: block event ──────────────────────────────────────────────────
        eve_log.log_block(ip, reason, permanent)
        log.warning(f"[{'PERM' if permanent else 'TEMP'} BLOCK] {ip} — {reason}")
        if self._on_block:
            self._on_block(ip, reason, not permanent)
        if not permanent:
            t = Timer(TEMP_BLOCK_SECS, self._auto_unblock, args=[ip])
            t.daemon = True
            self._timers[ip] = t
            t.start()

    def _auto_unblock(self, ip):
        with self._lock:
            self._unblock(ip)
        log.info(f"[AUTO-UNBLOCK] {ip}")

    def _unblock(self, ip):
        if ip not in self._blocked: return
        self._blocked.discard(ip)
        self._db.unblock(ip)
        IPBlocker.unblock(ip)
        t = self._timers.pop(ip, None)
        if t: t.cancel()
        if self._on_unblock:
            self._on_unblock(ip)

    def _strike(self, ip, reason):
        self._strikes[ip] = self._strikes.get(ip, 0) + 1
        n = self._strikes[ip]
        if n >= self.STRIKE_PERM:
            self._block(ip, f"Strike {n}: {reason}", permanent=True)
        elif n >= self.STRIKE_TEMP:
            self._block(ip, f"Strike {n}: {reason}", permanent=False)
        else:
            log.warning(f"[STRIKE {n}] {ip} — {reason}")

    def _whitelisted(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
            return any(addr in net for net in self._wl)
        except ValueError:
            return False


# ══════════════════════════════════════════════════════════════════════════════
#  METRICS TRACKER — in-memory counters (no DB hit per packet)
# ══════════════════════════════════════════════════════════════════════════════
class MetricsTracker:
    WIN = 5  # seconds for rate calculation

    def __init__(self):
        self._lock       = Lock()
        self.pkt_total   = 0
        self.alert_total = 0
        self.blocked_cnt = 0
        self._pkt_ts:    deque = deque()
        self._alert_ts:  deque = deque()
        self.proto       = Counter()
        self.cats        = Counter()
        self.sevs        = Counter()
        self.top_ips     = Counter()
        self.start       = time.time()

    def on_packet(self, pkt):
        with self._lock:
            self.pkt_total += 1
            self.proto[pkt.get("proto","?")] += 1
            now = time.time()
            self._pkt_ts.append(now)
            while self._pkt_ts and now - self._pkt_ts[0] > self.WIN:
                self._pkt_ts.popleft()

    def on_alert(self, a, src_ip: str = ""):
        with self._lock:
            self.alert_total += 1
            self.cats[a.get("cat","?")] += 1
            self.sevs[a.get("sev","?")] += 1
            # src lives on the packet dict; accept it via src_ip kwarg
            # or fall back to the alert's own "src" field
            ip = src_ip or a.get("src","?")
            self.top_ips[ip] += 1
            now = time.time()
            self._alert_ts.append(now)
            while self._alert_ts and now - self._alert_ts[0] > self.WIN:
                self._alert_ts.popleft()

    def on_block(self):
        with self._lock: self.blocked_cnt += 1

    def on_unblock(self):
        with self._lock: self.blocked_cnt = max(0, self.blocked_cnt - 1)

    def snap(self) -> dict:
        with self._lock:
            now = time.time()
            pps = len([t for t in self._pkt_ts   if now-t<=self.WIN]) / self.WIN
            aps = len([t for t in self._alert_ts  if now-t<=self.WIN]) / self.WIN
            up  = int(now - self.start)
            return {
                "pkt_total":   self.pkt_total,
                "alert_total": self.alert_total,
                "blocked_cnt": self.blocked_cnt,
                "pps":   round(pps, 1),
                "aps":   round(aps, 2),
                "uptime": up,
                "proto": dict(self.proto.most_common(5)),
                "cats":  dict(self.cats.most_common(8)),
                "sevs":  dict(self.sevs),
                "top_ips": dict(self.top_ips.most_common(10)),
            }


# ══════════════════════════════════════════════════════════════════════════════
#  CAPTURE WORKER  — BPF-filtered Scapy sniff in background QThread
# ══════════════════════════════════════════════════════════════════════════════
# BPF runs in the kernel/Npcap driver — filters non-IP and loopback BEFORE Python
BPF_FILTER = "ip and not host 127.0.0.1 and not (src net 224.0.0.0/4)"


class Signals(QObject):
    packet = pyqtSignal(dict)
    alert  = pyqtSignal(dict, list)   # pkt, list[alert_dict]
    error  = pyqtSignal(str)


class CaptureWorker(QThread):
    STATS_EVERY = 200   # emit stats every N packets

    def __init__(self, iface: str, engine: DetectionEngine, blocked: set, ip_tracker=None):
        super().__init__()
        self.iface      = iface
        self.engine     = engine
        self.blocked    = blocked
        self.signals    = Signals()
        self._stop      = Event()
        self._n         = 0
        self._ip_tracker = ip_tracker

    def stop(self): self._stop.set()

    def run(self):
        if not SCAPY_OK:
            self.signals.error.emit(
                "Scapy is not installed.\nRun:  pip install scapy\n\n"
                "Also install Npcap from https://npcap.com\n"
                "and enable WinPcap compatibility mode.")
            return
        try:
            sniff(iface=self.iface, filter=BPF_FILTER,
                  prn=self._handle, store=False,
                  stop_filter=lambda _: self._stop.is_set())
        except Exception as e:
            self.signals.error.emit(
                f"Capture failed on '{self.iface}':\n{e}\n\n"
                "Check:\n1. Npcap installed\n2. Running as Administrator\n"
                "3. Correct interface selected")

    def _handle(self, raw):
        if IP not in raw: return
        self._n += 1

        ip_l  = raw[IP]
        proto = ("TCP" if TCP in raw else "UDP" if UDP in raw
                 else "ICMP" if ICMP in raw else "IP")
        dport = (raw[TCP].dport if TCP in raw else
                 raw[UDP].dport if UDP in raw else 0)
        sport = (raw[TCP].sport if TCP in raw else
                 raw[UDP].sport if UDP in raw else 0)
        flags = ""
        if TCP in raw:
            mapping = {0x02:"S",0x10:"A",0x01:"F",0x04:"R",0x08:"P"}
            flags   = "-".join(v for k,v in mapping.items() if int(raw[TCP].flags)&k)

        payload = ""
        if Raw in raw:
            try:    payload = raw[Raw].load.decode("utf-8", errors="replace")
            except: payload = repr(raw[Raw].load)[:200]

        pkt = {
            "time": datetime.now(timezone.utc).strftime("%H:%M:%S"),
            "src":  ip_l.src, "dst": ip_l.dst,
            "proto": proto, "dport": dport, "sport": sport,
            "tcp_flags": flags, "payload": payload,
            "size": len(raw), "blocked": ip_l.src in self.blocked,
        }

        # ── Geo Intelligence: track every packet (src + dst) ───────────────────
        if self._ip_tracker:
            try:
                self._ip_tracker.on_packet(pkt["src"], pkt["dst"])
                if self._n % 500 == 0:   # log every 500 packets to avoid spam
                    log.debug(
                        f"[GeoTrack] on_packet called — "
                        f"src={pkt['src']} dst={pkt['dst']} "
                        f"(total packets seen: {self._n})"
                    )
            except Exception as exc:
                log.error(f"[GeoTrack] on_packet error for "
                          f"{pkt['src']}→{pkt['dst']}: {exc}")
        else:
            if self._n == 1:
                log.warning("[GeoTrack] ip_tracker is None — geo tracking disabled")

        # ── EVE: traffic event for every packet ───────────────────────────────
        eve_log.log_traffic(pkt)

        if not pkt["blocked"]:
            alerts = self.engine.process(pkt)
            if alerts:
                # ── EVE: one alert event per matched rule ─────────────────────
                eve_log.log_alerts(pkt, alerts)
                # Attach first alert summary to pkt for live-feed colouring
                pkt["alert_msg"]  = alerts[0]["msg"]
                pkt["sev"]        = alerts[0]["sev"]
                pkt["threat_score"] = alerts[0]["threat_score"]
                self.signals.alert.emit(pkt, alerts)
        else:
            pkt["alert_msg"] = "BLOCKED SOURCE"
            pkt["sev"]       = "BLOCKED"

        self.signals.packet.emit(pkt)


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN WINDOW
# ══════════════════════════════════════════════════════════════════════════════
class IPDSWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("IPDS Pro — Intrusion Prevention & Detection System")
        self.setMinimumSize(1300, 820)
        self._palette()

        # Core modules
        self.db       = Database()
        self.engine   = DetectionEngine()
        self.metrics  = MetricsTracker()
        self.response = ResponseEngine(
            self.db,
            on_block=self._on_block_cb,
            on_unblock=self._on_unblock_cb,
        )

        # ── Geo Intelligence ──────────────────────────────────────────────────────
        if GEO_OK:
            # Search for GeoLite2 databases — geoip/ subdirectory is canonical
            def _find_mmdb(name: str) -> Optional[str]:
                """Search common locations for *name*.mmdb.

                Returns the first existing absolute path, or None if the
                file cannot be found anywhere.  Passing None to build_geo_intel
                is correct — GeoEngine will disable that lookup gracefully
                rather than logging a misleading "not found at <fake path>".
                """
                # Resolve the directory that contains app.py itself, with a
                # safe fallback in case __file__ is unavailable (e.g. frozen).
                try:
                    script_dir = os.path.dirname(os.path.abspath(__file__))
                except (NameError, TypeError):
                    script_dir = os.getcwd()

                cwd = os.getcwd()

                candidates = [
                    # ── Canonical location (geoip/ sub-dir next to app.py) ──
                    os.path.join(script_dir, "geoip", name),
                    # ── CWD-relative (works when launched from project root) ─
                    os.path.join(cwd, "geoip", name),
                    # ── Flat layout — file next to app.py ──────────────────
                    os.path.join(script_dir, name),
                    # ── Flat layout — file in CWD ──────────────────────────
                    os.path.join(cwd, name),
                    # ── Legacy / alternate locations ──────────────────────
                    os.path.join(os.path.expanduser("~"), name),
                    os.path.join(os.path.expanduser("~"), "GeoLite2", name),
                    os.path.join(cwd, "GeoLite2", name),
                    os.path.join(cwd, "data", name),
                    os.path.join(script_dir, "GeoLite2", name),
                    os.path.join(script_dir, "data", name),
                ]

                seen: set = set()
                for p in candidates:
                    p = os.path.normpath(p)
                    if p in seen:
                        continue
                    seen.add(p)
                    if os.path.isfile(p):
                        log.info("[GeoInit] Found %s at: %s", name, p)
                        return p

                log.warning(
                    "[GeoInit] %s not found in any of these locations:\n  %s\n"
                    "  Geo country/city lookups will be disabled for this DB.\n"
                    "  Download from https://dev.maxmind.com/geoip/geolite2-free-geolocation-data"
                    "  and place in geoip/%s next to app.py.",
                    name,
                    "\n  ".join(sorted(seen)),
                    name,
                )
                return None   # ← None, NOT a fake path

            try:
                city_path = _find_mmdb("GeoLite2-City.mmdb")
                asn_path  = _find_mmdb("GeoLite2-ASN.mmdb")
                self.geo_engine, self.geo_db, self.ip_tracker = build_geo_intel(
                    city_db_path=city_path,
                    asn_db_path=asn_path,
                    db_path="logs/ipds.db",
                    flush_interval=5.0,
                )
                log.info(
                    "[GeoInit] Geo Intelligence initialized "
                    "(city=%s asn=%s)",
                    city_path, asn_path)
            except Exception as _geo_exc:
                log.error("[GeoInit] build_geo_intel failed: %s", _geo_exc,
                          exc_info=True)
                self.geo_engine = self.geo_db = self.ip_tracker = None
        else:
            self.geo_engine = self.geo_db = self.ip_tracker = None

        self.worker   = None
        self.ips_mode = False
        self.iface_map = {}
        self._page_loaded = False   # guard: sysmon tick only fires after page ready

        # UI update buffers — always initialized here so _on_packet/_on_alerts
        # can safely append even if the page hasn't finished loading yet.
        self._buf_alerts:  list = []
        self._buf_flows:   list = []
        self._buf_threats: list = []   # threat profile updates → renderThreatScores
        self._buf_corrs:   list = []   # correlation events    → renderCorrelations
        self._flush_timer:  QTimer | None = None  # started in _page_ready

        self._build_ui()
        self._load_interfaces()
        self._setup_tray()
        QTimer(self, timeout=self._tick,               interval=1000).start()
        QTimer(self, timeout=self._tick_top_ips,       interval=5000).start()
        QTimer(self, timeout=self._tick_sysmon,        interval=1500).start()
        QTimer(self, timeout=self._tick_blocked_sync,  interval=5000).start()
        QTimer(self, timeout=self.response.rate_limiter().cleanup, interval=60000).start()

    def _palette(self):
        p = QPalette()
        p.setColor(QPalette.ColorRole.Window,     QColor("#030712"))
        p.setColor(QPalette.ColorRole.WindowText, QColor("#e6edf3"))
        p.setColor(QPalette.ColorRole.Base,       QColor("#0d1117"))
        p.setColor(QPalette.ColorRole.Text,       QColor("#e6edf3"))
        p.setColor(QPalette.ColorRole.Button,     QColor("#21262d"))
        p.setColor(QPalette.ColorRole.ButtonText, QColor("#e6edf3"))
        QApplication.setPalette(p)

    # ── UI ────────────────────────────────────────────────────────────────────
    def _build_ui(self):
        root = QWidget()
        self.setCentralWidget(root)
        v = QVBoxLayout(root)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(0)
        v.addWidget(self._toolbar())

        self.web = QWebEngineView()
        s = self.web.settings()
        s.setAttribute(QWebEngineSettings.WebAttribute.JavascriptEnabled, True)
        s.setAttribute(QWebEngineSettings.WebAttribute.LocalContentCanAccessFileUrls, True)
        s.setAttribute(QWebEngineSettings.WebAttribute.LocalContentCanAccessRemoteUrls, True)
        # Reduce compositor overhead
        s.setAttribute(QWebEngineSettings.WebAttribute.ScrollAnimatorEnabled, False)
        s.setAttribute(QWebEngineSettings.WebAttribute.PluginsEnabled, False)
        # Keep the web view background transparent so Qt's dark palette shows
        # through before the page finishes loading (prevents white flash).
        self.web.page().setBackgroundColor(QColor("#030712"))

        html_path = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "dashboard.html"))
        if os.path.exists(html_path):
            self.web.load(QUrl.fromLocalFile(html_path))
            self.web.loadFinished.connect(self._page_ready)
        else:
            self.web.setHtml(
                "<body style='background:#030712;color:#ff4d6d;"
                "font-family:monospace;padding:40px'>"
                "<h2>WARNING: dashboard.html not found in same folder as app.py</h2></body>")

        v.addWidget(self.web, 1)

        self.sb = QStatusBar()
        self.sb.setStyleSheet(
            "background:#070d14;color:#484f58;"
            "border-top:1px solid #21262d;font-family:'Courier New';font-size:11px;")
        self.setStatusBar(self.sb)
        self.sb.showMessage("Ready — select interface and click START CAPTURE")

    def _toolbar(self):
        tb = QWidget()
        tb.setFixedHeight(54)
        tb.setStyleSheet("background:#070d14;border-bottom:1px solid #21262d;")
        h = QHBoxLayout(tb)
        h.setContentsMargins(16, 0, 16, 0)
        h.setSpacing(10)

        logo = QLabel("IPDS <span style='color:#58a6ff;font-size:13px'>PRO</span>")
        logo.setStyleSheet("color:#00ff9d;font-size:18px;font-weight:800;"
                           "letter-spacing:3px;font-family:'Courier New';")
        logo.setTextFormat(Qt.TextFormat.RichText)
        h.addWidget(logo)
        h.addWidget(self._sep())
        h.addWidget(QLabel("Interface:"))

        self.iface_combo = QComboBox()
        self.iface_combo.setStyleSheet(
            "background:#161b22;border:1px solid #21262d;color:#c9d1d9;"
            "padding:4px 10px;border-radius:4px;font-size:12px;"
            "min-width:220px;min-height:28px;")
        h.addWidget(self.iface_combo)
        h.addWidget(self._sep())

        self.btn_ips = QPushButton("IPS: OFF")
        self.btn_ips.setStyleSheet(self._btn_style("#ffaa00"))
        self.btn_ips.clicked.connect(self._toggle_ips)
        h.addWidget(self.btn_ips)

        # Whitelist button
        btn_wl = QPushButton("Whitelist IP")
        btn_wl.setStyleSheet(self._btn_style("#3fb950"))
        btn_wl.clicked.connect(self._whitelist_dialog)
        h.addWidget(btn_wl)

        # Export CSV button
        btn_exp = QPushButton("Export CSV")
        btn_exp.setStyleSheet(self._btn_style("#58a6ff"))
        btn_exp.clicked.connect(self._export_csv)
        h.addWidget(btn_exp)

        h.addStretch()

        self.lbl_status = QLabel("READY")
        self.lbl_status.setStyleSheet(
            "color:#7d8590;font-family:'Courier New';font-size:11px;"
            "padding:3px 10px;background:rgba(125,133,144,0.06);"
            "border:1px solid rgba(125,133,144,0.2);border-radius:4px;")
        h.addWidget(self.lbl_status)
        h.addSpacing(6)

        self.btn_start = QPushButton("▶  START CAPTURE")
        self.btn_start.setStyleSheet(self._btn_style("#00ff9d", bold=True))
        self.btn_start.clicked.connect(self._start)
        h.addWidget(self.btn_start)

        self.btn_stop = QPushButton("⏹  STOP")
        self.btn_stop.setStyleSheet(self._btn_style("#ff4d6d"))
        self.btn_stop.setEnabled(False)
        self.btn_stop.clicked.connect(self._stop)
        h.addWidget(self.btn_stop)

        return tb

    def _sep(self):
        f = QFrame()
        f.setFrameShape(QFrame.Shape.VLine)
        f.setStyleSheet("color:#21262d;")
        return f

    def _btn_style(self, color, bold=False):
        r, g, b = int(color[1:3],16), int(color[3:5],16), int(color[5:7],16)
        return (f"background:rgba({r},{g},{b},0.08);"
                f"border:1px solid rgba({r},{g},{b},0.4);"
                f"color:{color};padding:5px 14px;border-radius:4px;"
                f"font-size:12px;{'font-weight:700;' if bold else ''}"
                f"min-height:28px;")

    # ── Interface loading ─────────────────────────────────────────────────────
    def _load_interfaces(self):
        self.iface_combo.clear()
        self.iface_map = {}
        if not SCAPY_OK:
            self.iface_combo.addItem("(Scapy not installed)")
            return
        try:
            ifaces = get_windows_if_list()
            skip   = {"Filter","Scheduler","Driver","Loopback","Pseudo",
                      "Kernel","Virtual","VPN","TAP","Hyper-V"}
            real   = [i for i in ifaces
                      if not any(s in i.get("name","") for s in skip)
                      and i.get("guid")]
            real.sort(key=lambda x: 0 if "Wi-Fi" in x.get("name","") else 1)
            for i in real:
                ips   = [ip for ip in i.get("ips",[])
                         if ip.startswith(("192.","10.","172."))]
                label = f"{i['name']}  ({ips[0]})" if ips else i["name"]
                npf   = f"\\Device\\NPF_{i['guid']}"
                self.iface_map[label] = npf
                self.iface_combo.addItem(label)
            if not self.iface_map:
                self.iface_combo.addItem("(no interfaces found — install Npcap)")
                log.warning("No real network interfaces detected.")
        except Exception as e:
            log.error(f"Interface error: {e}")
            self.iface_combo.addItem("Wi-Fi")

    # ── Capture control ───────────────────────────────────────────────────────
    def _start(self):
        label = self.iface_combo.currentText()
        iface = self.iface_map.get(label)
        if not iface:
            QMessageBox.warning(self, "No Interface",
                "No valid interface selected.\n"
                "Install Npcap (npcap.com) and restart as Administrator.")
            return

        self.worker = CaptureWorker(iface, self.engine, self.response.blocked_set(),
                                         ip_tracker=self.ip_tracker)
        self.worker.signals.packet.connect(self._on_packet)
        self.worker.signals.alert.connect(self._on_alerts)
        self.worker.signals.error.connect(self._on_error)
        self.worker.start()

        self.btn_start.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.lbl_status.setText("MONITORING ACTIVE")
        self.lbl_status.setStyleSheet(
            "color:#00ff9d;font-family:'Courier New';font-size:11px;"
            "padding:3px 10px;background:rgba(0,255,157,0.06);"
            "border:1px solid rgba(0,255,157,0.2);border-radius:4px;")
        log.info(f"Capture started: {iface}")
        self._js("const e=document.getElementById('nav-status-txt');"
                 "if(e) e.textContent='MONITORING ACTIVE';")

    def _stop(self):
        if self.worker:
            self.worker.stop()
            if not self.worker.wait(3000):
                log.warning("Capture thread did not stop within 3s")
        self.btn_start.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self.lbl_status.setText("STOPPED")
        self.lbl_status.setStyleSheet(
            "color:#7d8590;font-family:'Courier New';font-size:11px;"
            "padding:3px 10px;background:rgba(125,133,144,0.06);"
            "border:1px solid rgba(125,133,144,0.2);border-radius:4px;")
        log.info("Capture stopped")

    # ── Packet → live feed ────────────────────────────────────────────────────
    def _on_packet(self, p: dict):
        self.metrics.on_packet(p)
        # Persist raw packet to DB (packets table) — full audit trail
        self.db.save_packet(p)
        sev = p.get("sev", "")
        cls = ("danger"  if sev in ("HIGH","CRITICAL","BLOCKED") else
               "warning" if sev == "MEDIUM" else "safe")
        act = ("block" if sev in ("HIGH","CRITICAL","BLOCKED") else
               "alert" if sev == "MEDIUM" else "allow")

        # Buffer ingestAlert payload — only non-alert / BLOCKED packets here.
        # (Alerted packets are buffered via _on_alerts.)
        if not p.get("alert_msg") or sev == "BLOCKED":
            self._buf_alerts.append({
                "type":      p.get("alert_msg", p.get("proto","TCP")),
                "category":  sev if sev else "Traffic",
                "severity":  ("HIGH" if sev == "BLOCKED" else "LOW"),
                "src_ip":    p.get("src",""),
                "src":       p.get("src",""),
                "timestamp": p.get("time",""),
                "action":    act,
            })

        # Buffer Flow Graph — sample every 5th normal packet
        if not hasattr(self, '_flow_pkt_counter'):
            self._flow_pkt_counter = 0
        self._flow_pkt_counter += 1
        if cls != "safe" or self._flow_pkt_counter % 5 == 0:
            risk = "NORMAL" if cls == "safe" else ("HIGH" if cls == "danger" else "SUSPICIOUS")
            self._buf_flows.append({
                "src": p["src"], "dst": p.get("dst","?"),
                "protocol": p.get("proto","TCP"), "packets": 1, "risk": risk,
            })

    # ── Alerts → dashboard + DB + response ───────────────────────────────────
    def _on_alerts(self, p: dict, alerts: list):
        for a in alerts:
            self.metrics.on_alert(a, src_ip=p.get("src",""))
            self.db.save_alert(p, a)

            # ── Geo Intelligence: record this attack event ────────────────────────
            if self.ip_tracker:
                src_ip_for_geo = p.get("src", "")
                if src_ip_for_geo:
                    score_delta = float(a.get("threat_score", 0)) * 0.1
                    try:
                        self.ip_tracker.on_attack(
                            src_ip=src_ip_for_geo,
                            category=a.get("cat", ""),
                            score_delta=score_delta,
                        )
                        log.debug(
                            f"[GeoTrack] on_attack — src={src_ip_for_geo} "
                            f"cat={a.get('cat','')} "
                            f"score_delta={score_delta:.2f}"
                        )
                    except Exception as exc:
                        log.error(f"[GeoTrack] on_attack error for {src_ip_for_geo}: {exc}")

            # Auto-response (IPS mode gates HIGH/CRITICAL)
            if self.ips_mode or a["action"] in ("PERM_BLOCK", "TEMP_BLOCK"):
                self.response.respond(p["src"], a["action"], a["msg"])

            # ── Buffer ingestAlert payload ─────────────────────────────────────
            action_str_js = ("block"  if a.get("action") in ("PERM_BLOCK","TEMP_BLOCK") else
                             "alert"  if a.get("action") == "ALERT" else "allow")
            corr_val = a.get("correlation", "")
            ts_val   = round(a.get("threat_score", 0), 1)
            log.debug("_on_alerts buffer | src=%s | threat_score=%.1f | correlation=%r",
                      p.get("src"), ts_val, corr_val)
            self._buf_alerts.append({
                "type":         a.get("msg", a.get("cat","Unknown")),
                "category":     a.get("cat",""),
                "severity":     a.get("sev","INFO"),
                "src_ip":       p.get("src",""),
                "src":          p.get("src",""),
                "timestamp":    p.get("time",""),
                "action":       action_str_js,
                "threat_score": ts_val,
                "correlation":  corr_val,
            })

            # ── Push threat profile to dashboard ──────────────────────────────
            profile = self.engine.get_profile(p["src"])
            if profile:
                self._buf_threats.append({
                    "src_ip":       p.get("src",""),
                    "score":        round(profile.score, 1),
                    "risk":         profile.risk,
                    "categories":   sorted(profile.categories),
                    "alert_count":  profile.alert_count,
                    "block_status": profile.block_status,
                })

            # ── Push correlation event to dashboard ────────────────────────────
            if a.get("correlation"):
                cats_seen = sorted(profile.categories) if profile else []
                self._buf_corrs.append({
                    "timestamp":   p.get("time",""),
                    "src_ip":      p.get("src",""),
                    "correlation": a.get("correlation",""),
                    "categories":  cats_seen,
                    "score":       round(a.get("threat_score", 0), 1),
                })

            # Tray notification for high-severity alerts
            if a["sev"] in ("CRITICAL", "HIGH"):
                self.tray.showMessage(
                    f"[{a['sev']}] {a['msg']}",
                    f"{p['src']} -> score {a.get('threat_score',0):.0f} | {a['action']}",
                    QSystemTrayIcon.MessageIcon.Critical, 5000)

            log.warning(json.dumps({
                "event":"ALERT","msg":a["msg"],"sev":a["sev"],
                "src":p["src"],"score":a.get("threat_score",0),
                "action":a["action"],"corr":a.get("correlation","")}))

            # Buffer Flow Graph event
            risk_map = {"CRITICAL": "CRITICAL", "HIGH": "HIGH",
                        "MEDIUM": "SUSPICIOUS", "LOW": "NORMAL"}
            self._buf_flows.append({
                "src": p["src"], "dst": p.get("dst","?"),
                "protocol": p.get("proto","TCP"), "packets": 1,
                "risk": risk_map.get(a["sev"], "NORMAL"),
            })

    # ── Buffered UI flush — called every 3 s by _flush_timer ─────────────────
    def _flush_ui_buffer(self):
        if not self._page_loaded:
            return

        alerts  = self._buf_alerts[:]
        flows   = self._buf_flows[:]
        threats = self._buf_threats[:]
        corrs   = self._buf_corrs[:]
        self._buf_alerts.clear()
        self._buf_flows.clear()
        self._buf_threats.clear()
        self._buf_corrs.clear()

        if not alerts and not flows and not threats and not corrs:
            return

        parts: list[str] = []

        # 1. Batch ingestAlert calls.
        #    - Set _renderInProgress = true so the JS debounced timer knows a
        #      batch flush is running and won't double-fire heavy renders.
        #    - Suppress all per-call render hooks during ingestion.
        #    - Run ONE render pass at the end.
        #    - Clear the JS debounce timer so it doesn't fire again 3s later.
        if alerts:
            payload_json = json.dumps(alerts)
            parts.append(f"""
(function(){{
    window._renderInProgress = true;
    var alerts = {payload_json};
    var _noop = function(){{}};
    var _origRenderChart   = window.renderChart;
    var _origRenderAlerts  = window.renderAlertsTable;
    var _origRenderGrid    = window.renderAttacksGrid;
    var _origRenderDonut   = window.renderDonut;
    var _origUpdateFilter  = window.updateTypeFilter;
    window.renderChart      = _noop;
    window.renderAlertsTable= _noop;
    window.renderAttacksGrid= _noop;
    window.renderDonut      = _noop;
    window.updateTypeFilter = _noop;
    alerts.forEach(function(a){{
        if(window.ingestAlert) window.ingestAlert(a);
    }});
    window.renderChart      = _origRenderChart;
    window.renderAlertsTable= _origRenderAlerts;
    window.renderAttacksGrid= _origRenderGrid;
    window.renderDonut      = _origRenderDonut;
    window.updateTypeFilter = _origUpdateFilter;
    // Cancel any pending JS debounce timer — we're about to render now
    if(window._heavyRenderTimer){{ clearTimeout(window._heavyRenderTimer); window._heavyRenderTimer=null; }}
    // Single render pass
    if(window.batchUpdateChart)     window.batchUpdateChart();
    if(window.renderAlertsTable)    window.renderAlertsTable();
    if(window.renderAttacksGrid)    window.renderAttacksGrid();
    if(window.renderDonut)          window.renderDonut();
    if(window.updateTypeFilter)     window.updateTypeFilter();
    if(window.updateHeroCounters)   window.updateHeroCounters();
    if(window.updateSummaryMetrics) window.updateSummaryMetrics();
    window._renderInProgress = false;
}})();""")

        # 2. Push threat profile updates
        if threats:
            threats_json = json.dumps(threats)
            parts.append(f"""
(function(){{
    var profiles = {threats_json};
    profiles.forEach(function(p){{
        if(window.ingestThreatProfile) window.ingestThreatProfile(p);
    }});
    if(window.renderThreatScores) window.renderThreatScores();
}})();""")

        # 3. Push correlation events
        if corrs:
            corrs_json = json.dumps(corrs)
            parts.append(f"""
(function(){{
    var corrs = {corrs_json};
    corrs.forEach(function(c){{
        if(window.ingestCorrelation) window.ingestCorrelation(c);
    }});
    if(window.renderCorrelations) window.renderCorrelations();
}})();""")

        # 4. Batch ingestFlow calls
        if flows:
            flows_json = json.dumps(flows)
            parts.append(f"""
(function(){{
    var flows = {flows_json};
    flows.forEach(function(f){{
        if(window.ingestFlow) window.ingestFlow(f);
    }});
}})();""")

        # ONE combined JS execution — avoids multiple IPC round-trips to the
        # renderer process which each cause a compositor frame flush.
        combined = "\n".join(parts)
        self._js(combined)

    # ── Block/unblock callbacks from ResponseEngine ───────────────────────────
    def _on_block_cb(self, ip: str, reason: str, temporary: bool):
        """Called from background thread — bounce UI work to GUI via QTimer."""
        QTimer.singleShot(0, lambda: self._do_block_ui(ip, reason, temporary))
        self.metrics.on_block()
        if self.ip_tracker:
            try:
                self.ip_tracker.on_block(ip)
                log.debug(f"[GeoTrack] on_block — ip={ip} temporary={temporary}")
            except Exception as exc:
                log.error(f"[GeoTrack] on_block error for {ip}: {exc}")

    def _on_unblock_cb(self, ip: str):
        QTimer.singleShot(0, lambda: self._do_unblock_ui(ip))
        self.metrics.on_unblock()
        if self.ip_tracker:
            try:
                self.ip_tracker.on_unblock(ip)
                log.debug(f"[GeoTrack] on_unblock — ip={ip}")
            except Exception as exc:
                log.error(f"[GeoTrack] on_unblock error for {ip}: {exc}")

    def _do_block_ui(self, ip: str, reason: str, temporary: bool):
        """Push a blocked-IP record into the dashboard's JS blockedIPs[] array.
        This keeps updateBlockedTable() — which rebuilds the table from blockedIPs[] —
        in sync so the row survives tab switches."""
        btype  = "TEMPORARY" if temporary else "PERMANENT"
        now    = datetime.now(timezone.utc).strftime("%H:%M:%S")
        payload = json.dumps({
            "ip":       ip,
            "reason":   reason,
            "time":     now,
            "severity": "HIGH",
            "btype":    btype,
        })
        self._js(f"if(window.ingestBlockedIP) window.ingestBlockedIP({payload});")
        log.info(f"[UI] Block pushed to dashboard: {ip} ({btype})")

    def _do_unblock_ui(self, ip: str):
        """Remove an IP from the dashboard's JS blockedIPs[] array."""
        payload = json.dumps(ip)
        self._js(f"if(window.removeBlockedIP) window.removeBlockedIP({payload});")
        log.info(f"[UI] Unblock pushed to dashboard: {ip}")

    def _on_error(self, msg: str):
        self._stop()
        QMessageBox.critical(self, "Capture Error", msg)

    # ── IPS toggle ────────────────────────────────────────────────────────────
    def _toggle_ips(self):
        self.ips_mode = not self.ips_mode
        if self.ips_mode:
            self.btn_ips.setText("IPS: ON -- AUTO BLOCKING")
            self.btn_ips.setStyleSheet(self._btn_style("#ff4d6d", bold=True))
            self._js("typeof toast==='function'&&"
                     "toast('IPS ON -- threats auto-blocked','error');")
        else:
            self.btn_ips.setText("IPS: OFF")
            self.btn_ips.setStyleSheet(self._btn_style("#ffaa00"))
            self._js("typeof toast==='function'&&"
                     "toast('IPS Mode OFF','warn');")

    # ── Whitelist dialog ──────────────────────────────────────────────────────
    def _whitelist_dialog(self):
        ip, ok = QInputDialog.getText(
            self, "Add to Whitelist",
            "Enter IP or CIDR to never block\n(e.g. 192.168.1.0/24 or 10.0.0.1):")
        if ok and ip.strip():
            self.response.whitelist_add(ip.strip())
            self._js(f"typeof toast==='function'&&"
                     f"toast('Whitelisted: {_html.escape(ip.strip())}','warn');")

    # ── Export CSV ────────────────────────────────────────────────────────────
    def _export_csv(self):
        path = self.db.export_csv()
        QMessageBox.information(self, "Export Complete",
            f"Alerts exported to:\n{os.path.abspath(path)}")

    # ── Page loaded — inject JS bridge ───────────────────────────────────────
    def _page_ready(self, ok):
        if not ok: return
        self._page_loaded = True

        # JS bridge — block/unblock commands from dashboard buttons
        self._js("""
        window.ipdsBlock = function(ip, reason){
            window._ipds_block_target = {ip:ip, reason:reason};
        };
        window.ipdsUnblock = function(ip){
            window._ipds_unblock_target = ip;
        };
        """)

        # JS bridge polling timer
        self._bridge_timer = QTimer()
        self._bridge_timer.timeout.connect(self._poll_js_bridge)
        self._bridge_timer.start(500)

        # Start the UI flush timer — 3s batch interval matches JS debounce
        self._flush_timer = QTimer()
        self._flush_timer.timeout.connect(self._flush_ui_buffer)
        self._flush_timer.start(3000)  # 3-second batch interval

        # ── Geo Intelligence: push geo data to dashboard every 3 s ─────────────
        # Start the timer whenever ip_tracker is available — even if geo_db
        # is None (DB open failure), _flush_geo has its own None guards.
        if GEO_OK and self.ip_tracker:
            self._geo_timer = QTimer()
            self._geo_timer.timeout.connect(self._flush_geo)
            self._geo_timer.start(3_000)   # 3-second real-time refresh
            # Push initial geo data immediately (don't wait 3s for first render)
            QTimer.singleShot(1_500, self._flush_geo)
            log.info("[GeoInit] Geo flush timer started — interval=3s")

        # Restore blocked IPs from DB
        for ip, reason, ts in self.db.get_blocked():
            self._do_block_ui(ip, reason, False)

        self.sb.showMessage(
            "Dashboard ready — select interface and click START CAPTURE")

    def _poll_js_bridge(self):
        self._js("""(function(){
            var b=window._ipds_block_target;
            if(b){window._ipds_block_target=null;
                  window._ipds_pending_block=JSON.stringify(b);}
            var u=window._ipds_unblock_target;
            if(u){window._ipds_unblock_target=null;
                  window._ipds_pending_unblock=u;}
        })();""")
        self.web.page().runJavaScript(
            "window._ipds_pending_block||''", self._handle_block_cmd)
        self.web.page().runJavaScript(
            "window._ipds_pending_unblock||''", self._handle_unblock_cmd)

    def _handle_block_cmd(self, val):
        if val:
            self._js("window._ipds_pending_block=null;")
            try:
                d = json.loads(val)
                self.response.manual_block(d["ip"], d.get("reason","Manual block"))
            except Exception:
                pass

    def _handle_unblock_cmd(self, val):
        if val:
            self._js("window._ipds_pending_unblock=null;")
            self.response.manual_unblock(val)

    # ── Timers ────────────────────────────────────────────────────────────────
    def _tick(self):
        snap    = self.metrics.snap()
        running = self.worker and self.worker.isRunning()
        up      = snap["uptime"]
        h, m, s = up // 3600, (up % 3600) // 60, up % 60
        self.sb.showMessage(
            f"Packets: {snap['pkt_total']:,}  |  "
            f"pkt/s: {snap['pps']}  |  "
            f"Alerts: {snap['alert_total']:,}  |  "
            f"alert/s: {snap['aps']}  |  "
            f"Blocked: {snap['blocked_cnt']}  |  "
            f"IPS: {'ON [ACTIVE]' if self.ips_mode else 'OFF'}  |  "
            f"Uptime: {h:02d}:{m:02d}:{s:02d}  |  "
            f"{'[CAPTURING]' if running else '[IDLE]'}")

        # Push live counters — use the IDs that actually exist in dashboard.html
        self._js(f"""(function(){{
            var a=document.getElementById('s-total-alerts');
            if(a) a.textContent='{snap["alert_total"]:,}';
            var b=document.getElementById('s-blocked-count');
            if(b) b.textContent='{snap["blocked_cnt"]}';
            var mb=document.getElementById('m-blocked');
            if(mb) mb.textContent='{snap["blocked_cnt"]}';
        }})();""")

    def _tick_top_ips(self):
        """Refresh top-attackers panel in dashboard every 5 seconds."""
        if not self._page_loaded:
            return
        snap  = self.metrics.snap()
        rows  = ""
        for ip, cnt in list(snap["top_ips"].items())[:8]:
            safe_ip = _html.escape(ip)
            bar     = "█" * min(cnt, 25)
            rows += (f'<tr><td style="color:#ff4d6d;font-family:monospace;'
                     f'padding:3px 8px">{safe_ip}</td>'
                     f'<td style="color:#484f58;font-size:10px;padding:3px 4px">{bar}</td>'
                     f'<td style="color:#8b949e;padding:3px 8px">{cnt}</td></tr>')

        # Category breakdown
        cat_rows = ""
        for cat, cnt in list(snap["cats"].items())[:6]:
            cat_rows += (f'<tr><td style="color:#8b949e;padding:2px 8px">{_html.escape(cat)}</td>'
                         f'<td style="color:#58a6ff;padding:2px 8px">{cnt}</td></tr>')

        self._js(f"""(function(){{
            var t=document.getElementById('top-attackers-table');
            if(t) t.innerHTML='{rows}';
            var c=document.getElementById('cat-breakdown-table');
            if(c) c.innerHTML='{cat_rows}';
        }})();""")

    # ── Periodic blocked-IP sync — push full DB list to JS every 5s ─────────
    def _tick_blocked_sync(self):
        """Re-sync the full blocked-IP list from SQLite → JS blockedIPs[].
        This is the safety net: even if a real-time push was missed (e.g. the
        page wasn't ready yet), the table will catch up within 5 seconds."""
        if not self._page_loaded:
            return
        rows = self.db.get_blocked()   # [(ip, reason, ts), ...]
        records = []
        for ip, reason, ts in rows:
            records.append({"ip": ip, "reason": reason,
                            "time": ts, "severity": "HIGH", "btype": "PERMANENT"})
        payload = json.dumps(records)
        self._js(f"if(window.syncBlockedIPs) window.syncBlockedIPs({payload});")

    # ── Sysmon tick — CPU / RAM / GPU ─────────────────────────────────────────
    def _tick_sysmon(self):
        """Push CPU/RAM/GPU metrics to dashboard every 1.5 seconds."""
        if not self._page_loaded:
            return
        data: dict = {}

        if PSUTIL_OK:
            data["cpu_pct"]      = psutil.cpu_percent(interval=None)
            data["cpu_cores"]    = psutil.cpu_count(logical=True)
            freq = psutil.cpu_freq()
            data["cpu_freq_ghz"] = round(freq.current / 1000, 2) if freq else 0
            mem = psutil.virtual_memory()
            data["ram_pct"]      = mem.percent
            data["ram_used_gb"]  = round(mem.used  / (1024**3), 2)
            data["ram_total_gb"] = round(mem.total / (1024**3), 2)
        else:
            data.update({"cpu_pct": 0, "cpu_cores": 0, "cpu_freq_ghz": 0,
                         "ram_pct": 0, "ram_used_gb": 0, "ram_total_gb": 0})

        # GPU — try GPUtil first, then pynvml
        gpu_ok = False
        if GPUTIL_OK:
            try:
                gpus = GPUtil.getGPUs()
                if gpus:
                    g = gpus[0]
                    data["gpu_pct"]         = g.load * 100
                    data["gpu_name"]        = g.name
                    data["gpu_mem_used_mb"] = g.memoryUsed
                    data["gpu_mem_total_mb"]= g.memoryTotal
                    gpu_ok = True
            except Exception:
                pass
        if not gpu_ok and PYNVML_OK:
            try:
                handle = pynvml.nvmlDeviceGetHandleByIndex(0)
                util   = pynvml.nvmlDeviceGetUtilizationRates(handle)
                mem_i  = pynvml.nvmlDeviceGetMemoryInfo(handle)
                name   = pynvml.nvmlDeviceGetName(handle)
                data["gpu_pct"]         = util.gpu
                data["gpu_name"]        = name if isinstance(name, str) else name.decode()
                data["gpu_mem_used_mb"] = mem_i.used  / (1024**2)
                data["gpu_mem_total_mb"]= mem_i.total / (1024**2)
                gpu_ok = True
            except Exception:
                pass
        if not gpu_ok:
            data["gpu_pct"] = None

        # Use a JS assignment via a temp global to avoid any f-string/quote
        # escaping issues with GPU names or floats.
        js_payload = json.dumps(data)          # always valid JSON / valid JS literal
        self._js(
            f"(function(){{ var d={js_payload};"
            f" if(window.ingestSysmon) window.ingestSysmon(d); }})();"
        )

    # ── Flow emit — called by detection engine on each matched packet ─────────
    def _emit_flow(self, src: str, dst: str, protocol: str,
                   packets: int, risk: str):
        """Buffer a network flow event — flushed in the next UI tick."""
        self._buf_flows.append({
            "src":      src,
            "dst":      dst,
            "protocol": protocol,
            "packets":  packets,
            "risk":     risk,
        })

    # ── System tray ───────────────────────────────────────────────────────────
    def _setup_tray(self):
        self.tray = QSystemTrayIcon(self)
        self.tray.setIcon(self.style().standardIcon(
            self.style().StandardPixmap.SP_DriveNetIcon))
        self.tray.setToolTip("IPDS Pro — Running")
        m = QMenu()
        m.addAction("Show",  self.show)
        m.addAction("Hide",  self.hide)
        m.addSeparator()
        m.addAction("Start Capture", self._start)
        m.addAction("Stop Capture",  self._stop)
        m.addSeparator()
        m.addAction("Quit", QApplication.quit)
        self.tray.setContextMenu(m)
        self.tray.activated.connect(lambda r:
            (self.show(), self.raise_())
            if r == QSystemTrayIcon.ActivationReason.DoubleClick else None)
        self.tray.show()

    def _js(self, code: str):
        if self._page_loaded:
            try:
                self.web.page().runJavaScript(code)
            except Exception as _js_exc:
                log.error("[JS] runJavaScript error: %s", _js_exc)

    def _flush_geo(self):
        """
        Push geo intelligence data to the dashboard JS bridge every 3 s.

        Strategy:
          1. Read in-memory IPStats from ip_tracker (zero-lag, never stale).
          2. Merge with DB data for country/cloud/TOR aggregates (updated by
             the IPTracker background flush thread every 5 s).
          3. Build the JSON payload and call window.ingestGeoData(data).

        Private / local IPs ARE included — they are valuable for internal
        lateral-movement detection even without geo coordinates.
        """
        if getattr(self, '_geo_closing', False):
            return
        if not self._page_loaded:
            log.debug("[GeoFlush] Skipped — page not ready yet")
            return
        if not self.ip_tracker:
            log.debug("[GeoFlush] Skipped — ip_tracker not initialised")
            return

        try:
            # ── 1. Real-time IP table from in-memory tracker ──────────────────
            live_stats: list[dict] = self.ip_tracker.get_all_dict()
            log.info(f"[GeoFlush] In-memory ip_tracker has {len(live_stats)} IPs")

            # Flatten nested GeoRecord into the row dict expected by the dashboard
            ip_table: list[dict] = []
            for s in live_stats:
                geo = s.get("geo", {})
                row = {
                    # identification
                    "ip":            s["ip"],
                    # geo fields
                    "country":       geo.get("country", ""),
                    "country_name":  geo.get("country_name", ""),
                    "region":        geo.get("region", ""),
                    "city":          geo.get("city", ""),
                    "isp":           geo.get("isp", "") or geo.get("asn_org", ""),
                    "asn":           geo.get("asn", 0),
                    "asn_org":       geo.get("asn_org", ""),
                    "latitude":      geo.get("latitude", 0.0),
                    "longitude":     geo.get("longitude", 0.0),
                    "timezone":      geo.get("timezone", ""),
                    "country_risk":  geo.get("country_risk", 0),
                    # threat intel tags
                    "is_tor":        geo.get("is_tor", False),
                    "is_vpn":        geo.get("is_vpn", False),
                    "is_private":    geo.get("is_private", False),
                    "is_loopback":   geo.get("is_loopback", False),
                    "cloud_provider":geo.get("cloud_provider", ""),
                    # runtime stats
                    "packet_count":  s.get("packet_count", 0),
                    "attack_count":  s.get("attack_count", 0),
                    "threat_score":  round(s.get("threat_score", 0.0), 1),
                    "threat_status": s.get("threat_status", "CLEAN"),
                    "is_blocked":    s.get("is_blocked", False),
                    "attack_types":  s.get("attack_types", []),
                    "first_seen":    s.get("first_seen", ""),
                    "last_seen":     s.get("last_seen", ""),
                }
                ip_table.append(row)

            # ── 1b. Fallback: if in-memory is empty, pull from DB ─────────────
            # This handles the window between startup and the first packet arriving.
            if not ip_table and self.geo_db:
                try:
                    db_rows = self.geo_db.get_all(limit=200)
                    if db_rows:
                        log.info("[GeoFlush] In-memory empty — using %d DB rows", len(db_rows))
                        ip_table = db_rows
                except Exception as fb_exc:
                    log.warning("[GeoFlush] DB fallback query failed: %s", fb_exc)

            # Sort by threat_score desc for the dashboard table
            ip_table.sort(key=lambda r: r.get("threat_score", 0), reverse=True)

            # ── 2. Aggregates from DB (updated by background flush thread) ────
            country_map = cloud_summary = top_attackers = tor_ips = blocked_geo = []
            if self.geo_db:
                try:
                    country_map   = self.geo_db.get_country_summary()
                    cloud_summary = self.geo_db.get_cloud_summary()
                    top_attackers = self.geo_db.get_top_attackers(20)
                    tor_ips       = self.geo_db.get_tor_ips()
                    blocked_geo   = self.geo_db.get_blocked_geo()
                except Exception as db_exc:
                    log.warning(f"[GeoFlush] DB aggregate query failed: {db_exc}")

            payload = {
                "ip_table":       ip_table[:200],
                "country_map":    country_map,
                "cloud_summary":  cloud_summary,
                "top_attackers":  top_attackers,
                "tor_ips":        tor_ips,
                "blocked_geo":    blocked_geo,
            }

            ip_count      = len(ip_table)
            country_count = len(country_map)
            log.info(
                f"[GeoFlush] Payload ready — IPs: {ip_count}, "
                f"countries: {country_count}, "
                f"tor: {len(tor_ips)}, blocked: {len(blocked_geo)}"
            )

            # ── 3. Inject into dashboard via window.ingestGeoData ─────────────
            try:
                # ensure_ascii=True: all non-ASCII characters are \uXXXX-escaped so
                # the JSON string is always safe to splice into a JS source string,
                # even when QWebEngine's JS parser runs in strict/ASCII mode.
                payload_json = json.dumps(payload, ensure_ascii=True, default=str)
            except Exception as ser_exc:
                log.error("[GeoFlush] JSON serialisation error: %s", ser_exc)
                return

            # Browser console debug line (visible in QtWebEngine DevTools)
            # Note: keep this string pure ASCII — non-ASCII chars in runJavaScript
            # source strings can trigger a SyntaxError in Chromium's JS parser.
            debug_js = (
                "console.log('[GeoIntel] _flush_geo -> "
                f"{ip_count} IPs / {country_count} countries / "
                f"{len(tor_ips)} TOR / {len(blocked_geo)} blocked');"
            )
            self._js(debug_js)

            # Main data push — payload_json is guaranteed ASCII-safe above.
            # Also call _geoInitMap() so the canvas initialises if the geo tab
            # is already visible (e.g. user opened it before capture started).
            self._js(
                f"if(window.ingestGeoData) window.ingestGeoData({payload_json});"
                f"if(window._geoInitMap) window._geoInitMap();"
            )
            log.info(
                "[GeoFlush] window.ingestGeoData called — %d IPs pushed to dashboard",
                ip_count
            )

        except Exception as exc:
            log.error(f"[GeoFlush] Unhandled error in _flush_geo: {exc}",
                      exc_info=True)

    def closeEvent(self, event):
        self._stop()
        self.tray.hide()
        eve_log.close()
        # ── Geo Intelligence cleanup ──────────────────────────────────────────
        self._geo_closing = True   # prevent _flush_geo from touching closed DB
        if self._geo_timer if hasattr(self, '_geo_timer') else None:
            try: self._geo_timer.stop()
            except Exception: pass
        if self.ip_tracker:
            self.ip_tracker.stop()
        if self.geo_engine:
            self.geo_engine.close()
        if self.geo_db:
            self.geo_db.close()
        event.accept()


# ══════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    # ── Chromium / QWebEngine environment flags ──────────────────────────────
    #
    # These MUST be set before QApplication is created.
    # os.environ.setdefault is used so that a user who sets the variable in
    # their environment can still override individual flags if needed.
    #
    # ── FLAGS REMOVED (and why they caused bugs) ────────────────────────────
    #
    #  --disable-gpu-compositing
    #    Moved all compositing to the CPU raster thread.  Result: every live
    #    DOM update (feed rows, counters, chart bars) triggered a FULL software
    #    repaint of the entire viewport — far more expensive than GPU compositing.
    #    Also caused the nav bar and toast to flicker on every alert ingest.
    #    REMOVED.
    #
    #  --disable-features=CSSBackdropFilter
    #    Intended to reduce compositor layer count, but this feature flag also
    #    disables the stacking-context isolation path that Qt Chromium uses to
    #    anchor the native select popup z-order.  Removing this flag was
    #    necessary but not sufficient (the popup bug also requires CSS fixes).
    #    REMOVED.
    #
    # ── FLAGS KEPT ──────────────────────────────────────────────────────────
    #
    #  --no-sandbox
    #    Required on Windows for non-SYSTEM users and inside PyInstaller bundles
    #    where the renderer process cannot create its own sandbox.  Safe for a
    #    local desktop security tool.
    #
    #  --disable-smooth-scrolling
    #    Prevents scroll animation jitter during rapid DOM updates.  The live
    #    feed inserts rows at ~3s intervals; without this flag the viewport
    #    stutters as Qt tries to animate the scroll position.
    #
    # ── FLAGS ADDED ─────────────────────────────────────────────────────────
    #
    #  --disable-background-timer-throttling
    #    Without this, Chromium throttles setInterval/setTimeout to 1-Hz when
    #    the window is minimised or the tab is hidden.  The monitoring dashboard
    #    needs its JS timers to keep firing at full rate even when backgrounded.
    #
    #  --disable-renderer-backgrounding
    #    Keeps the renderer process at normal OS scheduling priority even when
    #    the Qt window loses focus.  Prevents alert ingestion lag when the user
    #    is working in another application.
    #
    #  --force-color-profile=srgb
    #    Locks the ICC colour profile to sRGB.  Without this, the dark theme
    #    colours can shift on wide-gamut displays or when Windows HDR is active,
    #    making greens look yellow and reds look orange.
    #
    #  --disable-features=UseOzonePlatform
    #    On Linux with Wayland, Qt may route the popup layer through the Wayland
    #    subsurface protocol instead of X11, which breaks popup z-ordering in
    #    the same way as the stacking-context bugs.  This flag forces X11/XCB
    #    compositing regardless of the display server.  Safe on Windows too
    #    (the flag is a no-op there).
    #
    os.environ.setdefault(
        "QTWEBENGINE_CHROMIUM_FLAGS",
        "--no-sandbox "
        "--disable-smooth-scrolling "
        "--disable-background-timer-throttling "
        "--disable-renderer-backgrounding "
        "--force-color-profile=srgb "
        "--disable-features=UseOzonePlatform"
    )
    app = QApplication(sys.argv)
    app.setApplicationName("IPDS Pro")
    app.setStyle("Fusion")
    win = IPDSWindow()
    win.show()
    sys.exit(app.exec())
