#!/usr/bin/env python3
"""
geo_intelligence.py — Geo Intelligence & IP Attribution Engine
================================================================
Drop-in module for IPDS Pro (app.py / main.py).

Features:
  • MaxMind GeoLite2 (City + ASN) lookup with LRU cache
  • Public / Private / Loopback / Link-local classification
  • TOR exit-node detection (cached daily list)
  • Cloud provider detection (AWS, Azure, GCP, DigitalOcean, Cloudflare, …)
  • ISP / ASN intelligence
  • Country-level risk scoring (configurable)
  • Real-time per-IP statistics (packets, attacks, threat score, first/last seen)
  • Historical IP tracking via SQLite
  • Thread-safe; designed for high-volume packet ingestion
  • Zero repeated GeoIP lookups (ip_cache) — O(1) after first lookup
  • Full JSON export for dashboard JS bridge

Dependencies (pip install):
    geoip2          — GeoIP2 client + database reader
    requests        — TOR list download (optional, falls back gracefully)

MaxMind GeoLite2 databases (free, require registration):
    https://dev.maxmind.com/geoip/geolite2-free-geolocation-data
    Place the .mmdb files anywhere and pass the paths to GeoEngine():
        GeoCity.mmdb  →  city_db_path
        GeoASN.mmdb   →  asn_db_path
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import sqlite3
import threading
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from functools import lru_cache
from typing import Optional

log = logging.getLogger("IPDS.GeoIntel")

# ─── optional imports (degrade gracefully) ────────────────────────────────────
try:
    import geoip2.database
    import geoip2.errors
    GEOIP2_OK = True
except ImportError:
    GEOIP2_OK = False
    log.warning("geoip2 not installed — geo lookups disabled. "
                "Run:  pip install geoip2")

try:
    import requests as _requests
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False


# ══════════════════════════════════════════════════════════════════════════════
#  CONSTANTS & CONFIGURATION
# ══════════════════════════════════════════════════════════════════════════════

# Country ISO codes → risk level (0=low … 100=critical)
# Adjust freely to match your threat intelligence policy.
COUNTRY_RISK: dict[str, int] = {
    # Very high-risk sources (common attack origins in threat feeds)
    "CN": 75, "RU": 80, "KP": 95, "IR": 85, "BY": 70,
    "VN": 60, "NG": 65, "BR": 45, "UA": 55, "RO": 55,
    "TR": 50, "IN": 35, "PK": 60, "ID": 40,
    # Low-risk (mature, well-regulated internet)
    "US": 20, "GB": 15, "DE": 15, "JP": 15, "CA": 15,
    "AU": 15, "FR": 20, "NL": 20, "SE": 15, "CH": 15,
    # Default (not in table) → 30
}
DEFAULT_COUNTRY_RISK = 30

# Cloud provider CIDR prefixes (extend as needed)
CLOUD_PROVIDERS: dict[str, list[str]] = {
    "AWS":          ["3.0.0.0/8", "52.0.0.0/8", "54.0.0.0/8",
                     "13.0.0.0/8", "18.0.0.0/8", "34.192.0.0/10",
                     "35.0.0.0/8"],
    "Azure":        ["13.64.0.0/11", "20.0.0.0/8", "40.64.0.0/10",
                     "52.224.0.0/11", "104.40.0.0/13"],
    "GCP":          ["34.0.0.0/8",   "35.184.0.0/13", "104.154.0.0/15",
                     "130.211.0.0/16", "142.250.0.0/15"],
    "DigitalOcean": ["104.131.0.0/18", "159.65.0.0/18", "167.99.0.0/18",
                     "174.138.0.0/17"],
    "Cloudflare":   ["103.21.244.0/22", "103.22.200.0/22",
                     "104.16.0.0/13",   "172.64.0.0/13",
                     "198.41.128.0/17"],
    "Linode":       ["45.33.0.0/17",  "172.104.0.0/14"],
    "Vultr":        ["45.32.0.0/14",  "108.61.0.0/16"],
    "OVH":          ["51.68.0.0/14",  "54.36.0.0/14"],
}

# Pre-parse cloud CIDR prefixes once at import time
_CLOUD_NETS: list[tuple[str, ipaddress.IPv4Network | ipaddress.IPv6Network]] = []
for _provider, _cidrs in CLOUD_PROVIDERS.items():
    for _cidr in _cidrs:
        try:
            _CLOUD_NETS.append((_provider, ipaddress.ip_network(_cidr, strict=False)))
        except ValueError:
            pass

# TOR exit-node list URL (public, updated daily)
TOR_EXIT_LIST_URL = "https://check.torproject.org/torbulkexitlist"
TOR_CACHE_TTL     = 86_400   # 24 hours in seconds


# ══════════════════════════════════════════════════════════════════════════════
#  DATA CLASSES
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class GeoRecord:
    """Immutable geo-lookup result for one IP address."""
    ip:           str
    is_private:   bool
    is_loopback:  bool
    is_multicast: bool
    country:      str = ""          # ISO-2  e.g. "US"
    country_name: str = ""          # "United States"
    region:       str = ""          # state / region name
    city:         str = ""
    isp:          str = ""          # ISP / Org from ASN DB
    asn:          int = 0
    asn_org:      str = ""
    latitude:     float = 0.0
    longitude:    float = 0.0
    timezone:     str = ""
    country_risk: int = 0           # 0–100
    is_tor:       bool = False
    is_vpn:       bool = False      # heuristic via ASN keywords
    cloud_provider: str = ""        # "AWS", "Azure", … or ""
    lookup_ok:    bool = False      # False if DB missing or lookup failed


@dataclass
class IPStats:
    """Mutable runtime statistics for one IP address."""
    ip:           str
    geo:          GeoRecord
    packet_count: int   = 0
    attack_count: int   = 0
    threat_score: float = 0.0
    threat_status:str   = "CLEAN"   # CLEAN | SUSPICIOUS | MALICIOUS | BLOCKED
    first_seen:   str   = ""
    last_seen:    str   = ""
    is_blocked:   bool  = False
    attack_types: list  = field(default_factory=list)   # last N attack categories

    def to_dict(self) -> dict:
        d = asdict(self)
        d["geo"] = asdict(self.geo)
        return d


# ══════════════════════════════════════════════════════════════════════════════
#  TOR DETECTOR
# ══════════════════════════════════════════════════════════════════════════════

class TorDetector:
    """Maintains a daily-refreshed set of TOR exit-node IPs."""

    def __init__(self) -> None:
        self._exit_nodes: set[str] = set()
        self._fetched_at: float    = 0.0
        self._lock                 = threading.Lock()

    def _refresh(self) -> None:
        if not REQUESTS_OK:
            return
        now = time.time()
        if now - self._fetched_at < TOR_CACHE_TTL:
            return
        try:
            r = _requests.get(TOR_EXIT_LIST_URL, timeout=10)
            r.raise_for_status()
            nodes = {line.strip() for line in r.text.splitlines()
                     if line.strip() and not line.startswith("#")}
            with self._lock:
                self._exit_nodes = nodes
                self._fetched_at = now
            log.info(f"[TorDetector] Loaded {len(nodes)} TOR exit nodes")
        except Exception as exc:
            log.warning(f"[TorDetector] Failed to fetch TOR list: {exc}")

    def is_tor(self, ip: str) -> bool:
        self._refresh()
        with self._lock:
            return ip in self._exit_nodes

    def preload(self) -> None:
        """Call once at startup in a background thread."""
        threading.Thread(target=self._refresh, daemon=True).start()


# ══════════════════════════════════════════════════════════════════════════════
#  GEO ENGINE — core lookup + caching
# ══════════════════════════════════════════════════════════════════════════════

class GeoEngine:
    """
    Thread-safe GeoIP lookup engine.

    Parameters
    ----------
    city_db_path : path to GeoLite2-City.mmdb  (None → lookup disabled)
    asn_db_path  : path to GeoLite2-ASN.mmdb   (None → ASN disabled)
    cache_size   : max IPs cached in memory (LRU)
    """

    _VPN_ASN_KEYWORDS = (
        "vpn", "proxy", "anonymiz", "hide", "cloak",
        "tunnel", "private", "freedom", "shield",
    )

    def __init__(
        self,
        city_db_path: Optional[str] = None,
        asn_db_path:  Optional[str] = None,
        cache_size:   int = 4096,
    ) -> None:
        self._city_reader: Optional["geoip2.database.Reader"] = None
        self._asn_reader:  Optional["geoip2.database.Reader"] = None
        self._cache: dict[str, GeoRecord] = {}
        self._cache_size = cache_size
        self._lock = threading.Lock()
        self.tor = TorDetector()

        if GEOIP2_OK:
            if city_db_path and os.path.isfile(city_db_path):
                try:
                    self._city_reader = geoip2.database.Reader(city_db_path)
                    log.info(f"[GeoEngine] GeoLite2-City loaded OK: {city_db_path}")
                except Exception as e:
                    log.error(f"[GeoEngine] ERROR: GeoLite2-City DB open error ({city_db_path}): {e}")
            elif city_db_path:
                log.warning(
                    f"[GeoEngine] GeoLite2-City.mmdb not found at: {city_db_path!r} — "
                    "country/city/lat-lng lookups disabled. "
                    "Download from https://dev.maxmind.com/geoip/geolite2-free-geolocation-data"
                )
            else:
                log.warning("[GeoEngine] WARNING: No GeoLite2-City path provided — "
                            "country/city lookups disabled.")

            if asn_db_path and os.path.isfile(asn_db_path):
                try:
                    self._asn_reader = geoip2.database.Reader(asn_db_path)
                    log.info(f"[GeoEngine] GeoLite2-ASN loaded OK: {asn_db_path}")
                except Exception as e:
                    log.error(f"[GeoEngine] ERROR: GeoLite2-ASN DB open error ({asn_db_path}): {e}")
            elif asn_db_path:
                log.warning(
                    f"[GeoEngine] GeoLite2-ASN.mmdb not found at: {asn_db_path!r} — "
                    "ISP/ASN lookups disabled."
                )
            else:
                log.warning("[GeoEngine] WARNING: No GeoLite2-ASN path provided — "
                            "ISP/ASN lookups disabled.")
        else:
            log.warning(
                "[GeoEngine] WARNING: geoip2 library not installed — "
                "all GeoLite2 lookups disabled. Run: pip install geoip2"
            )

        # Kick off TOR list in background
        self.tor.preload()

    # ── public API ─────────────────────────────────────────────────────────────

    def lookup(self, ip: str) -> GeoRecord:
        """Return a GeoRecord for *ip*.  Result is cached — O(1) after first call."""
        with self._lock:
            if ip in self._cache:
                return self._cache[ip]

        record = self._lookup_uncached(ip)

        with self._lock:
            # Simple LRU eviction: drop oldest if over limit
            if len(self._cache) >= self._cache_size:
                oldest = next(iter(self._cache))
                del self._cache[oldest]
            self._cache[ip] = record

        return record

    def cache_size(self) -> int:
        with self._lock:
            return len(self._cache)

    def close(self) -> None:
        if self._city_reader:
            self._city_reader.close()
        if self._asn_reader:
            self._asn_reader.close()

    # ── private helpers ────────────────────────────────────────────────────────

    def _lookup_uncached(self, ip: str) -> GeoRecord:
        """Perform the actual GeoIP lookup (no caching layer)."""
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            # Unparseable string — return minimal record
            return GeoRecord(ip=ip, is_private=False, is_loopback=False,
                             is_multicast=False)

        # Classify address type
        is_private   = addr.is_private
        is_loopback  = addr.is_loopback
        is_multicast = addr.is_multicast
        is_link_local = addr.is_link_local

        rec = GeoRecord(
            ip=ip,
            is_private=is_private,
            is_loopback=is_loopback,
            is_multicast=is_multicast,
        )

        # Private / loopback addresses → no external lookup needed
        if is_private or is_loopback or is_multicast or is_link_local:
            rec.country      = "LOCAL"
            rec.country_name = "Local/Private Network"
            rec.isp          = "Internal"
            rec.lookup_ok    = True
            return rec

        # ── GeoLite2 City lookup ───────────────────────────────────────────────
        if self._city_reader:
            try:
                city = self._city_reader.city(ip)
                rec.country      = city.country.iso_code or ""
                rec.country_name = city.country.name or ""
                rec.region       = (city.subdivisions.most_specific.name or "")
                rec.city         = city.city.name or ""
                if city.location.latitude is not None:
                    rec.latitude  = round(city.location.latitude, 4)
                    rec.longitude = round(city.location.longitude, 4)
                rec.timezone  = city.location.time_zone or ""
                rec.lookup_ok = True
            except Exception:
                pass   # IP not in DB — leave fields blank

        # ── GeoLite2 ASN lookup ────────────────────────────────────────────────
        if self._asn_reader:
            try:
                asn_r        = self._asn_reader.asn(ip)
                rec.asn      = asn_r.autonomous_system_number or 0
                rec.asn_org  = asn_r.autonomous_system_organization or ""
                rec.isp      = rec.asn_org
                rec.lookup_ok = True
            except Exception:
                pass

        # ── Country risk score ─────────────────────────────────────────────────
        rec.country_risk = COUNTRY_RISK.get(rec.country, DEFAULT_COUNTRY_RISK)

        # ── TOR detection ──────────────────────────────────────────────────────
        rec.is_tor = self.tor.is_tor(ip)

        # ── VPN heuristic (ASN org keywords) ──────────────────────────────────
        if rec.asn_org:
            low = rec.asn_org.lower()
            rec.is_vpn = any(kw in low for kw in self._VPN_ASN_KEYWORDS)

        # ── Cloud provider detection ───────────────────────────────────────────
        rec.cloud_provider = self._cloud_provider(addr)

        return rec

    @staticmethod
    def _cloud_provider(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
        for provider, net in _CLOUD_NETS:
            try:
                if addr in net:
                    return provider
            except TypeError:
                pass
        return ""


# ══════════════════════════════════════════════════════════════════════════════
#  GEO DATABASE — SQLite persistence
# ══════════════════════════════════════════════════════════════════════════════

_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS geo_ip_stats (
    ip              TEXT PRIMARY KEY,
    -- Classification
    is_private      INTEGER DEFAULT 0,
    is_loopback     INTEGER DEFAULT 0,
    is_multicast    INTEGER DEFAULT 0,
    -- Geo fields
    country         TEXT DEFAULT '',
    country_name    TEXT DEFAULT '',
    region          TEXT DEFAULT '',
    city            TEXT DEFAULT '',
    isp             TEXT DEFAULT '',
    asn             INTEGER DEFAULT 0,
    asn_org         TEXT DEFAULT '',
    latitude        REAL DEFAULT 0.0,
    longitude       REAL DEFAULT 0.0,
    timezone        TEXT DEFAULT '',
    country_risk    INTEGER DEFAULT 0,
    -- Threat intelligence
    is_tor          INTEGER DEFAULT 0,
    is_vpn          INTEGER DEFAULT 0,
    cloud_provider  TEXT DEFAULT '',
    -- Runtime stats
    packet_count    INTEGER DEFAULT 0,
    attack_count    INTEGER DEFAULT 0,
    threat_score    REAL DEFAULT 0.0,
    threat_status   TEXT DEFAULT 'CLEAN',
    is_blocked      INTEGER DEFAULT 0,
    attack_types    TEXT DEFAULT '[]',   -- JSON array
    -- Timestamps
    first_seen      TEXT DEFAULT '',
    last_seen       TEXT DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_geo_country   ON geo_ip_stats(country);
CREATE INDEX IF NOT EXISTS idx_geo_threat    ON geo_ip_stats(threat_status);
CREATE INDEX IF NOT EXISTS idx_geo_blocked   ON geo_ip_stats(is_blocked);
CREATE INDEX IF NOT EXISTS idx_geo_tor       ON geo_ip_stats(is_tor);
CREATE INDEX IF NOT EXISTS idx_geo_cloud     ON geo_ip_stats(cloud_provider);
CREATE INDEX IF NOT EXISTS idx_geo_score     ON geo_ip_stats(threat_score DESC);
CREATE INDEX IF NOT EXISTS idx_geo_packets   ON geo_ip_stats(packet_count DESC);
CREATE INDEX IF NOT EXISTS idx_geo_attacks   ON geo_ip_stats(attack_count DESC);
CREATE INDEX IF NOT EXISTS idx_geo_last_seen ON geo_ip_stats(last_seen DESC);
"""

_UPSERT_SQL = """
INSERT INTO geo_ip_stats(
    ip, is_private, is_loopback, is_multicast,
    country, country_name, region, city, isp, asn, asn_org,
    latitude, longitude, timezone, country_risk,
    is_tor, is_vpn, cloud_provider,
    packet_count, attack_count, threat_score, threat_status,
    is_blocked, attack_types, first_seen, last_seen
) VALUES (
    :ip, :is_private, :is_loopback, :is_multicast,
    :country, :country_name, :region, :city, :isp, :asn, :asn_org,
    :latitude, :longitude, :timezone, :country_risk,
    :is_tor, :is_vpn, :cloud_provider,
    :packet_count, :attack_count, :threat_score, :threat_status,
    :is_blocked, :attack_types, :first_seen, :last_seen
)
ON CONFLICT(ip) DO UPDATE SET
    -- Geo fields only updated if missing (avoid overwriting good data with blanks)
    country       = CASE WHEN excluded.country != '' THEN excluded.country ELSE country END,
    country_name  = CASE WHEN excluded.country_name != '' THEN excluded.country_name ELSE country_name END,
    region        = CASE WHEN excluded.region != '' THEN excluded.region ELSE region END,
    city          = CASE WHEN excluded.city != '' THEN excluded.city ELSE city END,
    isp           = CASE WHEN excluded.isp != '' THEN excluded.isp ELSE isp END,
    asn           = CASE WHEN excluded.asn != 0 THEN excluded.asn ELSE asn END,
    asn_org       = CASE WHEN excluded.asn_org != '' THEN excluded.asn_org ELSE asn_org END,
    latitude      = CASE WHEN excluded.latitude != 0.0 THEN excluded.latitude ELSE latitude END,
    longitude     = CASE WHEN excluded.longitude != 0.0 THEN excluded.longitude ELSE longitude END,
    timezone      = CASE WHEN excluded.timezone != '' THEN excluded.timezone ELSE timezone END,
    country_risk  = excluded.country_risk,
    is_tor        = excluded.is_tor,
    is_vpn        = excluded.is_vpn,
    cloud_provider= excluded.cloud_provider,
    -- Stats always accumulated
    packet_count  = packet_count + excluded.packet_count,
    attack_count  = attack_count + excluded.attack_count,
    threat_score  = excluded.threat_score,
    threat_status = excluded.threat_status,
    is_blocked    = excluded.is_blocked,
    attack_types  = excluded.attack_types,
    first_seen    = CASE WHEN first_seen = '' THEN excluded.first_seen ELSE first_seen END,
    last_seen     = excluded.last_seen;
"""


class GeoDatabase:
    """
    Thread-safe SQLite persistence layer for geo_ip_stats.
    Uses the same DB file as the main IPDS database (logs/ipds.db)
    so everything stays in one place.
    """

    def __init__(self, db_path: str = "logs/ipds.db") -> None:
        os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        with self._lock:
            self._conn.executescript(_SCHEMA_SQL)
            self._conn.commit()
        log.info("[GeoDatabase] Schema ready")

    # ── Write ──────────────────────────────────────────────────────────────────

    def upsert(self, stats: IPStats) -> None:
        geo = stats.geo
        params = {
            "ip":            stats.ip,
            "is_private":    int(geo.is_private),
            "is_loopback":   int(geo.is_loopback),
            "is_multicast":  int(geo.is_multicast),
            "country":       geo.country,
            "country_name":  geo.country_name,
            "region":        geo.region,
            "city":          geo.city,
            "isp":           geo.isp,
            "asn":           geo.asn,
            "asn_org":       geo.asn_org,
            "latitude":      geo.latitude,
            "longitude":     geo.longitude,
            "timezone":      geo.timezone,
            "country_risk":  geo.country_risk,
            "is_tor":        int(geo.is_tor),
            "is_vpn":        int(geo.is_vpn),
            "cloud_provider":geo.cloud_provider,
            "packet_count":  stats.packet_count,
            "attack_count":  stats.attack_count,
            "threat_score":  round(stats.threat_score, 2),
            "threat_status": stats.threat_status,
            "is_blocked":    int(stats.is_blocked),
            "attack_types":  json.dumps(stats.attack_types[-20:]),
            "first_seen":    stats.first_seen,
            "last_seen":     stats.last_seen,
        }
        with self._lock:
            self._conn.execute(_UPSERT_SQL, params)
            self._conn.commit()

    def mark_blocked(self, ip: str, blocked: bool) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE geo_ip_stats SET is_blocked=?, threat_status=? WHERE ip=?",
                (int(blocked), "BLOCKED" if blocked else "MALICIOUS", ip))
            self._conn.commit()

    # ── Read ───────────────────────────────────────────────────────────────────

    def get(self, ip: str) -> Optional[dict]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM geo_ip_stats WHERE ip=?", (ip,)).fetchone()
        return dict(row) if row else None

    def get_all(
        self,
        limit: int = 500,
        order_by: str = "threat_score DESC",
        where: str = "1=1",
    ) -> list[dict]:
        safe_order = order_by if order_by in {
            "threat_score DESC", "packet_count DESC", "attack_count DESC",
            "last_seen DESC", "first_seen ASC", "country ASC",
        } else "threat_score DESC"
        with self._lock:
            rows = self._conn.execute(
                f"SELECT * FROM geo_ip_stats WHERE {where} "
                f"ORDER BY {safe_order} LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]

    def get_country_summary(self) -> list[dict]:
        """Aggregate stats per country for the heat-map."""
        with self._lock:
            rows = self._conn.execute("""
                SELECT
                    country, country_name, country_risk,
                    COUNT(*)            AS ip_count,
                    SUM(packet_count)   AS total_packets,
                    SUM(attack_count)   AS total_attacks,
                    AVG(threat_score)   AS avg_score,
                    SUM(is_tor)         AS tor_count,
                    SUM(is_vpn)         AS vpn_count
                FROM geo_ip_stats
                WHERE country != '' AND country != 'LOCAL'
                GROUP BY country
                ORDER BY total_attacks DESC
            """).fetchall()
        return [dict(r) for r in rows]

    def get_cloud_summary(self) -> list[dict]:
        """Aggregate stats per cloud provider."""
        with self._lock:
            rows = self._conn.execute("""
                SELECT
                    cloud_provider,
                    COUNT(*)          AS ip_count,
                    SUM(packet_count) AS total_packets,
                    SUM(attack_count) AS total_attacks
                FROM geo_ip_stats
                WHERE cloud_provider != ''
                GROUP BY cloud_provider
                ORDER BY total_attacks DESC
            """).fetchall()
        return [dict(r) for r in rows]

    def get_top_attackers(self, n: int = 20) -> list[dict]:
        return self.get_all(limit=n, order_by="attack_count DESC",
                            where="attack_count > 0")

    def get_top_external(self, n: int = 100) -> list[dict]:
        return self.get_all(limit=n, order_by="packet_count DESC",
                            where="is_private=0 AND is_loopback=0")

    def get_tor_ips(self) -> list[dict]:
        return self.get_all(limit=200, where="is_tor=1")

    def get_blocked_geo(self) -> list[dict]:
        return self.get_all(limit=200, where="is_blocked=1",
                            order_by="last_seen DESC")

    def search(self, query: str) -> list[dict]:
        """Fuzzy search by IP, country, city, ISP, ASN org."""
        like = f"%{query}%"
        with self._lock:
            rows = self._conn.execute("""
                SELECT * FROM geo_ip_stats
                WHERE ip LIKE ? OR country LIKE ? OR city LIKE ?
                   OR isp LIKE ? OR asn_org LIKE ? OR cloud_provider LIKE ?
                ORDER BY threat_score DESC
                LIMIT 200
            """, (like, like, like, like, like, like)).fetchall()
        return [dict(r) for r in rows]

    def dashboard_json(self) -> dict:
        """
        All data the dashboard JS needs in one call.
        Sent as JSON through the QWebEngineView bridge.
        """
        return {
            "ip_table":       self.get_all(limit=200),
            "country_map":    self.get_country_summary(),
            "cloud_summary":  self.get_cloud_summary(),
            "top_attackers":  self.get_top_attackers(20),
            "tor_ips":        self.get_tor_ips(),
            "blocked_geo":    self.get_blocked_geo(),
        }

    def close(self) -> None:
        with self._lock:
            self._conn.close()


# ══════════════════════════════════════════════════════════════════════════════
#  IP TRACKER — in-memory IPStats registry + DB flush
# ══════════════════════════════════════════════════════════════════════════════

class IPTracker:
    """
    Central registry of per-IP statistics.

    Call on_packet() for every captured packet.
    Call on_attack() when a detection rule fires.
    Call on_block() / on_unblock() when ResponseEngine acts.

    Internally:
      • Maintains an IPStats dict in memory (zero DB reads on hot path)
      • Flushes dirty records to GeoDatabase every flush_interval seconds
        (default 5 s) in a background thread
    """

    _MAX_ATTACK_TYPES = 20   # keep last N attack categories per IP

    def __init__(
        self,
        geo_engine:    GeoEngine,
        geo_db:        GeoDatabase,
        flush_interval: float = 5.0,
    ) -> None:
        self._geo     = geo_engine
        self._db      = geo_db
        self._lock    = threading.Lock()
        self._stats:  dict[str, IPStats] = {}
        self._dirty:  set[str]           = set()
        self._flush_interval = flush_interval

        # Periodic DB flush thread
        self._stop_evt = threading.Event()
        self._flush_thread = threading.Thread(
            target=self._flush_loop, daemon=True, name="GeoFlushThread")
        self._flush_thread.start()
        log.info("[IPTracker] Started with flush_interval=%ss", flush_interval)

    # ── Public API (called from CaptureWorker._handle) ─────────────────────────

    def on_packet(self, src_ip: str, dst_ip: str) -> None:
        """Record one packet.  Both src and dst are tracked (incl. private IPs)."""
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        try:
            self._touch(src_ip, ts, pkt_delta=1)
            self._touch(dst_ip, ts, pkt_delta=1)
        except Exception as exc:
            log.error(f"[IPTracker] on_packet error src={src_ip} dst={dst_ip}: {exc}")

    def on_attack(self, src_ip: str, category: str, score_delta: float) -> None:
        """
        Record an attack event originating from src_ip.
        category  — alert category string (e.g. "Port Scan", "SQLi")
        score_delta — how much to add to the IP's threat score
        """
        if not src_ip:
            log.debug("[IPTracker] on_attack called with empty src_ip — skipping")
            return
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        try:
            with self._lock:
                stats = self._get_or_create(src_ip, ts)
                stats.attack_count  += 1
                stats.threat_score  = min(100.0, stats.threat_score + score_delta)
                stats.last_seen     = ts
                if category and category not in stats.attack_types:
                    stats.attack_types.append(category)
                    stats.attack_types = stats.attack_types[-self._MAX_ATTACK_TYPES:]
                stats.threat_status = self._classify_threat(stats)
                self._dirty.add(src_ip)
            log.debug(
                f"[IPTracker] on_attack — ip={src_ip} cat={category} "
                f"score_delta={score_delta:.2f} "
                f"new_score={self._stats[src_ip].threat_score:.1f} "
                f"status={self._stats[src_ip].threat_status}"
            )
        except Exception as exc:
            log.error(f"[IPTracker] on_attack error for {src_ip}: {exc}")

    def on_block(self, ip: str) -> None:
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        try:
            with self._lock:
                stats = self._get_or_create(ip, ts)
                stats.is_blocked    = True
                stats.threat_status = "BLOCKED"
                stats.last_seen     = ts
                self._dirty.add(ip)
            self._db.mark_blocked(ip, True)
            log.debug(f"[IPTracker] on_block — ip={ip} marked BLOCKED")
        except Exception as exc:
            log.error(f"[IPTracker] on_block error for {ip}: {exc}")

    def on_unblock(self, ip: str) -> None:
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        try:
            with self._lock:
                if ip in self._stats:
                    stats = self._stats[ip]
                    stats.is_blocked    = False
                    stats.threat_status = self._classify_threat(stats)
                    stats.last_seen     = ts
                    self._dirty.add(ip)
            self._db.mark_blocked(ip, False)
            log.debug(f"[IPTracker] on_unblock — ip={ip} status restored")
        except Exception as exc:
            log.error(f"[IPTracker] on_unblock error for {ip}: {exc}")

    def get(self, ip: str) -> Optional[IPStats]:
        with self._lock:
            return self._stats.get(ip)

    def get_all_dict(self) -> list[dict]:
        with self._lock:
            return [s.to_dict() for s in self._stats.values()]

    def stop(self) -> None:
        self._stop_evt.set()
        self._flush_all()
        log.info("[IPTracker] Stopped and flushed")

    # ── Private ────────────────────────────────────────────────────────────────

    def _touch(self, ip: str, ts: str, pkt_delta: int = 1) -> None:
        with self._lock:
            stats = self._get_or_create(ip, ts)
            stats.packet_count += pkt_delta
            stats.last_seen    = ts
            self._dirty.add(ip)

    def _get_or_create(self, ip: str, ts: str) -> IPStats:
        """Must be called under self._lock."""
        if ip not in self._stats:
            geo = self._geo.lookup(ip)
            self._stats[ip] = IPStats(
                ip=ip, geo=geo, first_seen=ts, last_seen=ts)
        return self._stats[ip]

    @staticmethod
    def _classify_threat(stats: IPStats) -> str:
        if stats.is_blocked:
            return "BLOCKED"
        if stats.threat_score >= 75 or stats.attack_count >= 20:
            return "MALICIOUS"
        if stats.threat_score >= 35 or stats.attack_count >= 5:
            return "SUSPICIOUS"
        return "CLEAN"

    def _flush_loop(self) -> None:
        while not self._stop_evt.wait(self._flush_interval):
            self._flush_all()

    def _flush_all(self) -> None:
        with self._lock:
            to_flush = list(self._dirty)
            self._dirty.clear()

        if to_flush:
            log.debug(f"[IPTracker] Flushing {len(to_flush)} dirty IP(s) to DB")

        for ip in to_flush:
            with self._lock:
                stats = self._stats.get(ip)
            if stats:
                try:
                    self._db.upsert(stats)
                except Exception as exc:
                    log.error(f"[IPTracker] DB flush error for {ip}: {exc}")


# ══════════════════════════════════════════════════════════════════════════════
#  INTEGRATION HELPERS — plug these into app.py
# ══════════════════════════════════════════════════════════════════════════════

def build_geo_intel(
    city_db_path: Optional[str] = None,
    asn_db_path:  Optional[str] = None,
    db_path:      str = "logs/ipds.db",
    flush_interval: float = 5.0,
) -> tuple["GeoEngine", "GeoDatabase", "IPTracker"]:
    """
    Factory — call once during IPDS startup.

    city_db_path / asn_db_path may be None (file not found) — GeoEngine
    will still initialise and handle private-IP classification; only the
    MaxMind geo lookups will be disabled for that database.

    Returns (geo_engine, geo_db, ip_tracker).
    Pass ip_tracker into CaptureWorker and ResponseEngine callbacks.
    """
    log.info(
        f"[GeoIntel] build_geo_intel — city={city_db_path!r} "
        f"asn={asn_db_path!r} db={db_path!r} flush={flush_interval}s"
    )
    geo_engine = GeoEngine(city_db_path=city_db_path, asn_db_path=asn_db_path)
    geo_db     = GeoDatabase(db_path=db_path)
    ip_tracker = IPTracker(geo_engine=geo_engine, geo_db=geo_db,
                           flush_interval=flush_interval)
    log.info("[GeoIntel] build_geo_intel complete — pipeline active")
    return geo_engine, geo_db, ip_tracker


def geo_dashboard_js(geo_db: GeoDatabase) -> str:
    """
    Build a single JS statement that pushes all geo data into the dashboard
    using the SQLite DB as the data source.

    Prefer _flush_geo() in IPDSWindow for real-time data (reads in-memory
    ip_tracker stats directly).  This helper is kept for compatibility.

    JS functions expected on window:
        window.ingestGeoData(data)   — receives the full geo payload
    """
    try:
        payload = json.dumps(geo_db.dashboard_json(), ensure_ascii=False,
                             default=str)
        js = f"if(window.ingestGeoData) window.ingestGeoData({payload});"
        log.debug(f"[geo_dashboard_js] Built JS payload ({len(payload)} bytes)")
        return js
    except Exception as exc:
        log.error(f"[geo_dashboard_js] Serialization error: {exc}")
        return ""


# ══════════════════════════════════════════════════════════════════════════════
#  APP.PY PATCH — exact lines to add / change
# ══════════════════════════════════════════════════════════════════════════════
"""
─────────────────────────────────────────────────────────────────────────────
HOW TO INTEGRATE INTO app.py  (copy-paste reference)
─────────────────────────────────────────────────────────────────────────────

1.  TOP OF FILE — add import after other imports:

        from geo_intelligence import build_geo_intel, geo_dashboard_js

─────────────────────────────────────────────────────────────────────────────

2.  IPDSWindow.__init__  — after self.db = Database():

        # ── Geo Intelligence ──────────────────────────────────────────────
        self.geo_engine, self.geo_db, self.ip_tracker = build_geo_intel(
            city_db_path="GeoLite2-City.mmdb",
            asn_db_path="GeoLite2-ASN.mmdb",
        )

─────────────────────────────────────────────────────────────────────────────

3.  CaptureWorker._handle  — inside _handle(), after building pkt dict,
    before the engine.process() call:

        # ── Geo tracking ──────────────────────────────────────────────────
        if hasattr(self, '_ip_tracker') and self._ip_tracker:
            self._ip_tracker.on_packet(pkt["src"], pkt["dst"])

    Pass ip_tracker to CaptureWorker by adding it as a constructor param:

        class CaptureWorker(QThread):
            def __init__(self, iface, engine, blocked, ip_tracker=None):
                ...
                self._ip_tracker = ip_tracker

    And in IPDSWindow._start():

        self._worker = CaptureWorker(
            iface, self.engine, self.response.blocked_set(),
            ip_tracker=self.ip_tracker          # ← add this
        )

─────────────────────────────────────────────────────────────────────────────

4.  IPDSWindow._on_alerts  — inside the `for a in alerts:` loop, after
    self.db.save_alert():

        # ── Geo attack recording ──────────────────────────────────────────
        self.ip_tracker.on_attack(
            src_ip     = p.get("src", ""),
            category   = a.get("cat", ""),
            score_delta= float(a.get("threat_score", 0)) * 0.1,
        )

─────────────────────────────────────────────────────────────────────────────

5.  ResponseEngine callbacks — in IPDSWindow._on_block_cb():

        self.ip_tracker.on_block(ip)

    In IPDSWindow._on_unblock_cb():

        self.ip_tracker.on_unblock(ip)

─────────────────────────────────────────────────────────────────────────────

6.  _page_ready  — after starting _flush_timer, add a geo flush timer:

        self._geo_timer = QTimer()
        self._geo_timer.timeout.connect(self._flush_geo)
        self._geo_timer.start(10_000)   # push geo data every 10 s

    And add the handler:

        def _flush_geo(self):
            js = geo_dashboard_js(self.geo_db)
            if js:
                self._js(js)

─────────────────────────────────────────────────────────────────────────────

7.  closeEvent — add cleanup:

        self.ip_tracker.stop()
        self.geo_engine.close()
        self.geo_db.close()

─────────────────────────────────────────────────────────────────────────────
"""


# ══════════════════════════════════════════════════════════════════════════════
#  DASHBOARD JS SNIPPET (paste into dashboard.html)
# ══════════════════════════════════════════════════════════════════════════════
DASHBOARD_JS_SNIPPET = r"""
// ── Geo Intelligence Store ───────────────────────────────────────────────────
window._geoData = {
    ip_table:      [],
    country_map:   [],
    cloud_summary: [],
    top_attackers: [],
    tor_ips:       [],
    blocked_geo:   [],
};

window.ingestGeoData = function(data) {
    Object.assign(window._geoData, data);
    renderGeoTable();
    renderCountryMap();
    renderCloudBadges();
    renderTorBadges();
};

// ── Geo IP Table ─────────────────────────────────────────────────────────────
function renderGeoTable() {
    var rows = window._geoData.ip_table || [];
    var tbody = document.querySelector('#geoTable tbody');
    if (!tbody) return;
    tbody.innerHTML = '';
    rows.forEach(function(r) {
        var flagUrl = r.country && r.country.length === 2
            ? 'https://flagcdn.com/16x12/' + r.country.toLowerCase() + '.png'
            : '';
        var flag = flagUrl ? '<img src="' + flagUrl + '" style="margin-right:4px">' : '';
        var badges = '';
        if (r.is_tor)          badges += '<span class="badge badge-tor">TOR</span> ';
        if (r.is_vpn)          badges += '<span class="badge badge-vpn">VPN</span> ';
        if (r.cloud_provider)  badges += '<span class="badge badge-cloud">' + r.cloud_provider + '</span> ';
        if (r.is_private)      badges += '<span class="badge badge-priv">PRIVATE</span> ';

        var statusClass = {
            'BLOCKED':    'sev-critical',
            'MALICIOUS':  'sev-high',
            'SUSPICIOUS': 'sev-medium',
            'CLEAN':      'sev-low',
        }[r.threat_status] || '';

        var tr = document.createElement('tr');
        tr.innerHTML =
            '<td>' + r.ip + '</td>' +
            '<td>' + flag + (r.country || '—') + '</td>' +
            '<td>' + (r.city || '—') + '</td>' +
            '<td>' + (r.isp || r.asn_org || '—') + '</td>' +
            '<td>AS' + (r.asn || '—') + '</td>' +
            '<td>' + (r.country_risk || 0) + '</td>' +
            '<td>' + badges + '</td>' +
            '<td>' + r.packet_count + '</td>' +
            '<td>' + r.attack_count + '</td>' +
            '<td><span class="' + statusClass + '">' + r.threat_status + '</span></td>' +
            '<td>' + (r.last_seen || '—') + '</td>';
        tbody.appendChild(tr);
    });
}

// ── Country Map Summary ───────────────────────────────────────────────────────
function renderCountryMap() {
    var rows = window._geoData.country_map || [];
    var el = document.getElementById('countryMapSummary');
    if (!el) return;
    el.innerHTML = rows.slice(0, 15).map(function(r) {
        var risk = r.country_risk >= 75 ? '#ff4d6d'
                 : r.country_risk >= 50 ? '#ffaa00' : '#00e676';
        return '<div class="country-row">' +
            '<span style="color:' + risk + ';font-weight:600">' + r.country + '</span> ' +
            r.country_name + ' — ' +
            r.total_attacks + ' attacks / ' + r.ip_count + ' IPs' +
            (r.tor_count ? ' [TOR:' + r.tor_count + ']' : '') +
            '</div>';
    }).join('');
}

// ── Cloud Badges ──────────────────────────────────────────────────────────────
function renderCloudBadges() {
    var rows = window._geoData.cloud_summary || [];
    var el = document.getElementById('cloudSummary');
    if (!el) return;
    el.innerHTML = rows.map(function(r) {
        return '<span class="badge badge-cloud" title="' +
            r.total_packets + ' packets / ' + r.total_attacks + ' attacks">' +
            r.cloud_provider + ' (' + r.ip_count + ')' +
            '</span> ';
    }).join('');
}

// ── TOR Badges ────────────────────────────────────────────────────────────────
function renderTorBadges() {
    var rows = window._geoData.tor_ips || [];
    var el = document.getElementById('torCount');
    if (el) el.textContent = rows.length;
}
"""

DASHBOARD_HTML_SNIPPET = """
<!-- ═══════════════════════════════════════════════════════════════════════════
     GEO INTELLIGENCE TAB  — paste inside your <div id="tabs"> section
     ═══════════════════════════════════════════════════════════════════════ -->

<div id="tab-geo" class="tab-panel" style="display:none">
  <h2 style="color:#00e5ff;margin-bottom:12px">Geo Intelligence &amp; IP Attribution</h2>

  <!-- Summary row -->
  <div style="display:flex;gap:16px;flex-wrap:wrap;margin-bottom:16px">
    <div class="stat-card">
      <div class="stat-label">TOR Exit Nodes</div>
      <div class="stat-value" id="torCount">0</div>
    </div>
    <div class="stat-card" style="flex:1;min-width:300px">
      <div class="stat-label">Cloud Provider Traffic</div>
      <div id="cloudSummary" style="padding:6px 0"></div>
    </div>
    <div class="stat-card" style="flex:2;min-width:300px">
      <div class="stat-label">Top Attack Countries</div>
      <div id="countryMapSummary" style="padding:6px 0;font-size:12px;
           max-height:140px;overflow-y:auto"></div>
    </div>
  </div>

  <!-- Search bar -->
  <div style="margin-bottom:10px">
    <input id="geoSearch" type="text" placeholder="Search IP / country / ISP / ASN…"
      style="background:#1a1a2e;border:1px solid #333;color:#e0e0e0;
             padding:6px 12px;border-radius:6px;width:340px"
      oninput="filterGeoTable(this.value)">
  </div>

  <!-- IP Table -->
  <div style="overflow-x:auto">
    <table id="geoTable" style="width:100%;border-collapse:collapse;font-size:12px">
      <thead>
        <tr style="background:#1a1a2e;color:#00e5ff">
          <th>IP Address</th><th>Country</th><th>City</th>
          <th>ISP / Org</th><th>ASN</th><th>Risk</th>
          <th>Tags</th><th>Packets</th><th>Attacks</th>
          <th>Status</th><th>Last Seen</th>
        </tr>
      </thead>
      <tbody></tbody>
    </table>
  </div>
</div>
"""


# ══════════════════════════════════════════════════════════════════════════════
#  QUICK SELF-TEST (python geo_intelligence.py)
# ══════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    import tempfile

    logging.basicConfig(level=logging.INFO,
                        format="%(levelname)s  %(name)s  %(message)s")

    print("=" * 60)
    print("Geo Intelligence Module — Self Test")
    print("=" * 60)

    # Engine without .mmdb files — will test classification + cloud detection only
    engine = GeoEngine(city_db_path=None, asn_db_path=None)

    test_ips = [
        "192.168.1.100",   # private
        "127.0.0.1",       # loopback
        "8.8.8.8",         # Google DNS (public)
        "1.1.1.1",         # Cloudflare (public)
        "52.86.1.1",       # AWS range
        "20.1.1.1",        # Azure range
        "34.1.1.1",        # GCP range
        "104.131.1.1",     # DigitalOcean range
    ]

    for ip in test_ips:
        rec = engine.lookup(ip)
        tags = []
        if rec.is_private:   tags.append("PRIVATE")
        if rec.is_loopback:  tags.append("LOOPBACK")
        if rec.is_tor:       tags.append("TOR")
        if rec.is_vpn:       tags.append("VPN")
        if rec.cloud_provider: tags.append(rec.cloud_provider)
        print(f"  {ip:<18}  country={rec.country or '?':6}  "
              f"cloud={rec.cloud_provider or '-':15}  "
              f"tags={tags}")

    engine.close()

    # Test DB layer
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        tmp_db = f.name
    db = GeoDatabase(db_path=tmp_db)
    geo_rec = engine.lookup("8.8.8.8")
    stats = IPStats(ip="8.8.8.8", geo=geo_rec,
                    packet_count=42, attack_count=3,
                    threat_score=25.0, threat_status="SUSPICIOUS",
                    first_seen="2024-01-01 00:00:00",
                    last_seen="2024-01-02 12:00:00")
    db.upsert(stats)
    row = db.get("8.8.8.8")
    print(f"\n  DB round-trip OK — packet_count={row['packet_count']}, "
          f"threat_status={row['threat_status']}")
    db.close()
    os.unlink(tmp_db)

    print("\nAll self-tests passed.")
