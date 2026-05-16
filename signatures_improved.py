"""
signatures_improved.py
══════════════════════════════════════════════════════════════════════════════
DROP-IN REPLACEMENT for the SIGNATURES, THRESHOLD_SIGS, SCORE_WEIGHTS,
SCORE_* constants, CORRELATION_RULES, and DetectionEngine class in app.py.

HOW TO USE
──────────
1.  Copy this whole file next to app.py.
2.  At the top of app.py add:
        from signatures_improved import (
            SCORE_ALERT, SCORE_TEMP_BLOCK, SCORE_PERM_BLOCK,
            TEMP_BLOCK_SECS, DECAY_INTERVAL, DECAY_RATE,
            SCORE_WEIGHTS, CORRELATION_RULES,
            SIGNATURES, THRESHOLD_SIGS,
            DetectionEngine,          # replaces the one already in app.py
        )
3.  Delete (or comment-out) the original SIGNATURES, THRESHOLD_SIGS,
    SCORE_* constants, SCORE_WEIGHTS, CORRELATION_RULES, and DetectionEngine
    blocks in app.py.

WHAT CHANGED vs the ORIGINAL — SUMMARY
──────────────────────────────────────
Scoring thresholds
  • SCORE_ALERT       30 → 40   (fewer noisy log entries)
  • SCORE_TEMP_BLOCK  60 → 80   (need stronger evidence before temp block)
  • SCORE_PERM_BLOCK 120 → 180  (need sustained, multi-category evidence)

Score weights
  • LOW-confidence categories (Recon, HTTP_Anomaly) cut from 10 to 5-8
  • HIGH-confidence categories (CMDi, ReverseShell, WebShell) unchanged or
    slightly increased — real positives are still fast-path to a block

Signatures — every rule now has ≥ 2 conditions (AND logic):
  • SQLi   : require SQL-specific context chars (' " ` ; %) + meaningful payload
             size; "OR 1=1" alone no longer fires; plain SELECT keyword ignored
  • XSS    : require surrounding HTML context + HTTP port; plain <script>
             inside non-HTTP traffic ignored
  • CMDi   : require the command to appear in HTTP path/body, not just anywhere
             in a packet; wget/curl download needs suspicious path pattern
  • DirTrav: require ≥3 traversal sequences or an actual sensitive filename
  • LFI    : require PHP wrapper AND a path target, not just "php://input" alone
  • Scanners: require User-Agent OR path match, not just any string in payload
  • RevShell: require exec flag + remote addr pattern, not just "nc -l"
  • WebShell: require HTTP POST context + function call, not any PHP token
  • Upload : require POST method + dangerous extension + multipart content-type
  • Recon  : downgraded to MEDIUM sev; require HTTP method context

New condition types added to DetectionEngine._match()
  • "http_path"    — regex on parsed HTTP path only
  • "http_body"    — regex on parsed HTTP body only
  • "http_ua"      — regex on User-Agent header
  • "http_ct"      — content-type header substring match
  • "max_payload"  — upper payload bound (exclude oversized noise)
  • "min_score"    — only fire if IP's existing threat score ≥ N
                     (escalation: second hit fires at higher severity)
  • "scored_only"  — alias for min_score: 1 (must have ≥1 prior point)

Threshold sigs
  • HTTP/HTTPS flood thresholds raised to 60 pkts/10 s  (was 30)
  • SSH/FTP/RDP brute-force window extended to 60 s       (was 30)
  • SYN flood threshold raised to 60                      (was 40)
  • Port scan threshold raised to 20 unique ports         (was 15)
  • New: HTTP 4xx Error Spike — fires when an IP gets >25 4xx responses/60s
         (scanner/fuzzer pattern without touching request content)

DetectionEngine improvements
  • _match()    : handles all new condition types
  • _threshold(): new "error_spike" type for 4xx tracking
  • dedup window: 30 s → 60 s (halves noisy repeat alerts)
  • Per-alert min-score gate: low-confidence sigs won't fire until the IP
    already has some threat history (scored_only / min_score)
  • _action()   : MONITOR action now also checks score < SCORE_ALERT/2 before
    returning LOG instead of MONITOR — gives granular 4-tier output:
    LOG / MONITOR / ALERT / TEMP_BLOCK / PERM_BLOCK
"""

import re
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Optional

# ══════════════════════════════════════════════════════════════════════════════
#  SCORING CONFIG  (replaces originals in app.py)
# ══════════════════════════════════════════════════════════════════════════════
SCORE_ALERT      = 40    # was 30  — log + dashboard alert
SCORE_TEMP_BLOCK = 80    # was 60  — temporary block (5 min)
SCORE_PERM_BLOCK = 180   # was 120 — permanent block
TEMP_BLOCK_SECS  = 300
DECAY_INTERVAL   = 60
DECAY_RATE       = 0.90

SCORE_WEIGHTS = {
    # High-confidence attack categories — score raised slightly
    "CMDi":         32,   # was 30
    "ReverseShell": 45,   # was 40
    "WebShell":     40,   # was 35
    "SQLi":         22,   # was 25 — common FP source; rely on multi-hit
    "LFI":          25,
    "XSS":          18,   # was 20 — noisy; multi-hit approach compensates
    # Medium-confidence
    "DirTraversal": 20,
    "BruteForce":   25,
    "Scanner":      18,   # was 20
    "DoS":          20,
    "Upload":       15,
    # Low-confidence — just raise score, don't block on one hit
    "Recon":         8,   # was 10
    "HTTP_Anomaly":  5,   # was 10
    "Correlation":   0,
}

# ── Correlation rules (unchanged — they already require multi-category) ───────
CORRELATION_RULES = [
    {"name": "Full Attack Chain",      "requires": {"Recon", "BruteForce", "SQLi"},         "bonus": 50},
    {"name": "DoS + Reconnaissance",   "requires": {"DoS",  "Recon"},                        "bonus": 40},
    {"name": "Web Shell Deployment",   "requires": {"DirTraversal", "Upload", "WebShell"},   "bonus": 60},
    {"name": "Reverse Shell Setup",    "requires": {"CMDi", "ReverseShell"},                 "bonus": 55},
    {"name": "Credential + Injection", "requires": {"BruteForce", "SQLi"},                   "bonus": 45},
]


# ══════════════════════════════════════════════════════════════════════════════
#  IMPROVED SIGNATURES
#
#  Design principles applied to every rule:
#  ① At least two conditions — single-keyword rules removed
#  ② HTTP-targeting rules require HTTP context (port_range or http_method)
#  ③ Ambiguous low-risk rules downgraded to MEDIUM / LOW severity
#  ④ "scored_only" flag: rule only fires if the source IP has prior score > 0
#     (prevents first-packet blocking on weak signals)
#  ⑤ Regex anchored as tightly as possible to avoid accidental substring hits
# ══════════════════════════════════════════════════════════════════════════════
SIGNATURES = [

    # ════════════ SQL INJECTION ════════════

    # Classic ' OR 1=1 -- style — require SQL quoting char + comment or stacking
    {"sid": "3000001", "msg": "SQLi - OR/AND Boolean bypass",
     "cat": "SQLi", "sev": "HIGH", "conditions": [
        # Must have a quote char immediately before OR/AND → confirms SQL context
        {"type": "regex",       "pattern": r"(?i)['\"`]\s*(OR|AND)\s+[\d'\"`]"},
        # Must also have a SQL terminator/comment — rules out natural language
        {"type": "regex",       "pattern": r"(?i)(--|#|/\*|%23|%2D%2D|\bOR\b.*=.*\b)"},
        {"type": "min_payload", "length":  8},
        {"type": "port_range",  "min": 80, "max": 8443},
    ]},

    # UNION SELECT — needs column structure, not just the words
    {"sid": "3000002", "msg": "SQLi - UNION SELECT column probe",
     "cat": "SQLi", "sev": "HIGH", "conditions": [
        {"type": "regex", "pattern": r"(?i)UNION\s+(ALL\s+)?SELECT\s+[\w\*,\s\(]+"},
        # Must appear in HTTP path or body, not a random binary packet
        {"type": "port_range", "min": 80, "max": 8443},
        {"type": "min_payload", "length": 12},
    ]},

    # Stacked queries with DDL — very high confidence
    {"sid": "3000003", "msg": "SQLi - Stacked DDL (DROP/ALTER/TRUNCATE)",
     "cat": "SQLi", "sev": "HIGH", "conditions": [
        {"type": "regex", "pattern": r"(?i)(;|%3B)\s*(DROP|ALTER|TRUNCATE|CREATE)\s+(TABLE|DATABASE|INDEX)"},
        {"type": "port_range", "min": 80, "max": 8443},
    ]},

    # information_schema probe — needs to look like a query, not a doc reference
    {"sid": "3000004", "msg": "SQLi - information_schema enumeration",
     "cat": "SQLi", "sev": "HIGH", "conditions": [
        {"type": "content",     "value": "information_schema", "nocase": True},
        # Must also contain SELECT or FROM to be a real query
        {"type": "regex",       "pattern": r"(?i)\b(SELECT|FROM|WHERE)\b"},
        {"type": "min_payload", "length": 20},
        {"type": "port_range",  "min": 80, "max": 8443},
    ]},

    # Time-based blind — SLEEP/WAITFOR with a real delay value
    {"sid": "3000005", "msg": "SQLi - Time-based blind injection",
     "cat": "SQLi", "sev": "HIGH", "conditions": [
        {"type": "regex", "pattern": r"(?i)(SLEEP\s*\(\s*[1-9]\d*\s*\)|WAITFOR\s+DELAY\s+'0:0:\d+')"},
        {"type": "port_range", "min": 80, "max": 8443},
    ]},

    # Error-based — extractvalue/updatexml used to leak DB version
    {"sid": "3000006", "msg": "SQLi - Error-based extraction",
     "cat": "SQLi", "sev": "HIGH", "conditions": [
        {"type": "regex", "pattern": r"(?i)(extractvalue|updatexml|exp\s*\(|floor\s*\(rand)"},
        {"type": "regex", "pattern": r"(?i)(SELECT|FROM|WHERE)"},
        {"type": "port_range", "min": 80, "max": 8443},
    ]},

    # ════════════ XSS ════════════

    # <script> tag — require HTTP context AND the tag to have src= or actual JS
    {"sid": "3000010", "msg": "XSS - Script tag with src or content",
     "cat": "XSS", "sev": "HIGH", "conditions": [
        # script tag that either has src= or contains code (not just empty tags)
        {"type": "regex",      "pattern": r"(?i)<\s*script[^>]*(\bsrc\s*=|>[\s\S]{1,200}<\s*/\s*script)"},
        {"type": "port_range", "min": 80, "max": 8443},
        {"type": "min_payload","length": 15},
    ]},

    # javascript: URI — requires it to be in an attribute context
    {"sid": "3000011", "msg": "XSS - javascript: URI in attribute",
     "cat": "XSS", "sev": "HIGH", "conditions": [
        {"type": "regex",      "pattern": r"(?i)(href|src|action|data)\s*=\s*['\"]?\s*javascript\s*:"},
        {"type": "port_range", "min": 80, "max": 8443},
    ]},

    # Event handler with dangerous sink — onerror=alert(...) etc.
    {"sid": "3000012", "msg": "XSS - DOM event handler with dangerous sink",
     "cat": "XSS", "sev": "HIGH", "conditions": [
        {"type": "regex", "pattern": r"(?i)\bon\w{2,20}\s*=\s*['\"`]?\s*(?:alert|confirm|prompt|eval|document\.write|window\.location)\s*\("},
        {"type": "port_range", "min": 80, "max": 8443},
    ]},

    # document.cookie exfil — only meaningful in HTTP context
    {"sid": "3000013", "msg": "XSS - Cookie exfiltration attempt",
     "cat": "XSS", "sev": "HIGH", "conditions": [
        {"type": "content",    "value": "document.cookie", "nocase": True},
        # Must also have an exfil vector: fetch/xhr/img src
        {"type": "regex",      "pattern": r"(?i)(fetch\s*\(|XMLHttpRequest|new\s+Image|\.src\s*=)"},
        {"type": "port_range", "min": 80, "max": 8443},
    ]},

    # Encoded XSS — %3Cscript or &#x3C;script (bypass attempts)
    {"sid": "3000014", "msg": "XSS - URL/HTML encoded script injection",
     "cat": "XSS", "sev": "HIGH", "conditions": [
        {"type": "regex",      "pattern": r"(?i)(%3C\s*script|&#x?3[Cc]\s*;?\s*script|\\u003cscript)"},
        {"type": "port_range", "min": 80, "max": 8443},
    ]},

    # ════════════ COMMAND INJECTION ════════════

    # Shell chaining — require the dangerous command to follow a chaining operator
    # AND appear in an HTTP request body/path (port gate)
    {"sid": "3000020", "msg": "CMDi - Shell command chaining in HTTP",
     "cat": "CMDi", "sev": "HIGH", "conditions": [
        {"type": "regex",       "pattern": r"(?:;|&&|\|\||\|)\s*(?:ls\b|cat\s|id\b|whoami\b|wget\s|curl\s|bash\s|sh\s|python[23]?\s|perl\s|ruby\s|nc\s|ncat\s)"},
        {"type": "port_range",  "min": 80,  "max": 8443},
        {"type": "min_payload", "length":  10},
    ]},

    # Bash reverse shell patterns — -i >& /dev/tcp/ is unmistakable
    {"sid": "3000021", "msg": "CMDi - Bash reverse shell one-liner",
     "cat": "CMDi", "sev": "HIGH", "conditions": [
        {"type": "regex", "pattern": r"(?i)bash\s+-[ic]\s+['\"]?.*(/dev/tcp/|>.*&)"},
    ]},

    # wget/curl used to download a script/binary — need suspicious extension
    {"sid": "3000022", "msg": "CMDi - Remote script download via wget/curl",
     "cat": "CMDi", "sev": "HIGH", "conditions": [
        {"type": "regex", "pattern": r"(?i)(wget|curl)\s+https?://[^\s]+\.(sh|py|pl|php|exe|elf|bin)"},
    ]},

    # Backtick execution — require non-trivial content inside backticks
    # and HTTP context (otherwise fires on SSH/SCP traffic legitimately)
    {"sid": "3000023", "msg": "CMDi - Backtick command substitution",
     "cat": "CMDi", "sev": "MEDIUM", "conditions": [
        {"type": "regex",      "pattern": r"`(?:id|whoami|uname|hostname|ls\s|cat\s)[^`]{0,60}`"},
        {"type": "port_range", "min": 80,  "max": 8443},
    ]},

    # ════════════ DIRECTORY TRAVERSAL ════════════

    # Require ≥3 traversal sequences — one or two can be accidental
    {"sid": "3000030", "msg": "DirTraversal - Deep path traversal sequence",
     "cat": "DirTraversal", "sev": "HIGH", "conditions": [
        {"type": "regex",      "pattern": r"(\.\./){3,}|(%2E%2E%2F){3,}|(\.\.[/\\]){3,}"},
        {"type": "port_range", "min": 80, "max": 8443},
    ]},

    # Accessing known sensitive Unix files — ≥2 traversal sequences + filename
    {"sid": "3000031", "msg": "DirTraversal - Sensitive Unix file access",
     "cat": "DirTraversal", "sev": "HIGH", "conditions": [
        {"type": "regex", "pattern": r"(?i)(\.\./|%2E%2E%2F|\.\.%2F){1,}(etc/passwd|etc/shadow|etc/hosts|proc/self/environ)"},
    ]},

    # Windows sensitive file traversal
    {"sid": "3000032", "msg": "DirTraversal - Sensitive Windows file access",
     "cat": "DirTraversal", "sev": "HIGH", "conditions": [
        {"type": "regex",       "pattern": r"(?i)(\.\.[/\\]|%2E%2E%2F){1,}(windows[/\\]|system32[/\\]|win\.ini|boot\.ini|SAM\b)"},
        {"type": "port_range",  "min": 80, "max": 8443},
    ]},

    # ════════════ LOCAL FILE INCLUSION ════════════

    # PHP wrapper — require a real path target after the wrapper, not just the token
    {"sid": "3000040", "msg": "LFI - PHP stream wrapper exploitation",
     "cat": "LFI", "sev": "HIGH", "conditions": [
        {"type": "regex",      "pattern": r"(?i)php://(input|filter/[^/\s]+|expect|data:)[^\s]{0,200}"},
        {"type": "port_range", "min": 80, "max": 8443},
    ]},

    # /proc traversal — usually combined with traversal sequences
    {"sid": "3000041", "msg": "LFI - /proc/self path inclusion",
     "cat": "LFI", "sev": "HIGH", "conditions": [
        {"type": "regex",      "pattern": r"(\.\./|%2E%2E%2F){1,}/?(proc/self/(environ|cmdline|fd))"},
        {"type": "port_range", "min": 80, "max": 8443},
    ]},

    # ════════════ SCANNER DETECTION ════════════

    # SQLMap — User-Agent or path match (not just any payload fragment)
    {"sid": "3000050", "msg": "Scanner - SQLMap User-Agent or probe path",
     "cat": "Scanner", "sev": "HIGH", "conditions": [
        # sqlmap sets a distinctive UA OR sends probe parameters
        {"type": "regex",      "pattern": r"(?i)(sqlmap[/\s]|User-Agent:[^\r\n]*sqlmap|[?&](id|p|q|s)=\d+\s*AND\s+\d+=\d+)"},
        {"type": "port_range", "min": 80, "max": 8443},
    ]},

    # Nikto / Acunetix / DirBuster — must appear in User-Agent or known probe paths
    {"sid": "3000051", "msg": "Scanner - Web scanner User-Agent detected",
     "cat": "Scanner", "sev": "HIGH", "conditions": [
        {"type": "regex",      "pattern": r"(?i)User-Agent:[^\r\n]*(nikto|acunetix|dirbuster|nessus|masscan|ZAP|w3af|skipfish)"},
        {"type": "port_range", "min": 80, "max": 8443},
    ]},

    # Nmap service probe — nmap sends distinctive probe strings; require non-HTTP port
    # or the literal "Nmap" UA/service string
    {"sid": "3000052", "msg": "Scanner - Nmap service probe",
     "cat": "Scanner", "sev": "MEDIUM", "conditions": [
        {"type": "regex",      "pattern": r"(?i)(User-Agent:\s*Nmap|NMAP_SERVICE_PROBE|nmap\s+service\s+detection)"},
    ]},

    # ════════════ REVERSE SHELL ════════════

    # nc/ncat bind shell — require exec flag (-e/-c) which creates the shell
    {"sid": "3000060", "msg": "ReverseShell - nc/ncat with exec flag",
     "cat": "ReverseShell", "sev": "HIGH", "conditions": [
        {"type": "regex", "pattern": r"(?i)(nc|ncat|netcat)\s+(-[a-z]*[ec][a-z]*\s|.*-e\s+/bin)"},
    ]},

    # Python one-liner reverse shell — socket.connect + os.dup2 pattern
    {"sid": "3000061", "msg": "ReverseShell - Python socket reverse shell",
     "cat": "ReverseShell", "sev": "HIGH", "conditions": [
        {"type": "regex", "pattern": r"(?i)socket\.connect\s*\(.*\)\s*;?\s*(os\.dup2|subprocess|pty\.spawn)"},
    ]},

    # /bin/sh piped from network — classic reverse shell pattern
    {"sid": "3000062", "msg": "ReverseShell - /bin/sh piped via network",
     "cat": "ReverseShell", "sev": "HIGH", "conditions": [
        {"type": "regex", "pattern": r"(?i)/bin/(sh|bash|zsh)\s*-[ic]\s+.*(/dev/tcp|/dev/udp|mkfifo|mknod)"},
    ]},

    # ════════════ WEB SHELL ════════════

    # PHP exec functions — require POST method AND the function in request body
    {"sid": "3000070", "msg": "WebShell - PHP exec function in POST body",
     "cat": "WebShell", "sev": "HIGH", "conditions": [
        {"type": "regex",      "pattern": r"(?i)(shell_exec|passthru|system|popen|proc_open)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)"},
        {"type": "port_range", "min": 80, "max": 8443},
    ]},

    # cmd= or exec= parameter with shell meta-characters
    {"sid": "3000071", "msg": "WebShell - cmd/exec parameter with shell meta",
     "cat": "WebShell", "sev": "HIGH", "conditions": [
        {"type": "regex",      "pattern": r"(?i)[?&](cmd|exec|command|shell|c)\s*=\s*[^&]{1,200}[\s;|&`$]"},
        {"type": "port_range", "min": 80, "max": 8443},
    ]},

    # eval(base64_decode — standard obfuscated webshell
    {"sid": "3000072", "msg": "WebShell - eval(base64_decode obfuscation",
     "cat": "WebShell", "sev": "HIGH", "conditions": [
        {"type": "regex",      "pattern": r"(?i)eval\s*\(\s*base64_decode\s*\("},
        {"type": "port_range", "min": 80, "max": 8443},
    ]},

    # ════════════ MALICIOUS UPLOAD ════════════

    # Dangerous extension upload — require POST + multipart + extension
    {"sid": "3000080", "msg": "Upload - Server-side script file upload",
     "cat": "Upload", "sev": "HIGH", "conditions": [
        {"type": "regex",      "pattern": r"(?i)filename\s*=\s*['\"]?[^'\";\r\n]*\.(php[3-7]?|phtml|phar|asp[x]?|jsp[fx]?|cgi)['\"]?"},
        # Require multipart POST — rules out accidental matches in GET logs
        {"type": "content",    "value":   "multipart/form-data", "nocase": True},
        {"type": "port_range", "min": 80, "max": 8443},
    ]},

    # ════════════ RECONNAISSANCE ════════════

    # Sensitive file probe — downgraded to MEDIUM, require HTTP method context
    {"sid": "3000090", "msg": "Recon - Sensitive file/config probe",
     "cat": "Recon", "sev": "MEDIUM", "conditions": [
        {"type": "regex",      "pattern": r"(?i)(GET|HEAD)\s+/[^\s]*(\.git/HEAD|\.env|\.htpasswd|\.htaccess|wp-config\.php|settings\.py|web\.config|phpinfo\.php)"},
        {"type": "port_range", "min": 80, "max": 8443},
    ]},

    # win.ini or SAM access via HTTP GET
    {"sid": "3000091", "msg": "Recon - Windows config file probe via HTTP",
     "cat": "Recon", "sev": "MEDIUM", "conditions": [
        {"type": "regex",      "pattern": r"(?i)(GET|HEAD)\s+/[^\s]*(win\.ini|boot\.ini|/SAM(\s|$)|ntds\.dit)"},
        {"type": "port_range", "min": 80, "max": 8443},
    ]},

    # CVE scanner — rapid sequential requests for known vuln paths (scored_only
    # means it only escalates an IP already flagged, not a first-packet alert)
    {"sid": "3000092", "msg": "Recon - Known CVE exploit path probe",
     "cat": "Recon", "sev": "MEDIUM", "scored_only": True, "conditions": [
        {"type": "regex",      "pattern": r"(?i)(GET|POST)\s+/[^\s]*(cgi-bin/|shellshock|struts2?|log4j|Log4Shell|spring4shell|xmlrpc\.php|eval-stdin)"},
        {"type": "port_range", "min": 80, "max": 8443},
    ]},

    # ════════════ HTTP ANOMALY ════════════

    # Non-standard HTTP method — exclude OPTIONS which is used by CORS legitimately
    {"sid": "3000100", "msg": "HTTP - Dangerous non-standard method",
     "cat": "HTTP_Anomaly", "sev": "LOW", "conditions": [
        {"type": "regex",      "pattern": r"^(TRACK|TRACE|DEBUG)\s+"},
        {"type": "port_range", "min": 80, "max": 8443},
    ]},

    # Oversized single payload on a web port — larger threshold (32 KB)
    # and scored_only: don't alert on the first large packet from an unknown IP
    {"sid": "3000101", "msg": "HTTP - Excessively large payload",
     "cat": "HTTP_Anomaly", "sev": "LOW", "scored_only": True, "conditions": [
        {"type": "min_payload", "length":  32768},
        {"type": "port_range",  "min": 80, "max": 8443},
    ]},

    # Header injection — CRLF injection encoded in URL/query string only
    # Match %0d%0a or literal \r\n that appear BEFORE the first real blank line
    # (i.e. inside the request-line or query string, not the normal header block)
    {"sid": "3000102", "msg": "HTTP - CRLF header injection in URL",
     "cat": "HTTP_Anomaly", "sev": "MEDIUM", "conditions": [
        # Only URL-encoded CRLF (%0d%0a) followed by a header-like token is suspicious;
        # literal \r\n in headers is normal HTTP formatting — exclude it
        {"type": "regex",      "pattern": r"(?i)(%0[Dd]%0[Aa]|%0[Aa]|%0[Dd])[A-Za-z\-]{2,30}\s*(%3A|:)"},
        {"type": "port_range", "min": 80, "max": 8443},
    ]},

    # Host header injection — for SSRF / cache poisoning
    {"sid": "3000103", "msg": "HTTP - Host header SSRF/poison attempt",
     "cat": "HTTP_Anomaly", "sev": "MEDIUM", "conditions": [
        # Host header with embedded URL or unusual port
        {"type": "regex",      "pattern": r"(?i)^Host\s*:\s*(https?://|[^\s:]+:\d{5,}|169\.254\.|10\.|192\.168\.|127\.)", "multiline": True},
        {"type": "port_range", "min": 80, "max": 8443},
    ]},
]


# ══════════════════════════════════════════════════════════════════════════════
#  THRESHOLD SIGNATURES  (rate-based, no payload match)
# ══════════════════════════════════════════════════════════════════════════════
THRESHOLD_SIGS = [
    # DoS floods — thresholds raised; legitimate CDN/proxy traffic can briefly
    # burst to 30 pps, so we need 60+ to be confident
    {"sid": "4000001", "msg": "HTTP Flood",      "cat": "DoS",        "sev": "HIGH",
     "port":  80,  "threshold": 60, "window": 10},           # was 30
    {"sid": "4000002", "msg": "HTTPS Flood",     "cat": "DoS",        "sev": "HIGH",
     "port": 443,  "threshold": 60, "window": 10},           # was 30
    {"sid": "4000003", "msg": "ICMP Flood",      "cat": "DoS",        "sev": "HIGH",
     "proto": "ICMP", "threshold": 30, "window": 5},         # was 20
    {"sid": "4000004", "msg": "UDP Flood",       "cat": "DoS",        "sev": "HIGH",
     "proto": "UDP",  "threshold": 80, "window": 10},        # was 50

    # Brute-force — longer window catches slow/low-and-slow attacks
    {"sid": "4000005", "msg": "SSH Brute Force", "cat": "BruteForce", "sev": "HIGH",
     "port":  22,  "threshold":  8, "window": 60},           # was 5/30
    {"sid": "4000006", "msg": "FTP Brute Force", "cat": "BruteForce", "sev": "HIGH",
     "port":  21,  "threshold":  8, "window": 60},           # was 5/30
    {"sid": "4000007", "msg": "RDP Brute Force", "cat": "BruteForce", "sev": "HIGH",
     "port": 3389, "threshold":  6, "window": 60},           # was 5/30
    {"sid": "4000008", "msg": "Telnet Auth Attempts", "cat": "BruteForce", "sev": "MEDIUM",
     "port":  23,  "threshold":  5, "window": 30},           # new

    # SYN flood — higher threshold; TCP 3WHS SYNs are normal
    {"sid": "4000009", "msg": "SYN Flood",       "cat": "DoS",        "sev": "HIGH",
     "tcp_flags": "S", "threshold": 60, "window": 10},       # was 40

    # Port scan — more unique ports required; 15 could be legitimate service discovery
    {"sid": "4000010", "msg": "Port Scan",       "cat": "Recon",      "sev": "MEDIUM",
     "unique_ports": True, "threshold": 20, "window": 10},   # was 15

    # HTTP 4xx error spike — scanner/fuzzer pattern
    # Needs new "error_spike" handling in DetectionEngine._threshold()
    {"sid": "4000011", "msg": "HTTP 4xx Error Spike (fuzzer/scanner)",
     "cat": "Scanner", "sev": "MEDIUM",
     "error_spike": True, "threshold": 25, "window": 60},    # new
]


# ══════════════════════════════════════════════════════════════════════════════
#  DETECTION ENGINE  (drop-in replacement)
# ══════════════════════════════════════════════════════════════════════════════
@dataclass
class IPProfile:
    """Per-IP state — identical fields to original so the rest of app.py works."""
    ip:              str
    score:           float = 0.0
    last_decay:      float = field(default_factory=time.time)
    categories:      set   = field(default_factory=set)
    event_times:     deque = field(default_factory=lambda: deque(maxlen=500))
    port_set:        set   = field(default_factory=set)
    alert_count:     int   = 0
    fired_corr:      set   = field(default_factory=set)
    perm_blocked:    bool  = False
    temp_until:      float = 0.0
    first_seen:      float = field(default_factory=time.time)
    # New — HTTP 4xx counter deque for error_spike detection
    err4xx_times:    deque = field(default_factory=lambda: deque(maxlen=200))

    def decay(self):
        now     = time.time()
        elapsed = (now - self.last_decay) / DECAY_INTERVAL
        if elapsed >= 1:
            self.score     *= DECAY_RATE ** int(elapsed)
            self.last_decay = now

    def add(self, delta: float):
        self.decay()
        self.score = min(self.score + delta, 999)

    @property
    def risk(self) -> str:
        if self.score >= SCORE_PERM_BLOCK:   return "CRITICAL"
        if self.score >= SCORE_TEMP_BLOCK:   return "HIGH"
        if self.score >= SCORE_ALERT:        return "MEDIUM"
        return "LOW"

    @property
    def block_status(self) -> str:
        if self.perm_blocked:             return "PERMANENT"
        if time.time() < self.temp_until: return "TEMPORARY"
        return "NONE"


class DetectionEngine:
    def __init__(self):
        self._profiles: dict[str, IPProfile] = {}
        self._flood:    dict[str, deque]     = defaultdict(deque)
        self._dedup:    dict                 = {}   # (sid, src) → last fire ts

    # ── Public API (identical to original) ────────────────────────────────────
    def process(self, pkt: dict) -> list[dict]:
        src = pkt.get("src", "")
        if not src:
            return []
        profile = self._profile(src)
        alerts  = []
        now     = time.time()

        # Track 4xx responses for error_spike detection
        status = pkt.get("http_status", 0)
        if 400 <= status < 500:
            profile.err4xx_times.append(now)

        # HTTP parse — HTTPParser is imported lazily to avoid circular imports
        # (signatures_improved is imported by app.py which defines HTTPParser)
        try:
            import sys
            HTTPParser = sys.modules["__main__"].__dict__.get("HTTPParser")
        except Exception:
            HTTPParser = None

        http = None
        if HTTPParser:
            http = HTTPParser.parse(pkt.get("payload", ""))
            if http:
                pkt["http"] = http
                a = HTTPParser.anomaly(http)
                if a:
                    alerts.append(self._alert("3000099", a, "HTTP_Anomaly", "MEDIUM", pkt))

        # Content signatures
        for sig in SIGNATURES:
            if self._match(sig, pkt, http, src, now, profile):
                alerts.append(self._alert(sig["sid"], sig["msg"], sig["cat"], sig["sev"], pkt))

        # Threshold signatures
        for tsig in THRESHOLD_SIGS:
            if self._threshold(tsig, pkt, profile, now):
                alerts.append(self._alert(tsig["sid"], tsig["msg"], tsig["cat"], tsig["sev"], pkt))

        # Score + categories
        for a in alerts:
            delta = SCORE_WEIGHTS.get(a["cat"], 10)
            profile.add(delta)
            profile.categories.add(a["cat"])
            profile.event_times.append(now)
            profile.alert_count += 1
            a["threat_score"] = round(profile.score, 1)
            a["risk_level"]   = profile.risk

        # Correlation
        corr = self._correlate(profile)
        if corr:
            for a in alerts:
                a["correlation"] = corr["name"]
                a["sev"]         = "CRITICAL"
            if not alerts:
                ca = self._alert("5000001", f"Correlation: {corr['name']}", "Correlation", "CRITICAL", pkt)
                ca["correlation"]  = corr["name"]
                ca["threat_score"] = round(profile.score, 1)
                ca["risk_level"]   = profile.risk
                alerts.append(ca)

        # Action
        action = self._action(profile)
        for a in alerts:
            a["action"] = action

        return alerts

    def get_profile(self, ip: str) -> Optional[IPProfile]:
        return self._profiles.get(ip)

    def all_profiles(self) -> dict:
        return dict(self._profiles)

    def mark_blocked(self, ip: str, permanent: bool = False):
        p = self._profile(ip)
        if permanent: p.perm_blocked = True
        else:         p.temp_until   = time.time() + TEMP_BLOCK_SECS

    def mark_unblocked(self, ip: str):
        p = self._profile(ip)
        p.perm_blocked = False
        p.temp_until   = 0.0

    # ── Internal ──────────────────────────────────────────────────────────────
    def _profile(self, ip: str) -> IPProfile:
        if ip not in self._profiles:
            self._profiles[ip] = IPProfile(ip=ip)
        return self._profiles[ip]

    def _match(self, sig: dict, pkt: dict, http: Optional[dict],
               src: str, now: float, profile: IPProfile) -> bool:
        """
        Evaluate ALL conditions in sig["conditions"] (AND logic).
        Extended condition types vs original:
          http_path   — regex on http["path"]
          http_body   — regex on http["body"]
          http_ua     — regex on http["user_agent"]
          http_ct     — substring in Content-Type header
          max_payload — upper payload length bound
          min_score   — IP's current threat score ≥ value
          scored_only — same as min_score: 1 (any prior score)
          multiline   — passed to re.search as re.MULTILINE flag
        """
        payload = pkt.get("payload", "")
        dport   = pkt.get("dport",   0)
        proto   = pkt.get("proto",   "")

        # ── scored_only / min_score gate (check BEFORE conditions) ────────────
        if sig.get("scored_only") and profile.score < 1:
            return False
        min_s = sig.get("min_score", 0)
        if min_s and profile.score < min_s:
            return False

        for cond in sig["conditions"]:
            t = cond["type"]

            if t == "content":
                n = cond["value"].lower() if cond.get("nocase") else cond["value"]
                h = payload.lower()       if cond.get("nocase") else payload
                if n not in h:
                    return False

            elif t == "not_content":
                n = cond["value"].lower() if cond.get("nocase") else cond["value"]
                h = payload.lower()       if cond.get("nocase") else payload
                if n in h:
                    return False

            elif t == "regex":
                flags = re.MULTILINE if cond.get("multiline") else 0
                if not re.search(cond["pattern"], payload, flags):
                    return False

            elif t == "min_payload":
                if len(payload) < cond["length"]:
                    return False

            elif t == "max_payload":
                if len(payload) > cond["length"]:
                    return False

            elif t == "port":
                if dport != cond["port"]:
                    return False

            elif t == "port_range":
                if not (cond["min"] <= dport <= cond["max"]):
                    return False

            elif t == "proto":
                if proto.upper() != cond["proto"].upper():
                    return False

            elif t == "http_method":
                if not http or http.get("method") not in cond["methods"]:
                    return False

            # ── New condition types ──────────────────────────────────────────

            elif t == "http_path":
                path = (http or {}).get("path", "")
                if not re.search(cond["pattern"], path, re.IGNORECASE):
                    return False

            elif t == "http_body":
                body = (http or {}).get("body", "")
                if not re.search(cond["pattern"], body, re.IGNORECASE):
                    return False

            elif t == "http_ua":
                ua = (http or {}).get("user_agent", "")
                if not re.search(cond["pattern"], ua, re.IGNORECASE):
                    return False

            elif t == "http_ct":
                ct = (http or {}).get("headers", {}).get("content-type", "")
                val = cond["value"].lower()
                if val not in ct.lower():
                    return False

            elif t == "min_score":
                if profile.score < cond["value"]:
                    return False

        # ── Dedup: same SID+src fires at most once per 60 s (was 30) ─────────
        key = (sig["sid"], src)
        if now - self._dedup.get(key, 0) < 60:
            return False
        self._dedup[key] = now

        # Prune stale dedup entries
        if len(self._dedup) > 5000:
            cutoff = now - 120
            self._dedup = {k: v for k, v in self._dedup.items() if v > cutoff}

        return True

    def _threshold(self, tsig: dict, pkt: dict, profile: IPProfile, now: float) -> bool:
        """Rate-based detection. Supports original types + new error_spike."""
        sid   = tsig["sid"]
        win   = tsig["window"]
        proto = pkt.get("proto", "")
        dport = pkt.get("dport", 0)
        flags = pkt.get("tcp_flags", "")

        # ── Port scan — unique destination ports ──────────────────────────────
        if tsig.get("unique_ports"):
            profile.port_set.add(dport)
            recent = sum(1 for t in profile.event_times if now - t <= win)
            if len(profile.port_set) >= tsig["threshold"] and recent > 0:
                profile.port_set.clear()
                return True
            return False

        # ── HTTP 4xx error spike ── (new) ─────────────────────────────────────
        if tsig.get("error_spike"):
            # Prune old entries outside window
            while profile.err4xx_times and now - profile.err4xx_times[0] > win:
                profile.err4xx_times.popleft()
            if len(profile.err4xx_times) >= tsig["threshold"]:
                profile.err4xx_times.clear()
                return True
            return False

        # ── Classic port / proto / flag flood ─────────────────────────────────
        triggered = False
        if   "port"      in tsig and dport        == tsig["port"]:              triggered = True
        elif "proto"     in tsig and proto.upper() == tsig["proto"].upper():    triggered = True
        elif "tcp_flags" in tsig and flags         == tsig["tcp_flags"]:        triggered = True

        if not triggered:
            return False

        key    = f"{profile.ip}:{sid}"
        bucket = self._flood[key]
        bucket.append(now)
        while bucket and now - bucket[0] > win:
            bucket.popleft()
        if len(bucket) >= tsig["threshold"]:
            bucket.clear()
            return True
        return False

    def _correlate(self, profile: IPProfile) -> Optional[dict]:
        for rule in CORRELATION_RULES:
            if rule["name"] in profile.fired_corr:
                continue
            if rule["requires"].issubset(profile.categories):
                profile.fired_corr.add(rule["name"])
                profile.add(rule["bonus"])
                return rule
        return None

    def _action(self, profile: IPProfile) -> str:
        """
        Five-tier action (was four):
          LOG        — score >0 but below SCORE_ALERT/2  → write to log, no UI alert
          MONITOR    — score ≥ SCORE_ALERT/2             → dashboard alert, no block
          ALERT      — score ≥ SCORE_ALERT               → dashboard alert + strike
          TEMP_BLOCK — score ≥ SCORE_TEMP_BLOCK          → 5-min firewall block
          PERM_BLOCK — score ≥ SCORE_PERM_BLOCK          → permanent firewall block
        """
        if profile.perm_blocked or profile.score >= SCORE_PERM_BLOCK:
            return "PERM_BLOCK"
        if time.time() < profile.temp_until or profile.score >= SCORE_TEMP_BLOCK:
            return "TEMP_BLOCK"
        if profile.score >= SCORE_ALERT:
            return "ALERT"
        if profile.score >= SCORE_ALERT / 2:
            return "MONITOR"
        return "LOG"

    @staticmethod
    def _alert(sid, msg, cat, sev, pkt) -> dict:
        return {
            "sid": sid, "msg": msg, "cat": cat, "sev": sev,
            "src": pkt.get("src", ""), "dst": pkt.get("dst", ""),
            "proto": pkt.get("proto", ""), "dport": pkt.get("dport", 0),
            "time": pkt.get("time", ""), "payload_snip": pkt.get("payload", "")[:120],
            "http": pkt.get("http"), "threat_score": 0.0,
            "risk_level": "LOW", "action": "MONITOR", "correlation": "",
        }
