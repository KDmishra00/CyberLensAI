"""Synthetic event corpus shared by train_model.py and make_samples.py.

Everything comes from fixed templates driven by a seeded RNG, so runs are
deterministic. Each row is a plain dict; `event` holds the text exactly as
core.parser would extract it at inference time (e.g. "sshd: Failed password
..." for syslog lines, "GET /path" for Apache lines), which keeps training
features and inference features comparable.
"""
from __future__ import annotations

import random
import re
from datetime import datetime, timedelta

USERS = ["admin", "root", "jdoe", "asmith", "kmishra", "sshakya", "deploy",
         "svc_backup", "postgres", "mysql", "www-data", "jenkins", "test",
         "oracle", "ubuntu", "git", "appuser", "operator", "intern", "audit"]
INVALID_USERS = ["oracle1", "test123", "gitlab", "pi", "ubnt", "admin123",
                 "postgres0", "support", "sales", "backup"]

HOSTS = ["web1", "db1", "mail1", "app1", "build1", "jumphost", "filesrv"]
DOMAINS = ["cdn-update[.]net", "sync-backup[.]io", "metrics-hub[.]xyz",
           "telemetry-svc[.]com", "paste-bin[.]cc"]
NORMAL_PATHS = ["/", "/index.html", "/assets/app.css", "/assets/app.js",
                "/blog/post-{}", "/images/logo.png", "/favicon.ico",
                "/api/v1/users?page={}", "/api/health", "/help/getting-started",
                "/pricing", "/contact", "/search?q=queries"]
AUTH_PATHS = ["/wp-login.php", "/admin/login", "/api/login", "/login.php",
              "/administrator/index.php", "/xmlrpc.php"]
SQLI_PATHS = ["/product.php?id={}", "/items.php?id={}", "/search?q={}",
              "/api/users?name={}", "/blog/?cat={}", "/page?id={}"]
# Three octets each; the generator appends the fourth.
EXTERNAL_PREFIXES = ["203.0.113", "198.51.100", "45.148.10", "91.240.20",
                     "185.220.30", "104.244.70", "192.0.2"]
MALWARE_NAMES = ["svchost", "update", "chrome_updater", "winlogin", "csrss"]

BASE_TIME = datetime(2026, 8, 10, 6, 0, 0)


def _external_ip(rng: random.Random) -> str:
    return f"{rng.choice(EXTERNAL_PREFIXES)}.{rng.randint(2, 254)}"


def _internal_ip(rng: random.Random) -> str:
    return f"10.{rng.randint(0, 20)}.{rng.randint(0, 254)}.{rng.randint(2, 254)}"


_IP_IN_TEXT = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _row(rng, ts, label, prog, event, **kw) -> dict:
    # Mirror the log parser: the source IP is whatever appears in the event
    # text, and rows whose text names no IP simply have none. This keeps the
    # training features in the same distribution the app sees at inference.
    default_ip = None
    if "src_ip" not in kw or kw["src_ip"] is None:
        found = _IP_IN_TEXT.search(event)
        default_ip = found.group(0) if found else ""
    # The parser takes the port from the event text when the format has no
    # dedicated port field (e.g. sshd "from IP port N"), so training rows
    # must do the same to stay in the same distribution.
    if kw.get("dst_port") is None:
        port_in_text = re.search(r"\bport (\d{1,5})", event)
        default_port = int(port_in_text.group(1)) if port_in_text else None
    else:
        default_port = kw["dst_port"]
    row = {
        "timestamp": ts,
        "src_ip": kw.get("src_ip", default_ip),
        "dst_ip": kw.get("dst_ip", ""),
        "dst_port": default_port,
        # No default username: most log lines do not name a user, and the
        # parser leaves username empty for them. Inventing one here would
        # poison the per-IP user-variety feature the model learns from.
        "username": kw.get("username", ""),
        "event": event,
        "bytes": kw.get("bytes"),
        "duration": kw.get("duration"),
        "status": kw.get("status", ""),
        "prog": prog,
        "host": kw.get("host", rng.choice(HOSTS)),
        "request": kw.get("request"),
        "label": label,
    }
    return row


def _start(rng, days=5) -> datetime:
    return BASE_TIME + timedelta(seconds=rng.uniform(0, days * 86400))


def block_normal(rng: random.Random, n: int) -> list[dict]:
    """Routine traffic: accepted logins, normal web hits, cron, systemd."""
    rows = []
    ts = _start(rng)
    regulars = [_internal_ip(rng) for _ in range(max(3, n // 10))]
    for _ in range(n):
        ts += timedelta(seconds=rng.uniform(2, 90))
        kind = rng.random()
        if kind < 0.30:
            user = rng.choice(USERS)
            ip = _internal_ip(rng)
            rows.append(_row(rng, ts, "Normal", "sshd",
                             f"Accepted password for {user} from {ip} port {rng.randint(40000, 65000)} ssh2",
                             src_ip=ip, username=user, dst_port=22,
                             duration=round(rng.uniform(0.05, 2), 2)))
        elif kind < 0.45:
            rows.append(_row(rng, ts, "Normal", "CRON",
                             f"CRON[8{rng.randint(100, 999)}]: (root) CMD (run-parts /etc/cron.hourly)"))
        elif kind < 0.60:
            rows.append(_row(rng, ts, "Normal", "systemd",
                             f"systemd[1]: Started {'Daily apt download activities' if rng.random() < 0.5 else 'Cleanup of Temporary Directories'}.",
                             username=""))
        elif kind < 0.95:
            path = rng.choice(NORMAL_PATHS).format(rng.randint(1, 40))
            status = rng.choice([200, 200, 200, 304])
            rows.append(_row(rng, ts, "Normal", "httpd",
                             f"GET {path}",
                             src_ip=regulars[rng.randrange(len(regulars))],
                             username="", status=str(status),
                             bytes=rng.randint(200, 9000),
                             duration=round(rng.uniform(0.01, 1.2), 3),
                             request=f"GET {path} HTTP/1.1"))
        else:
            # One failed attempt happens in normal life too; it stays Normal.
            user = rng.choice(USERS)
            ip = _internal_ip(rng)
            rows.append(_row(rng, ts, "Normal", "sshd",
                             f"Failed password for {user} from {ip} port {rng.randint(40000, 65000)} ssh2",
                             src_ip=ip, username=user, dst_port=22))
    return rows


def block_bruteforce(rng: random.Random) -> list[dict]:
    """Bursts of failed logins from one IP against one or many usernames."""
    rows = []
    ts = _start(rng, days=1)
    attacker = _external_ip(rng)
    targets = [rng.choice(USERS) for _ in range(rng.choice([1, 1, 1, 3, 6]))]
    port = rng.choice([22, 22, 22, 3389, 21, 5900])
    n = rng.randint(60, 220)
    for i in range(n):
        ts += timedelta(seconds=rng.uniform(0.2, 3))
        user = rng.choice(targets) if rng.random() < 0.7 else rng.choice(INVALID_USERS)
        pick = rng.random()
        if pick < 0.55:
            event = f"sshd: Failed password for {user} from {attacker} port {rng.randint(40000, 65000)} ssh2"
            prog = "sshd"
        elif pick < 0.75:
            event = f"sshd: Invalid user {user} from {attacker} port {rng.randint(40000, 65000)}"
            prog = "sshd"
        elif pick < 0.85:
            event = f"sshd: Failed publickey for {user} from {attacker} port {rng.randint(40000, 65000)} ssh2: RSA SHA256:W{rng.randint(10**9, 10**10)}"
            prog = "sshd"
        elif pick < 0.92:
            event = f"auth: authentication failed for user {user} from {attacker} (LDAP)"
            prog = "auth"
        else:
            path = rng.choice(AUTH_PATHS)
            event = f"POST {path}"
            prog = "httpd"
            rows.append(_row(rng, ts, "Brute Force", prog, event,
                         src_ip=attacker, status="401",
                         bytes=rng.randint(180, 400),
                         request=f"POST {path} HTTP/1.1", username=""))
            continue
        rows.append(_row(rng, ts, "Brute Force", prog, event,
                         src_ip=attacker, dst_port=port, username=user,
                         bytes=rng.randint(80, 300), duration=round(rng.uniform(0.1, 3), 2)))
    # The burst sometimes ends in success - the classic compromised account.
    if rng.random() < 0.5:
        ts += timedelta(seconds=rng.uniform(2, 30))
        user = targets[0]
        rows.append(_row(rng, ts, "Brute Force", "sshd",
                         f"Accepted password for {user} from {attacker} port {rng.randint(40000, 65000)} ssh2",
                         src_ip=attacker, dst_port=22, username=user))
    return rows


def block_portscan(rng: random.Random) -> list[dict]:
    """One IP touching many distinct ports in a short window."""
    rows = []
    ts = _start(rng, days=1)
    attacker = _external_ip(rng)
    n = rng.randint(30, 260)
    for _ in range(n):
        ts += timedelta(seconds=rng.uniform(0.05, 0.6))
        dport = rng.choice([
            rng.randint(20, 1024), rng.randint(1024, 9000), rng.randint(30000, 65535),
            rng.choice([21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995,
                        1433, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200]),
        ])
        pick = rng.random()
        if pick < 0.4:
            event = f"firewall: blocked connection attempt from {attacker} to port {dport}"
            prog = "firewall"
        elif pick < 0.65:
            event = f"nsm: SYN packet from {attacker} to port {dport} (no handshake)"
            prog = "nsm"
        elif pick < 0.85:
            event = f"sshd: Connection closed by {attacker} port {rng.randint(40000, 65000)} [preauth]"
            prog = "sshd"
        else:
            event = f"app: connection to closed port {dport} from {attacker} refused"
            prog = "app"
        rows.append(_row(rng, ts, "Port Scan", prog, event,
                         src_ip=attacker, dst_port=dport,
                         bytes=rng.randint(0, 120), duration=round(rng.uniform(0, 0.05), 3)))
    return rows


def block_malware(rng: random.Random) -> list[dict]:
    """Suspicious execution, encoded payloads, beacons, ransomware noise."""
    rows = []
    ts = _start(rng, days=1)
    host = rng.choice(HOSTS)
    user = rng.choice(USERS)
    c2 = _external_ip(rng)
    for _ in range(rng.randint(8, 60)):
        ts += timedelta(seconds=rng.uniform(5, 60))
        pick = rng.random()
        b64 = "".join(rng.choice("SQBFAFgAaQB4ACgAXwBtAGkAawBhAHQAegAj") for _ in range(rng.randint(10, 24)))
        if pick < 0.18:
            event = f"edr: powershell -enc {b64} launched by {user}"
            prog = "edr"
        elif pick < 0.32:
            event = f"edr: Mimikatz credential dump detected on host {host}"
            prog = "edr"
        elif pick < 0.46:
            event = f"edr: Suspicious beaconing to {c2}:443 every 60s"
            prog = "edr"
        elif pick < 0.58:
            name = rng.choice(MALWARE_NAMES)
            event = f"edr: Dropped file C:\\Users\\{user}\\AppData\\Local\\Temp\\{name}.exe quarantined"
            prog = "edr"
        elif pick < 0.70:
            event = f"edr: Ransom note README_RESTORE_FILES.txt created in \\\\{host}\\docs"
            prog = "edr"
        elif pick < 0.80:
            event = f"edr: vssadmin delete shadows /all executed by {user}"
            prog = "edr"
        elif pick < 0.90:
            event = f"edr: Reverse shell connection to {_external_ip(rng)}:4444 blocked"
            prog = "edr"
        else:
            event = f"edr: Base64 payload decoded in %TEMP%\\{rng.choice(MALWARE_NAMES)}.exe"
            prog = "edr"
        rows.append(_row(rng, ts, "Malware Activity", prog, event,
                         dst_ip=c2, bytes=rng.randint(500, 200_000)))
    return rows


def block_sqli(rng: random.Random) -> list[dict]:
    """Injection payloads in query strings, raw and URL-encoded."""
    rows = []
    ts = _start(rng, days=1)
    attacker = _external_ip(rng)
    payloads = [
        "1' OR '1'='1", "' UNION SELECT username, password FROM users--",
        "admin'--", "1 AND SLEEP(5)", "1 UNION SELECT 1,2,3 FROM information_schema.tables",
        "1;DROP TABLE users--", "1' AND '1'='1", "' OR 1=1-- -",
        "%27%20OR%20%271%27%3D%271", "%27%20UNION%20SELECT%20null,null--",
        "1%20AND%20SLEEP%285%29", "1%27%3BDROP%20TABLE%20users--",
    ]
    for _ in range(rng.randint(5, 45)):
        ts += timedelta(seconds=rng.uniform(0.5, 10))
        payload = rng.choice(payloads)
        path = rng.choice(SQLI_PATHS).format(payload)
        event = f"GET {path}"
        rows.append(_row(rng, ts, "SQL Injection", "httpd", event,
                         src_ip=attacker, status=str(rng.choice([200, 500, 403, 200])),
                         bytes=rng.randint(300, 2500),
                         duration=round(rng.uniform(0.05, 5), 3),
                         request=f"GET {path} HTTP/1.1", username=""))
    return rows


def block_privesc(rng: random.Random) -> list[dict]:
    """Sudo abuse, sensitive-file access, group changes, UAC bypass."""
    rows = []
    ts = _start(rng, days=1)
    user = rng.choice(USERS + ["svc_backup", "deploy"])
    for _ in range(rng.randint(3, 30)):
        ts += timedelta(seconds=rng.uniform(10, 300))
        pick = rng.random()
        if pick < 0.22:
            event = f"sudo: {user} : user NOT in sudoers ; TTY=pts/{rng.randint(0, 4)} ; COMMAND=/bin/bash"
            prog = "sudo"
        elif pick < 0.40:
            event = f"sudo: {user} : COMMAND=/bin/sh -c whoami"
            prog = "sudo"
        elif pick < 0.55:
            event = f"audit: chmod 777 /etc/shadow by {user}"
            prog = "audit"
        elif pick < 0.68:
            event = f"audit: setuid bit set on /usr/bin/find by {user}"
            prog = "audit"
        elif pick < 0.80:
            event = f"usermod: user {user} added to group {'sudo' if rng.random() < 0.5 else 'wheel'}"
            prog = "usermod"
        elif pick < 0.90:
            event = f"sec: UAC bypass attempt via eventvwr.exe by {user}"
            prog = "sec"
        else:
            event = f"audit: /etc/passwd modified by {user}"
            prog = "audit"
        rows.append(_row(rng, ts, "Privilege Escalation", prog, event,
                         username=user, bytes=rng.randint(0, 2000)))
    return rows


def block_dos(rng: random.Random) -> list[dict]:
    """Floods, exhausted workers, oversized or malformed requests."""
    rows = []
    ts = _start(rng, days=1)
    attackers = [_external_ip(rng) for _ in range(rng.choice([1, 1, 2, 3]))]
    n = rng.randint(80, 400)
    for i in range(n):
        ts += timedelta(seconds=rng.uniform(0.05, 0.5))
        ip = attackers[i % len(attackers)]
        pick = rng.random()
        if pick < 0.25:
            event = f"ddos: SYN flood detected from {ip} ({rng.randint(2, 90)}k pkt/s)"
            prog = "ddos"
        elif pick < 0.45:
            event = f"lb: request rate {rng.randint(900, 8000)}/s from {ip} exceeds threshold"
            prog = "lb"
        elif pick < 0.60:
            event = f"app: worker pool exhausted; {rng.randint(500, 4000)} pending connections"
            prog = "app"
        elif pick < 0.72:
            event = f"kernel: conntrack table full, dropping packets from {ip}"
            prog = "kernel"
        elif pick < 0.86:
            event = "GET /download.iso"
            prog = "httpd"
            rows.append(_row(rng, ts, "DoS Indicators", prog, event,
                             src_ip=ip, status="200", bytes=rng.randint(10_000_000, 60_000_000),
                             duration=round(rng.uniform(0.5, 8), 2),
                             request="GET /download.iso HTTP/1.1", username=""))
            continue
        else:
            event = f"web: slowloris-style connection held by {ip}"
            prog = "web"
        rows.append(_row(rng, ts, "DoS Indicators", prog, event,
                         src_ip=ip, bytes=rng.randint(0, 2000),
                         duration=round(rng.uniform(0.1, 30), 2)))
    return rows


def corpus_blocks(seed: int = 42) -> list[dict]:
    """All rows from every block generator, with light label noise applied."""
    rng = random.Random(seed)
    blocks: list[dict] = []
    for _ in range(50):
        blocks.extend(block_normal(rng, 80))
    for _ in range(30):
        blocks.extend(block_bruteforce(rng))
    for _ in range(30):
        blocks.extend(block_portscan(rng))
    for _ in range(50):
        blocks.extend(block_malware(rng))
    for _ in range(50):
        blocks.extend(block_sqli(rng))
    for _ in range(60):
        blocks.extend(block_privesc(rng))
    for _ in range(15):
        blocks.extend(block_dos(rng))

    noise_rng = random.Random(seed + 1)
    classes = ["Normal", "Brute Force", "Port Scan", "Malware Activity",
               "SQL Injection", "Privilege Escalation", "DoS Indicators"]
    for row in blocks:
        if noise_rng.random() < 0.03:
            row["label"] = noise_rng.choice(classes)
    return blocks
