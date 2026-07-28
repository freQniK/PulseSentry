#!/usr/bin/env python3
"""
PulseSentry - Service, SSL & Blockchain RPC Monitor with Telegram Alerts
            - Static HTML Status Page Generation
"""

import argparse
import socket
import ssl
import sqlite3
import sys
import time
import os
from datetime import datetime, timezone, timedelta
from pathlib import Path
import requests
import urllib3

from cryptography import x509
from cryptography.hazmat.backends import default_backend

from rich.console import Console, Group
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.align import Align
from rich import box

# Suppress InsecureRequestWarning for RPC checks with verify=False
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ============ CONFIGURATION ============
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "YOUR_BOT_TOKEN_HERE")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "YOUR_CHAT_ID_HERE")
DB_PATH = "pulsesentry.db"
SSL_WARNING_DAYS = 15
CONNECT_TIMEOUT = 10
ALERT_COOLDOWN_HOURS = 6
RPC_LAG_THRESHOLD = 100  # blocks behind tip before marking RPC down
VERSION = "2.0.0"
HTML_OUTPUT = "pulsesentry_status.html"
# =======================================

console = Console()

BANNER = r"""
 ____        _          ____             _
|  _ \ _   _| |___  ___/ ___|  ___ _ __ | |_ _ __ _   _
| |_) | | | | / __|/ _ \___ \ / _ \ '_ \| __| '__| | | |
|  __/| |_| | \__ \  __/___) |  __/ | | | |_| |  | |_| |
|_|    \__,_|_|___/\___|____/ \___|_| |_|\__|_|   \__, |
                                                  |___/
"""

def print_banner():
    """Display the PulseSentry banner."""
    banner_text = Text(BANNER, style="bold cyan")
    subtitle = Text(
        f"Service & SSL Monitor  •  v{VERSION}  •  by: freQniK",
        style="bold magenta"
    )
    panel = Panel(
        Group(
            Align.center(banner_text),
            Align.center(subtitle),
        ),
        border_style="bright_yellow",
        box=box.DOUBLE_EDGE,
        padding=(0, 2)
    )
    console.print(panel)

def init_db():
    """Initialize SQLite database for tracking uptime history."""
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    # Per-check results
    cur.execute("""
        CREATE TABLE IF NOT EXISTS checks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            service TEXT NOT NULL,
            timestamp REAL NOT NULL,
            is_up INTEGER NOT NULL
        )
    """)
    cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_service_time
        ON checks(service, timestamp)
    """)

    # Alert cooldowns
    cur.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            service TEXT NOT NULL,
            alert_type TEXT NOT NULL,
            last_sent REAL NOT NULL,
            PRIMARY KEY (service, alert_type)
        )
    """)

    # Downtime tracking: each row is one outage episode
    cur.execute("""
        CREATE TABLE IF NOT EXISTS downtime_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            service TEXT NOT NULL,
            down_at REAL NOT NULL,
            up_at REAL,
            duration_seconds REAL
        )
    """)
    cur.execute("""
        CREATE INDEX IF NOT EXISTS idx_downtime_service
        ON downtime_log(service, down_at)
    """)

    # Current state of each service (tracks open downtime windows)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS service_state (
            service TEXT PRIMARY KEY,
            is_down INTEGER NOT NULL DEFAULT 0,
            down_since REAL
        )
    """)

    conn.commit()
    conn.close()

def record_check(service, is_up):
    """Record a check result in the database."""
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO checks (service, timestamp, is_up) VALUES (?, ?, ?)",
        (service, time.time(), 1 if is_up else 0)
    )
    cutoff = time.time() - (31 * 86400)
    cur.execute("DELETE FROM checks WHERE timestamp < ?", (cutoff,))
    conn.commit()
    conn.close()

def track_service_state(service, is_up):
    """
    Track service state transitions for downtime logging.
    - If service just went DOWN: record down_since in service_state.
    - If service just came UP: close the open downtime_log entry.
    """
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute(
        "SELECT is_down, down_since FROM service_state WHERE service = ?",
        (service,)
    )
    row = cur.fetchone()

    if row is None:
        # First time seeing this service
        if is_up:
            cur.execute(
                "INSERT INTO service_state (service, is_down, down_since) "
                "VALUES (?, 0, NULL)",
                (service,)
            )
        else:
            now = time.time()
            cur.execute(
                "INSERT INTO service_state (service, is_down, down_since) "
                "VALUES (?, 1, ?)",
                (service, now)
            )
            cur.execute(
                "INSERT INTO downtime_log (service, down_at) VALUES (?, ?)",
                (service, now)
            )
    else:
        was_down, down_since = row[0], row[1]
        if was_down and is_up:
            # Transition: DOWN → UP
            now = time.time()
            duration = now - down_since if down_since else 0
            cur.execute(
                "UPDATE service_state SET is_down = 0, down_since = NULL "
                "WHERE service = ?",
                (service,)
            )
            # Close the most recent open downtime_log row
            cur.execute("""
                UPDATE downtime_log
                SET up_at = ?, duration_seconds = ?
                WHERE service = ? AND up_at IS NULL
                ORDER BY down_at DESC LIMIT 1
            """, (now, duration, service))
        elif not was_down and not is_up:
            # Transition: UP → DOWN
            now = time.time()
            cur.execute(
                "UPDATE service_state SET is_down = 1, down_since = ? "
                "WHERE service = ?",
                (now, service)
            )
            cur.execute(
                "INSERT INTO downtime_log (service, down_at) VALUES (?, ?)",
                (service, now)
            )

    conn.commit()
    conn.close()

def get_uptime_percentage(service, hours):
    """Calculate uptime percentage for the given hours back."""
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cutoff = time.time() - (hours * 3600)
    cur.execute("""
        SELECT COUNT(*), SUM(is_up)
        FROM checks
        WHERE service = ? AND timestamp >= ?
    """, (service, cutoff))
    total, up = cur.fetchone()
    conn.close()
    if not total or total == 0:
        return None
    return (up / total) * 100

def get_daily_status(service, days=30):
    """
    Return a list of (date_str, status) for the last `days` calendar days.
    Status is one of: "green", "yellow", "red".
    - green: total downtime < 5 minutes that day
    - yellow: 5 min ≤ total downtime < 2 hours that day
    - red: total downtime ≥ 2 hours that day
    """
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    now = time.time()
    day_seconds = 86400
    result = []

    for offset in range(days - 1, -1, -1):
        day_start = now - (offset + 1) * day_seconds
        day_end = now - offset * day_seconds

        # Start of the next day for the date label
        day_dt = datetime.fromtimestamp(day_end, tz=timezone.utc)
        date_str = day_dt.strftime("%Y-%m-%d")

        # Sum downtime that overlaps this calendar day
        # downtime_log entries: down_at ≤ up_at (or up_at is NULL)
        cur.execute("""
            SELECT down_at, COALESCE(up_at, ?) AS effective_up
            FROM downtime_log
            WHERE service = ?
              AND down_at < ?
              AND COALESCE(up_at, ?) > ?
        """, (day_end, service, day_end, day_end, day_start))

        rows = cur.fetchall()
        total_downtime = 0.0
        for down_at, effective_up in rows:
            overlap_start = max(down_at, day_start)
            overlap_end = min(effective_up, day_end)
            if overlap_end > overlap_start:
                total_downtime += overlap_end - overlap_start

        if total_downtime < 300:  # less than 5 minutes
            status = "green"
        elif total_downtime < 7200:  # less than 2 hours
            status = "yellow"
        else:
            status = "red"

        result.append((date_str, status))

    conn.close()
    return result

def should_send_alert(service, alert_type):
    """Check if an alert should be sent (respects cooldown)."""
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(
        "SELECT last_sent FROM alerts WHERE service = ? AND alert_type = ?",
        (service, alert_type)
    )
    row = cur.fetchone()
    now = time.time()
    cooldown = ALERT_COOLDOWN_HOURS * 3600

    if row is None or (now - row[0]) > cooldown:
        cur.execute("""
            INSERT OR REPLACE INTO alerts (service, alert_type, last_sent)
            VALUES (?, ?, ?)
        """, (service, alert_type, now))
        conn.commit()
        conn.close()
        return True
    conn.close()
    return False

def send_telegram(message):
    """Send a notification via Telegram."""
    if (TELEGRAM_BOT_TOKEN == "YOUR_BOT_TOKEN_HERE"
            or TELEGRAM_CHAT_ID == "YOUR_CHAT_ID_HERE"):
        console.print(
            "[yellow][WARN][/yellow] Telegram credentials not configured"
        )
        return False
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": message,
        "parse_mode": "Markdown"
    }
    try:
        r = requests.post(url, json=payload, timeout=10)
        if r.status_code != 200:
            console.print(
                f"[red][ERROR][/red] Telegram send failed: {r.text}"
            )
            return False
        return True
    except Exception as e:
        console.print(f"[red][ERROR][/red] Telegram exception: {e}")
        return False

def check_tcp_connection(host, port):
    """Check if we can establish a TCP connection."""
    try:
        with socket.create_connection((host, port), timeout=CONNECT_TIMEOUT):
            return True
    except (socket.timeout, socket.error, OSError):
        return False

def check_ssl_certificate(host, port):
    """
    Check SSL certificate expiration using the cryptography library
    to parse the raw DER cert directly. Works even when verify_mode
    is CERT_NONE.

    Returns: (has_ssl, is_valid, days_until_expiry, expiry_dt)
    """
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection(
            (host, port), timeout=CONNECT_TIMEOUT
        ) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                der_cert = ssock.getpeercert(binary_form=True)
                if not der_cert:
                    return (False, False, None, None)

                cert = x509.load_der_x509_certificate(
                    der_cert, default_backend()
                )

                try:
                    expires = cert.not_valid_after_utc
                except AttributeError:
                    expires = cert.not_valid_after.replace(
                        tzinfo=timezone.utc
                    )

                now = datetime.now(timezone.utc)
                delta = expires - now
                days_left = int(delta.total_seconds() // 86400)
                is_valid = delta.total_seconds() > 0
                return (True, is_valid, days_left, expires)
    except ssl.SSLError:
        return (False, False, None, None)
    except (socket.timeout, socket.error, OSError, ValueError):
        return (False, False, None, None)

def is_rpc_service(host):
    """Determine if a service is a blockchain RPC endpoint."""
    return "rpc" in host.lower()

def check_rpc_status(host, port):
    """
    Query an RPC /status endpoint and return the latest block height.
    Returns: (success, height_int_or_None)
    """
    url = f"https://{host}:{port}/status"
    try:
        r = requests.get(url, timeout=CONNECT_TIMEOUT, verify=False)
        if r.status_code != 200:
            return (False, None)
        data = r.json()
        height = data.get("result", {}).get("sync_info", {}).get(
            "latest_block_height"
        )
        if height is None:
            return (False, None)
        return (True, int(height))
    except (requests.RequestException, ValueError, KeyError, TypeError):
        return (False, None)

def parse_services_file(filepath):
    """Parse the services input file."""
    services = []
    with open(filepath, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if ':' not in line:
                console.print(
                    f"[yellow][WARN][/yellow] Skipping invalid line: {line}"
                )
                continue
            host, port = line.rsplit(':', 1)
            try:
                services.append((host.strip(), int(port.strip())))
            except ValueError:
                console.print(
                    f"[yellow][WARN][/yellow] Invalid port: {line}"
                )
    return services

def check_service(host, port):
    """
    Perform initial check on a service. Note: RPC lag evaluation and
    final is_up determination happen later in evaluate_rpc_lag() once
    all RPC heights are known.
    """
    service_id = f"{host}:{port}"
    tcp_up = check_tcp_connection(host, port)

    result = {
        "service": service_id,
        "tcp_up": tcp_up,
        "is_up": tcp_up,  # may be overridden by RPC lag check
        "has_ssl": False,
        "ssl_valid": False,
        "days_left": None,
        "expiry_dt": None,
        "is_rpc": is_rpc_service(host),
        "block_height": None,
        "rpc_lagging": False,
        "blocks_behind": None,
    }

    if tcp_up:
        has_ssl, valid, days, expiry = check_ssl_certificate(host, port)
        result["has_ssl"] = has_ssl
        result["ssl_valid"] = valid
        result["days_left"] = days
        result["expiry_dt"] = expiry

        if result["is_rpc"]:
            rpc_ok, height = check_rpc_status(host, port)
            result["block_height"] = height

    return result

def evaluate_rpc_lag(results):
    """
    Compare RPC heights and mark any RPC that is RPC_LAG_THRESHOLD or
    more blocks behind the highest as lagging (which counts as DOWN).
    Also records final uptime to the database after this evaluation.
    """
    rpc_heights = [
        r["block_height"] for r in results
        if r["is_rpc"] and r["block_height"] is not None
    ]
    tip = max(rpc_heights) if rpc_heights else None

    for r in results:
        if r["is_rpc"] and r["tcp_up"]:
            if r["block_height"] is None:
                # RPC endpoint failed entirely — treat as down
                r["is_up"] = False
            elif tip is not None:
                behind = tip - r["block_height"]
                r["blocks_behind"] = behind
                if behind >= RPC_LAG_THRESHOLD:
                    r["rpc_lagging"] = True
                    r["is_up"] = False

        # Now that is_up is finalized, record it
        record_check(r["service"], r["is_up"])

        # Track state transitions for downtime logging
        track_service_state(r["service"], r["is_up"])

        # Recalculate uptime percentages with the final value recorded
        r["uptime_24h"] = get_uptime_percentage(r["service"], 24)
        r["uptime_7d"] = get_uptime_percentage(r["service"], 24 * 7)
        r["uptime_30d"] = get_uptime_percentage(r["service"], 24 * 30)

    return tip

def handle_notifications(result, chain_tip):
    """Send Telegram notifications for issues."""
    service = result["service"]

    # RPC lagging notification (specific alert type)
    if result["rpc_lagging"]:
        if should_send_alert(service, "rpc_lag"):
            msg = (
                f"⛓️ *PulseSentry Alert - RPC LAGGING*\n\n"
                f"*Service:* `{service}`\n"
                f"*Time:* {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
                f"*Node Height:* {result['block_height']:,}\n"
                f"*Network Tip:* {chain_tip:,}\n"
                f"*Blocks Behind:* {result['blocks_behind']:,}\n"
                f"*Threshold:* {RPC_LAG_THRESHOLD} blocks\n\n"
                f"This RPC is considered DOWN until it catches up."
            )
            send_telegram(msg)
        return

    # Service down notification
    if not result["is_up"]:
        if should_send_alert(service, "down"):
            uptime_24h = (
                f"{result['uptime_24h']:.2f}%"
                if result['uptime_24h'] is not None else "N/A"
            )
            uptime_7d = (
                f"{result['uptime_7d']:.2f}%"
                if result['uptime_7d'] is not None else "N/A"
            )
            # Distinguish between TCP down and RPC /status failure
            if result["is_rpc"] and result["tcp_up"]:
                reason = (
                    "TCP connection succeeded but /status endpoint failed."
                )
            else:
                reason = "TCP connection failed."
            msg = (
                f"🔴 *PulseSentry Alert - Service DOWN*\n\n"
                f"*Service:* `{service}`\n"
                f"*Time:* {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
                f"*Reason:* {reason}\n"
                f"*24h Uptime:* {uptime_24h}\n"
                f"*7d Uptime:* {uptime_7d}"
            )
            send_telegram(msg)
        return

    # SSL notifications
    days = result.get("days_left")
    if days is not None and result["has_ssl"]:
        expiry_str = (
            result["expiry_dt"].strftime("%Y-%m-%d %H:%M UTC")
            if result["expiry_dt"] else "Unknown"
        )
        if days <= 0:
            if should_send_alert(service, "ssl_expired"):
                msg = (
                    f"⛔ *PulseSentry Alert - SSL EXPIRED*\n\n"
                    f"*Service:* `{service}`\n"
                    f"*Expired:* {expiry_str}"
                )
                send_telegram(msg)
        elif days <= SSL_WARNING_DAYS:
            if should_send_alert(service, "ssl_warning"):
                msg = (
                    f"⚠️ *PulseSentry Alert - SSL Expiring Soon*\n\n"
                    f"*Service:* `{service}`\n"
                    f"*Days remaining:* {days}\n"
                    f"*Expires:* {expiry_str}"
                )
                send_telegram(msg)

def colorize_status(result):
    """Return colored status text."""
    if result["rpc_lagging"]:
        return Text("● LAGGING", style="bold red")
    if result["is_up"]:
        return Text("● UP", style="bold green")
    return Text("● DOWN", style="bold red")

def colorize_ssl(result):
    """Return colored SSL status."""
    if not result["tcp_up"]:
        return Text("\u2014", style="dim")
    if not result["has_ssl"]:
        return Text("No SSL", style="dim white")
    days = result["days_left"]
    if days is None:
        return Text("Unknown", style="yellow")
    if days <= 0:
        return Text("\u2717 EXPIRED", style="bold red")
    if days <= SSL_WARNING_DAYS:
        return Text(f"\u26a0 {days}d left", style="bold yellow")
    return Text(f"\u2713 OK ({days}d)", style="bold green")

def format_expiry(result):
    """Format SSL expiry date."""
    if not result["tcp_up"] or not result["has_ssl"]:
        return Text("\u2014", style="dim")
    if result["expiry_dt"] is None:
        return Text("Unknown", style="dim")
    return Text(
        result["expiry_dt"].strftime("%Y-%m-%d %H:%M UTC"),
        style="cyan"
    )

def format_height(result):
    """Format the block height with comma separation."""
    if not result["is_rpc"]:
        return Text("N/A", style="dim")
    if not result["tcp_up"]:
        return Text("\u2014", style="dim")
    height = result["block_height"]
    if height is None:
        return Text("ERROR", style="bold red")
    text = f"{height:,}"
    if result["rpc_lagging"]:
        text += f" (-{result['blocks_behind']:,})"
        return Text(text, style="bold red")
    if result["blocks_behind"] and result["blocks_behind"] > 0:
        text += f" (-{result['blocks_behind']:,})"
        return Text(text, style="yellow")
    return Text(text, style="bold cyan")

def colorize_uptime(pct):
    """Return colored uptime percentage."""
    if pct is None:
        return Text("N/A", style="dim")
    if pct >= 99.0:
        style = "bold green"
    elif pct >= 95.0:
        style = "bold yellow"
    else:
        style = "bold red"
    return Text(f"{pct:.2f}%", style=style)

def build_table(results):
    """Build a Rich table of results."""
    table = Table(
        title=None,
        box=box.ROUNDED,
        border_style="bright_yellow",
        header_style="bold bright_white on blue",
        show_lines=False,
        expand=True,
    )
    table.add_column("Service", style="bold white", no_wrap=True)
    table.add_column("Status", justify="center")
    table.add_column("Height", justify="right")
    table.add_column("SSL Cert", justify="center")
    table.add_column("SSL Expiration", justify="center")
    table.add_column("24h Uptime", justify="right")
    table.add_column("7d Uptime", justify="right")
    table.add_column("30d Uptime", justify="right")

    for r in results:
        table.add_row(
            r["service"],
            colorize_status(r),
            format_height(r),
            colorize_ssl(r),
            format_expiry(r),
            colorize_uptime(r["uptime_24h"]),
            colorize_uptime(r["uptime_7d"]),
            colorize_uptime(r["uptime_30d"]),
        )
    return table

def build_summary(results, interval, chain_tip):
    """Build summary footer."""
    up = sum(1 for r in results if r["is_up"])
    down = sum(1 for r in results if not r["is_up"])
    ssl_warn = sum(
        1 for r in results
        if r["tcp_up"] and r["has_ssl"]
        and r["days_left"] is not None
        and 0 < r["days_left"] <= SSL_WARNING_DAYS
    )
    ssl_exp = sum(
        1 for r in results
        if r["tcp_up"] and r["has_ssl"]
        and r["days_left"] is not None
        and r["days_left"] <= 0
    )
    rpc_total = sum(1 for r in results if r["is_rpc"])
    rpc_ok = sum(
        1 for r in results
        if r["is_rpc"] and r["is_up"] and r["block_height"] is not None
    )
    rpc_lag = sum(1 for r in results if r["rpc_lagging"])

    parts = [
        f"[bold green]\u25cf UP:[/bold green] {up}",
        f"[bold red]\u25cf DOWN:[/bold red] {down}",
        f"[bold yellow]\u26a0 SSL Warn:[/bold yellow] {ssl_warn}",
        f"[bold red]\u2717 SSL Exp:[/bold red] {ssl_exp}",
        f"[bold cyan]\u26d3 RPC OK:[/bold cyan] {rpc_ok}/{rpc_total}",
        f"[bold red]\u26d3 Lagging:[/bold red] {rpc_lag}",
    ]
    if chain_tip is not None:
        parts.append(f"[bold magenta]Tip:[/bold magenta] {chain_tip:,}")
    parts.append(f"[cyan]Interval:[/cyan] {interval}s")
    parts.append(
        f"[cyan]Last:[/cyan] {datetime.now().strftime('%H:%M:%S')}"
    )

    return Panel(
        "  \u2022  ".join(parts),
        border_style="bright_yellow",
        box=box.ROUNDED,
        padding=(0, 1)
    )

def publish_status_page(results, output_path=HTML_OUTPUT):
    """
    Generate a static HTML status page with a golden-yellow / black theme.
    Each service gets:
      - Current online/offline badge
      - 30-day uptime percentage
      - Horizontal 30-day meter bar (green/yellow/red per day)
    """
    now_utc = datetime.now(timezone.utc)
    generated_str = now_utc.strftime("%Y-%m-%d %H:%M:%S UTC")

    # CSS (golden-yellow / black theme)
    css = """
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
        background: #0a0a0a;
        color: #e0d090;
        font-family: 'Segoe UI', 'Helvetica Neue', Arial, sans-serif;
        min-height: 100vh;
    }
    .header {
        background: linear-gradient(180deg, #1a1400 0%, #111006 100%);
        border-bottom: 3px solid #c8a020;
        padding: 24px 32px;
        text-align: center;
    }
    .header h1 {
        color: #f0c040;
        font-size: 2rem;
        letter-spacing: 2px;
        text-transform: uppercase;
        text-shadow: 0 0 18px rgba(240,192,64,0.5);
    }
    .header .subtitle {
        color: #a08030;
        font-size: 0.85rem;
        margin-top: 4px;
    }
    .container {
        max-width: 960px;
        margin: 0 auto;
        padding: 28px 20px 40px 20px;
    }
    .service-card {
        background: #14110a;
        border: 1px solid #3a3010;
        border-radius: 10px;
        padding: 22px 26px;
        margin-bottom: 20px;
        box-shadow: 0 2px 12px rgba(200,160,32,0.08);
        transition: border-color 0.3s;
    }
    .service-card:hover {
        border-color: #c8a020;
    }
    .service-name {
        font-size: 1.15rem;
        font-weight: 700;
        color: #f0d060;
        font-family: 'Consolas', 'Fira Code', monospace;
        margin-bottom: 8px;
    }
    .service-meta {
        display: flex;
        align-items: center;
        gap: 16px;
        flex-wrap: wrap;
        margin-bottom: 14px;
    }
    .badge {
        display: inline-block;
        padding: 4px 14px;
        border-radius: 20px;
        font-size: 0.82rem;
        font-weight: 700;
        letter-spacing: 0.5px;
        text-transform: uppercase;
    }
    .badge-online {
        background: rgba(34,197,94,0.15);
        color: #22c55e;
        border: 1px solid #22c55e;
        box-shadow: 0 0 10px rgba(34,197,94,0.25);
    }
    .badge-offline {
        background: rgba(239,68,68,0.15);
        color: #ef4444;
        border: 1px solid #ef4444;
        box-shadow: 0 0 10px rgba(239,68,68,0.25);
    }
    .uptime-pct {
        font-size: 1.6rem;
        font-weight: 800;
        color: #f0c040;
    }
    .uptime-label {
        font-size: 0.75rem;
        color: #8a7030;
        text-transform: uppercase;
        letter-spacing: 1px;
    }
    .meter-section {
        margin-top: 8px;
    }
    .meter-label {
        font-size: 0.72rem;
        color: #8a7030;
        text-transform: uppercase;
        letter-spacing: 1px;
        margin-bottom: 6px;
    }
    .meter-bar {
        display: flex;
        gap: 3px;
        height: 24px;
        border-radius: 5px;
        overflow: hidden;
        background: #1c1808;
        padding: 3px;
    }
    .meter-segment {
        flex: 1;
        min-width: 6px;
        border-radius: 3px;
        position: relative;
        transition: transform 0.15s;
    }
    .meter-segment:hover {
        transform: scaleY(1.35);
        z-index: 2;
    }
    .meter-segment.green { background: #22c55e; box-shadow: 0 0 6px rgba(34,197,94,0.5); }
    .meter-segment.yellow { background: #eab308; box-shadow: 0 0 6px rgba(234,179,8,0.5); }
    .meter-segment.red { background: #ef4444; box-shadow: 0 0 6px rgba(239,68,68,0.5); }
    .meter-segment.no-data { background: #2a2818; box-shadow: none; }
    .meter-legend {
        display: flex;
        gap: 18px;
        margin-top: 8px;
        font-size: 0.7rem;
        color: #7a6820;
    }
    .legend-dot {
        display: inline-block;
        width: 10px;
        height: 10px;
        border-radius: 2px;
        margin-right: 4px;
        vertical-align: middle;
    }
    .legend-dot.green { background: #22c55e; }
    .legend-dot.yellow { background: #eab308; }
    .legend-dot.red { background: #ef4444; }
    .footer {
        text-align: center;
        padding: 20px;
        color: #5a4a18;
        font-size: 0.72rem;
        border-top: 1px solid #2a2410;
        margin-top: 30px;
    }
    .rpc-info {
        font-size: 0.8rem;
        color: #a08030;
        margin-top: 6px;
    }
    .ssl-info {
        font-size: 0.78rem;
        margin-top: 4px;
    }
    .ssl-ok { color: #22c55e; }
    .ssl-warn { color: #eab308; }
    .ssl-expired { color: #ef4444; }
    """

    # Build service cards HTML
    cards_html = ""
    for r in results:
        svc = r["service"]
        is_online = r["is_up"]
        uptime_30d = r.get("uptime_30d")

        # Online/Offline badge
        if is_online:
            badge_html = '<span class="badge badge-online">\u25cf Online</span>'
        else:
            badge_html = '<span class="badge badge-offline">\u25cf Offline</span>'

        # Uptime percentage
        if uptime_30d is not None:
            pct_html = f'<span class="uptime-pct">{uptime_30d:.1f}%</span>'
        else:
            pct_html = '<span class="uptime-pct">--</span>'

        # 30-day meter
        daily = get_daily_status(svc, days=30)
        if daily:
            segments = ""
            for date_str, status in daily:
                title = f"{date_str}: {status}"
                segments += (
                    f'<span class="meter-segment {status}" '
                    f'title="{title}"></span>'
                )
        else:
            segments = (
                '<span class="meter-segment no-data" '
                'title="No data yet"></span>' * 30
            )

        # SSL info
        ssl_html = ""
        if r.get("has_ssl") and r.get("days_left") is not None:
            days_left = r["days_left"]
            expiry = ""
            if r.get("expiry_dt"):
                expiry = r["expiry_dt"].strftime("%Y-%m-%d %H:%M UTC")
            if days_left <= 0:
                ssl_html = (
                    f'<div class="ssl-info ssl-expired">'
                    f'\u2717 SSL EXPIRED \u2014 Expires: {expiry}</div>'
                )
            elif days_left <= SSL_WARNING_DAYS:
                ssl_html = (
                    f'<div class="ssl-info ssl-warn">'
                    f'\u26a0 SSL expires in {days_left} days '
                    f'({expiry})</div>'
                )
            else:
                ssl_html = (
                    f'<div class="ssl-info ssl-ok">'
                    f'\u2713 SSL OK \u2014 {days_left} days remaining</div>'
                )

        # RPC info
        rpc_html = ""
        if r.get("is_rpc") and r.get("block_height") is not None:
            height = f"{r['block_height']:,}"
            if r.get("blocks_behind") is not None and r["blocks_behind"] > 0:
                height += f" (-{r['blocks_behind']:,} behind)"
            rpc_html = f'<div class="rpc-info">\u26d3 Block height: {height}</div>'

        cards_html += f"""
        <div class="service-card">
            <div class="service-name">{svc}</div>
            <div class="service-meta">
                {badge_html}
                <div>
                    <div class="uptime-label">30-Day Uptime</div>
                    {pct_html}
                </div>
            </div>
            {rpc_html}
            {ssl_html}
            <div class="meter-section">
                <div class="meter-label">30-Day History</div>
                <div class="meter-bar">{segments}</div>
                <div class="meter-legend">
                    <span><span class="legend-dot green"></span> Up (&lt;5m downtime)</span>
                    <span><span class="legend-dot yellow"></span> Brief outage</span>
                    <span><span class="legend-dot red"></span> Extended outage</span>
                </div>
            </div>
        </div>"""

    # Full HTML page
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta http-equiv="refresh" content="120">
<title>PulseSentry - Status</title>
<style>{css}</style>
</head>
<body>

<div class="header">
    <h1>\u26a1 PulseSentry</h1>
    <div class="subtitle">Service Status Dashboard &bull; Generated {generated_str}</div>
</div>

<div class="container">
{cards_html}
</div>

<div class="footer">
    PulseSentry v{VERSION} &bull; Auto-refreshes every 2 minutes &bull; by freQniK
</div>

</body>
</html>"""

    # Write to CWD
    out_path = Path(output_path)
    try:
        out_path.write_text(html, encoding="utf-8")
        console.print(
            f"[green][INFO][/green] Status page published to "
            f"[bold]{out_path.resolve()}[/bold]"
        )
    except OSError as e:
        console.print(
            f"[red][ERROR][/red] Failed to write status page: {e}"
        )

def render(results, interval, chain_tip):
    """Clear screen and render full dashboard."""
    console.clear()
    print_banner()
    console.print(build_table(results))
    console.print(build_summary(results, interval, chain_tip))

def main():
    parser = argparse.ArgumentParser(
        description="PulseSentry - Service, SSL & RPC Monitor"
    )
    parser.add_argument(
        "input_file",
        help="File containing host:PORT entries (one per line)"
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=60,
        help="Check interval in seconds (default: 60)"
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Run a single check and exit"
    )
    parser.add_argument(
        "--publish-html",
        action="store_true",
        help="Publish a static HTML status page after each check cycle"
    )
    parser.add_argument(
        "--html-output",
        default=HTML_OUTPUT,
        help=f"Path for the HTML status page (default: {HTML_OUTPUT})"
    )
    args = parser.parse_args()

    if not Path(args.input_file).exists():
        console.print(
            f"[red][ERROR][/red] Input file not found: {args.input_file}"
        )
        sys.exit(1)

    init_db()
    services = parse_services_file(args.input_file)
    if not services:
        console.print("[red][ERROR][/red] No valid services found")
        sys.exit(1)

    # If --publish-html used with --once, just generate and exit
    # after the check cycle (consistent behavior)
    try:
        while True:
            # Phase 1: gather all check data
            results = []
            for host, port in services:
                results.append(check_service(host, port))

            # Phase 2: evaluate RPC lag now that all heights are known,
            # then record to DB, track state, and compute uptime percentages
            chain_tip = evaluate_rpc_lag(results)

            # Phase 3: send notifications based on final state
            for result in results:
                handle_notifications(result, chain_tip)

            render(results, args.interval, chain_tip)

            # Phase 4: publish HTML status page if requested
            if args.publish_html:
                publish_status_page(results, args.html_output)

            if args.once:
                break

            for remaining in range(args.interval, 0, -1):
                console.print(
                    f"[dim]Next check in {remaining}s... "
                    f"(Ctrl+C to quit)[/dim]",
                    end="\r"
                )
                time.sleep(1)
    except KeyboardInterrupt:
        console.print(
            "\n[bold yellow]PulseSentry stopped by user[/bold yellow]"
        )
        sys.exit(0)

if __name__ == "__main__":
    main()
