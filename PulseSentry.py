#!/usr/bin/env python3
"""
PulseSentry - Service, SSL & Blockchain RPC Monitor with Telegram Alerts
"""

import argparse
import socket
import ssl
import sqlite3
import sys
import time
import os
from datetime import datetime, timezone
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
VERSION = "1.2.0"
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
    cur.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            service TEXT NOT NULL,
            alert_type TEXT NOT NULL,
            last_sent REAL NOT NULL,
            PRIMARY KEY (service, alert_type)
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
        return Text("—", style="dim")
    if not result["has_ssl"]:
        return Text("No SSL", style="dim white")
    days = result["days_left"]
    if days is None:
        return Text("Unknown", style="yellow")
    if days <= 0:
        return Text("✗ EXPIRED", style="bold red")
    if days <= SSL_WARNING_DAYS:
        return Text(f"⚠ {days}d left", style="bold yellow")
    return Text(f"✓ OK ({days}d)", style="bold green")

def format_expiry(result):
    """Format SSL expiry date."""
    if not result["tcp_up"] or not result["has_ssl"]:
        return Text("—", style="dim")
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
        return Text("—", style="dim")
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
        f"[bold green]● UP:[/bold green] {up}",
        f"[bold red]● DOWN:[/bold red] {down}",
        f"[bold yellow]⚠ SSL Warn:[/bold yellow] {ssl_warn}",
        f"[bold red]✗ SSL Exp:[/bold red] {ssl_exp}",
        f"[bold cyan]⛓ RPC OK:[/bold cyan] {rpc_ok}/{rpc_total}",
        f"[bold red]⛓ Lagging:[/bold red] {rpc_lag}",
    ]
    if chain_tip is not None:
        parts.append(f"[bold magenta]Tip:[/bold magenta] {chain_tip:,}")
    parts.append(f"[cyan]Interval:[/cyan] {interval}s")
    parts.append(
        f"[cyan]Last:[/cyan] {datetime.now().strftime('%H:%M:%S')}"
    )

    return Panel(
        "  •  ".join(parts),
        border_style="bright_yellow",
        box=box.ROUNDED,
        padding=(0, 1)
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

    try:
        while True:
            # Phase 1: gather all check data
            results = []
            for host, port in services:
                results.append(check_service(host, port))

            # Phase 2: evaluate RPC lag now that all heights are known,
            # then record to DB and compute uptime percentages
            chain_tip = evaluate_rpc_lag(results)

            # Phase 3: send notifications based on final state
            for result in results:
                handle_notifications(result, chain_tip)

            render(results, args.interval, chain_tip)

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