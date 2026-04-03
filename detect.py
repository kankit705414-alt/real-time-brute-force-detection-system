from __future__ import annotations

import os
import time
from collections import defaultdict, deque
from pathlib import Path

LOG_PATH = Path("auth.log")
TIME_WINDOW = 15
POLL_INTERVAL = 0.5
REFRESH_INTERVAL = 1.0

IP_THRESHOLD = 5
USER_SPRAY_THRESHOLD = 4
PASSWORD_SPRAY_THRESHOLD = 4
IP_USER_SPREAD_THRESHOLD = 5
MAX_ALERTS = 12
TOP_ROWS = 8

ip_events = defaultdict(deque)
user_events = defaultdict(deque)
password_events = defaultdict(deque)
ip_to_users = defaultdict(deque)
user_to_ips = defaultdict(deque)

blocked_ips = set()
blocked_users = set()
total_by_ip = defaultdict(int)
total_by_user = defaultdict(int)
total_by_password = defaultdict(int)
blocked_retries = defaultdict(int)
alerts = deque(maxlen=MAX_ALERTS)
last_event = "waiting for log activity"


def extract_field(parts: list[str], key: str, default: str = "unknown") -> str:
    prefix = f"{key}="
    for part in parts:
        if part.startswith(prefix):
            return part[len(prefix) :]
    return default


def cleanup_events(current_time: float) -> None:
    expiry = current_time - TIME_WINDOW

    for events in ip_events.values():
        while events and events[0] < expiry:
            events.popleft()

    for events in user_events.values():
        while events and events[0][0] < expiry:
            events.popleft()

    for events in password_events.values():
        while events and events[0][0] < expiry:
            events.popleft()

    for events in ip_to_users.values():
        while events and events[0][0] < expiry:
            events.popleft()

    for events in user_to_ips.values():
        while events and events[0][0] < expiry:
            events.popleft()


def remember_alert(kind: str, subject: str, detail: str) -> None:
    alerts.appendleft(f"{kind:<14} {subject:<18} {detail}")


def block_ip(ip: str, reason: str) -> None:
    if ip not in blocked_ips:
        blocked_ips.add(ip)
        remember_alert("BLOCK_IP", ip, reason)


def block_user(user: str, reason: str) -> None:
    if user not in blocked_users:
        blocked_users.add(user)
        remember_alert("BLOCK_USER", user, reason)


def count_unique_recent(events: deque[tuple[float, str]]) -> int:
    return len({value for _, value in events})


def process_line(line: str) -> None:
    global last_event

    if "Failed login" not in line:
        return

    parts = line.split()
    if not parts:
        return

    current_time = time.time()
    ip = parts[0]
    user = parts[4] if len(parts) > 4 else "unknown"
    password = extract_field(parts, "password")

    cleanup_events(current_time)

    total_by_ip[ip] += 1
    total_by_user[user] += 1
    total_by_password[password] += 1

    ip_events[ip].append(current_time)
    user_events[user].append((current_time, ip))
    password_events[password].append((current_time, user))
    ip_to_users[ip].append((current_time, user))
    user_to_ips[user].append((current_time, ip))

    if ip in blocked_ips:
        blocked_retries[ip] += 1
        last_event = (
            f"ignored retry from blocked ip={ip} user={user} "
            f"password={password} total={total_by_ip[ip]}"
        )
        remember_alert("IGNORED", ip, f"retry={blocked_retries[ip]} user={user}")
        return

    last_event = f"failed login ip={ip} user={user} password={password}"

    ip_window = len(ip_events[ip])
    user_ip_spread = count_unique_recent(user_to_ips[user])
    password_user_spread = count_unique_recent(password_events[password])
    ip_user_spread = count_unique_recent(ip_to_users[ip])

    if ip_window >= IP_THRESHOLD:
        remember_alert(
            "IP_BRUTE_FORCE",
            ip,
            f"window={ip_window} user={user} password={password}",
        )
        block_ip(ip, f"window={ip_window}")

    if user_ip_spread >= USER_SPRAY_THRESHOLD:
        remember_alert(
            "USER_SPRAY",
            user,
            f"ips={user_ip_spread} latest_ip={ip}",
        )
        block_user(user, f"ips={user_ip_spread}")

    if password_user_spread >= PASSWORD_SPRAY_THRESHOLD:
        remember_alert(
            "PASSWORD_SPRAY",
            password,
            f"users={password_user_spread} latest_user={user}",
        )

    if ip_user_spread >= IP_USER_SPREAD_THRESHOLD:
        remember_alert(
            "IP_SPREAD",
            ip,
            f"users={ip_user_spread} latest_user={user}",
        )
        block_ip(ip, f"users={ip_user_spread}")


def make_table(title: str, headers: list[str], rows: list[list[str]]) -> str:
    widths = [len(header) for header in headers]
    for row in rows:
        for index, value in enumerate(row):
            widths[index] = max(widths[index], len(value))

    def fmt(row: list[str]) -> str:
        return " | ".join(value.ljust(widths[index]) for index, value in enumerate(row))

    border = "-+-".join("-" * width for width in widths)
    lines = [title, fmt(headers), border]
    lines.extend(fmt(row) for row in rows)
    if not rows:
        lines.append("(no data yet)")
    return "\n".join(lines)


def build_ip_rows() -> list[list[str]]:
    rows = []
    for ip, total in sorted(total_by_ip.items(), key=lambda item: item[1], reverse=True)[:TOP_ROWS]:
        rows.append(
            [
                ip,
                str(total),
                str(len(ip_events[ip])),
                str(count_unique_recent(ip_to_users[ip])),
                "yes" if ip in blocked_ips else "no",
                str(blocked_retries[ip]),
            ]
        )
    return rows


def build_user_rows() -> list[list[str]]:
    rows = []
    for user, total in sorted(total_by_user.items(), key=lambda item: item[1], reverse=True)[:TOP_ROWS]:
        rows.append(
            [
                user,
                str(total),
                str(count_unique_recent(user_to_ips[user])),
                "yes" if user in blocked_users else "no",
            ]
        )
    return rows


def build_password_rows() -> list[list[str]]:
    rows = []
    for password, total in sorted(total_by_password.items(), key=lambda item: item[1], reverse=True)[:TOP_ROWS]:
        rows.append(
            [
                password,
                str(total),
                str(count_unique_recent(password_events[password])),
            ]
        )
    return rows


def render_dashboard() -> None:
    os.system("cls")
    print(
        f"Live Brute-Force Detection Dashboard\n"
        f"log={LOG_PATH} window={TIME_WINDOW}s poll={POLL_INTERVAL}s\n"
        f"blocked_ips={len(blocked_ips)} blocked_users={len(blocked_users)}\n"
        f"last_event={last_event}\n"
    )

    print(
        make_table(
            "IP Activity",
            ["ip", "total", "window", "uniq_users", "blocked", "retries"],
            build_ip_rows(),
        )
    )
    print()
    print(
        make_table(
            "User Activity",
            ["user", "total", "uniq_ips", "blocked"],
            build_user_rows(),
        )
    )
    print()
    print(
        make_table(
            "Password Activity",
            ["password", "total", "uniq_users"],
            build_password_rows(),
        )
    )
    print()
    print("Recent Alerts")
    print("-" * 70)
    if alerts:
        for item in alerts:
            print(item)
    else:
        print("(no alerts yet)")


def follow_log() -> None:
    LOG_PATH.touch(exist_ok=True)
    print(f"[INFO] Watching {LOG_PATH} live. Press Ctrl+C to stop.", flush=True)

    with LOG_PATH.open("r", encoding="utf-8") as handle:
        handle.seek(0, 2)
        last_refresh = 0.0

        while True:
            line = handle.readline()
            if line:
                process_line(line.strip())
            else:
                time.sleep(POLL_INTERVAL)

            now = time.time()
            cleanup_events(now)
            if now - last_refresh >= REFRESH_INTERVAL:
                render_dashboard()
                last_refresh = now


if __name__ == "__main__":
    try:
        follow_log()
    except KeyboardInterrupt:
        print("\n[INFO] Live detection stopped.", flush=True)
