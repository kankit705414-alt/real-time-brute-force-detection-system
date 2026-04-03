from __future__ import annotations

import argparse
import random
import time
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Append fake login events to a local auth log for safe lab testing."
    )
    parser.add_argument(
        "--log",
        default="auth.log",
        help="Path to the auth log file (default: auth.log)",
    )
    parser.add_argument(
        "--ip",
        default=None,
        help="Source IP address to write into the fake log entries",
    )
    parser.add_argument(
        "--user",
        default=None,
        help="Username to include in the fake log entries",
    )
    parser.add_argument(
        "--password",
        default=None,
        help="Password to include in the fake log entries",
    )
    parser.add_argument(
        "--failures",
        type=int,
        default=12,
        help="Number of fake failed login attempts to write (default: 12)",
    )
    parser.add_argument(
        "--mode",
        choices=["single", "spray"],
        default="single",
        help="single reuses one identity, spray rotates ip/user/password every attempt",
    )
    parser.add_argument(
        "--spray-pattern",
        choices=["user", "password", "mixed"],
        default="mixed",
        help="When using spray mode, choose whether repeated attempts pivot on user, password, or both",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=0.5,
        help="Delay in seconds between log entries (default: 0.5)",
    )
    parser.add_argument(
        "--success",
        action="store_true",
        help="Append one fake successful login after the failures",
    )
    return parser.parse_args()


def random_ip() -> str:
    return (
        f"10.{random.randint(1, 254)}.{random.randint(1, 254)}."
        f"{random.randint(1, 254)}"
    )


def random_user() -> str:
    return f"user{random.randint(100, 999)}"


def random_password() -> str:
    adjectives = ["red", "fast", "silent", "brave", "sharp"]
    nouns = ["fox", "node", "shield", "falcon", "vector"]
    return (
        f"{random.choice(adjectives)}"
        f"{random.choice(nouns)}{random.randint(100, 999)}"
    )


def main() -> int:
    args = parse_args()

    if args.failures < 0:
        print("[ERROR] Failures must be 0 or greater.")
        return 1

    if args.delay < 0:
        print("[ERROR] Delay must be 0 or greater.")
        return 1

    log_path = Path(args.log)
    base_ip = args.ip or random_ip()
    base_user = args.user or random_user()
    base_password = args.password or random_password()
    spray_users = [base_user, random_user(), random_user()]
    spray_passwords = [base_password, random_password(), random_password()]

    print(f"[LAB] Mode={args.mode} base_ip={base_ip} base_user={base_user} base_password={base_password}")

    with log_path.open("a", encoding="utf-8") as handle:
        for attempt in range(1, args.failures + 1):
            if args.mode == "spray":
                ip = random_ip()
                if args.spray_pattern == "user":
                    user = base_user
                    password = random_password()
                elif args.spray_pattern == "password":
                    user = random.choice(spray_users)
                    password = base_password
                else:
                    user = spray_users[(attempt - 1) % len(spray_users)]
                    password = spray_passwords[(attempt - 1) % len(spray_passwords)]
            else:
                ip = base_ip
                user = base_user
                password = base_password

            handle.write(
                f"{ip} Failed login for {user} password={password} "
                f"attempt={attempt} request_id={random.randint(1000, 9999)}\n"
            )
            handle.flush()
            print(
                f"[LAB] Wrote failed login {attempt}/{args.failures} "
                f"for ip={ip} user={user} password={password}"
            )
            time.sleep(args.delay)

        if args.success:
            handle.write(f"{ip} Successful login for {user} password={password}\n")
            handle.flush()
            print(f"[LAB] Wrote successful login for {ip}")

    print(f"[INFO] Fake login simulation finished. Log written to {log_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
