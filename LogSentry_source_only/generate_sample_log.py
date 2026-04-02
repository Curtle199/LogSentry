import os
import random
from datetime import datetime, timedelta
from typing import List, Tuple


AUTH_TARGET_USERS = [
    "root", "admin", "backup", "support", "svc_web", "svc_db", "oracle",
    "postgres", "ubuntu", "ec2-user", "analytics", "ansible", "deploy",
]

NORMAL_USERS = [
    "analyst", "helpdesk", "reporting", "ops", "api-service", "scheduler",
]

SOURCE_IPS = {
    "baseline": ["10.0.0.5", "10.0.0.8", "10.0.0.12", "10.0.0.18", "10.0.0.22", "10.0.0.31"],
    "recon": ["198.51.100.77", "198.51.100.91"],
    "bruteforce": ["203.0.113.50"],
    "spray": ["203.0.113.61", "203.0.113.88"],
}


class SampleLogBuilder:
    def __init__(self, seed: int = 42):
        self.rng = random.Random(seed)
        self.base = datetime(2026, 4, 1, 10, 0, 0)
        self.events: List[Tuple[datetime, str]] = []

    def add(self, offset_seconds: int, text: str, fmt: str = "iso") -> None:
        timestamp = self.base + timedelta(seconds=offset_seconds)
        if fmt == "syslog":
            stamp = timestamp.strftime("%b %d %H:%M:%S")
            line = f"{stamp} {text}"
        else:
            stamp = timestamp.strftime("%Y-%m-%d %H:%M:%S")
            line = f"{stamp} {text}"
        self.events.append((timestamp, line))

    def add_baseline(self, count: int = 50, include_syslog_mix: bool = True) -> None:
        for i in range(count):
            offset = 5 + (i * self.rng.randint(3, 8))
            user = self.rng.choice(NORMAL_USERS)
            ip = self.rng.choice(SOURCE_IPS["baseline"])
            route = self.rng.choice(["/api/status", "/api/orders", "/login", "/reports", "/health"])
            latency = self.rng.randint(12, 48)
            fmt = "syslog" if include_syslog_mix and i % 7 == 0 else "iso"

            choice = self.rng.choice(["login", "session", "heartbeat", "request"])
            if choice == "login":
                self.add(offset, f"INFO login successful for {user} from {ip}", fmt=fmt)
            elif choice == "session":
                self.add(offset, f"INFO session opened for user {user} from {ip}", fmt=fmt)
            elif choice == "heartbeat":
                self.add(offset, f"INFO application heartbeat ok route={route} latency={latency}ms", fmt=fmt)
            else:
                status = self.rng.choice([200, 200, 200, 201, 204])
                self.add(offset, f"INFO web01 route={route} latency={latency}ms status={status} source={ip}", fmt=fmt)

    def add_recon(self) -> None:
        offset = 180
        for ip in SOURCE_IPS["recon"]:
            for user in self.rng.sample(AUTH_TARGET_USERS, 8):
                self.add(offset, f"WARN sshd failed password for invalid user {user} from {ip}")
                offset += self.rng.randint(2, 5)
                if self.rng.random() < 0.35:
                    self.add(offset, f"WARN failed login attempt from {ip}")
                    offset += 1
                if self.rng.random() < 0.25:
                    self.add(offset, f"WARN authentication failure from {ip}")
                    offset += 1

    def add_password_spray(self) -> None:
        offset = 260
        for ip in SOURCE_IPS["spray"]:
            for user in ["admin", "backup", "support", "ops", "service", "devops"]:
                self.add(offset, f"WARN login failed from {ip}")
                self.add(offset + 1, f"WARN sshd failed password for invalid user {user} from {ip}")
                offset += self.rng.randint(4, 9)

    def add_brute_force_burst(self) -> None:
        offset = 340
        ip = SOURCE_IPS["bruteforce"][0]
        for i in range(28):
            user = AUTH_TARGET_USERS[i % len(AUTH_TARGET_USERS)]
            self.add(offset, f"WARN sshd failed password for invalid user {user} from {ip}")
            if i % 3 == 0:
                self.add(offset + 1, f"WARN authentication failure from {ip}")
            if i % 4 == 0:
                self.add(offset + 2, f"WARN failed login attempt from {ip}")
            offset += self.rng.randint(1, 3)

        self.add(offset + 6, f"INFO sshd accepted password for backup from {ip}")
        self.add(offset + 10, f"INFO session opened for user backup from {ip}")
        self.add(offset + 16, f"INFO session opened for user root from {ip}")

    def add_service_flood(self) -> None:
        offset = 470
        ip = SOURCE_IPS["bruteforce"][0]
        routes = ["/login", "/checkout", "/api/orders", "/reports"]
        for i in range(18):
            route = self.rng.choice(routes)
            self.add(offset, f"WARN reverse proxy timeout upstream=api01 route={route} source={ip}")
            self.add(offset + 1, f"WARN upstream latency increased avg_latency={self.rng.randint(650, 1400)}ms source={ip}")
            self.add(offset + 2, f"WARN HTTP 503 surge detected route={route} source={ip}")
            self.add(offset + 3, f"WARN active connections exceeded threshold source={ip}")
            self.add(offset + 4, f"WARN request queue depth elevated source={ip}")
            if i % 2 == 0:
                self.add(offset + 5, f"WARN connection pool saturation source={ip}")
            if i % 3 == 0:
                self.add(offset + 6, f"WARN health check failed upstream=api01 source={ip}")
            offset += self.rng.randint(4, 8)

        self.add(offset + 4, f"CRITICAL syn flood suspected interface=wan0 source={ip}")
        self.add(offset + 8, f"WARN firewall rate limit triggered source={ip}")
        self.add(offset + 12, f"WARN emergency rate limiting enabled source={ip}")
        self.add(offset + 16, f"WARN worker exhaustion max_workers reached source={ip}")
        self.add(offset + 20, f"WARN gateway timeout route=/checkout source={ip}")
        self.add(offset + 24, f"WARN service unavailable route=/checkout source={ip}")

    def add_recovery(self) -> None:
        offset = 760
        ip = SOURCE_IPS["bruteforce"][0]
        self.add(offset, f"INFO firewall throttle released source={ip}")
        self.add(offset + 6, "INFO application heartbeat ok route=/api/status latency=42ms")
        self.add(offset + 10, "INFO login succeeded for reporting from 10.0.0.12")
        self.add(offset + 14, "INFO session opened for user reporting from 10.0.0.12")
        self.add(offset + 18, "INFO web01 route=/api/orders latency=24ms status=200 source=10.0.0.18")
        self.add(offset + 24, "INFO web01 route=/reports latency=31ms status=200 source=10.0.0.31")

    def add_noise(self, count: int = 40) -> None:
        start = 40
        for i in range(count):
            offset = start + self.rng.randint(0, 760)
            route = self.rng.choice(["/api/status", "/health", "/reports", "/search", "/api/orders"])
            ip = self.rng.choice(SOURCE_IPS["baseline"])
            latency = self.rng.randint(14, 90)
            status = self.rng.choice([200, 200, 200, 201, 204, 304])
            fmt = "syslog" if i % 9 == 0 else "iso"
            self.add(offset, f"INFO web01 route={route} latency={latency}ms status={status} source={ip}", fmt=fmt)

    def build_lines(self) -> List[str]:
        self.events.sort(key=lambda item: item[0])
        return [line for _, line in self.events]


def write_sample_log(
    output_path: str,
    profile: str = "full_incident",
    seed: int = 42,
    include_noise: bool = True,
    include_syslog_mix: bool = True,
) -> tuple[str, int]:
    """
    Generate a richer sample log.

    Profiles:
    - full_incident: baseline + recon + spray + brute force + service flood + recovery
    - auth_focus: heavier authentication abuse, lighter web/app noise
    - availability_focus: lighter auth abuse, heavier service-flood sequence
    """
    builder = SampleLogBuilder(seed=seed)

    if profile == "auth_focus":
        builder.add_baseline(count=35, include_syslog_mix=include_syslog_mix)
        builder.add_recon()
        builder.add_password_spray()
        builder.add_brute_force_burst()
        builder.add_recovery()
        if include_noise:
            builder.add_noise(count=20)
    elif profile == "availability_focus":
        builder.add_baseline(count=45, include_syslog_mix=include_syslog_mix)
        builder.add_recon()
        builder.add_service_flood()
        builder.add_recovery()
        if include_noise:
            builder.add_noise(count=35)
    else:
        builder.add_baseline(count=55, include_syslog_mix=include_syslog_mix)
        builder.add_recon()
        builder.add_password_spray()
        builder.add_brute_force_burst()
        builder.add_service_flood()
        builder.add_recovery()
        if include_noise:
            builder.add_noise(count=45)

    lines = builder.build_lines()
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")

    return output_path, len(lines)
