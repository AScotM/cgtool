#!/usr/bin/env python3

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import logging
import math
import os
import platform
import pwd
import signal
import socket
import stat
import struct
import sys
import time
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Set, Tuple


APP_NAME = "cgtool"
APP_VERSION = "0.2.0"

PROC_NET_DEV_HEADER_LINES = 2
SIOCGIFADDR = 0x8915

DEFAULT_INTERVAL = 2.0
DEFAULT_LIMIT = 20
DEFAULT_DISK_LIMIT = 50
DEFAULT_CHUNK_SIZE = 1024 * 1024
DEFAULT_MAX_DEPTH = 2

BYTES_PER_KIB = 1024
BYTES_PER_MIB = 1024 * 1024
BYTES_PER_GIB = 1024 * 1024 * 1024
BYTES_PER_TIB = 1024 * 1024 * 1024 * 1024
BYTES_PER_PIB = 1024 * 1024 * 1024 * 1024 * 1024

UNITS = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"]

PPS_MILLION = 1_000_000
PPS_THOUSAND = 1_000

PRINTABLE_MIN = 32
PRINTABLE_MAX = 126
WHITESPACE_CHARS = (9, 10, 13)

TCP_STATES = {
    "01": "ESTABLISHED",
    "02": "SYN_SENT",
    "03": "SYN_RECV",
    "04": "FIN_WAIT1",
    "05": "FIN_WAIT2",
    "06": "TIME_WAIT",
    "07": "CLOSE",
    "08": "CLOSE_WAIT",
    "09": "LAST_ACK",
    "0A": "LISTEN",
    "0B": "CLOSING",
    "0C": "NEW_SYN_RECV",
}

UDP_STATES = {
    "01": "ESTABLISHED",
    "07": "UNCONN",
}

_stop_requested = False

logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")
logger = logging.getLogger(APP_NAME)


@dataclass
class NetSnapshot:
    iface: str
    operstate: str
    ipv4: Optional[str]
    mtu: Optional[int]
    rx_bytes: int
    tx_bytes: int
    rx_packets: int
    tx_packets: int
    rx_errs: int
    tx_errs: int
    rx_drop: int
    tx_drop: int


@dataclass
class ProcSnapshot:
    pid: int
    ppid: int
    uid: int
    user: str
    name: str
    state: str
    threads: int
    rss_bytes: int
    vms_bytes: int
    utime_ticks: int
    stime_ticks: int
    total_ticks: int
    starttime_ticks: int
    cmdline: str


@dataclass
class ProcRow:
    pid: int
    ppid: int
    uid: int
    user: str
    name: str
    state: str
    threads: int
    cpu_pct: float
    rss_bytes: int
    vms_bytes: int
    cmdline: str


@dataclass
class DiskEntry:
    path: str
    kind: str
    size: int
    mode: str
    uid: int
    gid: int
    mtime: float
    inode: int


@dataclass
class EntropyReport:
    path: str
    size: int
    sha256: str
    entropy: float
    printable_ratio: float
    null_ratio: float
    top_bytes: List[Tuple[int, int]]


@dataclass
class MountEntry:
    source: str
    target: str
    fstype: str
    options: str
    total_bytes: Optional[int]
    used_bytes: Optional[int]
    available_bytes: Optional[int]
    used_pct: Optional[float]


@dataclass
class SocketEntry:
    protocol: str
    family: str
    local_address: str
    local_port: int
    remote_address: str
    remote_port: int
    state: str
    uid: int
    inode: int


@dataclass
class SystemReport:
    hostname: str
    kernel: str
    architecture: str
    distribution: str
    uptime_seconds: float
    load_1m: float
    load_5m: float
    load_15m: float
    cpu_count: int
    mem_total: int
    mem_available: int
    mem_used: int
    swap_total: int
    swap_free: int
    swap_used: int
    processes: int


def signal_handler(_signum: int, _frame: Any) -> None:
    global _stop_requested
    _stop_requested = True


def install_signal_handlers() -> None:
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)


def human_bytes(value: float) -> str:
    negative = value < 0
    value = abs(float(value))
    idx = 0

    while value >= BYTES_PER_KIB and idx < len(UNITS) - 1:
        value /= BYTES_PER_KIB
        idx += 1

    prefix = "-" if negative else ""
    return f"{prefix}{value:.2f} {UNITS[idx]}"


def human_rate(value: float) -> str:
    return f"{human_bytes(value)}/s"


def format_pps(value: float) -> str:
    if value >= PPS_MILLION:
        return f"{value / PPS_MILLION:.2f} Mpps"
    if value >= PPS_THOUSAND:
        return f"{value / PPS_THOUSAND:.2f} Kpps"
    return f"{value:.2f} pps"


def format_duration(seconds: float) -> str:
    seconds = max(int(seconds), 0)
    days, seconds = divmod(seconds, 86400)
    hours, seconds = divmod(seconds, 3600)
    minutes, seconds = divmod(seconds, 60)

    parts = []

    if days:
        parts.append(f"{days}d")
    if hours or days:
        parts.append(f"{hours}h")
    if minutes or hours or days:
        parts.append(f"{minutes}m")
    parts.append(f"{seconds}s")

    return " ".join(parts)


def json_dump(data: Any) -> None:
    print(json.dumps(data, indent=2, ensure_ascii=False))


def read_text(path: Path) -> Optional[str]:
    try:
        return path.read_text(encoding="utf-8", errors="replace").strip()
    except (FileNotFoundError, PermissionError, OSError) as exc:
        logger.debug("Failed to read %s: %s", path, exc)
        return None


def read_bytes(path: Path) -> Optional[bytes]:
    try:
        return path.read_bytes()
    except (FileNotFoundError, PermissionError, OSError) as exc:
        logger.debug("Failed to read %s: %s", path, exc)
        return None


def read_int(path: Path) -> Optional[int]:
    value = read_text(path)

    if value is None:
        return None

    try:
        return int(value)
    except ValueError:
        return None


def safe_username(uid: int) -> str:
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return str(uid)


def clear_screen() -> None:
    if sys.stdout.isatty():
        print("\033[2J\033[H", end="")


def sleep_interruptible(seconds: float) -> None:
    deadline = time.monotonic() + seconds

    while not _stop_requested:
        remaining = deadline - time.monotonic()

        if remaining <= 0:
            return

        time.sleep(min(remaining, 0.2))


def validate_positive_interval(interval: float) -> bool:
    if interval <= 0:
        print("interval must be positive", file=sys.stderr)
        return False

    return True


def validate_limit(limit: int) -> bool:
    if limit < 0:
        print("limit must be zero or greater", file=sys.stderr)
        return False

    return True


def apply_limit(rows: List[Any], limit: int) -> List[Any]:
    if limit == 0:
        return rows

    return rows[:limit]


def get_ipv4_for_iface(iface: str) -> Optional[str]:
    if not iface:
        return None

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            request = struct.pack("256s", iface.encode("utf-8")[:15])
            result = fcntl.ioctl(sock.fileno(), SIOCGIFADDR, request)
            return socket.inet_ntoa(result[20:24])
    except OSError:
        return None


def get_interfaces() -> List[str]:
    base = Path("/sys/class/net")

    try:
        return sorted(entry.name for entry in base.iterdir())
    except OSError:
        return []


def parse_proc_net_dev() -> Dict[str, Dict[str, int]]:
    result: Dict[str, Dict[str, int]] = {}
    text = read_text(Path("/proc/net/dev"))

    if not text:
        return result

    lines = text.splitlines()

    for line in lines[PROC_NET_DEV_HEADER_LINES:]:
        if ":" not in line:
            continue

        left, right = line.split(":", 1)
        iface = left.strip()
        parts = right.split()

        if len(parts) < 16:
            continue

        try:
            result[iface] = {
                "rx_bytes": int(parts[0]),
                "rx_packets": int(parts[1]),
                "rx_errs": int(parts[2]),
                "rx_drop": int(parts[3]),
                "tx_bytes": int(parts[8]),
                "tx_packets": int(parts[9]),
                "tx_errs": int(parts[10]),
                "tx_drop": int(parts[11]),
            }
        except ValueError:
            continue

    return result


def collect_net(ifaces: Optional[List[str]] = None) -> List[NetSnapshot]:
    all_stats = parse_proc_net_dev()
    selected = ifaces if ifaces else get_interfaces()
    snapshots: List[NetSnapshot] = []

    for iface in selected:
        stats = all_stats.get(iface)

        if stats is None:
            continue

        snapshots.append(
            NetSnapshot(
                iface=iface,
                operstate=read_text(
                    Path("/sys/class/net") / iface / "operstate"
                ) or "unknown",
                ipv4=get_ipv4_for_iface(iface),
                mtu=read_int(Path("/sys/class/net") / iface / "mtu"),
                rx_bytes=stats["rx_bytes"],
                tx_bytes=stats["tx_bytes"],
                rx_packets=stats["rx_packets"],
                tx_packets=stats["tx_packets"],
                rx_errs=stats["rx_errs"],
                tx_errs=stats["tx_errs"],
                rx_drop=stats["rx_drop"],
                tx_drop=stats["tx_drop"],
            )
        )

    return snapshots


def net_rows(
    current: List[NetSnapshot],
    previous: Optional[List[NetSnapshot]],
    elapsed: float,
) -> List[Dict[str, Any]]:
    previous_map = {item.iface: item for item in previous or []}
    rows: List[Dict[str, Any]] = []

    for item in current:
        prev = previous_map.get(item.iface)

        rx_rate = 0.0
        tx_rate = 0.0
        rx_pps = 0.0
        tx_pps = 0.0

        if prev is not None and elapsed > 0:
            rx_rate = max(
                (item.rx_bytes - prev.rx_bytes) / elapsed,
                0.0,
            )
            tx_rate = max(
                (item.tx_bytes - prev.tx_bytes) / elapsed,
                0.0,
            )
            rx_pps = max(
                (item.rx_packets - prev.rx_packets) / elapsed,
                0.0,
            )
            tx_pps = max(
                (item.tx_packets - prev.tx_packets) / elapsed,
                0.0,
            )

        row = asdict(item)
        row["rx_rate"] = rx_rate
        row["tx_rate"] = tx_rate
        row["rx_pps"] = rx_pps
        row["tx_pps"] = tx_pps
        rows.append(row)

    return rows


def print_net_table(rows: List[Dict[str, Any]]) -> None:
    header = (
        f"{'IFACE':<12} "
        f"{'STATE':<10} "
        f"{'IPv4':<16} "
        f"{'MTU':>6} "
        f"{'RX RATE':>13} "
        f"{'TX RATE':>13} "
        f"{'RX PPS':>12} "
        f"{'TX PPS':>12} "
        f"{'RX ERR':>8} "
        f"{'TX ERR':>8} "
        f"{'RX DROP':>8} "
        f"{'TX DROP':>8}"
    )

    print(header)
    print("-" * len(header))

    for row in rows:
        print(
            f"{row['iface']:<12} "
            f"{row['operstate']:<10} "
            f"{(row['ipv4'] or '-'):<16} "
            f"{str(row['mtu'] or '-'):>6} "
            f"{human_rate(row['rx_rate']):>13} "
            f"{human_rate(row['tx_rate']):>13} "
            f"{format_pps(row['rx_pps']):>12} "
            f"{format_pps(row['tx_pps']):>12} "
            f"{row['rx_errs']:>8} "
            f"{row['tx_errs']:>8} "
            f"{row['rx_drop']:>8} "
            f"{row['tx_drop']:>8}"
        )


def parse_proc_pid(pid: int) -> Optional[ProcSnapshot]:
    base = Path("/proc") / str(pid)

    stat_text = read_text(base / "stat")
    statm_text = read_text(base / "statm")

    if not stat_text or not statm_text:
        return None

    try:
        left = stat_text.index("(")
        right = stat_text.rindex(")")

        name = stat_text[left + 1:right]
        rest = stat_text[right + 2:].split()

        if len(rest) < 20:
            return None

        state = rest[0]
        ppid = int(rest[1])
        utime_ticks = int(rest[11])
        stime_ticks = int(rest[12])
        threads = int(rest[17])
        starttime_ticks = int(rest[19])

        statm_parts = statm_text.split()

        if len(statm_parts) < 2:
            return None

        vms_pages = int(statm_parts[0])
        rss_pages = int(statm_parts[1])

        page_size = os.sysconf("SC_PAGE_SIZE")

        try:
            uid = base.stat().st_uid
        except OSError:
            uid = -1

        cmdline_raw = read_bytes(base / "cmdline")
        cmdline = ""

        if cmdline_raw:
            cmdline = (
                cmdline_raw
                .replace(b"\x00", b" ")
                .decode("utf-8", errors="replace")
                .strip()
            )

        return ProcSnapshot(
            pid=pid,
            ppid=ppid,
            uid=uid,
            user=safe_username(uid) if uid >= 0 else "?",
            name=name,
            state=state,
            threads=threads,
            rss_bytes=rss_pages * page_size,
            vms_bytes=vms_pages * page_size,
            utime_ticks=utime_ticks,
            stime_ticks=stime_ticks,
            total_ticks=utime_ticks + stime_ticks,
            starttime_ticks=starttime_ticks,
            cmdline=cmdline or f"[{name}]",
        )

    except (ValueError, IndexError, OSError):
        return None


def read_proc_stat() -> Dict[int, ProcSnapshot]:
    result: Dict[int, ProcSnapshot] = {}
    proc = Path("/proc")

    try:
        entries = list(proc.iterdir())
    except OSError:
        return result

    for entry in entries:
        if not entry.name.isdigit():
            continue

        pid = int(entry.name)
        snapshot = parse_proc_pid(pid)

        if snapshot is not None:
            result[pid] = snapshot

    return result


def build_proc_rows(
    current: Dict[int, ProcSnapshot],
    previous: Optional[Dict[int, ProcSnapshot]],
    elapsed: float,
) -> List[ProcRow]:
    hz = os.sysconf("SC_CLK_TCK")
    rows: List[ProcRow] = []

    for pid, proc in current.items():
        cpu_pct = 0.0

        if previous is not None and elapsed > 0:
            prev = previous.get(pid)

            if (
                prev is not None
                and prev.starttime_ticks == proc.starttime_ticks
            ):
                delta = proc.total_ticks - prev.total_ticks

                if delta >= 0:
                    cpu_pct = (delta / hz) / elapsed * 100.0

        rows.append(
            ProcRow(
                pid=proc.pid,
                ppid=proc.ppid,
                uid=proc.uid,
                user=proc.user,
                name=proc.name,
                state=proc.state,
                threads=proc.threads,
                cpu_pct=max(cpu_pct, 0.0),
                rss_bytes=proc.rss_bytes,
                vms_bytes=proc.vms_bytes,
                cmdline=proc.cmdline,
            )
        )

    return rows


def sort_proc_rows(
    rows: List[ProcRow],
    sort_by: str,
) -> List[ProcRow]:
    if sort_by == "cpu":
        rows.sort(
            key=lambda row: (
                row.cpu_pct,
                row.rss_bytes,
                row.pid,
            ),
            reverse=True,
        )
    elif sort_by == "rss":
        rows.sort(
            key=lambda row: (
                row.rss_bytes,
                row.cpu_pct,
                row.pid,
            ),
            reverse=True,
        )
    elif sort_by == "vms":
        rows.sort(
            key=lambda row: (
                row.vms_bytes,
                row.rss_bytes,
                row.pid,
            ),
            reverse=True,
        )
    elif sort_by == "pid":
        rows.sort(key=lambda row: row.pid)
    elif sort_by == "user":
        rows.sort(
            key=lambda row: (
                row.user.lower(),
                row.pid,
            )
        )
    else:
        rows.sort(
            key=lambda row: (
                row.name.lower(),
                row.pid,
            )
        )

    return rows


def filter_proc_rows(
    rows: List[ProcRow],
    user: Optional[str],
    name: Optional[str],
) -> List[ProcRow]:
    result = rows

    if user:
        result = [
            row
            for row in result
            if row.user == user or str(row.uid) == user
        ]

    if name:
        needle = name.lower()
        result = [
            row
            for row in result
            if needle in row.name.lower()
            or needle in row.cmdline.lower()
        ]

    return result


def print_proc_table(rows: List[ProcRow]) -> None:
    header = (
        f"{'PID':>7} "
        f"{'PPID':>7} "
        f"{'USER':<12} "
        f"{'S':<2} "
        f"{'THR':>5} "
        f"{'CPU%':>8} "
        f"{'RSS':>11} "
        f"{'VMS':>11} "
        f"CMD"
    )

    print(header)
    print("-" * len(header))

    for row in rows:
        print(
            f"{row.pid:>7} "
            f"{row.ppid:>7} "
            f"{row.user[:12]:<12} "
            f"{row.state:<2} "
            f"{row.threads:>5} "
            f"{row.cpu_pct:>8.2f} "
            f"{human_bytes(row.rss_bytes):>11} "
            f"{human_bytes(row.vms_bytes):>11} "
            f"{row.cmdline}"
        )


def disk_kind(mode: int) -> str:
    if stat.S_ISREG(mode):
        return "file"
    if stat.S_ISDIR(mode):
        return "dir"
    if stat.S_ISLNK(mode):
        return "link"
    if stat.S_ISCHR(mode):
        return "char"
    if stat.S_ISBLK(mode):
        return "block"
    if stat.S_ISFIFO(mode):
        return "fifo"
    if stat.S_ISSOCK(mode):
        return "sock"
    return "other"


def iter_disk(
    path: Path,
    max_depth: int,
    follow_symlinks: bool,
) -> Iterator[DiskEntry]:
    visited_dirs: Set[Tuple[int, int]] = set()

    def walk(
        current: Path,
        depth: int,
    ) -> Iterator[DiskEntry]:
        if max_depth >= 0 and depth > max_depth:
            return

        try:
            st = (
                current.stat()
                if follow_symlinks
                else current.lstat()
            )
        except (PermissionError, FileNotFoundError, OSError):
            return

        kind = disk_kind(st.st_mode)

        yield DiskEntry(
            path=str(current),
            kind=kind,
            size=st.st_size,
            mode=stat.filemode(st.st_mode),
            uid=st.st_uid,
            gid=st.st_gid,
            mtime=st.st_mtime,
            inode=st.st_ino,
        )

        if kind != "dir":
            if not (
                follow_symlinks
                and current.is_symlink()
            ):
                return

            try:
                if not current.resolve().is_dir():
                    return
            except OSError:
                return

        try:
            target_stat = current.stat()
        except OSError:
            return

        identity = (
            target_stat.st_dev,
            target_stat.st_ino,
        )

        if identity in visited_dirs:
            return

        visited_dirs.add(identity)

        try:
            children = sorted(
                current.iterdir(),
                key=lambda child: child.name,
            )
        except (
            PermissionError,
            FileNotFoundError,
            NotADirectoryError,
            OSError,
        ):
            return

        for child in children:
            if not follow_symlinks:
                try:
                    if child.is_symlink():
                        child_stat = child.lstat()

                        yield DiskEntry(
                            path=str(child),
                            kind="link",
                            size=child_stat.st_size,
                            mode=stat.filemode(
                                child_stat.st_mode
                            ),
                            uid=child_stat.st_uid,
                            gid=child_stat.st_gid,
                            mtime=child_stat.st_mtime,
                            inode=child_stat.st_ino,
                        )
                        continue
                except OSError:
                    continue

            yield from walk(
                child,
                depth + 1,
            )

    yield from walk(path, 0)


def sort_disk_rows(
    rows: List[DiskEntry],
    sort_by: str,
) -> List[DiskEntry]:
    if sort_by == "size":
        rows.sort(
            key=lambda row: (
                row.size,
                row.path,
            ),
            reverse=True,
        )
    elif sort_by == "mtime":
        rows.sort(
            key=lambda row: (
                row.mtime,
                row.path,
            ),
            reverse=True,
        )
    elif sort_by == "kind":
        rows.sort(
            key=lambda row: (
                row.kind,
                row.path,
            )
        )
    elif sort_by == "inode":
        rows.sort(
            key=lambda row: (
                row.inode,
                row.path,
            )
        )
    else:
        rows.sort(key=lambda row: row.path)

    return rows


def print_disk_table(rows: List[DiskEntry]) -> None:
    header = (
        f"{'KIND':<8} "
        f"{'SIZE':>12} "
        f"{'MODE':<10} "
        f"{'UID':>7} "
        f"{'GID':>7} "
        f"{'INODE':>12} "
        f"{'MTIME':<19} "
        f"PATH"
    )

    print(header)
    print("-" * len(header))

    for entry in rows:
        timestamp = time.strftime(
            "%Y-%m-%d %H:%M:%S",
            time.localtime(entry.mtime),
        )

        print(
            f"{entry.kind:<8} "
            f"{human_bytes(entry.size):>12} "
            f"{entry.mode:<10} "
            f"{entry.uid:>7} "
            f"{entry.gid:>7} "
            f"{entry.inode:>12} "
            f"{timestamp:<19} "
            f"{entry.path}"
        )


def shannon_entropy(
    counter: Counter[int],
    total: int,
) -> float:
    if total <= 0:
        return 0.0

    entropy = 0.0

    for count in counter.values():
        probability = count / total
        entropy -= probability * math.log2(probability)

    return entropy


def analyze_file(
    path: Path,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> EntropyReport:
    sha256 = hashlib.sha256()
    counter: Counter[int] = Counter()

    total = 0
    printable = 0
    nulls = 0

    with path.open("rb") as handle:
        while True:
            chunk = handle.read(chunk_size)

            if not chunk:
                break

            sha256.update(chunk)
            total += len(chunk)
            counter.update(chunk)

            printable += sum(
                1
                for byte in chunk
                if PRINTABLE_MIN <= byte <= PRINTABLE_MAX
                or byte in WHITESPACE_CHARS
            )

            nulls += chunk.count(0)

    return EntropyReport(
        path=str(path),
        size=total,
        sha256=sha256.hexdigest(),
        entropy=shannon_entropy(
            counter,
            total,
        ),
        printable_ratio=(
            printable / total
            if total
            else 0.0
        ),
        null_ratio=(
            nulls / total
            if total
            else 0.0
        ),
        top_bytes=counter.most_common(10),
    )


def print_entropy_report(
    report: EntropyReport,
) -> None:
    print(f"path            : {report.path}")
    print(f"size            : {report.size}")
    print(f"human_size      : {human_bytes(report.size)}")
    print(f"sha256          : {report.sha256}")
    print(f"entropy         : {report.entropy:.4f}")
    print(
        f"printable_ratio : "
        f"{report.printable_ratio:.4f}"
    )
    print(
        f"null_ratio      : "
        f"{report.null_ratio:.4f}"
    )
    print("top_bytes       :")

    for byte_value, count in report.top_bytes:
        print(
            f"  0x{byte_value:02x}  "
            f"{count}"
        )


def parse_os_release() -> Dict[str, str]:
    result: Dict[str, str] = {}
    text = read_text(Path("/etc/os-release"))

    if not text:
        return result

    for line in text.splitlines():
        if "=" not in line:
            continue

        key, value = line.split("=", 1)
        value = value.strip()

        if (
            len(value) >= 2
            and value[0] == value[-1]
            and value[0] in ("'", '"')
        ):
            value = value[1:-1]

        result[key] = value

    return result


def read_uptime() -> float:
    text = read_text(Path("/proc/uptime"))

    if not text:
        return 0.0

    try:
        return float(text.split()[0])
    except (ValueError, IndexError):
        return 0.0


def read_loadavg() -> Tuple[float, float, float]:
    text = read_text(Path("/proc/loadavg"))

    if not text:
        return 0.0, 0.0, 0.0

    parts = text.split()

    try:
        return (
            float(parts[0]),
            float(parts[1]),
            float(parts[2]),
        )
    except (ValueError, IndexError):
        return 0.0, 0.0, 0.0


def read_meminfo() -> Dict[str, int]:
    result: Dict[str, int] = {}
    text = read_text(Path("/proc/meminfo"))

    if not text:
        return result

    for line in text.splitlines():
        if ":" not in line:
            continue

        key, value = line.split(":", 1)
        parts = value.strip().split()

        if not parts:
            continue

        try:
            amount = int(parts[0])
        except ValueError:
            continue

        if len(parts) > 1 and parts[1].lower() == "kb":
            amount *= 1024

        result[key] = amount

    return result


def count_processes() -> int:
    try:
        return sum(
            1
            for entry in Path("/proc").iterdir()
            if entry.name.isdigit()
        )
    except OSError:
        return 0


def collect_system() -> SystemReport:
    os_release = parse_os_release()
    meminfo = read_meminfo()
    load_1m, load_5m, load_15m = read_loadavg()

    mem_total = meminfo.get("MemTotal", 0)
    mem_available = meminfo.get(
        "MemAvailable",
        meminfo.get("MemFree", 0),
    )
    mem_used = max(
        mem_total - mem_available,
        0,
    )

    swap_total = meminfo.get("SwapTotal", 0)
    swap_free = meminfo.get("SwapFree", 0)
    swap_used = max(
        swap_total - swap_free,
        0,
    )

    distribution = (
        os_release.get("PRETTY_NAME")
        or os_release.get("NAME")
        or platform.system()
    )

    return SystemReport(
        hostname=socket.gethostname(),
        kernel=platform.release(),
        architecture=platform.machine(),
        distribution=distribution,
        uptime_seconds=read_uptime(),
        load_1m=load_1m,
        load_5m=load_5m,
        load_15m=load_15m,
        cpu_count=os.cpu_count() or 0,
        mem_total=mem_total,
        mem_available=mem_available,
        mem_used=mem_used,
        swap_total=swap_total,
        swap_free=swap_free,
        swap_used=swap_used,
        processes=count_processes(),
    )


def print_system_report(
    report: SystemReport,
) -> None:
    mem_pct = (
        report.mem_used
        / report.mem_total
        * 100.0
        if report.mem_total
        else 0.0
    )

    swap_pct = (
        report.swap_used
        / report.swap_total
        * 100.0
        if report.swap_total
        else 0.0
    )

    print(
        f"hostname      : "
        f"{report.hostname}"
    )
    print(
        f"distribution  : "
        f"{report.distribution}"
    )
    print(
        f"kernel        : "
        f"{report.kernel}"
    )
    print(
        f"architecture  : "
        f"{report.architecture}"
    )
    print(
        f"uptime        : "
        f"{format_duration(report.uptime_seconds)}"
    )
    print(
        f"load          : "
        f"{report.load_1m:.2f} "
        f"{report.load_5m:.2f} "
        f"{report.load_15m:.2f}"
    )
    print(
        f"cpus          : "
        f"{report.cpu_count}"
    )
    print(
        f"memory        : "
        f"{human_bytes(report.mem_used)} / "
        f"{human_bytes(report.mem_total)} "
        f"({mem_pct:.1f}%)"
    )
    print(
        f"available     : "
        f"{human_bytes(report.mem_available)}"
    )
    print(
        f"swap          : "
        f"{human_bytes(report.swap_used)} / "
        f"{human_bytes(report.swap_total)} "
        f"({swap_pct:.1f}%)"
    )
    print(
        f"processes     : "
        f"{report.processes}"
    )


def unescape_mount_field(value: str) -> str:
    replacements = {
        "\\040": " ",
        "\\011": "\t",
        "\\012": "\n",
        "\\134": "\\",
    }

    for encoded, decoded in replacements.items():
        value = value.replace(
            encoded,
            decoded,
        )

    return value


def collect_mounts() -> List[MountEntry]:
    text = read_text(Path("/proc/self/mounts"))

    if not text:
        return []

    rows: List[MountEntry] = []

    for line in text.splitlines():
        parts = line.split()

        if len(parts) < 4:
            continue

        source = unescape_mount_field(parts[0])
        target = unescape_mount_field(parts[1])
        fstype = parts[2]
        options = parts[3]

        total: Optional[int] = None
        used: Optional[int] = None
        available: Optional[int] = None
        used_pct: Optional[float] = None

        try:
            usage = os.statvfs(target)

            total = (
                usage.f_blocks
                * usage.f_frsize
            )
            available = (
                usage.f_bavail
                * usage.f_frsize
            )
            free_all = (
                usage.f_bfree
                * usage.f_frsize
            )
            used = max(
                total - free_all,
                0,
            )

            if total > 0:
                used_pct = (
                    used / total * 100.0
                )

        except OSError:
            pass

        rows.append(
            MountEntry(
                source=source,
                target=target,
                fstype=fstype,
                options=options,
                total_bytes=total,
                used_bytes=used,
                available_bytes=available,
                used_pct=used_pct,
            )
        )

    return rows


def sort_mounts(
    rows: List[MountEntry],
    sort_by: str,
) -> List[MountEntry]:
    if sort_by == "used":
        rows.sort(
            key=lambda row: (
                row.used_pct
                if row.used_pct is not None
                else -1.0,
                row.target,
            ),
            reverse=True,
        )
    elif sort_by == "size":
        rows.sort(
            key=lambda row: (
                row.total_bytes
                if row.total_bytes is not None
                else -1,
                row.target,
            ),
            reverse=True,
        )
    elif sort_by == "type":
        rows.sort(
            key=lambda row: (
                row.fstype,
                row.target,
            )
        )
    elif sort_by == "source":
        rows.sort(
            key=lambda row: (
                row.source,
                row.target,
            )
        )
    else:
        rows.sort(key=lambda row: row.target)

    return rows


def print_mount_table(
    rows: List[MountEntry],
) -> None:
    header = (
        f"{'SOURCE':<24} "
        f"{'TYPE':<10} "
        f"{'SIZE':>11} "
        f"{'USED':>11} "
        f"{'AVAIL':>11} "
        f"{'USE%':>7} "
        f"TARGET"
    )

    print(header)
    print("-" * len(header))

    for row in rows:
        size = (
            human_bytes(row.total_bytes)
            if row.total_bytes is not None
            else "-"
        )
        used = (
            human_bytes(row.used_bytes)
            if row.used_bytes is not None
            else "-"
        )
        available = (
            human_bytes(row.available_bytes)
            if row.available_bytes is not None
            else "-"
        )
        used_pct = (
            f"{row.used_pct:.1f}%"
            if row.used_pct is not None
            else "-"
        )

        source = row.source

        if len(source) > 24:
            source = "..." + source[-21:]

        print(
            f"{source:<24} "
            f"{row.fstype:<10} "
            f"{size:>11} "
            f"{used:>11} "
            f"{available:>11} "
            f"{used_pct:>7} "
            f"{row.target}"
        )


def decode_ipv4(hex_address: str) -> str:
    try:
        packed = bytes.fromhex(hex_address)

        if len(packed) != 4:
            return "?"

        return socket.inet_ntop(
            socket.AF_INET,
            packed[::-1],
        )
    except (ValueError, OSError):
        return "?"


def decode_ipv6(hex_address: str) -> str:
    try:
        packed = bytes.fromhex(hex_address)

        if len(packed) != 16:
            return "?"

        words = struct.unpack(
            "<IIII",
            packed,
        )
        network = struct.pack(
            ">IIII",
            *words,
        )

        return socket.inet_ntop(
            socket.AF_INET6,
            network,
        )
    except (
        ValueError,
        OSError,
        struct.error,
    ):
        return "?"


def decode_endpoint(
    value: str,
    family: str,
) -> Tuple[str, int]:
    if ":" not in value:
        return "?", 0

    address_hex, port_hex = value.split(
        ":",
        1,
    )

    try:
        port = int(port_hex, 16)
    except ValueError:
        port = 0

    if family == "ipv6":
        address = decode_ipv6(address_hex)
    else:
        address = decode_ipv4(address_hex)

    return address, port


def parse_inet_socket_file(
    path: Path,
    protocol: str,
    family: str,
) -> List[SocketEntry]:
    text = read_text(path)

    if not text:
        return []

    rows: List[SocketEntry] = []
    state_map = (
        TCP_STATES
        if protocol == "tcp"
        else UDP_STATES
    )

    for line in text.splitlines()[1:]:
        parts = line.split()

        if len(parts) < 10:
            continue

        local = parts[1]
        remote = parts[2]
        state_code = parts[3]

        try:
            uid = int(parts[7])
            inode = int(parts[9])
        except (ValueError, IndexError):
            continue

        local_address, local_port = (
            decode_endpoint(
                local,
                family,
            )
        )
        remote_address, remote_port = (
            decode_endpoint(
                remote,
                family,
            )
        )

        rows.append(
            SocketEntry(
                protocol=protocol,
                family=family,
                local_address=local_address,
                local_port=local_port,
                remote_address=remote_address,
                remote_port=remote_port,
                state=state_map.get(
                    state_code,
                    state_code,
                ),
                uid=uid,
                inode=inode,
            )
        )

    return rows


def collect_sockets(
    protocols: Optional[Set[str]] = None,
) -> List[SocketEntry]:
    selected = protocols or {
        "tcp",
        "udp",
    }

    rows: List[SocketEntry] = []

    sources = [
        (
            "tcp",
            "ipv4",
            Path("/proc/net/tcp"),
        ),
        (
            "tcp",
            "ipv6",
            Path("/proc/net/tcp6"),
        ),
        (
            "udp",
            "ipv4",
            Path("/proc/net/udp"),
        ),
        (
            "udp",
            "ipv6",
            Path("/proc/net/udp6"),
        ),
    ]

    for protocol, family, path in sources:
        if protocol not in selected:
            continue

        rows.extend(
            parse_inet_socket_file(
                path,
                protocol,
                family,
            )
        )

    return rows


def sort_sockets(
    rows: List[SocketEntry],
    sort_by: str,
) -> List[SocketEntry]:
    if sort_by == "port":
        rows.sort(
            key=lambda row: (
                row.local_port,
                row.protocol,
                row.local_address,
            )
        )
    elif sort_by == "state":
        rows.sort(
            key=lambda row: (
                row.state,
                row.protocol,
                row.local_port,
            )
        )
    elif sort_by == "uid":
        rows.sort(
            key=lambda row: (
                row.uid,
                row.protocol,
                row.local_port,
            )
        )
    elif sort_by == "inode":
        rows.sort(
            key=lambda row: row.inode
        )
    else:
        rows.sort(
            key=lambda row: (
                row.protocol,
                row.family,
                row.local_address,
                row.local_port,
            )
        )

    return rows


def filter_sockets(
    rows: List[SocketEntry],
    listening: bool,
    port: Optional[int],
) -> List[SocketEntry]:
    result = rows

    if listening:
        result = [
            row
            for row in result
            if (
                row.state == "LISTEN"
                or (
                    row.protocol == "udp"
                    and row.remote_port == 0
                )
            )
        ]

    if port is not None:
        result = [
            row
            for row in result
            if row.local_port == port
            or row.remote_port == port
        ]

    return result


def format_endpoint(
    address: str,
    port: int,
    family: str,
) -> str:
    if family == "ipv6":
        return f"[{address}]:{port}"

    return f"{address}:{port}"


def print_socket_table(
    rows: List[SocketEntry],
) -> None:
    header = (
        f"{'PROTO':<6} "
        f"{'FAMILY':<6} "
        f"{'STATE':<13} "
        f"{'UID':>7} "
        f"{'LOCAL':<30} "
        f"{'REMOTE':<30} "
        f"{'INODE':>12}"
    )

    print(header)
    print("-" * len(header))

    for row in rows:
        local = format_endpoint(
            row.local_address,
            row.local_port,
            row.family,
        )
        remote = format_endpoint(
            row.remote_address,
            row.remote_port,
            row.family,
        )

        print(
            f"{row.protocol:<6} "
            f"{row.family:<6} "
            f"{row.state:<13} "
            f"{row.uid:>7} "
            f"{local:<30} "
            f"{remote:<30} "
            f"{row.inode:>12}"
        )


def cmd_version(
    _args: argparse.Namespace,
) -> int:
    print(f"{APP_NAME} {APP_VERSION}")
    return 0


def cmd_system(
    args: argparse.Namespace,
) -> int:
    report = collect_system()

    if args.json:
        json_dump(asdict(report))
    else:
        print_system_report(report)

    return 0


def cmd_net(
    args: argparse.Namespace,
) -> int:
    if not validate_positive_interval(
        args.interval
    ):
        return 1

    selected = args.iface or None

    previous: Optional[List[NetSnapshot]] = None
    previous_ts: Optional[float] = None

    cycles = 0

    while not _stop_requested:
        current = collect_net(selected)
        now = time.monotonic()

        elapsed = (
            now - previous_ts
            if previous_ts is not None
            else 0.0
        )

        rows = net_rows(
            current,
            previous,
            elapsed,
        )

        if (
            args.clear
            and cycles > 0
            and not args.json
        ):
            clear_screen()

        if args.json:
            payload = {
                "timestamp": time.time(),
                "elapsed": elapsed,
                "interfaces": rows,
            }
            json_dump(payload)
        else:
            print_net_table(rows)

        cycles += 1

        if not args.watch:
            break

        if (
            args.count > 0
            and cycles >= args.count
        ):
            break

        previous = current
        previous_ts = now

        if not args.json:
            print()

        sleep_interruptible(args.interval)

    return 0


def cmd_proc(
    args: argparse.Namespace,
) -> int:
    if not validate_positive_interval(
        args.interval
    ):
        return 1

    if not validate_limit(args.limit):
        return 1

    previous: Optional[
        Dict[int, ProcSnapshot]
    ] = None

    previous_ts: Optional[float] = None
    cycles = 0

    while not _stop_requested:
        current = read_proc_stat()
        now = time.monotonic()

        elapsed = (
            now - previous_ts
            if previous_ts is not None
            else 0.0
        )

        rows = build_proc_rows(
            current,
            previous,
            elapsed,
        )

        rows = filter_proc_rows(
            rows,
            args.user,
            args.name,
        )

        rows = sort_proc_rows(
            rows,
            args.sort,
        )

        rows = apply_limit(
            rows,
            args.limit,
        )

        if (
            args.clear
            and cycles > 0
            and not args.json
        ):
            clear_screen()

        if args.json:
            json_dump(
                {
                    "timestamp": time.time(),
                    "elapsed": elapsed,
                    "processes": [
                        asdict(row)
                        for row in rows
                    ],
                }
            )
        else:
            print_proc_table(rows)

        cycles += 1

        if not args.watch:
            break

        if (
            args.count > 0
            and cycles >= args.count
        ):
            break

        previous = current
        previous_ts = now

        if not args.json:
            print()

        sleep_interruptible(args.interval)

    return 0


def cmd_disk(
    args: argparse.Namespace,
) -> int:
    if not validate_limit(args.limit):
        return 1

    root = Path(args.path)

    if not root.exists() and not root.is_symlink():
        print(
            f"path not found: {root}",
            file=sys.stderr,
        )
        return 1

    rows = list(
        iter_disk(
            root,
            args.max_depth,
            args.follow_symlinks,
        )
    )

    if args.kind:
        rows = [
            row
            for row in rows
            if row.kind in args.kind
        ]

    rows = sort_disk_rows(
        rows,
        args.sort,
    )

    rows = apply_limit(
        rows,
        args.limit,
    )

    if args.json:
        json_dump(
            [
                asdict(row)
                for row in rows
            ]
        )
    else:
        print_disk_table(rows)

    return 0


def cmd_entropy(
    args: argparse.Namespace,
) -> int:
    path = Path(args.path)

    if not path.exists():
        print(
            f"path not found: {path}",
            file=sys.stderr,
        )
        return 1

    if not path.is_file():
        print(
            f"not a regular file: {path}",
            file=sys.stderr,
        )
        return 1

    if args.chunk_size <= 0:
        print(
            "chunk size must be positive",
            file=sys.stderr,
        )
        return 1

    try:
        report = analyze_file(
            path,
            args.chunk_size,
        )
    except (
        PermissionError,
        FileNotFoundError,
        OSError,
    ) as exc:
        print(
            f"cannot analyze {path}: {exc}",
            file=sys.stderr,
        )
        return 1

    if args.json:
        json_dump(asdict(report))
    else:
        print_entropy_report(report)

    return 0


def cmd_mounts(
    args: argparse.Namespace,
) -> int:
    if not validate_limit(args.limit):
        return 1

    rows = collect_mounts()

    if args.type:
        rows = [
            row
            for row in rows
            if row.fstype in args.type
        ]

    if args.real:
        virtual = {
            "autofs",
            "bpf",
            "cgroup",
            "cgroup2",
            "configfs",
            "debugfs",
            "devpts",
            "devtmpfs",
            "efivarfs",
            "fusectl",
            "hugetlbfs",
            "mqueue",
            "proc",
            "pstore",
            "securityfs",
            "sysfs",
            "tmpfs",
            "tracefs",
        }

        rows = [
            row
            for row in rows
            if row.fstype not in virtual
        ]

    rows = sort_mounts(
        rows,
        args.sort,
    )

    rows = apply_limit(
        rows,
        args.limit,
    )

    if args.json:
        json_dump(
            [
                asdict(row)
                for row in rows
            ]
        )
    else:
        print_mount_table(rows)

    return 0


def cmd_sockets(
    args: argparse.Namespace,
) -> int:
    if not validate_limit(args.limit):
        return 1

    protocols: Set[str] = set()

    if args.tcp:
        protocols.add("tcp")

    if args.udp:
        protocols.add("udp")

    if not protocols:
        protocols = {
            "tcp",
            "udp",
        }

    rows = collect_sockets(protocols)

    rows = filter_sockets(
        rows,
        args.listening,
        args.port,
    )

    rows = sort_sockets(
        rows,
        args.sort,
    )

    rows = apply_limit(
        rows,
        args.limit,
    )

    if args.json:
        json_dump(
            [
                asdict(row)
                for row in rows
            ]
        )
    else:
        print_socket_table(rows)

    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=APP_NAME,
        description="Cyber Garden Toolkit",
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {APP_VERSION}",
    )

    parser.add_argument(
        "--debug",
        action="store_true",
        help="enable debug logging",
    )

    subparsers = parser.add_subparsers(
        dest="command",
    )

    p_version = subparsers.add_parser(
        "version",
        help="show version",
    )
    p_version.set_defaults(
        func=cmd_version,
    )

    p_system = subparsers.add_parser(
        "system",
        help="system overview",
    )
    p_system.add_argument(
        "--json",
        action="store_true",
        help="json output",
    )
    p_system.set_defaults(
        func=cmd_system,
    )

    p_net = subparsers.add_parser(
        "net",
        help="network interface monitor",
    )
    p_net.add_argument(
        "--iface",
        action="append",
        help="select interface",
    )
    p_net.add_argument(
        "--watch",
        action="store_true",
        help="watch mode",
    )
    p_net.add_argument(
        "--interval",
        type=float,
        default=DEFAULT_INTERVAL,
        help="refresh interval",
    )
    p_net.add_argument(
        "--count",
        type=int,
        default=0,
        help="number of cycles, 0 = infinite",
    )
    p_net.add_argument(
        "--json",
        action="store_true",
        help="json output",
    )
    p_net.add_argument(
        "--clear",
        action="store_true",
        help="clear screen between updates",
    )
    p_net.set_defaults(
        func=cmd_net,
    )

    p_proc = subparsers.add_parser(
        "proc",
        help="process monitor",
    )
    p_proc.add_argument(
        "--watch",
        action="store_true",
        help="watch mode",
    )
    p_proc.add_argument(
        "--interval",
        type=float,
        default=DEFAULT_INTERVAL,
        help="refresh interval",
    )
    p_proc.add_argument(
        "--count",
        type=int,
        default=0,
        help="number of cycles, 0 = infinite",
    )
    p_proc.add_argument(
        "--limit",
        type=int,
        default=DEFAULT_LIMIT,
        help="row limit, 0 = unlimited",
    )
    p_proc.add_argument(
        "--sort",
        choices=[
            "cpu",
            "rss",
            "vms",
            "pid",
            "name",
            "user",
        ],
        default="cpu",
        help="sort field",
    )
    p_proc.add_argument(
        "--user",
        help="filter by user name or uid",
    )
    p_proc.add_argument(
        "--name",
        help="filter by process name or command",
    )
    p_proc.add_argument(
        "--json",
        action="store_true",
        help="json output",
    )
    p_proc.add_argument(
        "--clear",
        action="store_true",
        help="clear screen between updates",
    )
    p_proc.set_defaults(
        func=cmd_proc,
    )

    p_disk = subparsers.add_parser(
        "disk",
        help="filesystem inventory",
    )
    p_disk.add_argument(
        "path",
        nargs="?",
        default=".",
        help="target path",
    )
    p_disk.add_argument(
        "--limit",
        type=int,
        default=DEFAULT_DISK_LIMIT,
        help="row limit, 0 = unlimited",
    )
    p_disk.add_argument(
        "--sort",
        choices=[
            "path",
            "size",
            "mtime",
            "kind",
            "inode",
        ],
        default="path",
        help="sort field",
    )
    p_disk.add_argument(
        "--max-depth",
        type=int,
        default=DEFAULT_MAX_DEPTH,
        help="max traversal depth, -1 = unlimited",
    )
    p_disk.add_argument(
        "--follow-symlinks",
        action="store_true",
        help="follow symlinks",
    )
    p_disk.add_argument(
        "--kind",
        action="append",
        choices=[
            "file",
            "dir",
            "link",
            "char",
            "block",
            "fifo",
            "sock",
            "other",
        ],
        help="filter entry type",
    )
    p_disk.add_argument(
        "--json",
        action="store_true",
        help="json output",
    )
    p_disk.set_defaults(
        func=cmd_disk,
    )

    p_entropy = subparsers.add_parser(
        "entropy",
        help="file entropy report",
    )
    p_entropy.add_argument(
        "path",
        help="target file",
    )
    p_entropy.add_argument(
        "--chunk-size",
        type=int,
        default=DEFAULT_CHUNK_SIZE,
        help="read chunk size",
    )
    p_entropy.add_argument(
        "--json",
        action="store_true",
        help="json output",
    )
    p_entropy.set_defaults(
        func=cmd_entropy,
    )

    p_mounts = subparsers.add_parser(
        "mounts",
        help="mounted filesystem overview",
    )
    p_mounts.add_argument(
        "--limit",
        type=int,
        default=DEFAULT_LIMIT,
        help="row limit, 0 = unlimited",
    )
    p_mounts.add_argument(
        "--sort",
        choices=[
            "target",
            "source",
            "type",
            "size",
            "used",
        ],
        default="target",
        help="sort field",
    )
    p_mounts.add_argument(
        "--type",
        action="append",
        help="filter filesystem type",
    )
    p_mounts.add_argument(
        "--real",
        action="store_true",
        help="hide common virtual filesystems",
    )
    p_mounts.add_argument(
        "--json",
        action="store_true",
        help="json output",
    )
    p_mounts.set_defaults(
        func=cmd_mounts,
    )

    p_sockets = subparsers.add_parser(
        "sockets",
        help="TCP and UDP socket overview",
    )
    p_sockets.add_argument(
        "--tcp",
        action="store_true",
        help="show TCP sockets",
    )
    p_sockets.add_argument(
        "--udp",
        action="store_true",
        help="show UDP sockets",
    )
    p_sockets.add_argument(
        "--listening",
        action="store_true",
        help="show listening or unconnected sockets",
    )
    p_sockets.add_argument(
        "--port",
        type=int,
        help="filter local or remote port",
    )
    p_sockets.add_argument(
        "--limit",
        type=int,
        default=DEFAULT_LIMIT,
        help="row limit, 0 = unlimited",
    )
    p_sockets.add_argument(
        "--sort",
        choices=[
            "address",
            "port",
            "state",
            "uid",
            "inode",
        ],
        default="address",
        help="sort field",
    )
    p_sockets.add_argument(
        "--json",
        action="store_true",
        help="json output",
    )
    p_sockets.set_defaults(
        func=cmd_sockets,
    )

    return parser


def main(
    argv: Optional[List[str]] = None,
) -> int:
    install_signal_handlers()

    parser = build_parser()
    args = parser.parse_args(argv)

    if args.debug:
        logger.setLevel(logging.DEBUG)

    if not hasattr(args, "func"):
        parser.print_help()
        return 0

    try:
        return args.func(args)
    except BrokenPipeError:
        try:
            sys.stdout.close()
        except OSError:
            pass
        return 0
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
