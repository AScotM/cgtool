#!/usr/bin/env python3

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import logging
import math
import os
import socket
import stat
import struct
import sys
import time
from collections import Counter
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Tuple


APP_NAME = "cgtool"
APP_VERSION = "0.1.0"
PROC_NET_DEV_HEADER_LINES = 2
SIOCGIFADDR = 0x8915
DEFAULT_INTERVAL = 2.0
DEFAULT_LIMIT = 20
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
DNS_SERVER = "8.8.8.8"
DNS_PORT = 80


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class NetSnapshot:
    iface: str
    operstate: str
    ipv4: Optional[str]
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
    name: str
    state: str
    threads: int
    rss_bytes: int
    vms_bytes: int
    utime_ticks: int
    stime_ticks: int
    total_ticks: int
    cmdline: str


@dataclass
class DiskEntry:
    path: str
    kind: str
    size: int
    mode: str
    mtime: float


@dataclass
class EntropyReport:
    path: str
    size: int
    sha256: str
    entropy: float
    printable_ratio: float
    null_ratio: float
    top_bytes: List[Tuple[int, int]]


def human_bytes(value: float) -> str:
    idx = 0
    while value >= BYTES_PER_KIB and idx < len(UNITS) - 1:
        value /= BYTES_PER_KIB
        idx += 1
    return f"{value:.2f} {UNITS[idx]}"


def human_rate(value: float) -> str:
    return f"{human_bytes(value)}/s"


def format_pps(value: float) -> str:
    if value >= PPS_MILLION:
        return f"{value / PPS_MILLION:.2f} Mpps"
    if value >= PPS_THOUSAND:
        return f"{value / PPS_THOUSAND:.2f} Kpps"
    return f"{value:.2f} pps"


def json_dump(data: Any) -> None:
    print(json.dumps(data, indent=2, ensure_ascii=False))


def read_text(path: Path) -> Optional[str]:
    try:
        return path.read_text(encoding="utf-8").strip()
    except (FileNotFoundError, PermissionError, OSError, UnicodeDecodeError) as e:
        logger.debug(f"Failed to read text from {path}: {e}")
        return None


def read_bytes(path: Path) -> Optional[bytes]:
    try:
        return path.read_bytes()
    except (FileNotFoundError, PermissionError, OSError) as e:
        logger.debug(f"Failed to read bytes from {path}: {e}")
        return None


def read_int(path: Path) -> Optional[int]:
    value = read_text(path)
    if value is None:
        return None
    try:
        return int(value)
    except ValueError as e:
        logger.debug(f"Failed to parse int from {path}: {e}")
        return None


def get_ipv4_for_iface(iface: str) -> Optional[str]:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            iface_bytes = iface.encode()[:15]
            ifreq = struct.pack('16s', iface_bytes)
            addr = fcntl.ioctl(sock.fileno(), SIOCGIFADDR, ifreq)
            ip = socket.inet_ntoa(addr[20:24])
            return ip
        except OSError as e:
            logger.debug(f"IOCTL failed for {iface}: {e}")
        finally:
            sock.close()
    except (ImportError, OSError) as e:
        logger.debug(f"Socket setup failed: {e}")

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect((DNS_SERVER, DNS_PORT))
            return s.getsockname()[0]
    except OSError as e:
        logger.debug(f"Fallback IP detection failed: {e}")
        return None


def get_interfaces() -> List[str]:
    base = Path("/sys/class/net")
    try:
        return sorted(p.name for p in base.iterdir() if p.exists())
    except OSError as e:
        logger.debug(f"Failed to list interfaces: {e}")
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
        except ValueError as e:
            logger.debug(f"Failed to parse /proc/net/dev line for {iface}: {e}")
            continue
    return result


def collect_net(ifaces: Optional[List[str]] = None) -> List[NetSnapshot]:
    all_stats = parse_proc_net_dev()
    selected = ifaces if ifaces else get_interfaces()
    snapshots: List[NetSnapshot] = []
    for iface in selected:
        stats = all_stats.get(iface, {})
        snapshots.append(
            NetSnapshot(
                iface=iface,
                operstate=read_text(Path(f"/sys/class/net/{iface}/operstate")) or "unknown",
                ipv4=get_ipv4_for_iface(iface),
                rx_bytes=stats.get("rx_bytes", 0),
                tx_bytes=stats.get("tx_bytes", 0),
                rx_packets=stats.get("rx_packets", 0),
                tx_packets=stats.get("tx_packets", 0),
                rx_errs=stats.get("rx_errs", 0),
                tx_errs=stats.get("tx_errs", 0),
                rx_drop=stats.get("rx_drop", 0),
                tx_drop=stats.get("tx_drop", 0),
            )
        )
    return snapshots


def print_net_table(current: List[NetSnapshot], previous: Optional[List[NetSnapshot]], elapsed: float) -> None:
    prev_map = {x.iface: x for x in previous or []}
    header = (
        f"{'IFACE':<12} {'STATE':<12} {'IPv4':<16} "
        f"{'RX RATE':>12} {'TX RATE':>12} "
        f"{'RX PPS':>12} {'TX PPS':>12} "
        f"{'RX ERR':>8} {'TX ERR':>8}"
    )
    print(header)
    print("-" * len(header))
    for item in current:
        prev = prev_map.get(item.iface)
        if prev and elapsed > 0:
            rx_rate = max((item.rx_bytes - prev.rx_bytes) / elapsed, 0.0)
            tx_rate = max((item.tx_bytes - prev.tx_bytes) / elapsed, 0.0)
            rx_pps = max((item.rx_packets - prev.rx_packets) / elapsed, 0.0)
            tx_pps = max((item.tx_packets - prev.tx_packets) / elapsed, 0.0)
        else:
            rx_rate = tx_rate = rx_pps = tx_pps = 0.0
        print(
            f"{item.iface:<12} {item.operstate:<12} {(item.ipv4 or '-'):16} "
            f"{human_rate(rx_rate):>12} {human_rate(tx_rate):>12} "
            f"{format_pps(rx_pps):>12} {format_pps(tx_pps):>12} "
            f"{item.rx_errs:>8} {item.tx_errs:>8}"
        )


def read_proc_stat() -> Dict[int, ProcSnapshot]:
    result: Dict[int, ProcSnapshot] = {}
    page_size = os.sysconf("SC_PAGE_SIZE")
    proc = Path("/proc")
    for entry in proc.iterdir():
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        
        stat_path = entry / "stat"
        statm_path = entry / "statm"
        cmdline_path = entry / "cmdline"
        
        if not stat_path.exists() or not statm_path.exists():
            continue
            
        stat_text = read_text(stat_path)
        statm_text = read_text(statm_path)
        cmdline_raw = read_bytes(cmdline_path)
        
        if not stat_text or not statm_text:
            continue
            
        try:
            left = stat_text.index("(")
            right = stat_text.rindex(")")
            name = stat_text[left + 1:right]
            rest = stat_text[right + 2:].split()
            state = rest[0]
            ppid = int(rest[1])
            utime_ticks = int(rest[11])
            stime_ticks = int(rest[12])
            threads = int(rest[17])
            statm_parts = statm_text.split()
            vms_pages = int(statm_parts[0])
            rss_pages = int(statm_parts[1])
            cmdline = ""
            if cmdline_raw:
                cmdline = cmdline_raw.replace(b"\x00", b" ").decode("utf-8", errors="replace").strip()
            result[pid] = ProcSnapshot(
                pid=pid,
                ppid=ppid,
                name=name,
                state=state,
                threads=threads,
                rss_bytes=rss_pages * page_size,
                vms_bytes=vms_pages * page_size,
                utime_ticks=utime_ticks,
                stime_ticks=stime_ticks,
                total_ticks=utime_ticks + stime_ticks,
                cmdline=cmdline or name,
            )
        except (ValueError, IndexError, PermissionError) as e:
            logger.debug(f"Failed to parse /proc/{pid}/stat: {e}")
            continue
    return result


def print_proc_table(current: Dict[int, ProcSnapshot], previous: Optional[Dict[int, ProcSnapshot]], elapsed: float, limit: int, sort_by: str) -> None:
    hz = os.sysconf("SC_CLK_TCK")
    rows: List[Tuple[float, ProcSnapshot]] = []
    for pid, proc in current.items():
        prev = previous.get(pid) if previous else None
        cpu_pct = 0.0
        if prev and elapsed > 0:
            delta = proc.total_ticks - prev.total_ticks
            cpu_pct = max((delta / hz) / elapsed * 100.0, 0.0)
        rows.append((cpu_pct, proc))

    if sort_by == "cpu":
        rows.sort(key=lambda x: (x[0], x[1].rss_bytes), reverse=True)
    elif sort_by == "rss":
        rows.sort(key=lambda x: x[1].rss_bytes, reverse=True)
    elif sort_by == "pid":
        rows.sort(key=lambda x: x[1].pid)
    else:
        rows.sort(key=lambda x: x[1].name.lower())

    header = f"{'PID':>7} {'PPID':>7} {'STATE':<6} {'THR':>5} {'CPU%':>8} {'RSS':>10} {'VMS':>10} CMD"
    print(header)
    print("-" * len(header))
    for cpu_pct, proc in rows[:limit]:
        print(
            f"{proc.pid:>7} {proc.ppid:>7} {proc.state:<6} {proc.threads:>5} "
            f"{cpu_pct:>8.2f} {human_bytes(proc.rss_bytes):>10} {human_bytes(proc.vms_bytes):>10} "
            f"{proc.cmdline}"
        )


def iter_disk(path: Path, max_depth: int, follow_symlinks: bool) -> Iterator[DiskEntry]:
    visited = set()
    symlink_chain = set()

    def walk(p: Path, current_depth: int) -> Iterator[DiskEntry]:
        if max_depth >= 0 and current_depth > max_depth:
            return

        try:
            if follow_symlinks:
                real_path = p.resolve()
                if current_depth > 0:
                    resolved_str = str(real_path)
                    if resolved_str in symlink_chain:
                        return
                    symlink_chain.add(resolved_str)
                st = real_path.stat()
            else:
                st = p.lstat()
                real_path = p
        except (PermissionError, FileNotFoundError, OSError) as e:
            logger.debug(f"Cannot access {p}: {e}")
            return

        if not follow_symlinks and stat.S_ISLNK(st.st_mode):
            yield DiskEntry(
                path=str(p),
                kind="link",
                size=st.st_size,
                mode=stat.filemode(st.st_mode),
                mtime=st.st_mtime,
            )
            return

        mode = stat.filemode(st.st_mode)
        if stat.S_ISDIR(st.st_mode):
            kind = "dir"
            yield DiskEntry(
                path=str(p),
                kind=kind,
                size=st.st_size,
                mode=mode,
                mtime=st.st_mtime,
            )
            try:
                for child in sorted(p.iterdir(), key=lambda x: x.name):
                    child_resolved = child.resolve() if follow_symlinks else child
                    child_key = str(child_resolved)
                    if child_key in visited:
                        continue
                    visited.add(child_key)
                    yield from walk(child, current_depth + 1)
            except (PermissionError, FileNotFoundError, OSError) as e:
                logger.debug(f"Cannot read directory {p}: {e}")
                return
        elif stat.S_ISREG(st.st_mode):
            kind = "file"
            yield DiskEntry(
                path=str(p),
                kind=kind,
                size=st.st_size,
                mode=mode,
                mtime=st.st_mtime,
            )
        elif stat.S_ISCHR(st.st_mode):
            kind = "char"
            yield DiskEntry(
                path=str(p),
                kind=kind,
                size=st.st_size,
                mode=mode,
                mtime=st.st_mtime,
            )
        elif stat.S_ISBLK(st.st_mode):
            kind = "block"
            yield DiskEntry(
                path=str(p),
                kind=kind,
                size=st.st_size,
                mode=mode,
                mtime=st.st_mtime,
            )
        elif stat.S_ISFIFO(st.st_mode):
            kind = "fifo"
            yield DiskEntry(
                path=str(p),
                kind=kind,
                size=st.st_size,
                mode=mode,
                mtime=st.st_mtime,
            )
        elif stat.S_ISSOCK(st.st_mode):
            kind = "sock"
            yield DiskEntry(
                path=str(p),
                kind=kind,
                size=st.st_size,
                mode=mode,
                mtime=st.st_mtime,
            )
        else:
            kind = "other"
            yield DiskEntry(
                path=str(p),
                kind=kind,
                size=st.st_size,
                mode=mode,
                mtime=st.st_mtime,
            )

    visited.add(str(path.resolve()))
    yield from walk(path, 0)


def print_disk_table(entries: Iterable[DiskEntry], limit: int, sort_by: str) -> None:
    rows = list(entries)
    if sort_by == "size":
        rows.sort(key=lambda x: x.size, reverse=True)
    elif sort_by == "mtime":
        rows.sort(key=lambda x: x.mtime, reverse=True)
    elif sort_by == "kind":
        rows.sort(key=lambda x: (x.kind, x.path))
    else:
        rows.sort(key=lambda x: x.path)

    header = f"{'KIND':<8} {'SIZE':>12} {'MODE':<10} {'MTIME':<19} PATH"
    print(header)
    print("-" * len(header))
    for entry in rows[:limit]:
        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(entry.mtime))
        print(f"{entry.kind:<8} {human_bytes(entry.size):>12} {entry.mode:<10} {ts:<19} {entry.path}")


def shannon_entropy(counter: Counter[int], total: int) -> float:
    if total <= 0:
        return 0.0
    entropy = 0.0
    for count in counter.values():
        p = count / total
        entropy -= p * math.log2(p)
    return entropy


def analyze_file(path: Path, chunk_size: int = DEFAULT_CHUNK_SIZE) -> EntropyReport:
    sha256 = hashlib.sha256()
    counter: Counter[int] = Counter()
    total = 0
    printable = 0
    nulls = 0

    with path.open("rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            sha256.update(chunk)
            total += len(chunk)
            counter.update(chunk)
            printable += sum(1 for b in chunk if PRINTABLE_MIN <= b <= PRINTABLE_MAX or b in WHITESPACE_CHARS)
            nulls += chunk.count(0)

    top_bytes = counter.most_common(10)
    return EntropyReport(
        path=str(path),
        size=total,
        sha256=sha256.hexdigest(),
        entropy=shannon_entropy(counter, total),
        printable_ratio=(printable / total) if total else 0.0,
        null_ratio=(nulls / total) if total else 0.0,
        top_bytes=top_bytes,
    )


def print_entropy_report(report: EntropyReport) -> None:
    print(f"path            : {report.path}")
    print(f"size            : {report.size}")
    print(f"sha256          : {report.sha256}")
    print(f"entropy         : {report.entropy:.4f}")
    print(f"printable_ratio : {report.printable_ratio:.4f}")
    print(f"null_ratio      : {report.null_ratio:.4f}")
    print("top_bytes       :")
    for byte_value, count in report.top_bytes:
        print(f"  0x{byte_value:02x}  {count}")


def clear_screen() -> None:
    print("\033[2J\033[H", end="")


def validate_positive_interval(interval: float) -> bool:
    if interval <= 0:
        print("Interval must be positive", file=sys.stderr)
        return False
    return True


def cmd_version(_args: argparse.Namespace) -> int:
    print(f"{APP_NAME} {APP_VERSION}")
    return 0


def cmd_net(args: argparse.Namespace) -> int:
    if not validate_positive_interval(args.interval):
        return 1
    
    ifaces = args.iface or None
    if args.watch:
        previous = collect_net(ifaces)
        previous_ts = time.monotonic()
        if args.json:
            json_dump([asdict(x) for x in previous])
        else:
            print_net_table(previous, None, 0.0)
        cycles = 1
        while args.count <= 0 or cycles < args.count:
            time.sleep(args.interval)
            current = collect_net(ifaces)
            now = time.monotonic()
            elapsed = now - previous_ts
            if args.clear:
                clear_screen()
            if args.json:
                payload = {
                    "elapsed": elapsed,
                    "interfaces": [asdict(x) for x in current],
                }
                json_dump(payload)
            else:
                print_net_table(current, previous, elapsed)
            previous = current
            previous_ts = now
            cycles += 1
            if not args.json:
                print()
    else:
        rows = collect_net(ifaces)
        if args.json:
            json_dump([asdict(x) for x in rows])
        else:
            print_net_table(rows, None, 0.0)
    return 0


def cmd_proc(args: argparse.Namespace) -> int:
    if not validate_positive_interval(args.interval):
        return 1
    
    previous: Optional[Dict[int, ProcSnapshot]] = None
    previous_ts: Optional[float] = None

    def emit(current: Dict[int, ProcSnapshot], elapsed: float) -> None:
        if args.json:
            out = []
            for pid, item in current.items():
                row = asdict(item)
                if previous and elapsed > 0 and pid in previous:
                    delta = item.total_ticks - previous[pid].total_ticks
                    hz = os.sysconf("SC_CLK_TCK")
                    row["cpu_pct"] = max((delta / hz) / elapsed * 100.0, 0.0)
                else:
                    row["cpu_pct"] = 0.0
                out.append(row)
            json_dump(out[:args.limit])
        else:
            print_proc_table(current, previous, elapsed, args.limit, args.sort)

    if args.watch:
        cycles = 0
        while args.count <= 0 or cycles < args.count:
            current = read_proc_stat()
            now = time.monotonic()
            elapsed = (now - previous_ts) if previous_ts is not None else 0.0
            if args.clear and cycles > 0:
                clear_screen()
            emit(current, elapsed)
            previous = current
            previous_ts = now
            cycles += 1
            if args.count <= 0 or cycles < args.count:
                if not args.json:
                    print()
                time.sleep(args.interval)
    else:
        current = read_proc_stat()
        emit(current, 0.0)

    return 0


def cmd_disk(args: argparse.Namespace) -> int:
    root = Path(args.path)
    if not root.exists():
        print(f"path not found: {root}", file=sys.stderr)
        return 1
    
    if args.json:
        entries = list(iter_disk(root, args.max_depth, args.follow_symlinks))
        json_dump([asdict(x) for x in entries[:args.limit]])
    else:
        entries = iter_disk(root, args.max_depth, args.follow_symlinks)
        print_disk_table(entries, args.limit, args.sort)
    return 0


def cmd_entropy(args: argparse.Namespace) -> int:
    path = Path(args.path)
    if not path.exists():
        print(f"path not found: {path}", file=sys.stderr)
        return 1
    if not path.is_file():
        print(f"not a regular file: {path}", file=sys.stderr)
        return 1
    report = analyze_file(path, args.chunk_size)
    if args.json:
        json_dump(asdict(report))
    else:
        print_entropy_report(report)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog=APP_NAME, description="Cyber Garden Toolkit")
    parser.add_argument("--version", action="store_true", help="show version and exit")

    subparsers = parser.add_subparsers(dest="command")

    p_version = subparsers.add_parser("version", help="show version")
    p_version.set_defaults(func=cmd_version)

    p_net = subparsers.add_parser("net", help="network interface monitor")
    p_net.add_argument("--iface", action="append", help="select interface")
    p_net.add_argument("--watch", action="store_true", help="watch mode")
    p_net.add_argument("--interval", type=float, default=DEFAULT_INTERVAL, help="refresh interval")
    p_net.add_argument("--count", type=int, default=0, help="number of cycles, 0 = infinite")
    p_net.add_argument("--json", action="store_true", help="json output")
    p_net.add_argument("--clear", action="store_true", help="clear screen between updates")
    p_net.set_defaults(func=cmd_net)

    p_proc = subparsers.add_parser("proc", help="process snapshot")
    p_proc.add_argument("--watch", action="store_true", help="watch mode")
    p_proc.add_argument("--interval", type=float, default=DEFAULT_INTERVAL, help="refresh interval")
    p_proc.add_argument("--count", type=int, default=0, help="number of cycles, 0 = infinite")
    p_proc.add_argument("--limit", type=int, default=DEFAULT_LIMIT, help="row limit")
    p_proc.add_argument("--sort", choices=["cpu", "rss", "pid", "name"], default="cpu", help="sort field")
    p_proc.add_argument("--json", action="store_true", help="json output")
    p_proc.add_argument("--clear", action="store_true", help="clear screen between updates")
    p_proc.set_defaults(func=cmd_proc)

    p_disk = subparsers.add_parser("disk", help="filesystem inventory")
    p_disk.add_argument("path", nargs="?", default=".", help="target path")
    p_disk.add_argument("--limit", type=int, default=50, help="row limit")
    p_disk.add_argument("--sort", choices=["path", "size", "mtime", "kind"], default="path", help="sort field")
    p_disk.add_argument("--max-depth", type=int, default=DEFAULT_MAX_DEPTH, help="max traversal depth, -1 = unlimited")
    p_disk.add_argument("--follow-symlinks", action="store_true", help="follow symlinks")
    p_disk.add_argument("--json", action="store_true", help="json output")
    p_disk.set_defaults(func=cmd_disk)

    p_entropy = subparsers.add_parser("entropy", help="file entropy report")
    p_entropy.add_argument("path", help="target file")
    p_entropy.add_argument("--chunk-size", type=int, default=DEFAULT_CHUNK_SIZE, help="read chunk size")
    p_entropy.add_argument("--json", action="store_true", help="json output")
    p_entropy.set_defaults(func=cmd_entropy)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.version:
        return cmd_version(args)

    if not hasattr(args, "func"):
        parser.print_help()
        return 0

    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
