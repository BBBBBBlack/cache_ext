#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import re
import signal
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable


RUNNING = True


def handle_stop(signum: int, frame: object) -> None:
    del signum, frame
    global RUNNING
    RUNNING = False


@dataclass
class ProcTicks:
    pid_count: int
    utime_ticks: int
    stime_ticks: int

    @property
    def total_ticks(self) -> int:
        return self.utime_ticks + self.stime_ticks


@dataclass
class CgroupCpu:
    exists: bool
    usage_usec: int = 0
    user_usec: int = 0
    system_usec: int = 0
    nr_periods: int = 0
    nr_throttled: int = 0
    throttled_usec: int = 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Sample fio/dispatcher/loader CPU usage and existing policy counters "
            "for cache_ext fio benchmark runs."
        )
    )
    parser.add_argument("--cgroup-path", required=True)
    parser.add_argument("--dispatcher-pid", default="")
    parser.add_argument("--loader-pid", default="")
    parser.add_argument("--dispatcher-log", default="")
    parser.add_argument("--loader-log", default="")
    parser.add_argument("--cpu-output", required=True)
    parser.add_argument("--cpu-cgroup-output", required=True)
    parser.add_argument("--counter-output", required=True)
    parser.add_argument("--fio-cgroup-path", default="")
    parser.add_argument("--dispatcher-cgroup-path", default="")
    parser.add_argument("--loader-cgroup-path", default="")
    parser.add_argument("--interval", type=float, default=1.0)
    return parser.parse_args()


def timestamp_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def read_comm(pid: int) -> str | None:
    try:
        return Path(f"/proc/{pid}/comm").read_text(encoding="utf-8").strip()
    except OSError:
        return None


def read_proc_stat(pid: int) -> tuple[int, int] | None:
    try:
        raw = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
    except OSError:
        return None

    end = raw.rfind(")")
    if end < 0:
        return None
    fields = raw[end + 2 :].split()
    if len(fields) < 13:
        return None
    try:
        # /proc/<pid>/stat fields: field 14 utime and field 15 stime.
        # After stripping "pid (comm)", fields[0] is field 3.
        return int(fields[11]), int(fields[12])
    except ValueError:
        return None


def aggregate_pids(pids: Iterable[int]) -> ProcTicks:
    pid_count = 0
    utime = 0
    stime = 0
    for pid in sorted(set(pids)):
        ticks = read_proc_stat(pid)
        if ticks is None:
            continue
        pid_count += 1
        utime += ticks[0]
        stime += ticks[1]
    return ProcTicks(pid_count=pid_count, utime_ticks=utime, stime_ticks=stime)


def read_cgroup_fio_pids(cgroup_path: Path) -> list[int]:
    procs_path = cgroup_path / "cgroup.procs"
    try:
        raw = procs_path.read_text(encoding="utf-8")
    except OSError:
        return []

    pids: list[int] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            pid = int(line)
        except ValueError:
            continue
        if read_comm(pid) == "fio":
            pids.append(pid)
    return pids


def parse_optional_pid(raw: str) -> int | None:
    raw = str(raw or "").strip()
    if not raw:
        return None
    try:
        pid = int(raw)
    except ValueError:
        return None
    return pid if pid > 0 else None


def role_ticks(role: str, cgroup_path: Path, dispatcher_pid: int | None, loader_pid: int | None) -> ProcTicks:
    if role == "fio":
        return aggregate_pids(read_cgroup_fio_pids(cgroup_path))
    if role == "dispatcher":
        return aggregate_pids([dispatcher_pid] if dispatcher_pid else [])
    if role == "loader":
        return aggregate_pids([loader_pid] if loader_pid else [])
    raise ValueError(f"unsupported role: {role}")


def read_cgroup_cpu_stat(path: Path | None) -> CgroupCpu:
    if path is None:
        return CgroupCpu(exists=False)
    stat_path = path / "cpu.stat"
    if not stat_path.exists():
        return CgroupCpu(exists=False)

    values: dict[str, int] = {}
    try:
        with stat_path.open("r", encoding="utf-8") as handle:
            for raw in handle:
                parts = raw.strip().split()
                if len(parts) != 2:
                    continue
                try:
                    values[parts[0]] = int(parts[1])
                except ValueError:
                    continue
    except OSError:
        return CgroupCpu(exists=False)

    return CgroupCpu(
        exists=True,
        usage_usec=values.get("usage_usec", 0),
        user_usec=values.get("user_usec", 0),
        system_usec=values.get("system_usec", 0),
        nr_periods=values.get("nr_periods", 0),
        nr_throttled=values.get("nr_throttled", 0),
        throttled_usec=values.get("throttled_usec", 0),
    )


def read_last_text(path: str) -> str:
    if not path:
        return ""
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def parse_policy_counters(dispatcher_log: str, loader_log: str) -> dict[str, str]:
    counters = {
        "dispatcher_folio_added": "NA",
        "dispatcher_evict": "NA",
        "loader_call_count": "NA",
        "loader_evict_count": "NA",
    }

    dispatcher_text = read_last_text(dispatcher_log)
    for match in re.finditer(r"folio_added=(\d+).*?\bevict=(\d+)", dispatcher_text):
        counters["dispatcher_folio_added"] = match.group(1)
        counters["dispatcher_evict"] = match.group(2)

    loader_text = read_last_text(loader_log)
    for match in re.finditer(r"call_count=(\d+).*?\bevict_count=(\d+)", loader_text):
        counters["loader_call_count"] = match.group(1)
        counters["loader_evict_count"] = match.group(2)

    return counters


def cpu_pct(
    previous: ProcTicks | None,
    current: ProcTicks,
    previous_time: float | None,
    current_time: float,
    clock_ticks: int,
) -> float:
    if previous is None or previous_time is None:
        return 0.0
    elapsed = current_time - previous_time
    if elapsed <= 0:
        return 0.0
    delta_ticks = current.total_ticks - previous.total_ticks
    if delta_ticks < 0:
        return 0.0
    return (delta_ticks / float(clock_ticks)) / elapsed * 100.0


def cgroup_cpu_delta(
    previous: CgroupCpu | None,
    current: CgroupCpu,
    previous_time: float | None,
    current_time: float,
) -> tuple[int, int, int, float]:
    if previous is None or previous_time is None or not previous.exists or not current.exists:
        return 0, 0, 0, 0.0
    elapsed = current_time - previous_time
    if elapsed <= 0:
        return 0, 0, 0, 0.0
    usage_delta = max(0, current.usage_usec - previous.usage_usec)
    user_delta = max(0, current.user_usec - previous.user_usec)
    system_delta = max(0, current.system_usec - previous.system_usec)
    pct = (usage_delta / 1_000_000.0) / elapsed * 100.0
    return usage_delta, user_delta, system_delta, pct


def main() -> None:
    args = parse_args()
    if args.interval <= 0:
        raise ValueError("--interval must be positive")

    signal.signal(signal.SIGTERM, handle_stop)
    signal.signal(signal.SIGINT, handle_stop)

    cgroup_path = Path(args.cgroup_path)
    fio_cgroup_path = Path(args.fio_cgroup_path) if args.fio_cgroup_path else cgroup_path
    dispatcher_cgroup_path = Path(args.dispatcher_cgroup_path) if args.dispatcher_cgroup_path else None
    loader_cgroup_path = Path(args.loader_cgroup_path) if args.loader_cgroup_path else None
    dispatcher_pid = parse_optional_pid(args.dispatcher_pid)
    loader_pid = parse_optional_pid(args.loader_pid)
    clock_ticks = os.sysconf(os.sysconf_names["SC_CLK_TCK"])

    cpu_output = Path(args.cpu_output)
    cpu_cgroup_output = Path(args.cpu_cgroup_output)
    counter_output = Path(args.counter_output)
    cpu_output.parent.mkdir(parents=True, exist_ok=True)
    cpu_cgroup_output.parent.mkdir(parents=True, exist_ok=True)
    counter_output.parent.mkdir(parents=True, exist_ok=True)

    roles = ["fio", "dispatcher", "loader"]
    previous_ticks: dict[str, ProcTicks | None] = {role: None for role in roles}
    cgroup_paths: dict[str, Path | None] = {
        "fio": fio_cgroup_path,
        "dispatcher": dispatcher_cgroup_path,
        "loader": loader_cgroup_path,
    }
    previous_cgroup_cpu: dict[str, CgroupCpu | None] = {role: None for role in roles}
    previous_time: float | None = None
    start = time.time()

    with cpu_output.open("w", encoding="utf-8") as cpu_file, cpu_cgroup_output.open(
        "w", encoding="utf-8"
    ) as cpu_cgroup_file, counter_output.open("w", encoding="utf-8") as counter_file:
        cpu_file.write(
            "timestamp_iso\ttimestamp_sec\trole\tpid_count\tcpu_pct\tutime_ticks\tstime_ticks\n"
        )
        cpu_cgroup_file.write(
            "timestamp_iso\ttimestamp_sec\trole\texists\tusage_usec\tuser_usec\t"
            "system_usec\tnr_periods\tnr_throttled\tthrottled_usec\t"
            "usage_delta_usec\tuser_delta_usec\tsystem_delta_usec\tcpu_pct\n"
        )
        counter_file.write(
            "timestamp_iso\ttimestamp_sec\tdispatcher_folio_added\tdispatcher_evict\t"
            "loader_call_count\tloader_evict_count\n"
        )

        while RUNNING:
            now = time.time()
            elapsed = now - start
            ts = timestamp_iso()

            for role in roles:
                current = role_ticks(role, cgroup_path, dispatcher_pid, loader_pid)
                pct = cpu_pct(previous_ticks[role], current, previous_time, now, clock_ticks)
                cpu_file.write(
                    f"{ts}\t{elapsed:.3f}\t{role}\t{current.pid_count}\t{pct:.6f}\t"
                    f"{current.utime_ticks}\t{current.stime_ticks}\n"
                )
                previous_ticks[role] = current

                current_cgroup = read_cgroup_cpu_stat(cgroup_paths[role])
                usage_delta, user_delta, system_delta, cgroup_pct = cgroup_cpu_delta(
                    previous_cgroup_cpu[role], current_cgroup, previous_time, now
                )
                cpu_cgroup_file.write(
                    f"{ts}\t{elapsed:.3f}\t{role}\t{str(current_cgroup.exists).lower()}\t"
                    f"{current_cgroup.usage_usec}\t{current_cgroup.user_usec}\t"
                    f"{current_cgroup.system_usec}\t{current_cgroup.nr_periods}\t"
                    f"{current_cgroup.nr_throttled}\t{current_cgroup.throttled_usec}\t"
                    f"{usage_delta}\t{user_delta}\t{system_delta}\t{cgroup_pct:.6f}\n"
                )
                previous_cgroup_cpu[role] = current_cgroup

            counters = parse_policy_counters(args.dispatcher_log, args.loader_log)
            counter_file.write(
                f"{ts}\t{elapsed:.3f}\t{counters['dispatcher_folio_added']}\t"
                f"{counters['dispatcher_evict']}\t{counters['loader_call_count']}\t"
                f"{counters['loader_evict_count']}\n"
            )
            cpu_file.flush()
            cpu_cgroup_file.flush()
            counter_file.flush()
            previous_time = now

            sleep_until = now + args.interval
            while RUNNING:
                remaining = sleep_until - time.time()
                if remaining <= 0:
                    break
                time.sleep(min(remaining, 0.2))


if __name__ == "__main__":
    main()
