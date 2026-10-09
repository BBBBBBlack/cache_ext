#!/usr/bin/env python3
"""Align LevelDB reads, completed operations and cgroup counters (same snapshots).

One row per window AND block device; never sum stacked dm/physical devices.
Missing counters/reset counters stay blank, not zero. Warmup excluded by default.
"""
import argparse
import csv
import json
import sys
from datetime import datetime, timezone
from pathlib import Path


def pairs(text):
    result = {}
    for line in (text or "").splitlines():
        fields = line.split()
        if len(fields) == 2 and fields[1].isdigit():
            result[fields[0]] = int(fields[1])
    return result


def devices(text):
    result = {}
    for line in (text or "").splitlines():
        fields = line.split()
        if fields:
            result[fields[0]] = {k: int(v) for k, v in
                                 (f.split("=", 1) for f in fields[1:] if "=" in f)
                                 if v.isdigit()}
    return result


def pressure(text):
    return {fields[0]: int(field.split("=", 1)[1])
            for line in (text or "").splitlines() if (fields := line.split())
            for field in fields[1:] if field.startswith("total=")}


def delta(a, b, key):
    if key not in a or key not in b or b[key] < a[key]:
        return None
    return b[key] - a[key]


def ratio(value, denominator, scale=1):
    return value / denominator * scale if value is not None and denominator else None


def load_events(path):
    events = []
    with path.open() as stream:
        for number, line in enumerate(stream, 1):
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                raise ValueError(f"{path}:{number}: incomplete/corrupt JSONL; not a complete run")
    if not events or events[0].get("event") != "schema" or events[0].get("version") not in (1, 2):
        raise ValueError("unsupported or missing diagnostics schema")
    return events


def windows(events, include_warmup=False):
    completed_stages = {e["stage"] for e in events
                        if e.get("event") == "snapshot" and e.get("boundary") == "end"}
    ends = {e["id"]: e["mono_ns"] for e in events if e.get("event") == "compaction_end"}
    jobs = [(e["id"], e["mono_ns"], ends.get(e["id"])) for e in events
            if e.get("event") == "compaction_begin"]
    previous = None
    stage_start = None
    for event in events:
        if event.get("event") != "snapshot":
            continue
        if event["boundary"] == "begin":
            previous = event
            stage_start = event["mono_ns"]
            continue
        if previous is None or previous["stage"] != event["stage"]:
            raise ValueError("snapshot has no matching stage begin")
        a, b = previous, event
        previous = b
        if b["boundary"] == "end":
            previous = None
        if not include_warmup and "Warm-Up" in b["stage"]:
            continue
        t0, t1 = a["mono_ns"], b["mono_ns"]
        seconds = (t1 - t0) / 1e9
        if seconds <= 0:
            raise ValueError("non-increasing snapshot time")
        op_deltas = {key: delta(a["ops"], b["ops"], key) for key in b["ops"]}
        if any(v is None for v in op_deltas.values()):
            raise ValueError("operation counter reset within a stage")
        ops = sum(op_deltas.values())
        row = dict(stage=b["stage"], start_mono_ns=t0, end_mono_ns=t1,
                   stage_complete=b["stage"] in completed_stages,
                   timestamp=datetime.fromtimestamp(b["wall_ns"] / 1e9, timezone.utc).isoformat(),
                   elapsed_seconds=(t1-stage_start)/1e9, interval_seconds=seconds,
                   boundary=b["boundary"], completed_ops=ops, throughput_ops_s=ops/seconds,
                   snapshot_span_ms=(b["snapshot_end_mono_ns"]-t1)/1e6)
        for key, value in op_deltas.items():
            row[f"ops_{key.lower()}"] = value
        for role in b.get("reads", {}):
            for metric in b["reads"][role]:
                value = delta(a.get("reads", {}).get(role, {}), b["reads"][role], metric)
                row[f"{role}_{metric}"] = value
                if metric in ("read_calls", "returned_bytes"):
                    row[f"{role}_{metric}_per_op"] = ratio(value, ops)
        cg0, cg1 = a["cgroup"], b["cgroup"]
        # Cgroup-wide CPU time (including its background workers), not host
        # CPU utilization or elapsed time. Optional in historical schema 2.
        c0, c1 = pairs(cg0.get("cpu.stat")), pairs(cg1.get("cpu.stat"))
        for key in ("usage_usec", "user_usec", "system_usec"):
            value = delta(c0, c1, key)
            row[f"cpu_{key}"] = value
            row[f"cpu_{key}_per_op"] = ratio(value, ops)
        row["memory_current_end"] = (cg1.get("memory.current") or "").strip() or None
        m0, m1 = pairs(cg0.get("memory.stat")), pairs(cg1.get("memory.stat"))
        for key in ("anon", "file", "file_dirty", "file_writeback", "slab"):
            row[f"{key}_end"] = m1.get(key)
        for key in ("pgfault", "pgmajfault", "pgscan", "pgsteal", "workingset_refault_file"):
            row[key] = delta(m0, m1, key)
        r0, r1 = pairs(cg0.get("cache_ext_reclaim.stat")), pairs(cg1.get("cache_ext_reclaim.stat"))
        for key in sorted(r0.keys() | r1.keys()):
            row[f"reclaim_{key}"] = delta(r0, r1, key)
        p0, p1 = pressure(cg0.get("memory.pressure")), pressure(cg1.get("memory.pressure"))
        for key in ("some", "full"):
            row[f"psi_{key}_percent"] = ratio(delta(p0, p1, key), seconds * 1e6, 100)
        # Schema 2 no longer observes compaction: absent is not zero.
        if events[0].get("version", 1) == 1:
            overlapping = [(i, start, end) for i, start, end in jobs
                           if start < t1 and (end is None or end > t0)]
            row["compaction_ids"] = ";".join(str(j[0]) for j in overlapping)
            row["compaction_overlap_seconds"] = sum(
                (min(t1, end if end is not None else t1)-max(t0, start))/1e9
                for _, start, end in overlapping)
            row["compaction_missing_end"] = any(end is None for _, _, end in overlapping)
        d0, d1 = devices(cg0.get("io.stat")), devices(cg1.get("io.stat"))
        for device in sorted(d0.keys() | d1.keys()) or [""]:
            entry = dict(row, io_device=device)
            entry["io_status"] = "ok" if device in d0 and device in d1 else "missing_device_endpoint"
            for key in ("rbytes", "wbytes", "rios", "wios"):
                entry[key] = delta(d0.get(device, {}), d1.get(device, {}), key)
                if entry[key] is None and entry["io_status"] == "ok":
                    entry["io_status"] = "missing_or_reset_counter"
            entry["read_bytes_per_op"] = ratio(entry["rbytes"], ops)
            entry["write_bytes_per_op"] = ratio(entry["wbytes"], ops)
            entry["read_ios_per_kop"] = ratio(entry["rios"], ops, 1000)
            entry["write_ios_per_kop"] = ratio(entry["wios"], ops, 1000)
            yield entry
    if previous is not None:
        print("WARNING: final stage has no end snapshot; output contains completed windows only", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--throughput-log", type=Path)
    parser.add_argument("--stage-label", default="benchmark")
    parser.add_argument("--include-warmup", action="store_true")
    args = parser.parse_args()
    rows = list(windows(load_events(args.input), args.include_warmup))
    if not rows:
        raise SystemExit("No completed measurement windows; no valid CSV generated")
    path = args.output or args.input.with_suffix(".csv")
    fields = list(dict.fromkeys(key for row in rows for key in row))
    with path.open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fields)
        writer.writeheader()
        writer.writerows(rows)
    if args.throughput_log:
        seen = set()
        with args.throughput_log.open("w") as stream:
            stream.write("# Exact completed-op deltas / measured interval; warmup excluded; final partial window retained\n")
            for row in rows:
                key = (row["stage"], row["end_mono_ns"])
                if key in seen:
                    continue
                seen.add(key)
                stream.write(f"timestamp={row['timestamp']} stage={args.stage_label} "
                             f"elapsed_seconds={row['elapsed_seconds']:.6f} "
                             f"interval_seconds={row['interval_seconds']:.6f} "
                             f"throughput_ops_s={row['throughput_ops_s']:.6f} "
                             f"completed_ops={row['completed_ops']}\n")
    print(f"[Done] aligned LevelDB/IO/reclaim windows: {path}")


if __name__ == "__main__":
    main()
