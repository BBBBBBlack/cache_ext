#!/usr/bin/env python3
"""Summarize completed Direct S3FIFO runs using one block-device layer."""
import argparse
import csv
import json
import re
from pathlib import Path


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('input', type=Path)
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--device', default='253:1')
    args = ap.parse_args()
    totals, windows, accounting = [], [], []
    for repeat in sorted(args.input.glob('repeat*')):
        for mode, tag in [('perf', 'record'), ('no_perf', 'none')]:
            folder = repeat / mode
            if not folder.is_dir():
                continue
            for stage in ['baseline', 'direct_s3fifo']:
                paths = list(folder.glob(f'*_io_windows_{tag}_{stage}.csv'))
                assert len(paths) == 1, (folder, stage, paths)
                with paths[0].open() as f:
                    rows = [r for r in csv.DictReader(f)
                            if r['stage'] == 'Trace' and r['io_device'] == args.device]
                assert rows and all(r['stage_complete'] == 'True' and r['io_status'] == 'ok'
                                    for r in rows), paths[0]
                def total(k, rr=rows):
                    return sum(float(r[k] or 0) for r in rr)
                ops, seconds = total('completed_ops'), total('interval_seconds')
                meta = dict(repeat=repeat.name, mode=mode, stage=stage)
                result = dict(**meta, seconds=seconds, completed_ops=ops,
                              throughput=ops / seconds)
                for out, key, scale in [('read_B_per_op', 'rbytes', 1),
                        ('write_B_per_op', 'wbytes', 1), ('read_ios_per_kop', 'rios', 1000),
                        ('reclaimed_per_kop', 'reclaim_reclaimed_pages', 1000)]:
                    result[out] = total(key) / ops * scale
                for key in ['reclaim_requested_pages', 'reclaim_returned_pages',
                            'reclaim_submitted_pages', 'reclaim_reclaimed_pages',
                            'reclaim_keep_dirty_pages', 'reclaim_fallback_calls']:
                    result[key] = total(key)
                for out, num, den in [('returned_ratio','reclaim_returned_pages','reclaim_requested_pages'),
                        ('reclaim_efficiency','reclaim_reclaimed_pages','reclaim_submitted_pages')]:
                    result[out] = total(num)/total(den) if total(den) else ''
                result['psi_full_percent'] = sum(float(r['psi_full_percent'] or 0) *
                    float(r['interval_seconds']) for r in rows)/seconds
                totals.append(result)
                # Use complete 30s windows only; exclude the tiny final partial interval.
                full = [r for r in rows if float(r['interval_seconds']) >= 29]
                for lo in range(0, int(seconds), 300):
                    rr = [r for r in full if lo+.1 < float(r['elapsed_seconds']) <= lo+300+.1]
                    if rr:
                        windows.append(dict(**meta, begin=lo, end=lo+300,
                            throughput=total('completed_ops',rr)/total('interval_seconds',rr)))
            for line in (folder/'console.log').read_text().splitlines():
                if '[S3FIFO accounting]' in line:
                    fields = dict(re.findall(r'(\w+)=([^\s]+)', line))
                    accounting.append(dict(repeat=repeat.name, mode=mode, **fields))
    args.output.mkdir(parents=True, exist_ok=True)
    for name, rows in [('totals',totals), ('windows_300s',windows), ('accounting',accounting)]:
        if rows:
            keys = list(dict.fromkeys(k for r in rows for k in r))
            with (args.output/f'{name}.csv').open('w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=keys)
                writer.writeheader()
                writer.writerows(rows)
    print(args.output)


if __name__ == '__main__':
    main()
