#!/usr/bin/env python3
import argparse
import glob

file_index_map = {}

def iter_iolog(path):
    global file_index_map
    with open(path, "r") as f:
        for line in f:
            if line.startswith("fio version") or line.startswith("add") or line.startswith("open"):
                continue
            parts = line.strip().split()
            if len(parts) < 5:
                continue
            
            # 正确提取 filename
            t, filename, op, off, sz = parts[:5]
            op = op.lower()
            if op not in ("read", "write"):
                continue
                
            t = int(float(t))
            off = int(off)
            sz = int(sz)
            
            if sz <= 0 or sz > 1048576:
                continue

            # 动态注册文件并获取唯一的 file_idx
            if filename not in file_index_map:
                file_index_map[filename] = len(file_index_map)
            
            file_idx = file_index_map[filename]
            
            id_base = file_idx * (1 << 40)
            base_page = off // 4096
            n = (sz + 4095) // 4096
            obj_id = id_base + base_page
            
            yield (t, obj_id, n * 4096, op)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--pattern", required=True,
                        help="glob pattern, e.g. /path/prefix_job*")
    parser.add_argument("--out", default="fio_4k.csv",
                        help="output csv path")
    args = parser.parse_args()

    files = sorted(glob.glob(args.pattern))
    if not files:
        raise SystemExit(f"No files matched pattern: {args.pattern}")

    rows = []
    # 移除 job_id 的传入，保持 obj_id 原生纯净
    for path in files:
        rows.extend(iter_iolog(path))

    print(f"[Info] 成功读取 {len(rows)} 条 I/O 记录，正在按时间线全局排序...")
    # 全局按时间排序，解决时序错乱问题
    rows.sort(key=lambda x: x[0])

    print(f"[Info] 正在写入 CSV 文件: {args.out}")
    with open(args.out, "w") as out:
        # # ✅ 添加标准表头
        # out.write("time,obj_id,size,op\n")
        for t, obj_id, sz, op in rows:
            out.write(f"{t},{obj_id},{sz},{op}\n")
            
    print("[Success] 轨迹转换完成！")

if __name__ == "__main__":
    main()