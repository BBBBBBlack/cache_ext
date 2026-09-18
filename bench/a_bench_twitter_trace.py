import argparse
import json
import logging
import os
import re
import subprocess
from time import sleep
from typing import Dict, List

import psutil

from bench_lib import *

log = logging.getLogger(__name__)
GiB = 2**30
MiB = 2**20
CLEANUP_TASKS = []


def read_cgroup_pgfault(cgroup_name: str) -> dict:
    stat_path = f"/sys/fs/cgroup/{cgroup_name}/memory.stat"
    result = {
        "pgfault": 0,
        "pgmajfault": 0,
        "pgscan": 0,
        "pgsteal": 0,
        "pgscan_direct": 0,
        "pgsteal_direct": 0,
        "workingset_refault_file": 0,
        "workingset_activate_file": 0,
        "workingset_restore_file": 0,
    }
    try:
        with open(stat_path, "r") as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) == 2 and parts[0] in result:
                    result[parts[0]] = int(parts[1])
    except FileNotFoundError:
        pass
    return result


def parse_size_str(size_str: str) -> int:
    """Parse size strings like '1G', '512MB', '1024KiB' to bytes."""
    raw = size_str.strip()
    if not raw:
        raise ValueError("empty size string")

    normalized = raw.upper()
    units = [
        ("GIB", 1024**3),
        ("GB", 1024**3),
        ("G", 1024**3),
        ("MIB", 1024**2),
        ("MB", 1024**2),
        ("M", 1024**2),
        ("KIB", 1024),
        ("KB", 1024),
        ("K", 1024),
        ("B", 1),
    ]

    for suffix, multiplier in units:
        if normalized.endswith(suffix):
            number = raw[:-len(suffix)].strip()
            if not number:
                raise ValueError(f"invalid size string: {size_str}")
            return int(float(number) * multiplier)

    return int(raw)


def dir_size(path: str) -> int:
    if not os.path.exists(path):
        raise Exception("Directory not found: %s" % path)
    if not os.path.isdir(path):
        raise Exception("Not a directory: %s" % path)
    cmd = ["du", "-sb", path]
    result = check_output(cmd)
    return int(result.split()[0])


def file_size(path: str) -> int:
    if not os.path.exists(path):
        raise Exception("File not found: %s" % path)
    if not os.path.isfile(path):
        raise Exception("Not a file: %s" % path)
    return os.path.getsize(path)


def reset_database(db_dir: str, temp_db_dir: str):
    if not db_dir.endswith("/"):
        db_dir += "/"
    run(["rsync", "-avpl", "--delete", db_dir, temp_db_dir])


def parse_leveldb_bench_results(stdout: str) -> Dict:
    results = {}
    for line in stdout.splitlines():
        line = line.strip()
        if "Warm-Up" in line:
            continue
        elif "overall: UPDATE throughput" in line:
            pattern = r"(\w+ throughput) (\d+\.\d+) ops/sec"
            matches = re.findall(pattern, line)
            assert len(matches) == 6, "Unexpected line pattern: %s" % line
            assert "total throughput" in matches[-1][0]
            for match in matches:
                if "READ throughput" in match[0]:
                    results["read_throughput_avg"] = float(match[1])
                elif "INSERT throughput" in match[0]:
                    results["insert_throughput_avg"] = float(match[1])
                elif "UPDATE throughput" in match[0]:
                    results["update_throughput_avg"] = float(match[1])
                elif "SCAN throughput" in match[0]:
                    results["scan_throughput_avg"] = float(match[1])
                elif "READ_MODIFY_WRITE throughput" in match[0]:
                    results["read_modify_write_throughput_avg"] = float(match[1])
                elif "total throughput" in match[0]:
                    results["throughput_avg"] = float(match[1])
                else:
                    raise Exception("Unknown throughput type: " + match[0])
            results["throughput_avg"] = float(matches[-1][1])
        elif "overall: UPDATE average latency" in line:
            pattern = r"(\w+ \w+ latency) (\d+\.\d+) ns"
            matches = re.findall(pattern, line)
            for match in matches:
                if "READ average latency" in match[0]:
                    results["read_latency_avg"] = float(match[1])
                    results["latency_avg"] = float(match[1])
                elif "INSERT average latency" in match[0]:
                    results["insert_latency_avg"] = float(match[1])
                elif "UPDATE average latency" in match[0]:
                    results["update_latency_avg"] = float(match[1])
                elif "SCAN average latency" in match[0]:
                    results["scan_latency_avg"] = float(match[1])
                elif "READ_MODIFY_WRITE average latency" in match[0]:
                    results["read_modify_write_latency_avg"] = float(match[1])
                elif "READ p99 latency" in match[0]:
                    results["read_latency_p99"] = float(match[1])
                    results["latency_p99"] = float(match[1])
                elif "INSERT p99 latency" in match[0]:
                    results["insert_latency_p99"] = float(match[1])
                elif "UPDATE p99 latency" in match[0]:
                    results["update_latency_p99"] = float(match[1])
                elif "SCAN p99 latency" in match[0]:
                    results["scan_latency_p99"] = float(match[1])
                elif "READ_MODIFY_WRITE p99 latency" in match[0]:
                    results["read_modify_write_latency_p99"] = float(match[1])
                else:
                    raise Exception("Unknown latency metric: " + match[0])
    if not all(
        key in results for key in ["throughput_avg", "latency_avg", "latency_p99"]
    ):
        raise Exception("Could not parse results from stdout: \n" + stdout)
    return results


class TwitterTraceBenchmark(BenchmarkFramework):
    def __init__(self, benchresults_cls=BenchResults, cli_args=None):
        super().__init__("twitter_trace_benchmark", benchresults_cls, cli_args)
        if self.args.leveldb_temp_db is None:
            self.args.leveldb_temp_db = self.args.leveldb_db + "_temp"
        self.cache_ext_policy = CacheExtPolicy(
            self.args.cache_ext_cgroup,
            self.args.policy_loader,
            self.args.leveldb_temp_db,
        )
        if self.args.policy_loader:
            CLEANUP_TASKS.append(lambda: self.cache_ext_policy.stop())

    def add_arguments(self, parser: argparse.ArgumentParser):
        parser.add_argument(
            "--leveldb-db", type=str, required=True,
            help="Specify the directory to watch for cache_ext",
        )
        parser.add_argument(
            "--leveldb-temp-db", type=str, default=None,
            help="Specify the temporary directory for LevelDB benchmarking. Default is <leveldb-db>_temp",
        )
        parser.add_argument(
            "--policy-loader", type=str, default="",
            help="Path to the policy loader binary. Empty means external Dispatcher is managing policies.",
        )
        parser.add_argument(
            "--bench-binary-dir", type=str, required=True,
            help="Specify the directory containing the benchmark binary",
        )
        parser.add_argument(
            "--benchmark", type=str, required=True,
            help="Specify the benchmark to run, e.g., twitter_cluster17_bench",
        )
        parser.add_argument(
            "--twitter-traces-dir", type=str, required=True,
            help="Specify the directory containing Twitter trace metadata files",
        )
        parser.add_argument(
            "--cgroup-size", type=str, default="",
            help="Memory cgroup size limit, e.g., '200M', '1G'. If empty, auto-calculate from DB size.",
        )
        parser.add_argument(
            "--cgroup-size-pct", type=int, default=10,
            help="Cgroup size as percentage of DB size (used when --cgroup-size is empty)",
        )
        parser.add_argument(
            "--cache-ext-cgroup", type=str, default=DEFAULT_CACHE_EXT_CGROUP,
            help=f"Name of the cache_ext cgroup. Default: {DEFAULT_CACHE_EXT_CGROUP}.",
        )
        parser.add_argument(
            "--baseline-cgroup", type=str, default=DEFAULT_BASELINE_CGROUP,
            help=f"Name of the baseline cgroup. Default: {DEFAULT_BASELINE_CGROUP}.",
        )
        parser.add_argument(
            "--runtime-seconds", type=int, default=240,
            help="Trace benchmark runtime_seconds written into the workload YAML. Default: 240.",
        )
        parser.add_argument(
            "--warmup-runtime-seconds", type=int, default=45,
            help="Trace warmup_runtime_seconds written into the workload YAML. Default: 45.",
        )
        trace_nr_op_group = parser.add_mutually_exclusive_group()
        trace_nr_op_group.add_argument(
            "--limit-trace-nr-op",
            dest="trace_limit_nr_op",
            action="store_true",
            default=False,
            help="For trace workloads, stop when workload.nr_op/nr_warmup_op or runtime_seconds is reached.",
        )
        trace_nr_op_group.add_argument(
            "--ignore-trace-nr-op",
            dest="trace_limit_nr_op",
            action="store_false",
            help="For trace workloads, ignore workload.nr_op/nr_warmup_op and stop only on runtime_seconds or trace EOF. This is the default.",
        )

    def generate_configs(self, configs: List[Dict]) -> List[Dict]:
        configs = add_config_option("enable_mmap", [False], configs)
        configs = add_config_option("runtime_seconds", [self.args.runtime_seconds], configs)
        configs = add_config_option(
            "warmup_runtime_seconds", [self.args.warmup_runtime_seconds], configs
        )
        configs = add_config_option(
            "benchmark", parse_strings_string(self.args.benchmark), configs
        )
        configs = add_config_option(
            "trace_limit_nr_op", [self.args.trace_limit_nr_op], configs
        )

        if self.args.cgroup_size:
            cgroup_bytes = parse_size_str(self.args.cgroup_size)
            configs = add_config_option("cgroup_size", [cgroup_bytes], configs)
            configs = add_config_option("cgroup_size_auto", [False], configs)
        else:
            configs = add_config_option("cgroup_size_pct", [self.args.cgroup_size_pct], configs)
            configs = add_config_option("cgroup_size_auto", [True], configs)

        if self.args.default_only:
            configs = add_config_option(
                "cgroup_name", [self.args.baseline_cgroup], configs
            )
        else:
            configs = add_config_option(
                "cgroup_name", [self.args.cache_ext_cgroup], configs
            )

        for config in configs:
            if config["cgroup_name"] == self.args.cache_ext_cgroup:
                if self.cache_ext_policy.loader_path:
                    policy_loader_name = os.path.basename(self.cache_ext_policy.loader_path)
                else:
                    policy_loader_name = "dispatcher"
                config["policy_loader"] = policy_loader_name

        configs = add_config_option(
            "iteration", list(range(1, self.args.iterations + 1)), configs
        )
        return configs

    def _resolve_cgroup_size(self, config):
        if not config.get("cgroup_size_auto", False):
            return config["cgroup_size"]

        db_size = dir_size(self.args.leveldb_temp_db)
        cgroup_size = int(db_size * config["cgroup_size_pct"] / 100)
        cgroup_size += 20 * MiB
        cgroup_size = max(cgroup_size, 70 * MiB)
        return cgroup_size

    def _get_trace_file(self, config):
        cluster_match = re.search(r"cluster(\d+)", config["benchmark"])
        if not cluster_match:
            raise Exception(
                "Could not extract cluster number from benchmark name: %s"
                % config["benchmark"]
            )
        cluster_num = cluster_match.group(1)
        return os.path.join(
            self.args.twitter_traces_dir, f"cluster{cluster_num}_bench.txt"
        )

    def benchmark_prepare(self, config):
        reset_database(self.args.leveldb_db, self.args.leveldb_temp_db)
        drop_page_cache()
        disable_swap()
        disable_smt()

        trace_file = self._get_trace_file(config)
        trace_sz = file_size(trace_file)
        run(["cat", trace_file], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        cgroup_size = self._resolve_cgroup_size(config)
        config["_resolved_cgroup_size"] = cgroup_size

        log.info(
            "DB size: %s, trace file size: %s, cgroup size: %s",
            format_bytes_str(dir_size(self.args.leveldb_temp_db)),
            format_bytes_str(trace_sz),
            format_bytes_str(cgroup_size),
        )

        if config["cgroup_name"] == self.args.cache_ext_cgroup:
            if self.cache_ext_policy.loader_path:
                recreate_cache_ext_cgroup(cgroup=config["cgroup_name"], limit_in_bytes=cgroup_size)
                policy_loader_name = os.path.basename(self.cache_ext_policy.loader_path)
                if policy_loader_name == "cache_ext_s3fifo.out":
                    self.cache_ext_policy.start(cgroup_size=cgroup_size)
                else:
                    self.cache_ext_policy.start()
            else:
                log.info("Using external Dispatcher, skipping policy start.")
                cgroup_dir = f"/sys/fs/cgroup/{config['cgroup_name']}"
                if not os.path.isdir(cgroup_dir):
                    run(["sudo", "mkdir", "-p", cgroup_dir])
                run(["sudo", "sh", "-c", f"echo {cgroup_size} > {cgroup_dir}/memory.max"])
        else:
            recreate_baseline_cgroup(cgroup=config["cgroup_name"], limit_in_bytes=cgroup_size)

    def before_benchmark(self, config):
        psutil.cpu_percent(percpu=True)
        self.pgfault_before = read_cgroup_pgfault(config["cgroup_name"])

    def benchmark_cmd(self, config):
        bench_binary_dir = self.args.bench_binary_dir
        leveldb_temp_db_dir = self.args.leveldb_temp_db
        bench_binary = os.path.join(bench_binary_dir, "run_leveldb")
        bench_file = "../leveldb/config/%s.yaml" % config["benchmark"]
        bench_file = os.path.abspath(os.path.join(bench_binary_dir, bench_file))
        if not os.path.exists(bench_file):
            raise Exception("Benchmark file not found: %s" % bench_file)

        trace_file_path = self._get_trace_file(config)

        with edit_yaml_file(bench_file) as bench_config:
            bench_config["leveldb"]["data_dir"] = leveldb_temp_db_dir
            bench_config["workload"]["runtime_seconds"] = config["runtime_seconds"]
            bench_config["workload"]["warmup_runtime_seconds"] = config[
                "warmup_runtime_seconds"
            ]
            bench_config["workload"]["trace_file"] = trace_file_path
            bench_config["workload"]["trace_limit_nr_op"] = config["trace_limit_nr_op"]
        cmd = [
            "sudo",
            "cgexec",
            "-g",
            "memory:%s" % config["cgroup_name"],
            bench_binary,
            bench_file,
        ]
        return cmd

    def cmd_extra_envs(self, config):
        extra_envs = {}
        if (
            config["cgroup_name"] == self.args.cache_ext_cgroup
            and "mixed_get_scan" in config["benchmark"]
        ):
            extra_envs["ENABLE_BPF_SCAN_MAP"] = "1"
        if config["enable_mmap"]:
            extra_envs["LEVELDB_MAX_MMAPS"] = "10000"
        return extra_envs

    def after_benchmark(self, config):
        self.cpu_usage = sum(psutil.cpu_percent(percpu=True)[:config["cpus"]])
        pgfault_after = read_cgroup_pgfault(config["cgroup_name"])
        self.pgfault = pgfault_after["pgfault"] - self.pgfault_before["pgfault"]
        self.pgmajfault = pgfault_after["pgmajfault"] - self.pgfault_before["pgmajfault"]
        self.pgscan = pgfault_after["pgscan"] - self.pgfault_before["pgscan"]
        self.pgsteal = pgfault_after["pgsteal"] - self.pgfault_before["pgsteal"]
        self.pgscan_direct = pgfault_after["pgscan_direct"] - self.pgfault_before["pgscan_direct"]
        self.pgsteal_direct = pgfault_after["pgsteal_direct"] - self.pgfault_before["pgsteal_direct"]
        self.workingset_refault_file = pgfault_after["workingset_refault_file"] - self.pgfault_before["workingset_refault_file"]
        self.workingset_activate_file = pgfault_after["workingset_activate_file"] - self.pgfault_before["workingset_activate_file"]
        self.workingset_restore_file = pgfault_after["workingset_restore_file"] - self.pgfault_before["workingset_restore_file"]
        if config["cgroup_name"] == self.args.cache_ext_cgroup:
            if self.cache_ext_policy.loader_path:
                self.cache_ext_policy.stop()
                delete_cgroup(config["cgroup_name"])
        elif config["cgroup_name"] != self.args.cache_ext_cgroup:
            delete_cgroup(config["cgroup_name"])
        sleep(2)
        enable_smt()

    def parse_results(self, stdout: str) -> BenchResults:
        results = parse_leveldb_bench_results(stdout)
        results["cpu_usage"] = self.cpu_usage
        results["pgfault"] = self.pgfault
        results["pgmajfault"] = self.pgmajfault
        results["pgscan"] = self.pgscan
        results["pgsteal"] = self.pgsteal
        results["pgscan_direct"] = self.pgscan_direct
        results["pgsteal_direct"] = self.pgsteal_direct
        results["workingset_refault_file"] = self.workingset_refault_file
        results["workingset_activate_file"] = self.workingset_activate_file
        results["workingset_restore_file"] = self.workingset_restore_file
        return BenchResults(results)


def main():
    global log
    disable_swap()
    disable_smt()
    bench = TwitterTraceBenchmark()
    set_sysctl("vm.dirty_background_ratio", 1)
    set_sysctl("vm.dirty_ratio", 30)
    CLEANUP_TASKS.append(lambda: set_sysctl("vm.dirty_background_ratio", 10))
    CLEANUP_TASKS.append(lambda: set_sysctl("vm.dirty_ratio", 20))
    if not os.path.exists(bench.args.leveldb_db):
        raise Exception(
            "LevelDB DB directory not found: %s" % bench.args.leveldb_db
        )
    if not os.path.exists(bench.args.bench_binary_dir):
        raise Exception(
            "Benchmark binary directory not found: %s"
            % bench.args.bench_binary_dir
        )
    log.info("LevelDB DB directory: %s", bench.args.leveldb_db)
    log.info("LevelDB temp DB directory: %s", bench.args.leveldb_temp_db)
    bench.benchmark()

    set_sysctl("vm.dirty_background_ratio", 10)
    set_sysctl("vm.dirty_ratio", 20)


if __name__ == "__main__":
    try:
        logging.basicConfig(level=logging.INFO)
        main()
    except Exception as e:
        log.error("Error in main: %s", e)
        log.info("Cleaning up")
        for task in CLEANUP_TASKS:
            task()
        log.error("Re-raising exception")
        raise e
