import argparse
import json
import logging
import os
import re
from time import sleep
from typing import Dict, List

import psutil

from bench_lib import *

log = logging.getLogger(__name__)
GiB = 2**30
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
    size_str = size_str.upper()
    if size_str.endswith('G'): return int(float(size_str[:-1]) * (1024**3))
    if size_str.endswith('M'): return int(float(size_str[:-1]) * (1024**2))
    if size_str.endswith('K'): return int(float(size_str[:-1]) * 1024)
    return int(size_str)


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


class LevelDBBenchmark(BenchmarkFramework):
    def __init__(self, benchresults_cls=BenchResults, cli_args=None):
        super().__init__("leveldb_benchmark", benchresults_cls, cli_args)
        if self.args.leveldb_temp_db is None:
            self.args.leveldb_temp_db = self.args.leveldb_db + "_temp"
        self.cache_ext_policy = CacheExtPolicy(
            DEFAULT_CACHE_EXT_CGROUP, self.args.policy_loader, self.args.leveldb_temp_db
        )
        if self.args.policy_loader:
            CLEANUP_TASKS.append(lambda: self.cache_ext_policy.stop())

    def add_arguments(self, parser: argparse.ArgumentParser):
        parser.add_argument(
            "--leveldb-db",
            type=str,
            required=True,
            help="Specify the directory to watch for cache_ext",
        )
        parser.add_argument(
            "--leveldb-temp-db",
            type=str,
            default=None,
            help="Specify the temporary directory for LevelDB benchmarking. Default is <leveldb-db>_temp",
        )
        parser.add_argument(
            "--policy-loader",
            type=str,
            default="",
            help="Path to the policy loader binary. Empty means external Dispatcher is managing policies.",
        )
        parser.add_argument(
            "--bench-binary-dir",
            type=str,
            required=True,
            help="Specify the directory containing the benchmark binary",
        )
        parser.add_argument(
            "--cgroup-size",
            type=str,
            default="10G",
            help="Memory cgroup size limit, e.g., '5G', '10G'",
        )
        parser.add_argument(
            "--benchmark",
            type=str,
            required=True,
            help="Specify the benchmark to run, e.g., 'ycsb_a,ycsb_b,'",
        )
        parser.add_argument(
            "--fadvise-hints",
            type=str,
            default="",
            help="Specify the fadvise hints to use for the baseline cgroup, e.g., ',SEQUENTIAL,NOREUSE,DONTNEED'",
        )

    def generate_configs(self, configs: List[Dict]) -> List[Dict]:
        configs = add_config_option("enable_mmap", [False], configs)
        configs = add_config_option("runtime_seconds", [240], configs)
        configs = add_config_option("warmup_runtime_seconds", [45], configs)
        configs = add_config_option(
            "benchmark", parse_strings_string(self.args.benchmark), configs
        )
        cgroup_bytes = parse_size_str(self.args.cgroup_size)
        configs = add_config_option("cgroup_size", [cgroup_bytes], configs)
        if self.args.default_only:
            configs = add_config_option(
                "cgroup_name", [DEFAULT_BASELINE_CGROUP], configs
            )
        else:
            configs = add_config_option(
                "cgroup_name",
                [DEFAULT_BASELINE_CGROUP, DEFAULT_CACHE_EXT_CGROUP],
                configs,
            )

        fadvise_hints = parse_strings_string(self.args.fadvise_hints)
        new_configs = []
        for config in configs:
            if config["cgroup_name"] == DEFAULT_BASELINE_CGROUP:
                for fadvise in fadvise_hints:
                    new_config = config.copy()
                    new_config["fadvise"] = fadvise
                    new_configs.append(new_config)
            elif config["cgroup_name"] == DEFAULT_CACHE_EXT_CGROUP:
                if self.cache_ext_policy.loader_path:
                    policy_loader_name = os.path.basename(self.cache_ext_policy.loader_path)
                else:
                    policy_loader_name = "dispatcher"
                config["policy_loader"] = policy_loader_name
                new_configs.append(config)
            else:
                new_configs.append(config)
        configs = new_configs
        configs = add_config_option(
            "iteration", list(range(1, self.args.iterations + 1)), configs
        )
        return configs

    def benchmark_prepare(self, config):
        reset_database(self.args.leveldb_db, self.args.leveldb_temp_db)
        drop_page_cache()
        disable_swap()
        disable_smt()
        if config["cgroup_name"] == DEFAULT_CACHE_EXT_CGROUP:
            if self.cache_ext_policy.loader_path:
                recreate_cache_ext_cgroup(limit_in_bytes=config["cgroup_size"])
                policy_loader_name = os.path.basename(self.cache_ext_policy.loader_path)
                if policy_loader_name == "cache_ext_s3fifo.out":
                    self.cache_ext_policy.start(cgroup_size=config["cgroup_size"])
                else:
                    self.cache_ext_policy.start()
            else:
                log.info("Using external Dispatcher, skipping policy start.")
                cgroup_dir = f"/sys/fs/cgroup/{config['cgroup_name']}"
                if not os.path.isdir(cgroup_dir):
                    run(["sudo", "mkdir", "-p", cgroup_dir])
                run(["sudo", "sh", "-c", f"echo {config['cgroup_size']} > {cgroup_dir}/memory.max"])
        else:
            recreate_baseline_cgroup(limit_in_bytes=config["cgroup_size"])

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
        with edit_yaml_file(bench_file) as bench_config:
            bench_config["leveldb"]["data_dir"] = leveldb_temp_db_dir
            bench_config["workload"]["runtime_seconds"] = config["runtime_seconds"]
            bench_config["workload"]["warmup_runtime_seconds"] = config[
                "warmup_runtime_seconds"
            ]
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
            config["cgroup_name"] == DEFAULT_CACHE_EXT_CGROUP
            and "mixed_get_scan" in config["benchmark"]
        ):
            extra_envs["ENABLE_BPF_SCAN_MAP"] = "1"
        if config["enable_mmap"]:
            extra_envs["LEVELDB_MAX_MMAPS"] = "10000"
        if config["cgroup_name"] == DEFAULT_BASELINE_CGROUP and config["fadvise"] != "":
            extra_envs["ENABLE_SCAN_FADVISE"] = config["fadvise"]
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
        if config["cgroup_name"] == DEFAULT_CACHE_EXT_CGROUP:
            if self.cache_ext_policy.loader_path:
                self.cache_ext_policy.stop()
                delete_cgroup(config["cgroup_name"])
        elif config["cgroup_name"] != DEFAULT_CACHE_EXT_CGROUP:
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
    leveldb_bench = LevelDBBenchmark()
    set_sysctl("vm.dirty_background_ratio", 1)
    set_sysctl("vm.dirty_ratio", 30)
    CLEANUP_TASKS.append(lambda: set_sysctl("vm.dirty_background_ratio", 10))
    CLEANUP_TASKS.append(lambda: set_sysctl("vm.dirty_ratio", 20))
    if not os.path.exists(leveldb_bench.args.leveldb_db):
        raise Exception(
            "LevelDB DB directory not found: %s" % leveldb_bench.args.leveldb_db
        )
    if not os.path.exists(leveldb_bench.args.bench_binary_dir):
        raise Exception(
            "Benchmark binary directory not found: %s"
            % leveldb_bench.args.bench_binary_dir
        )
    log.info("LevelDB DB directory: %s", leveldb_bench.args.leveldb_db)
    log.info("LevelDB temp DB directory: %s", leveldb_bench.args.leveldb_temp_db)
    leveldb_bench.benchmark()

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
