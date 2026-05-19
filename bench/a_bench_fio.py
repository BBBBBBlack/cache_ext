import argparse
import json
import logging
import os
from typing import Dict, List

import psutil
from yanniszark_common.cmdutils import check_output

from bench_lib import *

log = logging.getLogger(__name__)

CLEANUP_TASKS = []

def approx_equal(val1, val2, threshold=0.1):
    if val1 == val2:
        return True
    diff = abs(val1 - val2)
    avg = (val1 + val2) / 2
    pct_diff = diff / avg
    return pct_diff <= threshold

def ensure_random_file(path: str, size_in_bytes: int):
    if os.path.exists(path):
        actual_size = os.path.getsize(path)
        if approx_equal(actual_size, size_in_bytes):
            log.info(f"File {path} already exists with correct size {size_in_bytes} bytes")
            return
        else:
            raise ValueError(
                f"File {path} exists but has wrong size {actual_size} bytes (expected {size_in_bytes})"
            )
    bs = 1024 * 1024  # 1MB
    count = size_in_bytes // bs
    cmd = [
        "dd", "if=/dev/urandom", f"of={path}", f"bs={bs}", f"count={count}",
        "status=progress"
    ]
    check_output(cmd)

def pre_allocate_files(target_dir: str, file_size: str, nrfiles: int, ioengine: str):
    log.info(f"Pre-allocating files in {target_dir} (size={file_size}, nrfiles={nrfiles})")
    cmd = [
        "fio", "--name=pre_allocate",
        f"--directory={target_dir}",
        f"--size={file_size}",
        f"--nrfiles={nrfiles}",
        "--rw=write", "--bs=1m", "--direct=0",
        f"--ioengine={ioengine}",
        "--fill_device=0", "--do_verify=0"
    ]
    check_output(cmd)

def parse_size_str(size_str: str) -> int:
    size_str = size_str.upper()
    if size_str.endswith('GIB'): return int(float(size_str[:-3]) * (1024**3))
    if size_str.endswith('G'): return int(float(size_str[:-1]) * (1024**3))
    if size_str.endswith('MIB'): return int(float(size_str[:-3]) * (1024**2))
    if size_str.endswith('M'): return int(float(size_str[:-1]) * (1024**2))
    if size_str.endswith('KIB'): return int(float(size_str[:-3]) * 1024)
    if size_str.endswith('K'): return int(float(size_str[:-1]) * 1024)
    return int(size_str)

def parse_size_list(size_list_str: str) -> List[int]:
    return [parse_size_str(s.strip()) for s in size_list_str.split(',')]

class FioBenchmark(BenchmarkFramework):
    def __init__(self, benchresults_cls=BenchResults, cli_args=None):
        super().__init__("fio_benchmark", benchresults_cls, cli_args)
        target_dir = self.args.target_dir
        if not os.path.exists(target_dir):
            os.mkdir(target_dir)
            
        self.cache_ext_policy = CacheExtPolicy(
            DEFAULT_CACHE_EXT_CGROUP, self.args.policy_loader, target_dir
        )
        if self.args.policy_loader:
            CLEANUP_TASKS.append(lambda: self.cache_ext_policy.stop())

        # ================= 新增：动态异构文件分配 =================
        if self.args.job_config:
            jobs = json.loads(self.args.job_config)
            for job in jobs:
                if "filename" in job and "size" in job:
                    target_file = os.path.join(target_dir, job["filename"])
                    ensure_random_file(target_file, parse_size_str(job["size"]))
        # ==========================================================
        elif self.args.test_mode == "single":
            target_file = os.path.join(target_dir, "fio_benchfile")
            ensure_random_file(target_file, parse_size_str(self.args.file_size))
        elif self.args.test_mode == "directory":
            pre_allocate_files(target_dir, self.args.file_size, self.args.nrfiles, self.args.ioengine)

    def add_arguments(self, parser: argparse.ArgumentParser):
        parser.add_argument(
            "--test-mode", type=str, choices=["single", "directory", "custom"], default="directory", 
            help="Test mode execution logic.")
        # 新增通用异构接口
        parser.add_argument(
            "--job-config", type=str, default="",
            help="JSON string defining heterogeneous fio jobs."
        )
        parser.add_argument("--target-dir", type=str, required=True)
        parser.add_argument("--policy-loader", type=str, default="")
        parser.add_argument("--cgroup-sizes", type=str, default="5G,10G,30G")
        parser.add_argument("--workload", type=str, default="randread")
        parser.add_argument("--rwmixread", type=int, default=None)
        parser.add_argument("--file-size", type=str, default="10G")
        parser.add_argument("--runtime", type=int, default=120)
        parser.add_argument("--nrfiles", type=int, default=100)
        parser.add_argument("--openfiles", type=int, default=10)
        parser.add_argument("--ioengine", type=str, default="psync")
        parser.add_argument("--bs", type=str, default="4k")
        parser.add_argument("--numjobs", type=int, default=1)
        parser.add_argument("--random-distribution", type=str, default="")
        parser.add_argument("--write_iolog", type=str, default="")
        parser.add_argument("--log_offset", type=int, default=0)

    def generate_configs(self, configs: List[Dict]) -> List[Dict]:
        cgroup_sizes = parse_size_list(self.args.cgroup_sizes)
        configs = add_config_option("test_mode", [self.args.test_mode], configs)
        configs = add_config_option("job_config", [self.args.job_config], configs)
        configs = add_config_option("iteration", list(range(1, self.args.iterations + 1)), configs)
        configs = add_config_option("workload", [self.args.workload], configs)
        configs = add_config_option("runtime_seconds", [self.args.runtime], configs)
        configs = add_config_option("nr_threads", [self.args.numjobs], configs)
        configs = add_config_option("cgroup_size", cgroup_sizes, configs)
        configs = add_config_option("nrfiles", [self.args.nrfiles], configs)
        configs = add_config_option("openfiles", [self.args.openfiles], configs)
        configs = add_config_option("ioengine", [self.args.ioengine], configs)
        configs = add_config_option("bs", [self.args.bs], configs)
        configs = add_config_option("random_distribution", [self.args.random_distribution], configs)
        configs = add_config_option("write_iolog", [self.args.write_iolog], configs)
        configs = add_config_option("log_offset", [self.args.log_offset], configs)

        if self.args.default_only:
            configs = add_config_option("cgroup_name", [DEFAULT_BASELINE_CGROUP], configs)
        else:
            configs = add_config_option("cgroup_name", [DEFAULT_CACHE_EXT_CGROUP], configs)

        for config in configs:
            config["rwmixread"] = self.args.rwmixread 
            if config["cgroup_name"] == DEFAULT_CACHE_EXT_CGROUP:
                policy_loader_name = os.path.basename(self.cache_ext_policy.loader_path)
                config["policy_loader"] = policy_loader_name
        return configs

    def benchmark_prepare(self, config):
        log.info("Dropping page cache")
        drop_page_cache()
        if config["cgroup_name"] == DEFAULT_CACHE_EXT_CGROUP:
            if self.cache_ext_policy.loader_path:
                recreate_cache_ext_cgroup(limit_in_bytes=config["cgroup_size"])
                policy_loader_name = os.path.basename(self.cache_ext_policy.loader_path)
                if policy_loader_name == "cache_ext_s3fifo.out":
                    self.cache_ext_policy.start(cgroup_size=config["cgroup_size"])
                elif policy_loader_name:
                    self.cache_ext_policy.start()
            else:
                log.info("Using external Dispatcher, skipping cgroup recreation.")
                cgroup_dir = f"/sys/fs/cgroup/{config['cgroup_name']}"
                os.system(f"echo {config['cgroup_size']} > {cgroup_dir}/memory.max")
        else:
            recreate_baseline_cgroup(limit_in_bytes=config["cgroup_size"])

    def before_benchmark(self, config):
        psutil.cpu_percent(percpu=True)

    def benchmark_cmd(self, config):
        target_dir = self.args.target_dir    
        cmd = [
            "sudo", "cgexec", "-g", f"memory:{config['cgroup_name']}",
            "fio", "--direct=0", "--group_reporting", "--output-format=json", "--norandommap=1"
        ]
        
        # ================= 新增：动态异构命令组装 =================
        if config.get("job_config"):
            jobs = json.loads(config["job_config"])
            for job in jobs:
                job_name_base = job.get("name", "custom_job")
                # 支持单个 job 声明自身的并发数
                for i in range(job.get("numjobs", 1)):
                    cmd.extend([
                        f"--name={job_name_base}_{i}",
                        f"--rw={job['rw']}",
                        f"--bs={job['bs']}",
                        "--time_based",
                        f"--ioengine={config['ioengine']}"
                    ])

                    if "runtime" in job:
                        cmd.append(f"--runtime={job['runtime']}")
                    else:
                        cmd.append(f"--runtime={config['runtime_seconds']}")
                    if "startdelay" in job:
                        cmd.append(f"--startdelay={job['startdelay']}")

                    if "filename" in job:
                        cmd.append(f"--filename={os.path.join(target_dir, job['filename'])}")
                    if "size" in job:
                        cmd.append(f"--size={job['size']}")
                    if "rate_iops" in job:
                        cmd.append(f"--rate_iops={job['rate_iops']}")
                    if "random_distribution" in job:
                        cmd.append(f"--random_distribution={job['random_distribution']}")
                    if "rwmixread" in job:
                        cmd.append(f"--rwmixread={job['rwmixread']}")
                        
                    # 统一命名规范：..._job_配置名_索引。确保被 to_csv 完美拾取
                    if config.get("write_iolog"):
                        cmd.append(f"--write_iolog={config['write_iolog']}_job_{job_name_base}_{i}")
                    if config.get("log_offset"):
                        cmd.append(f"--log_offset={config['log_offset']}")
        # ==========================================================
        else:
            # 保持原有单一模式逻辑不变
            nr_threads = config['nr_threads']
            for i in range(nr_threads):
                cmd.extend([
                    f"--name=test_{i}",
                    f"--rw={config['workload']}",
                    "--time_based",
                    f"--runtime={config['runtime_seconds']}",
                    f"--bs={config['bs']}",
                ])
                if config.get("write_iolog"):
                    cmd.append(f"--write_iolog={config['write_iolog']}_job_{i}")
                if config.get("log_offset"):
                    cmd.append(f"--log_offset={config['log_offset']}")

                if config["test_mode"] == "single":
                    target_file = os.path.join(target_dir, "fio_benchfile")
                    cmd.extend([f"--filename={target_file}"])
                else:
                    cmd.extend([
                        f"--directory={target_dir}",
                        f"--size={self.args.file_size}",
                        f"--nrfiles={config['nrfiles']}",
                        f"--openfiles={config['openfiles']}",
                        f"--ioengine={config['ioengine']}"
                    ])
                if config.get("random_distribution"):
                    cmd.append(f"--random_distribution={config['random_distribution']}")
                if config.get("rwmixread") is not None:
                    cmd.extend(["--rwmixread", str(config["rwmixread"])])
        return cmd

    def after_benchmark(self, config):
        self.cpu_usage = sum(psutil.cpu_percent(percpu=True)[:config["cpus"]])
        if (config["cgroup_name"] == DEFAULT_CACHE_EXT_CGROUP and self.cache_ext_policy.loader_path):
            self.cache_ext_policy.stop()
        delete_cgroup(config["cgroup_name"])
        enable_smt()

    def parse_results(self, stdout: str) -> BenchResults:
        fio_results = json.loads(stdout)
        fio_results["cpu_usage"] = self.cpu_usage
        return BenchResults(fio_results)

def main():
    disable_swap()
    disable_smt()
    fio_bench = FioBenchmark()
    fio_bench.benchmark()

if __name__ == "__main__":
    try:
        logging.basicConfig(level=logging.INFO)
        main()
    except Exception as e:
        log.error("Error in main: %s", e)
        for task in CLEANUP_TASKS:
            task()
        raise e