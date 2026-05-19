import logging
import os
from time import time
from typing import List, Dict

from bench_lib import *

log = logging.getLogger(__name__)

# These only run on error
CLEANUP_TASKS = []


class FileSearchBenchmark(BenchmarkFramework):
    def __init__(self, benchresults_cls=BenchResults, cli_args=None):
        super().__init__("filesearch_benchmark", benchresults_cls, cli_args)

        # 这里指定cgroup的名称——/sys/fs/cgroup/{cgroup}
        self.cache_ext_policy = CacheExtPolicy(
            DEFAULT_CACHE_EXT_CGROUP, self.args.policy_loader, self.args.data_dir
        )
        CLEANUP_TASKS.append(lambda: self.cache_ext_policy.stop())

    def add_arguments(self, parser: argparse.ArgumentParser):
        parser.add_argument(
            "--data-dir",
            type=str,
            required=True,
            help="Data directory",
        )
        parser.add_argument(
            "--policy-loader",
            type=str,
            required=True,
            help="Specify the path to the policy loader binary",
        )

    def benchmark_cmd(self):
        # Start the cache extension policy
        self.cache_ext_policy.start()
        # Run the benchmark
        self.run_benchmark()
        # Stop the cache extension policy
        self.cache_ext_policy.stop()

    def generate_configs(self, configs: List[Dict]) -> List[Dict]:
        configs = add_config_option("passes", [10], configs)
        # configs = add_config_option("cgroup_size", [1 * GiB], configs)
        configs = add_config_option("cgroup_size", [30 * MiB], configs)

        if self.args.default_only:
            configs = add_config_option(
                "cgroup_name", [DEFAULT_BASELINE_CGROUP], configs
            )

        else:
            configs = add_config_option(
                "cgroup_name",
                # [DEFAULT_BASELINE_CGROUP, DEFAULT_CACHE_EXT_CGROUP],
                [DEFAULT_CACHE_EXT_CGROUP],
                configs,
            )

        configs = add_config_option("benchmark", ["filesearch"], configs)
        configs = add_config_option(
            "iteration", list(range(1, self.args.iterations + 1)), configs
        )
        return configs

    def before_benchmark(self, config):
        drop_page_cache()
        disable_swap()
        # disable_smt()
        try:
            disable_smt()
        except Exception:
            print("警告: 虚拟机环境无法关闭 SMT，已跳过此步骤 (不影响程序运行)")

        # dispatcher被挂在cgroup上
        if config["cgroup_name"] == DEFAULT_CACHE_EXT_CGROUP:
            recreate_cache_ext_cgroup(limit_in_bytes=config["cgroup_size"])
            self.cache_ext_policy.start()
        else:
            recreate_baseline_cgroup(limit_in_bytes=config["cgroup_size"])
        self.start_time = time()

    # 真正的benchmark运行命令
    def benchmark_cmd(self, config):
        pattern = "write"
        data_dir = self.args.data_dir
        cgroup_name = config["cgroup_name"]
        # rg_cmd = f"rg {pattern} {data_dir}"
        # repeated_rg_cmd = (
        #     f"for i in $(seq 1 {config['passes']}); do {rg_cmd} > /dev/null; done"
        # )
        inner_cmd = (
            f"echo $$ | sudo tee /sys/fs/cgroup/{cgroup_name}/cgroup.procs > /dev/null; "
            f"echo '>>> [Phase 1] Loading cache...'; "
            f"find {data_dir} -type f -exec cat {{}} + > /dev/null 2>&1; "
            f"echo '>>> [Phase 1] Done. Dropping caches...'; "
            f"sudo /usr/bin/sync; echo 3 | sudo /usr/bin/tee /proc/sys/vm/drop_caches; "
            f"echo '>>> [Phase 2] Running again...'; "
            f"find {data_dir} -type f -exec cat {{}} + > /dev/null 2>&1; "
            f"sleep 10; echo '>>> Test End'"
        )

        cmd = [
            "sudo",
            "/bin/sh",
            "-c",
            inner_cmd,
        ]
        return cmd

    def after_benchmark(self, config):
        self.end_time = time()
        if config["cgroup_name"] == DEFAULT_CACHE_EXT_CGROUP:
            self.cache_ext_policy.stop()
        # enable_smt()
        try:
            enable_smt()
        except Exception:
            print("警告: 虚拟机环境无法开启 SMT，已跳过此步骤 (不影响程序运行)")

    def parse_results(self, stdout: str) -> BenchResults:
        results = {"runtime_sec": self.end_time - self.start_time}
        return BenchResults(results)


def main():
    global log
    logging.basicConfig(level=logging.DEBUG)
    global log
    # To ensure that writeback keeps up with the benchmark
    filesearch_bench = FileSearchBenchmark()
    # Check that trace data dir exists
    if not os.path.exists(filesearch_bench.args.data_dir):
        raise Exception(
            "Filesearch data directory not found: %s" % filesearch_bench.args.data_dir
        )
    log.info("Filesearch data directory: %s", filesearch_bench.args.data_dir)
    filesearch_bench.benchmark()


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
