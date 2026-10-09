#include <argp.h>
#include <bpf/bpf.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

typedef uint64_t u64;
typedef int64_t s64;
typedef uint32_t u32;

#include "dir_watcher.h"
#include "cache_ext_s3fifo.skel.h"

char *USAGE = "Usage: ./cache_ext_s3fifo --watch_dir <dir> --cgroup_size <size> --cgroup_path <path>\n";
struct cmdline_args {
	char *watch_dir;
        uint64_t cgroup_size;
        char *cgroup_path;
};

static struct argp_option options[] = {
	{ "watch_dir", 'w', "DIR", 0, "Directory to watch" },
        {"cgroup_size", 's', "SIZE", 0, "Size of the cgroup"},
        {"cgroup_path", 'c', "PATH", 0, "Path to cgroup (e.g., /sys/fs/cgroup/cache_ext_test)"},
	{ 0 },
};

static const uint64_t s3fifo_ghost_map_entries = 4000000;

static volatile sig_atomic_t exiting;

static void sig_handler(int signo) {
	exiting = 1;
}

static void print_accounting_stats(struct cache_ext_s3fifo_bpf *skel,
                                   const char *phase)
{
	struct timespec mono, real;
	if (!skel || !skel->bss)
		return;
	clock_gettime(CLOCK_MONOTONIC, &mono);
	clock_gettime(CLOCK_REALTIME, &real);
	/* Independent relaxed snapshots, not a transaction across fields. */
#define SNAP(field) __atomic_load_n(&skel->bss->field, __ATOMIC_RELAXED)
	unsigned long long list_missing = SNAP(diag_add_fail_list_missing);
	unsigned long long node_invalid = SNAP(diag_add_fail_node_invalid);
	unsigned long long already_linked = SNAP(diag_add_fail_already_linked);
	unsigned long long other = SNAP(diag_add_fail_other);
	/* Derived only in userspace: no second atomic increment per failure. */
	unsigned long long add_fail_total = list_missing + node_invalid + already_linked + other;
	printf("[S3FIFO accounting] revision=6 phase=%s mono_ns=%llu unix_ns=%llu marker_mask=%u "
	       "small=%lld main=%lld "
	       "add_fail_total=%llu pre_add_node_missing=%llu accessed_node_missing=%llu "
	       "add_fail_list_missing=%llu add_fail_node_invalid=%llu "
	       "add_fail_already_linked=%llu add_fail_other=%llu "
	       "small_negative_updates=%llu main_negative_updates=%llu\n",
	       phase, (unsigned long long)mono.tv_sec * 1000000000ULL + mono.tv_nsec,
	       (unsigned long long)real.tv_sec * 1000000000ULL + real.tv_nsec,
	       SNAP(admission_tracking_mask),
	       (long long)SNAP(small_list_size), (long long)SNAP(main_list_size),
	       add_fail_total,
	       (unsigned long long)SNAP(diag_pre_add_node_missing),
	       (unsigned long long)SNAP(diag_accessed_node_missing),
	       list_missing, node_invalid, already_linked, other,
	       (unsigned long long)SNAP(diag_small_negative_updates),
	       (unsigned long long)SNAP(diag_main_negative_updates));
#undef SNAP
	fflush(stdout);
}

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
	struct cmdline_args *args = state->input;
	switch (key) {
	case 'w':
		args->watch_dir = arg;
		break;
        case 's':
                // TODO: move this to parse_args()
                errno = 0;
                args->cgroup_size = strtoull(arg, NULL, 10);
                if (errno)
                        args->cgroup_size = 0;

                break;
        case 'c':
                args->cgroup_path = arg;
                break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static int parse_args(int argc, char **argv, struct cmdline_args *args) {
	struct argp argp = { options, parse_opt, 0, 0 };
	argp_parse(&argp, argc, argv, 0, 0, args);

	if (args->watch_dir == NULL) {
		fprintf(stderr, "Missing required argument: watch_dir\n");
		return 1;
	}

	if (args->cgroup_size == 0) {
	        fprintf(stderr, "Invalid cgroup size\n");
	        return 1;
	}

	if (args->cgroup_path == NULL) {
		fprintf(stderr, "Missing required argument: cgroup_path\n");
		return 1;
	}

	return 0;
}

/*
 * Validate watch_dir
 *
 * watch_dir_full_path must be able to hold PATH_MAX bytes.
 */
static int validate_watch_dir(const char *watch_dir, char *watch_dir_full_path) {
	// Does watch_dir exist?
	if (access(watch_dir, F_OK) == -1) {
		fprintf(stderr, "Directory does not exist: %s\n", watch_dir);
		return 1;
	}

	// Get full path of watch_dir
	if (realpath(watch_dir, watch_dir_full_path) == NULL) {
		perror("realpath");
		return 1;
	}

	// BPF policy restriction
	if (strlen(watch_dir_full_path) > 128) {
		fprintf(stderr, "watch_dir path too long\n");
		return 1;
	}

	return 0;
}

int main(int argc, char **argv) {
	struct cmdline_args args = { 0 };
	struct cache_ext_s3fifo_bpf *skel = NULL;
	struct bpf_link *link = NULL;
	struct sigaction sa;
	char watch_dir_path[PATH_MAX];
	int cgroup_fd = -1;
	int ret = 1;

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

	if (parse_args(argc, argv, &args))
		return 1;

	memset(&sa, 0, sizeof(sa));
	sigemptyset(&sa.sa_mask);
	sa.sa_handler = sig_handler;

	// Install signal handler
	if (sigaction(SIGINT, &sa, NULL) || sigaction(SIGTERM, &sa, NULL)) {
		perror("Failed to set up signal handling");
		return 1;
	}

	if (validate_watch_dir(args.watch_dir, watch_dir_path))
		return 1;

	// Open cgroup directory early
	cgroup_fd = open(args.cgroup_path, O_RDONLY);
	if (cgroup_fd < 0) {
		perror("Failed to open cgroup path");
		return 1;
	}

	skel = cache_ext_s3fifo_bpf__open();
	if (!skel) {
		perror("Failed to open BPF skeleton");
		goto cleanup;
	}

	fprintf(stderr, "Cgroup size: %lu bytes\n", args.cgroup_size);
	fprintf(stderr, "S3FIFO ghost_map max_entries: %lu\n", s3fifo_ghost_map_entries);

	// Resize ghost_map. Keep this aligned with dispatcher S3FIFO so direct
	// and dispatcher runs use the same ghost-history capacity.
	if (bpf_map__set_max_entries(skel->maps.ghost_map, s3fifo_ghost_map_entries)) {
		perror("Failed to resize ghost_map");
		ret = 1;
		goto cleanup;
	}

	// Set watch_dir
	watch_dir_path_len_map(skel) = strlen(watch_dir_path);
	strcpy(watch_dir_path_map(skel), watch_dir_path);

	if (cache_ext_s3fifo_bpf__load(skel)) {
		perror("Failed to load BPF skeleton");
		ret = 1;
		goto cleanup;
	}

	if (initialize_watch_dir_map(watch_dir_path, bpf_map__fd(inode_watchlist_map(skel)), true)) {
		perror("Failed to initialize watch_dir map");
		ret = 1;
		goto cleanup;
	}

	link = bpf_map__attach_cache_ext_ops(skel->maps.s3fifo_ops, cgroup_fd);
	if (link == NULL) {
		perror("Failed to attach cache_ext_ops to cgroup");
		ret = 1;
		goto cleanup;
	}

	// This is necessary for the dir_watcher functionality
	if (cache_ext_s3fifo_bpf__attach(skel)) {
		perror("Failed to attach BPF skeleton");
		ret = 1;
		goto cleanup;
	}

	printf("Press Ctrl-C to exit; accounting snapshots every 30s.\n");
	print_accounting_stats(skel, "start");
	while (!exiting) {
		sleep(30);
		if (!exiting)
			print_accounting_stats(skel, "periodic");
	}
	print_accounting_stats(skel, "final");
	ret = 0;

cleanup:
	close(cgroup_fd);
	bpf_link__destroy(link);
	cache_ext_s3fifo_bpf__destroy(skel);
	return ret;
}
