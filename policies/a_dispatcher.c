#include <argp.h>
#include <bpf/bpf.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "a_dispatcher.skel.h"
#include "dir_watcher.h"

#define REGISTRY_MAP_PATH "/sys/fs/bpf/dispatcher_registry"

char* USAGE = "Usage: ./a_dispatcher --watch_dir <dir> --cgroup_path <path>\n";
struct cmdline_args
{
  char* watch_dir;
  char* cgroup_path;
};

static struct argp_option options[] = {
    {"watch_dir", 'w', "DIR", 0, "Directory to watch"},
    {"cgroup_path", 'c', "PATH", 0,
     "Path to cgroup (e.g., /sys/fs/cgroup/cache_ext_test)"},
    {0},
};

static volatile sig_atomic_t exiting;

static void sig_handler(int signo)
{
  exiting = 1;
}

static error_t parse_opt(int key, char* arg, struct argp_state* state)
{
  struct cmdline_args* args = state->input;
  switch (key)
  {
  case 'w':
    args->watch_dir = arg;
    break;
  case 'c':
    args->cgroup_path = arg;
    break;
  default:
    return ARGP_ERR_UNKNOWN;
  }
  return 0;
}

static int parse_args(int argc, char** argv, struct cmdline_args* args)
{
  struct argp argp = {options, parse_opt, 0, 0};
  argp_parse(&argp, argc, argv, 0, 0, args);

  if (args->watch_dir == NULL)
  {
    fprintf(stderr, "Missing required argument: watch_dir\n");
    return 1;
  }

  if (args->cgroup_path == NULL)
  {
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
static int validate_watch_dir(const char* watch_dir, char* watch_dir_full_path)
{
  // Does watch_dir exist?
  if (access(watch_dir, F_OK) == -1)
  {
    fprintf(stderr, "Directory does not exist: %s\n", watch_dir);
    return 1;
  }

  // Get full path of watch_dir
  if (realpath(watch_dir, watch_dir_full_path) == NULL)
  {
    perror("realpath");
    return 1;
  }

  // BPF policy restriction
  if (strlen(watch_dir_full_path) > 128)
  {
    fprintf(stderr, "watch_dir path too long\n");
    return 1;
  }

  return 0;
}

struct dispatcher_prog_ids
{
  __u32 folio_added_id;
  __u32 folio_accessed_id;
  __u32 evict_folios_id;
  __u32 folio_evicted_id;
};

int get_or_create_registry_map()
{
  // 1. 尝试直接打开
  int fd = bpf_obj_get(REGISTRY_MAP_PATH);
  if (fd >= 0)
    return fd;

  // 2. 如果不存在 (ENOENT)，则创建
  if (errno == ENOENT)
  {
    // 创建一个 Hash Map: Key=Cgroup_ID(u64), Value=Prog_ID(u32)
    struct bpf_map_create_opts opts = {.sz = sizeof(opts)};
    fd = bpf_map_create(BPF_MAP_TYPE_HASH, "dispatcher_reg",
                        sizeof(__u64), sizeof(struct dispatcher_prog_ids), 1024, &opts);
    if (fd < 0)
    {
      perror("Failed to create registry map");
      return -1;
    }
    // pin到了文件系统，全局可见
    if (bpf_obj_pin(fd, REGISTRY_MAP_PATH) < 0)
    {
      perror("Failed to pin registry map");
      close(fd);
      return -1;
    }
    printf("Created and pinned registry map at %s\n", REGISTRY_MAP_PATH);
    return fd;
  }
  perror("Failed to open registry map");
  return -1;
}

void register_dispatcher(int cgroup_fd, struct a_dispatcher_bpf* skel)
{
  // 1. 获取 Cgroup ID (Inode)
  struct stat st;
  if (fstat(cgroup_fd, &st) < 0)
  {
    perror("Failed to stat cgroup fd");
    return;
  }
  __u64 cgroup_id = st.st_ino;

  // 2. 获取 Program ID

  struct dispatcher_prog_ids ids = {0};

  // 获取 folio_added 的 ID
  struct bpf_prog_info info = {0};
  __u32 len = sizeof(info);
  if (bpf_obj_get_info_by_fd(bpf_program__fd(skel->progs._folio_added), &info, &len) == 0)
    ids.folio_added_id = info.id;

  // 获取 folio_accessed 的 ID
  memset(&info, 0, sizeof(info));
  len = sizeof(info);
  if (bpf_obj_get_info_by_fd(bpf_program__fd(skel->progs._folio_accessed), &info, &len) == 0)
    ids.folio_accessed_id = info.id;

  // 获取 evict_folios 的 ID
  memset(&info, 0, sizeof(info));
  len = sizeof(info);
  if (bpf_obj_get_info_by_fd(bpf_program__fd(skel->progs._evict_folios), &info, &len) == 0)
    ids.evict_folios_id = info.id;

  // 获取 folio_evited 的 ID
  memset(&info, 0, sizeof(info));
  len = sizeof(info);
  if (bpf_obj_get_info_by_fd(bpf_program__fd(skel->progs._folio_evicted), &info, &len) == 0)
    ids.folio_evicted_id = info.id;

  // 3. 写入注册表
  int map_fd = get_or_create_registry_map();
  if (map_fd < 0)
    return;

  if (bpf_map_update_elem(map_fd, &cgroup_id, &ids, BPF_ANY) < 0)
  {
    perror("Failed to register dispatcher");
  }
  else
  {
    printf("[Registry] Mapped Cgroup ID %llu -> folio_added:%u, evict_folios:%u\n",
           cgroup_id, ids.folio_added_id, ids.evict_folios_id);
  }
  close(map_fd);
}

void unregister_dispatcher(int cgroup_fd)
{
  struct stat st;
  if (fstat(cgroup_fd, &st) < 0)
    return;
  __u64 cgroup_id = st.st_ino;

  int map_fd = bpf_obj_get(REGISTRY_MAP_PATH);
  if (map_fd >= 0)
  {
    if (bpf_map_delete_elem(map_fd, &cgroup_id) == 0)
    {
      printf("[Registry] Unmapped Cgroup ID %llu\n", cgroup_id);
    }
    close(map_fd);
  }
}

int main(int argc, char** argv)
{
  struct cmdline_args args = {0};
  struct a_dispatcher_bpf* skel = NULL;
  struct bpf_link* link = NULL;
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
  if (sigaction(SIGINT, &sa, NULL))
  {
    perror("Failed to set up signal handling");
    return 1;
  }

  if (validate_watch_dir(args.watch_dir, watch_dir_path))
    return 1;

  cgroup_fd = open(args.cgroup_path, O_RDONLY);
  if (cgroup_fd < 0)
  {
    perror("Failed to open cgroup path");
    return 1;
  }

  skel = a_dispatcher_bpf__open();
  if (!skel)
  {
    perror("Failed to open BPF skeleton");
    goto cleanup;
  }

  watch_dir_path_len_map(skel) = strlen(watch_dir_path);
  strcpy(watch_dir_path_map(skel), watch_dir_path);

  if (a_dispatcher_bpf__load(skel))
  {
    perror("Failed to load BPF skeleton");
    goto cleanup;
  }

  if (initialize_watch_dir_map(watch_dir_path,
                               bpf_map__fd(inode_watchlist_map(skel)), true))
  {
    perror("Failed to initialize watch_dir map");
    goto cleanup;
  }

  link = bpf_map__attach_cache_ext_ops(skel->maps.dispatcher_ops, cgroup_fd);
  if (link == NULL)
  {
    perror("Failed to attach cache_ext_ops to cgroup");
    goto cleanup;
  }

  // This is necessary for the dir_watcher functionality
  if (a_dispatcher_bpf__attach(skel))
  {
    perror("Failed to attach BPF skeleton");
    goto cleanup;
  }

  register_dispatcher(cgroup_fd, skel);
  // Wait for keyboard input
  printf("Press any key to exit...\n");
  getchar();
  ret = 0;

cleanup:
  if (cgroup_fd >= 0)
  {
    unregister_dispatcher(cgroup_fd);
    close(cgroup_fd);
  }
  bpf_link__destroy(link);
  a_dispatcher_bpf__destroy(skel);
  return ret;
}
