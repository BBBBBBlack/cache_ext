#define _POSIX_C_SOURCE 200809L
#define _GNU_SOURCE

#include <argp.h>
#include <bpf/bpf.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include "a_uapi.h"

#include "a_dispatcher.skel.h"
#include "dir_watcher.h"

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define REGISTRY_MAP_PATH "/sys/fs/bpf/dispatcher_registry"
#define DISPATCHER_CONTROL_SOCKET_PATH "/tmp/cache_ext_dispatcher_%llu.sock"
#define LOADER_CONTROL_SOCKET_PATH "/tmp/cache_ext_loader_%llu.sock"

#define MAX_EVENTS 10

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

static u64 get_cgroup_id(int cgroup_fd)
{
  struct stat st;
  if (fstat(cgroup_fd, &st) < 0)
    return 0;

  return (u64)st.st_ino;
}

struct dispatcher_prog_ids
{
  __u32 folio_added_id;
  __u32 folio_accessed_id;
  __u32 evict_folios_id;
  __u32 folio_evicted_id;
};

struct dispatcher_ring_ctx
{
  __u64 cgroup_id;
  bool notified;
};

/**
 * ******************************************registry*******************************************
 */
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
  __u64 cgroup_id = get_cgroup_id(cgroup_fd);
  if (cgroup_id == 0)
  {
    perror("Failed to stat cgroup fd");
    return;
  }

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
  __u64 cgroup_id = get_cgroup_id(cgroup_fd);
  if (cgroup_id == 0)
    return;

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

/**
 * ******************************************recieve / send command*******************************************
 */

struct dispatcher_server
{
  int listen_fd;
  int epoll_fd;
  int ring_epoll_fd;
  char socket_path[PATH_MAX];
  struct dispatcher_ring_ctx ring_ctx;
  struct ring_buffer* complete_rb;
};

void handle_loader_command(struct a_dispatcher_bpf* skel, char* cmd)
{
  if (strcmp(cmd, "MIGRATION_BEGIN") == 0)
  {
    skel->bss->global_ts.high_ghr_streak = 0;
    skel->bss->global_ts.low_ghr_streak = 0;
    uint64_t routing_core = ((uint64_t)100 << 32) | PHASE_SLOW_START;
    __atomic_store_n(&skel->bss->global_ts.routing_core, routing_core, __ATOMIC_RELEASE);
    __atomic_store_n(&skel->bss->enable_secondary_slot, 1, __ATOMIC_RELEASE);
    printf("[Dispatcher] Received MIGRATION_BEGIN. phase=%u p=%u\n",
           skel->bss->global_ts.phase, skel->bss->global_ts.p);
  }
  else if (strcmp(cmd, "MIGRATION_COMPLETE") == 0)
  {
    printf("[Dispatcher] Received MIGRATION_COMPLETE. Migration finished.\n");
  }
}

static int handle_loader(int listen_fd, struct a_dispatcher_bpf* skel)
{
  while (1)
  {
    int conn_fd;
    char buf[128];

    conn_fd = accept(listen_fd, NULL, NULL);
    if (conn_fd < 0)
    {
      if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
        return 0;

      perror("accept");
      return -1;
    }

    ssize_t n = read(conn_fd, buf, sizeof(buf) - 1);
    if (n > 0)
    {
      buf[n] = '\0';
      handle_loader_command(skel, buf);
    }

    close(conn_fd);
  }
}

static int notify_loader_command(__u64 cgroup_id, const char* msg)
{
  int fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0)
    return -1;

  struct sockaddr_un addr;
  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;

  char cmd_socket_path[PATH_MAX];

  snprintf(cmd_socket_path, sizeof(cmd_socket_path), LOADER_CONTROL_SOCKET_PATH, cgroup_id);
  strncpy(addr.sun_path, cmd_socket_path, sizeof(addr.sun_path) - 1);

  int ret = -1;
  if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) == 0)
  {
    if (write(fd, msg, strlen(msg)) >= 0)
      ret = 0;
  }
  else
  {
    perror("Failed to connect to loader control socket");
  }

  close(fd);
  return ret;
}

static int handle_bpf_dispatcher_command(void* ctx, void* data, size_t data_sz)
{
  struct dispatcher_ring_ctx* ring_ctx = ctx;
  if (!ring_ctx || data_sz < sizeof(u32))
    return 0;

  u32 phase = *(u32*)data;
  if (phase == PHASE_COMPLETE && !ring_ctx->notified)
  {
    ring_ctx->notified = true;
    if (notify_loader_command(ring_ctx->cgroup_id, "MIGRATION_COMPLETE") == 0)
      printf("[Dispatcher] Forwarded COMPLETE event to loader.\n");
  }
  return 0;
}

static int handle_bpf_dispatcher(struct ring_buffer* complete_rb)
{
  int ret = ring_buffer__consume(complete_rb);
  if (ret < 0 && ret != -EINTR)
  {
    fprintf(stderr, "ring_buffer__poll failed: %d\n", ret);
    return -1;
  }
  return 0;
}

static int add_epoll_fd(int epoll_fd, int fd)
{
  struct epoll_event ev;
  memset(&ev, 0, sizeof(ev));

  ev.events = EPOLLIN; // 监听事件类型：可读事件
  ev.data.fd = fd;

  // 将 fd 插入到 epoll_fd 内部的红黑树中，按照 ev 设定的规则开始监控
  if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ev) < 0)
  {
    perror("epoll_ctl add failed");
    return -1;
  }

  return 0;
}

static int build_server(int cgroup_fd, struct a_dispatcher_bpf* skel,
                        struct dispatcher_server* server)
{
  memset(server, 0, sizeof(*server));
  server->listen_fd = -1;
  server->epoll_fd = -1;
  server->ring_epoll_fd = -1;

  struct bpf_map* complete_events_map =
      bpf_object__find_map_by_name(skel->obj, "migration_complete_events");
  if (!complete_events_map)
  {
    fprintf(stderr, "Failed to find migration_complete_events map\n");
    return -1;
  }

  __u64 cgroup_id = get_cgroup_id(cgroup_fd);
  server->ring_ctx.cgroup_id = cgroup_id;
  server->ring_ctx.notified = false;

  // ring buffer
  server->complete_rb = ring_buffer__new(bpf_map__fd(complete_events_map),
                                         handle_bpf_dispatcher_command, &server->ring_ctx, NULL);
  if (!server->complete_rb)
  {
    fprintf(stderr, "Failed to create ring buffer for COMPLETE events\n");
    return -1;
  }
  server->ring_epoll_fd = ring_buffer__epoll_fd(server->complete_rb);
  if (server->ring_epoll_fd < 0)
  {
    fprintf(stderr, "Failed to get ring buffer epoll fd\n");
    return -1;
  }
  // socket
  server->listen_fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (server->listen_fd < 0)
  {
    perror("Failed to create command socket");
    return -1;
  }

  struct sockaddr_un addr;
  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;

  snprintf(server->socket_path, sizeof(server->socket_path),
           DISPATCHER_CONTROL_SOCKET_PATH, cgroup_id);
  unlink(server->socket_path);
  strncpy(addr.sun_path, server->socket_path, sizeof(addr.sun_path) - 1);

  int flags = fcntl(server->listen_fd, F_GETFL, 0);
  if (flags >= 0)
    fcntl(server->listen_fd, F_SETFL, flags | O_NONBLOCK);

  if (bind(server->listen_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0)
  {
    perror("Failed to bind command socket");
    return -1;
  }

  if (listen(server->listen_fd, 5) < 0)
  {
    perror("Failed to listen on command socket");
    return -1;
  }

  server->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
  if (server->epoll_fd < 0)
  {
    perror("Failed to create epoll instance");
    return -1;
  }

  if (add_epoll_fd(server->epoll_fd, server->listen_fd) < 0)
    return -1;
  if (add_epoll_fd(server->epoll_fd, server->ring_epoll_fd) < 0)
    return -1;

  return 0;
}

static void destroy_dispatcher_command_server(struct dispatcher_server* server)
{
  if (server->epoll_fd >= 0)
    close(server->epoll_fd);
  if (server->complete_rb)
    ring_buffer__free(server->complete_rb);
  if (server->listen_fd >= 0)
    close(server->listen_fd);
  if (server->socket_path[0] != '\0')
    unlink(server->socket_path);
}

static int dispatcher_command_server_step(struct dispatcher_server* server,
                                          struct a_dispatcher_bpf* skel)
{
  struct epoll_event events[MAX_EVENTS];
  int n = epoll_wait(server->epoll_fd, events, MAX_EVENTS, -1);
  if (n < 0)
  {
    if (errno == EINTR)
      return 0;

    perror("epoll_wait failed");
    return -1;
  }

  for (int i = 0; i < n; i++)
  {
    int ready_fd = events[i].data.fd;
    // 有新连接到达时触发
    if (ready_fd == server->listen_fd)
    {
      if (handle_loader(server->listen_fd, skel) < 0)
        return -1;
    }
    else if (ready_fd == server->ring_epoll_fd)
    {
      if (handle_bpf_dispatcher(server->complete_rb) < 0)
        return -1;
    }
  }

  return 0;
}

int run_command_server(int cgroup_fd, struct a_dispatcher_bpf* skel)
{
  struct dispatcher_server server = {0};

  if (build_server(cgroup_fd, skel, &server) < 0)
    return -1;

  printf("Dispatcher is running and listening for commands...\n");

  while (!exiting)
  {
    if (dispatcher_command_server_step(&server, skel) < 0)
      continue;
  }

  destroy_dispatcher_command_server(&server);
  return 0;
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
  run_command_server(cgroup_fd, skel);
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
