#include <argp.h>
#include <bpf/bpf.h>
// #include "vmlinux.h"
#include <bpf/libbpf.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

// #include "a_uapi.h"
#include "logger.h"

typedef unsigned long long u64;
typedef unsigned int u32;

#include "a_fifo_policy.skel.h"
#include "a_s3fifo_policy.skel.h"

#define REGISTRY_MAP_PATH "/sys/fs/bpf/dispatcher_registry"

#ifndef BPF_CGROUP_ITER_SELF_ONLY
enum bpf_cgroup_iter_order
{
  BPF_CGROUP_ITER_ORDER_UNSPEC,
  BPF_CGROUP_ITER_SELF_ONLY,
  BPF_CGROUP_ITER_DESCENDANTS_PRE,
  BPF_CGROUP_ITER_DESCENDANTS_POST,
  BPF_CGROUP_ITER_ANCESTORS_UP,
};

// 重新定义一个兼容当前内核的结构体
struct bpf_iter_link_info_kern
{
  union
  {
    struct
    {
      __u32 map_fd;
    } map;
    struct
    {
      enum bpf_cgroup_iter_order order;
      __u32 cgroup_fd;
      __u64 cgroup_id;
    } cgroup;
    struct
    {
      __u32 tid;
      __u32 pid;
      __u32 pid_fd;
    } task;
  };
};
#endif

/**
 * ******************************************传参处理*******************************************
 */
enum policy_type
{
  POLICY_UNKNOWN = 0,
  POLICY_FIFO,
  POLICY_S3FIFO,
  POLICY_LRU,
  POLICY_LFU,
};

struct cmdline_args
{
  char* cgroup_path;
  enum policy_type old_policy;
  enum policy_type new_policy;
};

static struct argp_option options[] = {
    {"cgroup_path", 'c', "PATH", 0, "Path to cgroup (must match Dispatcher's cgroup)"},
    {"old", 'o', "NAME", 0, "Old policy to load first (e.g., fifo)"},
    {"new", 'n', "NAME", 0, "New policy to migrate to (e.g., s3fifo)"},
    {0}};

static error_t parse_opt(int key, char* arg, struct argp_state* state)
{
  struct cmdline_args* args = state->input;
  switch (key)
  {
  case 'c':
    args->cgroup_path = arg;
    break;
  case 'o':
    if (strcmp(arg, "fifo") == 0)
      args->old_policy = POLICY_FIFO;
    else if (strcmp(arg, "s3fifo") == 0)
      args->old_policy = POLICY_S3FIFO;
    break;
  case 'n':
    if (strcmp(arg, "fifo") == 0)
      args->new_policy = POLICY_FIFO;
    else if (strcmp(arg, "s3fifo") == 0)
      args->new_policy = POLICY_S3FIFO;
    break;
  default:
    return ARGP_ERR_UNKNOWN;
  }
  return 0;
}

static struct argp argp = {options, parse_opt, 0, "Load FIFO policy and attach to a specific Cgroup Dispatcher."};

/********策略选择*********/
#define INIT_POLICY_CASE(UPPER, lower)                                                 \
  case POLICY_##UPPER:                                                                 \
    driver->type = POLICY_##UPPER;                                                     \
    driver->skel.lower = a_##lower##_policy_bpf__open();                               \
    if (!driver->skel.lower)                                                           \
      return -1;                                                                       \
    driver->load = wrap_##lower##_load;                                                \
    driver->attach = wrap_##lower##_attach;                                            \
    driver->destroy = wrap_##lower##_destroy;                                          \
    driver->get_call_count = wrap_##lower##_get_call_count;                            \
    driver->progs.do_targeted_init = driver->skel.lower->progs.do_targeted_init;       \
    driver->progs.trigger_push = driver->skel.lower->progs.trigger_push;               \
    driver->progs.trigger_pull = driver->skel.lower->progs.trigger_pull;               \
    driver->progs.folio_added = driver->skel.lower->progs.lower##_folio_added;         \
    driver->progs.folio_accessed = driver->skel.lower->progs.lower##_folio_accessed;   \
    driver->progs.evict_folios = driver->skel.lower->progs.lower##_evict_folios;       \
    driver->progs.folio_evicted = driver->skel.lower->progs.lower##_folio_evicted;     \
    driver->maps.migration_qstate_map = driver->skel.lower->maps.migration_qstate_map; \
    driver->maps.migration_queue = driver->skel.lower->maps.migration_queue;           \
    break;

struct policy_driver
{
  enum policy_type type;
  union
  {
    struct a_fifo_policy_bpf* fifo;
    struct a_s3fifo_policy_bpf* s3fifo;
    // struct a_lru_policy_bpf* lru;
  } skel;

  int (*load)(struct policy_driver* driver);
  int (*attach)(struct policy_driver* driver);
  void (*destroy)(struct policy_driver* driver);

  // 获取统计数据的接口（测试用的）
  u64 (*get_call_count)(struct policy_driver* driver);

  struct
  {
    struct bpf_program* do_targeted_init;
    struct bpf_program* trigger_push;
    struct bpf_program* trigger_pull;
    struct bpf_program* folio_added;
    struct bpf_program* folio_accessed;
    struct bpf_program* evict_folios;
    struct bpf_program* folio_evicted;
    struct bpf_program* migrate_push_out;
  } progs;

  struct
  {
    struct bpf_map* migration_qstate_map;
    struct bpf_map* migration_queue;
  } maps;
};

static int wrap_fifo_load(struct policy_driver* driver)
{
  return a_fifo_policy_bpf__load(driver->skel.fifo);
}
static int wrap_fifo_attach(struct policy_driver* driver)
{
  return a_fifo_policy_bpf__attach(driver->skel.fifo);
}
static void wrap_fifo_destroy(struct policy_driver* driver)
{
  if (driver->skel.fifo)
  {
    a_fifo_policy_bpf__destroy(driver->skel.fifo);
    driver->skel.fifo = NULL;
  }
}
static u64 wrap_fifo_get_call_count(struct policy_driver* driver)
{
  return (driver->skel.fifo && driver->skel.fifo->bss)
             ? driver->skel.fifo->bss->call_count
             : 0;
}

static int wrap_s3fifo_load(struct policy_driver* driver)
{
  return a_s3fifo_policy_bpf__load(driver->skel.s3fifo);
}
static int wrap_s3fifo_attach(struct policy_driver* driver)
{
  return a_s3fifo_policy_bpf__attach(driver->skel.s3fifo);
}
static void wrap_s3fifo_destroy(struct policy_driver* driver)
{
  if (driver->skel.s3fifo)
  {
    a_s3fifo_policy_bpf__destroy(driver->skel.s3fifo);
    driver->skel.s3fifo = NULL;
  }
}
static u64 wrap_s3fifo_get_call_count(struct policy_driver* driver)
{
  return (driver->skel.s3fifo && driver->skel.s3fifo->bss)
             ? driver->skel.s3fifo->bss->call_count
             : 0;
}

int select_skel(struct policy_driver* driver, enum policy_type type)
{
  switch (type)
  {
    INIT_POLICY_CASE(FIFO, fifo);
    INIT_POLICY_CASE(S3FIFO, s3fifo);
  default:
    fprintf(stderr, "Invalid or unknown policy selected.\n");
    return -1;
  }
  if (driver->progs.do_targeted_init)
    bpf_program__set_autoattach(driver->progs.do_targeted_init, false);
  if (driver->progs.trigger_push)
    bpf_program__set_autoattach(driver->progs.trigger_push, false);
  if (driver->progs.trigger_pull)
    bpf_program__set_autoattach(driver->progs.trigger_pull, false);
  return 0;
}

// *********************************************************************************************

struct dispatcher_prog_ids
{
  __u32 folio_added_id;
  __u32 folio_accessed_id;
  __u32 evict_folios_id;
  __u32 folio_evicted_id;
};
struct dispatcher_prog_fds
{
  int fd_added;
  int fd_accessed;
  int fd_evict;
  int fd_evicted;
};

int get_dispatcher_fd_from_registry(__u64 target_cgroup_id, const char* cgroup_path,
                                    struct dispatcher_prog_fds* fds)
{
  // B. 打开注册表 Map
  int map_fd = bpf_obj_get(REGISTRY_MAP_PATH);
  if (map_fd < 0)
  {
    fprintf(stderr, "Error: Registry map not found at %s.\n", REGISTRY_MAP_PATH);
    fprintf(stderr, "Hint: Is the 'a_dispatcher' running?\n");
    return -1;
  }

  // C. 查表：Cgroup ID -> Dispatcher Prog ID
  struct dispatcher_prog_ids ids = {0};
  int ret = bpf_map_lookup_elem(map_fd, &target_cgroup_id, &ids);
  close(map_fd);

  if (ret < 0)
  {
    fprintf(stderr, "Error: No dispatcher registered for Cgroup %s (ID: %llu).\n",
            cgroup_path, target_cgroup_id);
    fprintf(stderr, "Hint: Please check if 'a_dispatcher' is attached to this specific cgroup.\n");
    return -1;
  }

  // D. 把 Prog ID 转换成 Kernel File Descriptor
  fds->fd_added = bpf_prog_get_fd_by_id(ids.folio_added_id);
  fds->fd_accessed = bpf_prog_get_fd_by_id(ids.folio_accessed_id);
  fds->fd_evict = bpf_prog_get_fd_by_id(ids.evict_folios_id);
  fds->fd_evicted = bpf_prog_get_fd_by_id(ids.folio_evicted_id);

  printf("Service Discovery: folio_added (FD:%d), evict_folios (FD:%d)\n",
         fds->fd_added, fds->fd_evict);
  return 0;
}

// 提取出的通用挂载函数
static int attach_prog_to_slot(struct bpf_program* prog, int host_fd, const char* func_name, int slot_id)
{
  char slot_func_name[64];
  snprintf(slot_func_name, sizeof(slot_func_name), "slot_%s%d", func_name, slot_id);

  bpf_program__set_type(prog, BPF_PROG_TYPE_EXT);

  if (bpf_program__set_attach_target(prog, host_fd, slot_func_name))
  {
    fprintf(stderr, "Failed to set attach target for %s\n", slot_func_name);
    return -1;
  }
  return 0;
}

static int prepare_slot_hooks(struct policy_driver* policy, struct dispatcher_prog_fds* fds, int slot_id)
{
  if (attach_prog_to_slot(policy->progs.folio_added, fds->fd_added,
                          "folio_added", slot_id) < 0)
    return -1;
  if (attach_prog_to_slot(policy->progs.folio_accessed, fds->fd_accessed,
                          "folio_accessed", slot_id) < 0)
    return -1;
  if (attach_prog_to_slot(policy->progs.evict_folios, fds->fd_evict,
                          "evict_folios", slot_id) < 0)
    return -1;
  if (attach_prog_to_slot(policy->progs.folio_evicted, fds->fd_evicted,
                          "folio_evicted", slot_id) < 0)
    return -1;
  return 0;
}

static int trigger_syscall_prog(struct bpf_program* prog)
{
  if (!prog)
    return -1;

  int prog_fd = bpf_program__fd(prog);
  if (prog_fd < 0)
  {
    fprintf(stderr, "Invalid trigger_pull prog fd\n");
    return -1;
  }
  DECLARE_LIBBPF_OPTS(bpf_test_run_opts, opts,
                      .ctx_in = NULL,
                      .ctx_size_in = 0, );
  int err = bpf_prog_test_run_opts(prog_fd, &opts);
  if (err < 0)
  {
    fprintf(stderr, "Failed to run syscall prog: %s\n", strerror(errno));
    return -1;
  }
  return opts.retval;
}

static int trigger_cgroup_iterator(const char* cgroup_path, struct bpf_program* prog)
{
  if (!cgroup_path || !prog)
  {
    fprintf(stderr, "Error: Invalid arguments to trigger_cgroup_iterator\n");
    return -1;
  }
  int cgroup_fd = open(cgroup_path, O_RDONLY);
  if (cgroup_fd < 0)
  {
    fprintf(stderr, "Failed to open cgroup path %s: %s\n", cgroup_path, strerror(errno));
    return -1;
  }
  DECLARE_LIBBPF_OPTS(bpf_iter_attach_opts, opts);
  struct bpf_iter_link_info_kern linfo = {};
  linfo.cgroup.cgroup_fd = cgroup_fd;
  linfo.cgroup.order = BPF_CGROUP_ITER_SELF_ONLY;
  opts.link_info = &linfo;
  opts.link_info_len = sizeof(linfo);

  // 1. 挂载迭代器程序
  struct bpf_link* iter_link = bpf_program__attach_iter(prog, &opts);
  if (!iter_link)
  {
    perror("Failed to attach iterator program");
    close(cgroup_fd);
    return -1;
  }
  // 2. 创建迭代器文件描述符
  int ret = -1;
  int iter_fd = bpf_iter_create(bpf_link__fd(iter_link));
  if (iter_fd >= 0)
  {
    char buf[16];
    ssize_t bytes;

    while ((bytes = read(iter_fd, buf, sizeof(buf))) > 0)
    {
    }
    if (bytes < 0)
      perror("Read iterator error");
    else
    {
      printf("Iterator pipeline execution finished.\n");
      ret = 0; // 成功执行完毕
    }
    close(iter_fd);
  }
  else
    perror("Failed to create iter fd");

  bpf_link__destroy(iter_link);
  close(cgroup_fd);
  return ret;
}

int main(int argc, char** argv)
{
  struct cmdline_args args = {0};
  int ret = 1;
  int shared_qstate_fd = -1;
  int shared_queue_fd = -1;

  if (argp_parse(&argp, argc, argv, 0, 0, &args))
    return 1;
  if (!args.cgroup_path)
  {
    fprintf(stderr, "Error: --cgroup_path is required.\n");
    return 1;
  }

  // 获取 Cgroup ID (Inode)
  struct stat st;
  if (stat(args.cgroup_path, &st) < 0)
  {
    fprintf(stderr, "Error: Failed to verify cgroup path %s: %s\n",
            args.cgroup_path, strerror(errno));
    return -1;
  }

  // 查找内核中 Dispatcher 的主入口名称
  __u64 target_cgroup_id = st.st_ino;
  struct dispatcher_prog_fds fds = {-1, -1, -1, -1};
  if (get_dispatcher_fd_from_registry(
          target_cgroup_id, args.cgroup_path, &fds) < 0)
    goto cleanup;

  // *********************** Old Policy ***********************
  struct policy_driver old_policy;
  memset(&old_policy, 0, sizeof(old_policy));
  if (select_skel(&old_policy, args.old_policy) < 0)
  {
    fprintf(stderr, "Error: Failed to initialize selected policy skeleton.\n");
    goto cleanup;
  }

  if (prepare_slot_hooks(&old_policy, &fds, 1) < 0)
    goto cleanup;

  if (old_policy.load(&old_policy) || old_policy.attach(&old_policy))
  {
    fprintf(stderr, "Failed to load/attach Old Policy.\n");
    goto cleanup;
  }
  printf("Old Policy running. Inject traffic now, then press [ENTER] to migrate...\n");
  getchar();

  // *********************** New Policy ***********************
  struct policy_driver new_policy;
  memset(&new_policy, 0, sizeof(new_policy));
  if (select_skel(&new_policy, args.new_policy) < 0)
  {
    fprintf(stderr, "Error: Failed to initialize selected policy skeleton.\n");
    goto cleanup;
  }

  int old_qstate_fd = bpf_map__fd(old_policy.maps.migration_qstate_map);
  int old_queue_fd = bpf_map__fd(old_policy.maps.migration_queue);
  if (old_qstate_fd < 0 || old_queue_fd < 0)
  {
    fprintf(stderr, "Error: Failed to extract shared Map FDs from old policy.\n");
    goto cleanup;
  }
  if (bpf_map__reuse_fd(new_policy.maps.migration_qstate_map, old_qstate_fd) < 0 ||
      bpf_map__reuse_fd(new_policy.maps.migration_queue, old_queue_fd) < 0)
  {
    fprintf(stderr, "Error: Failed to reuse shared maps for new policy.\n");
    goto cleanup;
  }

  if (prepare_slot_hooks(&new_policy, &fds, 2) < 0)
    goto cleanup;

  if (new_policy.load(&new_policy) || new_policy.attach(&new_policy))
  {
    fprintf(stderr, "Failed to load/attach New Policy.\n");
    goto cleanup;
  }

  printf("Starting asynchronous state migration...\n");
  if (trigger_cgroup_iterator(args.cgroup_path, old_policy.progs.trigger_push) < 0)
  {
    fprintf(stderr, "Failed to execute migration pipeline.\n");
    goto cleanup;
  }
  int total_pulled = 0;
  while (1)
  {
    int count = trigger_syscall_prog(new_policy.progs.trigger_pull);

    if (count < 0)
    {
      fprintf(stderr, "Error occurred during data pull.\n");
      break;
    }
    if (count == 0)
      break;
    total_pulled += count;
    printf("Pulled %d folios (Total: %d)...\n", count, total_pulled);
  }
  // *******************************************************

  printf("Both policies are now attached to Dispatcher. Press [ENTER] to exit...\n");
  getchar();

  fflush(stdout);

  // while (1)
  // {
  //   sleep(3);
  //   if (new_policy.get_call_count)
  //     printf("Current call_count: %llu\n", new_policy.get_call_count(&new_policy));
  // }
  ret = 0;

cleanup:
  if (shared_qstate_fd >= 0)
    close(shared_qstate_fd);
  if (shared_queue_fd >= 0)
    close(shared_queue_fd);
  if (fds.fd_added >= 0)
    close(fds.fd_added);
  if (fds.fd_accessed >= 0)
    close(fds.fd_accessed);
  if (fds.fd_evict >= 0)
    close(fds.fd_evict);
  if (fds.fd_evicted >= 0)
    close(fds.fd_evicted);
  if (old_policy.destroy)
    old_policy.destroy(&old_policy);
  if (new_policy.destroy)
    new_policy.destroy(&new_policy);
  return ret;
}