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
  int slot_id;
  enum policy_type policy;
};

static struct argp_option options[] = {
    {"cgroup_path", 'c', "PATH", 0, "Path to cgroup (must match Dispatcher's cgroup)"},
    {"slot_id", 's', "ID", 0, "Slot ID to attach to (default: 1)"},
    {"policy", 'p', "NAME", 0, "Policy to load (e.g., fifo, s3fifo. default: fifo)"},
    {0}};

static error_t parse_opt(int key, char* arg, struct argp_state* state)
{
  struct cmdline_args* args = state->input;
  switch (key)
  {
  case 'c':
    args->cgroup_path = arg;
    break;
  case 's':
    args->slot_id = atoi(arg);
    break;
  case 'p':
    if (strcmp(arg, "fifo") == 0)
      args->policy = POLICY_FIFO;
    else if (strcmp(arg, "s3fifo") == 0)
      args->policy = POLICY_S3FIFO;
    else
      args->policy = POLICY_UNKNOWN; // 无法识别的策略
    break;
  default:
    return ARGP_ERR_UNKNOWN;
  }
  return 0;
}

static struct argp argp = {options, parse_opt, 0, "Load FIFO policy and attach to a specific Cgroup Dispatcher."};

/********策略选择*********/
#define INIT_POLICY_CASE(UPPER, lower)                                               \
  case POLICY_##UPPER:                                                               \
    driver->type = POLICY_##UPPER;                                                   \
    driver->skel.lower = a_##lower##_policy_bpf__open();                             \
    if (!driver->skel.lower)                                                         \
      return -1;                                                                     \
    driver->load = wrap_##lower##_load;                                              \
    driver->attach = wrap_##lower##_attach;                                          \
    driver->destroy = wrap_##lower##_destroy;                                        \
    driver->get_call_count = wrap_##lower##_get_call_count;                          \
    driver->progs.do_targeted_init = driver->skel.lower->progs.do_targeted_init;     \
    driver->progs.folio_added = driver->skel.lower->progs.lower##_folio_added;       \
    driver->progs.folio_accessed = driver->skel.lower->progs.lower##_folio_accessed; \
    driver->progs.evict_folios = driver->skel.lower->progs.lower##_evict_folios;     \
    driver->progs.folio_evicted = driver->skel.lower->progs.lower##_folio_evicted;   \
    return 0;

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
    struct bpf_program* folio_added;
    struct bpf_program* folio_accessed;
    struct bpf_program* evict_folios;
    struct bpf_program* folio_evicted;
  } progs;
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

int main(int argc, char** argv)
{
  struct cmdline_args args = {0};
  int ret = 1;

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
  struct dispatcher_prog_fds fds = {-1, -1, -1};
  if (get_dispatcher_fd_from_registry(
          target_cgroup_id, args.cgroup_path, &fds) < 0)
    goto cleanup;

  struct policy_driver policy;
  memset(&policy, 0, sizeof(policy));
  if (select_skel(&policy, args.policy) < 0)
  {
    fprintf(stderr, "Error: Failed to initialize selected policy skeleton.\n");
    goto cleanup;
  }
  bpf_program__set_autoattach(policy.progs.do_targeted_init, false);

  // folio_added
  if (attach_prog_to_slot(policy.progs.folio_added, fds.fd_added,
                          "folio_added", args.slot_id) < 0)
    goto cleanup;
  // folio accessed
  if (attach_prog_to_slot(policy.progs.folio_accessed, fds.fd_accessed,
                          "folio_accessed", args.slot_id) < 0)
    goto cleanup;
  // evict_folios
  if (attach_prog_to_slot(policy.progs.evict_folios, fds.fd_evict,
                          "evict_folios", args.slot_id) < 0)
    goto cleanup;
  // folio evicted
  if (attach_prog_to_slot(policy.progs.folio_evicted, fds.fd_evicted,
                          "folio_evicted", args.slot_id) < 0)
    goto cleanup;

  if (policy.load(&policy))
  {
    fprintf(stderr, "Failed to load FIFO skeleton\n");
    goto cleanup;
  }
  if (policy.attach(&policy))
  {
    fprintf(stderr, "Failed to attach FIFO skeleton\n");
    goto cleanup;
  }

  // int cgroup_fd = open(args.cgroup_path, O_RDONLY);
  // if (cgroup_fd < 0)
  // {
  //   fprintf(stderr, "Failed to open cgroup path %s: %s\n",
  //           args.cgroup_path, strerror(errno));
  //   goto cleanup;
  // }
  // DECLARE_LIBBPF_OPTS(bpf_iter_attach_opts, opts);
  // struct bpf_iter_link_info_kern linfo = {};
  // linfo.cgroup.cgroup_fd = cgroup_fd;
  // linfo.cgroup.order = BPF_CGROUP_ITER_SELF_ONLY;
  // opts.link_info = &linfo;
  // opts.link_info_len = sizeof(linfo);
  // struct bpf_link* iter_link = bpf_program__attach_iter(
  //     skel->progs.do_targeted_init, &opts);
  // if (!iter_link)
  // {
  //   perror("Failed to attach init iterator");
  //   goto cleanup;
  // }
  // int iter_fd = bpf_iter_create(bpf_link__fd(iter_link));
  // if (iter_fd >= 0)
  // {
  //   char buf[16];
  //   ssize_t bytes;
  //   while ((bytes = read(iter_fd, buf, sizeof(buf))) > 0)
  //   {
  //     printf("Read %zd bytes from iterator\n", bytes);
  //   }
  //   if (bytes < 0)
  //     perror("Read iterator error");
  //   printf("Iterator read finished.\n");
  //   close(iter_fd);
  // }
  // else
  //   perror("Failed to create iter fd");
  // bpf_link__destroy(iter_link);

  printf("Successfully linked FIFO policy to Dispatcher slot %d\n", args.slot_id);

  printf("Press Enter to unload policy and exit...\n");
  fflush(stdout);

  while (1)
  {
    sleep(3);
    if (policy.get_call_count)
      printf("Current call_count: %llu\n", policy.get_call_count(&policy));
  }
  getchar(); // 等待用户按下回车
  ret = 0;

cleanup:
  if (fds.fd_added >= 0)
    close(fds.fd_added);
  if (fds.fd_accessed >= 0)
    close(fds.fd_accessed);
  if (fds.fd_evict >= 0)
    close(fds.fd_evict);
  if (fds.fd_evicted >= 0)
    close(fds.fd_evicted);
  if (policy.destroy)
    policy.destroy(&policy);
  return ret;
}