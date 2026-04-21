#include "cache_ext_lib.bpf.h"
// #include "dir_watcher.bpf.h"
#include "logger.h"
#include "vmlinux.h"

#ifndef likely
#define likely(x) __builtin_expect(!!(x), 1)
#endif
#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif

char __license[] SEC("license") = "GPL";

#define ENOENT 2 /* include/uapi/asm-generic/errno-base.h */
#define INT64_MAX (9223372036854775807LL)

#define CACHE_SIZE (((1ull << 20) * 200) / 4096)
const volatile size_t cache_size = 0;

static volatile const u64 secret = 0x9876543210;

/**
 * ****************************************** MAP *******************************************
 */

struct folio_metadata
{
  s64 freq;
  bool in_main;
};

struct ghost_entry
{
  u64 address_space;
  u64 offset;
};

struct
{
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, u64);
  __type(value, struct folio_metadata);
  __uint(max_entries, 4000000);
} folio_metadata_map SEC(".maps");

struct
{
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __type(key, struct ghost_entry);
  __type(value, u8);
  __uint(max_entries, 4000000);
  __uint(map_flags, BPF_F_NO_COMMON_LRU); // Per-CPU LRU eviction logic
} ghost_map SEC(".maps");

static __always_inline struct folio_metadata* get_folio_metadata(struct folio* folio)
{
  u64 key = (u64)folio;

  struct cache_ext_val_buffer* ptr = bpf_cache_ext_map_lookup(
      (struct bpf_map*)&folio_metadata_map, &key, sizeof(key));

  return (struct folio_metadata*)ptr;
}

static __always_inline int set_folio_metadata(struct folio* folio, struct folio_metadata* data)
{
  u64 key = (u64)folio;

  // 调用底层的 kfunc，把栈上的 data 内存安全地覆盖到 Map 里
  return bpf_cache_ext_map_update((struct bpf_map*)&folio_metadata_map,
                                  &key, sizeof(key),
                                  data, sizeof(*data));
}

static inline bool folio_in_ghost(struct folio* folio)
{
  if (!folio->mapping)
    return false;

  struct ghost_entry key = {
      .address_space = (u64)folio->mapping->host,
      .offset = folio->index,
  };
  // TODO: handle non-ENOENT errors
  // 返回 0 为成功
  return bpf_cache_ext_map_delete((struct bpf_map*)&ghost_map, &key, sizeof(key)) == 0;
}

/**
 * ****************************************** INIT *******************************************
 */
static u64 main_list;
static u64 small_list;

static s64 small_list_size = 0;
static s64 main_list_size = 0;

static __always_inline int ensure_initialized_impl(u64 tmp_main_list, u64 tmp_small_list)
{
  if (tmp_main_list == 0 || tmp_small_list == 0)
  {
    // bpf_printk("FIFO init failed: list ID is 0\n");
    return -1;
  }
  // CAS
  __sync_val_compare_and_swap(&main_list, 0, tmp_main_list);
  __sync_val_compare_and_swap(&small_list, 0, tmp_small_list);

  return 0;
}

static __always_inline int ensure_initialized_by_memcg(struct mem_cgroup* memcg)
{
  if (likely(main_list != 0 && small_list != 0))
    return 0;
  u64 tmp_main_list = bpf_cache_ext_ds_registry_new_list(memcg);
  u64 tmp_small_list = bpf_cache_ext_ds_registry_new_list(memcg);
  return ensure_initialized_impl(tmp_main_list, tmp_small_list);
}

static __always_inline int ensure_initialized_by_folio(struct folio* folio)
{
  if (likely(main_list != 0 && small_list != 0))
    return 0;
  u64 tmp_main_list = bpf_cache_ext_ds_registry_new_list_from_folio(folio);
  u64 tmp_small_list = bpf_cache_ext_ds_registry_new_list_from_folio(folio);
  return ensure_initialized_impl(tmp_main_list, tmp_small_list);
}

SEC("iter/cgroup")
int do_targeted_init(struct bpf_iter__cgroup* ctx)
{
  struct cgroup* cgrp = ctx->cgroup;
  if (!cgrp)
    return 0;
  struct mem_cgroup* memcg = bpf_cgroup_to_memcg(cgrp);
  if (!memcg)
  {
    bpf_printk("null memcg\n");
    return 0;
  }

  // 初始化
  bpf_printk("S3FIFO Loader Init\n");
  main_list = bpf_cache_ext_ds_registry_new_list(memcg);
  small_list = bpf_cache_ext_ds_registry_new_list(memcg);

  return 0;
}

/**
 * ****************************************** MIGRATION *******************************************
 */

static int s3fifo_push_cb(int idx, struct cache_ext_list_node* a)
{
  u32 state_key = 0;
  migration_qstate* qstate = bpf_map_lookup_elem(&migration_qstate_map, &state_key);
  if (!qstate)
    return CACHE_EXT_STOP_ITER;

  u32 head = READ_ONCE(qstate->head);
  u32 current_tail = READ_ONCE(qstate->tail);
  if (current_tail - head >= MIGRATION_Q_SIZE)
    return CACHE_EXT_STOP_ITER;

  u64 handle = bpf_cache_ext_folio_to_handle(a->folio, secret);

  u32 tail = __sync_fetch_and_add(&qstate->tail, 1);
  u32 q_idx = tail & (MIGRATION_Q_SIZE - 1);
  generic_cache_metrics metrics = {.handle = handle,
                                   .seq = tail + 1};

  long err = bpf_map_update_elem(&migration_queue, &q_idx, &metrics, BPF_ANY);
  if (err)
    return CACHE_EXT_STOP_ITER;
  return CACHE_EXT_CONTINUE_ITER;
}

SEC("iter/cgroup")
int trigger_push(struct bpf_iter__cgroup* ctx)
{
  struct cgroup* cgrp = ctx->cgroup;
  if (!cgrp)
    return 0;
  struct mem_cgroup* memcg = bpf_cgroup_to_memcg(cgrp);
  if (!memcg)
    return 0;
  // if (!main_list || !small_list)
  //   return 0;

  bpf_printk("[S3FIFO] Starting pipeline push for memcg...\n");
  bpf_cache_ext_list_iterate_scan(memcg, small_list, s3fifo_push_cb);
  bpf_cache_ext_list_iterate_scan(memcg, main_list, s3fifo_push_cb);
  return 0;
}

// TODO： 处理页面被old policy驱逐后，迁移回新policy的情况
// 兼容 FIFO(仅存活时间), LRU(有最近访问时间), LFU/ARC(有真实频次)
static __always_inline int
__s3fifo_add_folio(struct folio* folio,
                   generic_cache_metrics* migrated_metrics)
{
  if (!migrated_metrics || ensure_initialized_by_folio(folio) < 0)
    return -1;

  if (!folio->mapping || folio_in_ghost(folio))
    return 0;

  u64 key = (u64)folio;
  struct folio_metadata new_meta = {0};
  u64 list_to_add;

  new_meta.freq = (migrated_metrics->freq >= 3) ? 3 : migrated_metrics->freq;
  new_meta.in_main = true;
  list_to_add = main_list;

  if (bpf_map_update_elem((struct bpf_map*)&folio_metadata_map, &key, &new_meta, BPF_NOEXIST))
    return 0;

  int ret = bpf_cache_ext_list_add_tail(list_to_add, folio);
  if (ret)
  {
    bpf_cache_ext_map_delete((struct bpf_map*)&folio_metadata_map, &key, sizeof(key));
    return -1;
  }

  __sync_fetch_and_add(&main_list_size, 1);

  return 0;
}

SEC("syscall")
int trigger_pull(void* ctx)
{
  // struct cgroup* cgrp = ctx->cgroup;
  // if (!cgrp)
  //   return 0;
  // struct mem_cgroup* memcg = bpf_cgroup_to_memcg(cgrp);
  // if (!memcg)
  //   return 0;

  u32 state_key = 0;
  migration_qstate* qstate = bpf_map_lookup_elem(&migration_qstate_map, &state_key);
  if (!qstate)
    return 0;

  bpf_printk("[S3FIFO] Received pull trigger from migration queue.\n");
  int count = 0;

  for (int i = 0; i < 1024; i++)
  {
    u32 head = READ_ONCE(qstate->head);
    if (head == READ_ONCE(qstate->tail))
      break;

    u32 idx = head & (MIGRATION_Q_SIZE - 1);

    generic_cache_metrics* m = bpf_map_lookup_elem(&migration_queue, &idx);
    if (!m || m->seq != head + 1)
      break;

    // 必须将数据拷贝到本地栈，因为 Array 里的内存槽会被后续复用
    generic_cache_metrics metrics = *m;

    // 数据读取成功，原子移动 Head 指针 (完成 Pop 操作)
    if (__sync_val_compare_and_swap(&qstate->head, head, head + 1) != head)
      continue;

    struct folio* f = bpf_cache_ext_handle_to_folio(metrics.handle, secret);
    if (!f || !f->mapping)
      continue;

    struct folio_metadata* existing_data = get_folio_metadata(f);
    // TODO: 有改进空间
    if (existing_data)
    {
      u64 key = (u64)f;
      bpf_cache_ext_map_inc((struct bpf_map*)&folio_metadata_map, &key, sizeof(key),
                            __builtin_offsetof(struct folio_metadata, freq), 3);
      continue;
    }

    // bpf_printk("Checking migration queue: head=%u, tail=%u\n",
    //            READ_ONCE(qstate->head), READ_ONCE(qstate->tail));
    if (__s3fifo_add_folio(f, &metrics) == 0)
    {
      count++;
    }
  }
  return count;
}
// *********************************************************************************************

static int bpf_s3fifo_score_small_fn(int idx, struct cache_ext_list_node* a)
{
  if (!folio_test_uptodate(a->folio) || !folio_test_lru(a->folio))
    return CACHE_EXT_CONTINUE_ITER;

  if (folio_test_dirty(a->folio) || folio_test_writeback(a->folio))
    return CACHE_EXT_CONTINUE_ITER;
  struct folio_metadata* data = get_folio_metadata(a->folio);
  if (!data)
  {
    // bpf_printk("cache_ext: score_fn: Failed to get metadata\n");
    return CACHE_EXT_CONTINUE_ITER;
  }
  // Move to main list if freq > 1
  if (data->freq > 1)
  {
    // struct folio_metadata new_data = *data;
    // new_data.in_main = true;
    // set_folio_metadata(a->folio, &new_data);

    u64 key_val = (u64)a->folio;
    bpf_cache_ext_map_set_bool(
        (struct bpf_map*)&folio_metadata_map, &key_val, sizeof(key_val),
        __builtin_offsetof(struct folio_metadata, in_main), true);
    return CACHE_EXT_CONTINUE_ITER;
  }
  // Else, evict
  return CACHE_EXT_EVICT_NODE;
}

static void evict_small(struct cache_ext_eviction_ctx* eviction_ctx, struct mem_cgroup* memcg)
{
  /*
   * Iterate from head. If freq > 1, move to main list, otherwise evict.
   * (When evicting, move to tail in the meantime).
   *
   * Use the iterate interface.
   */
  struct cache_ext_iterate_opts opts = {
      .continue_list = main_list,
      .continue_mode = CACHE_EXT_ITERATE_TAIL,
      .evict_list = CACHE_EXT_ITERATE_SELF,
      .evict_mode = CACHE_EXT_ITERATE_TAIL,
  };

  if (bpf_cache_ext_list_iterate_extended(memcg, small_list, bpf_s3fifo_score_small_fn, &opts,
                                          eviction_ctx) < 0)
  {
    // bpf_printk("cache_ext: evict: Failed to iterate small_list\n");
    return;
  }
  if (__sync_fetch_and_sub(&small_list_size, opts.nr_folios_continue) < 0)
    small_list_size = 0;
  if (__sync_fetch_and_add(&main_list_size, opts.nr_folios_continue) < 0)
    main_list_size = opts.nr_folios_continue;
}

#define MAIN_ITER_FN(id)                                                                \
  static int bpf_s3fifo_score_main_iter_fn_##id(int idx, struct cache_ext_list_node* a) \
  {                                                                                     \
    if (!folio_test_uptodate(a->folio) || !folio_test_lru(a->folio) ||                  \
        folio_test_dirty(a->folio) || folio_test_writeback(a->folio))                   \
      return CACHE_EXT_CONTINUE_ITER;                                                   \
                                                                                        \
    u64 key = (u64)a->folio;                                                            \
    s64 new_freq = bpf_cache_ext_map_dec(                                               \
        (struct bpf_map*)&folio_metadata_map, &key, sizeof(key),                        \
        __builtin_offsetof(struct folio_metadata, freq), 0);                            \
                                                                                        \
    if (new_freq < 0)                                                                   \
      return CACHE_EXT_CONTINUE_ITER;                                                   \
    if (new_freq < id)                                                                  \
      /*data->freq = 0;*/                                                               \
      return CACHE_EXT_EVICT_NODE;                                                      \
                                                                                        \
    return CACHE_EXT_CONTINUE_ITER;                                                     \
  }

MAIN_ITER_FN(0)
MAIN_ITER_FN(1)
MAIN_ITER_FN(2)
MAIN_ITER_FN(3)

static void evict_main_iter(struct cache_ext_eviction_ctx* eviction_ctx, struct mem_cgroup* memcg)
{
  /*
   * Iterate from head. If freq > 0, move to tail, freq--.
   * Otherwise, evict. (When evicting, move to tail in the meantime).
   */

  struct cache_ext_iterate_opts opts = {
      .continue_list = CACHE_EXT_ITERATE_SELF,
      .continue_mode = CACHE_EXT_ITERATE_TAIL,
      .evict_list = CACHE_EXT_ITERATE_SELF,
      .evict_mode = CACHE_EXT_ITERATE_TAIL,
  };

  if (bpf_cache_ext_list_iterate_extended(memcg, main_list,
                                          bpf_s3fifo_score_main_iter_fn_0, &opts, eviction_ctx) < 0)
    // bpf_printk("cache_ext: evict: Failed to iterate main_list\n");
    return;

  if (eviction_ctx->nr_folios_to_evict < eviction_ctx->request_nr_folios_to_evict)
  {
    if (bpf_cache_ext_list_iterate_extended(memcg, main_list,
                                            bpf_s3fifo_score_main_iter_fn_1, &opts, eviction_ctx) < 0)
      // bpf_printk("cache_ext: evict: Failed to iterate main_list\n");
      return;
  }
  else
    return;

  if (eviction_ctx->nr_folios_to_evict < eviction_ctx->request_nr_folios_to_evict)
  {
    if (bpf_cache_ext_list_iterate_extended(memcg, main_list,
                                            bpf_s3fifo_score_main_iter_fn_2, &opts, eviction_ctx) < 0)
      // bpf_printk("cache_ext: evict: Failed to iterate main_list\n");
      return;
  }
  else
    return;

  if (eviction_ctx->nr_folios_to_evict < eviction_ctx->request_nr_folios_to_evict)
  {
    if (bpf_cache_ext_list_iterate_extended(memcg, main_list, bpf_s3fifo_score_main_iter_fn_3, &opts,
                                            eviction_ctx) < 0)
      // bpf_printk("cache_ext: evict: Failed to iterate main_list\n");
      return;
  }
}

SEC("freplace/slot_evict_folios1")
int s3fifo_evict_folios(u64 eviction_ctx_handle, u64 memcg_handle)
{
  // bpf_printk("FIFO evicted.\n");

  struct cache_ext_eviction_ctx* eviction_ctx =
      bpf_cache_ext_handle_to_ctx(eviction_ctx_handle, secret);

  struct mem_cgroup* memcg =
      bpf_cache_ext_handle_to_memcg(memcg_handle, secret);

  if (!eviction_ctx || !memcg)
    return -1;

  if (ensure_initialized_by_memcg(memcg) < 0)
    return -1;
  if (small_list_size >= cache_size / 15 || main_list_size <= 2 * small_list_size)
    evict_small(eviction_ctx, memcg);
  else
    evict_main_iter(eviction_ctx, memcg);
  return 0;
}

SEC("freplace/slot_folio_accessed1")
int s3fifo_folio_accessed(u64 handle)
{

  struct folio* folio = bpf_cache_ext_handle_to_folio(handle, secret);
  if (!folio)
    return -1;
  if (ensure_initialized_by_folio(folio) < 0)
    return -1;

  // Cap frequency at 3
  u64 key = (u64)folio;
  if (bpf_cache_ext_map_inc((struct bpf_map*)&folio_metadata_map, &key, sizeof(key),
                            __builtin_offsetof(struct folio_metadata, freq), 3) < 0)
    return -1;
  // if (__sync_add_and_fetch(&data->freq, 1) > 3)
  //   data->freq = 3;
  return 0;
}

u64 call_count = 0;

SEC("freplace/slot_folio_evicted1")
int s3fifo_folio_evicted(u64 handle)
{
  struct folio* folio = bpf_cache_ext_handle_to_folio(handle, secret);
  if (!folio)
    return -1;
  if (ensure_initialized_by_folio(folio) < 0)
    return -1;

  u64 key = (u64)folio;
  u8 ghost_val = 0;

  // if (bpf_cache_ext_list_del(folio)) {
  // 	bpf_printk("cache_ext: Failed to delete folio from sampling_list\n");
  // 	return;
  // }
  struct ghost_entry ghost_key = {
      .address_space = (u64)folio->mapping->host,
      .offset = folio->index,
  };
  // Don't return early, we want to delete the folio metadata regardless
  bpf_cache_ext_map_update((struct bpf_map*)&ghost_map,
                           &ghost_key, sizeof(ghost_key),
                           &ghost_val, sizeof(ghost_val));

  struct folio_metadata* data = get_folio_metadata(folio);
  if (!data)
    // bpf_printk("cache_ext: evicted: Failed to get metadata\n");
    return -1;

  if (data->in_main)
    __sync_fetch_and_sub(&main_list_size, 1);
  else
    __sync_fetch_and_sub(&small_list_size, 1);

  bpf_cache_ext_map_delete((struct bpf_map*)&folio_metadata_map, &key, sizeof(key));

  return 0;
}

SEC("freplace/slot_folio_added1")
int s3fifo_folio_added(u64 handle)
{
  // bpf_printk("FIFO added.\n");
  struct folio* folio = bpf_cache_ext_handle_to_folio(handle, secret);
  if (!folio)
    return -1;
  if (ensure_initialized_by_folio(folio) < 0)
    return -1;

  u64 key = (u64)folio;
  struct folio_metadata new_meta = {
      .freq = 0,
  };

  u64 list_to_add;
  bool is_main = false;

  if (folio_in_ghost(folio))
  {
    list_to_add = main_list;
    new_meta.in_main = true;
    is_main = true;
  }
  else
  {
    list_to_add = small_list;
    new_meta.in_main = false;
  }

  if (bpf_cache_ext_list_add_tail(list_to_add, folio))
  {
    // TODO: add back to ghost_map?
    // bpf_printk("cache_ext: added: Failed to add folio to main_list\n");
    return -1;
  }

  if (bpf_cache_ext_map_update((struct bpf_map*)&folio_metadata_map, &key, sizeof(key),
                               &new_meta, sizeof(new_meta)))
  {
    // TODO: add back to ghost_map? + error check delete call?
    bpf_cache_ext_list_del(folio);
    // bpf_printk("cache_ext: added: Failed to create folio metadata\n");
    return -1;
  }

  if (is_main)
    __sync_fetch_and_add(&main_list_size, 1);
  else
    __sync_fetch_and_add(&small_list_size, 1);
  call_count += 1;
  return 0;
}
