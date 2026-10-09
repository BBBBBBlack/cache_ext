#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "cache_ext_lib.bpf.h"
#include "dir_watcher.bpf.h"

char _license[] SEC("license") = "GPL";

#define ENOENT 2 /* include/uapi/asm-generic/errno-base.h */
#define EEXIST 17
#define ESTALE 116 /* include/uapi/asm-generic/errno.h */
#define INT64_MAX (9223372036854775807LL)
#define S3FIFO_DIRTY_FREQ_PENALTY 1LL

// Set from userspace. In terms of number of pages.
// TODO: change

static u64 cache_size_pages = 0;

struct ghost_entry
{
  u64 address_space;
  u64 offset;
};

struct
{
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __type(key, struct ghost_entry);
  __type(value, u8);
  //__uint(max_entries, CACHE_SIZE); // TODO: change
  __uint(map_flags, BPF_F_NO_COMMON_LRU); // Per-CPU LRU eviction logic
} ghost_map SEC(".maps");

static u64 main_list;
static u64 small_list;

/*
 * Successful admission/removal counts. Transfers between these counters are
 * still separate atomics, so concurrent snapshots can be transiently skewed.
 */
s64 small_list_size = 0;
s64 main_list_size = 0;

/* Anomaly counters; accessed only counts failed node lookups, not hits.
 * Units: folios/events, not base pages. Accounting log revision 6.
 */
u32 admission_tracking_mask;
u64 diag_add_fail_list_missing;
u64 diag_add_fail_node_invalid;
u64 diag_add_fail_already_linked;
u64 diag_add_fail_other;
u64 diag_pre_add_node_missing;
u64 diag_accessed_node_missing;
u64 diag_small_negative_updates;
u64 diag_main_negative_updates;

static inline bool is_folio_relevant(struct folio* folio)
{
  if (!folio || !folio->mapping || !folio->mapping->host)
    return false;

  return inode_in_watchlist(folio->mapping->host->i_ino);
}

/*
 * Check if a folio is in the ghost map and delete the ghost entry.
 * We only check if an element is in the ghost map on inserting into the cache.
 * Relies on bpf_map_delete_elem() returning -ENOENT if the element is not found.
 */
static inline bool folio_in_ghost(struct folio* folio)
{
  struct ghost_entry key = {
      .address_space = (u64)folio->mapping->host,
      .offset = folio->index,
  };
  // TODO: handle non-ENOENT errors
  return bpf_map_delete_elem(&ghost_map, &key) != -ENOENT;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(s3fifo_init, struct mem_cgroup* memcg)
{
  admission_tracking_mask = bpf_cache_ext_admission_tracking_mask();
  if (!admission_tracking_mask)
    return -1;
  main_list = bpf_cache_ext_ds_registry_new_list(memcg);
  if (main_list == 0)
  {
    bpf_printk("cache_ext: init: Failed to create main_list\n");
    return -1;
  }
  bpf_printk("cache_ext: Created main_list: %llu\n", main_list);

  small_list = bpf_cache_ext_ds_registry_new_list(memcg);
  if (small_list == 0)
  {
    bpf_printk("cache_ext: init: Failed to create small_list\n");
    return -1;
  }
  bpf_printk("cache_ext: Created small_list: %llu\n", small_list);

  if (memcg)
    cache_size_pages = memcg->memory.max;

  return 0;
}

static s64 bpf_s3fifo_score_main_fn(struct cache_ext_list_node* a)
{
  if (!folio_test_uptodate(a->folio) || !folio_test_lru(a->folio))
    return INT64_MAX;

  if (folio_test_writeback(a->folio))
    return INT64_MAX;

  s64 freq = __sync_sub_and_fetch(&a->metadata[0], 1);
  if (folio_test_dirty(a->folio))
    freq += S3FIFO_DIRTY_FREQ_PENALTY;

  return freq;
}

static int bpf_s3fifo_score_small_fn(int idx, struct cache_ext_list_node* a)
{
  if (!folio_test_uptodate(a->folio) || !folio_test_lru(a->folio) ||
      folio_test_writeback(a->folio))
  {
    /* evict_small moves every CONTINUE node to main, including these
     * temporarily ineligible folios. Match folios_evicted accounting.
     */
    // a->metadata[1] = 1;
    // return CACHE_EXT_CONTINUE_ITER;
    return CACHE_EXT_RETRY_LATER;
  }

  // Move to main list if freq > 1
  s64 freq = (s64)a->metadata[0];
  if (folio_test_dirty(a->folio))
    freq += S3FIFO_DIRTY_FREQ_PENALTY;
  if (freq > 1)
  {
    a->metadata[1] = 1;
    return CACHE_EXT_CONTINUE_ITER;
  }

  // Else, evict
  return CACHE_EXT_EVICT_NODE;
}

static void evict_main(struct cache_ext_eviction_ctx* eviction_ctx, struct mem_cgroup* memcg)
{
  /*
   * Iterate from head. If freq > 0, move to tail, freq--.
   * Otherwise, evict. (When evicting, move to tail in the meantime).
   */

  struct sampling_options opts = {
      .sample_size = 10,
  };

  if (bpf_cache_ext_list_sample(memcg, main_list, bpf_s3fifo_score_main_fn, &opts,
                                eviction_ctx))
  {
    bpf_printk("cache_ext: evict: Failed to sample main_list\n");
    return;
  }

  // if (__sync_sub_and_fetch(&main_list_size, eviction_ctx->nr_folios_to_evict) < 0)
  // 	main_list_size = 0;
}

#define MAIN_ITER_FN(id)                                                                \
  static int bpf_s3fifo_score_main_iter_fn_##id(int idx, struct cache_ext_list_node* a) \
  {                                                                                     \
    if (!folio_test_uptodate(a->folio) || !folio_test_lru(a->folio))                    \
      return CACHE_EXT_RETRY_LATER;                                                     \
                                                                                        \
    if (folio_test_writeback(a->folio))                                                 \
      return CACHE_EXT_RETRY_LATER;                                                     \
                                                                                        \
    s64 freq = __sync_sub_and_fetch(&a->metadata[0], 1);                                \
    if (folio_test_dirty(a->folio))                                                     \
      freq += S3FIFO_DIRTY_FREQ_PENALTY;                                                \
    if (freq < id)                                                                      \
    {                                                                                   \
      return CACHE_EXT_EVICT_NODE;                                                      \
    }                                                                                   \
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
      .retry_list = CACHE_EXT_ITERATE_SELF,
      .retry_mode = CACHE_EXT_ITERATE_TAIL,
      .deferred_list = CACHE_EXT_ITERATE_SELF,
      .deferred_mode = CACHE_EXT_ITERATE_TAIL,
  };

  if (bpf_cache_ext_list_iterate_extended(memcg, main_list, bpf_s3fifo_score_main_iter_fn_0, &opts,
                                          eviction_ctx) < 0)
  {
    bpf_printk("cache_ext: evict: Failed to iterate main_list\n");
    return;
  }

  if (eviction_ctx->nr_folios_to_evict < eviction_ctx->request_nr_folios_to_evict)
  {
    if (bpf_cache_ext_list_iterate_extended(memcg, main_list, bpf_s3fifo_score_main_iter_fn_1, &opts,
                                            eviction_ctx) < 0)
    {
      bpf_printk("cache_ext: evict: Failed to iterate main_list\n");
      return;
    }
  }
  else
  {
    return;
  }

  if (eviction_ctx->nr_folios_to_evict < eviction_ctx->request_nr_folios_to_evict)
  {
    if (bpf_cache_ext_list_iterate_extended(memcg, main_list, bpf_s3fifo_score_main_iter_fn_2, &opts,
                                            eviction_ctx) < 0)
    {
      bpf_printk("cache_ext: evict: Failed to iterate main_list\n");
      return;
    }
  }
  else
  {
    return;
  }

  if (eviction_ctx->nr_folios_to_evict < eviction_ctx->request_nr_folios_to_evict)
  {
    if (bpf_cache_ext_list_iterate_extended(memcg, main_list, bpf_s3fifo_score_main_iter_fn_3, &opts,
                                            eviction_ctx) < 0)
    {
      bpf_printk("cache_ext: evict: Failed to iterate main_list\n");
      return;
    }
  }
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
      .retry_list = CACHE_EXT_ITERATE_SELF,
      .retry_mode = CACHE_EXT_ITERATE_TAIL,
      .deferred_list = CACHE_EXT_ITERATE_SELF,
      .deferred_mode = CACHE_EXT_ITERATE_TAIL,
  };

  if (bpf_cache_ext_list_iterate_extended(memcg, small_list, bpf_s3fifo_score_small_fn, &opts,
                                          eviction_ctx) < 0)
  {
    bpf_printk("cache_ext: evict: Failed to iterate small_list\n");
    return;
  }

  s64 n = opts.nr_folios_continue;
  s64 old_small = __sync_fetch_and_sub(&small_list_size, n);
  if (old_small < n)
    __sync_fetch_and_add(&diag_small_negative_updates, 1);

  s64 old_main = __sync_fetch_and_add(&main_list_size, n);
  if (old_main < -n)
    __sync_fetch_and_add(&diag_main_negative_updates, 1);
  /* Do not clamp with plain stores: that can discard concurrent updates.
   * Retain diagnostics for remaining transfer/accounting races instead.
   */
}

void BPF_STRUCT_OPS(s3fifo_evict_folios, struct cache_ext_eviction_ctx* eviction_ctx,
                    struct mem_cgroup* memcg)
{
  // bpf_printk("cache_ext: evict_folios: main_list_size: %lld, small_list_size: %lld, cache_size: %lld\n",
  // 	   main_list_size, small_list_size, cache_size);
  if (small_list_size >= (s64)(cache_size_pages / 15) || main_list_size <= 2 * small_list_size)
    evict_small(eviction_ctx, memcg);
  else
    evict_main_iter(eviction_ctx, memcg);
}

void BPF_STRUCT_OPS(s3fifo_folio_accessed, struct folio* folio)
{
  if (!is_folio_relevant(folio))
    return;

  struct cache_ext_list_node* node = bpf_cache_ext_folio_to_node(folio);
  if (!node)
  {
    __sync_fetch_and_add(&diag_accessed_node_missing, 1);
    return;
  }

  // Cap frequency at 3
  if (__sync_add_and_fetch(&node->metadata[0], 1) > 3)
    node->metadata[0] = 3;
}

void BPF_STRUCT_OPS(s3fifo_folios_evicted, struct cache_ext_evicted_ctx* ectx)
{
  for (int i = 0; i < (int)ectx->nr_folios && i < 32; i++)
  {
    struct folio* folio = ectx->folios[i];
    if (!folio)
      continue;

    u8 ghost_val = 0;

    struct ghost_entry ghost_key = {
        .address_space = (u64)folio->mapping->host,
        .offset = folio->index,
    };
    bpf_map_update_elem(&ghost_map, &ghost_key, &ghost_val, BPF_ANY);

    struct cache_ext_list_node* node = bpf_cache_ext_folio_to_node(folio);
    if (!node)
      continue;

    bool in_main = (bool)node->metadata[1];
    bool admitted = !!(node->state.counter & admission_tracking_mask);
    if (!admitted)
      continue;
    /* EVER_ADMITTED is sufficient for this fresh Direct policy attachment;
     * it is not policy-generation ownership across live policy switching.
     */
    if (in_main)
    {
      if (__sync_fetch_and_sub(&main_list_size, 1) <= 0)
        __sync_fetch_and_add(&diag_main_negative_updates, 1);
    }
    else
    {
      if (__sync_fetch_and_sub(&small_list_size, 1) <= 0)
        __sync_fetch_and_add(&diag_small_negative_updates, 1);
    }
  }
}

/*
 * If folio is in the ghost map, add to tail of main list, otherwise add to tail
 * of small list.
 */
void BPF_STRUCT_OPS(s3fifo_folio_added, struct folio* folio)
{
  if (!is_folio_relevant(folio))
    return;

  bool is_ghost = folio_in_ghost(folio);
  /* Obtain the node before changing counters or list membership. Keep ghost
   * lookup/consumption in its original position, including failure cases.
   * The filemap addition caller holds the folio locked through initialization.
   */
  struct cache_ext_list_node* node = bpf_cache_ext_folio_to_node(folio);
  if (!node)
  {
    __sync_fetch_and_add(&diag_pre_add_node_missing, 1);
    return;
  }
  u64 list_to_add;
  if (is_ghost)
  {
    list_to_add = main_list;
    __sync_fetch_and_add(&main_list_size, 1);
  }
  else
  {
    list_to_add = small_list;
    __sync_fetch_and_add(&small_list_size, 1);
  }

  int add_ret = bpf_cache_ext_list_add_tail(list_to_add, folio);
  if (add_ret)
  {
    /* Only the failure path pays for reason classification. Old kernels
     * return -1 for all causes; leave those in other, never guess a reason.
     */
    if (add_ret == -ENOENT)
      __sync_fetch_and_add(&diag_add_fail_list_missing, 1);
    else if (add_ret == -ESTALE)
      __sync_fetch_and_add(&diag_add_fail_node_invalid, 1);
    else if (add_ret == -EEXIST)
      __sync_fetch_and_add(&diag_add_fail_already_linked, 1);
    else
      __sync_fetch_and_add(&diag_add_fail_other, 1);
    if (is_ghost)
    {
      if (__sync_fetch_and_sub(&main_list_size, 1) <= 0)
        __sync_fetch_and_add(&diag_main_negative_updates, 1);
    }
    else
    {
      if (__sync_fetch_and_sub(&small_list_size, 1) <= 0)
        __sync_fetch_and_add(&diag_small_negative_updates, 1);
    }
    // TODO: add back to ghost_map?
    /* Count failures above; avoid per-event tracing on this frequent path. */
    return;
  }

  node->metadata[0] = 0;                /* freq */
  node->metadata[1] = is_ghost ? 1 : 0; /* in_main */
}

SEC(".struct_ops.link")
struct cache_ext_ops s3fifo_ops = {
    .init = (void*)s3fifo_init,
    .evict_folios = (void*)s3fifo_evict_folios,
    .folio_accessed = (void*)s3fifo_folio_accessed,
    .folios_evicted = (void*)s3fifo_folios_evicted,
    .folio_added = (void*)s3fifo_folio_added,
};
