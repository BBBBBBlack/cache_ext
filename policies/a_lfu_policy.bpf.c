#include "cache_ext_lib.bpf.h"
#include "logger.h"
#include "vmlinux.h"

#ifndef likely
#define likely(x) __builtin_expect(!!(x), 1)
#endif
#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif

char __license[] SEC("license") = "GPL";

#define INT64_MAX (9223372036854775807LL)
#define LFU_DIRTY_SCORE_PENALTY 1LL

static volatile const u64 secret = 0x9876543210;

/**
 * ****************************************** MAP *******************************************
 */

/* metadata[0] = freq (s64): access count, used as LFU score */

/**
 * ****************************************** INIT *******************************************
 */

static u64 lfu_list;

static __always_inline int ensure_initialized_impl(u64 new_list)
{
  if (new_list == 0)
    return -1;
  /* CAS：多核并发时只有一个 winner，其余忽略竞态失败 */
  __sync_val_compare_and_swap(&lfu_list, 0, new_list);
  return 0;
}

static __always_inline int ensure_initialized_by_memcg(struct mem_cgroup* memcg)
{
  if (likely(lfu_list != 0))
    return 0;
  return ensure_initialized_impl(bpf_cache_ext_ds_registry_new_list(memcg));
}

static __always_inline int ensure_initialized_by_folio(struct folio* folio)
{
  if (likely(lfu_list != 0))
    return 0;
  return ensure_initialized_impl(bpf_cache_ext_ds_registry_new_list_from_folio(folio));
}

/* 由 loader 通过 iter/cgroup 主动触发的初始化入口 */
SEC("iter/cgroup")
int do_targeted_init(struct bpf_iter__cgroup* ctx)
{
  struct cgroup* cgrp = ctx->cgroup;
  if (!cgrp)
    return 0;
  struct mem_cgroup* memcg = bpf_cgroup_to_memcg(cgrp);
  if (!memcg)
  {
    return 0;
  }
  lfu_list = bpf_cache_ext_ds_registry_new_list(memcg);
  return 0;
}

/**
 * ****************************************** MIGRATION *******************************************
 */

SEC("freplace/slot_pop")
u64 lfu_pop(void)
{
  struct folio* f = bpf_cache_ext_list_pop(lfu_list, false);
  if (!f)
    return 0;

  return bpf_cache_ext_folio_to_handle(f, secret);
}

SEC("freplace/slot_push")
int lfu_push(u64 handle)
{
  struct folio* f = bpf_cache_ext_handle_to_folio(handle, secret);
  if (!f || !folio_test_lru(f) || !f->mapping)
    return 0;

  if (ensure_initialized_by_folio(f) < 0)
    return 0;

  if (bpf_cache_ext_list_add_tail(lfu_list, f))
    return 0;

  struct cache_ext_list_node* node = bpf_cache_ext_folio_to_node(f);
  if (!node)
    return 0;
  node->metadata[0] = 1;

  return 1;
}

/**
 * ****************************************** EVICTION *******************************************
 *
 * 与 cache_ext_sampling 的 bpf_lfu_score_fn + bpf_cache_ext_list_sample 完全对应。
 * sample_size = 20：每次随机采样 20 个候选，驱逐其中 freq 最低的若干个。
 *
 * 原版的 LEVELDB 最后一页优化此处暂不移植（依赖 is_last_page_in_file，
 * 需要额外 kfunc 支持），可后续按需添加。
 */

__u64 call_count = 0;
__u64 evict_count = 0;
static s64 bpf_lfu_score_fn(struct cache_ext_list_node* a)
{
  /* Not reclaimable by this policy path. Dirty folios are still candidates
   * below, but get a score penalty so clean folios are preferred.
   */
  if (!folio_test_uptodate(a->folio))
  {
    return INT64_MAX;
  }
  if (!folio_test_lru(a->folio))
  {
    return INT64_MAX;
  }
  if (folio_test_writeback(a->folio))
  {
    return INT64_MAX;
  }

  s64 score = (s64)a->metadata[0];
  if (folio_test_dirty(a->folio))
  {
    if (score > INT64_MAX - LFU_DIRTY_SCORE_PENALTY)
      return INT64_MAX;
    score += LFU_DIRTY_SCORE_PENALTY;
  }
  return score;
}

SEC("freplace/slot_evict_folios1")
int lfu_evict_folios(u64 eviction_ctx_handle, u64 memcg_handle)
{
  struct cache_ext_eviction_ctx* eviction_ctx =
      bpf_cache_ext_handle_to_ctx(eviction_ctx_handle, secret);
  struct mem_cgroup* memcg =
      bpf_cache_ext_handle_to_memcg(memcg_handle, secret);

  if (!eviction_ctx || !memcg)
    return -1;
  if (ensure_initialized_by_memcg(memcg) < 0)
    return -1;

  struct sampling_options sampling_opts = {
      .sample_size = 10, /* 与原 cache_ext_sampling 保持一致 */
  };
  bpf_cache_ext_list_sample(memcg, lfu_list, bpf_lfu_score_fn,
                            &sampling_opts, eviction_ctx);
  evict_count += 1;
  return 0;
}

SEC("freplace/slot_folios_evicted1")
int lfu_folios_evicted(u64 ctx_handle)
{
  struct cache_ext_evicted_ctx* ctx =
      bpf_cache_ext_handle_to_evicted_ctx(ctx_handle, secret);
  if (!ctx)
    return -1;

  return 0;
}

SEC("freplace/slot_folio_accessed1")
int lfu_folio_accessed(u64 handle)
{
  struct folio* folio = bpf_cache_ext_handle_to_folio(handle, secret);
  if (!folio)
    return -1;
  if (ensure_initialized_by_folio(folio) < 0)
    return -1;

  struct cache_ext_list_node* node = bpf_cache_ext_folio_to_node(folio);
  if (!node)
    return -1;
  __sync_fetch_and_add(&node->metadata[0], 1);

  return 0;
}

SEC("freplace/slot_folio_added1")
int lfu_folio_added(u64 handle)
{
  call_count += 1;
  struct folio* f = bpf_cache_ext_handle_to_folio(handle, secret);
  if (!f)
    return -1;
  if (ensure_initialized_by_folio(f) < 0)
    return 0;

  if (bpf_cache_ext_list_add_tail(lfu_list, f))
    return -1;

  struct cache_ext_list_node* node = bpf_cache_ext_folio_to_node(f);
  if (!node)
    return -1;
  node->metadata[0] = 1;

  return 0;
}
