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

static volatile const u64 secret = 0x9876543210;

static u64 lru_list;
static u64 access_seq = 0;

static __always_inline int ensure_initialized_impl(u64 new_list)
{
  if (new_list == 0)
    return -1;
  __sync_val_compare_and_swap(&lru_list, 0, new_list);
  return 0;
}

static __always_inline int ensure_initialized_by_memcg(struct mem_cgroup* memcg)
{
  if (likely(lru_list != 0))
    return 0;
  return ensure_initialized_impl(bpf_cache_ext_ds_registry_new_list(memcg));
}

static __always_inline int ensure_initialized_by_folio(struct folio* folio)
{
  if (likely(lru_list != 0))
    return 0;
  return ensure_initialized_impl(bpf_cache_ext_ds_registry_new_list_from_folio(folio));
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
    bpf_printk("LRU: null memcg\n");
    return 0;
  }
  bpf_printk("LRU Loader Init\n");
  lru_list = bpf_cache_ext_ds_registry_new_list(memcg);
  return 0;
}

SEC("freplace/slot_pop")
u64 lru_pop(void)
{
  struct folio* f = bpf_cache_ext_list_pop(lru_list, false);
  if (!f)
    return 0;

  return bpf_cache_ext_folio_to_handle(f, secret);
}

SEC("freplace/slot_push")
int lru_push(u64 handle)
{
  struct folio* f = bpf_cache_ext_handle_to_folio(handle, secret);
  if (!f || !folio_test_lru(f) || !f->mapping)
    return 0;

  if (ensure_initialized_by_folio(f) < 0)
    return 0;

  if (bpf_cache_ext_list_add_tail(lru_list, f))
    return 0;

  struct cache_ext_list_node* node = bpf_cache_ext_folio_to_node(f);
  if (!node)
    return 0;
  node->metadata[0] = __sync_fetch_and_add(&access_seq, 1);

  return 1;
}

// Sampling score: lower last_access = older = evict first
static s64 bpf_lru_score_fn(struct cache_ext_list_node* a)
{
  if (!folio_test_uptodate(a->folio) || !folio_test_lru(a->folio))
    return INT64_MAX;
  if (folio_test_dirty(a->folio) || folio_test_writeback(a->folio))
    return INT64_MAX;

  return a->metadata[0];
}

SEC("freplace/slot_evict_folios1")
int lru_evict_folios(u64 eviction_ctx_handle, u64 memcg_handle)
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
      .sample_size = 20,
  };
  bpf_cache_ext_list_sample(memcg, lru_list, bpf_lru_score_fn,
                            &sampling_opts, eviction_ctx);
  return 0;
}

u64 call_count = 0;
u64 evict_count = 0;

SEC("freplace/slot_folios_evicted1")
int lru_folios_evicted(u64 ctx_handle)
{
  struct cache_ext_evicted_ctx* ctx =
      bpf_cache_ext_handle_to_evicted_ctx(ctx_handle, secret);
  if (!ctx)
    return -1;

  return 0;
}

SEC("freplace/slot_folio_accessed1")
int lru_folio_accessed(u64 handle)
{
  struct folio* folio = bpf_cache_ext_handle_to_folio(handle, secret);
  if (!folio)
    return -1;
  if (ensure_initialized_by_folio(folio) < 0)
    return -1;

  struct cache_ext_list_node* node = bpf_cache_ext_folio_to_node(folio);
  if (!node)
    return -1;
  node->metadata[0] = __sync_fetch_and_add(&access_seq, 1);

  return 0;
}

SEC("freplace/slot_folio_added1")
int lru_folio_added(u64 handle)
{
  struct folio* f = bpf_cache_ext_handle_to_folio(handle, secret);
  if (!f)
    return -1;
  if (ensure_initialized_by_folio(f) < 0)
    return 0;

  if (bpf_cache_ext_list_add_tail(lru_list, f))
    return -1;

  struct cache_ext_list_node* node = bpf_cache_ext_folio_to_node(f);
  if (!node)
    return -1;
  node->metadata[0] = __sync_fetch_and_add(&access_seq, 1);

  call_count += 1;
  return 0;
}
