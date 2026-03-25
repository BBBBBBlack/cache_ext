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
static volatile const u64 secret = 0x9876543210;
static u64 main_list;

static __always_inline int ensure_initialized_impl(u64 new_list)
{
  if (new_list == 0)
  {
    // bpf_printk("FIFO init failed: list ID is 0\n");
    return -1;
  }
  // CAS
  u64 old_val = __sync_val_compare_and_swap(&main_list, 0, new_list);
  // if (old_val == 0)
  //   bpf_printk("FIFO init success, list id: %llu\n", new_list);
  // else
  // {
  //   // 竞态失败，忽略多余的 list
  //   // bpf_cache_ext_list_free(new_list); // TODO
  // }
  return 0;
}

static __always_inline int ensure_initialized_by_memcg(struct mem_cgroup* memcg)
{
  if (likely(main_list != 0))
    return 0;
  return ensure_initialized_impl(bpf_cache_ext_ds_registry_new_list(memcg));
}

static __always_inline int ensure_initialized_by_folio(struct folio* folio)
{
  if (likely(main_list != 0))
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
    bpf_printk("null memcg\n");
    return 0;
  }

  // 初始化
  bpf_printk("FIFO Loader Init\n");
  main_list = bpf_cache_ext_ds_registry_new_list(memcg);

  return 0;
}

static int bpf_fifo_evict_cb(int idx, struct cache_ext_list_node* a)
{
  if (!folio_test_uptodate(a->folio) || !folio_test_lru(a->folio))
    return CACHE_EXT_CONTINUE_ITER;

  if (folio_test_dirty(a->folio) || folio_test_writeback(a->folio))
    return CACHE_EXT_CONTINUE_ITER;

  return CACHE_EXT_EVICT_NODE;
}

SEC("freplace/slot_evict_folios1")
int fifo_evict_folios(u64 eviction_ctx_handle, u64 memcg_handle)
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
  if (bpf_cache_ext_list_iterate(
          memcg, main_list, bpf_fifo_evict_cb, eviction_ctx) < 0)
    return -1;
  return 0;
}

u64 call_count = 0;

SEC("freplace/slot_folio_evicted1")
int fifo_folio_evicted(u64 handle)
{
  // if (!is_folio_relevant(folio))
  //   return 0;
  return 0;
}

SEC("freplace/slot_folio_accessed1")
int fifo_folio_accessed(u64 handle)
{
  return 0;
}

SEC("freplace/slot_folio_added1")
int fifo_folio_added(u64 handle)
{
  // bpf_printk("FIFO added.\n");
  struct folio* f = bpf_cache_ext_handle_to_folio(handle, secret);
  if (!f)
    return -1;
  if (ensure_initialized_by_folio(f) < 0)
    return 0;

  bpf_cache_ext_list_add_tail(main_list, f);

  return 0;
}