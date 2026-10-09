#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "cache_ext_lib.bpf.h"
#include "dir_watcher.bpf.h"

char _license[] SEC("license") = "GPL";

static u64 main_list;

u64 fifo_evict_calls;
u64 fifo_requested_folios;
u64 fifo_returned_folios;
u64 fifo_cb_evict;
u64 fifo_cb_skip_not_uptodate;
u64 fifo_cb_skip_not_lru;
u64 fifo_cb_skip_writeback;
u64 fifo_iter_continue;
u64 fifo_iter_evict;
u64 fifo_iter_deferred;
u64 fifo_iter_ret_done;
u64 fifo_iter_ret_max_iter;
u64 fifo_iter_ret_array_filled;
u64 fifo_iter_ret_error;

static inline bool is_folio_relevant(struct folio* folio)
{
  if (!folio || !folio->mapping || !folio->mapping->host)
    return false;

  return inode_in_watchlist(folio->mapping->host->i_ino);
}

s32 BPF_STRUCT_OPS_SLEEPABLE(fifo_init, struct mem_cgroup* memcg)
{
  main_list = bpf_cache_ext_ds_registry_new_list(memcg);
  if (main_list == 0)
  {
    bpf_printk("cache_ext: init: Failed to create main_list\n");
    return -1;
  }
  bpf_printk("cache_ext: Created main_list: %llu\n", main_list);

  return 0;
}

static int bpf_fifo_evict_cb(int idx, struct cache_ext_list_node* a)
{
  if (!folio_test_uptodate(a->folio))
  {
    fifo_cb_skip_not_uptodate++;
    return CACHE_EXT_CONTINUE_ITER;
  }

  if (!folio_test_lru(a->folio))
  {
    fifo_cb_skip_not_lru++;
    return CACHE_EXT_CONTINUE_ITER;
  }

  if (folio_test_writeback(a->folio))
  {
    fifo_cb_skip_writeback++;
    return CACHE_EXT_CONTINUE_ITER;
  }

  fifo_cb_evict++;
  return CACHE_EXT_EVICT_NODE;
}

void BPF_STRUCT_OPS(fifo_evict_folios, struct cache_ext_eviction_ctx* eviction_ctx,
                    struct mem_cgroup* memcg)
{
  int ret;

  fifo_evict_calls++;
  fifo_requested_folios += eviction_ctx->request_nr_folios_to_evict;

  struct cache_ext_iterate_opts opts = {
      .continue_list = CACHE_EXT_ITERATE_SELF,
      .continue_mode = CACHE_EXT_ITERATE_SKIP,
      .evict_list = CACHE_EXT_ITERATE_SELF,
      .evict_mode = CACHE_EXT_ITERATE_TAIL,
      .deferred_list = CACHE_EXT_ITERATE_SELF,
      .deferred_mode = CACHE_EXT_ITERATE_TAIL,
  };

  ret = bpf_cache_ext_list_iterate_extended(memcg, main_list, bpf_fifo_evict_cb,
                                            &opts, eviction_ctx);
  fifo_returned_folios += eviction_ctx->nr_folios_to_evict;
  fifo_iter_continue += opts.nr_folios_continue;
  fifo_iter_evict += opts.nr_folios_evict;
  fifo_iter_deferred += opts.nr_folios_deferred;

  if (ret < 0)
  {
    fifo_iter_ret_error++;
    bpf_printk("cache_ext: evict: Failed to iterate main_list\n");
    return;
  }

  if (ret == CACHE_EXT_MAX_ITER_REACHED)
    fifo_iter_ret_max_iter++;
  else if (ret == CACHE_EXT_EVICT_ARRAY_FILLED)
    fifo_iter_ret_array_filled++;
  else
    fifo_iter_ret_done++;
}

void BPF_STRUCT_OPS(fifo_folios_evicted, struct cache_ext_evicted_ctx *ectx)
{
}

void BPF_STRUCT_OPS(fifo_folio_added, struct folio* folio)
{
  if (!is_folio_relevant(folio))
    return;

  if (bpf_cache_ext_list_add_tail(main_list, folio))
  {
    bpf_printk("cache_ext: added: Failed to add folio to main_list\n");
    return;
  }
}

SEC(".struct_ops.link")
struct cache_ext_ops fifo_ops = {
    .init = (void*)fifo_init,
    .evict_folios = (void*)fifo_evict_folios,
    .folios_evicted = (void*)fifo_folios_evicted,
    .folio_added = (void*)fifo_folio_added,
};
