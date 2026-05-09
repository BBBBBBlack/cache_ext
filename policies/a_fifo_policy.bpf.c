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

/**
 * ****************************************** INIT *******************************************
 */
static u64 main_list;

static __always_inline int ensure_initialized_impl(u64 new_list)
{
  if (new_list == 0)
  {
    // bpf_printk("FIFO init failed: list ID is 0\n");
    return -1;
  }
  // CAS
  __sync_val_compare_and_swap(&main_list, 0, new_list);
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

/**
 * ****************************************** MIGRATION *******************************************
 */

// static int fifo_push_cb(int idx, struct cache_ext_list_node* a)
// {
//   u32 state_key = 0;
//   migration_qstate* qstate = bpf_map_lookup_elem(&migration_qstate_map, &state_key);
//   if (!qstate)
//     return CACHE_EXT_STOP_ITER;
//   u32 head = READ_ONCE(qstate->head);
//   u32 current_tail = READ_ONCE(qstate->tail);
//   if (current_tail - head >= MIGRATION_Q_SIZE)
//     return CACHE_EXT_STOP_ITER;
//   u64 handle = bpf_cache_ext_folio_to_handle(a->folio, secret);
//   u32 tail = __sync_fetch_and_add(&qstate->tail, 1);
//   u32 q_idx = tail & (MIGRATION_Q_SIZE - 1);
//   generic_cache_metrics metrics = {.handle = handle,
//                                    .seq = tail + 1};
//   long err = bpf_map_update_elem(&migration_queue, &q_idx, &metrics, BPF_ANY);
//   if (err)
//     return CACHE_EXT_STOP_ITER;
//   return CACHE_EXT_CONTINUE_ITER;
// }

// SEC("iter/cgroup")
// int trigger_push(struct bpf_iter__cgroup* ctx)
// {
//   struct cgroup* cgrp = ctx->cgroup;
//   if (!cgrp)
//     return 0;
//   struct mem_cgroup* memcg = bpf_cgroup_to_memcg(cgrp);
//   if (!memcg)
//     return 0;
//   if (!main_list)
//     return 0;
//   bpf_printk("[FIFO] Starting pipeline push for memcg...\n");
//   bpf_cache_ext_list_iterate_scan(memcg, main_list, fifo_push_cb);
//   return 0;
// }

// static __always_inline int
// __fifo_add_folio(struct folio* folio,
//                  generic_cache_metrics* migrated_metrics)
// {
//   if (!migrated_metrics || ensure_initialized_by_folio(folio) < 0)
//     return -1;
//   if (!folio_test_lru(folio) || !folio->mapping)
//     return 0;
//   if (bpf_cache_ext_list_add_tail(main_list, folio))
//     return -1;
//   return 0;
// }

// SEC("syscall")
// int trigger_pull(void* ctx)
// {
//   // struct cgroup* cgrp = ctx->cgroup;
//   // if (!cgrp)
//   //   return 0;
//   // struct mem_cgroup* memcg = bpf_cgroup_to_memcg(cgrp);
//   // if (!memcg)
//   //   return 0;
//   u32 state_key = 0;
//   migration_qstate* qstate = bpf_map_lookup_elem(&migration_qstate_map, &state_key);
//   if (!qstate)
//     return 0;
//   bpf_printk("[FIFO] Received pull trigger from migration queue.\n");
//   int count = 0;
//   for (int i = 0; i < 1024; i++)
//   {
//     u32 head = READ_ONCE(qstate->head);
//     if (head == READ_ONCE(qstate->tail))
//       break;
//     u32 idx = head & (MIGRATION_Q_SIZE - 1);
//     generic_cache_metrics* m = bpf_map_lookup_elem(&migration_queue, &idx);
//     if (!m || m->seq != head + 1)
//       break;
//     // 必须将数据拷贝到本地栈，因为 Array 里的内存槽会被后续复用
//     generic_cache_metrics metrics = *m;
//     // 数据读取成功，原子移动 Head 指针 (完成 Pop 操作)
//     if (__sync_val_compare_and_swap(&qstate->head, head, head + 1) != head)
//       continue;
//     struct folio* f = bpf_cache_ext_handle_to_folio(metrics.handle, secret);
//     if (!f)
//       continue; // Folio 已死
//     // bpf_printk("Checking migration queue: head=%u, tail=%u\n",
//     //            READ_ONCE(qstate->head), READ_ONCE(qstate->tail));
//     if (__fifo_add_folio(f, &metrics) == 0)
//     {
//       count++;
//     }
//   }
//   return count;
// }

SEC("freplace/slot_pop")
u64 fifo_pop(void)
{
  struct folio* f = bpf_cache_ext_list_pop(main_list, false);
  if (!f)
    return 0;
  return bpf_cache_ext_folio_to_handle(f, secret);
}

SEC("freplace/slot_push")
int fifo_push(u64 handle)
{
  struct folio* f = bpf_cache_ext_handle_to_folio(handle, secret);
  if (!f || !folio_test_lru(f) || !f->mapping)
    return 0;

  if (ensure_initialized_by_folio(f) < 0)
    return 0;

  if (bpf_cache_ext_list_add_tail(main_list, f) == 0)
    return 1;
  return 0;
}
// *********************************************************************************************

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
