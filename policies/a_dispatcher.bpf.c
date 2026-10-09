#include <bpf/bpf_core_read.h>

#include "cache_ext_lib.bpf.h"
#include "dir_watcher.bpf.h"

char _license[] SEC("license") = "GPL";
static volatile const u64 secret = 0x9876543210;

// *********************** Switch Policy ***********************

bool enable_secondary_slot = false;
u32 active_slot_id = 0;
u64 stub_folio_added1_count = 0;

struct
{
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 4096);
} migration_complete_events SEC(".maps");

static __always_inline void notify_migration_status(u32 phase)
{
  struct migration_status_event* event =
      bpf_ringbuf_reserve(&migration_complete_events, sizeof(*event), 0);
  if (!event)
    return;

  event->phase = phase;
  event->p = 0;
  bpf_ringbuf_submit(event, 0);
}

static inline bool is_folio_relevant(struct folio* folio)
{
  if (!folio || !folio->mapping || !folio->mapping->host)
    return false;

  return inode_in_watchlist(folio->mapping->host->i_ino);
}

__attribute__((visibility("default")))
__noinline int
slot_evict_folios1(u64 eviction_ctx_handle, u64 memcg_handle)
{
  // bpf_printk("evict folio slot 1\n");
  asm volatile("" : : "r"(eviction_ctx_handle), "r"(memcg_handle));
  return 0;
}

__attribute__((visibility("default")))
__noinline int
slot_evict_folios2(u64 eviction_ctx_handle, u64 memcg_handle)
{
  // bpf_printk("evict folio slot 2\n");
  asm volatile("" : : "r"(eviction_ctx_handle), "r"(memcg_handle));
  return 0;
}

__attribute__((visibility("default")))
__noinline int
slot_folios_evicted1(u64 ctx_handle)
{
  asm volatile("" : : "r"(ctx_handle));
  return 0;
}

__attribute__((visibility("default")))
__noinline int
slot_folios_evicted2(u64 ctx_handle)
{
  asm volatile("" : : "r"(ctx_handle));
  return 0;
}

__attribute__((visibility("default")))
__noinline int
slot_folio_accessed1(u64 handle)
{
  // bpf_printk("folio accessed slot 1\n");
  asm volatile("" : : "r"(handle));
  return 0;
}

__attribute__((visibility("default")))
__noinline int
slot_folio_accessed2(u64 handle)
{
  // bpf_printk("folio accessed slot 2\n");
  asm volatile("" : : "r"(handle));
  return 0;
}

__attribute__((visibility("default")))
__noinline int
slot_folio_added1(u64 handle)
{
  stub_folio_added1_count += 1;
  asm volatile("" : : "r"(handle));
  return 0;
}

__attribute__((visibility("default")))
__noinline int
slot_folio_added2(u64 handle)
{
  // bpf_printk("folio added slot 2\n");
  asm volatile("" : : "r"(handle));
  return 0;
}

__attribute__((weak, visibility("default")))
__noinline u64
slot_pop(void)
{
  u64 ret = 0;
  asm volatile("" : "+r"(ret));
  return ret;
}

// return >0 if push successful, 0 if push failed
__attribute__((weak, visibility("default")))
__noinline int
slot_push(u64 handle)
{
  asm volatile("" : : "r"(handle));
  return 0;
}

SEC("syscall")
int trigger_pull(void* ctx)
{
  if (!enable_secondary_slot)
    return 0;
  if (READ_ONCE(active_slot_id) == 2)
    return 0;

  int count = 0;
  for (int i = 0; i < 1024; i++)
  {
    u64 handle = slot_pop();
    if (!handle)
    {
      WRITE_ONCE(active_slot_id, 2);
      notify_migration_status(PHASE_END);
      break;
    }
    if (slot_push(handle) > 0)
      count++;
  }
  return count;
}

u64 dispatcher_folio_added_count = 0;
u64 dispatcher_evict_count = 0;

s32 BPF_STRUCT_OPS_SLEEPABLE(_init, struct mem_cgroup* memcg)
{
  enable_secondary_slot = false;
  active_slot_id = 1;

  bpf_printk("Cache_ext Dispatcher init.\n");
  return 0;
}

void BPF_STRUCT_OPS(_evict_folios, struct cache_ext_eviction_ctx* eviction_ctx,
                    struct mem_cgroup* memcg)
{
  dispatcher_evict_count += 1;
  u64 eviction_ctx_handle = bpf_cache_ext_ctx_to_handle(eviction_ctx, secret);
  u64 memcg_handle = bpf_cache_ext_memcg_to_handle(memcg, secret);

  if (likely(!enable_secondary_slot))
  {
    if (active_slot_id == 1)
      slot_evict_folios1(eviction_ctx_handle, memcg_handle);
    else
      slot_evict_folios2(eviction_ctx_handle, memcg_handle);
    return;
  }

  if (READ_ONCE(active_slot_id) == 2)
  {
    slot_evict_folios2(eviction_ctx_handle, memcg_handle);
    return;
  }

  int ret = slot_evict_folios1(eviction_ctx_handle, memcg_handle);
  if (ret < 0 && ret != -2)
    return;
  if (eviction_ctx->nr_folios_to_evict < eviction_ctx->request_nr_folios_to_evict)
    slot_evict_folios2(eviction_ctx_handle, memcg_handle);
}

void BPF_STRUCT_OPS(_folios_evicted, struct cache_ext_evicted_ctx *ectx)
{
  u64 ctx_handle = bpf_cache_ext_evicted_ctx_to_handle(ectx, secret);

  if (likely(!enable_secondary_slot))
  {
    if (active_slot_id == 1)
      slot_folios_evicted1(ctx_handle);
    else
      slot_folios_evicted2(ctx_handle);
    return;
  }

  if (READ_ONCE(active_slot_id) != 2)
    slot_folios_evicted1(ctx_handle);
  slot_folios_evicted2(ctx_handle);
}

void BPF_STRUCT_OPS(_folio_accessed, struct folio* folio)
{
  if (!is_folio_relevant(folio))
    return;

  u64 handle = bpf_cache_ext_folio_to_handle(folio, secret);

  if (likely(!enable_secondary_slot))
  {
    if (active_slot_id == 1)
      slot_folio_accessed1(handle);
    else
      slot_folio_accessed2(handle);
    return;
  }

  if (READ_ONCE(active_slot_id) != 2)
    slot_folio_accessed1(handle);
  slot_folio_accessed2(handle);
}

void BPF_STRUCT_OPS(_folio_added, struct folio* folio)
{
  if (!is_folio_relevant(folio))
    return;

  dispatcher_folio_added_count += 1;
  u64 handle = bpf_cache_ext_folio_to_handle(folio, secret);

  if (likely(!enable_secondary_slot))
  {
    if (active_slot_id == 1)
      slot_folio_added1(handle);
    else
      slot_folio_added2(handle);
    return;
  }

  slot_folio_added2(handle);
}

SEC(".struct_ops.link")
struct cache_ext_ops dispatcher_ops = {
    .init = (void*)_init,
    .evict_folios = (void*)_evict_folios,
    .folios_evicted = (void*)_folios_evicted,
    .folio_added = (void*)_folio_added,
    .folio_accessed = (void*)_folio_accessed};
