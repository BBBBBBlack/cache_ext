#include <bpf/bpf_core_read.h>

#include "cache_ext_lib.bpf.h"
#include "dir_watcher.bpf.h"

char _license[] SEC("license") = "GPL";
static volatile const u64 secret = 0x9876543210;

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
  bpf_printk("evict folio slot 1\n");
  asm volatile("" : : "r"(eviction_ctx_handle), "r"(memcg_handle));
  return 0;
}

__attribute__((visibility("default")))
__noinline int
slot_evict_folios2(u64 eviction_ctx_handle, u64 memcg_handle)
{
  bpf_printk("evict folio slot 2\n");
  asm volatile("" : : "r"(eviction_ctx_handle), "r"(memcg_handle));
  return 0;
}

__attribute__((visibility("default")))
__noinline int
slot_folio_evicted1(u64 handle)
{
  bpf_printk("folio evicted slot 1\n");
  asm volatile("" : : "r"(handle));
  return 0;
}

__attribute__((visibility("default")))
__noinline int
slot_folio_evicted2(u64 handle)
{
  bpf_printk("folio evicted slot 2\n");
  asm volatile("" : : "r"(handle));
  return 0;
}

__attribute__((visibility("default")))
__noinline int
slot_folio_accessed1(u64 handle)
{
  bpf_printk("folio accessed slot 1\n");
  asm volatile("" : : "r"(handle));
  return 0;
}

__attribute__((visibility("default")))
__noinline int
slot_folio_accessed2(u64 handle)
{
  bpf_printk("folio accessed slot 2\n");
  asm volatile("" : : "r"(handle));
  return 0;
}

__attribute__((visibility("default")))
__noinline int
slot_folio_added1(u64 handle)
{
  bpf_printk("folio added slot 1\n");
  asm volatile("" : : "r"(handle));
  return 0;
}

__attribute__((visibility("default")))
__noinline int
slot_folio_added2(u64 handle)
{
  bpf_printk("folio added slot 2\n");
  asm volatile("" : : "r"(handle));
  return 0;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(_init, struct mem_cgroup* memcg)
{
  bpf_printk("Cache_ext Dispatcher init.\n");
  return 0;
}

void BPF_STRUCT_OPS(_evict_folios, struct cache_ext_eviction_ctx* eviction_ctx,
                    struct mem_cgroup* memcg)
{
  // bpf_printk("Evicted folio.\n");

  u64 eviction_ctx_handle = bpf_cache_ext_ctx_to_handle(eviction_ctx, secret);

  u64 memcg_handle = bpf_cache_ext_memcg_to_handle(memcg, secret);

  slot_evict_folios1(eviction_ctx_handle, memcg_handle);
  slot_evict_folios2(eviction_ctx_handle, memcg_handle);
  return;
}

void BPF_STRUCT_OPS(_folio_evicted, struct folio* folio)
{
  // bpf_printk("Folio evicted.\n");
  // if (!is_folio_relevant(folio))
  //   return;
  u64 handle = bpf_cache_ext_folio_to_handle(folio, secret);

  slot_folio_evicted1(handle);
  slot_folio_evicted2(handle);
  return;
}

void BPF_STRUCT_OPS(_folio_accessed, struct folio* folio)
{
  // bpf_printk("Folio accessed.\n");
  // if (!is_folio_relevant(folio))
  //   return;

  u64 handle = bpf_cache_ext_folio_to_handle(folio, secret);

  slot_folio_accessed1(handle);
  slot_folio_accessed2(handle);
  return;
}

void BPF_STRUCT_OPS(_folio_added, struct folio* folio)
{
  // bpf_printk("Folio added.\n");
  // if (!is_folio_relevant(folio))
  //   return;

  u64 handle = bpf_cache_ext_folio_to_handle(folio, secret);

  slot_folio_added1(handle);
  slot_folio_added2(handle);
  return;
}

SEC(".struct_ops.link")
struct cache_ext_ops dispatcher_ops = {
    .init = (void*)_init,
    .evict_folios = (void*)_evict_folios,
    .folio_evicted = (void*)_folio_evicted,
    .folio_added = (void*)_folio_added,
    .folio_accessed = (void*)_folio_accessed};
