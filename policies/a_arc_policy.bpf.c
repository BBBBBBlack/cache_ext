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
#define SCORE_PENALTY (1LL << 62)

static volatile const u64 secret = 0x9876543210;

/* Inline metadata layout in cache_ext_list_node->metadata[]:
 *   metadata[0] = last_access  (access sequence number)
 *   metadata[1] = in_t2        (0 = T1 recency, 1 = T2 frequency)
 */

struct ghost_key
{
  u64 mapping;
  u64 index;
};

struct
{
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, struct ghost_key);
  __type(value, u8);
  __uint(max_entries, 1000000);
} ghost_b1_map SEC(".maps");

struct
{
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, struct ghost_key);
  __type(value, u8);
  __uint(max_entries, 1000000);
} ghost_b2_map SEC(".maps");

static u64 arc_list;
static u64 access_seq = 0;

s64 target_p = 0;
s64 t1_count = 0;
s64 t2_count = 0;
s64 b1_count = 0;
s64 b2_count = 0;

u64 call_count = 0;
u64 evict_count = 0;

static __always_inline int ensure_initialized_impl(u64 new_list)
{
  if (new_list == 0)
    return -1;
  __sync_val_compare_and_swap(&arc_list, 0, new_list);
  return 0;
}

static __always_inline int ensure_initialized_by_memcg(struct mem_cgroup* memcg)
{
  if (likely(arc_list != 0))
    return 0;
  return ensure_initialized_impl(bpf_cache_ext_ds_registry_new_list(memcg));
}

static __always_inline int ensure_initialized_by_folio(struct folio* folio)
{
  if (likely(arc_list != 0))
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
    return 0;
  bpf_printk("ARC Loader Init\n");
  arc_list = bpf_cache_ext_ds_registry_new_list(memcg);
  return 0;
}

SEC("freplace/slot_pop")
u64 arc_pop(void)
{
  struct folio* f = bpf_cache_ext_list_pop(arc_list, false);
  if (!f)
    return 0;

  struct cache_ext_list_node* node = bpf_cache_ext_folio_to_node(f);
  if (node)
  {
    if ((s64)node->metadata[1])
      __sync_fetch_and_add(&t2_count, -1);
    else
      __sync_fetch_and_add(&t1_count, -1);
  }

  return bpf_cache_ext_folio_to_handle(f, secret);
}

SEC("freplace/slot_push")
int arc_push(u64 handle)
{
  struct folio* f = bpf_cache_ext_handle_to_folio(handle, secret);
  if (!f || !folio_test_lru(f) || !f->mapping)
    return 0;
  if (ensure_initialized_by_folio(f) < 0)
    return 0;

  s64 is_t2 = 0;
  struct ghost_key gk = {.mapping = (u64)f->mapping, .index = f->index};

  if (bpf_map_lookup_elem(&ghost_b1_map, &gk))
  {
    is_t2 = 1;
    bpf_map_delete_elem(&ghost_b1_map, &gk);
    __sync_fetch_and_add(&b1_count, -1);
  }
  else
  {
    if (bpf_map_lookup_elem(&ghost_b2_map, &gk))
    {
      is_t2 = 1;
      bpf_map_delete_elem(&ghost_b2_map, &gk);
      __sync_fetch_and_add(&b2_count, -1);
    }
  }

  if (bpf_cache_ext_list_add_tail(arc_list, f))
    return 0;

  struct cache_ext_list_node* push_node = bpf_cache_ext_folio_to_node(f);
  if (!push_node)
    return 0;
  push_node->metadata[0] = (u64)__sync_fetch_and_add(&access_seq, 1);
  push_node->metadata[1] = (u64)is_t2;

  if (is_t2)
    __sync_fetch_and_add(&t2_count, 1);
  else
    __sync_fetch_and_add(&t1_count, 1);

  return 1;
}

static s64 bpf_arc_score_fn(struct cache_ext_list_node* a)
{
  if (!folio_test_uptodate(a->folio) || !folio_test_lru(a->folio))
    return INT64_MAX;
  if (folio_test_dirty(a->folio) || folio_test_writeback(a->folio))
    return INT64_MAX;

  s64 last_access = (s64)a->metadata[0];
  s64 in_t2 = (s64)a->metadata[1];

  s64 p = target_p;
  s64 t1 = t1_count;
  s64 t2 = t2_count;
  bool prefer_evict_t1 = (t1 > p) || (t2 == 0);

  if (prefer_evict_t1)
  {
    if (!in_t2)
      return last_access;
    return last_access + SCORE_PENALTY;
  }
  else
  {
    if (in_t2)
      return last_access;
    return last_access + SCORE_PENALTY;
  }
}

SEC("freplace/slot_evict_folios1")
int arc_evict_folios(u64 eviction_ctx_handle, u64 memcg_handle)
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
  bpf_cache_ext_list_sample(memcg, arc_list, bpf_arc_score_fn,
                            &sampling_opts, eviction_ctx);
  return 0;
}

SEC("freplace/slot_folios_evicted1")
int arc_folios_evicted(u64 ctx_handle)
{
  struct cache_ext_evicted_ctx* ctx =
      bpf_cache_ext_handle_to_evicted_ctx(ctx_handle, secret);
  if (!ctx)
    return -1;

  for (int i = 0; i < (int)ctx->nr_folios && i < 32; i++)
  {
    struct folio* folio = ctx->folios[i];
    if (!folio)
      continue;

    struct cache_ext_list_node* node = bpf_cache_ext_folio_to_node(folio);
    if (node)
    {
      struct ghost_key gk = {.mapping = (u64)folio->mapping, .index = folio->index};
      u8 dummy = 1;

      if ((s64)node->metadata[1])
      {
        __sync_fetch_and_add(&t2_count, -1);
        if (!bpf_map_update_elem(&ghost_b2_map, &gk, &dummy, BPF_ANY))
          __sync_fetch_and_add(&b2_count, 1);
      }
      else
      {
        __sync_fetch_and_add(&t1_count, -1);
        if (!bpf_map_update_elem(&ghost_b1_map, &gk, &dummy, BPF_ANY))
          __sync_fetch_and_add(&b1_count, 1);
      }
    }
  }
  return 0;
}

SEC("freplace/slot_folio_accessed1")
int arc_folio_accessed(u64 handle)
{
  struct folio* folio = bpf_cache_ext_handle_to_folio(handle, secret);
  if (!folio)
    return -1;
  if (ensure_initialized_by_folio(folio) < 0)
    return -1;

  struct cache_ext_list_node* node = bpf_cache_ext_folio_to_node(folio);
  if (!node)
    return -1;

  u64 in_t2 = node->metadata[1];
  if (!(s64)in_t2)
  {
    in_t2 = 1;
    __sync_fetch_and_add(&t1_count, -1);
    __sync_fetch_and_add(&t2_count, 1);
  }

  node->metadata[0] = (u64)__sync_fetch_and_add(&access_seq, 1);
  node->metadata[1] = in_t2;
  return 0;
}

SEC("freplace/slot_folio_added1")
int arc_folio_added(u64 handle)
{
  struct folio* f = bpf_cache_ext_handle_to_folio(handle, secret);
  if (!f)
    return -1;
  if (ensure_initialized_by_folio(f) < 0)
    return 0;

  s64 is_t2 = 0;

  if (f->mapping)
  {
    struct ghost_key gk = {.mapping = (u64)f->mapping, .index = f->index};

    if (bpf_map_lookup_elem(&ghost_b1_map, &gk))
    {
      // B1 ghost hit: T1 was too small, increase p
      u64 b1c = (u64)(b1_count > 0 ? b1_count : 1);
      u64 b2c = (u64)(b2_count > 0 ? b2_count : 0);
      s64 delta = (s64)(b2c / b1c);
      if (delta < 1) delta = 1;
      s64 total = t1_count + t2_count;
      s64 new_p = target_p + delta;
      if (new_p > total) new_p = total;
      target_p = new_p;

      bpf_map_delete_elem(&ghost_b1_map, &gk);
      __sync_fetch_and_add(&b1_count, -1);
      is_t2 = 1;
    }
    else
    {
      if (bpf_map_lookup_elem(&ghost_b2_map, &gk))
      {
        // B2 ghost hit: T2 was too small, decrease p
        u64 b2c = (u64)(b2_count > 0 ? b2_count : 1);
        u64 b1c = (u64)(b1_count > 0 ? b1_count : 0);
        s64 delta = (s64)(b1c / b2c);
        if (delta < 1) delta = 1;
        s64 new_p = target_p - delta;
        if (new_p < 0) new_p = 0;
        target_p = new_p;

        bpf_map_delete_elem(&ghost_b2_map, &gk);
        __sync_fetch_and_add(&b2_count, -1);
        is_t2 = 1;
      }
    }
  }

  if (bpf_cache_ext_list_add_tail(arc_list, f))
    return -1;

  struct cache_ext_list_node* added_node = bpf_cache_ext_folio_to_node(f);
  if (!added_node)
    return -1;
  added_node->metadata[0] = (u64)__sync_fetch_and_add(&access_seq, 1);
  added_node->metadata[1] = (u64)is_t2;

  if (is_t2)
    __sync_fetch_and_add(&t2_count, 1);
  else
    __sync_fetch_and_add(&t1_count, 1);

  call_count += 1;
  return 0;
}
