#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "cache_ext_lib.bpf.h"
#include "dir_watcher.bpf.h"

char _license[] SEC("license") = "GPL";

#define BPF_STRUCT_OPS(name, args...) \
  SEC("struct_ops/" #name)            \
  BPF_PROG(name, ##args)

#define BPF_STRUCT_OPS_SLEEPABLE(name, args...) \
  SEC("struct_ops.s/" #name)                    \
  BPF_PROG(name, ##args)

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

#define INT64_MAX (9223372036854775807LL)
#define LFU_DIRTY_SCORE_PENALTY 10LL

// #define DEBUG
#ifdef DEBUG
#define dbg_printk(fmt, ...) bpf_printk(fmt, ##__VA_ARGS__)
#else
#define dbg_printk(fmt, ...)
#endif

/*
 * Maps
 */

#define MAX_PAGES (1 << 20)

__u64 lfu_list;

/* App type for specific optimizations */
enum App
{
  GENERIC_APP,
  LEVELDB,
};

/* App-specific scoring configuration */
const int APP_TYPE = GENERIC_APP;

inline bool is_folio_relevant(struct folio* folio)
{
  if (!folio)
  {
    // bpf_printk("folio not relevant because it's null\n");
    return false;
  }
  if (folio->mapping == NULL)
  {
    // bpf_printk("folio not relevant because it's mapping is null\n");
    return false;
  }
  if (folio->mapping->host == NULL)
  {
    // bpf_printk("folio not relevant because it's host is null\n");
    return false;
  }
  bool res = inode_in_watchlist(folio->mapping->host->i_ino);
  // if (!res) {
  // 	bpf_printk("folio not relevant because it's inode is not in watchlist, inode %llu\n",
  // 		   folio->mapping->host->i_ino);

  // }
  return res;
}

// SEC("struct_ops.s/lfu_init")
s32 BPF_STRUCT_OPS_SLEEPABLE(lfu_init, struct mem_cgroup* memcg)
{
  dbg_printk("cache_ext: Hi from the lfu_init hook! :D\n");
  lfu_list = bpf_cache_ext_ds_registry_new_list(memcg);
  if (lfu_list == 0)
  {
    bpf_printk("cache_ext: Failed to create lfu_list\n");
    return -1;
  }
  return 0;
}

void BPF_STRUCT_OPS(lfu_folio_added, struct folio* folio)
{
  dbg_printk(
      "cache_ext: Hi from the lfu_folio_added hook! :D\n");
  if (!is_folio_relevant(folio))
  {
    return;
  }

  int ret = bpf_cache_ext_list_add_tail(lfu_list, folio);
  if (ret != 0)
  {
    bpf_printk(
        "cache_ext: Failed to add folio to lfu_list\n");
    return;
  }
  dbg_printk("cache_ext: Added folio to lfu_list\n");

  struct cache_ext_list_node* node = bpf_cache_ext_folio_to_node(folio);
  if (node)
    node->metadata[0] = 1;
}

void BPF_STRUCT_OPS(lfu_folio_accessed, struct folio* folio)
{
  if (!is_folio_relevant(folio))
  {
    return;
  }
  struct cache_ext_list_node* node = bpf_cache_ext_folio_to_node(folio);
  if (!node)
    return;
  __sync_fetch_and_add(&node->metadata[0], 1);
}

void BPF_STRUCT_OPS(lfu_folios_evicted, struct cache_ext_evicted_ctx* ectx)
{
  /* No policy metadata needs updating after eviction. */
}

static inline bool is_last_page_in_file(struct folio* folio)
{
  struct address_space* mapping = folio->mapping;
  if (!mapping)
  {
    return false;
  }
  struct inode* inode = mapping->host;
  if (!inode)
  {
    return false;
  }
  // TODO: Handle hugepages
  if (folio_test_large(folio) || folio_test_hugetlb(folio))
  {
    bpf_printk("cache_ext: Hugepages not supported\n");
    return false;
  }
  unsigned long long file_size = i_size_read(inode);
  unsigned long long page_index = folio_index(folio);
  unsigned long long page_size = 4096;
  unsigned long long last_page_index = (file_size + page_size - 1) / page_size - 1;
  return page_index == last_page_index;
}

static s64 bpf_lfu_score_fn(struct cache_ext_list_node* a)
{
  s64 score = (s64)a->metadata[0];
  if (APP_TYPE == LEVELDB)
  {
    // In leveldb, the index block is at the end of the file.
    bool is_last_page = is_last_page_in_file(a->folio);
    if (is_last_page)
    {
      // bpf_printk("cache_ext: Found last page in file\n");
      score += 100000;
    }
  }

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
  if (folio_test_dirty(a->folio))
  {
    if (score > INT64_MAX - LFU_DIRTY_SCORE_PENALTY)
      return INT64_MAX;
    score += LFU_DIRTY_SCORE_PENALTY;
  }
  return score;
}

void BPF_STRUCT_OPS(lfu_evict_folios,
                    struct cache_ext_eviction_ctx* eviction_ctx,
                    struct mem_cgroup* memcg)
{
  dbg_printk(
      "cache_ext: Hi from the lfu_evict_folios hook! :D\n");

  struct sampling_options sampling_opts = {
      .sample_size = 10,
  };
  bpf_cache_ext_list_sample(memcg, lfu_list, bpf_lfu_score_fn,
                            &sampling_opts, eviction_ctx);
  dbg_printk("cache_ext: Evicting %d pages (%d requested)\n",
             eviction_ctx->nr_folios_to_evict,
             eviction_ctx->request_nr_folios_to_evict);
  dbg_printk("cache_ext: Printing first two and last two folios: %p %p %p %p\n",
             eviction_ctx->folios_to_evict[0],
             eviction_ctx->folios_to_evict[1],
             eviction_ctx->folios_to_evict[32 - 2],
             eviction_ctx->folios_to_evict[32 - 1]);
}

SEC(".struct_ops.link")
struct cache_ext_ops lfu_ops = {
    .init = (void*)lfu_init,
    .evict_folios = (void*)lfu_evict_folios,
    .folio_accessed = (void*)lfu_folio_accessed,
    .folios_evicted = (void*)lfu_folios_evicted,
    .folio_added = (void*)lfu_folio_added,
};
