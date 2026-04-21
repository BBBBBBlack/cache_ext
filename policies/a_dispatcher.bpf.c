#include <bpf/bpf_core_read.h>

#include "cache_ext_lib.bpf.h"
#include "dir_watcher.bpf.h"

char _license[] SEC("license") = "GPL";
static volatile const u64 secret = 0x9876543210;

// *********************** Switch Policy ***********************

bool enable_secondary_slot = false;

#define SCALE 10000
#define EPOCH_EVENTS 1024
#define COMPLETE 8000

static __always_inline void dispatcher_unpack_routing_core(u64 routing_core, u32* phase, u32* p)
{
  *phase = (u32)(routing_core & 0xFFFFFFFFULL);
  *p = (u32)(routing_core >> 32);
}

static __always_inline u64 dispatcher_pack_routing_core(u32 phase, u32 p)
{
  return ((u64)p << 32) | phase;
}

// 状态机全局状态（由 libbpf 放入全局数据区）
struct transition_state global_ts = {};

struct
{
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 4096);
} migration_complete_events SEC(".maps");

static __always_inline void notify_migration_complete(void)
{
  u32* event = bpf_ringbuf_reserve(&migration_complete_events, sizeof(*event), 0);
  if (!event)
    return;

  *event = PHASE_COMPLETE;
  bpf_ringbuf_submit(event, 0);
}

static __noinline void update_transition_state(struct transition_state* state, u32 ghr)
{
  // 预设阈值参数
  u32 GHR_RECOVERY_THRESHOLD = 2500;   // 25%
  u32 GHR_NORMAL_THRESHOLD = 500;      // 5%
  u32 STREAK_REQUIRED_FOR_CA = 2;      // 需要 2 个连续周期低 GHR 才从 FAST_RECOVERY 返回 CA
  u32 STREAK_REQUIRED_FOR_TIMEOUT = 3; // 需要 3 个连续周期高 GHR 才从 FAST_RECOVERY 进入 TIMEOUT
  u64 routing_core = READ_ONCE(state->routing_core);
  u32 current_phase, current_p = 0;
  dispatcher_unpack_routing_core(routing_core, &current_phase, &current_p);
  u32 new_phase = current_phase;
  u32 new_p = current_p;
  bool disable_slot_after_write = false;

  switch (current_phase)
  {
  case PHASE_SLOW_START:
    if (ghr > GHR_RECOVERY_THRESHOLD)
    {
      // 激进错误，进入 Fast Recovery
      new_p = current_p / 2;
      state->ssthresh = new_p;
      new_phase = PHASE_FAST_RECOVERY;

      state->high_ghr_streak++;
      state->low_ghr_streak = 0;
    }
    else
    {
      // 指数增长 (或者乘 2)
      new_p = (current_p == 0) ? 100 : (current_p * 2);
      if (new_p >= state->ssthresh)
        new_phase = PHASE_CA;

      state->high_ghr_streak = 0;
      state->low_ghr_streak = 0;
    }
    break;

  case PHASE_CA:
    if (ghr > GHR_RECOVERY_THRESHOLD)
    {
      new_p = current_p / 2;
      state->ssthresh = new_p;
      new_phase = PHASE_FAST_RECOVERY;

      state->high_ghr_streak++;
      state->low_ghr_streak = 0;
    }
    else
    {
      // 线性增长
      new_p = current_p + 200; // 每次 Epoch 增加 2%
      state->high_ghr_streak = 0;
      state->low_ghr_streak = 0;

      // TODO: 若达到一定值切换到新策略
      if (new_p >= COMPLETE)
      {
        new_p = SCALE;
        new_phase = PHASE_COMPLETE;
      }
    }
    break;

  case PHASE_FAST_RECOVERY:
    if (ghr <= GHR_NORMAL_THRESHOLD)
    {
      state->high_ghr_streak = 0;
      state->low_ghr_streak++;

      // 恢复正常，返回 CA
      if (state->low_ghr_streak >= STREAK_REQUIRED_FOR_CA)
      {
        new_phase = PHASE_CA;
        state->low_ghr_streak = 0;
      }
    }
    else if (ghr > GHR_RECOVERY_THRESHOLD)
    {
      state->low_ghr_streak = 0;
      state->high_ghr_streak++;

      // 持续恶化，进入 Timeout 兜底
      if (state->high_ghr_streak >= STREAK_REQUIRED_FOR_TIMEOUT)
      {
        new_phase = PHASE_TIMEOUT;
        state->high_ghr_streak = 0;
      }
    }
    else
    {
      state->high_ghr_streak = 0;
      state->low_ghr_streak = 0;
    }
    break;

  case PHASE_TIMEOUT:
    if (current_p >= 2500)
    {
      // 已经迁移了一半以上，沉没成本较高，选择强行切换到新策略
      new_p = SCALE;
      new_phase = PHASE_COMPLETE;
    }
    else
    {
      // 进度较低（< 80%），说明新策略严重水土不服，彻底回滚旧策略
      new_p = 0;
      new_phase = PHASE_SLOW_START;
      disable_slot_after_write = true;
      // 可选：通过 BPF Ringbuffer 向用户态发信号，通知撤销新策略
    }
    break;

  case PHASE_COMPLETE:
    // 终态，直接返回，不再重置 Epoch，也不再调整 p
    break;
  }

  // 边界钳制
  if (new_p > SCALE)
    new_p = SCALE;

  WRITE_ONCE(state->routing_core, dispatcher_pack_routing_core(new_phase, new_p));
  if (disable_slot_after_write)
    enable_secondary_slot = false;

  if (new_phase == PHASE_COMPLETE && current_phase != PHASE_COMPLETE)
    notify_migration_complete();
}

// *********************** Ghost Map ***********************

const volatile u64 ghost_window_ns = 1000000000ULL;

#define DISPATCHER_GHOST_MAP_MAX_ENTRIES (1U << 20)
#define DISPATCHER_MIN_SAMPLES_FOR_EWMA 100

struct dispatcher_ghost_entry
{
  u64 address_space;
  u64 offset;
};

struct dispatcher_ghost_window_stats
{
  u64 window_start_ns;
  u32 sample_total;
  u32 ghost_hits;
  u32 ghost_hit_rate_bp;
  u32 reserved;
  struct bpf_spin_lock lock;
};

struct
{
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, DISPATCHER_GHOST_MAP_MAX_ENTRIES);
  __type(key, struct dispatcher_ghost_entry);
  __type(value, u8);
  __uint(map_flags, BPF_F_NO_COMMON_LRU);
} dispatcher_ghost_map SEC(".maps");

struct
{
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, u32);
  __type(value, struct dispatcher_ghost_window_stats);
} ghost_window_map SEC(".maps");

static __always_inline bool dispatcher_consume_ghost(struct folio* folio)
{
  if (!folio || !folio->mapping || !folio->mapping->host)
    return false;

  struct dispatcher_ghost_entry key = {
      .address_space = (u64)folio->mapping->host,
      .offset = folio->index,
  };

  return bpf_cache_ext_map_delete((struct bpf_map*)&dispatcher_ghost_map,
                                  &key, sizeof(key)) == 0;
}

static __always_inline void dispatcher_store_ghost(struct folio* folio)
{
  if (!folio || !folio->mapping || !folio->mapping->host)
    return;

  struct dispatcher_ghost_entry key = {
      .address_space = (u64)folio->mapping->host,
      .offset = folio->index,
  };
  u8 val = 1;

  bpf_cache_ext_map_update((struct bpf_map*)&dispatcher_ghost_map,
                           &key, sizeof(key),
                           &val, sizeof(val));
}

static __noinline void dispatcher_record_ghost_window_sample(bool ghost_hit)
{
  // bpf_printk("Recording ghost window sample.\n");
  bool need_update = false;
  u32 smoothed_bp = 0;

  u32 key = 0;
  struct dispatcher_ghost_window_stats* stats =
      bpf_map_lookup_elem(&ghost_window_map, &key);
  if (!stats)
    return;

  u64 now = bpf_ktime_get_ns();

  bpf_spin_lock(&stats->lock);

  if (stats->window_start_ns == 0)
    stats->window_start_ns = now;

  u64 elapsed = now - stats->window_start_ns;
  if (elapsed >= ghost_window_ns)
  {
    if (stats->sample_total >= DISPATCHER_MIN_SAMPLES_FOR_EWMA)
    {
      u32 inst_bp = (u32)((stats->ghost_hits * 10000ULL) / stats->sample_total);
      if (!(stats->reserved & 0x1))
      {
        stats->ghost_hit_rate_bp = inst_bp;
        stats->reserved |= 0x1;
      }
      else
        stats->ghost_hit_rate_bp =
            (u32)(((u64)stats->ghost_hit_rate_bp * 7 + (u64)inst_bp * 3) / 10);

      stats->sample_total = 0;
      stats->ghost_hits = 0;
      stats->window_start_ns = now;
      need_update = true;
      smoothed_bp = stats->ghost_hit_rate_bp;
    }
  }
  stats->sample_total += 1;
  if (ghost_hit)
    stats->ghost_hits += 1;

  bpf_spin_unlock(&stats->lock);

  if (need_update)
  {
    if (!enable_secondary_slot)
      return;

    u64 routing_core = READ_ONCE(global_ts.routing_core);
    u32 phase, p = 0;
    dispatcher_unpack_routing_core(routing_core, &phase, &p);
    if (phase != PHASE_COMPLETE)
      update_transition_state(&global_ts, smoothed_bp);
    bpf_printk("Ghost window updated: ghost_hit_rate=%u bp, phase=%u, p=%u\n",
               smoothed_bp, phase, p);
  }
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
slot_folio_evicted1(u64 handle)
{
  // bpf_printk("folio evicted slot 1\n");
  asm volatile("" : : "r"(handle));
  return 0;
}

__attribute__((visibility("default")))
__noinline int
slot_folio_evicted2(u64 handle)
{
  // bpf_printk("folio evicted slot 2\n");
  asm volatile("" : : "r"(handle));
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
  // bpf_printk("folio added slot 1\n");
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

s32 BPF_STRUCT_OPS_SLEEPABLE(_init, struct mem_cgroup* memcg)
{
  // 初始化状态机
  enable_secondary_slot = false;
  WRITE_ONCE(global_ts.routing_core,
             dispatcher_pack_routing_core(PHASE_SLOW_START, 0));
  global_ts.ssthresh = 5000; // 初始慢启动阈值
  global_ts.high_ghr_streak = 0;
  global_ts.low_ghr_streak = 0;

  bpf_printk("Cache_ext Dispatcher init.\n");
  return 0;
}

void BPF_STRUCT_OPS(_evict_folios, struct cache_ext_eviction_ctx* eviction_ctx,
                    struct mem_cgroup* memcg)
{
  // bpf_printk("Evicted folio.\n");
  bool route_to_new = false;

  u64 eviction_ctx_handle = bpf_cache_ext_ctx_to_handle(eviction_ctx, secret);
  u64 memcg_handle = bpf_cache_ext_memcg_to_handle(memcg, secret);

  if (enable_secondary_slot)
  {
    u64 routing_core = READ_ONCE(global_ts.routing_core);
    u32 phase = 0, p = 0;
    dispatcher_unpack_routing_core(routing_core, &phase, &p);

    if (phase != PHASE_COMPLETE)
    {
      u32 rnd = bpf_get_prandom_u32() % SCALE;
      if (rnd < p)
        route_to_new = true;
    }
    else
      route_to_new = true;
  }
  if (route_to_new)
    slot_evict_folios2(eviction_ctx_handle, memcg_handle); // 迁移完成，全走新策略
  else
    slot_evict_folios1(eviction_ctx_handle, memcg_handle); // 未开始，全走旧策略

  // slot_evict_folios1(eviction_ctx_handle, memcg_handle);
  // if (unlikely(enable_secondary_slot))
  //   slot_evict_folios2(eviction_ctx_handle, memcg_handle);
  return;
}

void BPF_STRUCT_OPS(_folio_evicted, struct folio* folio)
{
  // bpf_printk("Folio evicted.\n");
  // if (!is_folio_relevant(folio))
  //   return;
  u64 handle = bpf_cache_ext_folio_to_handle(folio, secret);

  slot_folio_evicted1(handle);
  if (unlikely(enable_secondary_slot))
  {
    slot_folio_evicted2(handle);
    dispatcher_store_ghost(folio);
  }
  return;
}

void BPF_STRUCT_OPS(_folio_accessed, struct folio* folio)
{
  // bpf_printk("Folio accessed.\n");
  // if (!is_folio_relevant(folio))
  //   return;
  u64 handle = bpf_cache_ext_folio_to_handle(folio, secret);

  u64 routing_core = READ_ONCE(global_ts.routing_core);
  u32 phase = 0, p = 0;
  dispatcher_unpack_routing_core(routing_core, &phase, &p);
  if (enable_secondary_slot && phase == PHASE_COMPLETE)
  {
    slot_folio_accessed2(handle);
    return;
  }

  slot_folio_accessed1(handle);
  if (unlikely(enable_secondary_slot))
    slot_folio_accessed2(handle);
  return;
}

void BPF_STRUCT_OPS(_folio_added, struct folio* folio)
{
  // bpf_printk("Folio added.\n");
  // if (!is_folio_relevant(folio))
  //   return;
  u64 handle = bpf_cache_ext_folio_to_handle(folio, secret);

  u64 routing_core = READ_ONCE(global_ts.routing_core);
  u32 phase = 0, p = 0;
  dispatcher_unpack_routing_core(routing_core, &phase, &p);
  if (enable_secondary_slot && phase == PHASE_COMPLETE)
  {
    slot_folio_added2(handle);
    return;
  }

  slot_folio_added1(handle);
  if (unlikely(enable_secondary_slot))
  {
    slot_folio_added2(handle);
    bool ghost_hit = dispatcher_consume_ghost(folio);
    dispatcher_record_ghost_window_sample(ghost_hit);
  }
  return;
}

SEC(".struct_ops.link")
struct cache_ext_ops dispatcher_ops = {
    .init = (void*)_init,
    .evict_folios = (void*)_evict_folios,
    .folio_evicted = (void*)_folio_evicted,
    .folio_added = (void*)_folio_added,
    .folio_accessed = (void*)_folio_accessed};
