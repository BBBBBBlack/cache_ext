/* a_uapi.h */
// 存放“内核态与用户态共享的数据结构和宏定义”的标准命名规范
#ifndef __A_UAPI_H__
#define __A_UAPI_H__

#ifndef __BPF__
#include <linux/types.h>
#include <stdint.h>
typedef uint32_t u32;
typedef uint64_t u64;
#endif

#define MIGRATION_Q_SIZE 4096 // 容量必须是 2 的幂

struct generic_cache_metrics_uapi
{
  __u32 freq;              // 访问频次
  __u32 seq;               // 序列号
  __u64 last_access_ns;    // 最近访问时间
  __u64 insertion_time_ns; // 存活时长/进入时间
  __u64 handle;            // folio指针
};

struct migration_qstate_uapi
{
  __u32 head __attribute__((aligned(64)));
  __u32 tail __attribute__((aligned(64)));
};

struct ghost_window_stats_uapi
{
  __u64 window_start_ns;
  __u64 window_ns;
  __u32 sample_total;
  __u32 ghost_hits;
  __u32 ghost_hit_rate_bp;
  __u32 reserved;
  struct bpf_spin_lock lock;
};

enum
{
  PHASE_OFF = 0,
  PHASE_SLOW_START = 1,
  PHASE_CA = 2, // Congestion Avoidance
  PHASE_FAST_RECOVERY = 3,
  PHASE_TIMEOUT = 4,
  PHASE_COMPLETE = 5
};

struct transition_state
{
  union
  {
    struct
    {
      u32 phase;
      u32 p; // 当前采用新策略的概率 (0-10000)
    };
    u64 routing_core; // 将 phase 和 p 联合为一个 64 位整数
  };
  u32 ssthresh; // 慢启动阈值 (0-10000)

  // 持续性判断：多周期高/低 GHR 计数器
  u32 high_ghr_streak; // 连续高 GHR 的周期数
  u32 low_ghr_streak;  // 连续低 GHR 的周期数
};

#endif /* __A_UAPI_H__ */