/* a_uapi.h */
#ifndef __A_UAPI_H__
#define __A_UAPI_H__

#ifndef __BPF__
#include <linux/types.h>
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

#endif /* __A_UAPI_H__ */