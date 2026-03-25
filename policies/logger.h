#ifndef __LOGGER_COMMON_H__
#define __LOGGER_COMMON_H__

#define MAX_LOG_MSG_LEN 64
#define MAX_LOG_ARGS 4

// 日志事件结构体
struct log_event
{
  unsigned long long ts;                 // 时间戳
  unsigned int pid;                      // 进程 ID
  char fmt[MAX_LOG_MSG_LEN];             // 格式化字符串 (例如 "Value is %d")
  unsigned long long args[MAX_LOG_ARGS]; // 参数数组
};

#endif