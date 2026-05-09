#ifndef A_COMMUNICATION_H
#define A_COMMUNICATION_H

#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define DISPATCHER_CONTROL_SOCKET_PATH "/tmp/cache_ext_dispatcher_%llu.sock"
#define LOADER_CONTROL_SOCKET_PATH "/tmp/cache_ext_loader_%llu.sock"

enum ipc_cmd
{
  CMD_MIGRATION_BEGIN = 1,
  CMD_MIGRATION_PROGRESS = 2,
  CMD_MIGRATION_COMPLETE = 3
};

struct ipc_msg
{
  uint32_t cmd;
  uint32_t p;
};

// 封装 UDS 和 epoll 的核心资源
struct ipc_server_ctx
{
  int listen_fd;
  int epoll_fd;
  char socket_path[PATH_MAX];
};

// 工具函数暴露给外部复用
int set_nonblocking(int fd);
int add_epoll_fd(int epoll_fd, int fd);

static inline int send_ipc_message(const char* path_fmt, unsigned long long cgroup_id, struct ipc_msg* msg)
{
  int fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0)
    return -1;

  struct sockaddr_un addr;
  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;

  // 使用 sizeof(addr.sun_path) 确保不会发生缓冲区溢出
  snprintf(addr.sun_path, sizeof(addr.sun_path), path_fmt, cgroup_id);

  int ret = -1;
  if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) == 0)
  {
    if (write(fd, msg, sizeof(*msg)) == sizeof(*msg))
      ret = 0;
  }
  else
    perror("Failed to connect to IPC socket");
  close(fd);
  return ret;
}

// 生命周期管理
int build_ipc_server(struct ipc_server_ctx* ctx, const char* socket_path);
void destroy_ipc_server(struct ipc_server_ctx* ctx);

#endif // A_COMMUNICATION_H