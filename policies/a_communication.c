#include "a_communication.h"
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

int set_nonblocking(int fd)
{
  int flags = fcntl(fd, F_GETFL, 0);
  if (flags < 0)
    return -1;
  return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

int add_epoll_fd(int epoll_fd, int fd)
{
  struct epoll_event ev;
  memset(&ev, 0, sizeof(ev));
  ev.events = EPOLLIN;
  ev.data.fd = fd;

  if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ev) < 0)
  {
    perror("epoll_ctl add failed");
    return -1;
  }
  return 0;
}

int build_ipc_server(struct ipc_server_ctx* ctx, const char* socket_path)
{
  memset(ctx, 0, sizeof(*ctx));
  ctx->listen_fd = -1;
  ctx->epoll_fd = -1;
  strncpy(ctx->socket_path, socket_path, sizeof(ctx->socket_path) - 1);

  ctx->listen_fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (ctx->listen_fd < 0)
  {
    perror("Failed to create socket");
    goto cleanup;
  }

  struct sockaddr_un addr;
  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  unlink(ctx->socket_path);
  strncpy(addr.sun_path, ctx->socket_path, sizeof(addr.sun_path) - 1);

  if (set_nonblocking(ctx->listen_fd) < 0)
  {
    perror("Failed to set non-blocking");
    goto cleanup;
  }

  if (bind(ctx->listen_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0)
  {
    perror("Failed to bind socket");
    goto cleanup;
  }

  if (listen(ctx->listen_fd, 5) < 0)
  {
    perror("Failed to listen on socket");
    goto cleanup;
  }

  ctx->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
  if (ctx->epoll_fd < 0)
  {
    perror("Failed to create epoll instance");
    goto cleanup;
  }

  if (add_epoll_fd(ctx->epoll_fd, ctx->listen_fd) < 0)
    goto cleanup;

  return 0;

cleanup:
  destroy_ipc_server(ctx);
  return -1;
}

void destroy_ipc_server(struct ipc_server_ctx* ctx)
{
  if (!ctx)
    return;
  if (ctx->epoll_fd >= 0)
  {
    close(ctx->epoll_fd);
    ctx->epoll_fd = -1;
  }
  if (ctx->listen_fd >= 0)
  {
    close(ctx->listen_fd);
    ctx->listen_fd = -1;
  }
  if (ctx->socket_path[0] != '\0')
  {
    unlink(ctx->socket_path);
    ctx->socket_path[0] = '\0';
  }
}