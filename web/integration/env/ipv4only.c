// Test-environment shim, NOT part of any product build.
// Some sandboxes (e.g. gVisor/Firecracker CI containers) have no IPv6 stack:
// socket(AF_INET6, ...) fails with EAFNOSUPPORT. Holochain 0.7's websocket
// dual_bind only falls back to IPv4-only for EADDRNOTAVAIL, the errno Linux
// returns when IPv6 is *disabled*. This preload reports the latter so the
// unchanged conductor uses its documented IPv4-only fallback.
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <sys/socket.h>

int socket(int domain, int type, int protocol) {
  static int (*real)(int, int, int);
  if (!real) real = (int (*)(int, int, int))dlsym(RTLD_NEXT, "socket");
  int fd = real(domain, type, protocol);
  if (fd < 0 && domain == AF_INET6 && errno == EAFNOSUPPORT) errno = EADDRNOTAVAIL;
  return fd;
}
