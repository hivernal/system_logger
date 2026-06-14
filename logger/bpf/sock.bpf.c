#include "logger/bpf/helpers.h"
#include "logger/bpf/sock.h"

/* IPV4. */
#define AF_INET 2
/* IPV6. */
#define AF_INET6 10

/* For file.f_inode->i_mode. */
#define S_IFMT 00170000
/* Linux socket. */
#define S_IFSOCK 0140000
/* Is socket. */
#define S_ISSOCK(m) (((m) & S_IFMT) == S_IFSOCK)

/* Buffer for sending sys_sock6 and sys_sock4 data to the userspace. */
struct {
  RINGBUF_BODY(NPROC * sizeof(struct sys_sock6));
} sys_sock_buf SEC(".maps");

/*
 * Map for sharing data between enter and exit sockets syscalls
 * tracepoints.
 */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 128);
  __type(key, u64);
  __type(value, int);
} sys_enter_sock_hash SEC(".maps");

FUNC_INLINE int get_sock_from_fd(int fd, const struct sock** sock,
                                 enum error* errors) {
  if (!sock) return 1;
  const struct file* file;
  const struct socket* socket;
  long ret = get_file_from_fd(fd, &file, errors);
  if (ret == FAILURE_CODE) {
    *errors |= EGET_FILE_FROM_FD;
    return FAILURE_CODE;
  }
  umode_t i_mode;
  if (BPF_CORE_READ_INTO(&i_mode, file, f_inode, i_mode)) {
    *errors |= ECORE_READ;
    return FAILURE_CODE;
  }
  if (!S_ISSOCK(i_mode)) return FAILURE_CODE;
  ret = bpf_core_read(&socket, sizeof(socket), &file->private_data);
  if (ret < 0) {
    *errors |= ECORE_READ;
    return FAILURE_CODE;
  }
  ret = bpf_core_read(sock, sizeof(*sock), &socket->sk);
  if (ret < 0) {
    *errors |= ECORE_READ;
    return FAILURE_CODE;
  }
  return SUCCESS_CODE;
}

/* Fills the sys_enter_sock_hash map. */
FUNC_INLINE int on_sys_enter_sock(int fd) {
  const uint64_t hash_id = bpf_get_current_pid_tgid();
  return (int)bpf_map_update_elem(&sys_enter_sock_hash, &hash_id, &fd, BPF_ANY);
}

SEC("tracepoint/syscalls/sys_enter_connect")
int tracepoint__syscalls__sys_enter_connect(struct syscall_trace_enter* ctx) {
  return on_sys_enter_sock((int)ctx->args[0]);
}

/*
SEC("tracepoint/syscalls/sys_enter_close")
int tracepoint__syscalls__sys_enter_close(struct syscall_trace_enter* ctx) {
  return on_sys_enter_sock((int)ctx->args[0]);
}

SEC("tracepoint/syscalls/sys_enter_shutdown")
int tracepoint__syscalls__sys_enter_shutdown(struct syscall_trace_enter* ctx) {
  return on_sys_enter_sock((int)ctx->args[0]);
}
*/

/* Reads the destination and source addresses and ports of the sock. */
FUNC_INLINE int fill_sys_sock4(struct sys_sock4* sys_sock4,
                               const struct sock* sock, enum error* errors) {
  if (bpf_core_read(&sys_sock4->daddr, sizeof(sys_sock4->daddr),
                    &sock->__sk_common.skc_daddr) < 0) {
    *errors |= EREAD_DADDR;
    return FAILURE_CODE;
  }
  if (bpf_core_read(&sys_sock4->saddr, sizeof(sys_sock4->saddr),
                    &sock->__sk_common.skc_rcv_saddr) < 0) {
    *errors |= EREAD_SADDR;
    return FAILURE_CODE;
  }
  if (bpf_core_read(&sys_sock4->dport, sizeof(sys_sock4->dport),
                    &sock->__sk_common.skc_dport) < 0) {
    *errors |= EREAD_DPORT;
    return FAILURE_CODE;
  }
  if (bpf_core_read(&sys_sock4->sport, sizeof(sys_sock4->sport),
                    &sock->__sk_common.skc_num) < 0) {
    *errors |= EREAD_SPORT;
    return FAILURE_CODE;
  }
  return SUCCESS_CODE;
}

FUNC_INLINE int fill_sys_sock6(struct sys_sock6* sys_sock6,
                               const struct sock* sock, enum error* errors) {
  if (bpf_core_read(&sys_sock6->daddr, sizeof(sys_sock6->daddr),
                    &sock->__sk_common.skc_v6_daddr.in6_u) < 0) {
    *errors |= EREAD_DADDR;
    return FAILURE_CODE;
  }
  if (bpf_core_read(&sys_sock6->saddr,
                    sizeof(sock->__sk_common.skc_v6_rcv_saddr),
                    &sock->__sk_common.skc_v6_rcv_saddr.in6_u) < 0) {
    *errors |= EREAD_SADDR;
    return FAILURE_CODE;
  }
  if (bpf_core_read(&sys_sock6->dport, sizeof(sock->__sk_common.skc_portpair),
                    &sock->__sk_common.skc_portpair) < 0) {
    *errors |= EREAD_DPORT;
    return FAILURE_CODE;
  }
  return SUCCESS_CODE;
}

/* Reads socket protocol, state, type, fills task. */
FUNC_INLINE int fill_sys_sock(const struct sock* sock,
                              struct sys_sock* sys_sock, int event_ret,
                              sa_family_t family, int event_type) {
  enum error errors = 0;
  long ret = bpf_core_read(&sys_sock->protocol, sizeof(sock->sk_protocol),
                           &sock->sk_protocol);
  if (ret < 0) errors |= EREAD_SOCK_PROTOCOL;
  ret = bpf_core_read(&sys_sock->type, sizeof(sock->sk_type), &sock->sk_type);
  if (ret < 0) errors |= EREAD_SOCK_TYPE;
  ret = fill_task(&sys_sock->task, &errors);
  if (ret == FAILURE_CODE) errors |= EFILL_TASK;
  sys_sock->ret = event_ret;
  sys_sock->family = family;
  sys_sock->event_type = event_type;
  ret = bpf_core_read(&sys_sock->state, sizeof(sys_sock->state),
                      &sock->__sk_common.skc_state);
  if (ret < 0) errors |= EREAD_SOCK_STATE;
  sys_sock->errors |= errors;
  if (errors) return FAILURE_CODE;
  return SUCCESS_CODE;
}

FUNC_INLINE int fill_and_send_sock(const struct sock* sock, int event_ret,
                                   int event_type) {
  sa_family_t family;
  long ret =
      bpf_core_read(&family, sizeof(family), &sock->__sk_common.skc_family);
  if (ret < 0) return FAILURE_CODE;
  struct sys_sock* sys_sock = NULL;
  enum error errors = 0;
  unsigned char state;
  ret = bpf_core_read(&state, sizeof(state), &sock->__sk_common.skc_state);
  if (ret < 0) errors |= EREAD_SOCK_STATE;
  if ((event_type == SYS_CONNECT && state == TCP_CLOSE)) return SUCCESS_CODE;
  if (family == AF_INET) {
    struct sys_sock4* sys_sock4 =
        bpf_ringbuf_reserve(&sys_sock_buf, sizeof(*sys_sock4), 0);
    if (!sys_sock4) return FAILURE_CODE;
    sys_sock = (struct sys_sock*)sys_sock4;
    ret = fill_sys_sock4(sys_sock4, sock, &errors);
    if (ret == FAILURE_CODE) errors |= EFILL_SOCK4;
  } else if (family == AF_INET6) {
    struct sys_sock6* sys_sock6 =
        bpf_ringbuf_reserve(&sys_sock_buf, sizeof(*sys_sock6), 0);
    if (!sys_sock6) return FAILURE_CODE;
    sys_sock = (struct sys_sock*)sys_sock6;
    ret = fill_sys_sock6(sys_sock6, sock, &errors);
    if (ret == FAILURE_CODE) errors |= EFILL_SOCK6;
  } else {
    return SUCCESS_CODE;
  }
  ret = fill_sys_sock(sock, sys_sock, event_ret, family, event_type);
  if (ret == FAILURE_CODE) errors |= EFILL_SOCK;
  sys_sock->errors |= errors;
  bpf_ringbuf_submit(sys_sock, 0);
  if (errors) return FAILURE_CODE;
  return SUCCESS_CODE;
}

FUNC_INLINE int on_sys_exit_sock(int ret, int event_type) {
  const uint64_t hash_id = bpf_get_current_pid_tgid();
  const int* fd = bpf_map_lookup_elem(&sys_enter_sock_hash, &hash_id);
  if (!fd) return 1;
  const struct sock* sock;
  enum error errors = 0;
  if (get_sock_from_fd(*fd, &sock, &errors) == FAILURE_CODE) {
    bpf_map_delete_elem(&sys_enter_sock_hash, &hash_id);
    return 1;
  }
  bpf_map_delete_elem(&sys_enter_sock_hash, &hash_id);
  if (fill_and_send_sock(sock, ret, event_type) == FAILURE_CODE) return 1;
  return 0;
}

SEC("tracepoint/syscalls/sys_exit_connect")
int tracepoint__syscalls__sys_exit_connect(struct syscall_trace_exit* ctx) {
  return on_sys_exit_sock((int)ctx->ret, SYS_CONNECT);
}

/*
SEC("tracepoint/syscalls/sys_exit_close")
int tracepoint__syscalls__sys_exit_close(struct syscall_trace_exit* ctx) {
  return on_sys_exit_sock((int)ctx->ret, SYS_CLOSE);
}

SEC("tracepoint/syscalls/sys_exit_shutdown")
int tracepoint__syscalls__sys_exit_shutdown(struct syscall_trace_exit* ctx) {
  return on_sys_exit_sock((int)ctx->ret, SYS_SHUTDOWN);
}
*/

SEC("tracepoint/syscalls/sys_exit_accept")
int tracepoint__syscalls__sys_exit_accept(struct syscall_trace_exit* ctx) {
  int fd = (int)ctx->ret;
  const struct sock* sock;
  enum error errors = 0;
  if (get_sock_from_fd(fd, &sock, &errors) == FAILURE_CODE) return 1;
  return fill_and_send_sock(sock, fd, SYS_ACCEPT);
}

SEC("tracepoint/syscalls/sys_exit_accept4")
int tracepoint__syscalls__sys_exit_accept4(struct syscall_trace_exit* ctx) {
  int fd = (int)ctx->ret;
  const struct sock* sock;
  enum error errors;
  if (get_sock_from_fd(fd, &sock, &errors)) return 1;
  return fill_and_send_sock(sock, fd, SYS_ACCEPT4);
}

SEC("tracepoint/syscalls/sys_enter_listen")
int tracepoint__syscalls__sys_enter_listen(struct syscall_trace_enter* ctx) {
  return on_sys_enter_sock((int)ctx->args[0]);
}

/* Reads the source addresse and port of the sock. */
FUNC_INLINE int fill_sys_sock4_saddr(struct sys_single_sock4* sock4,
                                     const struct sock* sock,
                                     enum error* errors) {
  if (bpf_core_read(&sock4->addr, sizeof(sock4->addr),
                    &sock->__sk_common.skc_rcv_saddr) < 0) {
    *errors |= EREAD_SADDR;
    return FAILURE_CODE;
  }
  if (bpf_core_read(&sock4->port, sizeof(sock4->port),
                    &sock->__sk_common.skc_num) < 0) {
    *errors |= EREAD_SPORT;
    return FAILURE_CODE;
  }
  return SUCCESS_CODE;
}

/* Reads the source addresse and port of the sock. */
FUNC_INLINE int fill_sys_sock6_saddr(struct sys_single_sock6* sock6,
                                     const struct sock* sock,
                                     enum error* errors) {
  if (bpf_core_read(&sock6->addr, sizeof(sock6->addr),
                    &sock->__sk_common.skc_v6_rcv_saddr.in6_u) < 0) {
    *errors |= EREAD_SADDR;
    return FAILURE_CODE;
  }
  if (bpf_core_read(&sock6->port, sizeof(sock6->port),
                    &sock->__sk_common.skc_num) < 0) {
    *errors |= EREAD_SPORT;
    return FAILURE_CODE;
  }
  return SUCCESS_CODE;
}

FUNC_INLINE int fill_and_send_sock_saddr(const struct sock* sock, int event_ret,
                                         int event_type) {
  sa_family_t family;
  long ret =
      bpf_core_read(&family, sizeof(family), &sock->__sk_common.skc_family);
  if (ret < 0) return 1;
  struct sys_sock* sys_sock = NULL;
  enum error errors = 0;
  if (family == AF_INET) {
    struct sys_single_sock4* sys_single_sock4 =
        bpf_ringbuf_reserve(&sys_sock_buf, sizeof(*sys_single_sock4), 0);
    if (!sys_single_sock4) return FAILURE_CODE;
    sys_sock = (struct sys_sock*)sys_single_sock4;
    ret = fill_sys_sock4_saddr(sys_single_sock4, sock, &errors);
    if (ret == FAILURE_CODE) errors |= EFILL_SOCK4;
  } else if (family == AF_INET6) {
    struct sys_single_sock6* sys_single_sock6 =
        bpf_ringbuf_reserve(&sys_sock_buf, sizeof(*sys_single_sock6), 0);
    if (!sys_single_sock6) return FAILURE_CODE;
    sys_sock = (struct sys_sock*)sys_single_sock6;
    ret = fill_sys_sock6_saddr(sys_single_sock6, sock, &errors);
    if (ret == FAILURE_CODE) errors |= EFILL_SOCK6;
  } else {
    return SUCCESS_CODE;
  }
  ret = fill_sys_sock(sock, sys_sock, event_ret, family, event_type);
  if (ret == FAILURE_CODE) errors |= EFILL_SOCK;
  sys_sock->errors |= errors;
  bpf_ringbuf_submit(sys_sock, 0);
  if (errors) return FAILURE_CODE;
  return SUCCESS_CODE;
};

FUNC_INLINE int on_sys_exit_listen(int event_ret, int event_type) {
  const uint64_t hash_id = bpf_get_current_pid_tgid();
  const int* fd = bpf_map_lookup_elem(&sys_enter_sock_hash, &hash_id);
  if (!fd) return 1;
  const struct sock* sock;
  enum error errors = 0;
  long ret = get_sock_from_fd(*fd, &sock, &errors);
  if (ret == FAILURE_CODE) {
    bpf_map_delete_elem(&sys_enter_sock_hash, &hash_id);
    return 1;
  }
  if (fill_and_send_sock_saddr(sock, event_ret, event_type) == FAILURE_CODE)
    return 1;
  bpf_map_delete_elem(&sys_enter_sock_hash, &hash_id);
  return 0;
}

SEC("tracepoint/syscalls/sys_exit_listen")
int tracepoint__syscalls__sys_exit_listen(struct syscall_trace_exit* ctx) {
  return on_sys_exit_listen((int)ctx->ret, SYS_LISTEN);
}
