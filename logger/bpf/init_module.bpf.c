#include "logger/bpf/helpers.h"
#include "logger/bpf/init_module.h"

struct sys_enter_init_module {
  /* fd from finit_module arg. */
  int fd;
  /* flags from finit_module arg. */
  int flags;
  /* size from init_module arg. */
  unsigned long size;
  char params[PARAMS_SIZE];
  enum error errors;
};

/* Map for sharing data between enter and exit tracepoints. */
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, u32);
  __type(value, struct sys_enter_init_module);
} sys_enter_init_module_array SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 64);
  __type(key, u64);
  __type(value, struct sys_enter_init_module);
} sys_enter_init_module_hash SEC(".maps");

/* Buffer for sending sys_init_module data to the userspace. */
struct {
  RINGBUF_BODY(NPROC * sizeof(struct sys_finit_module));
} sys_init_module_buf SEC(".maps");

FUNC_INLINE int on_sys_enter_init_module(int fd, int flags, unsigned long size,
                                         const char* params) {
  const int array_index = 0;
  struct sys_enter_init_module* enter =
      bpf_map_lookup_elem(&sys_enter_init_module_array, &array_index);
  if (!enter) return 1;
  enter->errors = 0;
  enter->size = size;
  enter->flags = flags;
  enter->fd = fd;
  enter->params[0] = '\0';
  if (bpf_probe_read_user_str(&enter->params, sizeof(enter->params), params) <
      0) {
    enter->errors |= EREAD_ARGV;
    return 1;
  }
  const uint64_t hash_id = bpf_get_current_pid_tgid();
  bpf_map_update_elem(&sys_enter_init_module_hash, &hash_id, enter, BPF_ANY);
  return 0;
}

SEC("tracepoint/syscalls/sys_enter_init_module")
int tracepoint__syscalls__sys_enter_init_module(
    struct syscall_trace_enter* ctx) {
  return on_sys_enter_init_module(0, 0, (unsigned long)ctx->args[1],
                                  (const char*)ctx->args[2]);
}

SEC("tracepoint/syscalls/sys_enter_finit_module")
int tracepoint__syscalls__sys_enter_finit_module(
    struct syscall_trace_enter* ctx) {
  return on_sys_enter_init_module((int)ctx->args[0], (int)ctx->args[2], 0,
                                  (const char*)ctx->args[1]);
}

FUNC_INLINE int on_sys_exit_init_module(int event_ret, int event_type) {
  const uint64_t hash_id = bpf_get_current_pid_tgid();
  struct sys_enter_init_module* enter =
      bpf_map_lookup_elem(&sys_enter_init_module_hash, &hash_id);
  if (!enter) return 1;

  unsigned long data_sz = sizeof(struct sys_init_module);
  if (event_type == SYS_FINIT_MODULE) data_sz = sizeof(struct sys_finit_module);
  struct sys_init_module* sys_init_module =
      bpf_ringbuf_reserve(&sys_init_module_buf, data_sz, 0);
  if (!sys_init_module) goto clean;
  sys_init_module->errors = enter->errors;
  sys_init_module->event_type = event_type;
  sys_init_module->ret = event_ret;
  long ret = bpf_probe_read_kernel_str(&sys_init_module->params,
                                       sizeof(sys_init_module->params),
                                       &enter->params);
  if (ret < 0) sys_init_module->errors |= ECOPY_ENTER;
  ret = fill_task(&sys_init_module->task, &sys_init_module->errors);
  if (ret == FAILURE_CODE) sys_init_module->errors |= EFILL_TASK;

  if (event_type == SYS_FINIT_MODULE) {
    struct sys_finit_module* finit = (struct sys_finit_module*)sys_init_module;
    ret = read_fd_path(enter->fd, &finit->module, 0, &sys_init_module->errors);
    if (ret == FAILURE_CODE) sys_init_module->errors |= EREAD_FD_PATH;
    finit->flags = enter->flags;
  } else {
    sys_init_module->size = enter->size;
  }

  bpf_ringbuf_submit(sys_init_module, 0);
clean:
  bpf_map_delete_elem(&sys_enter_init_module_hash, &hash_id);
  return 0;
}

SEC("tracepoint/syscalls/sys_exit_init_module")
int tracepoint__syscalls__sys_exit_init_module(struct syscall_trace_exit* ctx) {
  return on_sys_exit_init_module((int)ctx->ret, SYS_INIT_MODULE);
}

SEC("tracepoint/syscalls/sys_exit_finit_module")
int tracepoint__syscalls__sys_exit_finit_module(
    struct syscall_trace_exit* ctx) {
  return on_sys_exit_init_module((int)ctx->ret, SYS_FINIT_MODULE);
}
