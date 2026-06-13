#include "logger/bpf/helpers.h"
#include "logger/bpf/delete_module.h"

struct sys_enter_delete_module {
  unsigned int flags;
  char name[MODULE_NAME_SIZE];
  enum error errors;
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 64);
  __type(key, u64);
  __type(value, struct sys_enter_delete_module);
} sys_enter_delete_module_hash SEC(".maps");

/* Buffer for sending sys_delete_module data to the userspace. */
struct {
  RINGBUF_BODY(NPROC * sizeof(struct sys_delete_module));
} sys_delete_module_buf SEC(".maps");

FUNC_INLINE int on_sys_enter_delete_module(const char* name,
                                           unsigned int flags) {
  struct sys_enter_delete_module enter = {
      .errors = 0, .flags = flags, .name[0] = '\0'};
  long ret = bpf_probe_read_user_str(&enter.name, sizeof(enter.name), name);
  if (ret < 0) {
    enter.errors |= EPROBE_READ_USER_STR;
    return 1;
  }
  const uint64_t hash_id = bpf_get_current_pid_tgid();
  bpf_map_update_elem(&sys_enter_delete_module_hash, &hash_id, &enter, BPF_ANY);
  return 0;
}

SEC("tracepoint/syscalls/sys_enter_delete_module")
int tracepoint__syscalls__sys_enter_delete_module(
    struct syscall_trace_enter* ctx) {
  return on_sys_enter_delete_module((const char*)ctx->args[0],
                                    (unsigned int)ctx->args[1]);
}

FUNC_INLINE int copy_sys_enter_delete_module(
    const struct sys_enter_delete_module* enter,
    struct sys_delete_module* sys_delete_module) {
  sys_delete_module->errors = enter->errors;
  sys_delete_module->flags = enter->flags;
  long ret = bpf_probe_read_kernel_str(
      &sys_delete_module->name, sizeof(sys_delete_module->name), &enter->name);
  if (ret < 0) {
    sys_delete_module->errors |= EPROBE_READ_KERNEL_STR;
    return FAILURE_CODE;
  }
  return SUCCESS_CODE;
}

FUNC_INLINE int on_sys_exit_delete_module(int event_ret, int event_type) {
  const uint64_t hash_id = bpf_get_current_pid_tgid();
  struct sys_enter_delete_module* enter =
      bpf_map_lookup_elem(&sys_enter_delete_module_hash, &hash_id);
  if (!enter) return 1;

  struct sys_delete_module* sys_delete_module = bpf_ringbuf_reserve(
      &sys_delete_module_buf, sizeof(*sys_delete_module), 0);
  if (!sys_delete_module) goto clean;

  sys_delete_module->ret = event_ret;
  sys_delete_module->event_type = event_type;
  long ret = copy_sys_enter_delete_module(enter, sys_delete_module);
  if (ret == FAILURE_CODE) sys_delete_module->errors |= ECOPY_ENTER;
  ret = fill_task(&sys_delete_module->task, &sys_delete_module->errors);
  if (ret == FAILURE_CODE) sys_delete_module->errors |= EFILL_TASK;

  bpf_ringbuf_submit(sys_delete_module, 0);
clean:
  bpf_map_delete_elem(&sys_enter_delete_module_hash, &hash_id);
  return 0;
}

SEC("tracepoint/syscalls/sys_exit_delete_module")
int tracepoint__syscalls__sys_exit_delete_module(struct syscall_trace_exit* ctx) {
  return on_sys_exit_delete_module((int)ctx->ret, SYS_DELETE_MODULE);
}
