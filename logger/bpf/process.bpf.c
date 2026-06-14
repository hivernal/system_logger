#include "logger/bpf/helpers.h"
#include "logger/bpf/process.h"

/* Buffer for sending sys_clone data to the userspace. */
struct {
  RINGBUF_BODY(NPROC * sizeof(struct sys_clone));
} sys_clone_buf SEC(".maps");

/* Buffer for sending sched_process_exit data to the userspace. */
struct {
  RINGBUF_BODY(NPROC * sizeof(struct sched_process_exit));
} sched_process_exit_buf SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 128);
  __type(key, u64);
  __type(value, u64);
} sys_enter_clone_hash SEC(".maps");

FUNC_INLINE int on_sys_enter_clone(uint64_t flags) {
  const uint64_t hash_id = bpf_get_current_pid_tgid();
  return (int)bpf_map_update_elem(&sys_enter_clone_hash, &hash_id, &flags,
                                  BPF_ANY);
}

SEC("tracepoint/syscalls/sys_enter_clone")
int tracepoint__syscalls__sys_enter_clone(struct syscall_trace_enter* ctx) {
  return on_sys_enter_clone((uint64_t)ctx->args[0]);
}

SEC("tracepoint/syscalls/sys_enter_clone3")
int tracepoint__syscalls__sys_enter_clone3(struct syscall_trace_enter* ctx) {
  struct clone_args* args = (struct clone_args*)ctx->args[0];
  uint64_t flags;
  if (bpf_core_read_user(&flags, sizeof(flags), &args->flags) < 0) return 1;
  return on_sys_enter_clone(flags);
}

FUNC_INLINE int on_sys_exit_clone(int ret, int event_type) {
  const uint64_t hash_id = bpf_get_current_pid_tgid();
  uint64_t* flags = bpf_map_lookup_elem(&sys_enter_clone_hash, &hash_id);
  if (!flags) return 1;
  struct sys_clone* sys_clone =
      bpf_ringbuf_reserve(&sys_clone_buf, sizeof(*sys_clone), 0);
  if (!sys_clone) goto clean;
  sys_clone->errors = 0;
  sys_clone->flags = *flags;
  if (fill_task(&sys_clone->task, &sys_clone->errors) == FAILURE_CODE)
    sys_clone->errors |= EFILL_TASK;
  sys_clone->ret = ret;
  sys_clone->event_type = event_type;
  bpf_ringbuf_submit(sys_clone, 0);
clean:
  bpf_map_delete_elem(&sys_enter_clone_hash, &hash_id);
  return 0;
}

SEC("tracepoint/syscalls/sys_exit_clone")
int tracepoint__syscalls__sys_exit_clone(struct syscall_trace_exit* ctx) {
  return on_sys_exit_clone((int)ctx->ret, SYS_CLONE);
}

SEC("tracepoint/syscalls/sys_exit_clone3")
int tracepoint__syscalls__sys_exit_clone3(struct syscall_trace_exit* ctx) {
  return on_sys_exit_clone((int)ctx->ret, SYS_CLONE3);
}

SEC("tracepoint/sched/sched_process_exit")
int tracepoint__sched__sched_process_exit(
    struct trace_event_raw_sched_process_exit* ctx) {
  struct sched_process_exit* sched_process_exit = bpf_ringbuf_reserve(
      &sched_process_exit_buf, sizeof(*sched_process_exit), 0);
  if (!sched_process_exit) return 1;
  sched_process_exit->errors = 0;
  sched_process_exit->exit_code = 0;
  long ret = fill_task(&sched_process_exit->task, &sched_process_exit->errors);
  if (ret == FAILURE_CODE) sched_process_exit->errors |= EFILL_TASK;
  struct task_struct* task = (struct task_struct*)bpf_get_current_task();
  if (!task) {
    sched_process_exit->errors |= EGET_CURRENT_TASK;
  } else {
    ret =
        bpf_core_read(&sched_process_exit->exit_code,
                      sizeof(sched_process_exit->exit_code), &task->exit_code);
    if (ret < 0) sched_process_exit->errors |= ECORE_READ;
  }
  sched_process_exit->group_dead = (int)ctx->group_dead;
  bpf_ringbuf_submit(sched_process_exit, 0);
  return 0;
}
