#include "logger/bpf/helpers.h"
#include "logger/bpf/mmap.h"

/* Buffer for sending sys_mmap data to userspace. */
struct {
  RINGBUF_BODY(NPROC * sizeof(struct sys_mmap));
} sys_mmap_buf SEC(".maps");

/* Struct contains sys_enter_mmap tracepoint data. */
struct sys_enter_mmap {
  /* prot argument describes the desired memory protection of the mapping. */
  int prot;
  /*
   * The flags argument determines whether updates to the mapping are visible to
   * other processes mapping the same region.
   */
  unsigned int flags;
  /* The file descriptor of the file. */
  int fd;
  enum error errors;
};

/* Hash map for sharing data between enter and exit tracepoints. */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 128);
  __type(key, u64);
  __type(value, struct sys_enter_mmap);
} sys_enter_mmap_hash SEC(".maps");

/* For file.f_inode->i_mode. */
#define S_IFMT 00170000
/* Regular file. */
#define S_IFREG 0100000

/* Is regular file. */
#define S_ISREG(m) (((m) & S_IFMT) == S_IFREG)

/* mmap prot bit value. */
#define PROT_EXEC 0x4

FUNC_INLINE int on_sys_enter_mmap(int fd, int prot, unsigned flags) {
  if (!(prot & PROT_EXEC)) return 0;
  const struct file* file;
  enum error errors = 0;
  if (get_file_from_fd(fd, &file, &errors) == FAILURE_CODE) return 1;
  umode_t i_mode = BPF_CORE_READ(file, f_inode, i_mode);
  if (!S_ISREG(i_mode)) return 0;

  struct sys_enter_mmap enter = {
      .fd = fd, .prot = prot, .flags = flags, .errors = 0};
  const uint64_t hash_id = bpf_get_current_pid_tgid();
  bpf_map_update_elem(&sys_enter_mmap_hash, &hash_id, &enter, BPF_ANY);
  return 0;
}

SEC("tracepoint/syscalls/sys_enter_mmap")
int tracepoint__syscalls__sys_enter_mmap(struct syscall_trace_enter* ctx) {
  return on_sys_enter_mmap((int)ctx->args[4], (int)ctx->args[2],
                           (unsigned int)ctx->args[3]);
}

FUNC_INLINE int on_sys_exit_mmap(int event_ret, int event_type) {
  const uint64_t hash_id = bpf_get_current_pid_tgid();
  struct sys_enter_mmap* enter =
      bpf_map_lookup_elem(&sys_enter_mmap_hash, &hash_id);
  if (!enter) return 1;
  struct sys_mmap* sys_mmap =
      bpf_ringbuf_reserve(&sys_mmap_buf, sizeof(*sys_mmap), 0);
  if (!sys_mmap) goto clean;
  sys_mmap->errors = enter->errors;
  long ret = read_fd_path(enter->fd, &sys_mmap->file, 0, &sys_mmap->errors);
  if (ret == FAILURE_CODE) sys_mmap->errors |= EREAD_FD_PATH;
  ret = fill_task(&sys_mmap->task, &sys_mmap->errors);
  if (ret == FAILURE_CODE) sys_mmap->errors |= EFILL_TASK;
  sys_mmap->ret = event_ret;
  sys_mmap->event_type = event_type;
  sys_mmap->flags = enter->flags;
  sys_mmap->prot = enter->prot;
  bpf_ringbuf_submit(sys_mmap, 0);
clean:
  bpf_map_delete_elem(&sys_enter_mmap_hash, &hash_id);
  return 0;
}

SEC("tracepoint/syscalls/sys_exit_mmap")
int tracepoint__syscalls__sys_exit_mmap(struct syscall_trace_exit* ctx) {
  return on_sys_exit_mmap((int)ctx->ret, SYS_MMAP);
}
