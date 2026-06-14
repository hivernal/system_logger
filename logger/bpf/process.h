#ifndef LOGGER_BPF_PROCESS_H_
#define LOGGER_BPF_PROCESS_H_

#include "logger/bpf/task.h"

/* Struct for clone and clone3 syscalls. */
struct sys_clone {
  struct task task;
  uint64_t flags;
  int event_type;
  enum error errors;
  int ret;
};

/* Struct for sched_process_exit. Process exit. */
struct sched_process_exit {
  int exit_code;
  int group_dead;
  enum error errors;
  struct task task;
};

#endif  // LOGGER_BPF_PROCESS_H_
