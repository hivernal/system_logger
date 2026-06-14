#ifndef LOGGER_BPF_MMAP_H_
#define LOGGER_BPF_MMAP_H_

#include "logger/bpf/task.h"

/* Struct for mmap syscall. */
struct sys_mmap {
  /* mmaped file. */
  struct path_dentries file;
  /* prot argument describes the desired memory protection of the mapping. */
  int prot;
  /*
   * The flags argument determines whether updates to the mapping are visible to
   * other processes mapping the same region.
   */
  unsigned flags;
  enum error errors;
  /* mmap returned value. */
  int ret;
  struct task task;
  int event_type;
};

#endif  // LOGGER_BPF_MMAP_H_
