#ifndef LOGGER_BPF_DELETE_MODULE_H_
#define LOGGER_BPF_DELETE_MODULE_H_

#include "logger/bpf/task.h"

#define MODULE_NAME_SIZE 64

/* Struct for delete_module syscall. */
struct sys_delete_module {
  int event_type;
  char name[MODULE_NAME_SIZE];
  unsigned int flags;
  int ret;
  enum error errors;
  struct task task;
};

#endif // LOGGER_BPF_DELETE_MODULE_H_
