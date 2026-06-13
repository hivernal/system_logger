#ifndef LOGGER_BPF_INIT_MODULE_H_
#define LOGGER_BPF_INIT_MODULE_H_

#include "logger/bpf/task.h"

#define PARAMS_SIZE 1024

/* Struct for init_module syscall. */
struct sys_init_module {
  int event_type;
  char params[PARAMS_SIZE];
  enum error errors;
  int ret;
  struct task task;
  unsigned long size;
};

/* Struct for finit_module syscall. */
struct sys_finit_module {
  int event_type;
  char params[PARAMS_SIZE];
  enum error errors;
  int ret;
  struct task task;
  struct path_dentries module;
  int flags;
};

#endif // LOGGER_BPF_INIT_MODULE_H_
