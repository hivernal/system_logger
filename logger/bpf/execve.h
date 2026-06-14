#ifndef LOGGER_BPF_EXECVE_H_
#define LOGGER_BPF_EXECVE_H_

#include "logger/bpf/task.h"

#define ARG_SIZE 256
#define MAX_ARGS 128
#define ARGS_SIZE ((ARG_SIZE * MAX_ARGS) / 4)
#define LAST_ARG_OFFSET (ARGS_SIZE - ARG_SIZE)

/* Struct for execve syscall. */
struct sys_execve {
  /* A binary executable, or a script name. */
  // char filename[PATH_SIZE];
  struct string filename;
  /* Arguments. */
  char argv[ARGS_SIZE];
  enum error errors;
  /* execve returned value. */
  int ret;
  struct task task;
  enum path_type filename_type;
  int event_type;
  /* Current working directory of the task. */
  struct path_dentries cwd;
};

/* Struct for execveat syscall. */
struct sys_execveat {
  struct sys_execve sys_execve;
  /*
   * The parent directory of the executable file.
   * Can't be the current working directory.
   */
  struct path_dentries dir;
};

#endif // LOGGER_BPF_EXECVE_H_
