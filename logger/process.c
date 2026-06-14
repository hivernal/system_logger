#include "logger/process.h"

#include <stdio.h>

#include "logger/helpers.h"
#include "logger/bpf/process.h"

void fprint_sys_clone(FILE* file, const struct sys_clone* sys_clone) {
  if (sys_clone->event_type == SYS_CLONE) {
    fprintf(file, "event: sys_clone\n");
  } else if (sys_clone->event_type == SYS_CLONE3) {
    fprintf(file, "event: sys_clone3\n");
  } else {
    return;
  }
  fprintf(file, "flags: 0x%lx\nerrors: 0x%lx\n", sys_clone->flags,
          sys_clone->errors);
  fprint_task(file, &sys_clone->task);
  fputc('\n', file);
}

int sys_clone_cb(void* ctx, void* data, size_t data_sz UNUSED) {
  FILE* file = fopen(*(const char**)ctx, "a");
  if (file) {
    fprint_sys_clone(file, data);
    fclose(file);
  } else {
    fprint_sys_clone(stdout, data);
  }
  return 0;
}

void fprint_sched_process_exit(
    FILE* file, const struct sched_process_exit* sched_process_exit) {
  fprintf(file,
          "event: sched_process_exit\nexit_code: 0x%x\n"
          "group_dead: %d\nerrors: 0x%lx\n",
          sched_process_exit->exit_code, sched_process_exit->group_dead,
          sched_process_exit->errors);
  fprint_task(file, &sched_process_exit->task);
  fputc('\n', file);
}

int sched_process_exit_cb(void* ctx, void* data, size_t data_sz UNUSED) {
  FILE* file = fopen(*(const char**)ctx, "a");
  if (file) {
    fprint_sched_process_exit(file, data);
    fclose(file);
  } else {
    fprint_sched_process_exit(stdout, data);
  }
  return 0;
}
