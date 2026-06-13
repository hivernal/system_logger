#include "logger/delete_module.h"
#include "logger/helpers.h"
#include "logger/bpf/delete_module.h"

void fprint_sys_delete_module(
    FILE* file, const struct sys_delete_module* sys_delete_module) {
  fprintf(file,
          "event: sys_delete_module\nmodule: %s\nflags 0x%x\nret: "
          "%d\nerrors: 0x%lx\n",
          sys_delete_module->name, sys_delete_module->flags,
          sys_delete_module->ret, sys_delete_module->errors);
  fprint_task(file, &sys_delete_module->task);
  fputc('\n', file);
}

int sys_delete_module_cb(void* ctx, void* data, size_t data_sz UNUSED) {
  FILE* file = fopen(*(const char**)ctx, "a");
  if (file) {
    fprint_sys_delete_module(file, data);
    fclose(file);
  } else {
    fprint_sys_delete_module(stdout, data);
  }
  return 0;
}
