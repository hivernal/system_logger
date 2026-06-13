#include "logger/init_module.h"
#include "logger/helpers.h"
#include "logger/bpf/init_module.h"

void __fprint_sys_init_module(FILE* file,
                              const struct sys_init_module* sys_init_module) {
  fprintf(file,
          "event: sys_init_module\nsize: %lu\nparams: %s\nret: %d\nerrors: "
          "0x%lx\n",
          sys_init_module->size, sys_init_module->params, sys_init_module->ret,
          sys_init_module->errors);
}

void fprint_sys_finit_module(FILE* file,
                             const struct sys_finit_module* sys_finit_module) {
  fprintf(file,
          "event: sys_finit_module\nmodule: %s\nparams: %s\nflags 0x%x\nret: "
          "%d\nerrors: "
          "0x%lx\n",
          sys_finit_module->module.data + sys_finit_module->module.offset,
          sys_finit_module->params, sys_finit_module->flags,
          sys_finit_module->ret, sys_finit_module->errors);
}

void fprint_sys_init_module(FILE* file,
                            const struct sys_init_module* sys_init_module) {
  if (sys_init_module->event_type == SYS_INIT_MODULE) {
    __fprint_sys_init_module(file, sys_init_module);
  } else if (sys_init_module->event_type == SYS_FINIT_MODULE) {
    fprint_sys_finit_module(file,
                            (const struct sys_finit_module*)sys_init_module);
  } else {
    return;
  }
  fprint_task(file, &sys_init_module->task);
  fputc('\n', file);
}

int sys_init_module_cb(void* ctx, void* data, size_t data_sz UNUSED) {
  FILE* file = fopen(*(const char**)ctx, "a");
  if (file) {
    fprint_sys_init_module(file, data);
    fclose(file);
  } else {
    fprint_sys_init_module(stdout, data);
  }
  return 0;
}
