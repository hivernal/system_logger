#include "logger/mmap.h"

#include <stdio.h>

#include "logger/helpers.h"
#include "logger/bpf/mmap.h"

void fprint_sys_mmap(FILE* file, const struct sys_mmap* sys_mmap) {
  // const struct hash* hash = data->hash;
  fprintf(file,
          "event: sys_mmap\nfilename: %s\nprot: %d\nflags: 0x%x\nret: "
          "%d\nerrors: 0x%lx\n",
          sys_mmap->file.data + sys_mmap->file.offset, sys_mmap->prot,
          sys_mmap->flags, sys_mmap->ret, sys_mmap->errors);
  fprint_task(file, &sys_mmap->task);
  fputc('\n', file);
}

int sys_mmap_cb(void* ctx, void* data, size_t data_sz UNUSED) {
  FILE* file = fopen(*(const char**)ctx, "a");
  if (file) {
    fprint_sys_mmap(file, data);
    fclose(file);
  } else {
    fprint_sys_mmap(stdout, data);
  }
  return 0;
}
