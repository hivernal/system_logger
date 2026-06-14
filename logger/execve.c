#include "logger/execve.h"

#include <stdio.h>
#include <string.h>

#include "logger/helpers.h"
#include "logger/bpf/execve.h"

static inline void fprint_hash_filename(FILE* file, const char* filename,
                                        const struct hash* hash) {
  if (!hash) return;
  unsigned char* digest = hash_filename(filename, hash);
  if (!digest) return;
  fprintf(file, "\n%s: ", EVP_MD_get0_description(hash->md));
  fprint_hex(file, digest, (size_t)hash->len);
  free(digest);
}

static inline void fprint_hash_dir_filename(FILE* file, const char* dirname,
                                            const char* filename,
                                            const struct hash* hash) {
  if (!hash) return;
  unsigned char* digest = hash_dir_filename(dirname, filename, hash);
  if (!digest) return;
  fprintf(file, "\n%s: ", EVP_MD_get0_description(hash->md));
  fprint_hex(file, digest, (size_t)hash->len);
  free(digest);
}

void fprint_sys_execve(FILE* file, const struct sys_execve* sys_execve,
                       const struct sys_execve_cb_data* data) {
  const struct hash* hash = data->hash;
  if (sys_execve->event_type == SYS_EXECVE) {
    fprintf(file, "event: sys_execve\n");
  } else if (sys_execve->event_type == SYS_EXECVEAT) {
    fprintf(file, "event: sys_execveat\n");
  } else {
    return;
  }
  fprintf(file, "filename: ");
  if (sys_execve->filename_type == PATH_ABSOLUTE) {
    fprintf(file, "%s", sys_execve->filename.str);
    fprint_hash_filename(file, sys_execve->filename.str, hash);
  } else if (sys_execve->filename_type == PATH_RELATIVE_CWD) {
    fprint_full_path(file, &sys_execve->filename, &sys_execve->cwd);
    fprint_hash_dir_filename(file,
                             sys_execve->cwd.data + sys_execve->cwd.offset,
                             sys_execve->filename.str, hash);
  } else if (sys_execve->filename_type == PATH_RELATIVE_FD) {
    const struct sys_execveat* sys_execveat = (struct sys_execveat*)sys_execve;
    fprint_full_path(file, &sys_execve->filename, &sys_execveat->dir);
    fprint_hash_dir_filename(file,
                             sys_execveat->dir.data + sys_execveat->dir.offset,
                             sys_execve->filename.str, hash);
  }
  fprintf(file, "\nargv: %s\ncwd: %s\nret: %d\nerrors: 0x%lx\n",
          sys_execve->argv, sys_execve->cwd.data + sys_execve->cwd.offset,
          sys_execve->ret, sys_execve->errors);
  fprint_task(file, &sys_execve->task);
  fputc('\n', file);
}

int sys_execve_cb(void* ctx, void* data, size_t data_sz UNUSED) {
  FILE* file = fopen(((struct sys_execve_cb_data*)ctx)->filename, "a");
  if (file) {
    fprint_sys_execve(file, data, ctx);
    fclose(file);
  } else {
    fprint_sys_execve(stdout, data, ctx);
  }
  return 0;
}
