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

/* Capabilities from linux/capabilities.h. */
#define CAP_CHOWN 0
#define CAP_DAC_OVERRIDE 1
#define CAP_DAC_READ_SEARCH 2
#define CAP_FOWNER 3
#define CAP_FSETID 4
#define CAP_KILL 5
#define CAP_SETGID 6
#define CAP_SETUID 7
#define CAP_SETPCAP 8
#define CAP_LINUX_IMMUTABLE 9
#define CAP_NET_BIND_SERVICE 10
#define CAP_NET_BROADCAST 11
#define CAP_NET_ADMIN 12
#define CAP_NET_RAW 13
#define CAP_IPC_LOCK 14
#define CAP_IPC_OWNER 15
#define CAP_SYS_MODULE 16
#define CAP_SYS_RAWIO 17
#define CAP_SYS_CHROOT 18
#define CAP_SYS_PTRACE 19
#define CAP_SYS_PACCT 20
#define CAP_SYS_ADMIN 21
#define CAP_SYS_BOOT 22
#define CAP_SYS_NICE 23
#define CAP_SYS_RESOURCE 24
#define CAP_SYS_TIME 25
#define CAP_SYS_TTY_CONFIG 26
#define CAP_MKNOD 27
#define CAP_LEASE 28
#define CAP_AUDIT_WRITE 29
#define CAP_AUDIT_CONTROL 30
#define CAP_SETFCAP 31
#define CAP_MAC_OVERRIDE 32
#define CAP_MAC_ADMIN 33
#define CAP_SYSLOG 34
#define CAP_WAKE_ALARM 35
#define CAP_BLOCK_SUSPEND 36
#define CAP_AUDIT_READ 37
#define CAP_PERFMON 38
#define CAP_BPF 39
#define CAP_CHECKPOINT_RESTORE 40
#define CAP_FULL 0x1ffffffffff

void check_cap(FILE* file, unsigned long long cap) {
  if (cap == CAP_FULL) return;
#define CHECK_CAP(value)       \
  if (cap & (1ULL << (value))) \
    fprintf(file, " %s", #value);
    // fprintf(file, ", %s (0x%llx)", #value, 1ULL << (value));

  CHECK_CAP(CAP_CHOWN);
  CHECK_CAP(CAP_DAC_OVERRIDE);
  CHECK_CAP(CAP_DAC_READ_SEARCH);
  CHECK_CAP(CAP_FOWNER);
  CHECK_CAP(CAP_FSETID);
  CHECK_CAP(CAP_KILL);
  CHECK_CAP(CAP_SETGID);
  CHECK_CAP(CAP_SETUID);
  CHECK_CAP(CAP_SETPCAP);
  CHECK_CAP(CAP_LINUX_IMMUTABLE);
  CHECK_CAP(CAP_NET_BIND_SERVICE);
  CHECK_CAP(CAP_NET_BROADCAST);
  CHECK_CAP(CAP_NET_ADMIN);
  CHECK_CAP(CAP_NET_RAW);
  CHECK_CAP(CAP_IPC_LOCK);
  CHECK_CAP(CAP_IPC_OWNER);
  CHECK_CAP(CAP_SYS_MODULE);
  CHECK_CAP(CAP_SYS_RAWIO);
  CHECK_CAP(CAP_SYS_CHROOT);
  CHECK_CAP(CAP_SYS_PTRACE);
  CHECK_CAP(CAP_SYS_PACCT);
  CHECK_CAP(CAP_SYS_ADMIN);
  CHECK_CAP(CAP_SYS_BOOT);
  CHECK_CAP(CAP_SYS_NICE);
  CHECK_CAP(CAP_SYS_RESOURCE);
  CHECK_CAP(CAP_SYS_TIME);
  CHECK_CAP(CAP_SYS_TTY_CONFIG);
  CHECK_CAP(CAP_MKNOD);
  CHECK_CAP(CAP_LEASE);
  CHECK_CAP(CAP_AUDIT_WRITE);
  CHECK_CAP(CAP_AUDIT_CONTROL);
  CHECK_CAP(CAP_SETFCAP);
  CHECK_CAP(CAP_MAC_OVERRIDE);
  CHECK_CAP(CAP_MAC_ADMIN);
  CHECK_CAP(CAP_SYSLOG);
  CHECK_CAP(CAP_WAKE_ALARM);
  CHECK_CAP(CAP_BLOCK_SUSPEND);
  CHECK_CAP(CAP_AUDIT_READ);
  CHECK_CAP(CAP_PERFMON);
  CHECK_CAP(CAP_BPF);
  CHECK_CAP(CAP_CHECKPOINT_RESTORE);

#undef CHECK_CAPS
}

void check_caps(FILE* file, const struct task_caps* caps) {
  fprintf(file, "capinh");
  // fprintf(file, "capinh: 0x%llx", caps->inheritable);
  check_cap(file, caps->inheritable);
  fputc('\n', file);

  fprintf(file, "capprm");
  // fprintf(file, "capprm: 0x%llx", caps->permitted);
  check_cap(file, caps->permitted);
  fputc('\n', file);

  fprintf(file, "capeff:");
  // fprintf(file, "capeff: 0x%llx", caps->effective);
  check_cap(file, caps->effective);
  fputc('\n', file);

  fprintf(file, "capbnd:");
  // fprintf(file, "capbnd: 0x%llx", caps->bset);
  check_cap(file, caps->bset);
  fputc('\n', file);

  fprintf(file, "capamb:");
  // fprintf(file, "capamb: 0x%llx", caps->ambient);
  check_cap(file, caps->ambient);
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
  check_caps(file, &sys_execve->caps);
  fputc('\n', file);
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
