#ifndef LOGGER_HELPERS_H_
#define LOGGER_HELPERS_H_

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <pwd.h>

#include "logger/bpf/task.h"
#include "logger/bpf/feature_probe.h"
#include "logger/list.h"

#define UNUSED __attribute__((unused))

/* Prints substring to the file. */
static inline void fprint_substr(FILE* file, const char* start,
                                 const char* end) {
  for (; start <= end; ++start) fputc(*start, file);
}

static inline void fprint_task_cred(FILE* file, const struct task* task) {
  const struct task_cred* task_cred = &task->cred;
  // uid_t ids[sizeof(*task_cred) / sizeof(task_cred->uid) + 1];
  // struct passwd* getpwnam();
  fprintf(file,
          "loginuid: %u\nuid: %u\ngid: %u\nsuid: %u\nsgid: "
          "%u\neuid: %u\negid: %u\nfsuid: "
          "%u\nfsgid: %u\n",
          task->loginuid, task_cred->uid, task_cred->gid, task_cred->suid,
          task_cred->sgid, task_cred->euid, task_cred->egid, task_cred->fsuid,
          task_cred->fsgid);
}

static inline void fprint_task_mm(FILE* file, const struct task_mm* mm) {
  fprintf(file, "mm_exe_file: %s\nmm_argv: ",
          mm->exe_file.data + (mm->exe_file.offset & (PATH_SIZE - 1)));
  for (int i = 0; i < mm->argv_size - 1; ++i) {
    if (mm->argv[i] == '\0') {
      fputc(' ', file);
      continue;
    }
    fputc(mm->argv[i], file);
  }
  fputc('\n', file);
}

static inline void fprint_task_namespaces(FILE* file,
                                          const struct task_namespaces* ns) {
  const struct task_mnt_ns* mnt_ns = &ns->mnt_ns;
  fprintf(file, "mnt_ns_id: %u\n", mnt_ns->inum);
  const struct task_pid_ns* pid_ns = &ns->pid_ns;
  fprintf(file,
          "pid_ns_id: %u\npid_ns_level: %u\n"
          "pid_ns_child_reaper_pid: %d\n",
          pid_ns->inum, pid_ns->level, pid_ns->child_reaper_pid);
  const struct task_uts_ns* uts_ns = &ns->uts_ns;
  fprintf(file,
          "uts_ns_id: %u\n"
          "uts_ns_sysname: %s\n"
          "uts_ns_nodename: %s\n"
          "uts_ns_release: %s\n"
          "uts_ns_version: %s\n"
          "uts_ns_machine: %s\n",
          uts_ns->inum, uts_ns->sysname, uts_ns->nodename, uts_ns->release,
          uts_ns->version, uts_ns->machine);
  const struct task_user_ns* user_ns = &ns->user_ns;
  fprintf(file,
          "user_ns_id: %u\nuser_ns_level: %u\n",
          user_ns->inum, user_ns->level);
}

/* Prints task struct to the file. */
static inline void fprint_task(FILE* file, const struct task* task) {
  fprintf(file,
          "time: %lu\npid: %d\nppid: %d\ntgid %d\ncomm: "
          "%s\nsessionid: %u\n",
          task->time_nsec, task->pid, task->ppid, task->tgid, task->comm,
          task->sessionid);
  fprint_task_cred(file, task);
  fprint_task_mm(file, &task->mm);
  fprint_task_namespaces(file, &task->ns);
}

static inline void fprint_hex(FILE* file, const unsigned char* data,
                              size_t len) {
  for (size_t i = 0; i < len; ++i) fprintf(file, "%02x", data[i]);
}

#define print_task(task) fprint_task(stdout, task)
#define print_substr(start, end) fprint_substr(stdout, start, end)

/* Prints filename relative to path_dentries to the file. */
void fprint_relative_filename(FILE* file, const char* filename,
                              const struct path_dentries* path_dentries);
void fprint_full_path(FILE* file, const struct string* filename,
                      const struct path_dentries* dir);
#define print_relative_filename(filename, path_dentries) \
  fprint_relative_filename(stdout, filename, path_dentries)

/*
void fill_relative_filename(char* buffer_start, const char* buffer_end,
                            const char* filename,
                            const struct path_dentries* path_dentries);
*/

struct dentry_range {
  struct list_head node;
  const char* start;
  const char* end;
};

int dentry_ranges_init(struct list_head* list, const char* filename,
                       const struct path_dentries* path_dentries);
void dentry_ranges_delete(struct list_head* list);
void fprint_dentry_ranges(FILE* file, const struct list_head* list);

#endif  //  LOGGER_HELPERS_H_
