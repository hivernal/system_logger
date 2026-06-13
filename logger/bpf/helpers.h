#ifndef LOGGER_BPF_HELPERS_H_
#define LOGGER_BPF_HELPERS_H_

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wmissing-declarations"
#include "logger/bpf/vmlinux.h"
#pragma clang diagnostic pop

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#include "logger/bpf/task.h"

#define FUNC_INLINE static inline __attribute__((always_inline))
#define UNUSED __attribute__((unused))
#define AT_FDCWD -100

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define RINGBUF_BODY(size)            \
  __uint(type, BPF_MAP_TYPE_RINGBUF); \
  __uint(max_entries, size)

#define PERF_EVENT_ARRAY_BODY                  \
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY); \
  __uint(key_size, sizeof(u32));               \
  __uint(value_size, sizeof(u32))

#define RINGBUF_DECL(name, size) \
  struct {                       \
    RINGBUF_BODY(size);          \
  } name SEC(".maps");

#define PERF_EVENT_ARRAY_DECL(name) \
  struct {                          \
    PERF_EVENT_BODY;                \
  } name SEC(".maps");

FUNC_INLINE int fill_task_user_ns(const struct task_struct* task,
                                  struct task_user_ns* user_ns,
                                  enum error* errors) {
  const struct user_namespace* user_namespace;
  if (BPF_CORE_READ_INTO(&user_namespace, task, real_cred, user_ns)) {
    *errors |= ECORE_READ;
    return FAILURE_CODE;
  }
  if (bpf_core_read(&user_ns->level, sizeof(user_ns->level),
                    &user_namespace->level) < 0) {
    *errors |= ECORE_READ;
    return FAILURE_CODE;
  }
  if (BPF_CORE_READ_INTO(&user_ns->inum, user_namespace, ns.inum) < 0) {
    *errors |= ECORE_READ;
    return FAILURE_CODE;
  }
  return SUCCESS_CODE;
}

FUNC_INLINE int fill_new_utsname(const struct new_utsname* name,
                                 struct task_uts_ns* uts_ns,
                                 enum error* errors) {
  uts_ns->sysname[0] = '\0';
  uts_ns->nodename[0] = '\0';
  uts_ns->release[0] = '\0';
  uts_ns->version[0] = '\0';
  uts_ns->machine[0] = '\0';
  if (bpf_core_read_str(&uts_ns->sysname, sizeof(uts_ns->sysname),
                        &name->sysname) < 0 ||
      bpf_core_read_str(&uts_ns->nodename, sizeof(uts_ns->nodename),
                        &name->nodename) < 0 ||
      bpf_core_read_str(&uts_ns->release, sizeof(uts_ns->release),
                        &name->release) < 0 ||
      bpf_core_read_str(&uts_ns->version, sizeof(uts_ns->version),
                        &name->version) < 0 ||
      bpf_core_read_str(&uts_ns->machine, sizeof(uts_ns->machine),
                        &name->machine) < 0) {
    *errors |= ECORE_READ_STR;
    return FAILURE_CODE;
  }
  return SUCCESS_CODE;
}

FUNC_INLINE int fill_task_uts_ns(const struct nsproxy* nsproxy,
                                 struct task_uts_ns* uts_ns,
                                 enum error* errors) {
  uts_ns->inum = 0;
  const struct uts_namespace* uts_namespace;
  if (BPF_CORE_READ_INTO(&uts_namespace, nsproxy, uts_ns)) {
    *errors |= ECORE_READ;
    return FAILURE_CODE;
  }
  if (BPF_CORE_READ_INTO(&uts_ns->inum, uts_namespace, ns.inum)) {
    *errors |= ECORE_READ;
    return FAILURE_CODE;
  }
  if (fill_new_utsname(&uts_namespace->name, uts_ns, errors)) {
    *errors |= EFILL_NEW_UTSNAME;
    return FAILURE_CODE;
  }
  return SUCCESS_CODE;
}

FUNC_INLINE int fill_task_mnt_ns(const struct nsproxy* nsproxy,
                                 struct task_mnt_ns* mnt_ns,
                                 enum error* errors) {
  mnt_ns->inum = 0;
  if (BPF_CORE_READ_INTO(&mnt_ns->inum, nsproxy, mnt_ns, ns.inum)) {
    *errors |= ECORE_READ;
    return FAILURE_CODE;
  }
  return SUCCESS_CODE;
}

FUNC_INLINE int fill_task_pid_ns(const struct nsproxy* nsproxy,
                                 struct task_pid_ns* pid_ns,
                                 enum error* errors) {
  pid_ns->inum = 0;
  pid_ns->level = 0;
  pid_ns->child_reaper_pid = -1;
  const struct pid_namespace* pid_namespace;
  if (bpf_core_read(&pid_namespace, sizeof(pid_namespace),
                    &nsproxy->pid_ns_for_children) < 0) {
    *errors |= ECORE_READ;
    return FAILURE_CODE;
  }

  if (BPF_CORE_READ_INTO(&pid_ns->inum, pid_namespace, ns.inum) ||
      BPF_CORE_READ_INTO(&pid_ns->level, pid_namespace, level) ||
      BPF_CORE_READ_INTO(&pid_ns->child_reaper_pid, pid_namespace, child_reaper,
                         pid)) {
    *errors |= ECORE_READ;
    return FAILURE_CODE;
  }

  return SUCCESS_CODE;
}

FUNC_INLINE int fill_task_namespaces(const struct task_struct* task,
                                     struct task_namespaces* ns,
                                     enum error* errors) {
  struct nsproxy* nsproxy;
  if (bpf_core_read(&nsproxy, sizeof(nsproxy), &task->nsproxy) < 0) {
    *errors |= ECORE_READ;
    return FAILURE_CODE;
  }
  if (fill_task_mnt_ns(nsproxy, &ns->mnt_ns, errors) == FAILURE_CODE) {
    *errors |= EFILL_MOUNT_NAMESPACE;
    return FAILURE_CODE;
  }
  if (fill_task_pid_ns(nsproxy, &ns->pid_ns, errors) == FAILURE_CODE) {
    *errors |= EFILL_PID_NAMESPACE;
    return FAILURE_CODE;
  }
  if (fill_task_uts_ns(nsproxy, &ns->uts_ns, errors) == FAILURE_CODE) {
    *errors |= EFILL_UTS_NAMESPACE;
    return FAILURE_CODE;
  }
  if (fill_task_user_ns(task, &ns->user_ns, errors) == FAILURE_CODE) {
    *errors |= EFILL_USER_NAMESPACE;
    return FAILURE_CODE;
  }
  return SUCCESS_CODE;
}

FUNC_INLINE int fill_task_cred(struct task_cred* task_cred,
                               const struct task_struct* task,
                               enum error* errors) {
  if (!task_cred || !task) {
    *errors |= ENULL_ARG;
    return FAILURE_CODE;
  }
  const struct cred* real_cred;
  long ret = bpf_core_read(&real_cred, sizeof(real_cred), &task->real_cred);
  if (ret < 0) {
    *errors |= ECORE_READ;
    return FAILURE_CODE;
  }
  ret = bpf_core_read(task_cred, sizeof(*task_cred), &real_cred->uid);
  if (ret < 0) {
    *errors |= ECORE_READ;
    return FAILURE_CODE;
  }
  return SUCCESS_CODE;
}

FUNC_INLINE int read_path(const struct path* path,
                          struct path_dentries* path_dentries, int is_dir,
                          enum error* errors) {
  path_dentries->data[0] = '\0';
  path_dentries->offset = 0;
  const struct dentry *dentry = NULL, *dentry_parent = NULL, *mnt_root = NULL;
  long ret = bpf_core_read(&dentry, sizeof(dentry), &path->dentry);
  if (ret < 0) {
    *errors |= ECORE_READ;
    return FAILURE_CODE;
  }
  const unsigned size = sizeof(path_dentries->data);
  unsigned offset = size - (is_dir ? 1 : 0);
  struct qstr d_name;
  unsigned len;

  const struct vfsmount* vfsmnt = NULL;
  ret = bpf_core_read(&vfsmnt, sizeof(vfsmnt), &path->mnt);
  if (ret < 0) {
    *errors |= ECORE_READ;
    return FAILURE_CODE;
  }
  struct mount *mnt = NULL, *mnt_parent = NULL;
  mnt = container_of(vfsmnt, struct mount, mnt);

  for (int i = 0; i < MAX_DENTRIES; ++i) {
    if (bpf_core_read(&mnt_root, sizeof(mnt_root), &vfsmnt->mnt_root) < 0 ||
        bpf_core_read(&dentry_parent, sizeof(dentry_parent),
                      &dentry->d_parent) < 0) {
      *errors |= ECORE_READ;
      return FAILURE_CODE;
    }
    if (dentry == mnt_root || dentry == dentry_parent) {
      if (dentry != mnt_root) break;
      if (mnt != mnt_parent) {
        // We reached root, but not global root - continue with mount point path
        if (bpf_core_read(&dentry, sizeof(dentry), &mnt->mnt_mountpoint) < 0 ||
            bpf_core_read(&mnt, sizeof(mnt), &mnt->mnt_parent) < 0 ||
            bpf_core_read(&mnt_parent, sizeof(mnt_parent), &mnt->mnt_parent) <
                0) {
          *errors |= ECORE_READ;
          return FAILURE_CODE;
        }
        vfsmnt = &mnt->mnt;
        continue;
      }
      break;
    }
    ret = bpf_core_read(&d_name, sizeof(d_name), &dentry->d_name);
    if (ret < 0) {
      *errors |= ECORE_READ;
      return FAILURE_CODE;
    }
    len = (d_name.len + 1) & (DENTRY_NAME_SIZE - 1);
    if (offset - len > size) {
      *errors |= ENAME_TOO_LONG;
      return FAILURE_CODE;
    }
    ret = bpf_core_read_str(&path_dentries->data[offset - len], len,
                            (const char*)d_name.name);
    if (ret < 0) {
      *errors |= ECORE_READ_STR;
      return FAILURE_CODE;
    }
    if (offset - 1 < size - 1) path_dentries->data[offset - 1] = '/';
    offset -= len;
    dentry = dentry_parent;
  }
  path_dentries->data[--offset & (size - 1)] = '/';
  path_dentries->data[size - 1] = '\0';
  path_dentries->offset = offset;
  return (int)offset;
}

FUNC_INLINE int fill_task_mm(const struct task_struct* current_task,
                             struct task_mm* mm, enum error* errors) {
  mm->argv_size = 0;
  mm->argv[0] = '\0';
  const struct mm_struct* task_mm;
  if (bpf_core_read(&task_mm, sizeof(task_mm), &current_task->mm) < 0) {
    *errors |= ECORE_READ;
    return FAILURE_CODE;
  }
  const struct file* exe_file;
  if (bpf_core_read(&exe_file, sizeof(exe_file), &task_mm->exe_file) < 0) {
    *errors |= ECORE_READ;
    return FAILURE_CODE;
  }
  const struct path* path = &exe_file->f_path;
  if (read_path(path, &mm->exe_file, 0, errors) < 0) {
    *errors |= EREAD_PATH;
    return FAILURE_CODE;
  }
  unsigned long arg_start, arg_end;
  if (bpf_core_read(&arg_start, sizeof(arg_start), &task_mm->arg_start) < 0 ||
      bpf_core_read(&arg_end, sizeof(arg_end), &task_mm->arg_end) < 0) {
    *errors |= ECORE_READ;
    return FAILURE_CODE;
  }
  unsigned long len = arg_end - arg_start;
  len &= sizeof(mm->argv) - 1;
  long ret =
      bpf_core_read_user(&mm->argv, (unsigned int)len, (const void*)arg_start);
  if (ret < 0) {
    *errors |= ECORE_READ_STR;
    return FAILURE_CODE;
  }
  mm->argv_size = (int)len;
  return SUCCESS_CODE;
}

/*
 * Fills task structure (tgid, pid, ppid, time_nsec, comm, loginuid, sessionid).
 */
FUNC_INLINE int fill_task(struct task* task, enum error* errors) {
  const struct task_struct* current_task =
      (struct task_struct*)bpf_get_current_task();
  if (!current_task) {
    *errors |= EGET_CURRENT_TASK;
    return FAILURE_CODE;
  }
  enum error local_errors = SUCCESS_CODE;
  const struct task_struct* parent_task;
  task->time_nsec = bpf_ktime_get_tai_ns();
  long ret = bpf_core_read(&task->pid, sizeof(task->pid), &current_task->pid);
  ret |= bpf_core_read(&task->tgid, sizeof(task->tgid), &current_task->tgid);
  ret |= bpf_core_read(&parent_task, sizeof(parent_task),
                       &current_task->real_parent);
  ret |= bpf_core_read(&task->ppid, sizeof(task->ppid), &parent_task->pid);
  ret |= bpf_core_read(&task->sessionid, sizeof(task->sessionid),
                       &current_task->sessionid);
  ret |= bpf_core_read(&task->loginuid, sizeof(task->loginuid),
                       &current_task->loginuid);
  if (ret < 0) local_errors |= ECORE_READ;
  if (fill_task_cred(&task->cred, current_task, errors) == FAILURE_CODE)
    local_errors |= EFILL_TASK_CRED;
  if (fill_task_mm(current_task, &task->mm, errors) == FAILURE_CODE)
    local_errors |= EFILL_TASK_MM_DATA;
  if (fill_task_namespaces(current_task, &task->ns, errors) == FAILURE_CODE)
    local_errors |= EFILL_TASK_NAMESPACES;
  if (bpf_get_current_comm(&task->comm, TASK_COMM_LEN) < 0)
    local_errors |= EGET_CURRENT_COMM;
  *errors |= local_errors;
  if (local_errors) return FAILURE_CODE;
  return SUCCESS_CODE;
}

/*
 * Gets file structure from file descriptor fd. Returns 0 on success, other on
 * errors.
 */
FUNC_INLINE int get_file_from_fd(int file_fd, const struct file** file,
                                 enum error* errors) {
  if (file_fd == AT_FDCWD) {
    *errors |= EAT_FDCWD;
    return FAILURE_CODE;
  }
  const struct task_struct* task = (struct task_struct*)bpf_get_current_task();
  if (!task) {
    *errors |= EGET_CURRENT_TASK;
    return FAILURE_CODE;
  }
  const struct file** fds;
  if (BPF_CORE_READ_INTO(&fds, task, files, fdt, fd)) {
    *errors |= ECORE_READ;
    return FAILURE_CODE;
  }
  if (bpf_probe_read_kernel(file, sizeof(*file), &fds[file_fd]) < 0) {
    *errors |= EPROBE_READ_KERNEL;
    return FAILURE_CODE;
  }
  return SUCCESS_CODE;
}

/*
 * Gets path structure from file descriptor fd.
 * Returns 0 on success and negative on errors.
 */
FUNC_INLINE int get_path_from_fd(int fd, const struct path** path,
                                 enum error* errors) {
  if (!path) {
    *errors |= ENULL_ARG;
    return FAILURE_CODE;
  }
  const struct file* file;
  if (get_file_from_fd(fd, &file, errors) == FAILURE_CODE) {
    *errors |= EGET_FILE_FROM_FD;
    return FAILURE_CODE;
  }
  *path = &file->f_path;
  // ret = (int)bpf_core_read(path, sizeof(struct path), &file->f_path);
  // if (ret < 0) return -EBPF_PROBE_READ_KERNEL;
  return 0;
}

/*
 * Gets path structure pwd from current task. Returns 0 on success, other on
 * errors.
 */
FUNC_INLINE int get_task_pwd(const struct path** path, enum error* errors) {
  const struct task_struct* task = (struct task_struct*)bpf_get_current_task();
  if (!task) {
    *errors |= EGET_CURRENT_TASK;
    return FAILURE_CODE;
  }
  struct fs_struct* fs;
  if (bpf_core_read(&fs, sizeof(fs), &task->fs) < 0) {
    *errors |= ECORE_READ;
    return FAILURE_CODE;
  }
  *path = &fs->pwd;
  return SUCCESS_CODE;
}

FUNC_INLINE int read_fd_path(int fd, struct path_dentries* path_dentries,
                             int is_dir, enum error* errors) {
  const struct path* path;
  if (fd == AT_FDCWD && get_task_pwd(&path, errors) == FAILURE_CODE) {
    *errors |= EGET_TASK_PWD;
    return FAILURE_CODE;
  } else if (fd != AT_FDCWD &&
             get_path_from_fd(fd, &path, errors) == FAILURE_CODE) {
    *errors |= EGET_PATH_FROM_FD;
    return FAILURE_CODE;
  }
  int ret = read_path(path, path_dentries, is_dir, errors);
  if (ret == FAILURE_CODE) {
    *errors |= EREAD_PATH;
    return FAILURE_CODE;
  }
  return ret;
}

FUNC_INLINE int read_cwd(struct path_dentries* path_dentries,
                         enum error* errors) {
  const struct path* path;
  if (get_task_pwd(&path, errors) == FAILURE_CODE) {
    *errors |= EGET_TASK_PWD;
    return FAILURE_CODE;
  }
  int ret = read_path(path, path_dentries, 1, errors);
  if (ret == FAILURE_CODE) {
    *errors |= EREAD_PATH;
    return FAILURE_CODE;
  }
  return ret;
}

#endif  // LOGGER_BPF_HELPERS_H_
