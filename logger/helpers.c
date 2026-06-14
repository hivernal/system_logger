#include "logger/helpers.h"
#include "logger/list.h"

#include <stddef.h>

#define dentry_range_init() malloc(sizeof(struct dentry_range))
#define dentry_range_delete(ptr) free(ptr)

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

const char* find_parent_dentry(const struct path_dentries* filename,
                               int parent) {
  const char* const filename_start = filename->data + filename->offset;
  const char* sptr = filename->data + sizeof(filename->data) - 2;
  if (parent <= 0) return sptr;
  if (*sptr == '/') --sptr;
  for (; parent > 0 && sptr >= filename_start; --sptr) {
    if (*sptr == '/') --parent;
  }
  return ++sptr;
}

char* resolve_full_path(const struct path_dentries* cwd,
                        const struct string* filename, char* buffer,
                        size_t buffer_size) {
  char* dptr = buffer + buffer_size - 1;
  const char* sptr = filename->str + filename->len - 1;
  int parent = 0;
  for (; sptr >= filename->str && dptr >= buffer; --sptr) {
    if (*sptr == '/') {
      if (sptr - 1 >= filename->str && *(sptr - 1) == '.') {
        --sptr;
        if (sptr - 1 >= filename->str && *(sptr - 1) == '.') {
          ++parent;
          --sptr;
        }
        continue;
      } else if (sptr - 1 >= filename->str && *(sptr - 1) == '/') {
        continue;
      } else if (parent > 0) {
        for (; sptr - 1 >= filename->str && *(sptr - 1) != '/'; --sptr);
        --parent;
        continue;
      }
    }
    *dptr = *sptr;
    --dptr;
  }
  if (filename->str[0] == '/') {
    *dptr = '/';
    return dptr;
  }
  const char* cwd_end = find_parent_dentry(cwd, parent);
  const char* const cwd_start = cwd->data + cwd->offset;
  ptrdiff_t cwd_size = cwd_end - cwd_start;
  if (dptr - cwd_size < buffer) goto inc_dptr;
  for (; cwd_end >= cwd_start; --cwd_end, --dptr) *dptr = *cwd_end;
inc_dptr:
  ++dptr;
  return dptr;
}

void fprint_full_path(FILE* file, const struct string* filename,
                      const struct path_dentries* dir) {
  if (!filename || filename->str[0] == '\0') return;
  char buffer[sizeof(filename->str)];
  fputs(resolve_full_path(dir, filename, buffer, sizeof(buffer)), file);
}

/* Gets const char pointers to each filename entry. */
int get_filename_cptrs(struct list_head* list, const char* filename) {
  int parent_dir_index = 0;
  while (*filename) {
    if (*filename == '.') {
      /* If current directory (./). */
      if (*(filename + 1) == '/') {
        filename += 2;
        continue;
        /* If parent directory (../). */
      } else if (*(filename + 1) == '.') {
        /* If list is not empty. */
        if (list != list->next) {
          struct dentry_range* p =
              list_last_entry(list, struct dentry_range, node);
          list_delete_tail(list);
          dentry_range_delete(p);
        } else {
          ++parent_dir_index;
        }
        filename += 3;
        continue;
      }
    }
    struct dentry_range* offsets = dentry_range_init();
    if (!offsets) return ~parent_dir_index + 1;
    offsets->start = filename;
    for (; *(filename + 1) && *filename != '/'; ++filename);
    offsets->end = filename;
    ++filename;
    list_add_tail(&offsets->node, list);
  }
  return parent_dir_index;
}

const char* get_dir_cptr(const struct path_dentries* path_dentries,
                         int parent_dir_index) {
  /* The last symbol before '\0'. */
  const char* cptr = path_dentries->data + sizeof(path_dentries->data) - 2;
  if (!parent_dir_index) return cptr;
  --cptr;
  const char* const start = path_dentries->data + path_dentries->offset;
  for (; cptr > start; --cptr) {
    if (*cptr == '/' && !(--parent_dir_index)) break;
  }
  return cptr;
}

int dentry_ranges_init(struct list_head* list, const char* filename,
                       const struct path_dentries* path_dentries) {
  int parent_dir_index = get_filename_cptrs(list, filename);
  if (parent_dir_index < 0) return -1;
  struct dentry_range* dir = dentry_range_init();
  dir->start = path_dentries->data + path_dentries->offset;
  dir->end = get_dir_cptr(path_dentries, parent_dir_index);
  list_add(&dir->node, list);
  return 0;
};

void dentry_ranges_delete(struct list_head* list) {
  struct dentry_range *c, *n;
  list_for_each_entry_safe(c, n, list, node) { dentry_range_delete(c); }
}

void fprint_dentry_ranges(FILE* file, const struct list_head* list) {
  const struct dentry_range* c;
  list_for_each_entry(c, list, node) { fprint_substr(file, c->start, c->end); }
}

void fprint_relative_filename(FILE* file, const char* filename,
                              const struct path_dentries* path_dentries) {
  if (!*filename) return;
  struct list_head list = LIST_HEAD_INIT(list);
  int parent_dir_index = get_filename_cptrs(&list, filename);
  if (parent_dir_index < 0) return;
  const char* cptr = get_dir_cptr(path_dentries, parent_dir_index);
  fprint_substr(file, path_dentries->data + path_dentries->offset, cptr);
  struct dentry_range* c;
  list_for_each_entry(c, &list, node) { fprint_substr(file, c->start, c->end); }
  dentry_ranges_delete(&list);
}

/*
#include <string.h>

char* fill_substr(char* buffer_start, const char* buffer_end, const char* start,
                  const char* end) {
  size_t res = (size_t)(end - start + 1);
  if (buffer_start + res > buffer_end) return buffer_start;
  memcpy(buffer_start, start, res);
  return buffer_start + res;
};

void fill_relative_filename(char* buffer_start, const char* buffer_end,
                            const char* filename,
                            const struct path_dentries* path_dentries) {
  if (!*filename) return;
  struct list_head list = LIST_HEAD_INIT(list);
  int parent_dir_index = get_filename_cptrs(&list, filename);
  if (parent_dir_index < 0) return;
  const char* cptr = get_dir_cptr(path_dentries, parent_dir_index);
  buffer_start = fill_substr(buffer_start, buffer_end,
                             path_dentries->data + path_dentries->offset, cptr);
  struct dentry_range* c;
  list_for_each_entry(c, &list, node) {
    buffer_start = fill_substr(buffer_start, buffer_end, c->start, c->end);
  }
  *buffer_start = 0;
  dentry_ranges_delete(&list);
}
*/
