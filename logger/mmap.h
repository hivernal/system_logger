#ifndef LOGGER_MMAP_H_
#define LOGGER_MMAP_H_

#include <stddef.h>
#include <string.h>

#include "logger/hash.h"
#include "logger/bpf/feature_probe.h"

/* Callback function for sys_mmap_buf ring buffer. */
int sys_mmap_cb(void* ctx, void* data, size_t data_sz);

#endif  // LOGGER_MMAP_H_
