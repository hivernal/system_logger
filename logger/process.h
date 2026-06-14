#ifndef LOGGER_PROCESS_H_
#define LOGGER_PROCESS_H_

#include <stddef.h>

#include "logger/hash.h"
#include "logger/bpf/feature_probe.h"

/* Callback function for sys_clone_buf ring buffer. */
int sys_clone_cb(void* ctx, void* data, size_t data_sz);

/* Callback function for sched_process_exit_buf ring buffer. */
int sched_process_exit_cb(void* ctx, void* data, size_t data_sz);

#endif  // LOGGER_PROCESS_H_
