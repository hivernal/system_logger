#ifndef LOGGER_SOCK_H_
#define LOGGER_SOCK_H_

#include <stddef.h>
#include "logger/bpf/feature_probe.h"

/* Callback function for sys_sock_buf ring buffer. */
int sys_sock_cb(void* ctx, void* data, size_t data_sz);

#endif  // LOGGER_SOCK_H_
