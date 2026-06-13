#ifndef LOGGER_SETID_H_
#define LOGGER_SETID_H_

#include <stddef.h>
#include "logger/bpf/feature_probe.h"

/* Callback function for sys_setid_buf ring buffer. */
int sys_setid_cb(void* ctx, void* data, size_t data_sz);

#endif  // LOGGER_SETID_H_
