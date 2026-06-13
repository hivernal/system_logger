#ifndef LOGGER_INIT_MODULE_H_
#define LOGGER_INIT_MODULE_H_

#include <stddef.h>

/* Callback function for sys_sock_buf ring buffer. */
int sys_init_module_cb(void* ctx, void* data, size_t data_sz);

#endif  // LOGGER_INIT_MODULE_H_
