#ifndef LOGGER_DELETE_MODULE_H_
#define LOGGER_DELETE_MODULE_H_

#include <stddef.h>

/* Callback function for sys_sock_buf ring buffer. */
int sys_delete_module_cb(void* ctx, void* data, size_t data_sz);

#endif  // LOGGER_DELETE_MODULE_H_
