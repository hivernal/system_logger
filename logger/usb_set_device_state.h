#ifndef LOGGER_USB_SET_DEVICE_STATE_H_
#define LOGGER_USB_SET_DEVICE_STATE_H_

#include <stddef.h>

/* Callback function for sys_usb_set_device_state_buf ring buffer. */
int kprobe_usb_set_device_state_cb(void* ctx, void* data, size_t data_sz);

#endif  // LOGGER_USB_SET_DEVICE_STATE_H_
