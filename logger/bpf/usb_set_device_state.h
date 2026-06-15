#ifndef LOGGER_BPF_USB_SET_DEVICE_STATE_H_
#define LOGGER_BPF_USB_SET_DEVICE_STATE_H_

#include "logger/bpf/task.h"

#define PRODUCT_SIZE 32
#define SERIAL_SIZE 32
#define MANUFACTURER_SIZE 32

/* Struct for mmap syscall. */
struct kprobe_usb_set_device_state {
  char product[PRODUCT_SIZE];
  char serial[SERIAL_SIZE];
  char manufacturer[MANUFACTURER_SIZE];
  /* New device state. */
  int new_state;
  /* Old device state. */
  int old_state;
  uint16_t vendorid;
  uint16_t productid;
  enum error errors;
  /* mmap returned value. */
  int ret;
  int event_type;
};

#endif  // LOGGER_BPF_USB_SET_DEVICE_STATE_H_
