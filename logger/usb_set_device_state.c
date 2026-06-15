#include "logger/usb_set_device_state.h"

#include <stdio.h>

#include "logger/helpers.h"
#include "logger/bpf/usb_set_device_state.h"

static inline void fprint_kprobe_usb_set_device_state(
    FILE* file, const struct kprobe_usb_set_device_state* data) {
  // const struct hash* hash = data->hash;
  fprintf(file,
          "event: kprobe_usb_set_device_state\nproduct: %s\nserial: "
          "%s\nmanufacturer: %s\nold_state: %d\nnew_state: %d\nvendorid: "
          "0x%x\nproductid: 0x%x\nerrors: 0x%lx\n\n",
          data->product, data->serial, data->manufacturer, data->old_state,
          data->new_state, data->vendorid, data->productid, data->errors);
}

int kprobe_usb_set_device_state_cb(void* ctx UNUSED, void* data,
                                   size_t data_sz UNUSED) {
  /*
  FILE* file = fopen(*(const char**)ctx, "a");
  if (file) {
    fprint_sys_mmap(file, data);
    fclose(file);
  } else {
  */
  fprint_kprobe_usb_set_device_state(stdout, data);
  // }
  return 0;
}
