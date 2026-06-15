#include "logger/bpf/helpers.h"
#include "logger/bpf/usb_set_device_state.h"

#include <bpf/bpf_tracing.h>

/* Buffer for sending kprobe_usb_set_device_state data to userspace. */
struct {
  RINGBUF_BODY(NPROC * sizeof(struct kprobe_usb_set_device_state));
} kprobe_usb_set_device_state_buf SEC(".maps");

SEC("kprobe/usb_set_device_state")
int BPF_KPROBE(usb_set_device_state, struct usb_device* udev UNUSED,
               unsigned long long new_state UNUSED) {
  /* Silence unused variable warning. */
  (void)ctx;

  struct kprobe_usb_set_device_state* data =
      bpf_ringbuf_reserve(&kprobe_usb_set_device_state_buf, sizeof(*data), 0);
  if (!data) return 1;
  data->errors = 0;
  data->product[0] = '\0';
  data->serial[0] = '\0';
  data->manufacturer[0] = '\0';
  data->productid = 0;
  data->vendorid = 0;
  data->new_state = (int)new_state;
  data->old_state = -1;

  const char* cptr;
  long ret = bpf_core_read(&cptr, sizeof(cptr), &udev->product);
  if (ret < 0) data->errors |= ECORE_READ;
  ret = bpf_probe_read_kernel_str(&data->product, sizeof(data->product), cptr);
  if (ret < 0) data->errors |= EPROBE_READ_KERNEL_STR;

  ret = bpf_core_read(&cptr, sizeof(cptr), &udev->manufacturer);
  if (ret < 0) data->errors |= ECORE_READ;
  ret = bpf_probe_read_kernel_str(&data->manufacturer,
                                  sizeof(data->manufacturer), cptr);
  if (ret < 0) data->errors |= EPROBE_READ_KERNEL_STR;

  ret = bpf_core_read(&cptr, sizeof(cptr), &udev->serial);
  if (ret < 0) data->errors |= ECORE_READ;
  ret = bpf_probe_read_kernel_str(&data->serial, sizeof(data->serial), cptr);
  if (ret < 0) data->errors |= EPROBE_READ_KERNEL_STR;

  ret = bpf_core_read(&data->old_state, sizeof(data->old_state), &udev->state);
  if (ret < 0) data->errors |= ECORE_READ;

  ret = bpf_core_read(&data->productid, sizeof(data->productid),
                      &udev->descriptor.idProduct);
  if (ret < 0) data->errors |= ECORE_READ;
  ret = bpf_core_read(&data->vendorid, sizeof(data->vendorid),
                      &udev->descriptor.idVendor);
  if (ret < 0) data->errors |= ECORE_READ;

  bpf_ringbuf_submit(data, 0);
  return 0;
}
