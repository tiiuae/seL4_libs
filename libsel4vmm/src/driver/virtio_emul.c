/*
 * Copyright 2017, Data61
 * Commonwealth Scientific and Industrial Research Organisation (CSIRO)
 * ABN 41 687 119 230.
 *
 * This software may be distributed and modified according to the terms of
 * the GNU General Public License version 2. Note that NO WARRANTY is provided.
 * See "LICENSE_GPLv2.txt" for details.
 *
 * @TAG(DATA61_GPL)
 */

#include <autoconf.h>

#include <string.h>

#include <vmm/driver/virtio_emul.h>
#include <ethdrivers/virtio/virtio_pci.h>
#include <ethdrivers/virtio/virtio_net.h>
#include <ethdrivers/virtio/virtio_config.h>

int read_guest_mem(uintptr_t phys, void *vaddr, size_t size, size_t offset, void *cookie) {
    memcpy(cookie + offset, vaddr, size);
    return 0;
}

int write_guest_mem(uintptr_t phys, void *vaddr, size_t size, size_t offset, void *cookie) {
    memcpy(vaddr, cookie + offset, size);
    return 0;
}

uint16_t ring_avail_idx(vspace_t *guest_vspace, struct vring *vring) {
    uint16_t idx;
    vmm_guest_vspace_touch(guest_vspace, (uintptr_t)&vring->avail->idx, sizeof(vring->avail->idx), read_guest_mem, &idx);
    return idx;
}

uint16_t ring_avail(vspace_t *guest_vspace, struct vring *vring, uint16_t idx) {
    uint16_t elem;
    vmm_guest_vspace_touch(guest_vspace, (uintptr_t)&(vring->avail->ring[idx % vring->num]), sizeof(elem), read_guest_mem, &elem);
    return elem;
}

struct vring_desc ring_desc(vspace_t *guest_vspace, struct vring *vring, uint16_t idx) {
    struct vring_desc desc;
    vmm_guest_vspace_touch(guest_vspace, (uintptr_t)&(vring->desc[idx]), sizeof(desc), read_guest_mem, &desc);
    return desc;
}

void ring_used_add(vspace_t *guest_vspace, struct vring *vring, struct vring_used_elem elem) {
    uint16_t guest_idx;
    vmm_guest_vspace_touch(guest_vspace, (uintptr_t)&vring->used->idx, sizeof(vring->used->idx), read_guest_mem, &guest_idx);
    vmm_guest_vspace_touch(guest_vspace, (uintptr_t)&vring->used->ring[guest_idx % vring->num], sizeof(elem), write_guest_mem, &elem);
    guest_idx++;
    vmm_guest_vspace_touch(guest_vspace, (uintptr_t)&vring->used->idx, sizeof(vring->used->idx), write_guest_mem, &guest_idx);
}
