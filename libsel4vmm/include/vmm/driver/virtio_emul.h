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

#pragma once

#include <platsupport/io.h>
#include <ethdrivers/raw.h>
#include <satadrivers/raw.h>
#include <vmm/platform/guest_vspace.h>
#include <ethdrivers/virtio/virtio_ring.h>
#include "camkes_mutex.h"

struct ethif_virtio_emul_internal;

typedef struct ethif_virtio_emul {
    /* pointer to internal information */
    struct ethif_virtio_emul_internal *internal;
    /* io port interface functions */
    int (*io_in)(struct ethif_virtio_emul *emul, unsigned int offset, unsigned int size, unsigned int *result);
    int (*io_out)(struct ethif_virtio_emul *emul, unsigned int offset, unsigned int size, unsigned int value);
    /* notify of a status change in the underlying driver.
     * typically this would be due to link coming up
     * meaning that transmits can finally happen */
    int (*notify)(struct ethif_virtio_emul *emul);
} ethif_virtio_emul_t;

ethif_virtio_emul_t *ethif_virtio_emul_init(ps_io_ops_t io_ops, int queue_size, vspace_t *guest_vspace, ethif_driver_init driver, void *config);

typedef struct blkif_virtio_emul_internal {
    struct disk_driver driver;
    int status;
    struct virtio_blk_config cfg;
    uint16_t queue;
    struct vring vring;
    uint16_t queue_size;
    uint32_t queue_pfn;
    uint16_t last_idx;
    vspace_t guest_vspace;
    ps_dma_man_t dma_man;
} blkif_virtio_emul_internal_t;

typedef struct blkif_virtio_emul blkif_virtio_emul_t;

typedef int (*io_port_in_func_t)(blkif_virtio_emul_t *emul, unsigned int offset, unsigned int size, unsigned int *result);
typedef int (*io_port_out_func_t)(blkif_virtio_emul_t *emul, unsigned int offset, unsigned int size, unsigned int value);
typedef int (*notify_func_t)(blkif_virtio_emul_t *emul);

typedef struct blkif_virtio_emul {
    /* pointer to internal information */
    blkif_virtio_emul_internal_t *internal;
    /* io port interface functions */
    io_port_in_func_t io_in;
    io_port_out_func_t io_out;
    /* notify of a status change in the underlying driver.
     * typically this would be due to link coming up
     * meaning that transmits can finally happen */
    notify_func_t notify;
} blkif_virtio_emul_t;

blkif_virtio_emul_t *blkif_virtio_emul_init(ps_io_ops_t io_ops, int queue_size, vspace_t *guest_vspace, camkes_mutex_t *mutex, diskif_driver_init driver, void *config);

typedef struct emul_tx_cookie {
    uint16_t desc_head;
    void *vaddr;
} emul_tx_cookie_t;

// Common Functions
int read_guest_mem(uintptr_t phys, void *vaddr, size_t size, size_t offset, void *cookie);
int write_guest_mem(uintptr_t phys, void *vaddr, size_t size, size_t offset, void *cookie);
uint16_t ring_avail_idx(vspace_t *guest_vspace, struct vring *vring);
uint16_t ring_avail(vspace_t *guest_vspace, struct vring *vring, uint16_t idx);
struct vring_desc ring_desc(vspace_t *guest_vspace, struct vring *vring, uint16_t idx);
void ring_used_add(vspace_t *guest_vspace, struct vring *vring, struct vring_used_elem elem);
