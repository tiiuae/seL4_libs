/*
 * Copyright 2019, DornerWorks
 *
 * This software may be distributed and modified according to the terms of
 * the GNU General Public License version 2. Note that NO WARRANTY is provided.
 * See "LICENSE_GPLv2.txt" for details.
 *
 */

#include <autoconf.h>

#include <string.h>

#include <vmm/driver/virtio_emul.h>
#include <ethdrivers/virtio/virtio_pci.h>
#include <ethdrivers/virtio/virtio_net.h>
#include <ethdrivers/virtio/virtio_ring.h>
#include <ethdrivers/virtio/virtio_config.h>
#include <satadrivers/virtio/virtio_blk.h>

#define BUF_SIZE 8192
#define MAX_DATA_BUF_SIZE 4096

static camkes_mutex_t *virtio_blk_mutex;

static void complete_virtio_blk_request(void *iface, void *cookie) {
    blkif_virtio_emul_t *emul = (blkif_virtio_emul_t*)iface;
    blkif_virtio_emul_internal_t *blk = emul->internal;
    emul_tx_cookie_t *tx_cookie = (emul_tx_cookie_t*)cookie;
    /* free the dma memory */
    ps_dma_unpin(&blk->dma_man, tx_cookie->vaddr, BUF_SIZE);
    ps_dma_free(&blk->dma_man, tx_cookie->vaddr, BUF_SIZE);
    /* put the descriptor chain into the used list */
    struct vring_used_elem used_elem = {tx_cookie->desc_head, 0};
    ring_used_add(&emul->internal->guest_vspace, &blk->vring, used_elem);
    free(tx_cookie);
    /* notify the guest that we have completed some of its buffers */
    blk->driver.i_fn.raw_handleIRQ(&blk->driver, 0);
}

static void handle_virtio_blk_request(blkif_virtio_emul_t *emul) {
    int error UNUSED;
    error = camkes_mutex_lock(virtio_blk_mutex);

    /* Create Local Copies of the Passed in Structure */
    blkif_virtio_emul_internal_t *blk = emul->internal;
    struct vring *vring = &blk->vring;

    /* read the index */
    uint16_t guest_idx = ring_avail_idx(&emul->internal->guest_vspace, vring);

    /* process what we can of the ring */
    uint16_t idx = blk->last_idx;
    uint32_t buf_len = 0;

    uint64_t desc_addrs[3];

    while (idx != guest_idx) {
        uint16_t desc_head;

        /* read the head of the descriptor chain */
        desc_head = ring_avail(&emul->internal->guest_vspace, vring, idx);

        /* allocate a packet */
        void *vaddr = ps_dma_alloc(&blk->dma_man, BUF_SIZE, blk->driver.dma_alignment, 1, PS_MEM_NORMAL);
        if (!vaddr) {
            /* try again later */
            break;
        }
        uintptr_t phys = ps_dma_pin(&blk->dma_man, vaddr, BUF_SIZE);
        assert(phys);

        /* length of the final packet to deliver */
        uint32_t len = 0;

        /* start walking the descriptors */
        struct vring_desc desc;
        uint16_t desc_idx = desc_head;
        int i = 0;
        do {

            desc = ring_desc(&emul->internal->guest_vspace, vring, desc_idx);
            /* truncate packets that are too large */
            uint32_t this_len = desc.len;
            this_len = MIN(BUF_SIZE - len, this_len);
            vmm_guest_vspace_touch(&blk->guest_vspace, (uintptr_t)desc.addr, this_len, read_guest_mem, vaddr + len);
            /* Save off the descriptor addresses so we can write back to the VM */
            desc_addrs[i] = desc.addr;
            /* The second descriptor (index 1) is the data buffer.
             *  The length of this buffer determines how much we need to
             *  copy to or from this buffer.
             */
            if(i == 1)
            {
              buf_len = desc.len;
            }
            i++;
            len += this_len;
            desc_idx = desc.next;

        } while (desc.flags & VRING_DESC_F_NEXT);
        /* ship it */
        emul_tx_cookie_t *cookie = malloc(sizeof(*cookie));
        assert(cookie);
        cookie->desc_head = desc_head;
        cookie->vaddr = vaddr;

        /* Currently we can only handle buffers of a certain size or less.
         *  We could fix this, but not sure if it is necessary based on the
         *  FileSystem types that have been tested
         */
        assert(buf_len <= MAX_DATA_BUF_SIZE);

        struct virtio_blk_outhdr hdr;
        memcpy(&hdr, (void *)phys, sizeof(struct virtio_blk_outhdr));

        /* Calculate the addresses to which we actually write data */
        uintptr_t guest_buf_phys = phys + sizeof(struct virtio_blk_outhdr);
        uintptr_t req_status_phys = phys + sizeof(struct virtio_blk_outhdr) + buf_len;

        /* Start disk read or write chain */
        int result = blk->driver.i_fn.raw_xfer(&blk->driver, hdr.type, hdr.sector, buf_len, guest_buf_phys);

        switch (result) {
          case VIRTIO_BLK_XFER_COMPLETE:
              *(uint8_t*)req_status_phys = VIRTIO_BLK_S_OK;
              if(VIRTIO_BLK_T_IN == hdr.type)
              {
                /* We assume descriptor address at index 1 is the buffer */
                vmm_guest_vspace_touch(&blk->guest_vspace, desc_addrs[1], buf_len, write_guest_mem, vaddr + sizeof(struct virtio_blk_outhdr) );
              }
              /* We assume descriptor address at index 2 is the status of the IO cmd*/
              vmm_guest_vspace_touch(&blk->guest_vspace, desc_addrs[2], 1, write_guest_mem, vaddr + sizeof(struct virtio_blk_outhdr) + buf_len);
              complete_virtio_blk_request(emul, cookie);
              break;
          case VIRTIO_BLK_XFER_FAILED:
              *(uint8_t*)req_status_phys = VIRTIO_BLK_S_IOERR;
              vmm_guest_vspace_touch(&blk->guest_vspace, desc_addrs[2], 1, write_guest_mem, vaddr + sizeof(struct virtio_blk_outhdr) + buf_len);
              complete_virtio_blk_request(emul, cookie);
              break;
          }
        /* next */
        idx++;
    }
    /* update which parts of the ring we have processed */
    blk->last_idx = idx;
    error = camkes_mutex_unlock(virtio_blk_mutex);
}

static int emul_io_in(blkif_virtio_emul_t *emul, unsigned int offset, unsigned int size, unsigned int *result) {
    switch(offset) {
    case VIRTIO_PCI_HOST_FEATURES:
        assert(size == 4);
        *result = (BIT(VIRTIO_BLK_F_BLK_SIZE) | BIT(VIRTIO_BLK_F_SEG_MAX) | BIT(VIRTIO_BLK_F_SIZE_MAX));
        break;
    case VIRTIO_PCI_STATUS:
        assert(size == 1);
        *result = emul->internal->status;
        break;
    case VIRTIO_PCI_QUEUE_NUM:
        assert(size == 2);
        *result = emul->internal->queue_size;
        break;
    case VIRTIO_PCI_QUEUE_PFN:
        assert(size == 4);
        *result = emul->internal->queue_pfn;
        break;
    case VIRTIO_PCI_ISR:
        assert(size == 1);
        *result = 1;
        break;
    case VIRTIO_PCI_CONFIG_OFF(0) ... VIRTIO_PCI_CONFIG_OFF(0) + sizeof(struct virtio_blk_config):
        assert(size == 1);
        memcpy(result, (((uint8_t *)&emul->internal->cfg) + offset - VIRTIO_PCI_CONFIG_OFF(0)), size);
        break;
    default:
        printf("Unhandled offset of 0x%x of size %d, reading\n", offset, size);
        assert(!"panic");
    }
    return 0;
}

static int emul_io_out(blkif_virtio_emul_t *emul, unsigned int offset, unsigned int size, unsigned int value) {
    switch(offset) {
    case VIRTIO_PCI_GUEST_FEATURES:
        assert(size == 4);
        assert(value == (BIT(VIRTIO_BLK_F_BLK_SIZE) | BIT(VIRTIO_BLK_F_SEG_MAX) | BIT(VIRTIO_BLK_F_SIZE_MAX)));
        break;
    case VIRTIO_PCI_STATUS:
        assert(size == 1);
        emul->internal->status = value & 0xff;
        break;
    case VIRTIO_PCI_QUEUE_SEL:
        assert(size == 2);
        // This doesn't even matter, virtio_blk only implements a single queue
        emul->internal->queue = (value & 0xffff);
        assert(emul->internal->queue == 0);
        break;
    case VIRTIO_PCI_QUEUE_PFN: {
        assert(size == 4);
        emul->internal->queue_pfn = value;
        vring_init(&emul->internal->vring, emul->internal->queue_size, (void*)(uintptr_t)(value << VIRTIO_PCI_QUEUE_ADDR_SHIFT), VIRTIO_PCI_VRING_ALIGN);
        break;
    }
    case VIRTIO_PCI_QUEUE_NOTIFY:
        handle_virtio_blk_request(emul);
        break;
    default:
        printf("Unhandled offset of 0x%x of size %d, writing 0x%x\n", offset, size, value);
        assert(!"panic");
    }
    return 0;
}

static int emul_notify(blkif_virtio_emul_t *emul) {
    if (emul->internal->status != VIRTIO_CONFIG_S_DRIVER_OK) {
        return -1;
    }
    handle_virtio_blk_request(emul);
    return 0;
}

blkif_virtio_emul_t *blkif_virtio_emul_init(ps_io_ops_t io_ops, int queue_size, vspace_t *guest_vspace, camkes_mutex_t *mutex, diskif_driver_init driver, void *config) {
    blkif_virtio_emul_t *emul = NULL;
    blkif_virtio_emul_internal_t *internal = NULL;

    if(NULL == mutex){
        goto error;
    }

    virtio_blk_mutex = mutex;

    int err;
    emul = malloc(sizeof(*emul));
    internal = malloc(sizeof(*internal));
    if (!emul || !internal) {
        goto error;
    }
    memset(emul, 0, sizeof(*emul));
    memset(internal, 0, sizeof(*internal));
    emul->internal = internal;
    emul->io_in = emul_io_in;
    emul->io_out = emul_io_out;
    emul->notify = emul_notify;
    internal->queue_size = queue_size;
    /* create dummy ring. we never actually dereference the ring so it can be null */
    vring_init(&internal->vring, emul->internal->queue_size, 0, VIRTIO_PCI_VRING_ALIGN);
    internal->driver.cb_cookie = emul;
    internal->guest_vspace = *guest_vspace;
    internal->dma_man = io_ops.dma_manager;
    err = driver(&internal->driver, io_ops, config);
    if (err) {
        ZF_LOGE("Fafiled to initialize driver");
        goto error;
    }
    internal->driver.i_fn.low_level_init(&internal->driver, &internal->cfg);
    return emul;
error:
    if (emul) {
        free(emul);
    }
    if (internal) {
        free(internal);
    }
    return NULL;
}
