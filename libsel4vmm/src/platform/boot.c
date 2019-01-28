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

/* Initialization functions related to the seL4 side of vmm
 * booting and management. */

#include <autoconf.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <sel4/sel4.h>
#include <simple/simple.h>
#include <vka/capops.h>

#include "vmm/platform/boot.h"
#include "vmm/platform/guest_vspace.h"
#include "vmm/processor/apicdef.h"
#include "vmm/processor/lapic.h"

int vmm_init(vmm_t *vmm, allocman_t *allocman, simple_t simple, vka_t vka, vspace_t vspace,
             platform_callbacks_t callbacks, int num_vcpus, int primary_core,
             seL4_CPtr async_event_notif) {
    int err;
    assert(0 < num_vcpus);
    memset(vmm, 0, sizeof(vmm_t));
    vmm->allocman = allocman;
    vmm->vka = vka;
    vmm->host_simple = simple;
    vmm->host_vspace = vspace;
    // Currently set this to 4k pages by default
    vmm->page_size = seL4_PageBits;
    err = vmm_pci_init(&vmm->pci);
    if (err) {
        return err;
    }
    err = vmm_io_port_init(&vmm->io_port);
    if (err) {
        return err;
    }

    vmm->vmcall_handlers = NULL;
    vmm->vmcall_num_handlers = 0;

    /* Per VCPU properties--have at least one */
    vmm->num_vcpus = num_vcpus;
    vmm->vcpus = (vmm_vcpu_t *)malloc(num_vcpus * sizeof(*vmm->vcpus));
    if (!vmm->vcpus) {
        return -1;
    }
    memset(vmm->vcpus, 0, num_vcpus * sizeof(*vmm->vcpus));

    vmm->vcpus[0].plat_callbacks = callbacks;
    vmm->vcpus[0].affinity = primary_core;
    vmm->vcpus[0].tcb = simple_get_tcb(&simple);
    vmm->vcpus[0].sc = simple_get_sc(&simple);
    vmm->vcpus[0].sched_ctrl = simple_get_sched_ctrl(&simple, primary_core);
    vmm->vcpus[0].async_event_notification = async_event_notif;


    for (int i = 0; i < num_vcpus; i++) {
        vmm->vcpus[i].parent_vmm = vmm;
        vmm->vcpus[i].vcpu_id = i;
        vmm->vcpus[i].apic_id = -1;
        err = vmm_mmio_init(&vmm->vcpus[i].mmio_list);
        assert(err == seL4_NoError);
    }

    return 0;
}

int vmm_init_secondary_vcpu(vmm_vcpu_t *vcpu, platform_callbacks_t callbacks, int core,
                            sel4utils_thread_t *new_thread, sched_params_t *sched_params,
                            seL4_CPtr async_event_notif) {
    assert(NULL != vcpu);
    assert(NULL != new_thread);
    assert(NULL != sched_params);

    vcpu->plat_callbacks = callbacks;
    vcpu->affinity = core;
    vcpu->tcb = new_thread->tcb.cptr;
    vcpu->sc = sched_params->sched_context;
    vcpu->sched_ctrl = sched_params->sched_ctrl;
    vcpu->async_event_notification = async_event_notif;

    return 0;
}

int vmm_init_host(vmm_t *vmm) {
    vmm->done_host_init = 1;
    return 0;
}

static int vmm_init_guest_vcpu(vmm_vcpu_t *vcpu) {
    int error = 0;

    /* sel4 vcpu (vmcs) */
    vcpu->guest_vcpu = vka_alloc_vcpu_leaky(&vcpu->parent_vmm->vka);
    if (vcpu->guest_vcpu == 0) {
        return -1;
    }

    /* bind the VCPU to the VMM thread */
    error = seL4_X86_VCPU_SetTCB(vcpu->guest_vcpu, vcpu->tcb);
    assert(error == seL4_NoError);

    error = seL4_TCB_SetEPTRoot(vcpu->tcb, vcpu->parent_vmm->guest_pd);
    assert(error == seL4_NoError);

    /* All LAPICs are created enabled, in virtual wire mode */
    vmm_create_lapic(vcpu, 1);

    vmm_mmio_add_handler(&vcpu->mmio_list, APIC_DEFAULT_PHYS_BASE,
                         APIC_DEFAULT_PHYS_BASE + sizeof(struct local_apic_regs) - 1,
                         NULL, "Local APIC", vmm_apic_mmio_read, vmm_apic_mmio_write);

    return error;
}

int vmm_init_guest(vmm_t *vmm) {
    int error;

    assert(vmm->done_host_init);

    /* Create an EPT which is the pd for all the vcpu tcbs */
    vmm->guest_pd = vka_alloc_ept_pml4_leaky(&vmm->vka);
    if (vmm->guest_pd == 0) {
        return -1;
    }
    /* Assign an ASID */
    error = simple_ASIDPool_assign(&vmm->host_simple, vmm->guest_pd);
    if (error != seL4_NoError) {
        ZF_LOGE("Failed to assign ASID pool to EPT root");
        return -1;
    }
    /* Initialize a vspace for the guest */
    error = vmm_get_guest_vspace(&vmm->host_vspace, &vmm->host_vspace, &vmm->guest_mem.vspace,
                                 &vmm->vka, vmm->guest_pd);
    if (error) {
        return error;
    }

    /* Init guest memory information.
     * TODO: should probably done elsewhere */
    vmm->guest_mem.num_ram_regions = 0;
    vmm->guest_mem.ram_regions = malloc(0);

    for (int i = 0; i < vmm->num_vcpus; i++) {
        vmm_init_guest_vcpu(&vmm->vcpus[i]);
    }

    vmm->done_guest_init = 1;
    return 0;
}

