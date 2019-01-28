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

#include <simple/simple.h>
#include <vka/vka.h>
#include <vspace/vspace.h>
#include <allocman/allocman.h>
#include <sel4utils/thread.h>
#include "vmm/vmm.h"

int vmm_init(vmm_t *vmm, allocman_t *allocman, simple_t simple, vka_t vka, vspace_t vspace, platform_callbacks_t callbacks, int num_vcpus, int primary_core, seL4_CPtr async_event_notif);
int vmm_init_secondary_vcpu(vmm_vcpu_t *vcpu, platform_callbacks_t callbacks, int core, sel4utils_thread_t *new_thread, sched_params_t *sched_params, seL4_CPtr async_event_notif);
int vmm_init_host(vmm_t *vmm);
int vmm_init_guest(vmm_t *vmm);

