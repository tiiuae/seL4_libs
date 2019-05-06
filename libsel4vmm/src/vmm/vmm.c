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

/* Functions for VMM main host thread.
 *
 *     Authors:
 *         Qian Ge
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sel4/sel4.h>
#include <vka/capops.h>
#include <platsupport/arch/tsc.h>
#include <sel4/arch/vmenter.h>

#include "vmm/debug.h"
#include "vmm/vmm.h"
#include "vmm/interrupt.h"
#include "vmm/platform/boot_guest.h"

#define VMM_INITIAL_STACK 0x96000

int vmm_resume_vcpu(vmm_vcpu_t *vcpu)
{
    if (NULL == vcpu) {
        ZF_LOGE("Passed in vcpu is NULL");
        return -1;
    }

    int error;
    seL4_UserContext regs;
    const int num_regs = sizeof(regs) / sizeof(seL4_Word);

    error = seL4_TCB_ReadRegisters(vcpu->tcb, false, 0, num_regs, &regs);
    if (error) {
        ZF_LOGE("Failed to read registers for vcpu %d, error %d", vcpu->vcpu_id, error);
        return -1;
    }

    /* We assume the VCPU has been correctly suspended with vmm_suspend_vcpu.
     * Therefore, we step over the suspend instruction (0f 05) by incrementing
     * the instruction pointer by 2 bytes
     */
#ifdef CONFIG_ARCH_X86_64
    regs.rip += 2;
#else
    regs.eip += 2;
#endif

    /* Write the registers, resuming the thread in the process */
    error = seL4_TCB_WriteRegisters(vcpu->tcb, true, 0, num_regs, &regs);
    if (error) {
        ZF_LOGE("Failed to write registers for vcpu %d, error %d", vcpu->vcpu_id, error);
        return -1;
    }

    return 0;
}

int vmm_suspend_vcpu(vmm_vcpu_t *vcpu)
{
    if (NULL == vcpu) {
        ZF_LOGE("Passed in vcpu is NULL");
        return -1;
    }

    seL4_TCB_Suspend(vcpu->tcb);

    return 0;
}

void vmm_sync_guest_context(vmm_vcpu_t *vcpu) {
    if (vmm_get_current_apic_id() != vcpu->apic_id) {
        DPRINTF(4, "WARNING: %s called from apic_id %d for vcpu with apic_id %d\n",
                __func__, vmm_get_current_apic_id(), vcpu->apic_id);
        vcpu->sync_guest_context = true;
        return;
    }

    if (IS_MACHINE_STATE_MODIFIED(vcpu->guest_state.machine.context)) {
        seL4_VCPUContext context;
        context.eax = vmm_read_user_context(&vcpu->guest_state, USER_CONTEXT_EAX);
        context.ebx = vmm_read_user_context(&vcpu->guest_state, USER_CONTEXT_EBX);
        context.ecx = vmm_read_user_context(&vcpu->guest_state, USER_CONTEXT_ECX);
        context.edx = vmm_read_user_context(&vcpu->guest_state, USER_CONTEXT_EDX);
        context.esi = vmm_read_user_context(&vcpu->guest_state, USER_CONTEXT_ESI);
        context.edi = vmm_read_user_context(&vcpu->guest_state, USER_CONTEXT_EDI);
        context.ebp = vmm_read_user_context(&vcpu->guest_state, USER_CONTEXT_EBP);
#ifdef CONFIG_ARCH_X86_64
        context.r8 = vmm_read_user_context(&vcpu->guest_state, USER_CONTEXT_R8);
        context.r9 = vmm_read_user_context(&vcpu->guest_state, USER_CONTEXT_R9);
        context.r10 = vmm_read_user_context(&vcpu->guest_state, USER_CONTEXT_R10);
        context.r11 = vmm_read_user_context(&vcpu->guest_state, USER_CONTEXT_R11);
        context.r12 = vmm_read_user_context(&vcpu->guest_state, USER_CONTEXT_R12);
        context.r13 = vmm_read_user_context(&vcpu->guest_state, USER_CONTEXT_R13);
        context.r14 = vmm_read_user_context(&vcpu->guest_state, USER_CONTEXT_R14);
        context.r15 = vmm_read_user_context(&vcpu->guest_state, USER_CONTEXT_R15);
#endif
        seL4_X86_VCPU_WriteRegisters(vcpu->guest_vcpu, &context);
        /* Sync our context */
        MACHINE_STATE_SYNC(vcpu->guest_state.machine.context);
    }
}

void vmm_reply_vm_exit(vmm_vcpu_t *vcpu) {
    ZF_LOGF_IF(!vcpu->guest_state.exit.in_exit, "VCPU %d not in_exit\n", vcpu->vcpu_id);

    if (IS_MACHINE_STATE_MODIFIED(vcpu->guest_state.machine.context)) {
        vmm_sync_guest_context(vcpu);
    }

    /* Before we resume the guest, ensure there is no dirty state around */
    ZF_LOGF_IF(!vmm_guest_state_no_modified(&vcpu->guest_state), "VCPU %d was modified\n", vcpu->vcpu_id);
    vmm_guest_state_invalidate_all(&vcpu->guest_state);

    vcpu->guest_state.exit.in_exit = 0;
}

void vmm_sync_guest_state(vmm_vcpu_t *vcpu) {
    if (vmm_get_current_apic_id() != vcpu->apic_id) {
        DPRINTF(4, "WARNING: %s called from apic_id %d for vcpu with apic_id %d\n",
                __func__, vmm_get_current_apic_id(), vcpu->apic_id);
        vcpu->sync_guest_state = true;
        return;
    }

    vmm_guest_state_sync_cr0(&vcpu->guest_state, vcpu->guest_vcpu);
    vmm_guest_state_sync_cr3(&vcpu->guest_state, vcpu->guest_vcpu);
    vmm_guest_state_sync_cr4(&vcpu->guest_state, vcpu->guest_vcpu);
    vmm_guest_state_sync_idt_base(&vcpu->guest_state, vcpu->guest_vcpu);
    vmm_guest_state_sync_idt_limit(&vcpu->guest_state, vcpu->guest_vcpu);
    vmm_guest_state_sync_gdt_base(&vcpu->guest_state, vcpu->guest_vcpu);
    vmm_guest_state_sync_gdt_limit(&vcpu->guest_state, vcpu->guest_vcpu);
    vmm_guest_state_sync_cs_selector(&vcpu->guest_state, vcpu->guest_vcpu);
#ifdef CONFIG_ARCH_X86_64
    vmm_guest_state_sync_ss_selector(&vcpu->guest_state, vcpu->guest_vcpu);
    vmm_guest_state_sync_ds_selector(&vcpu->guest_state, vcpu->guest_vcpu);
    vmm_guest_state_sync_es_selector(&vcpu->guest_state, vcpu->guest_vcpu);
    vmm_guest_state_sync_fs_selector(&vcpu->guest_state, vcpu->guest_vcpu);
    vmm_guest_state_sync_gs_selector(&vcpu->guest_state, vcpu->guest_vcpu);
    vmm_guest_state_sync_esp(&vcpu->guest_state, vcpu->guest_vcpu);
#endif
    vmm_guest_state_sync_entry_exception_error_code(&vcpu->guest_state, vcpu->guest_vcpu);
}

/* Handle VM exit in VMM module. */
static void vmm_handle_vm_exit(vmm_vcpu_t *vcpu) {
    int reason = vmm_guest_exit_get_reason(&vcpu->guest_state);

    /* Distribute the task according to the exit info. */
    vmm_print_guest_context(3, vcpu);

    if (reason == -1) {
        ZF_LOGF("Kernel failed to perform vmlaunch or vmresume, we have no recourse");
    }

    if (!vcpu->parent_vmm->vmexit_handlers[reason]) {
        printf("VM_FATAL_ERROR ::: vm exit handler is NULL for reason 0x%x.\n", reason);
        vmm_print_guest_context(0, vcpu);
        vcpu->online = 0;
        return;
    }

    /* Call the handler. */
    if (vcpu->parent_vmm->vmexit_handlers[reason](vcpu)) {
        printf("VM_FATAL_ERROR ::: vmexit handler return error\n");
        vmm_print_guest_context(0, vcpu);
        vcpu->online = 0;
        return;
    }

    /* Reply to the VM exit exception to resume guest. */
    vmm_sync_guest_state(vcpu);
    if (vcpu->guest_state.exit.in_exit && !vcpu->guest_state.virt.interrupt_halt) {
        /* Guest is blocked, but we are no longer halted. Reply to it */
        vmm_reply_vm_exit(vcpu);
    }
}

static void vmm_update_guest_state_from_interrupt(vmm_vcpu_t *vcpu, seL4_Word *msg) {
    vcpu->guest_state.machine.eip = msg[SEL4_VMENTER_CALL_EIP_MR];
    vcpu->guest_state.machine.control_ppc = msg[SEL4_VMENTER_CALL_CONTROL_PPC_MR];
    vcpu->guest_state.machine.control_entry = msg[SEL4_VMENTER_CALL_CONTROL_ENTRY_MR];
}

static void vmm_update_guest_state_from_fault(vmm_vcpu_t *vcpu, seL4_Word *msg) {
    ZF_LOGF_IF(!vcpu->guest_state.exit.in_exit, "VCPU (%d) not in_exit\n", vcpu->vcpu_id);

    /* The interrupt state is a subset of the fault state */
    vmm_update_guest_state_from_interrupt(vcpu, msg);

    vcpu->guest_state.exit.reason = msg[SEL4_VMENTER_FAULT_REASON_MR];
    vcpu->guest_state.exit.qualification = msg[SEL4_VMENTER_FAULT_QUALIFICATION_MR];
    vcpu->guest_state.exit.instruction_length = msg[SEL4_VMENTER_FAULT_INSTRUCTION_LEN_MR];
    vcpu->guest_state.exit.guest_physical = msg[SEL4_VMENTER_FAULT_GUEST_PHYSICAL_MR];

    MACHINE_STATE_READ(vcpu->guest_state.machine.rflags, msg[SEL4_VMENTER_FAULT_RFLAGS_MR]);
    MACHINE_STATE_READ(vcpu->guest_state.machine.guest_interruptibility, msg[SEL4_VMENTER_FAULT_GUEST_INT_MR]);

    MACHINE_STATE_READ(vcpu->guest_state.machine.cr3, msg[SEL4_VMENTER_FAULT_CR3_MR]);

    seL4_VCPUContext context;
    context.eax = msg[SEL4_VMENTER_FAULT_EAX];
    context.ebx = msg[SEL4_VMENTER_FAULT_EBX];
    context.ecx = msg[SEL4_VMENTER_FAULT_ECX];
    context.edx = msg[SEL4_VMENTER_FAULT_EDX];
    context.esi = msg[SEL4_VMENTER_FAULT_ESI];
    context.edi = msg[SEL4_VMENTER_FAULT_EDI];
    context.ebp = msg[SEL4_VMENTER_FAULT_EBP];
#ifdef CONFIG_ARCH_X86_64
    context.r8 = msg[SEL4_VMENTER_FAULT_R8];
    context.r9 = msg[SEL4_VMENTER_FAULT_R9];
    context.r10 = msg[SEL4_VMENTER_FAULT_R10];
    context.r11 = msg[SEL4_VMENTER_FAULT_R11];
    context.r12 = msg[SEL4_VMENTER_FAULT_R12];
    context.r13 = msg[SEL4_VMENTER_FAULT_R13];
    context.r14 = msg[SEL4_VMENTER_FAULT_R14];
    context.r15 = msg[SEL4_VMENTER_FAULT_R15];
#endif
    MACHINE_STATE_READ(vcpu->guest_state.machine.context, context);
}

/* Entry point of VMM main host module. */
void vmm_run_vcpu(vmm_vcpu_t *vcpu) {
    int UNUSED error;
    DPRINTF(4, "VMM MAIN HOST MODULE STARTED FOR CORE %d\n", (int)vcpu->affinity);

    vcpu->apic_id = vmm_get_current_apic_id();

#ifdef CONFIG_ARCH_X86_64
    /* On Linux Kernels below 4.7, startup_64 does not setup a stack before
     * calling verify_cpu, which causes a triple fault. This sets an initial
     * stack in low memory. For Linux kernels > 4.7, this will simply get
     * overwritten
     */
    vmm_guest_state_set_esp(&vcpu->guest_state, VMM_INITIAL_STACK);
#endif

    vcpu->guest_state.virt.interrupt_halt = 0;
    vcpu->guest_state.exit.in_exit = 0;

    /* Wait for IPI to start secondary thread */
    if (BOOT_VCPU != vcpu->vcpu_id) {
        error = vmm_suspend_vcpu(vcpu);
        ZF_LOGF_IF(-1 == error, "Failed to suspend vcpu %d\n", vcpu->vcpu_id);
    }

    /* sync the existing guest state */
    vmm_sync_guest_state(vcpu);
    vmm_sync_guest_context(vcpu);

    /* now invalidate everything */
    assert(vmm_guest_state_no_modified(&vcpu->guest_state));
    vmm_guest_state_invalidate_all(&vcpu->guest_state);

    /* Start the vcpu guest thread running */
    vcpu->online = 1;

    /* Get our interrupt pending callback happening */
    error = seL4_TCB_BindNotification(vcpu->tcb, vcpu->async_event_notification);
    assert(error == seL4_NoError);

    while (1) {
        /* Block and wait for incoming msg or VM exits. */
        seL4_Word badge;
        int fault;

        if (vcpu->sync_guest_state) {
            vmm_sync_guest_state(vcpu);
            vcpu->sync_guest_state = false;
        }

        if (vcpu->sync_guest_context) {
            vmm_sync_guest_context(vcpu);
            vcpu->sync_guest_context = false;
        }

        if (vcpu->online && !vcpu->guest_state.virt.interrupt_halt && !vcpu->guest_state.exit.in_exit) {
            seL4_SetMR(0, vmm_guest_state_get_eip(&vcpu->guest_state));
            seL4_SetMR(1, vmm_guest_state_get_control_ppc(&vcpu->guest_state));
            seL4_SetMR(2, vmm_guest_state_get_control_entry(&vcpu->guest_state));
            fault = seL4_VMEnter(&badge);

            if (fault == SEL4_VMENTER_RESULT_FAULT) {
                /* We in a fault */
                vcpu->guest_state.exit.in_exit = 1;

                /* Update the guest state from a fault */
                seL4_Word fault_message[SEL4_VMENTER_RESULT_FAULT_LEN];
                for (int i = 0 ; i < SEL4_VMENTER_RESULT_FAULT_LEN; i++) {
                    fault_message[i] = seL4_GetMR(i);
                }
                vmm_guest_state_invalidate_all(&vcpu->guest_state);
                vmm_update_guest_state_from_fault(vcpu, fault_message);
            } else {
                /* update the guest state from a non fault */
                seL4_Word int_message[SEL4_VMENTER_RESULT_NOTIF_LEN];
                for (int i = 0 ; i < SEL4_VMENTER_RESULT_NOTIF_LEN; i++) {
                    int_message[i] = seL4_GetMR(i);
                }
                vmm_guest_state_invalidate_all(&vcpu->guest_state);
                vmm_update_guest_state_from_interrupt(vcpu, int_message);
            }
        } else {
            seL4_Wait(vcpu->async_event_notification, &badge);
            fault = SEL4_VMENTER_RESULT_NOTIF;
        }

        if (fault == SEL4_VMENTER_RESULT_NOTIF) {
            if (0 == badge) {
                /* This is an IPI, not a PIC interrupt */
                vmm_vcpu_accept_interrupt(vcpu);
                continue;
            }

            if (BOOT_VCPU == vcpu->vcpu_id) {
                assert(badge >= vcpu->parent_vmm->num_vcpus);
                /* assume interrupt */
                int raise = vcpu->plat_callbacks.do_async(badge);
                if (raise == 0) {
                    /* Check if this caused PIC to generate interrupt */
                    vmm_check_external_interrupt(vcpu->parent_vmm);
                }

                continue;
            }
        }

        /* Handle the vm exit */
        vmm_handle_vm_exit(vcpu);

        if (BOOT_VCPU == vcpu->vcpu_id) {
            vmm_check_external_interrupt(vcpu->parent_vmm);
        }

        DPRINTF(5, "VMM main host blocking for another message...\n");
    }

}

static void vmm_exit_init(vmm_t *vmm) {
    /* Connect VM exit handlers to correct function pointers */
    vmm->vmexit_handlers[EXIT_REASON_PENDING_INTERRUPT] = vmm_pending_interrupt_handler;
    //vmm->vmexit_handlers[EXIT_REASON_EXCEPTION_NMI] = vmm_exception_handler;
    vmm->vmexit_handlers[EXIT_REASON_CPUID] = vmm_cpuid_handler;
    vmm->vmexit_handlers[EXIT_REASON_MSR_READ] = vmm_rdmsr_handler;
    vmm->vmexit_handlers[EXIT_REASON_MSR_WRITE] = vmm_wrmsr_handler;
    vmm->vmexit_handlers[EXIT_REASON_EPT_VIOLATION] = vmm_ept_violation_handler;
    vmm->vmexit_handlers[EXIT_REASON_CR_ACCESS] = vmm_cr_access_handler;
    vmm->vmexit_handlers[EXIT_REASON_IO_INSTRUCTION] = vmm_io_instruction_handler;
/*    vmm->vmexit_handlers[EXIT_REASON_RDTSC] = vmm_rdtsc_instruction_handler;*/
    vmm->vmexit_handlers[EXIT_REASON_HLT] = vmm_hlt_handler;
    vmm->vmexit_handlers[EXIT_REASON_VMX_TIMER] = vmm_vmx_timer_handler;
    vmm->vmexit_handlers[EXIT_REASON_VMCALL] = vmm_vmcall_handler;
}

int vmm_finalize(vmm_t *vmm) {
    int err;
    vmm_exit_init(vmm);

    for (int i = 0; i < vmm->num_vcpus; i++) {
        vmm_vcpu_t *vcpu = &vmm->vcpus[i];

        vmm_init_guest_thread_state(vcpu);
        err = vmm_io_port_init_guest(&vmm->io_port, &vmm->host_simple, vcpu->guest_vcpu, &vmm->vka);
        if (err) {
            return err;
        }
    }
    return 0;
}

seL4_CPtr vmm_create_async_event_notification_cap(vmm_t *vmm, seL4_Word badge) {

    if (!(badge & BIT(27))) {
        ZF_LOGE("Invalid badge");
        return seL4_CapNull;
    }

    // path to notification cap slot
    cspacepath_t ntfn_path;
    vka_cspace_make_path(&vmm->vka, vmm->vcpus[0].async_event_notification, &ntfn_path);

    // allocate slot to store copy
    cspacepath_t minted_ntfn_path = {};
    vka_cspace_alloc_path(&vmm->vka, &minted_ntfn_path);

    // mint the notification cap
    int error = vka_cnode_mint(&minted_ntfn_path, &ntfn_path, seL4_AllRights, badge);

    if (error != seL4_NoError) {
        ZF_LOGE("Failed to mint notification cap");
        return seL4_CapNull;
    }

    return minted_ntfn_path.capPtr;
}
