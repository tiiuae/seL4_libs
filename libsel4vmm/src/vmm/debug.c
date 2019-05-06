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

/* Debugging helper functions used by VMM lib.
 *     Authors:
 *         Qian Ge
 */

#include <stdio.h>
#include <stdlib.h>

#include <sel4/sel4.h>

#include "vmm/debug.h"

#ifdef CONFIG_ARCH_X86_64

/* Print out the context of a guest OS thread. */
void vmm_print_guest_context(int level, vmm_vcpu_t *vcpu) {
    DPRINTF(level, "================== GUEST OS CONTEXT =================\n");

    DPRINTF(level, "exit info : reason 0x%lx    qualification 0x%lx   instruction len 0x%lx\n",
            vmm_guest_exit_get_reason(&vcpu->guest_state),
            vmm_guest_exit_get_qualification(&vcpu->guest_state),
            vmm_guest_exit_get_int_len(&vcpu->guest_state));
    DPRINTF(level, "            interrupt info 0x%lx     interrupt error 0x%lx\n",
            vmm_vmcs_read(vcpu->guest_vcpu, VMX_DATA_EXIT_INTERRUPT_INFO),
            vmm_vmcs_read(vcpu->guest_vcpu, VMX_DATA_EXIT_INTERRUPT_ERROR));
    DPRINTF(level, "            guest physical 0x%lx     rflags 0x%lx\n",
            vmm_guest_exit_get_physical(&vcpu->guest_state),
            vmm_guest_state_get_rflags(&vcpu->guest_state, vcpu->guest_vcpu));
    DPRINTF(level, "            guest interruptibility 0x%lx   control entry 0x%lx\n",
            vmm_guest_state_get_interruptibility(&vcpu->guest_state, vcpu->guest_vcpu),
            vmm_guest_state_get_control_entry(&vcpu->guest_state));

    DPRINTF(level, "rip 0x%lx\n",
            vmm_guest_state_get_eip(&vcpu->guest_state));
    DPRINTF(level, "rax 0x%lx         rbx 0x%lx      rcx 0x%lx\n",
            vmm_read_user_context(&vcpu->guest_state, USER_CONTEXT_EAX),
            vmm_read_user_context(&vcpu->guest_state, USER_CONTEXT_EBX),
            vmm_read_user_context(&vcpu->guest_state, USER_CONTEXT_ECX));
    DPRINTF(level, "rdx 0x%lx         rsi 0x%lx      rdi 0x%lx\n",
            vmm_read_user_context(&vcpu->guest_state, USER_CONTEXT_EDX),
            vmm_read_user_context(&vcpu->guest_state, USER_CONTEXT_ESI),
            vmm_read_user_context(&vcpu->guest_state, USER_CONTEXT_EDI));
    DPRINTF(level, "rbp 0x%lx\n",
            vmm_read_user_context(&vcpu->guest_state, USER_CONTEXT_EBP));
    DPRINTF(level, "r8 0x%lx          r9 0x%lx       r10 0x%lx\n",
            vmm_read_user_context(&vcpu->guest_state, USER_CONTEXT_R8),
            vmm_read_user_context(&vcpu->guest_state, USER_CONTEXT_R9),
            vmm_read_user_context(&vcpu->guest_state, USER_CONTEXT_R10));
    DPRINTF(level, "r11 0x%lx         r12 0x%lx      r13 0x%lx\n",
            vmm_read_user_context(&vcpu->guest_state, USER_CONTEXT_R11),
            vmm_read_user_context(&vcpu->guest_state, USER_CONTEXT_R12),
            vmm_read_user_context(&vcpu->guest_state, USER_CONTEXT_R13));
    DPRINTF(level, "r14 0x%lx         r15 0x%lx\n",
            vmm_read_user_context(&vcpu->guest_state, USER_CONTEXT_R14),
            vmm_read_user_context(&vcpu->guest_state, USER_CONTEXT_R15));
    DPRINTF(level, "cr0 0x%lx      cr3 0x%lx   cr4 0x%lx\n",
            vmm_guest_state_get_cr0(&vcpu->guest_state, vcpu->guest_vcpu),
            vmm_guest_state_get_cr3(&vcpu->guest_state, vcpu->guest_vcpu),
            vmm_guest_state_get_cr4(&vcpu->guest_state, vcpu->guest_vcpu));
}

#else

/* Print out the context of a guest OS thread. */
void vmm_print_guest_context(int level, vmm_vcpu_t *vcpu) {
    DPRINTF(level, "================== GUEST OS CONTEXT =================\n");

    DPRINTF(level, "exit info : reason 0x%x    qualification 0x%x   instruction len 0x%x interrupt info 0x%x interrupt error 0x%x\n",
                    vmm_guest_exit_get_reason(&vcpu->guest_state), vmm_guest_exit_get_qualification(&vcpu->guest_state), vmm_guest_exit_get_int_len(&vcpu->guest_state), vmm_vmcs_read(vcpu->guest_vcpu, VMX_DATA_EXIT_INTERRUPT_INFO), vmm_vmcs_read(vcpu->guest_vcpu, VMX_DATA_EXIT_INTERRUPT_ERROR));
    DPRINTF(level, "            guest physical 0x%x     rflags 0x%x \n",
                   vmm_guest_exit_get_physical(&vcpu->guest_state), vmm_guest_state_get_rflags(&vcpu->guest_state, vcpu->guest_vcpu));
    DPRINTF(level, "            guest interruptibility 0x%x   control entry 0x%x\n",
                   vmm_guest_state_get_interruptibility(&vcpu->guest_state, vcpu->guest_vcpu), vmm_guest_state_get_control_entry(&vcpu->guest_state));

    DPRINTF(level, "eip 0x%8x\n",
                   vmm_guest_state_get_eip(&vcpu->guest_state));
    DPRINTF(level, "eax 0x%8x         ebx 0x%8x      ecx 0x%8x\n",
                   vmm_read_user_context(&vcpu->guest_state, USER_CONTEXT_EAX), vmm_read_user_context(&vcpu->guest_state, USER_CONTEXT_EBX), vmm_read_user_context(&vcpu->guest_state, USER_CONTEXT_ECX));
    DPRINTF(level, "edx 0x%8x         esi 0x%8x      edi 0x%8x\n",
                   vmm_read_user_context(&vcpu->guest_state, USER_CONTEXT_EDX), vmm_read_user_context(&vcpu->guest_state, USER_CONTEXT_ESI), vmm_read_user_context(&vcpu->guest_state, USER_CONTEXT_EDI));
    DPRINTF(level, "ebp 0x%8x\n",
                   vmm_read_user_context(&vcpu->guest_state, USER_CONTEXT_EBP));

    DPRINTF(level, "cr0 0x%x      cr3 0x%x   cr4 0x%x\n", vmm_guest_state_get_cr0(&vcpu->guest_state, vcpu->guest_vcpu), vmm_guest_state_get_cr3(&vcpu->guest_state, vcpu->guest_vcpu), vmm_guest_state_get_cr4(&vcpu->guest_state, vcpu->guest_vcpu));
}

#endif
