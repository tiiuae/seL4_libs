/*
 * Copyright 2017, Data61, CSIRO (ABN 41 687 119 230)
 * Copyright 2022, Technology Innovation Institute
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sel4/sel4.h>
#include <sel4/simple_types.h>
#include <sel4debug/unknown_syscall.h>

void debug_unknown_syscall_message(int (*printfn)(const char *format, ...),
                                   seL4_Word* mrs)
{
    /* See section 6.2.2.1 of the "seL4 Reference Manual" Version 8.0.0
     * https://sel4.systems/Info/Docs/seL4-manual-8.0.0.pdf
     *
     * and
     * 
     * seL4/libsel4/sel4_arch_include/aarch32/sel4/sel4_arch/constants.h 
     */

    seL4_Word r0      = mrs[seL4_UnknownSyscall_R0];
    seL4_Word r1      = mrs[seL4_UnknownSyscall_R1];
    seL4_Word r2      = mrs[seL4_UnknownSyscall_R2];
    seL4_Word r3      = mrs[seL4_UnknownSyscall_R3];
    seL4_Word r4      = mrs[seL4_UnknownSyscall_R4];
    seL4_Word r5      = mrs[seL4_UnknownSyscall_R5];
    seL4_Word r6      = mrs[seL4_UnknownSyscall_R6];
    seL4_Word r7      = mrs[seL4_UnknownSyscall_R7];
    seL4_Word faultIP = mrs[seL4_UnknownSyscall_FaultIP];
    seL4_Word sp      = mrs[seL4_UnknownSyscall_SP];
    seL4_Word lr      = mrs[seL4_UnknownSyscall_LR];
    seL4_Word cpsr    = mrs[seL4_UnknownSyscall_CPSR];
    int syscall       = (int) mrs[seL4_UnknownSyscall_Syscall];

    printfn(" R0      = 0x%" SEL4_PRIx_word "\n"
            " R1      = 0x%" SEL4_PRIx_word "\n"
            " R2      = 0x%" SEL4_PRIx_word "\n"
            " R3      = 0x%" SEL4_PRIx_word "\n"
            " R4      = 0x%" SEL4_PRIx_word "\n"
            " R5      = 0x%" SEL4_PRIx_word "\n"
            " R6      = 0x%" SEL4_PRIx_word "\n"
            " R7      = 0x%" SEL4_PRIx_word "\n"
            " FaultIP = 0x%" SEL4_PRIx_word "\n"
            " SP      = 0x%" SEL4_PRIx_word "\n"
            " LR      = 0x%" SEL4_PRIx_word "\n"
            " CPSR    = 0x%" SEL4_PRIx_word "\n"
            " Syscall = %"   SEL4_PRIi_word "\n",
            r0, r1, r2, r3, r4, r5, r6, r7, 
            faultIP, sp, lr, cpsr, syscall);
}
