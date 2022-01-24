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
    /* See section 6.2.2.2 of the "seL4 Reference Manual" Version 8.0.0
     * https://sel4.systems/Info/Docs/seL4-manual-8.0.0.pdf
     *
     * and
     * 
     * seL4/libsel4/sel4_arch_include/ia32/sel4/sel4_arch/constants.h 
     */

    seL4_Word eax      = mrs[seL4_UnknownSyscall_EAX];
    seL4_Word ebx      = mrs[seL4_UnknownSyscall_EBX];
    seL4_Word ecx      = mrs[seL4_UnknownSyscall_ECX];
    seL4_Word edx      = mrs[seL4_UnknownSyscall_EDX];
    seL4_Word esi      = mrs[seL4_UnknownSyscall_ESI];
    seL4_Word edi      = mrs[seL4_UnknownSyscall_EDI];
    seL4_Word ebp      = mrs[seL4_UnknownSyscall_EBP];
    seL4_Word faultIP  = mrs[seL4_UnknownSyscall_FaultIP];
    seL4_Word sp       = mrs[seL4_UnknownSyscall_SP];
    seL4_Word flags    = mrs[seL4_UnknownSyscall_FLAGS];
    int syscall        = (int) mrs[seL4_UnknownSyscall_Syscall];

    printfn(" EAX      = 0x%" SEL4_PRIx_word "\n"
            " EBX      = 0x%" SEL4_PRIx_word "\n"
            " ECX      = 0x%" SEL4_PRIx_word "\n"
            " EDX      = 0x%" SEL4_PRIx_word "\n"
            " ESI      = 0x%" SEL4_PRIx_word "\n"
            " EDI      = 0x%" SEL4_PRIx_word "\n"
            " EBP      = 0x%" SEL4_PRIx_word "\n"
            " FaultIP  = 0x%" SEL4_PRIx_word "\n"
            " SP       = 0x%" SEL4_PRIx_word "\n"
            " FLAGS    = 0x%" SEL4_PRIx_word "\n"
            " Syscall  = %"   SEL4_PRIi_word "\n",
            eax, ebx, ecx, edx, esi, edi, ebp, 
            faultIP, sp, flags, syscall);
}
