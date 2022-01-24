/*
 * Copyright 2017, Data61, CSIRO (ABN 41 687 119 230)
 * Copyright 2022, Technology Innovation Institute
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sel4/sel4.h>
#include <sel4/simple_types.h>
#include <sel4debug/user_exception.h>

void debug_user_exception_message(int (*printfn)(const char *format, ...),
                                  seL4_Word* mrs)
{
    /* See section 6.2.3.1 of the "seL4 Reference Manual" Version 8.0.0
     * https://sel4.systems/Info/Docs/seL4-manual-8.0.0.pdf
     *
     * and
     * 
     * seL4/libsel4/sel4_arch_include/aarch32/sel4/sel4_arch/constants.h 
     */

    seL4_Word faultIP = mrs[seL4_UserException_FaultIP];
    seL4_Word sp      = mrs[seL4_UserException_SP];
    seL4_Word cpsr    = mrs[seL4_UserException_CPSR];
    int num           = (int) mrs[seL4_UserException_Number];
    int code          = (int) mrs[seL4_UserException_Code];

    printfn(" FaultIP          = 0x%" SEL4_PRIx_word "\n"
            " SP               = 0x%" SEL4_PRIx_word "\n"
            " CPSR             = 0x%" SEL4_PRIx_word "\n"
            " Exception number = %"   SEL4_PRIi_word "\n"
            " Exception code   = %"   SEL4_PRIi_word "\n",
            faultIP, sp, cpsr, num, code);
}
