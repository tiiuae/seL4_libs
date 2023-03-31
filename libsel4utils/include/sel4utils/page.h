/*
 * Copyright 2017, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <vspace/page.h>
#include <utils/arith.h>

#define UTILS_NUM_PAGE_SIZES SEL4_NUM_PAGE_SIZES

static inline DEPRECATED("Use sel4_valid_size_bits") bool
utils_valid_size_bits(size_t size_bits)
{
    return sel4_valid_size_bits(size_bits);
}


/* Similar macros to libutils/page.h.
 * Placed here to keep libutils "external" 
 * to seL4-specific libraries. */

#define SEL4_PAGE_BITS (SEL4_SMALLEST_PAGE_BITS)
#define SEL4_PAGE_SIZE (BIT(SEL4_PAGE_BITS))

#define SEL4_PAGE_ALIGN(addr)      ALIGN_DOWN(addr, SEL4_PAGE_BITS)
#define SEL4_IS_PAGE_ALIGNED(addr) IS_ALIGNED(addr, SEL4_PAGE_BITS)