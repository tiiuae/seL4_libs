/*
 * Copyright 2017, Data61, CSIRO (ABN 41 687 119 230)
 * Copyright 2022, Technology Innovation Institute
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <stdint.h>
#include <inttypes.h>

struct st_frame_record {
    struct st_frame_record *parent;
    uintptr_t *return_addr;
};

void print_stack_trace(void);

