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

#include "vmm/vmm.h"
#include <stdio.h>
#include <elf.h>

#ifdef CONFIG_ARCH_X86_64
#define ELF_HEADER_SIZE 512
typedef struct Elf64_Header vmm_elf_header_t;
#else
#define ELF_HEADER_SIZE 256
typedef struct Elf32_Header vmm_elf_header_t;
#endif

#define ISELF32(elfFile) ( ((struct Elf32_Header*)elfFile)->e_ident[EI_CLASS] == ELFCLASS32 )
#define ISELF64(elfFile) ( ((struct Elf64_Header*)elfFile)->e_ident[EI_CLASS] == ELFCLASS64 )

/*
	Reads the elf header and elf program headers from a file
		when given a sufficiently large memory buffer
*/
int vmm_read_elf_headers(void *buf, vmm_t *vmm, FILE *file, size_t buf_size);
