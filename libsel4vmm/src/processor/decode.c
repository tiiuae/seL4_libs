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

/* x86 fetch/decode/emulate code

Author: W.A.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "vmm/debug.h"
#include "vmm/platform/guest_vspace.h"
#include "vmm/platform/guest_memory.h"
#include "vmm/guest_state.h"
#include "vmm/processor/platfeature.h"

#include <vmm/processor/msr.h>

/* TODO are these defined elsewhere? */
#define IA32_PDE_SIZE(pde)      (pde & BIT(7))
#define IA32_PDE_PRESENT(pde)   (pde & BIT(0))
#define IA32_PTE_ADDR(pte)      (pte & 0xFFFFF000)
#define IA32_PDPTE_ADDR(pdpte)  (pdpte & 0xC0000000)
#define IA32_PDE_ADDR(pde)      (pde & 0xFFE00000)
#define IA32_PSE_ADDR(pse)      (pse & 0xFFC00000)

#define IA32_OPCODE_S(op) (op & BIT(0))
#define IA32_OPCODE_D(op) (op & BIT(1))
#define IA32_OPCODY_BODY(op) (op & 0b11111100)
#define IA32_MODRM_REG(m) ((m & 0b00111000) >> 3)

#define SEG_MULT (0x10)

#define EXTRACT_BITS(num, x, y) ((MASK(x) & ((num) >> (y))))

/* Get a word from a guest physical address */
inline static seL4_Word guest_get_phys_word(vmm_t *vmm, uintptr_t addr) {
    seL4_Word val;
    vmm_guest_vspace_touch(&vmm->guest_mem.vspace, addr, sizeof(seL4_Word),
            vmm_guest_get_phys_data_help, &val);

    return val;
}

/* Fetch a guest's instruction */
int vmm_fetch_instruction(vmm_vcpu_t *vcpu, uintptr_t eip, uintptr_t cr3, int len, uint8_t *buf)
{
    /* Walk page tables to get physical address of instruction */
    uintptr_t instr_phys = 0;
    uintptr_t cr4 = vmm_guest_state_get_cr4(&vcpu->guest_state, vcpu->guest_vcpu);

#ifndef CONFIG_ARCH_X86_64
    /* ensure that PAE is not enabled */
    if (vmm_guest_state_get_cr4(&vcpu->guest_state, vcpu->guest_vcpu) & X86_CR4_PAE) {
        ZF_LOGE("Do not support walking PAE paging structures");
        return -1;
    }
#endif

    /* Number of instructions on the next page */
    int extra_inst = 0;
    int read_instr = len;

    if ((eip >> seL4_PageBits) != ((eip + len) >> seL4_PageBits)) {
        extra_inst = (eip + len) % BIT(seL4_PageBits);
        read_instr -= extra_inst;
    }

    /* Assume a 4-level paging scheme */
    if (cr4 & X86_CR4_PAE)
    {
        /* assert that pcid is off */
        assert(!(cr4 & X86_CR4_PCIDE));

        uint64_t eip_47_39 = EXTRACT_BITS(eip, 9, 39);  /* Bits 47:39 of linear address */
        uint64_t eip_38_30 = EXTRACT_BITS(eip, 9, 30);  /* Bits 38:30 of linear address */
        uint64_t eip_29_21 = EXTRACT_BITS(eip, 9, 21);  /* Bits 29:21 of linear address */
        uint64_t eip_20_0 = EXTRACT_BITS(eip, 21, 0);   /* Bits 20:0 of linear address */

        uint64_t pml4e = guest_get_phys_word(vcpu->parent_vmm, cr3 | (eip_47_39 << 3));

        assert(IA32_PDE_PRESENT(pml4e));

        uint64_t pdpte = guest_get_phys_word(vcpu->parent_vmm, IA32_PTE_ADDR(pml4e) | (eip_38_30 << 3));

        assert(IA32_PDE_PRESENT(pdpte));

        /* If this maps a 1GB page, then we can fetch the instruction now. */
        if(IA32_PDE_SIZE(pdpte)) {
            instr_phys = IA32_PDPTE_ADDR(pdpte) + EXTRACT_BITS(eip, 29, 0);
            goto fetch;
        }

        uint64_t pde = guest_get_phys_word(vcpu->parent_vmm, IA32_PTE_ADDR(pdpte) | (eip_29_21 << 3));

        assert(IA32_PDE_PRESENT(pde));

        /* If this maps a 2MB page, then we can fetch the instruction now. */
        if(IA32_PDE_SIZE(pde)) {
            instr_phys = IA32_PDE_ADDR(pde) + eip_20_0;
            goto fetch;
        }

        uint64_t pte = guest_get_phys_word(vcpu->parent_vmm, IA32_PTE_ADDR(pde) | (eip_20_0 << 3));

        /* If this maps a 4KB page, then we can fetch the instruction now. */
        if(IA32_PDE_SIZE(pte)) {
            instr_phys = IA32_PTE_ADDR(pte) + EXTRACT_BITS(eip, 11, 0);
            goto fetch;
        }

        return -1;
    }
    /* 32-bit paging scheme */
    else
    {
        uint32_t pdi = eip >> 22;
        uint32_t pti = (eip >> 12) & 0x3FF;

        uint32_t pde = guest_get_phys_word(vcpu->parent_vmm, cr3 + pdi * 4);

        assert(IA32_PDE_PRESENT(pde)); /* WTF? */

        if (IA32_PDE_SIZE(pde)) {
            /* PSE is used, 4M pages */
            instr_phys = (uintptr_t)IA32_PSE_ADDR(pde) + (eip & 0x3FFFFF);
        } else {
            /* 4k pages */
            uint32_t pte = guest_get_phys_word(vcpu->parent_vmm,
                                               (uintptr_t)IA32_PTE_ADDR(pde) + pti * 4);
            assert(IA32_PDE_PRESENT(pte));

            instr_phys = (uintptr_t)IA32_PTE_ADDR(pte) + (eip & 0xFFF);
        }
    }

fetch:
    /* Fetch instruction */
    vmm_guest_vspace_touch(&vcpu->parent_vmm->guest_mem.vspace, instr_phys, read_instr,
            vmm_guest_get_phys_data_help, buf);

    if (extra_inst > 0) {
        vmm_fetch_instruction(vcpu, eip + read_instr, cr3, extra_inst, buf + read_instr);
    }

    return 0;
}

/* Returns 1 if this byte is an x86 instruction prefix */
static int is_prefix(uint8_t byte) {
    switch (byte) {
        case 0x26:
        case 0x2e:
        case 0x36:
        case 0x3e:
#ifdef CONFIG_ARCH_X86_64
        case 0x40 ... 0x4f:
#endif
        case 0x64:
        case 0x65:
        case 0x67:
        case 0x66:
            return 1;
    }

    return 0;
}

static int is_high_reg_prefix(uint8_t byte) {
    switch (byte) {
        case 0x44:
        case 0x4c:
        case 0x4d:
            return 1;
    }
    return 0;
}

static void debug_print_instruction(uint8_t *instr, int instr_len) {
    printf("instruction dump: ");
    for (int j = 0; j < instr_len; j++) {
        printf("%2x ", instr[j]);
    }
    printf("\n");
}

/* Partial support to decode an instruction for a memory access
   This is very crude. It can break in many ways. */
int vmm_decode_instruction(uint8_t *instr, int instr_len, int *reg, seL4_Word *imm, int *op_len) {
    /* First loop through and check prefixes */
    int oplen = 1; /* Operand length */
    int reg_mod = 0;
    int i;
    for (i = 0; i < instr_len; i++) {
        if (is_prefix(instr[i])) {
            if (instr[i] == 0x66) {
                /* 16 bit modifier */
                oplen = 2;
            }
            if (is_high_reg_prefix(instr[i])) {
                reg_mod = 8;
            }
        } else {
            /* We've hit the opcode */
            break;
        }
    }
    assert(i < instr_len); /* We still need an opcode */

    uint8_t opcode = instr[i];
    //uint8_t opcode_ex = 0;
    if (opcode == 0x0f) {
        printf("can't emulate instruction with multi-byte opcode!\n");
        debug_print_instruction(instr, instr_len);
        assert(0); /* We don't handle >1 byte opcodes */
    }
    if (oplen != 2 && IA32_OPCODE_S(opcode)) {
        oplen = 4;
    }

    uint8_t modrm = instr[++i];
    switch (opcode) {
        case 0x88:
        case 0x89:
        case 0x8a:
        case 0x8b:
        case 0x8c:
            // Mov with register
            *reg = IA32_MODRM_REG(modrm) + reg_mod;
            *op_len = oplen;
            break;
        case 0xc6:
        case 0xc7:
            // Mov with immediate
            *reg = -1;
            *op_len = oplen;
            uint32_t immediate = 0;
            for (int j = 0; j < oplen; j++) {
                immediate <<= 8;
                immediate |= instr[instr_len - j - 1];
            }
            *imm = immediate;
            break;
        default:
            printf("can't emulate this instruction!\n");
            debug_print_instruction(instr, instr_len);
            assert(0);
    }

    return 0;
}

/*
   Useful information: The GDT loaded by the Linux SMP trampoline looks like:
0x00: 00 00 00 00 00 00 00 00
0x08: 00 00 00 00 00 00 00 00
0x10: ff ff 00 00 00 9b cf 00 <- Executable 0x00000000-0xffffffff
0x18: ff ff 00 00 00 93 cf 00 <- RW data    0x00000000-0xffffffff
*/

/* Interpret just enough virtual 8086 instructions to run trampoline code.
   Returns the final jump address.

   For 64-bit guests, this function first emulates the 8086 instructions, and then
   also emulates the 32-bit instructions before returning the final jump address.
   NOTE: This function does not emulate the "call verify_cpu" function, since in
         order to get this far, a 64-bit guest would have to make it through init
         code, thus verifying the cpu.
 */
uintptr_t vmm_emulate_realmode(guest_memory_t *gm, uint8_t *instr_buf,
                               uint16_t *segment, uintptr_t eip, uint32_t len, guest_state_t *gs,
                               int m66_set, vmm_vcpu_t *vcpu)
{
    /* We only track one segment, and assume that code and data are in the same
       segment, which is valid for most trampoline and bootloader code */
    uint8_t *instr = instr_buf;
    assert(segment);

    while (instr - instr_buf < len) {
        uintptr_t mem = 0;
        uint32_t lit = 0;
        /* Since 64-bit guests emulate two sections, the second section is already in 32-bit mode,
         * thus every memory read/write will automatically be 4 bytes. This allows the caller to
         * pass in an operating mode
         */
        int m66 = m66_set;

        uint32_t base = 0;
        uint32_t limit = 0;

        if (*instr == 0x66) {
            m66 = 1;
            instr++;
        }

        if (*instr == 0x0f) {
            instr++;
            if (*instr == 0x01) {
                instr++;
                if (*instr == 0x1e) {
                    // lidtl
                    instr++;
                    memcpy(&mem, instr, 2);
                    mem += *segment * SEG_MULT;
                    instr += 2;

                    /* Limit is first 2 bytes, base is next 4 bytes */
                    vmm_guest_vspace_touch(&gm->vspace, mem,
                            2, vmm_guest_get_phys_data_help, &limit);
                    vmm_guest_vspace_touch(&gm->vspace, mem + 2,
                            4, vmm_guest_get_phys_data_help, &base);
                    DPRINTF(4, "lidtl %p\n", (void*)mem);

                    vmm_guest_state_set_idt_base(gs, base);
                    vmm_guest_state_set_idt_limit(gs, limit);
                } else if (*instr == 0x16) {
                    // lgdtl
                    instr++;
                    memcpy(&mem, instr, 2);
                    mem += *segment * SEG_MULT;
                    instr += 2;

                    /* Limit is first 2 bytes, base is next 4 bytes */
                    vmm_guest_vspace_touch(&gm->vspace, mem,
                            2, vmm_guest_get_phys_data_help, &limit);
                    vmm_guest_vspace_touch(&gm->vspace, mem + 2,
                            4, vmm_guest_get_phys_data_help, &base);
                    DPRINTF(4, "lgdtl %p; base = %x, limit = %x\n", (void*)mem,
                            base, limit);

                    vmm_guest_state_set_gdt_base(gs, base);
                    vmm_guest_state_set_gdt_limit(gs, limit);
                } else {
                    //ignore
                    instr++;
                }
            }
#ifdef CONFIG_ARCH_X86_64
            else if (*instr == 0x22) {
                // mov eax crX
                instr++;
                seL4_Word eax = vmm_read_user_context(gs, USER_CONTEXT_EAX);

                if (*instr == 0xc0) {
                    vmm_guest_state_set_cr0(gs, eax);
                    DPRINTF(4, "cr0 %lx\n", (long unsigned int)eax);
                }
                if (*instr == 0xd8) {
                    vmm_guest_state_set_cr3(gs, eax);
                    DPRINTF(4, "cr3 %lx\n", (long unsigned int)eax);
                }
                if (*instr == 0xe0) {
                    vmm_guest_state_set_cr4(gs, eax);
                    DPRINTF(4, "cr4 %lx\n", (long unsigned int)eax);
                }
            }
            else if (*instr == 0x30) {
                // wrmsr
                instr++;
                seL4_Word eax = vmm_read_user_context(gs, USER_CONTEXT_EAX);
                seL4_Word ecx = vmm_read_user_context(gs, USER_CONTEXT_ECX);
                seL4_Word edx = vmm_read_user_context(gs, USER_CONTEXT_EDX);
                if (MSR_EFER == ecx) {
                    vmm_vmcs_write(vcpu->guest_vcpu, VMX_GUEST_EFER, (edx << 32) | eax);
                    DPRINTF(4, "wrmsr %lx %lx\n", ecx, (edx << 32) | eax);
                }
            }
#endif
            else {
                //ignore
                instr++;
            }
        } else if (*instr == 0xea) {
            /* Absolute jmp */
            instr++;
            uint32_t base = 0;
            uintptr_t jmp_addr = 0;
            if (m66) {
                // base is 4 bytes
                /* Make the wild assumptions that we are now in protected mode
                   and the relevant GDT entry just covers all memory. Therefore
                   the base address is our absolute address. This just happens
                   to work with Linux and probably other modern systems that
                   don't use the GDT much. */
                memcpy(&base, instr, 4);
                instr += 4;
                jmp_addr = base;
                memcpy(segment, instr, 2);
            } else {
                memcpy(&base, instr, 2);
                instr += 2;
                memcpy(segment, instr, 2);
                jmp_addr = *segment * SEG_MULT + base;
            }
            instr += 2;
            DPRINTF(4, "absolute jmpf $%p, cs now %04x\n", (void*)jmp_addr, *segment);
            if (((int64_t)jmp_addr - (int64_t)(len + eip)) >= 0) {
                vmm_guest_state_set_cs_selector(gs, *segment);
                return jmp_addr;
            } else {
                instr = jmp_addr - eip + instr_buf;
            }
        } else {
            switch (*instr) {
                case 0xa1:
                    /* mov offset memory to eax */
                    instr++;
#ifdef CONFIG_ARCH_X86_64
                    memcpy(&mem, instr, 4);
                    instr += 4;
#else
                    memcpy(&mem, instr, 2);
                    instr += 2;
                    mem += *segment * SEG_MULT;
#endif
                    DPRINTF(4, "mov %lx, eax\n", mem);
                    uint32_t eax;
                    vmm_guest_vspace_touch(&gm->vspace, mem,
                            4, vmm_guest_get_phys_data_help, &eax);
                    vmm_set_user_context(gs, USER_CONTEXT_EAX, eax);
                    break;
#ifdef CONFIG_ARCH_X86_64
                case 0xb8:
                    /* mov const to eax */
                    instr++;
                    memcpy(&mem, instr, 4);
                    instr += 4;
                    DPRINTF(4, "mov %lx, eax\n", mem);
                    vmm_set_user_context(gs, USER_CONTEXT_EAX, mem);
                    break;
                case 0xb9:
                    /* mov const to ecx */
                    instr++;
                    memcpy(&mem, instr, 4);
                    instr += 4;
                    DPRINTF(4, "mov %lx, ecx\n", mem);
                    vmm_set_user_context(gs, USER_CONTEXT_ECX, mem);
                    break;
                case 0x8b:
                    /* mov offset memory to edx */
                    instr++;
                    if (*instr == 0x15) {
                        instr++;
                        memcpy(&mem, instr, 4);
                        instr += 4;
                        uint32_t edx;
                        vmm_guest_vspace_touch(&gm->vspace, mem,
                                               4, vmm_guest_get_phys_data_help, &edx);
                        DPRINTF(4, "mov %x, edx\n", edx);
                        vmm_set_user_context(gs, USER_CONTEXT_EDX, edx);
                    }
                    break;
                case 0x81:
                    instr++;
                    if (*instr = 0xc4) {
                        /* add lit to rsp */
                        instr++;
                        memcpy(&mem, instr, 4);
                        instr += 4;
                        seL4_Word esp = vmm_guest_state_get_esp(gs, mem);
                        esp += mem;
                        vmm_guest_state_set_esp(gs, esp);
                        DPRINTF(4, "add %lx, rsp\n", mem);
                    }
                    break;
#endif
                case 0xc7:
                    instr++;
                    if (*instr == 0x06) { // modrm
                        int size;
                        instr++;
                        /* mov literal to memory */
                        memcpy(&mem, instr, 2);
                        mem += *segment * SEG_MULT;
                        instr += 2;
                        if (m66) {
                            memcpy(&lit, instr, 4);
                            size = 4;
                        } else {
                            memcpy(&lit, instr, 2);
                            size = 2;
                        }
                        instr += size;
                        DPRINTF(4, "mov $0x%x, %p\n", lit, (void*)mem);
                        vmm_guest_vspace_touch(&gm->vspace, mem,
                                size, vmm_guest_set_phys_data_help, &lit);
                    }
                    break;
                case 0xba:
#ifdef CONFIG_ARCH_X86_64
                    /* mov const to edx */
                    instr++;
                    memcpy(&mem, instr, 4);
                    instr += 4;
                    DPRINTF(4, "mov %lx, edx\n", mem);
                    vmm_set_user_context(gs, USER_CONTEXT_EDX, mem);
#else
                    //?????mov literal to dx
                    /* ignore */
                    instr += 2;
#endif
                    break;
                case 0xbc:
#ifdef CONFIG_ARCH_X86_64
                    // mov lit esp
                    instr++;
                    memcpy(&mem, instr, 4);
                    instr += 4;
                    DPRINTF(4, "mov %lx, esp\n", mem);
                    vmm_guest_state_set_esp(gs, mem);
#endif
                    break;
                case 0x8c:
                    /* mov from sreg. ignore */
                    instr += 2;
                    break;
                case 0x8e:
#ifdef CONFIG_ARCH_X86_64
                    // mov eax/edx -> segment register
                    instr++;

                    seL4_Word val = 0;

                    if ((*instr == 0xc0) || (*instr == 0xd0) || (*instr == 0xd8)) {
                        val = vmm_read_user_context(gs, USER_CONTEXT_EAX);
                    }
                    else if ((*instr == 0xc2) || (*instr == 0xd2) || (*instr == 0xda)
                             || (*instr == 0xe2) || (*instr == 0xea))
                    {
                        val = vmm_read_user_context(gs, USER_CONTEXT_EDX);
                    }

                    /* Mask everything but lowest 16 bits */
                    val &= 0xffff;

                    if ((*instr == 0xd0) || (*instr == 0xd2)) {
                        vmm_guest_state_set_ss_selector(gs, val);
                        DPRINTF(4, "ss %lx\n", (long unsigned int)val);
                    }
                    else if ((*instr == 0xd8) || (*instr == 0xda)) {
                        vmm_guest_state_set_ds_selector(gs, val);
                        DPRINTF(4, "ds %lx\n", (long unsigned int)val);
                    }
                    else if ((*instr == 0xc0) || (*instr == 0xc2)) {
                        vmm_guest_state_set_es_selector(gs, val);
                        DPRINTF(4, "es %lx\n", (long unsigned int)val);
                    }
                    else if (*instr == 0xe2) {
                        vmm_guest_state_set_fs_selector(gs, val);
                        DPRINTF(4, "fs %lx\n", (long unsigned int)val);
                    }
                    else if (*instr == 0xea) {
                        vmm_guest_state_set_gs_selector(gs, val);
                        DPRINTF(4, "gs %lx\n", (long unsigned int)val);
                    }

                    instr++;
#else
                    /* mov to/from sreg. ignore */
                    instr += 2;
#endif
                    break;
#ifdef CONFIG_ARCH_X86_64
                case 0x75:
                    /* jne */
                case 0x85:
                    /* test eax, eax */
                    instr += 2;
                    break;
                case 0xe8:
                    /* call rel */
                    instr += 3;
                    break;
#endif
                default:
                    /* Assume this is a single byte instruction we can ignore */
                    instr++;
            }
        }

        DPRINTF(6, "read %zu bytes\n", (size_t)(instr - instr_buf));
    }

    return 0;
}
