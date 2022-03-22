/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: elfloader struct definitions and function declares
 * Create: 2021-02
 */

#ifndef _ELFLOADER_H_
#define _ELFLOADER_H_

#include <types.h>
#include <uapi/api/mm_common.h>
#include <uidgid.h>

#include "plat_cfg_public.h" /* definition of struct platform_info */

typedef uint64_t vaddr_t;
/*
 * constants for Elf32_Phdr.p_flags
 */
#ifndef PF_X
#define PF_X        1    /* readable segment */
#endif

#ifndef PF_W
#define PF_W        2    /* writeable segment */
#endif

#ifndef PF_R
#define PF_R        4    /* executable segment */
#endif

struct image_info {
    paddr_t phys_region_start;
    paddr_t phys_region_end;
    paddr_t p_symtab_start;
    paddr_t p_symtab_end;
    paddr_t p_strtab_start;
    paddr_t p_strtab_end;
    unsigned long symtab_len;
    unsigned long strtab_len;

    vaddr_t virt_region_start;
    vaddr_t virt_region_end;
    vaddr_t  virt_entry;
    uint64_t phys_virt_offset;
    uint64_t to_kernel_offset;
    uint64_t rand_seed;
    const char *name;
    cred_t cred;
};

/* Information extracted from an ELF file */
struct boot_ph {
    uint64_t    p_vaddr;
    uint64_t    p_paddr;
    uint64_t    p_filesz;
    uint64_t    p_offset;
    uint64_t    p_memsz;
    uint32_t    p_flags;
    uint32_t    p_type;
} PACKED;

/* Program header information from an ELF file */
#define RESERVED_LEN 3
struct boot_phinfo {
    uint16_t phnum;
    uint16_t reserved[RESERVED_LEN];
    struct boot_ph ph[0];
} PACKED;

struct ns_kernel_info {
    uint32_t    r0;
    uint32_t    r1;
    uint32_t    r2;
    uint32_t    pc;
    uint32_t    cpsr;
};

struct elfloader_to_kernel_args {
    struct image_info *user_img_info;
    int num_apps;
    struct image_info *kernel_img_info;
    struct platform_info *plat_cfg_info;
    uint64_t uart_paddr;
    uint64_t uart_used;
    uint64_t elfloader_map_size;
    uint64_t rand_num;
};

#ifdef CONFIG_ARCH_AARCH32
extern struct ns_kernel_info g_ns_info;
#endif

uint64_t get_kernel_phys_base(void);
uint64_t get_kernel_tee_base_phys(void);

extern struct image_info g_kernel_info;
extern struct platform_info g_plat_cfg;
int psci_cpu_on(unsigned long target_cpu, unsigned long entry_point, unsigned long context_id);

#endif
