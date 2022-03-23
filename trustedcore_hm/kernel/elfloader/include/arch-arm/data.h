/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: elfloader mmu data API declares
 * Create: 2020-12
 */
#ifndef ELFLOADER_DATA_H
#define ELFLOADER_DATA_H

#include <autoconf.h>
#include <config.h>
#include <types.h>
#include <arch/machine/registerset.h>
#include <arch/lib/barrier.h>
#include <arch/object/structures.h>
#include <elfloader.h>
#include <kernel/spinlock.h>

#ifdef CONFIG_ARCH_AARCH64
#include <arch/arm/64/spinlock.h>
#else
#include <arch/arm/32/spinlock.h>
#endif

extern char core_stacks[BIT(PAGE_BITS)] ALIGN(BIT(PAGE_BITS));

typedef pte_t pte_array_t[BIT(PT_INDEX_BITS)];

#ifndef ALIGN_UP
#define ALIGN_UP(x, alignment) (((x) + ((alignment) - 1)) & ~((alignment) - 1))
#endif

#ifndef ALIGN_DOWN
#define ALIGN_DOWN(x, align)  ((x) & ~((align)-1))
#endif

#define ELFLOADER_PAGE         0x200000
extern int g_boot_num_app;
void flush_cache_all(void);
#ifdef CONFIG_ARCH_AARCH64
void v8_dma_flush_range(uint64_t, uint64_t);
#else
void dma_flush_range(uint64_t, uint64_t);
#endif

/*
 * elf binary info that initialized by elfloader-main.c
 * and used by Hong Meng kernel init
 */
extern struct image_info g_kernel_info;
extern struct platform_info g_plat_cfg;

extern void arm_enable_mmu(void);
extern char _start[];
extern char _end[];
extern char _archive_start[];
extern char _archive_end[];
extern char _image_base_addr[];
extern struct hm_spinlock g_elfloader_lock;

typedef void (*init_kernel_t)(struct elfloader_to_kernel_args *boot_args);

static inline void cpu_on(unsigned int id)
{
#ifdef CONFIG_ARCH_AARCH64
    uint64_t nid = (uint64_t)id;
    MSR("tpidr_el1", nid);
#else
    unsigned int nid = id;
    MCR("p15, 0, %0, c13, c0, 4", nid);
#endif
    dmb(sy);
}

static inline void init_cpu_status(int cid)
{
    (void)cid;
}

void load_images(struct image_info *kernel_info, struct image_info *user_info, int max_user_images, int *num_images);
kaddr_t elfloader_kaddr_to_paddr(vaddr_t vaddr);
vaddr_t elfloader_paddr_to_vaddr(paddr_t paddr);

#ifdef CONFIG_ARCH_AARCH64
void init_kernel_vspace(const struct image_info *kernel_info);
#else
void init_kernel_vspace(void);
#endif

void arm_switch_on_mmu(void);

void boot_kernel(uint64_t uart_used, uint64_t elfloader_map_size);
void init_cpus(void);
void smp_boot(void);
struct image_info *get_user_img_info();

#ifdef CONFIG_KERNEL_ASLR
uint64_t get_kaslr_pg_size(uint64_t map_size);
#endif

/* Secure monitor call */
uint32_t smc(uint32_t, uint32_t, uint32_t, uint32_t);
void map_devices(uint64_t dst_addr);
#endif
