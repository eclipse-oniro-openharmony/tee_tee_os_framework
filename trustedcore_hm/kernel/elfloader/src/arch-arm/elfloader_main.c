/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: elfloader main function file
 * Create: 2020-12
 */
#include <autoconf.h>
#include <config.h>
#include <log.h>
#include <cpio/cpio.h>
#include <memmove.h>
#include <string.h>
#include <elf/sys_elf.h>
#include <elfloader.h>
#include <data.h>
#include <arch/smp/smp.h> // for get_current_cpu_id
#include <uidgid.h>
#include <arch-arm/random.h>
#include "io.h"
#include <mmu.h>
#include <plat/machine/devices.h>
#include <uart_register.h>
#include <snapshot.h>

#if CONFIG_KERNEL_ASLR || CONFIG_SYSSERV_ASLR
#include <arch-arm/timer.h>
#endif
#ifdef CONFIG_ARCH_AARCH64
#define UINT_SIZE_MAX UINT64_MAX
#else
#define UINT_SIZE_MAX UINT32_MAX
#endif

static uint64_t g_kernel_phys_base;
static uint64_t g_kernel_tee_base_phys;
static uint64_t g_image_start;
static struct image_info g_user_info[MAX_USER_IMAGES];

#define MAX_PH_LOADER_NUMBER 10
#define START_POOL_NEED_MEMORY addr_page_roundup(CONFIG_PT_POOL_INIT_SIZE)

#define UART_KADDR_OFFSET 21
#define COMPRESS_PROTECT_RANGE BOOT_OFFSET

extern int zuncompress(void *compressed_data, unsigned long compressed_sz, void *unpack_data, unsigned long unpack_sz,
                       void *free_mem, unsigned long free_mem_sz);
extern void set_plat_uart_func(uint64_t plat);
extern uint64_t __unzip_size;

int cfi_disabled = 1;
static uint64_t g_elfloader_max_size;
#define offsetof(st, m) ((size_t)(uintptr_t)&(((st *)0)->m))
#define LEFT_4M                     (4 << 20)
#define SIZE_15M                    (15 << 20)

struct program_header {
    uint64_t paddr;
    uint64_t vaddr;
    uint64_t memory_size;
    uint64_t file_size;
    uint64_t offset;
    uint32_t flags;
    uint32_t type;
};

uint64_t get_kernel_phys_base(void)
{
    return g_kernel_phys_base;
}

uint64_t get_kernel_tee_base_phys(void)
{
    return g_kernel_tee_base_phys;
}

static paddr_t paddr_bitclear(paddr_t addr, unsigned long bits)
{
    return (addr & (~(paddr_t)bits));
}

/* will this overflow ? */
static paddr_t addr_page_roundup(paddr_t addr)
{
    return paddr_bitclear(addr + PAGE_SIZE, PAGE_SIZE - 1);
}

static void print_gic(void)
{
    uint32_t i;
    klog(DEBUG_LOG, "gic: version=%c\n", g_plat_cfg.gic_config.version);
    if (g_plat_cfg.gic_config.version == GIC_V2_VERSION) {
        klog(DEBUG_LOG, "dist.start=0x%llx, dist.end=0x%llx\n",
             g_plat_cfg.gic_config.v2.dist.start, g_plat_cfg.gic_config.v2.dist.end);
        klog(DEBUG_LOG, "contr.start=0x%llx, contr.end=0x%llx\n",
             g_plat_cfg.gic_config.v2.contr.start, g_plat_cfg.gic_config.v2.contr.end);
    } else if (g_plat_cfg.gic_config.version == GIC_V3_VERSION) {
        klog(DEBUG_LOG, "dist.start=0x%llx, dist.end=0x%llx\n",
             g_plat_cfg.gic_config.v3.dist.start, g_plat_cfg.gic_config.v3.dist.end);
        klog(DEBUG_LOG, "redist_num=%u, redist_stride=%u\n",
             g_plat_cfg.gic_config.v3.redist_num, g_plat_cfg.gic_config.v3.redist_stride);
        for (i = 0; i < GICR_MAX_NUM; i++) {
            klog(DEBUG_LOG, "redist[%u], start=0x%llx, end=0x%llx\n", i,
                 g_plat_cfg.gic_config.v3.redist[i].start, g_plat_cfg.gic_config.v3.redist[i].end);
        }
    }
}

static void print_platform_info(void)
{
    klog(DEBUG_LOG, "boot_args_size=0x%llx\n", g_plat_cfg.boot_args_size);
    klog(DEBUG_LOG, "phys_region_size=0x%llx\n", g_plat_cfg.phys_region_size);
    klog(DEBUG_LOG, "phys_region_start=0x%llx\n", g_plat_cfg.phys_region_start);
    klog(DEBUG_LOG, "uart_addr=0x%llx\n", g_plat_cfg.uart_addr);
    klog(DEBUG_LOG, "uart_type=0x%llx\n", g_plat_cfg.uart_type);
    klog(DEBUG_LOG, "shmem_offset=0x%llx\n", g_plat_cfg.shmem_offset);
    klog(DEBUG_LOG, "shmem_size=0x%llx\n", g_plat_cfg.shmem_size);
    klog(DEBUG_LOG, "random seed=0x%lx\n", (unsigned long)g_plat_cfg.random_seed);
    klog(DEBUG_LOG, "spi_num_for_notify=%u\n", g_plat_cfg.spi_num_for_notify);
    klog(DEBUG_LOG, "plat_features=0x%llx\n", g_plat_cfg.plat_features);
    print_gic();
}

static void print_image_info(const struct image_info *image_info)
{
    if (image_info == NULL || image_info->name == NULL)
        return;
    klog(DEBUG_LOG, "Image info of %s:\n", image_info->name);

    klog(DEBUG_LOG, "\tphysical: 0x%llx - 0x%llx\n", image_info->phys_region_start, image_info->phys_region_end - 1);

    klog(DEBUG_LOG, "\tvirtual: 0x%llx - 0x%llx", image_info->virt_region_start, image_info->virt_region_end - 1);

    klog(DEBUG_LOG, "\tentry: 0x%llx\n", image_info->virt_entry);
    klog(DEBUG_LOG, "\tphys to virt offset: 0x%llx\n", image_info->phys_virt_offset);
    klog(DEBUG_LOG, "\tto_kernel_offset: 0x%llx\n", image_info->to_kernel_offset);
    klog(DEBUG_LOG, "Image->name 0x%llx\n", (unsigned long long)(uintptr_t)(image_info->name));
}

/*
 * Panic if the given address is at or after the location of the ELF loader
 */
static void check_overwrite(const char *filename __attribute__((unused)), paddr_t addr)
{
    extern char _end[];
    paddr_t elfloader_end_phys = elfloader_kaddr_to_paddr((vaddr_t)(uintptr_t)_end);
    if (addr <= elfloader_end_phys) {
        klog(DEBUG_WARNING, "Warning ... file %s might overwrite\n", filename);
        klog(DEBUG_LOG, "ELF loader at 0x%llx with limit 0x%llx\n", addr, (paddr_t)(uintptr_t)_end);
    }
}

#if CONFIG_KERNEL_ASLR || CONFIG_SYSSERV_ASLR
#define ENOEXEC 8
#ifdef CONFIG_KERNEL_ASLR
ulong_t g_aslr_kernel_offset;
ulong_t get_aslr_kernel_offset(void)
{
    return g_aslr_kernel_offset;
}
#endif
#ifdef CONFIG_SYSSERV_ASLR
ulong_t g_aslr_sysmgr_offset;
ulong_t g_aslr_filemgr_offset;
ulong_t g_aslr_sysserv_offset;
#endif

static void inc_value(void *addr, uint64_t value, int is32)
{
    if (is32)
        *(uint32_t *)addr += (uint32_t)(value & 0xFFFFFFFFUL);
    else
        *(uint64_t *)addr += value;
}

static void set_value(void *addr, uint64_t value, int is32)
{
    if (is32 != 0)
        *(uint32_t *)addr = (uint32_t)(value & 0xFFFFFFFFUL);
    else
        *(uint64_t *)addr = value;
}

static uint64_t get_relocate_offset(const void *elf_file, uint64_t vaddr)
{
    uint16_t sec_n, i;
    uint64_t sec_size, sec_off, sec_addr;
    sec_n = elf_get_num_sections(elf_file);
    for (i = 0; i < sec_n; i++) {
        sec_size        = elf_get_section_size(elf_file, i);
        sec_addr        = elf_get_section_addr(elf_file, i);
        sec_off = elf_get_section_offset(elf_file, i);
        if (vaddr >= sec_addr && (vaddr - sec_addr) < sec_size) {
            return vaddr - sec_addr + sec_off;
        }
    }
    klog(DEBUG_ERROR, "ERROR !!!!!!!!!!!!!!! addr not in elf\n");
    return 0;
}

static int relocate_rel(const struct image_info *image_info, const void *elf_file,
                        const void *rela_sec, ulong_t ent_num,
                        uint64_t offset, paddr_t out)
{
    ulong_t i;
    uint64_t off, vaddr;
    for (i = 0; i < ent_num; i++) {
        switch (elf_get_rel_type(elf_file, rela_sec, i)) {
        case R_ARM_RELATIVE:
            vaddr    = elf_get_rel_offset(elf_file, rela_sec, i);
            if (vaddr < image_info->virt_region_start || vaddr > image_info->virt_region_end) {
                klog(DEBUG_ERROR, "kaslr : reloc position out of range\n");
                return -ENOEXEC;
            }
            off = get_relocate_offset(elf_file, vaddr);
            if (off == 0)
                return -ENOEXEC;

            (void)out;
            inc_value((void *)(uintptr_t)(elf_file + off), offset, ISELF32(elf_file));
            break;
        default:
            klog(DEBUG_ERROR, "kaslr : rel type[%x] is not supported\n", elf_get_rel_type(elf_file, rela_sec, i));
            return -ENOEXEC;
        }
    }
    return 0;
}

static int relocate_rela(const struct image_info *image_info, const void *elf_file,
                         const void *rela_sec, ulong_t ent_num,
                         uint64_t offset, paddr_t out)
{
    ulong_t i;
    uint64_t off, vaddr, addend;
    for (i = 0; i < ent_num; i++) {
        switch (elf_get_rela_type(elf_file, rela_sec, i)) {
        case R_AARCH64_RELATIVE:
            vaddr = elf_get_rela_offset(elf_file, rela_sec, i);
            if (vaddr < image_info->virt_region_start || vaddr > image_info->virt_region_end) {
                klog(DEBUG_ERROR, "kernel aslr : reloc position out of range\n");
                return -ENOEXEC;
            }
            off = get_relocate_offset(elf_file, vaddr);
            if (off == 0)
                return -ENOEXEC;
            addend = elf_get_rela_addend(elf_file, rela_sec, i);
            (void)out;
            set_value((void *)(uintptr_t)(elf_file + off), addend + offset, ISELF32(elf_file));
            break;
        default:
            klog(DEBUG_ERROR, "kaslr : rela type[%x] is not supported\n", elf_get_rela_type(elf_file, rela_sec, i));
            return -ENOEXEC;
        }
    }
    return 0;
}

static int relocate(const struct image_info *image_info, const void *elf_file, ulong_t offset, paddr_t out)
{
    int ret;
    uint16_t sec_n, i;
    uint64_t sec_off, sec_len, sec_es;
    char *sec_addr = NULL;
    sec_n = elf_get_num_sections(elf_file);

    for (i = 0; i < sec_n; i++) {
        char *sec_name = elf_get_section_name(elf_file, i);
        sec_off        = elf_get_section_offset(elf_file, i);
        sec_len        = elf_get_section_size(elf_file, i);
        sec_es         = elf_get_section_entry_size(elf_file, i);
        sec_addr       = (char *)(uintptr_t)((uint64_t)(uintptr_t)elf_file + sec_off);
        ulong_t sec_num = (ulong_t)(sec_len) / (ulong_t)(sec_es);
        if (strcmp(sec_name, ".rela.dyn") == 0 && sec_es != 0) {
            ret = relocate_rela(image_info, elf_file, sec_addr, sec_num, offset, out);
            if (ret != 0)
                return ret;
        } else if (strcmp(sec_name, ".rel.dyn") == 0 && sec_es != 0) {
            ret = relocate_rel(image_info, elf_file, sec_addr, sec_num, offset, out);
            if (ret != 0)
                return ret;
        }
    }
    klog(DEBUG_ERROR, "TEE kaslr/sysserv aslr reloc done\n");
    return 0;
}

#ifdef CONFIG_KERNEL_ASLR
#ifndef align_up
#define align_up(x, alignment)                          \
        (((x) + ((alignment)-1)) & ~((alignment)-1))
#endif
#ifdef CONFIG_ARCH_AARCH32
#define KERNEL_ASLR_START 0xc0000000
#define KERNEL_ASLR_RANGE 0x20000000
#define KERNEL_ASLR_ALIGN BIT(hm_LargePageBits)
#define KERNEL_SIZE 0x100000
#else
#define KERNEL_ASLR_START 0xFFFFFF8000000000
#define KERNEL_ASLR_RANGE       0x4000000000
#define KERNEL_ASLR_ALIGN BIT(hm_LargePageBits)
#define KERNEL_SIZE 0x100000
#endif
static void get_kernel_aslr_offset()
{
    ulong_t rand = rand_get(g_plat_cfg.random_seed);
    if (rand == 0)
        klog(DEBUG_ERROR, "kernel random is unavailable\n");
    ulong_t kernel_load_off = align_up(KERNEL_LOAD_OFFSET, BIT(hm_LargePageBits));
    ulong_t total_off = KERNEL_SIZE + KERNEL_LOAD_OFFSET + kernel_load_off;
    rand = rand % (KERNEL_ASLR_RANGE - total_off);
    rand = rand & ~(KERNEL_ASLR_ALIGN - 1);
    rand += KERNEL_LOAD_OFFSET;
    ulong_t off = (ulong_t)(rand & (BIT(hm_HugePageBits) - 1));
    if (off < KERNEL_LOAD_OFFSET)
        rand += kernel_load_off;

    /* as we will reconstruct pagetables from kernel_virt_start int kernel vspace */
    if (off < ELFLOADER_MAP_SIZE)
        rand += ELFLOADER_MAP_SIZE;
    g_aslr_kernel_offset = rand + KERNEL_ASLR_START;
}
#endif

#ifdef CONFIG_SYSSERV_ASLR
#ifdef CONFIG_ARCH_AARCH32
#define SYSSERV_ASLR_START 0x400000
#define SYSSERV_ASLR_RANGE 0x20000000
#define SYSSERV_ASLR_ALIGN BIT(hm_PageBits)
#else
#define SYSSERV_ASLR_START 0x400000
#define SYSSERV_ASLR_RANGE 0x40000000
#define SYSSERV_ASLR_ALIGN BIT(hm_PageBits)
#endif
static void get_sysserv_aslr_offset()
{
    uint32_t rand = rand_get(g_plat_cfg.random_seed);
    if (rand == 0)
        klog(DEBUG_ERROR, "sysserv random is unavailable\n");

    rand = rand & ~(SYSSERV_ASLR_ALIGN - 1);
    rand = rand % SYSSERV_ASLR_RANGE;
    g_aslr_sysmgr_offset = rand + SYSSERV_ASLR_START;

    rand = rand_get(g_plat_cfg.random_seed);
    if (rand == 0)
        klog(DEBUG_ERROR, "sysserv random is unavailable\n");

    rand = rand & ~(SYSSERV_ASLR_ALIGN - 1);
    rand = rand % SYSSERV_ASLR_RANGE;
    g_aslr_filemgr_offset = rand + SYSSERV_ASLR_START;
}
#endif
#endif

/*
 * Copy the ELF sections.
 */
static void get_elf_program_header(const void *elf_file, const void *elf_head, struct program_header *ph_load,
    uint16_t *ph_load_num)
{
    uint16_t i;
    uint16_t j = 0;
    void *elf_ph = NULL;
    uint16_t phnum = elf_get_num_program_headers(elf_head);

    for (i = 0; i < phnum; i++) {
        if (j >= *ph_load_num)
            fail("ph is too large         %u\n", phnum);

        elf_ph = ISELF32(elf_file) ?
                 (Elf32_Phdr *)(&((Elf32_Phdr *)(((char *)elf_file) + ((Elf32_Ehdr *)elf_head)->e_phoff))[i]) :
                 (Elf32_Phdr *)(&((Elf64_Phdr *)(((char *)elf_file) + ((Elf64_Ehdr *)elf_head)->e_phoff))[i]);

        ph_load[j].type = ISELF32(elf_file) ? ((Elf32_Phdr *)elf_ph)->p_type : ((Elf64_Phdr *)elf_ph)->p_type;
        ph_load[j].memory_size = ISELF32(elf_file) ? ((Elf32_Phdr *)elf_ph)->p_memsz : ((Elf64_Phdr *)elf_ph)->p_memsz;

        if (ph_load[j].type != PT_LOAD || ph_load[j].memory_size == 0)
            continue;

        ph_load[j].paddr = ISELF32(elf_file) ? ((Elf32_Phdr *)elf_ph)->p_paddr : ((Elf64_Phdr *)elf_ph)->p_paddr;
        ph_load[j].vaddr = ISELF32(elf_file) ? ((Elf32_Phdr *)elf_ph)->p_vaddr : ((Elf64_Phdr *)elf_ph)->p_vaddr;
        ph_load[j].file_size = ISELF32(elf_file) ? ((Elf32_Phdr *)elf_ph)->p_filesz : ((Elf64_Phdr *)elf_ph)->p_filesz;
        ph_load[j].offset = ISELF32(elf_file) ? ((Elf32_Phdr *)elf_ph)->p_offset : ((Elf64_Phdr *)elf_ph)->p_offset;
        ph_load[j].flags = ISELF32(elf_file) ? ((Elf32_Phdr *)elf_ph)->p_flags : ((Elf64_Phdr *)elf_ph)->p_flags;
        j++;
    }
    *ph_load_num = j;
}

static uint64_t process_elf_sections(paddr_t out, const struct image_info *image_info, const void *elf_file,
                                     struct program_header *ph, uint32_t ph_load_num)
{
    uint32_t i;
    uint64_t base;
    uint64_t delta;
    uint64_t total = 0;
    uint64_t offset_in_page;
    void *dest = (void *)(uintptr_t)out;
    void *src = NULL;

    for (i = 0; i < ph_load_num; i++) {
        /* Copy the data from the file to memory */
        offset_in_page = ph[i].vaddr & (PAGE_SIZE - 1);
        base      = paddr_bitclear(ph[i].vaddr, PAGE_SIZE - 1);
        delta     = base - image_info->virt_region_start;
        if (delta > base)
            fail("base or start is error");

        src = (uint8_t *)elf_file + ph[i].offset;
        if (src < elf_file || (out + delta) < out || ((out + delta + offset_in_page) < out))
            fail("overturn in addr is error");

        if ((out + delta + offset_in_page) > (uint64_t)(uintptr_t)dest)
            if (memset(dest, 0, out + delta + offset_in_page - (paddr_t)((uintptr_t)dest)) != 0)
                fail("between old dest and new dest memory clear fail");

        dest = (void *)(uintptr_t)(out + delta + offset_in_page);
        if (dest == NULL)
            continue;

        if (memcpy(dest, src, ph[i].file_size) != 0)
            fail("copy section i=%u failed\n", i);

        if (ph[i].file_size < ph[i].memory_size)
            if (memset((char *)dest + ph[i].file_size, 0, ph[i].memory_size - ph[i].file_size) != 0)
                fail("bss memory clear fail");

        total = (uint64_t)(uintptr_t)dest - out + ph[i].memory_size;
        if (ph[i].memory_size > total)
            fail("overturn in total is error");

        dest += ph[i].memory_size;
        if (ph[i].memory_size > (uint64_t)(uintptr_t)dest)
            fail("overturn in dest is error");
    }
    return total;
}

static void copy_elf_syminfo(paddr_t out, struct image_info *info, const void *elf_file, const void *elf_head)
{
    unsigned int num_sections, i;

    if (info == NULL || elf_file == NULL)
        return;

    num_sections = elf_get_num_sections(elf_head);
    for (i = 0; i < num_sections; i++) {
        unsigned long off;
        unsigned long len;
        char *s_name = elf_get_section_name_mini(elf_file, elf_head, i);
        if (s_name == NULL)
            continue;
        off = elf_get_section_offset_mini(elf_file, elf_head, i);
        len = elf_get_section_size_mini(elf_file, elf_head, i);
        if (strcmp(".symtab", s_name) == 0) {
            if (memcpy((char *)(uintptr_t)out, (char *)(uintptr_t)elf_file + off, len) != 0)
                fail("copy symtab failed\n");
            info->p_symtab_start = out;
            info->p_symtab_end   = out + len;
            out                  = addr_page_roundup(out + len);
        }
        if (strcmp(".strtab", s_name) == 0) {
            if (memcpy((char *)(uintptr_t)out, (char *)(uintptr_t)elf_file + off, len) != 0)
                fail("copy strtab failed\n");
            info->p_strtab_start = out;
            info->p_strtab_end   = out + len;
            out                  = addr_page_roundup(out + len);
        }
    }
}

static void get_symtab_strtab_size(const void *elf_file, unsigned long *symtab_len, unsigned long *strtab_len)
{
    unsigned numSections, i;
    if (elf_file == NULL || symtab_len == NULL || strtab_len == NULL)
        return;
    numSections = elf_get_num_sections(elf_file);
    for (i = 0; i < numSections; i++) {
        unsigned long len;
        char *s_name = elf_get_section_name(elf_file, i);
        if (s_name == NULL)
            continue;
        if (strcmp(".symtab", s_name) == 0) {
            len = elf_get_section_size(elf_file, i);
            if (((len >> PAGE_BITS) + 1) > UINT_SIZE_MAX / PAGE_SIZE)
                return;
            *symtab_len = PAGE_SIZE * ((len >> PAGE_BITS) + 1);
        }
        if (strcmp(".strtab", s_name) == 0) {
            len = elf_get_section_size(elf_file, i);
            if (((len >> PAGE_BITS) + 1) > UINT_SIZE_MAX / PAGE_SIZE)
                return;
            *strtab_len = PAGE_SIZE * ((len >> PAGE_BITS) + 1);
        }
    }
}

/*
 * Add ELF info
 * @out:    Virtual address at which data will be written
 * @elf_file:    Pointer to the in-memory ELF file
 *
 * Returns a pointer to the first byte, rounded up to PAGE_SIZE, after the
 * ELF information
 */
static vaddr_t add_elf_info(vaddr_t out, const void *elf_file, int check_4k_align,
                            const struct program_header *ph_load, uint32_t ph_load_num)
{
    struct boot_ph *ph = NULL;
    vaddr_t used;
    uint32_t i;

    if (elf_file == NULL)
        return out;

    struct boot_phinfo *phinfo = (struct boot_phinfo *)(uintptr_t)out;
    phinfo->phnum              = 0;
    for (i = 0; i < ph_load_num; i++) {
        ph         = &(phinfo->ph[phinfo->phnum]);

        ph->p_type = ph_load[i].type;
        if (ph->p_type != PT_LOAD)
            continue;

        ph->p_flags = ph_load[i].flags;
        ph->p_vaddr = ph_load[i].vaddr;
        ph->p_paddr = ph_load[i].paddr;
        ph->p_filesz = ph_load[i].file_size;
        ph->p_offset = ph_load[i].offset;
        ph->p_memsz = ph_load[i].memory_size;
#if CONFIG_KERNEL_ASLR
        if (check_4k_align == 1) {
            ph->p_vaddr += g_aslr_kernel_offset;
            klog(DEBUG_ERROR, "kernel aslr has adapted\n");
            klog(DEBUG_LOG, "kernel offset: 0x%lx\n", (unsigned long)g_aslr_kernel_offset);
        }
#endif
#if CONFIG_SYSSERV_ASLR
        if (check_4k_align == 0) {
            ph->p_vaddr += g_aslr_sysserv_offset;
            klog(DEBUG_ERROR, "sysserv aslr has adapted\n");
            klog(DEBUG_LOG, "sysserv offset: 0x%lx\n", (unsigned long)g_aslr_sysserv_offset);
        }
#endif
        /* kernel segments vaddr should be aligned 4K, otherwise the pt may be insecure */
        if (check_4k_align != 0 && (ph->p_vaddr & (PAGE_SIZE - 1)) != 0)
            klog(DEBUG_ERROR, "kernel segments vaddr should be 4K aligned!\n");
        phinfo->phnum++;
    }

    used = addr_page_roundup((uintptr_t)offsetof(struct boot_phinfo, ph[i]));
    return out + used;
}
/*
 * Read the next ELF file in the CPIO archive and write it to memory.
 * @out:    Virtual address where the file page should be stored
 * @image_info:    Information about the file
 * @filename:    Name of the file
 * @filesize:    Number of bytes in the file
 * @elf_file:    Virtual address of the ELF-format input file
 *
 * Returns the virtual address just past the last byte of the file.
 */
static bool elf_file_check(const void *elf_file)
{
    int rc;
    if (ISELF32(elf_file))
        rc = elf32_check_file(elf_file);
    else
        rc = elf64_check_file(elf_file);

    switch (rc) {
    case VALID_ELF_FORM:
        return true;
    case INVALID_ELF_MAGIC:
        fail("Not an ELF file\n");
        return false;

    case INVALID_ELF_BITS:
        fail("ELF file not 64-bit format\n");
        return false;
    default:
        return true;
    }
}

static vaddr_t process_elf_file(uint64_t out, struct image_info *image_info,
                                const char *filename __attribute__((unused)),
                                uint32_t filesize __attribute__((unused)), const void *elf_file, int check_4k_align)
{
    uint64_t size;
    Elf64_Ehdr elf_head_64;
    Elf32_Ehdr elf_head_32;
    void *elf_head = NULL;
    struct program_header ph_load[MAX_PH_LOADER_NUMBER];
    uint16_t ph_load_num = MAX_PH_LOADER_NUMBER;

    if (image_info == NULL || elf_file == NULL || !elf_file_check(elf_file))
        return out;

    check_overwrite(filename, image_info->phys_region_start);
    check_overwrite(filename, image_info->phys_region_end);
    size   = image_info->phys_region_end - image_info->phys_region_start;

    if (ISELF32(elf_file)) {
        elf_head_32 = *(Elf32_Ehdr *)elf_file;
        elf_head = (void *)&elf_head_32;
    } else {
        elf_head_64 = *(Elf64_Ehdr *)elf_file;
        elf_head = (void *)&elf_head_64;
    }
    get_elf_program_header(elf_file, (const void *)elf_head, ph_load, &ph_load_num);

    uint64_t sec_size = process_elf_sections(out, image_info, elf_file, ph_load, ph_load_num);
    if (sec_size == 0 || sec_size > (size - image_info->symtab_len - image_info->strtab_len)) {
        klog(DEBUG_ERROR, "copy size error 0x%llx\n", sec_size);
        return 0;
    }
    if (memset((void *)(uintptr_t)(out + sec_size), 0,
        (size - image_info->symtab_len - image_info->strtab_len - sec_size)) != 0) {
        klog(DEBUG_ERROR, "memory clear fail\n");
        return 0;
    }

    copy_elf_syminfo(out + size - image_info->symtab_len - image_info->strtab_len, image_info, elf_file, elf_head);
    out = add_elf_info(out + size, elf_file, check_4k_align, ph_load, ph_load_num);
    return out;
}

static uint64_t get_max(uint64_t sect, uint64_t mem)
{
    if (sect > mem)
        return sect;
    return mem;
}

static uint64_t get_min(uint64_t sect, uint64_t mem)
{
    if (sect < mem)
        return sect;
    return mem;
}

static int elf_get_memory_bounds(const void *elf_file, int phys, uint64_t *min, uint64_t *max)
{
    uint64_t memory_min = UINT64_MAX;
    uint64_t memory_max = 0;
    uint16_t i;

    if (elf_check_file(elf_file) != VALID_ELF_FORM)
        return 0;

    for (i = 0; i < elf_get_num_program_headers(elf_file); i++) {
        uint64_t sect_min, sect_max;

        if (elf_get_program_header_memory_size(elf_file, i) == 0)
            continue;

        if (phys != 0)
            sect_min = elf_get_program_header_paddr(elf_file, i);
        else
            sect_min = elf_get_program_header_vaddr(elf_file, i);

        sect_max = sect_min + elf_get_program_header_memory_size(elf_file, i);

        memory_max = get_max(sect_max, memory_max);
        memory_min = get_min(sect_min, memory_min);
    }

    *min = memory_min;
    *max = memory_max;
    return 1;
}

static void read_elf_header(struct image_info *image_info, const char *filename, const void *elf_file)
{
    paddr_t phys_min;
    paddr_t phys_max;
    vaddr_t virt_min;
    paddr_t virt_max;
    int rc;
    unsigned long symtab_len = 0;
    unsigned long strtab_len = 0;

    if (image_info == NULL || filename == NULL || elf_file == NULL)
        return;

    get_symtab_strtab_size(elf_file, &symtab_len, &strtab_len);
    image_info->symtab_len = symtab_len;
    image_info->strtab_len = strtab_len;

    rc = elf_get_memory_bounds(elf_file, 1, &phys_min, &phys_max);
    if (rc != 1)
        fail("Unable to get program physical memory bounds\n");
    image_info->phys_region_start = paddr_bitclear(phys_min, PAGE_SIZE - 1);
    image_info->phys_region_end   = addr_page_roundup(phys_max) + symtab_len + strtab_len;

    rc = elf_get_memory_bounds(elf_file, 0, &virt_min, &virt_max);
    if (rc != 1)
        fail("Unable to get program virtual memory bounds\n");
    image_info->virt_region_start = paddr_bitclear(virt_min, PAGE_SIZE - 1);
    image_info->virt_region_end   = addr_page_roundup(virt_max) + symtab_len + strtab_len;

    image_info->virt_entry = elf_get_entry_point(elf_file);
    image_info->name       = filename;
}

/*
 * Read information about the next file in the CPIO archive file.
 *
 * Returns a pointer to the next CPIO header or NULL if we have reached
 * the end of the archive.
 */
static struct cpio_header *cpio_header_parse(const struct cpio_header *archive, const char **filename,
                                             uint32_t *filesize, void **data)
{
    struct cpio_header *next = NULL;
    int rc;

    rc = cpio_parse_entry(archive, filename, filesize, data, &next);
    if (rc == -1)
        fail("Bad cpio header\n");
    if (rc == 1)
        return NULL;
    return next;
}

static uint64_t get_phy_base(void)
{
    uint64_t phy_base;
    phy_base = elfloader_kaddr_to_paddr(g_kernel_phys_base);
    return phy_base;
}

/*
 * Process the ELF file for the kernel. This is the first file in the
 * archive. Returns the address of the page after the last page used for the
 * kernel
 */
static struct cpio_header *process_kernel(struct image_info *kernel_img_info,
                                          const struct cpio_header *archive, vaddr_t *out)
{
    const char *filename = NULL;
    uint32_t filesize;
    void *elf_file = NULL;
    vaddr_t file_start, file_end;

    if (kernel_img_info == NULL || archive == NULL)
        return NULL;
    struct cpio_header *next = cpio_header_parse(archive, &filename, &filesize, &elf_file);
    if (next == NULL)
        fail("No kernel found\n");
    read_elf_header(kernel_img_info, filename, elf_file);
    /*
     * We have an identify mapping, so use the kernel physical address as
     * the starting virtual address at which to store applications
     */
    uint64_t phy_base = get_phy_base();
    if (phy_base == 0)
        fail("no phy_base set!! check your platform\n");

    kernel_img_info->phys_region_start = phy_base;
    file_start = (vaddr_t)kernel_img_info->phys_region_start;

    kernel_img_info->phys_region_end = kernel_img_info->phys_region_start +
                (kernel_img_info->virt_region_end - kernel_img_info->virt_region_start);
#ifdef CONFIG_KERNEL_ASLR
    if (kernel_img_info->virt_region_start != 0)
        klog(DEBUG_ERROR, "error! kernel virt start should be 0\n");
    relocate(kernel_img_info, elf_file, g_aslr_kernel_offset, elfloader_paddr_to_vaddr(file_start));
#endif

    file_end = process_elf_file(elfloader_paddr_to_vaddr(file_start), kernel_img_info, filename, filesize, elf_file, 1);
#ifdef CONFIG_KERNEL_ASLR
    kernel_img_info->virt_region_start += g_aslr_kernel_offset;
    kernel_img_info->virt_region_end += g_aslr_kernel_offset;
    kernel_img_info->virt_entry += g_aslr_kernel_offset;
#endif
    kernel_img_info->phys_virt_offset  = file_start - kernel_img_info->virt_region_start;
    /* virtual address offset from elfloader to kernel */
    kernel_img_info->to_kernel_offset = kernel_img_info->virt_region_start - KERNEL_LOAD_OFFSET - \
                                        (uint64_t)(uintptr_t)_image_base_addr + BOOT_OFFSET;
    print_image_info(kernel_img_info);

    /*
     * All of the rest of the applications are immediately after the
     * kernel in physical memory, that is, we ignore the physical memory
     * information we are given in the ELF file.
     */
    if (out)
        *out = file_end;

    return next;
}
#ifdef CONFIG_SYSSERV_ASLR
static void reset_image_virt(vaddr_t file_start, struct image_info *ii)
{
    ii->virt_region_start += g_aslr_sysserv_offset;
    ii->virt_region_end += g_aslr_sysserv_offset;
    ii->virt_entry += g_aslr_sysserv_offset;
    ii->phys_virt_offset  = file_start - ii->virt_region_start;
}
#endif
/*
 * Process the next non-kernel ELF file in the CPIO archive
 *
 * Returns the address of the page in physical memory after this application
 */
static void process_boot_apps(struct cpio_header *next, vaddr_t out, struct image_info *image_info, int max_apps,
                              int *num_apps)
{
    const char *filename = NULL;
    uint32_t filesize;
    void *elf_file = NULL;
    int i;

    if (next == NULL || image_info == NULL)
        return;
    for (i = 0;; i++) {
        uint64_t size;

        struct image_info *ii = &image_info[i];
        next = cpio_header_parse(next, &filename, &filesize, &elf_file);
        if (next == NULL)
            break;
        if (i == max_apps)
            fail("Too many boot applications %x", i);

        read_elf_header(ii, filename, elf_file);
        size                  = ii->phys_region_end - ii->phys_region_start;
        ii->phys_region_start = elfloader_kaddr_to_paddr(out);
        ii->phys_region_end   = ii->phys_region_start + size;

        if (g_image_start != 0 && ii->phys_region_end > g_image_start)
            fail("image %s addr overlapped\n", ii->name);
        /* All the init apps are root user for now */
        ii->cred.uid = MKUID(0);
        ii->cred.gid = MKGID(0);
#ifdef CONFIG_SYSSERV_ASLR
        vaddr_t file_start = out;
        g_aslr_sysserv_offset = i == 0 ? g_aslr_sysmgr_offset : g_aslr_filemgr_offset;
        if (ii->virt_region_start != 0)
            klog(DEBUG_ERROR, "error! %s virt start should be 0\n", i == 0 ? "sysmgr" : "filemgr");
        relocate(ii, elf_file, g_aslr_sysserv_offset, file_start);
#else
        ii->phys_virt_offset  = out - ii->virt_region_start;
#endif
        out = process_elf_file(out, ii, filename, filesize, elf_file, 0);
#ifdef CONFIG_SYSSERV_ASLR
        reset_image_virt(elfloader_kaddr_to_paddr(file_start), ii);
#endif
        ii->rand_seed = rand_get(g_plat_cfg.random_seed);
        print_image_info(ii);
        /* The next application follows this one */
    }

    if (num_apps)
        *num_apps = i;
}

/* If there is problem with console, we should fail here already */
static void welcome(const void *archive __attribute__((unused)))
{
    for (int i = 0; i < 10; i++) {
        put_debug_char('.');
    }
    cfi_disabled = 1;
    klog(DEBUG_INFO, "Welcome onboard\n");
    klog(DEBUG_LOG, "%p! (%p, %p)\n", archive, _archive_start, _archive_end);
    for (int i = 0; i < 10; i++) {
        put_debug_char('.');
    }

    klog(DEBUG_INFO, "\n");
}

static void get_need_max_memory(struct cpio_header *archive, uint64_t *total_len)
{
    uint32_t i;
    uint64_t ph_need;
    uint16_t phnum;
    const char *filename = NULL;
    uint32_t filesize = 0;
    void *elf_file = NULL;

    *total_len = 0;
    for (i = 0; (i < MAX_USER_IMAGES && archive != NULL); i++) {
        archive = cpio_header_parse(archive, &filename, &filesize, &elf_file);
        phnum = elf_get_num_program_headers(elf_file);
        ph_need = addr_page_roundup((uintptr_t)offsetof(struct boot_phinfo, ph[phnum]));
        read_elf_header(&g_user_info[i], filename, elf_file);

        if (*total_len > (*total_len + (g_user_info[i].virt_region_end - g_user_info[i].virt_region_start) + ph_need))
            fail("elf need size is error %llx %llx\n", *total_len, ph_need);

        *total_len += (g_user_info[i].virt_region_end - g_user_info[i].virt_region_start) + ph_need;
    }
}

static uint64_t move_archive_to_end_addr(struct cpio_header *archive, uint64_t arch_size, void *cpio_start)
{
    uint64_t total_len;
    klog(DEBUG_LOG, "g_kernel_phys_base=0x%llx\n", g_kernel_phys_base);
    klog(DEBUG_LOG, "archive=0x%llx, arch_size=0x%llx\n",
         (unsigned long long)(uintptr_t)archive, arch_size);

    get_need_max_memory(archive, &total_len);

    klog(DEBUG_LOG, "total_len=0x%llx\n", total_len);
    if (total_len <= arch_size || total_len > g_elfloader_max_size)
        fail("total len is error 0x%llx", total_len);

    if (arch_size > UINT32_MAX || (total_len + g_kernel_phys_base) < total_len)
        fail("image size too large\n");

    if ((uint64_t)(uintptr_t)cpio_start < g_kernel_phys_base ||
        (total_len + g_kernel_phys_base) > (uint64_t)(uintptr_t)cpio_start)
        fail("memory is not enough need len is %llx, have %llx",
             (total_len + g_kernel_phys_base - g_kernel_tee_base_phys), g_elfloader_max_size);

    if (memcpy(cpio_start, archive, (uint32_t)arch_size) != 0)
        fail("copy archive fail");

    return (uint64_t)(uintptr_t)cpio_start;
}

static int is_gzip(const void *_archive)
{
    unsigned char *magic = (unsigned char *)_archive;

    if ((magic[0] == 0x1f) && (magic[1] == 0x8b))
        return 1;
    return 0;
}

static void *prepare_archive(void)
{
    unsigned long archive_size = (unsigned long)(_archive_end - _archive_start);
    int err;
    uint64_t archive_unzip_size = (uint64_t)(uintptr_t)&__unzip_size;
    for (int i = 0; i < 10; i++)
        put_debug_char('.');

    klog(DEBUG_INFO, "archive_unzip_size=0x%llx\n", archive_unzip_size);
    void *cpio_start = _image_base_addr - BOOT_OFFSET + g_elfloader_max_size \
                       - g_plat_cfg.shmem_size - archive_unzip_size;

#ifdef CONFIG_KERNEL_ASLR
    uint64_t kaslr_size = get_kaslr_pg_size(g_elfloader_max_size);
    cpio_start = cpio_start - kaslr_size;
    klog(DEBUG_INFO, "kaslr pagetable need size=0x%llx\n", kaslr_size);
#endif

    if (is_gzip(_archive_start) == 0) {
        klog(DEBUG_INFO, "Not gzipped archive\n");
        g_image_start = move_archive_to_end_addr((struct cpio_header *)_archive_start,
                                                 archive_size, cpio_start);
        return (void *)(uintptr_t)g_image_start;
    }

    klog(DEBUG_INFO, "g_plat_cfg.phys_region_size=0x%llx\n", g_plat_cfg.phys_region_size);
    klog(DEBUG_INFO, "g_elfloader_max_size=0x%llx\n", g_elfloader_max_size);
    klog(DEBUG_LOG, "cpio_start=0x%llx\n", (unsigned long long)(uintptr_t)cpio_start);
    if ((uint64_t)(uintptr_t)cpio_start - COMPRESS_PROTECT_RANGE < (uint64_t)(uintptr_t)_archive_start)
        fail("phys_region_size too small\n");
    err = zuncompress(_archive_start, archive_size, cpio_start, archive_unzip_size,
                      cpio_start - COMPRESS_PROTECT_RANGE, COMPRESS_PROTECT_RANGE);
    if (err != 0)
        fail("gunzip failed: %d\n", err);

    g_image_start = (uint64_t)(uintptr_t)cpio_start;
    klog(DEBUG_WARNING, "Successfuly unzipped\n");
    return cpio_start;
}

static void aslr_init()
{
#ifdef CONFIG_KERNEL_ASLR
    get_kernel_aslr_offset();
#endif
#ifdef CONFIG_SYSSERV_ASLR
    get_sysserv_aslr_offset();
#endif
}

static uint64_t g_uart_addr_used;
static void loader_init()
{
    uint64_t uart_kaddr_aligin = ALIGN_DOWN(UART6_KADDR, ELFLOADER_PAGE);
    uint64_t uart_paddr = g_plat_cfg.uart_addr;
    uint64_t uart_paddr_aligin = ALIGN_DOWN(uart_paddr, ELFLOADER_PAGE);
    g_uart_addr_used = uart_kaddr_aligin + uart_paddr - uart_paddr_aligin;
    /* init uart function */
    register_uart(g_plat_cfg.uart_type);
    set_uart_addr(g_uart_addr_used);
    welcome(NULL);
    print_platform_info();
    g_kernel_tee_base_phys = (uint64_t)((uintptr_t)_image_base_addr - BOOT_OFFSET);
    g_kernel_phys_base = addr_page_roundup((paddr_t)(uintptr_t)_archive_start) + START_POOL_NEED_MEMORY;
#ifdef CONFIG_ARCH_AARCH32
    aslr_init();
    init_kernel_vspace();
#endif

    if (memset(&g_elfloader_lock, 0, sizeof(struct hm_spinlock)) != 0)
        fail("memset failed\n");

}

static void barrier()
{
#ifdef CONFIG_ARCH_AARCH64
    asm volatile("ic ialluis; dsb ish; isb");
#else
    MCR("p15, 0, %0, c7, c1", 0);
    asm volatile("dsb ish; isb");
#endif
}

static void aslr_done()
{
    rand_clear();
}

static void acquire_lock()
{
    klog(DEBUG_LOG, "Acquire lock for cpu zero ...\n");
    hm_spinlock_acquire(&g_elfloader_lock);
    klog(DEBUG_LOG, "lock acuired!\n");
}

struct image_info *get_user_img_info()
{
    return g_user_info;
}

int main(int32_t argc __attribute__((unused)), char **tee_size, char **tee_addr)
{
    vaddr_t out;
    g_plat_cfg.phys_region_size  = (uint64_t)(uintptr_t)tee_size;
    g_plat_cfg.phys_region_start = (uint64_t)(uintptr_t)tee_addr;
    g_plat_cfg.shmem_offset = g_plat_cfg.phys_region_size - g_plat_cfg.shmem_size;

    g_elfloader_max_size         = ELFLOADER_MAP_SIZE > g_plat_cfg.phys_region_size ? \
                                   g_plat_cfg.phys_region_size : ELFLOADER_MAP_SIZE;
    void *archive = NULL;
    loader_init();
#if defined(CONFIG_ASCEND_PLATFORM)
#define TIMER0_INDEX 0
#define TRNG_INDEX   1
    map_devices(g_plat_cfg.extend_datas_io.plat_io_regions[TIMER0_INDEX].start);
    map_devices(g_plat_cfg.extend_datas_io.plat_io_regions[TRNG_INDEX].start);
#endif

#ifdef CONFIG_ARCH_AARCH64
    v8_dma_flush_range((uint64_t)(uintptr_t)_image_base_addr - BOOT_OFFSET,
                       (uint64_t)(uintptr_t)_image_base_addr - BOOT_OFFSET +
                       g_elfloader_max_size);
#else
    dma_flush_range((uint64_t)(uintptr_t)_image_base_addr - BOOT_OFFSET,
                    (uint64_t)(uintptr_t)_image_base_addr - BOOT_OFFSET + g_elfloader_max_size);
#endif
    archive = prepare_archive();
    if (archive == NULL)
        fail("CPIO archive is unavailable\n");
    cpu_on(0);
    welcome(archive);
#ifdef CONFIG_ARCH_AARCH64
    aslr_init();
#endif
    struct cpio_header *next = process_kernel(&g_kernel_info, archive, &out);
    if (next == NULL)
        fail("process kernel failed\n");

    process_boot_apps(next, out, g_user_info, ARRAY_SIZE(g_user_info), &g_boot_num_app);
    if ((paddr_t)(uintptr_t)_image_base_addr < BOOT_OFFSET)
        fail("image_base_addr less than BOOT_OFFSET, maybe config errors\n");

    barrier();
    acquire_lock();
#ifdef CONFIG_ARCH_AARCH64
    init_kernel_vspace(&g_kernel_info);
#endif
#if CONFIG_MAX_NUM_NODES > 1
    smp_boot();
#endif

    aslr_done();
    /* The cpu boot entry of the current cpu do not have to change sp */
    ASSERT(get_current_cpu_id() == 0);
    boot_kernel(g_uart_addr_used, g_elfloader_max_size);
    return 0;
}
