/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2009-2019. All rights reserved.
 * Description: Function implementation.
 * Author: Hisilicon
 * Create: 2009-12-16
 */

#include "media_mem.h"
#include "sec_mmz.h"
#include "drv_tee_mem_common.h"
#include "hi_tee_drv_os_hal.h"
#include "mmz_intf.h"

#define MAX_ZONE_NUM  4

unsigned long g_zone_start[MAX_ZONE_NUM] = {0};
unsigned long g_zone_size[MAX_ZONE_NUM]  = {0};
unsigned int  g_zone_type[MAX_ZONE_NUM]  = {0};

static unsigned int g_zone_num = 0;


int  match_zone_type(const char *name)
{
    int mem_type = -1;

    if (!strcmp(name, "NONSEC-MMZ")) {
        mem_type = NORMAL_MMZ_TYPE;
    }else if(!strcmp(name, "SEC-MMZ")) {
        mem_type = SEC_MMZ_TYPE;
    }else if(!strcmp(name, "SEC-MMZ2")) {
        mem_type = SEC_MMZ2_TYPE;
    }else if(!strcmp(name, "SMMU-MMZ")) {
        mem_type = SEC_SMMU_MMZ_TYPE;
    }else {
        PRINTK_CA("Can't match any zone type!\n");
    }

    return mem_type;
}

hil_mmz_t *new_zone(const char *name, unsigned long phys_start, unsigned long size, unsigned int alloc_type)
{
    hil_mmz_t *mmz = NULL;
    unsigned int j = 0;
    unsigned int mem_type;

    if (!phys_start || !size || (phys_start >= (phys_start + size)))
        return NULL;

    if (g_zone_num >= MAX_ZONE_NUM) {
        PRINTK_CA("More than Max zone numbersi, forbid!\n");
        return NULL;
    }

    mem_type = match_zone_type(name);
    if (mem_type == -1) {
        return NULL;
    }
    for (; j < g_zone_num; j++) {
        if (alloc_type != SECURE_MEM)
                continue;

        if (!g_zone_start[j] || !g_zone_size[j]) {
                continue;
        }

        if (((phys_start >= g_zone_start[j]) &&
            (phys_start < (g_zone_start[j] + g_zone_size[j]))) ||
            (((phys_start + size) > g_zone_start[j]) &&
             ((phys_start + size) <= (g_zone_start[j] + g_zone_size[j])))) {
                PRINTK_CA("The zone area should not intersect!\n");
                return NULL;
        }
    }

    mmz = hil_mmz_create(name, alloc_type, phys_start, size);
    if (mmz == NULL) {
        PRINTK_CA("Create mem zone failed!\n");
        return NULL;
    }

    if (hil_mmz_register(mmz) != 0) {
        PRINTK_CA("%s, %d, mmz=0x%x\n", __func__, __LINE__, mmz);
        hil_mmz_destroy(mmz);
        return NULL;
    }

    if (alloc_type == SECURE_MEM) {
        g_zone_start[g_zone_num] = phys_start;
        g_zone_size[g_zone_num]  = size;
        g_zone_type[g_zone_num]  = mem_type;
        g_zone_num++;
    }

    return mmz;
}

int is_sec_mmz(unsigned long phys_addr)
{
    int mem_type = 0;
    unsigned int i = 0;

    for (; i < g_zone_num ; i++) {
        if ((phys_addr >= g_zone_start[i]) && (phys_addr < (g_zone_start[i] + g_zone_size[i]))) {
                mem_type = g_zone_type[i];
                break;
        }
    }

    return mem_type;
}

void delete_zone(hil_mmz_t *zone)
{
    hil_mmz_unregister(zone);
    hil_mmz_destroy(zone);
}

unsigned long new_mmb(const char *name, int size, unsigned int alloc_type, const char *zone_name)
{
    hil_mmb_t *mmb = NULL;

    mmb = hil_mmb_alloc(name, size, alloc_type, zone_name);
    if (mmb == NULL) {
        PRINTK_CA("%s, %d: Fail to new mmb %s(0x%X Bytes) from zone %s, alloc_type=%d\n", __func__, __LINE__,
                  name ? name : "null", size, zone_name ? zone_name : "null", alloc_type);
        mmz_dump();
        return MMB_ADDR_INVALID;
    }

    return (unsigned long)hil_mmb_phys(mmb);
}

void delete_mmb(unsigned long addr)
{
    hil_mmb_t *mmb = NULL;

    mmb = hil_mmb_getby_phys((unsigned long)addr);
    if (mmb == NULL)
        return;

    hil_mmb_free(mmb);
}

void *remap_mmb(unsigned long addr)
{
    hil_mmb_t *mmb = NULL;
    void *virt = NULL;
    unsigned long offset;

    mmb = hil_mmb_getby_phys((unsigned long)addr);
    if (mmb == NULL) {
        PRINTK_CA("%s, %d\n", __func__, __LINE__);
        return NULL;
    }
    virt = hil_mmb_map2kern(mmb);
    if (virt == NULL) {
        PRINTK_CA("%s  %d  map failed!\n", __func__, __LINE__);
        return NULL;
    }
    offset = addr - mmb->phys_addr;
    virt = (void *)((unsigned long)(uintptr_t)virt + offset);

    return virt;
}

void *remap_mmb_cached(unsigned long addr)
{
    hil_mmb_t *mmb = NULL;
    void *virt = NULL;
    unsigned long offset;

    mmb = hil_mmb_getby_phys((unsigned long)addr);
    if (mmb == NULL) {
        PRINTK_CA("%s, %d\n", __func__, __LINE__);
        return NULL;
    }

    virt =  hil_mmb_map2kern_cached(mmb);
    if (virt == NULL) {
        PRINTK_CA("%s  %d  map failed!\n", __func__, __LINE__);
        return NULL;
    }
    offset = addr - mmb->phys_addr;
    virt = (void *)((unsigned long)(uintptr_t)virt + offset);

    return virt;
}

void *remap_mmb_uk(unsigned long addr)
{
    hil_mmb_t *mmb = NULL;
    void *virt = NULL;
    unsigned long offset;

    mmb = hil_mmb_getby_phys((unsigned long)addr);
    if (mmb == NULL) {
        PRINTK_CA("%s, %d\n", __func__, __LINE__);
        return NULL;
    }
    virt = hil_mmb_map2uk(mmb);
    if (virt == NULL) {
        PRINTK_CA("%s  %d  map failed!\n", __func__, __LINE__);
        return NULL;
    }
    offset = addr - mmb->phys_addr;

    virt = (void *)(uintptr_t)((unsigned long)(uintptr_t)virt + offset);

    return virt;
}

void *remap_mmb_uk_cached(unsigned long addr)
{
    hil_mmb_t *mmb = NULL;
    void *virt = NULL;
    unsigned long offset;

    mmb = hil_mmb_getby_phys((unsigned long)addr);
    if (mmb == NULL) {
        PRINTK_CA("%s, %d\n", __func__, __LINE__);
        return NULL;
    }

    virt = hil_mmb_map2uk_cached(mmb);
    if (virt == NULL) {
        PRINTK_CA("%s  %d  map failed!\n", __func__, __LINE__);
        return NULL;
    }

    offset = addr - mmb->phys_addr;
    virt = (void *)(uintptr_t)((unsigned long)(uintptr_t)virt + offset);

    return virt;
}

int unmap_mmb(const void *mapped_addr)
{
    void *mmb = NULL;

    mmb = hil_mmb_getby_kvirt(mapped_addr);
    if (mmb == NULL) {
        PRINTK_CA("%s, %d\n", __func__, __LINE__);
        return -1;
    }

    return hil_mmb_unmap(mmb);
}

int unmap_mmb_uk(const void *mapped_addr)
{
    hil_mmb_t *mmb = NULL;

    mmb = hil_mmb_getby_uvirt(mapped_addr);
    if (mmb == NULL) {
        PRINTK_CA("%s, %d\n", __func__, __LINE__);
        return -1;
    }

    return hil_mmb_unmap_uk(mmb);
}

int flush_mmb(unsigned long addr)
{
    void *mmb = NULL;

    mmb = hil_mmb_getby_phys(addr);

    hil_mmb_flush_l2cached(mmb);

    return 0;
}

void mmz_dump(void)
{
    hil_mmz_dump();
}

