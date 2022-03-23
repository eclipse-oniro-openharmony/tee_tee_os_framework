/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2009-2019. All rights reserved.
 * Description: Function implementation.
 * Author: Hisilicon
 * Create: 2009-12-16
 */

#include "media_mem.h"
#include "sec_mmz.h"
#include "tee_drv_mem_layout.h"
#include "hi_tee_drv_os_hal.h"

#define MMZ_DBG_LEVEL 0x0
#define mmz_trace(level, s, params...) do { \
    if (level & MMZ_DBG_LEVEL) \
    PRINTK_CA("[%s, %d]: " s "\n", \
          __FUNCTION__, __LINE__, params);\
} while (0)

#define mmz_trace_func() mmz_trace(0x02, "%s", __FILE__)

#ifndef PAGE_SIZE
#define PAGE_SIZE    (1 << 12)
#endif
#define MMZ_GRAIN       PAGE_SIZE

#define mmz_align2(x, g)      ((((x) + (g) - 1) / (g)) * (g))
#define mmz_grain_align(x)    mmz_align2(x, MMZ_GRAIN)
#define mmz_length2grain(len) (mmz_grain_align(len) / MMZ_GRAIN)

#define SZ_1K 1024
#define HIL_MMZ_FMT_S "PHYS(0x%x, 0x%x), nBYTES=%dKB,   NAME=\"%s\""
#define hil_mmz_fmt_arg(p) (p)->phys_start,(p)->phys_start+(p)->nbytes-1, \
                (p)->nbytes / SZ_1K, (p)->name

#define HIL_MMB_FMT_S "phys(0x%08lX, 0x%08lX), kvirt=0x%p, flags=0x%08lX, length=%luKB,    name =\"%s\""
#define hil_mmb_fmt_arg(p) (p)->phys_addr,mmz_grain_align((p)->phys_addr+ \
                (p)->length)-1,(p)->kvirt,(p)->flags, \
                (p)->length / SZ_1K, (p)->name


/* flags */
#define HIL_MMB_MAP2KERN          (1<<0)
#define HIL_MMB_MAP2KERN_CACHED   (1<<1)
#define HIL_MMB_MAP2UK            (1<<2)
#define HIL_MMB_MAP2UK_CACHED     (1<<3)
#define HIL_MMB_RELEASED          (1<<4)

struct hi_tee_hal_mutex g_mmz_lock;

static LIST_HEAD(mmz_list);

static int g_anony = 0;

static hil_mmb_t *mach_mmb_by_phys(unsigned long addr)
{
    hil_mmb_t *p = NULL;
    hil_mmz_t *__mach_mmb_zone__ = NULL;
    list_for_each_entry(__mach_mmb_zone__, &mmz_list, list) {
        hil_mmb_t *__mach_mmb__ = NULL;
        list_for_each_entry(__mach_mmb__, &__mach_mmb_zone__->mmb_list, list) {
            if (((uintptr_t)__mach_mmb__->phys_addr <= (uintptr_t)(addr)) &&
                (((uintptr_t)__mach_mmb__->phys_addr + __mach_mmb__->length) > (uintptr_t)(addr))) {
                p = __mach_mmb__;
                break;
            }
        }
        if (p != NULL) {
            break;
        }
    }
    return p;
}

static hil_mmb_t *mach_mmb_by_virt(const void *virt)
{
    hil_mmb_t *p = NULL;
    hil_mmz_t *__mach_mmb_zone__ = NULL;
    list_for_each_entry(__mach_mmb_zone__, &mmz_list, list) {
        hil_mmb_t *__mach_mmb__ = NULL;
        list_for_each_entry(__mach_mmb__, &__mach_mmb_zone__->mmb_list, list) {
            if (((uintptr_t)__mach_mmb__->kvirt <= (uintptr_t)(virt)) &&
                (((uintptr_t)__mach_mmb__->kvirt + __mach_mmb__->length) > (uintptr_t)(virt))) {
                p = __mach_mmb__;
                break;
            }
        }
        if (p != NULL) {
            break;
        }
    }
    return p;
}
static inline void mmz_mutex_init(struct hi_tee_hal_mutex *lock)
{
    int ret;

    ret = hi_tee_drv_hal_mutex_init("g_mmz_lock", lock);
    if (ret) {
        PRINTK_CA("Create mutex failed(0x%x).\n", ret);
    }
}

static inline void mmz_mutex_lock(struct hi_tee_hal_mutex *lock)
{
    hi_tee_drv_hal_mutex_lock(lock);
}

static inline void mmz_mutex_unlock(struct hi_tee_hal_mutex *lock)
{
    hi_tee_drv_hal_mutex_unlock(lock);
}

static void *mmz_alloc(unsigned long size)
{
    if (!size)
        return NULL;

    return hi_tee_drv_hal_malloc(size);
}

// Deallocates or frees a memory block
static void mmz_free(void *memblock)
{
    hi_tee_drv_hal_free(memblock);
    memblock = NULL;
}

static int mmz_check(hil_mmz_t *zone)
{
    hil_mmz_t *p = NULL;
    unsigned long start, end ;

    unsigned long new_start = zone->phys_start;
    unsigned long new_end = zone->phys_start + zone->nbytes;

    if (zone->nbytes == 0) {
        return -1;
    }

    list_for_each_entry(p, &mmz_list, list) {
        start = p->phys_start;
        end = p->phys_start + p->nbytes;

        if (new_start >= end) {
            continue;
        } else if ((new_start < start) && (new_end <= start)) {
            continue;
        }

        PRINTK_CA("ERROR: Conflict MMZ:\n");
        PRINTK_CA("MMZ new:   " HIL_MMZ_FMT_S "\n", hil_mmz_fmt_arg(zone));
        PRINTK_CA("MMZ exist: " HIL_MMZ_FMT_S "\n", hil_mmz_fmt_arg(p));
        PRINTK_CA("Add new MMZ failed!\n");
        return -1;
    }

    return 0;
}

static unsigned long _find_fixed_region(unsigned long *region_len, hil_mmz_t *mmz, unsigned long size)
{
    unsigned long start, len;
    unsigned long fixed_start = 0;
    unsigned long blank_len = 0;
    long long tmp;
    long fixed_len = -1;
    hil_mmb_t *p = NULL;

    mmz_trace_func();

    /* align to phys address first! */
    start = mmz_align2(mmz->phys_start, MMZ_GRAIN);
    len = mmz_grain_align(size);  // size to align to 1M
    tmp = (long long)len;

    list_for_each_entry(p, &mmz->mmb_list, list) {
        hil_mmb_t *next = NULL;
        mmz_trace(4, "p->phys_addr=0x%08lX p->length = %luKB \t",
                    p->phys_addr, p->length/SZ_1K);
        next = list_entry(p->list.next, typeof(*p), list);
        mmz_trace(4, ",next = 0x%08lX\n\n", next->phys_addr);

        /* //if p is the first entry or not */
        if (list_first_entry(&mmz->mmb_list, typeof(*p), list) == p) {
            blank_len = p->phys_addr - start;
            if ((blank_len < fixed_len) && (blank_len >= len)) {
                fixed_len = blank_len;
                fixed_start = start;
                mmz_trace(4, "%d: fixed_region: start=0x%08lX, len=%luKB\n", __LINE__,
                      fixed_start, fixed_len/SZ_1K);
            }
        }

        start = mmz_align2((p->phys_addr + p->length), MMZ_GRAIN);  // start align to usr's align
        if ((start < mmz->phys_start) || (start > (mmz->phys_start + mmz->nbytes))) {
            return 0;
        }

        /* //if we have to alloc after the last node */
        if (list_is_last(&p->list, &mmz->mmb_list)) {
            blank_len = mmz->phys_start + mmz->nbytes - start;
            if ((blank_len < fixed_len) && (blank_len >= len)) {
                fixed_len = blank_len;
                fixed_start = start;
                mmz_trace(4, "%d: fixed_region: start=0x%08lX, len=%luKB\n", __LINE__,
                      fixed_start, fixed_len/SZ_1K);
                break;
            } else {
                if (fixed_len != -1)
                    goto out;
                fixed_start = 0;
                mmz_trace(4, "%d: fixed_region: start=0x%08lX, len=%luKB\n", __LINE__,
                      fixed_start, fixed_len/SZ_1K);
                goto out;
            }
        }

        // blank is too little
        if ((start + len) > next->phys_addr) {
            mmz_trace(4, "start=0x%08lX ,len=%lu,next=0x%08lX\n",
                        start, len, next->phys_addr);
            continue;
        }

        blank_len = next->phys_addr - start;
        if ((blank_len < fixed_len) && (blank_len >= len)) {
            fixed_len = blank_len;
            fixed_start = start;
            mmz_trace(4, "%d: fixed_region: start=0x%08lX, len=%luKB\n", __LINE__,
                  fixed_start, fixed_len/SZ_1K);
        }
    }

    tmp = tmp + (long long)start;
    if ((mmz_grain_align(start+len) <= (mmz->phys_start + mmz->nbytes))
        && (start >= mmz->phys_start) && (start < (mmz->phys_start + mmz->nbytes))
        && (tmp > (long long)start) && (tmp <= (long long)(mmz->phys_start + mmz->nbytes))) {
        fixed_len = len;
        fixed_start = start;
        mmz_trace(4, "%d: fixed_region: start=0x%08lX, len=%luKB\n",
              __LINE__, fixed_start, fixed_len/SZ_1K);
    } else {
        fixed_start = 0;
        mmz_trace(4, "%d: fixed_region: start=0x%08lX, len=%luKB\n",
              __LINE__, fixed_start, len/SZ_1K);
    }

out:
    *region_len = len;

    return fixed_start;
}


static int _do_mmb_alloc(hil_mmb_t *mmb)
{
    hil_mmb_t *p = NULL;

    mmz_trace_func();

    /* add mmb sorted */
    list_for_each_entry(p, &mmb->zone->mmb_list, list) {
        if (mmb->phys_addr < p->phys_addr) {
            break;
        }

        if (mmb->phys_addr == p->phys_addr) {
            PRINTK_CA("ERROR: media-mem allocator bad in %s! (%s, %d)",
                mmb->zone->name, __FUNCTION__, __LINE__);
        }
    }
    list_add(&mmb->list, p->list.prev);

    mmz_trace(1, HIL_MMB_FMT_S, hil_mmb_fmt_arg(mmb));

    return 0;
}

static hil_mmb_t *mmb_alloc(const char *name, unsigned long size,
                unsigned int alloc_type, const char *mmz_name)
{
    hil_mmz_t *mmz = NULL;
    hil_mmb_t *mmb = NULL;
    unsigned long start ;
    unsigned long region_len = 0;
    unsigned long fixed_start = 0;
    long fixed_len = -1;
    hil_mmz_t *fixed_mmz = NULL;

    mmz_trace_func();

    if ((size == 0) || (size > MEM_LIMIT_SIZE) || ((alloc_type != SECURE_MEM) && (alloc_type != NON_SECURE_MEM))) {
        PRINTK_CA("%s: invalid alloc type!", __FUNCTION__);
        return NULL;
    }
    size = mmz_grain_align(size);

    list_for_each_entry(mmz, &mmz_list, list) {
        if (alloc_type != mmz->alloc_type ||
            ((mmz_name != NULL) && (*mmz_name != '\0') && strncmp(mmz_name, mmz->name, HIL_MAX_NAME_LEN)) ||
            ((mmz_name == NULL) && (g_anony == 1) && (strncmp("anonymous", mmz->name, HIL_MAX_NAME_LEN)))) {
            continue;
        }

        mmz_trace(1, HIL_MMZ_FMT_S, hil_mmz_fmt_arg(mmz));

        start = _find_fixed_region(&region_len, mmz, size);
        if ((fixed_len > region_len) && (start != 0)) {
            fixed_len   = region_len;
            fixed_start = start;
            fixed_mmz = mmz;
        }
    }

    mmb = mmz_alloc(sizeof(hil_mmb_t));
    if (fixed_mmz == NULL || mmb == NULL || memset_s(mmb, sizeof(hil_mmb_t), 0, sizeof(hil_mmb_t)) != EOK) {
        PRINTK_CA("%s: malloc failed! fixed_mmz:%p mmb:%p", __FUNCTION__, fixed_mmz, mmb);
        goto exit;
    }

    mmb->zone = fixed_mmz;
    mmb->phys_addr = fixed_start;
    mmb->length = size;
    (name != NULL) ? (strlcpy(mmb->name, name, sizeof(mmb->name))) : (strlcpy(mmb->name, "--", sizeof("--")));
    if (_do_mmb_alloc(mmb)) {
        goto exit;
    }

    return mmb;
exit:
    if (mmb != NULL) {
        mmz_free(mmb);
        mmb = NULL;
    }

    return NULL;
}

static void *mmb_remap_cached(unsigned long pa, unsigned long size)
{
    unsigned int va_addr ;
    /* 0 indicat remap succeed and va equal with pa */
    va_addr = (unsigned int)(uintptr_t)hi_tee_drv_hal_remap((unsigned int)pa, (unsigned int)size, true, 1);
    if (va_addr == 0) {
        return NULL;
    } else {
        return (void *)(uintptr_t)va_addr;
    }
}

static void *mmb_remap_nocache(unsigned long pa, unsigned long size)
{
    unsigned int va_addr ;
    /* 0 indicat remap succeed and va equal with pa */
    va_addr = (unsigned int)(uintptr_t)hi_tee_drv_hal_remap((unsigned int)pa, (unsigned int)size, true, 0);
    if (va_addr == 0)
        return NULL;
    else
        return (void *)(uintptr_t)va_addr;
}

/* cache_mode: 0, non_cache; 1, cache */
static void *mmb_remap_uk(unsigned long long pa, unsigned long long size, unsigned int cache_mode)
{
    int result;
    int prot;
    int drv_pid;
    unsigned int ta_pid;
    unsigned int ta_vaddr = 0;
    unsigned int drv_vaddr;
    unsigned int ret;

    drv_pid = hm_getpid();
    if (drv_pid < 0) {
        tloge("get drv pid failed!\n");
        return NULL;
    }

    ret = SRE_TaskSelf(&ta_pid);
    if (ret != 0) {
        tloge("get ta pid failed!\n");
        return NULL;
    }

    /* secure_mode: 0, secure; 1, non_secure */
    result = sre_mmap((paddr_t)pa, (unsigned int)size, &drv_vaddr, 0, cache_mode);
    if (result != 0) {
        tloge("sre_map failed. paddr=0x%llX, rc=%d\n", pa, result);
        return NULL;
    }

    if (drv_map_from_task((unsigned int)drv_pid, drv_vaddr, (unsigned int)size, ta_pid, &ta_vaddr, &prot)) {
        tloge("drv_map_from_task failed!\n");
        if (sre_unmap(drv_vaddr, (unsigned int)size)) {
            tloge("unmap failed!\n");
        }
        return NULL;
    }

    if (sre_unmap(drv_vaddr, (unsigned int)size)) {
        tloge("unmap failed!\n");
    }

    return (void *)ta_vaddr;
}

static void *mmb_remap_uk_cached(unsigned long long pa, unsigned long long size)
{
    return mmb_remap_uk(pa, size, 1);
}

static void *mmb_remap_uk_nocache(unsigned long long pa, unsigned long long size)
{
    return mmb_remap_uk(pa, size, 0);
}

static void mmb_unmap(void *va, unsigned long size, unsigned long flags)
{
    (void *)flags;
    hi_tee_drv_hal_unmap(va, size);
}

static int mmb_unmap_uk(void *va, unsigned long long size, unsigned long flags)
{
    unsigned int ret;
    unsigned int ta_pid;

    (void *)flags;

    ret = SRE_TaskSelf(&ta_pid);
    if (ret != 0) {
        tloge("get ta pid failed!\n");
        return -1;
    }

    if (__task_unmap_from_ns_page(ta_pid, (unsigned int)(uintptr_t)va, (unsigned int)size)) {
        tloge("unmap from task failed!\n");
        return -1;
    }
    return 0;
}

static void *mmb_map2kern(hil_mmb_t *mmb, unsigned long cached)
{
    if (mmb->flags & HIL_MMB_MAP2KERN) {
        if ((cached * HIL_MMB_MAP2KERN_CACHED) != (mmb->flags & HIL_MMB_MAP2KERN_CACHED)) {
            PRINTK_CA("mmb<%s> already kernel-mapped %s, can not be re-mapped as %s.", mmb->name,
                      (mmb->flags & HIL_MMB_MAP2KERN_CACHED) ? "cached" : "non-cached",
                      (cached) ? "cached" : "non-cached");
            return NULL;
        }

        mmb->map_ref++;

        return mmb->kvirt;
    }

    if (cached) {
        mmb->flags |= HIL_MMB_MAP2KERN_CACHED;
        mmb->kvirt = mmb_remap_cached(mmb->phys_addr, mmb->length);
    } else {
        mmb->flags &= ~HIL_MMB_MAP2KERN_CACHED;
        mmb->kvirt = mmb_remap_nocache(mmb->phys_addr, mmb->length);
    }

    if (mmb->kvirt) {
        mmb->flags |= HIL_MMB_MAP2KERN;
        mmb->map_ref++;
    }

    return mmb->kvirt;
}

static void *mmb_map2uk(hil_mmb_t *mmb, unsigned long cached)
{
    if (mmb->flags & HIL_MMB_MAP2UK) {
        if ((cached * HIL_MMB_MAP2UK_CACHED) != (mmb->flags & HIL_MMB_MAP2UK_CACHED)) {
            PRINTK_CA("mmb<%s> already uk-mapped %s, can not be re-mapped as %s.", mmb->name,
                      (mmb->flags & HIL_MMB_MAP2UK_CACHED) ? "cached" : "non-cached",
                      (cached) ? "cached" : "non-cached");
            return NULL;
        }

        mmb->u_map_ref++;
        mmb->map_ref++;
        return mmb->uvirt;
    }

    if (cached) {
        mmb->flags |= HIL_MMB_MAP2UK_CACHED;
        mmb->uvirt = mmb_remap_uk_cached(mmb->phys_addr, mmb->length);
    } else {
        mmb->flags &= ~HIL_MMB_MAP2UK_CACHED;
        mmb->uvirt = mmb_remap_uk_nocache(mmb->phys_addr, mmb->length);
    }

    if (mmb->uvirt) {
        mmb->flags |= HIL_MMB_MAP2UK;
        mmb->map_ref++;
        mmb->u_map_ref++;
    }

    return mmb->uvirt;
}

static int mmb_free(hil_mmb_t *mmb)
{
    if ((mmb->flags & HIL_MMB_MAP2KERN_CACHED)
        || (mmb->flags & HIL_MMB_MAP2UK_CACHED)) {
        if (mmb->kvirt)
            hi_tee_drv_hal_dcache_flush((void *)mmb->kvirt, mmb->length);
        if (mmb->uvirt)
            hi_tee_drv_hal_dcache_flush((void *)mmb->uvirt, mmb->length);
    }

    list_del(&mmb->list);
    mmz_free(mmb);

    return 0;
}

static int g_init_cnt = 0;
hil_mmz_t *hil_mmz_create(const char *name, unsigned int alloc_type, unsigned long phys_start, unsigned long nbytes)
{
    hil_mmz_t *p = NULL;

    mmz_trace_func();

    if (name == NULL) {
        PRINTK_CA("%s: 'name' can not be zero!", __FUNCTION__);
        return NULL;
    }

    if ((alloc_type != SECURE_MEM) && (alloc_type != NON_SECURE_MEM)) {
        PRINTK_CA("%s: invalid alloc type!", __FUNCTION__);
        return NULL;
    }

    p = mmz_alloc(sizeof(hil_mmz_t));
    if (p == NULL) {
        PRINTK_CA("%s: malloc failed!", __FUNCTION__);
        return NULL;
    }

    if (memset_s(p, sizeof(hil_mmz_t), 0, sizeof(hil_mmz_t))) {
        mmz_free(p);
        return NULL;
    }
    strlcpy(p->name, name, sizeof(p->name));
    p->phys_start = phys_start;
    p->nbytes = nbytes;
    p->alloc_type = alloc_type;
    p->destructor = mmz_free;

    INIT_LIST_HEAD(&p->list);
    INIT_LIST_HEAD(&p->mmb_list);
    if (!g_init_cnt) {
        mmz_mutex_init(&g_mmz_lock);
    }
    g_init_cnt++;
    return p;
}

int hil_mmz_destroy(hil_mmz_t *mmz)
{
    if (mmz == NULL) {
        return -1;
    }

    hil_mmz_t *zone = mmz;

    if (zone->destructor != NULL) {
        zone->destructor(zone);
    } else
        PRINTK_CA("%s: missed destructor!", __FUNCTION__);

    return 0;
}

int hil_mmz_register(hil_mmz_t *mmz)
{
    int ret ;

    if (mmz == NULL) {
        PRINTK_CA("NULL zone!\n");
        return -1;
    }

    hil_mmz_t *zone = mmz;
    mmz_trace(1, HIL_MMZ_FMT_S, hil_mmz_fmt_arg(zone));

    ret = mmz_check(zone);
    if (ret) {
        PRINTK_CA("%s, %d, illegal mmz!!!\n", __func__, __LINE__);
        return ret;
    }

    INIT_LIST_HEAD(&zone->mmb_list);

    list_add(&zone->list, &mmz_list);

    return 0;
}

int hil_mmz_unregister(hil_mmz_t *mmz)
{
    int losts = 0;
    hil_mmb_t *p = NULL;

    if (mmz == NULL) {
        PRINTK_CA("%s, %d\n", __func__, __LINE__);
        return -1;
    }

    hil_mmz_t *zone = mmz;
    mmz_trace_func();

    list_for_each_entry(p, &zone->mmb_list, list) {
        losts++;
    }

    if (losts) {
        PRINTK_CA("%s, %d\n", __func__, __LINE__);
        PRINTK_CA("%d mmbs not free, mmz<%s> can not be deregistered! \n", losts, zone->name);
        return -1;
    }

    list_del(&zone->list);

    return 0;
}

hil_mmb_t *hil_mmb_alloc(const char *name, unsigned long size,
            unsigned int alloc_type, const char *mmz_name)
{
    hil_mmb_t *mmb = NULL;

    mmz_mutex_lock(&g_mmz_lock);
    mmb = mmb_alloc(name, size, alloc_type, mmz_name);
    mmz_mutex_unlock(&g_mmz_lock);

    return mmb;
}

void *hil_mmb_map2kern(hil_mmb_t *_mmb)
{
    void *p = NULL;
    hil_mmb_t *mmb = NULL;

    if (_mmb == NULL) {
        PRINTK_CA("%s, %d\n", __func__, __LINE__);
        return NULL;
    }

    mmb = _mmb;
    mmz_mutex_lock(&g_mmz_lock);
    p = mmb_map2kern(mmb, 0);
    mmz_mutex_unlock(&g_mmz_lock);
    return p;
}

void *hil_mmb_map2kern_cached(hil_mmb_t *_mmb)
{
    void *p = NULL;
    hil_mmb_t *mmb = NULL;

    if (_mmb == NULL) {
        return NULL;
    }

    mmb = _mmb;
    mmz_mutex_lock(&g_mmz_lock);
    p = mmb_map2kern(mmb, 1);
    mmz_mutex_unlock(&g_mmz_lock);

    return p;
}

void *hil_mmb_map2uk(hil_mmb_t *_mmb)
{
    hil_mmb_t *mmb = NULL;
    void *p = NULL;

    if (_mmb == NULL) {
        PRINTK_CA("%s, %d\n", __func__, __LINE__);
        return NULL;
    }

    mmb = _mmb;
    mmz_mutex_lock(&g_mmz_lock);
    p = mmb_map2uk(mmb, 0);
    mmz_mutex_unlock(&g_mmz_lock);

    return p;
}

void *hil_mmb_map2uk_cached(hil_mmb_t *_mmb)
{
    void *p = NULL;

    if (_mmb == NULL) {
        return NULL;
    }

    hil_mmb_t *mmb = _mmb;
    p = mmb_map2uk(mmb, 1);

    return p;
}


int hil_mmb_unmap(hil_mmb_t *_mmb)
{
    int kernel_ref = 0;

    if (_mmb == NULL) {
        return -1;
    }

    hil_mmb_t *mmb = _mmb;
    if (mmb->flags & HIL_MMB_MAP2KERN_CACHED) {
        hi_tee_drv_hal_dcache_flush((void *)mmb->kvirt, mmb->length);
    }

    if (mmb->flags & HIL_MMB_MAP2KERN) {
        --mmb->map_ref;
        kernel_ref = mmb->map_ref - mmb->u_map_ref;
        if (kernel_ref != 0) {
            return 0;
        }

        mmb_unmap(mmb->kvirt, mmb->length, mmb->flags);
    }

    mmb->kvirt  = NULL;
    mmb->flags &= ~HIL_MMB_MAP2KERN;
    mmb->flags &= ~HIL_MMB_MAP2KERN_CACHED;

    if (mmb->flags & HIL_MMB_RELEASED) {
        PRINTK_CA("%s, %d\n", __func__, __LINE__);
        mmb_free(mmb);
    }

    return 0;
}

int hil_mmb_unmap_uk(hil_mmb_t *_mmb)
{
    int u_map_ref = 0;

    if (_mmb == NULL) {
        return -1;
    }

    hil_mmb_t *mmb = _mmb;
    if (mmb->flags & HIL_MMB_MAP2UK_CACHED) {
        hi_tee_drv_hal_dcache_flush((void *)mmb->uvirt, mmb->length);
    }

    if ((mmb->flags & HIL_MMB_MAP2UK)) {
        --mmb->map_ref;
        u_map_ref = --mmb->u_map_ref;
        if (u_map_ref != 0) {
            return 0;
        }

        mmb_unmap_uk(mmb->uvirt, mmb->length, mmb->flags);

        mmb->uvirt = NULL;
    }

    mmb->flags &= ~HIL_MMB_MAP2UK;
    mmb->flags &= ~HIL_MMB_MAP2UK_CACHED;

    if (mmb->flags & HIL_MMB_RELEASED) {
        PRINTK_CA("%s, %d\n", __func__, __LINE__);
        mmb_free(mmb);
    }

    return 0;
}

int hil_mmb_free(hil_mmb_t *_mmb)
{
    hil_mmb_t *mmb = NULL;

    mmz_trace_func();

    if (_mmb == NULL) {
        return -1;
    }

    mmb = _mmb;
    mmz_trace(1, HIL_MMB_FMT_S, hil_mmb_fmt_arg(mmb));

    if (mmb->flags & HIL_MMB_RELEASED) {
        PRINTK_CA("hil_mmb_free: amazing, mmb<%s> is released before, but still used!\n", mmb->name);

        return 0;
    }

    if ((mmb->flags & HIL_MMB_MAP2KERN) || (mmb->flags & HIL_MMB_MAP2UK)) {
        PRINTK_CA("hil_mmb_free: free mmb<%s> delayed for which is kernel-mapped to 0x%p with map_ref %d!\n",
                  mmb->name, mmb->kvirt, mmb->map_ref);
        mmb->flags |= HIL_MMB_RELEASED;

        return 0;
    }

    mmb_free(mmb);

    return 0;
}

void hil_mmz_dump(void)
{
    hil_mmz_t *p = NULL;
    hil_mmb_t *q = NULL;
    unsigned long mmz_no = 0;
    unsigned long mmb_no ;

    list_for_each_entry(p, &mmz_list, list) {
        PRINTK_CA("\n-----------------------------------------------------------------------------\n");
        PRINTK_CA("MMZ %d(%s)  Addr=0x%X  Size=0x%X  Type=0x%X\n",
                  mmz_no, p->name ? p->name : "null", p->phys_start, p->nbytes, p->alloc_type);
        PRINTK_CA("-----------------------------------------------------------------------------\n");

        mmb_no = 0;
        list_for_each_entry(q, &p->mmb_list, list) {
            PRINTK_CA("MMB No.%d  ", mmb_no);
            PRINTK_CA("Name: %s  ", q->name);
            PRINTK_CA("Addr=0x%x  ", q->phys_addr);
            PRINTK_CA("Size=0x%x  ", q->length);
            PRINTK_CA("Flags=0x%x  ", q->flags);
            mmb_no++;
            PRINTK_CA("\n");
        }
        mmz_no++;
    }
    PRINTK_CA("-----------------------------------------------------------------------------\n");
}

hil_mmb_t *hil_mmb_getby_phys(unsigned long addr)
{
    hil_mmb_t *p = NULL;
    mmz_mutex_lock(&g_mmz_lock);

    p = mach_mmb_by_phys(addr);

    mmz_mutex_unlock(&g_mmz_lock);
    return p;
}

hil_mmb_t *hil_mmb_getby_kvirt(const void *virt)
{
    hil_mmb_t *p = NULL;

    if (virt == NULL) {
        return NULL;
    }

    p = mach_mmb_by_virt(virt);

    return p;
}

hil_mmb_t *hil_mmb_getby_uvirt(const void *virt)
{
    hil_mmz_t *zone = NULL;
    hil_mmb_t *mmb = NULL;
    hil_mmb_t *p = NULL;

    if (virt == NULL) {
        return NULL;
    }

    list_for_each_entry(zone, &mmz_list, list) {
        list_for_each_entry(mmb, &zone->mmb_list, list) {
            if (((uintptr_t)mmb->uvirt <= (uintptr_t)virt) &&
                (((uintptr_t)mmb->uvirt + mmb->length) > (uintptr_t)virt)) {
                p = mmb;
                break;
            }
        }
        if (p != NULL) {
            break;
        }
    }

    return p;
}

void *hil_mmb_kvirt(hil_mmb_t *_mmb)
{
    hil_mmb_t *mmb = NULL;

    if (_mmb == NULL) {
        return NULL;
    }
    mmb = _mmb;
    return mmb->kvirt;
}

unsigned long hil_mmb_phys(hil_mmb_t *_mmb)
{
    hil_mmb_t *mmb = NULL;

    if (_mmb == NULL) {
        return 0;
    }
    mmb = (hil_mmb_t *)_mmb;

    return mmb->phys_addr;
}

void hil_mmb_flush_l2cached(hil_mmb_t *_mmb)
{
    hil_mmb_t *mmb = NULL;

    if (_mmb == NULL) {
        return;
    }
    mmb = _mmb;
    if (mmb && (mmb->flags & HIL_MMB_MAP2KERN_CACHED)) {
        hi_tee_drv_hal_dcache_flush((void *)mmb->kvirt, mmb->length);
    }
}

int hil_tee_is_nonsec_mem(unsigned long phy_addr, unsigned long size)
{
    unsigned long long zone_size = 0;
    unsigned long long phy_addr_start;
    unsigned long long phy_addr_end ;
    unsigned long long zone_start;
    unsigned long long zone_end;
    unsigned long long ddr_start;
    unsigned long long ddr_size;
    unsigned long long ddr_end;

    phy_addr_start = phy_addr;
    phy_addr_end = (unsigned long long)phy_addr_start + (unsigned long long)size;

    ddr_start = hi_tee_drv_mem_get_zone_range(TOTAL_MEM_RANGE, &ddr_size);
    if (!ddr_size) {
        PRINTK_CA("cannot get ddr size!\n");
        return -1;;
    }
    ddr_end = ddr_start + ddr_size;

    /* check if phys in ddr range   */
    if (!((phy_addr_start >= ddr_start) &&
          (phy_addr_start < ddr_end) &&
          (phy_addr_end >= ddr_start) &&
          (phy_addr_end <= ddr_end))) {
        PRINTK_CA("illegal phys mem, out of ddr \n");
        return -1;
    }

    zone_start = hi_tee_drv_mem_get_zone_range(SEC_MEM_RANGE, &zone_size);
    if (!zone_size) {
        PRINTK_CA("cannot get sec mem size!\n");
        return -1;;
    }
    zone_end = zone_start + zone_size;
    if ((zone_start <= phy_addr_start) &&
        (phy_addr_start < zone_end) &&
        (phy_addr_end > zone_start) &&
        (phy_addr_end < zone_end) &&
        (phy_addr_end >= phy_addr_start)) {
        return 0;
    } else {
        return 1;
    }
}

int hil_tee_is_sec_mem(unsigned long phy_addr, unsigned long size)
{
    int ret;

    ret = hil_tee_is_nonsec_mem(phy_addr, size);
    if (ret == -1) {
        PRINTK_CA("%s failed!\n", __func__);
        return -1;
    }

    if (ret) {
        return 0;
    } else {
        return 1;
    }
}
