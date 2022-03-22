/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2009-2019. All rights reserved.
 * Description: Defines the common data type of the system.
 * Author: Hisilicon
 * Create: 2009-12-16
 */

#ifndef __ASM_ARCH_MEDIA_MEM_H
#define __ASM_ARCH_MEDIA_MEM_H

#include "hi_tee_drv_os_hal.h"
#include "hi_list.h"
#include "hi_type_dev.h"

#ifdef __cplusplus
extern "C"{
#endif

#define PRINTK_CA(fmt...)    hi_tee_drv_hal_printf(fmt)

#ifndef HI_TEE_LOG_SUPPORT
#define MMZ_RELEASE_SUPPORT
#else
#undef    MMZ_RELEASE_SUPPORT
#endif

#ifndef SECURE_MEM
#define SECURE_MEM 0
#endif

#ifndef NON_SECURE_MEM
#define NON_SECURE_MEM 1
#endif

#define MEM_LIMIT_SIZE          0x40000000

#define HIL_MAX_NAME_LEN 16
#define UUID_LENGTH 16
struct hil_media_memory_block {
    char name[HIL_MAX_NAME_LEN];
    struct hil_media_memory_zone *zone;
    struct list_head list;
    unsigned long phys_addr;
    void *kvirt;
    unsigned long length;
    unsigned long flags;
    int map_ref;
    TEE_UUID uuid;
    TEE_UUID alloc_uuid;
    void *uvirt; // ta virt
    int u_map_ref;
};
typedef struct hil_media_memory_block hil_mmb_t;


struct hil_media_memory_zone {
    char name[HIL_MAX_NAME_LEN];
    unsigned long phys_start;
    unsigned long nbytes;
    struct list_head list;
    struct list_head mmb_list;
    unsigned int alloc_type;
    void (*destructor)(void *);
};
typedef struct hil_media_memory_zone  hil_mmz_t;

/**********  API_0 for inf  *********/
extern hil_mmz_t *hil_mmz_create(const char *name, unsigned int alloc_type, unsigned long phys_start,
                                 unsigned long nbytes);
extern int   hil_mmz_destroy(hil_mmz_t *mmz);
extern int   hil_mmz_register(hil_mmz_t* mmz);
extern int   hil_mmz_unregister(hil_mmz_t *mmz);
extern int   hil_mmb_unmap(hil_mmb_t *_mmb);
extern hil_mmb_t* hil_mmb_getby_phys(unsigned long addr);
extern hil_mmb_t* hil_mmb_getby_kvirt(const void *virt);
extern void* hil_mmb_map2kern(hil_mmb_t *_mmb);
extern void* hil_mmb_map2kern_cached(hil_mmb_t *_mmb);
extern void* hil_mmb_map2uk(hil_mmb_t *_mmb);
extern void* hil_mmb_map2uk_cached(hil_mmb_t *_mmb);
extern void* hil_mmb_kvirt(hil_mmb_t *_mmb);
extern void  hil_mmb_flush_l2cached(hil_mmb_t *_mmb);
extern void  hil_mmz_dump(void);
extern unsigned long hil_mmb_phys(hil_mmb_t *_mmb);
extern hil_mmb_t *hil_mmb_getby_uvirt(const void *virt);
extern int hil_mmb_unmap_uk(hil_mmb_t *_mmb);

/********** API_1 for inf & usr *********/
extern hil_mmb_t *hil_mmb_alloc(const char *name, unsigned long size, unsigned int alloc_type, const char *mmz_name);
extern int hil_mmb_free(hil_mmb_t *mmb);
extern int hil_tee_is_sec_mem(unsigned long phy_addr, unsigned long size);
extern int hil_tee_is_nonsec_mem(unsigned long phy_addr, unsigned long size);

extern int get_smmz_alloc_uuid(unsigned long phys_addr, TEE_UUID *uuid);
#ifdef __cplusplus
}
#endif

#endif
