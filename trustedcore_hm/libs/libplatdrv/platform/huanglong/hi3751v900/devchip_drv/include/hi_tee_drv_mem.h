/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2009-2019. All rights reserved.
 * Description: Defines the common data type of the system.
 * Author: Hisilicon
 * Create: 2009-12-16
 */

#ifndef _HI_TEE_DRV_MEM_H
#define _HI_TEE_DRV_MEM_H

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif /* __cpluscplus */
#endif /* __cpluscplus */

#include <stddef.h>
#include "stdbool.h"

typedef enum {
    HI_SEC_MMZ = 0,
    HI_SHARE_CMA,
}hi_tee_mmz_type;

typedef struct {
    void* virt;
    unsigned long phys_addr;
    size_t size;
} hi_tee_mmz_buf;

typedef struct {
    void* virt;
    unsigned long  smmu_addr;
    size_t size;
}hi_tee_smmu_buf;

/*
 * brief : alloc a mmz type buffer
 * @buf_name : the name of buffer which will be alloc
 * @size     : the size of buffer
 * @mem_type : specify the mmz area which to alloc
 *             HI_SEC_MMZ: sec-mmz memory  HI_SHARE_CMA: share cma memory
 * @mmz_buf  : the struct memory which store the buffer info
 * return:
 *      HI_SUCCESS, if exec successfully
 *      HI_FAILED, if exec failed
 *
 */
int hi_tee_drv_mmz_alloc(const char *buf_name,
                         size_t size,
                         hi_tee_mmz_type mem_type,
                         hi_tee_mmz_buf *mmz_buf);

/*
 * brief : free a mmz type buffer
 * @mmz_buf : the struct memory which store the buffer info
 * return:
 *      HI_SUCCESS, if exec successfully
 *      HI_FAILED, if exec failed
 *
 */
int hi_tee_drv_mmz_free(const hi_tee_mmz_buf *mmz_buf);

/*
 * brief : map a sec-mmz type buffer into tee kernel
 * @mmz_buf : the struct memory which store the buffer info
 * @cache   : specify the cache attribute
 *      HI_SUCCESS, if exec successfully
 *      HI_FAILED, if exec failed
 *
 */
int hi_tee_drv_mmz_map_cpu(hi_tee_mmz_buf *mmz_buf, bool cache);

/*
 * brief : unmap a sec-mm type buffer from  tee kernel
 * @mmz_buf : the struct memory which store the buffer info
 * return:
 *      HI_SUCCESS, if exec successfully
 *      HI_FAILED, if exec failed
 *
 */
int hi_tee_drv_mmz_unmap_cpu(const hi_tee_mmz_buf *mmz_buf);

/*
 * brief : map share cma type buffer into tee kernel
 * @mmz_buf : the struct memory which store the buffer info
 * @cache   : specify the cache attribute
 * return:
 *      HI_SUCCESS, if exec successfully
 *      HI_FAILED, if exec failed
 *
 */
int hi_tee_drv_nsmmz_map_cpu(hi_tee_mmz_buf *mmz_buf, bool cache);

/*
 * brief : unmap a share cma type type buffer from tee kernel
 * @mmz_buf : the struct memory which store the buffer info
 * return:
 *      HI_SUCCESS, if exec successfully
 *      HI_FAILED, if exec failed
 *
 */
int hi_tee_drv_nsmmz_unmap_cpu(hi_tee_mmz_buf *mmz_buf);

/*
 * brief : flush the dcache by va range
 * @virt    : the start va to be flushed
 * @size    : the size of the flush range
 * return:
 *      HI_SUCCESS, if exec successfully
 *      HI_FAILED, if exec failed
 *
 */
int hi_tee_drv_mem_flush(void *virt, size_t size);

/*
 * brief : check the buffer's security attribute
 * @phys_addr: the phys address of the buffer
 * @is_sec   : the security attribute of the buffer
 * return:
 *      HI_SUCCESS, if exec successfully
 *      HI_FAILED, if exec failed
 *
 */
int hi_tee_drv_mmz_is_sec(unsigned long phys_addr, bool *is_sec);


/*
 * brief : alloc a secsmmu type buffer
 * @buf_name : the name of buffer which will be alloc
 * @size     : the size of buffer
 * @smmu_buf : the struct memory which store the buffer info
 * return:
 *      HI_SUCCESS, if exec successfully
 *      HI_FAILED, if exec failed
 *
 */
int hi_tee_drv_smmu_alloc(const char *buf_name, size_t size, hi_tee_smmu_buf *smmu_buf);

/*
 * brief : free a secsmu type buffer
 * @smmu_buf : the struct memory which store the buffer info
 * return:
 *      HI_SUCCESS, if exec successfully
 *      HI_FAILED, if exec failed
 *
 */
int hi_tee_drv_smmu_free(const hi_tee_smmu_buf *smmu_buf);

/*
 * brief : map a secsmmu type buffer into tee kernel
 * @smmu_buf : the struct memory which store the buffer info
 * @cache    : specify the cache attribute
 * return:
 *      HI_SUCCESS, if exec successfully
 *      HI_FAILED, if exec failed
 *
 */
int hi_tee_drv_smmu_map_cpu(hi_tee_smmu_buf *smmu_buf,  bool cache);

/*
 * brief : unmap a sec-smmu type buffer from tee kernel
 * @smmu_buf : the struct memory which store the buffer info
 * @cache    : specify the cache attribute
 * return:
 *      HI_SUCCESS, if exec successfully
 *      HI_FAILED, if exec failed
 *
 */
int hi_tee_drv_smmu_unmap_cpu(const hi_tee_smmu_buf *smmu_buf);

/*
 * brief : map a no-secsmmu type buffer into tee kernel
 * @smmu_buf : the struct memory which store the buffer info
 * @cache    : specify the cache attribute
 * return:
 *      HI_SUCCESS, if exec successfully
 *      HI_FAILED, if exec failed
 *
 */
int hi_tee_drv_nssmmu_map_cpu(hi_tee_smmu_buf *smmu_buf, bool cache);

/*
 * brief : unmap a no-secsmmu type buffer to cpu
 * @smmu_buf : the struct memory which store the buffer info
 * @cache    : specify the cache attribute
 * return:
 *      HI_SUCCESS, if exec successfully
 *      HI_FAILED, if exec failed
 *
 */
int hi_tee_drv_nssmmu_unmap_cpu(hi_tee_smmu_buf *smmu_buf);

/*
 * brief : check the buffer's security attribute
 * @smmu_addr: the smmu address of the buffer
 * @is_sec   : the security attribute of the buffer
 * return:
 *      HI_SUCCESS, if exec successfully
 *      HI_FAILED, if exec failed
 *
 */
int hi_tee_drv_smmu_is_sec(unsigned long smmu_addr, bool *is_sec);

/*
 * brief : get info about smmu's tables
 * @secsmmu_e_raddr : address of the read error smmu table
 * @secsmmu_e_waddr : address of the write error smmu table
 * @secsmmu_pgtbl   : address of the smmu table
 * return:
 *      HI_SUCCESS, if exec successfully
 *      HI_FAILED, if exec failed
 *
 */
int hi_tee_drv_smmu_get_pgtinfo(unsigned long long *secsmmu_e_raddr,
                                unsigned long long *secsmmu_e_waddr,
                                unsigned long long *secsmmu_pgtbl);

/*
 * brief : set the smmu buffer's tag attribute
 * @smmu_buf : the struct memory which store the buffer info
 * @ssm_tag  : the value which store the tag info
 * return:
 *      HI_SUCCESS, if exec successfully
 *      HI_FAILED, if exec failed
 *
 */
int hi_tee_drv_smmu_set_tag(const hi_tee_smmu_buf *smmu_buf, unsigned int ssm_tag);

/*
 * brief : get the phy addr of the smmu buffer
 * @smmu_buf : the struct memory which store the buffer info
 * @mmz_buf  : the struct memory which store the phy address info
 * return:
 *      HI_SUCCESS, if exec successfully
 *      HI_FAILED, if exec failed
 *
 */
int hi_tee_drv_smmu_get_mmz_by_sec_smmu(hi_tee_smmu_buf *smmu_buf, hi_tee_mmz_buf *mmz_buf);

/*
 * brief :  map a mmz type buffer to secsmmu spcae
 * @mmz_buf : the struct memory which store the mmz type buffer info
 * @smmu_buf: the struct memory which store the smmu address info
 * return:
 *      HI_SUCCESS, if exec successfully
 *      HI_FAILED, if exec failed
 *
 */
int hi_tee_drv_mmz_map_secsmmu(const hi_tee_mmz_buf *mmz_buf, hi_tee_smmu_buf *smmu_buf);

/*
 * brief : unmap a mmz type buffer from secsmmu spcae
 * @mmz_buf : the struct memory which store the mmz type buffer info
 * @smmu_buf: the struct memory which store the smmu address info
 * return:
 *      HI_SUCCESS, if exec successfully
 *      HI_FAILED, if exec failed
 *
 */
int hi_tee_drv_mmz_unmap_secsmmu(const hi_tee_smmu_buf *smmu_buf, unsigned long phys_addr);

/*
 * brief : get secsmmu addr by handle id
 * @smmu_buf: the struct of memory which store the sec smmu addr
 * @handle_id: the handle id
 * return:
 *      HI_SUCCESS, if exec successfully
 *      HI_FAILED, if exec failed
 */
int hi_tee_drv_mem_get_secsmmu_by_handle_id(hi_tee_smmu_buf *smmu_buf, unsigned long long handle_id);

/*
 * brief : get secsmmz addr by handle id
 * @mmz_buf: the struct of memory which store the sec phys addr
 * @handle_id: the handle id
 * return:
 *      HI_SUCCESS, if exec successfully
 *      HI_FAILED, if exec failed
 */
int hi_tee_drv_mem_get_secsmmz_by_handle_id(hi_tee_mmz_buf *mmz_buf, unsigned long long handle_id);

/*
 * brief : get nssmmu addr by handle id
 * @smmu_buf: the struct of memory which store the nssmmu addr
 * @handle_id: the handle id
 * return:
 *      HI_SUCCESS, if exec successfully
 *      HI_FAILED, if exec failed
 */
int hi_tee_drv_mem_get_nssmmu_by_handle_id(hi_tee_smmu_buf *smmu_buf, unsigned long long handle_id);

/*
 * brief : get nsmmz addr by handle id
 * @mmz_buf: the struct of memory which store the nsmmz addr
 * @handle_id: the handle id
 * return:
 *      HI_SUCCESS, if exec successfully
 *      HI_FAILED, if exec failed
 */
int hi_tee_drv_mem_get_nsmmz_by_handle_id(hi_tee_mmz_buf *mmz_buf, unsigned long long handle_id);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */

#endif
