/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2009-2019. All rights reserved.
 * Description: Defines the common data type of the system.
 * Author: Hisilicon
 * Create: 2009-12-16
 */

#ifndef __MMZ_STRUCT_H__
#define __MMZ_STRUCT_H__

#ifdef __cplusplus
#if __cplusplus
extern "C"{
#endif
#endif /* End of #ifdef __cplusplus */


/*************************** Structure Definition ****************************/
/** \addtogroup      H_2_1_2 */
/** @{ */  /** <!-- 【Common data structure. CNcomment: 通用数据结构】 */


/** Maximum bytes of a buffer name */
/** CNcomment:  buffer命名的最大字节数 */
#define MAX_BUFFER_NAME_SIZE 16

/** alloc_type */
/** CNcomment:  alloc_type */
#define SECURE_MEM 0
#define NON_SECURE_MEM 1

/** Structure of an MMZ buffer */
/** CNcomment:  MMZ buffer信息结构 */
struct hi_mmz_buf {
    unsigned long long phyaddr;                /* <Physical address of an MMZ buffer */
    unsigned int alloc_type;        /* <Indicate to alloc mem from the non-secure or secure memory */
    unsigned long long  bufsize;                /*  <Size of an MMZ buffer */
};

struct hi_smmu_buf {
    unsigned long long handle;
    unsigned int alloc_type;        /*  <Indicate to alloc mem from the non-secure or secure memory */
    void *virt;                        /*  <Virtual address of an MMZ buffer */
    unsigned long long bufsize;            /*  <Size of an MMZ buffer */
};

enum mmz_drv_ioctl_func_id {
    MMZ_NEW_ID = 0x0,
    MMZ_DEL_ID,
    TEE_ISSECMMZ,
    TEE_ISSECMEM,
    TEE_ISNONSECMEM,
    CALL_DEBUG,
    MMZ_ALLOC_MAPALL_ID,
    MMZ_FREE_UNMAPALL_ID,
    MMZ_ALLOC_MAPSMMU,
    MMZ_FREE_UNMAPSMMU,
};
struct hi_tee_mmz_ioctl_data {
    struct hi_mmz_buf buf;
    struct hi_smmu_buf smmu_buf;
    char *mmz_name;
    char *mmb_name;
    unsigned long long addr;
    unsigned long long size;
    unsigned long long phys_addr;
    unsigned long long arg0;
    unsigned long long arg1;
    unsigned long long arg2;
    unsigned long long arg3;
    enum mmz_drv_ioctl_func_id cmd_id;
};

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /*  __cplusplus */

#endif  /*  __MMZ_STRUCT_H__ */

