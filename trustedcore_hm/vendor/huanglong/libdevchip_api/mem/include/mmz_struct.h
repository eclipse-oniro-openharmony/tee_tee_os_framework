/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2009-2019. All rights reserved.
 * Description: Defines the common data type of the system.
 * Author: Hisilicon
 * Create: 2009-12-16
 */

#ifndef __MMZ_STRUCT_H__
#define __MMZ_STRUCT_H__
#include <hi_log.h>

#ifdef __cplusplus
#if __cplusplus
extern "C"{
#endif
#endif /* End of #ifdef __cplusplus */


#define MAX_BUFFER_NAME_SIZE 16

/* alloc_type */
#define SECURE_MEM 0
#define NON_SECURE_MEM 1

struct mmz_buf {
    unsigned long long  phyaddr;
    unsigned int alloc_type;
    unsigned long long  bufsize;
};

struct smmu_buf {
    unsigned long long handle;
    unsigned int alloc_type;
    void *virt;
    unsigned long long  bufsize;
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
    struct mmz_buf buf;
    struct smmu_buf smmu_buf;
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

#define MMZ_LOG_ERROR(fmt...)          hi_log_err(fmt)
#define MMZ_LOG_WARN(fmt...)           hi_log_warn(fmt)
#define MMZ_LOG_INFO(fmt...)           hi_log_info(fmt)
#define MMZ_LOG_DEBUG(fmt...)       hi_log_dbg(fmt)

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */

#endif  /* __MMZ_STRUCT_H__ */

