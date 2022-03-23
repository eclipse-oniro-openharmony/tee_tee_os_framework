/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2009-2019. All rights reserved.
 * Description: Function implementation.
 * Author: Hisilicon
 * Create: 2009-12-16
 */

#include "hi_tee_hal.h"
#include "hi_tee_mmz.h"
#include "mmz_struct.h"
#include "securec.h"
#include "hi_tee_drv_syscall_id.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#define HIL_MAX_NAME_LEN    16
#define MEM_LIMIT_SIZE      0x40000000

unsigned long long hi_tee_mmz_new(unsigned long long size, const char *mmz_name, const char *buf_name)
{
    uint32_t reval;
    struct hi_tee_mmz_ioctl_data buf_para;
    char zonename[HIL_MAX_NAME_LEN];
    char mmbname[HIL_MAX_NAME_LEN];
    char *zone = NULL;
    char *mmb = NULL;
    unsigned int args[2] = {0}; /* init data to 0 2 is the array subscript */

    if (size == 0 || size > MEM_LIMIT_SIZE) {
        return 0;
    }

    if (memset_s(zonename, HIL_MAX_NAME_LEN, 0x0, HIL_MAX_NAME_LEN)) {
        return 0;
    }
    if (memset_s(mmbname, HIL_MAX_NAME_LEN, 0x0, HIL_MAX_NAME_LEN)) {
        return 0;
    }
    if (memset_s(&buf_para, sizeof(struct hi_tee_mmz_ioctl_data), 0x0,
                 sizeof(struct hi_tee_mmz_ioctl_data))) {
        return 0;
    }
    if (mmz_name != NULL) {
        if (memcpy_s(zonename, HIL_MAX_NAME_LEN, mmz_name,
            (strlen(mmz_name) > HIL_MAX_NAME_LEN) ? HIL_MAX_NAME_LEN : strlen(mmz_name))) {
            return 0;
        }
        zonename[HIL_MAX_NAME_LEN - 1] = '\0';
        zone = zonename;
    }
    if (buf_name != NULL) {
        if (memcpy_s(mmbname, HIL_MAX_NAME_LEN, buf_name,
            (strlen(buf_name) > HIL_MAX_NAME_LEN) ? HIL_MAX_NAME_LEN : strlen(buf_name))) {
            return 0;
        }
        mmbname[HIL_MAX_NAME_LEN - 1] = '\0';
        mmb = mmbname;
    }

    buf_para.buf.bufsize = size;
    buf_para.buf.alloc_type = SECURE_MEM;

    buf_para.mmz_name = zone;
    buf_para.mmb_name = mmb;
    buf_para.cmd_id = MMZ_NEW_ID;
    args[0] = (unsigned int)(uintptr_t)&buf_para;
    args[1] = sizeof(struct hi_tee_mmz_ioctl_data);
    reval = hm_drv_call(HI_TEE_SYSCALL_MMZ_ID, args, ARRAY_SIZE(args));
    if (reval == HI_SUCCESS) {
        return buf_para.buf.phyaddr;
    } else {
        return 0;
    }
}

int hi_tee_mmz_delete(unsigned long long phys_addr)
{
    struct hi_tee_mmz_ioctl_data buf_para;
    unsigned int args[2] = {0}; /* init data to 0 2 is the array subscript */

    if (memset_s(&buf_para, sizeof(struct hi_tee_mmz_ioctl_data), 0x0,
                 sizeof(struct hi_tee_mmz_ioctl_data))) {
        return -1;
    }
    buf_para.addr = phys_addr;
    buf_para.cmd_id = MMZ_DEL_ID;
    args[0] = (unsigned int)(uintptr_t)&buf_para;
    args[1] = sizeof(struct hi_tee_mmz_ioctl_data);

    return hm_drv_call(HI_TEE_SYSCALL_MMZ_ID, args, ARRAY_SIZE(args));
}

int hi_tee_mmz_issmmz(unsigned long long phys_addr)
{
    uint32_t reval;
    struct hi_tee_mmz_ioctl_data buf_para;
    unsigned int args[2] = {0}; /* init data to 0 2 is the array subscript */

    if (memset_s(&buf_para, sizeof(struct hi_tee_mmz_ioctl_data), 0x0,
                 sizeof(struct hi_tee_mmz_ioctl_data))) {
        return -1;
    }
    buf_para.phys_addr = phys_addr;
    buf_para.cmd_id = TEE_ISSECMMZ;
    args[0] = (unsigned int)(uintptr_t)&buf_para;
    args[1] = sizeof(struct hi_tee_mmz_ioctl_data);
    reval = hm_drv_call(HI_TEE_SYSCALL_MMZ_ID, args, ARRAY_SIZE(args));
    if (reval == HI_SUCCESS) {
        return (int)buf_para.arg0;
    } else {
        return -1;
    }
}

void *hi_tee_mmz_alloc_and_mapall(unsigned long long size, const char *mmz_name,
                                  const char *buf_name, unsigned long long *handle)
{
    uint32_t reval;
    struct hi_tee_mmz_ioctl_data buf_para;
    char zonename[HIL_MAX_NAME_LEN];
    char mmbname[HIL_MAX_NAME_LEN];
    char *zone = NULL;
    char *mmb = NULL;
    unsigned int args[2] = {0}; /* init data to 0 and 2 is the array subscript */

    if (size == 0 || size > MEM_LIMIT_SIZE || handle == NULL) {
        return (void *)NULL;
    }
    if (memset_s(zonename, HIL_MAX_NAME_LEN, 0x0, HIL_MAX_NAME_LEN))
        return (void *)NULL;
    if (memset_s(mmbname, HIL_MAX_NAME_LEN, 0x0, HIL_MAX_NAME_LEN))
        return (void *)NULL;
    if (memset_s(&buf_para, sizeof(struct hi_tee_mmz_ioctl_data), 0x0,
                 sizeof(struct hi_tee_mmz_ioctl_data)))
        return (void *)NULL;
    if (mmz_name != NULL) {
        if (memcpy_s(zonename, HIL_MAX_NAME_LEN, mmz_name,
            (strlen(mmz_name) > HIL_MAX_NAME_LEN) ? HIL_MAX_NAME_LEN : strlen(mmz_name)))
            return (void *)NULL;
        zonename[HIL_MAX_NAME_LEN - 1] = '\0';
        zone = zonename;
    }
    if (buf_name != NULL) {
        if (memcpy_s(mmbname, HIL_MAX_NAME_LEN, buf_name,
            (strlen(buf_name) > HIL_MAX_NAME_LEN) ? HIL_MAX_NAME_LEN : strlen(buf_name)))
            return (void *)NULL;
        mmbname[HIL_MAX_NAME_LEN - 1] = '\0';
        mmb = mmbname;
    }
    buf_para.smmu_buf.bufsize = size;
    buf_para.smmu_buf.alloc_type = SECURE_MEM;

    buf_para.mmz_name = zone;
    buf_para.mmb_name = mmb;
    buf_para.cmd_id = MMZ_ALLOC_MAPALL_ID;
    args[0] = (unsigned int)(uintptr_t)&buf_para;
    args[1] = sizeof(struct hi_tee_mmz_ioctl_data);
    reval = hm_drv_call(HI_TEE_SYSCALL_MMZ_ID, args, ARRAY_SIZE(args));
    if (reval != HI_SUCCESS) {
        *handle = 0;
        return (void *)NULL;
    }

    *handle = buf_para.smmu_buf.handle;

    return buf_para.smmu_buf.virt;
}

int hi_tee_mmz_unmap_and_freeall(void *virt, unsigned long long handle)
{
    struct hi_tee_mmz_ioctl_data buf_para;
    unsigned int args[2] = {0}; /* init data to 0 and 2 is the array subscript */

    if (virt == NULL) {
        return -1;
    }
    if (memset_s(&buf_para, sizeof(struct hi_tee_mmz_ioctl_data), 0x0,
                 sizeof(struct hi_tee_mmz_ioctl_data))) {
        return -1;
    }
    buf_para.smmu_buf.virt = virt;
    buf_para.smmu_buf.handle = handle;

    buf_para.cmd_id = MMZ_FREE_UNMAPALL_ID;
    args[0] = (unsigned int)(uintptr_t)&buf_para;
    args[1] = sizeof(struct hi_tee_mmz_ioctl_data);
    return hm_drv_call(HI_TEE_SYSCALL_MMZ_ID, args, ARRAY_SIZE(args));
}

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif

