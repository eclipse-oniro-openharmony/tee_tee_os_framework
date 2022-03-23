/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2009-2019. All rights reserved.
 * Description: Function implementation.
 * Author: Hisilicon
 * Create: 2009-12-16
 */

#include "hi_tee_hal.h"
#include "hi_tee_mem.h"
#include "hi_type_dev.h"
#include "smmu_struct.h"
#include "hi_tee_mmz.h"
#include "securec.h"
#include "hi_tee_drv_syscall_id.h"
#include <string.h>

#ifndef HI_SUCCESS
#define HI_SUCCESS      0
#endif
#ifndef HI_FAILED
#define HI_FAILED       (-1)
#endif

#define SMMU_MEM        1
#define CMA_MEM         0

#define SHARE_MMZ       1
#define HIL_MAX_NAME_LEN        16
#define INVIDE_ADDR     0

enum hi_tee_mmz_type {
    HI_TEE_SEC_MMZ = 0,  /**< mem in trustedzone  */
    HI_TEE_NORMAL_MMZ,   /**< mem in share mem area */
};


unsigned long long hi_tee_smmu_alloc(const char *name, size_t size)
{
    uint32_t reval;
    struct hi_tee_smmu_ioctl_data buf_para;
    char mmb_name[HIL_MAX_NAME_LEN];
    char *t_name = NULL;
    unsigned int args[2] = {0}; /* init data to 0 and 2 is the array subscript */

    if (!size) {
        SMMU_LOG_ERROR("%s, err args, size:0x%x\n", __func__, size);
        return INVIDE_ADDR;
    }
    if (memset_s(mmb_name, HIL_MAX_NAME_LEN, 0x0, HIL_MAX_NAME_LEN)) {
        return INVIDE_ADDR;
    }
    if (memset_s(&buf_para, sizeof(struct hi_tee_smmu_ioctl_data), 0x0,
                 sizeof(struct hi_tee_smmu_ioctl_data))) {
        return INVIDE_ADDR;
    }
    if (name != NULL) {
        if (memcpy_s(mmb_name, HIL_MAX_NAME_LEN, name,
                     (strlen(name) > HIL_MAX_NAME_LEN) ? HIL_MAX_NAME_LEN : strlen(name))) {
            return INVIDE_ADDR;
        }
        mmb_name[HIL_MAX_NAME_LEN - 1] = '\0';
        t_name = mmb_name;
    }

    buf_para.bufname = t_name;
    buf_para.buf_size = size;
    buf_para.memtype = SMMU_MEM;
    buf_para.cmd_id = HISI_SEC_ALLOC;
    args[0] = (unsigned int)(uintptr_t)&buf_para;
    args[1] = sizeof(struct hi_tee_smmu_ioctl_data);
    reval = hm_drv_call(HI_TEE_SYSCALL_SMMU_ID, args, ARRAY_SIZE(args));
    if (reval != HI_SUCCESS) {
        SMMU_LOG_ERROR("%s, alloc mem failed!\n", __func__);
        return INVIDE_ADDR;
    } else {
        return buf_para.smmu_addr;
    }
}

int hi_tee_smmu_free(unsigned long long secsmmu)
{
    uint32_t reval;
    struct hi_tee_smmu_ioctl_data buf_para;
    unsigned int args[2] = {0}; /* init data to 0 and 2 is the array subscript */

    if (!secsmmu) {
        SMMU_LOG_ERROR("%s, err args, sec smmu:0x%x\n", __func__, secsmmu);
        return HI_FAILED;
    }
    if (memset_s(&buf_para, sizeof(struct hi_tee_smmu_ioctl_data), 0x0, sizeof(struct hi_tee_smmu_ioctl_data)))
        return HI_FAILED;

    buf_para.sec_addr = secsmmu;
    buf_para.memtype = SMMU_MEM;
    buf_para.cmd_id = HISI_SEC_FREE;
    args[0] = (unsigned int)(uintptr_t)&buf_para;
    args[1] = sizeof(struct hi_tee_smmu_ioctl_data);
    reval = hm_drv_call(HI_TEE_SYSCALL_SMMU_ID, args, ARRAY_SIZE(args));
    if (reval != HI_SUCCESS) {
        SMMU_LOG_ERROR("%s, free mem failed, sec-smmu:0x%x!\n", __func__, secsmmu);
        return -1;
    } else {
        return 0;
    }
}

unsigned long long hi_tee_mmz_alloc(const char *name,
                                    unsigned long long size,
                                    enum hi_tee_mmz_type memtype)
{
    uint32_t reval;
    unsigned long long phys_addr = INVIDE_ADDR;
    struct hi_tee_smmu_ioctl_data buf_para;
    char mmb_name[HIL_MAX_NAME_LEN];
    char *t_name = NULL;
    unsigned int args[2] = {0}; /* init data to 0 and 2 is the array subscript */

    if (!size) {
        SMMU_LOG_ERROR("%s, err args, size:0x%x\n", __func__, size);
        return INVIDE_ADDR;
    }

    if (memset_s(mmb_name, HIL_MAX_NAME_LEN, 0x0, HIL_MAX_NAME_LEN)) {
        return INVIDE_ADDR;
    }
    if (memset_s(&buf_para, sizeof(struct hi_tee_smmu_ioctl_data), 0x0,
                 sizeof(struct hi_tee_smmu_ioctl_data))) {
        return INVIDE_ADDR;
    }
    if (name != NULL) {
        if (memcpy_s(mmb_name, HIL_MAX_NAME_LEN, name,
                     (strlen(name) > HIL_MAX_NAME_LEN) ? HIL_MAX_NAME_LEN : strlen(name))) {
            return INVIDE_ADDR;
        }
        mmb_name[HIL_MAX_NAME_LEN - 1] = '\0';
        t_name = mmb_name;
    }

    if (memtype == HI_TEE_NORMAL_MMZ) {
#if defined(CHIP_TYPE_hi3796mv200) || defined(CHIP_TYPE_hi3716mv450)
        (void)ret;
        SMMU_LOG_ERROR("Cannot support sec normal mmz in the platform!\n");
        return INVIDE_ADDR;
#else
        buf_para.bufname = t_name;
        buf_para.buf_size = size;
        buf_para.memtype = CMA_MEM;
        buf_para.cmd_id = HISI_SEC_ALLOC;
        args[0] = (unsigned int)(uintptr_t)&buf_para;
        args[1] = sizeof(struct hi_tee_smmu_ioctl_data);
        reval = hm_drv_call(HI_TEE_SYSCALL_SMMU_ID, args, ARRAY_SIZE(args));
        if (reval != HI_SUCCESS) {
            SMMU_LOG_ERROR("alloc mmz mem failed!\n");
        } else {
            phys_addr = buf_para.phys_addr;
        }
#endif
    } else if (memtype == HI_TEE_SEC_MMZ) {
        phys_addr = hi_tee_mmz_new(size, "SEC-MMZ", name);
        if (!phys_addr) {
            SMMU_LOG_ERROR("%s, alloc sec mmz mem failed!\n", __func__);
        }
    } else {
        SMMU_LOG_ERROR("%s, wrong type:%d  alloc sec mmz mem failed!\n", __func__, memtype);
    }

    return phys_addr;
}

int hi_tee_mmz_free(unsigned long long phys_addr)
{
    int ret;
    uint32_t reval;
    struct hi_tee_smmu_ioctl_data buf_para;
    unsigned int args[2] = {0}; /* init data to 0 and 2 is the array subscript */

    if (!phys_addr) {
        SMMU_LOG_ERROR("%s, err args, phys addr:0x%x\n", __func__, phys_addr);
        return HI_FAILED;
    }
    if (memset_s(&buf_para, sizeof(struct hi_tee_smmu_ioctl_data), 0x0,
                 sizeof(struct hi_tee_smmu_ioctl_data))) {
        return HI_FAILED;
    }

    ret = hi_tee_mmz_issmmz(phys_addr);
    if (ret == HI_FAILED) {
        return ret;
    }
    if (!ret) {
        buf_para.sec_addr = phys_addr;
        buf_para.memtype = CMA_MEM;
        buf_para.cmd_id = HISI_SEC_FREE;
        args[0] = (unsigned int)(uintptr_t)&buf_para;
        args[1] = sizeof(struct hi_tee_smmu_ioctl_data);
        reval = hm_drv_call(HI_TEE_SYSCALL_SMMU_ID, args, ARRAY_SIZE(args));
        if (reval != HI_SUCCESS) {
            SMMU_LOG_ERROR("%s, free mem failed, sec-phys:0x%x!\n", __func__, phys_addr);
            return -1;
        }
    } else {
        ret = hi_tee_mmz_delete(phys_addr);
        if (ret != HI_SUCCESS) {
            SMMU_LOG_ERROR("%s, free mem failed, sec-phys:0x%x!\n", __func__, phys_addr);
            return ret;
        }
    }
    return ret;
}

int hi_tee_mmz_alloc_and_map(const char *buf_name, size_t size, void **virt, unsigned long long *handle)
{
    int ret = HI_FAILED;
    if (virt == NULL) {
        return ret;
    }

    *virt = hi_tee_mmz_alloc_and_mapall(size, "SEC-MMZ", buf_name, handle);
    if (*virt != NULL) {
        ret = HI_SUCCESS;
    }

    return ret;
}

int hi_tee_mmz_unmap_and_free(void *virt, const unsigned long long handle)
{
    return hi_tee_mmz_unmap_and_freeall(virt, handle);
}

