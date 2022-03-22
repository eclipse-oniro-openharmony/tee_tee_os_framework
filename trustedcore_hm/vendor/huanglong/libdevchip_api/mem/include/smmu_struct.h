/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2009-2019. All rights reserved.
 * Description: Defines the common data type of the system.
 * Author: Hisilicon
 * Create: 2009-12-16
 */

#ifndef __SMMU_STRUCT_H__
#define __SMMU_STRUCT_H__

#ifdef __cplusplus
#if __cplusplus
extern "C"{
#endif
#endif /* End of #ifdef __cplusplus */


/*************************** Structure Definition ****************************/
/** \addtogroup      H_2_1_2 */
enum smmu_drv_ioctl_cmd_id {
    HISI_SEC_MAPTOSMMU = 0x0,
    HISI_SEC_UNMAPFROMSMMU,
    HISI_SEC_MAPTOSMMU_AND_SETFLAG,
    HISI_SEC_UNMAPFROMSMMU_AND_CLRFLG,
    HISI_SEC_ALLOC,
    HISI_SEC_FREE,
    HISI_NOSEC_MEM_MAP_TO_SEC_SMMU,
    HISI_NOSEC_MEM_UNMAP_FROM_SEC_SMMU,
    AGENT_CLOSED,
    SEC_IOCTL,
    CHECK_SEC_SMMU,
    CHECK_SEC_MMZ,
};

struct hi_tee_smmu_ioctl_data {
    char *bufname;
    unsigned long long phys_addr;
    unsigned long long sec_addr;
    unsigned long long nonsec_addr;
    unsigned long long buf_phys;
    unsigned long long buf_size;
    unsigned long long smmu_addr;
    unsigned long long cmd;
    unsigned long long arg0;
    unsigned long long arg1;
    int memtype;
    int share_mem;
    enum smmu_drv_ioctl_cmd_id cmd_id;
};

#define SMMU_LOG_ERROR(fmt...)  tloge(fmt)
#define SMMU_LOG_WARN(fmt...)   tlogw(fmt)
#define SMMU_LOG_INFO(fmt...)   tlogi(fmt)


/* End of CMPI */

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */

#endif  /* __SMMU_STRUCT_H__ */

