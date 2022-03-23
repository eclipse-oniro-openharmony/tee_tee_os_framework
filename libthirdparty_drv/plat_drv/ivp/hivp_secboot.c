/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: This file implement some api for load ivp bin
 * Create: 2020-05-30
 */

#include <stdio.h>
#include <errno.h>
#include <stdint.h>
#include <drv_mem.h>
#include <sre_typedef.h>
#include <drv_module.h>
#include <mem_ops.h>
#include "hisi_secureboot.h"
#include "secmem.h"
#include "securec.h"
#include "string.h"
#include "tee_log.h"
#include "sre_task.h"
#include "sre_syscalls_id_ext.h"
#include "sre_syscalls_id.h"
#include "sre_access_control.h"
#include "drv_pal.h"
#include "sre_syscall.h"
#include "dynion.h"
#include "sec_smmu_com.h"

#include <hmdrv_stub.h> /* keep this last */

#define SECSMMU_STREAMID_IVP    11
#define SECSMMU_SUBSTREAMID_IVP 6

#define IVP_EOK    0
#define IVP_EINVAL 1

#ifndef UNUSED
#define UNUSED(a) (a=a)
#endif

#define SECOS_PARAM_INDEX0 0
#define SECOS_PARAM_INDEX1 1
#define SECOS_PARAM_INDEX2 2
#define SECOS_PARAM_INDEX3 3

typedef struct {
    int sharefd;           /* memory fd */
    unsigned int size;     /* memory size */
    unsigned int type;     /* memory type */
    unsigned int da;       /* device address */
    unsigned int prot;     /* operation right */
    unsigned int sec_flag; /* secure flag */
    unsigned long long pa; /* physical address */
} secivp_mem_info;

static UINT32 hivp_nonsec_mem_map(struct smmu_domain *domain, secivp_mem_info *buffer, struct sglist *sgl)
{
    UINT32 ret;

    if (buffer->da == 0) {
        tloge("wrong da, da.0x%x", buffer->da);
        return IVP_EINVAL;
    }

    if (buffer->size == 0) {
        tloge("wrong size, size.0x%x", buffer->size);
        return IVP_EINVAL;
    }

    if (buffer->sec_flag != non_secure) {
        tloge("wrong sec flag, sec flag.%u", buffer->sec_flag);
        return IVP_EINVAL;
    }

    tlogi("iommu map for secivp mem");
    ret = siommu_map(domain, sgl, buffer->da, buffer->size, buffer->prot, buffer->sec_flag);
    if (ret != IVP_EOK)
        tloge("fail, siommu_map. ret.%u", ret);

    return ret;
}

static UINT32 hivp_nonsec_mem_unmap(struct smmu_domain *domain, secivp_mem_info *buffer, struct sglist *sgl)
{
    UINT32 ret;

    if (buffer->da == 0) {
        tloge("wrong da, da.0x%x", buffer->da);
        return IVP_EINVAL;
    }

    if (buffer->size == 0) {
        tloge("wrong size, size.0x%x", buffer->size);
        return IVP_EINVAL;
    }

    if (buffer->sec_flag != non_secure) {
        tloge("wrong sec flag, sec flag.%u", buffer->sec_flag);
        return IVP_EINVAL;
    }

    tlogi("iommu unmap for secivp mem");
    ret = siommu_unmap(domain, sgl, buffer->da, buffer->size, buffer->sec_flag);
    if (ret != IVP_EOK)
        tloge("fail, siommu_unmap. ret.%u", ret);

    return ret;
}

static UINT32 hivp_sec_mem_map(secivp_mem_info *buffer, UINT32 sfd)
{
    struct mem_chunk_list mcl;
    UINT32 ret;

    if (buffer == NULL) {
        tloge("buffer is null");
        return IVP_EINVAL;
    }
    if (buffer->size == 0) { /* secmem size maybe empty, need secmem feedback */
        tloge("empty size, size.0x%x", buffer->size);
    }
    if (buffer->sec_flag != secure) {
        tloge("wrong sec flag, sec flag.%d", buffer->sec_flag);
        return IVP_EINVAL;
    }

    mcl.protect_id = SEC_TASK_SEC;
    mcl.buff_id = sfd;
    mcl.va = buffer->da;
    mcl.size = buffer->size;
    mcl.prot = buffer->prot;
    mcl.mode = buffer->sec_flag;
    tlogi("iommu map for secivp mem");
    ret = sion_map_iommu(&mcl);
    if (ret != IVP_EOK)
        tloge("fail, sion_map_iommu. ret.%u", ret);
    else
        buffer->size = mcl.size; /* feedback real size , secmem support */
    return ret;
}

static UINT32 hivp_sec_mem_unmap(secivp_mem_info *buffer, UINT32 sfd)
{
    struct mem_chunk_list mcl;
    UINT32 ret;

    if (buffer == NULL) {
        tloge("buffer is null");
        return IVP_EINVAL;
    }
    if (buffer->size == 0) {
        tloge("wrong size, size.0x%x", buffer->size);
        return IVP_EINVAL;
    }
    if (buffer->sec_flag != secure) {
        tloge("wrong sec flag, sec flag.%d", buffer->sec_flag);
        return IVP_EINVAL;
    }

    mcl.protect_id = SEC_TASK_SEC;
    mcl.buff_id = sfd;
    mcl.va = buffer->da;
    mcl.size = buffer->size;
    mcl.prot = buffer->prot;
    mcl.mode = buffer->sec_flag;
    mcl.smmuid = SMMU_MEDIA2;
    mcl.sid = SECSMMU_STREAMID_IVP;
    mcl.ssid = SECSMMU_SUBSTREAMID_IVP;
    tlogi("iommu unmap for secivp mem");
    ret = sion_unmap_iommu(&mcl);
    if (ret != IVP_EOK)
        tloge("fail, sion_unmap_iommu. ret.%u", ret);

    return ret;
}

static UINT32 secivp_nonsec_map(struct smmu_domain *domain, secivp_mem_info *buffer, struct sglist *sgl)
{
    UINT32 ret;

    if (buffer == NULL) {
        tloge("buffer is NULL");
        return IVP_EINVAL;
    }

    if (sgl == NULL) {
        tloge("sgl is NULL");
        return IVP_EINVAL;
    }

    tlogi("set up pagetable mapping by buffer information");
    ret = hivp_nonsec_mem_map(domain, buffer, sgl);
    if (ret != IVP_EOK)
        tloge("hivp_nonsec_mem_map fail. ret.%u", ret);

    return ret;
}

static UINT32 secivp_nonsec_unmap(struct smmu_domain *domain, secivp_mem_info *buffer, struct sglist *sgl)
{
    UINT32 ret;

    if (buffer == NULL) {
        tloge("buffer is NULL");
        return IVP_EINVAL;
    }

    if (sgl == NULL) {
        tloge("sgl is NULL");
        return IVP_EINVAL;
    }

    tlogi("set up pagetable mapping by buffer information");
    ret = hivp_nonsec_mem_unmap(domain, buffer, sgl);
    if (ret != IVP_EOK)
        tloge("hivp_nonsec_mem_unmap fail. ret.%u", ret);

    return ret;
}

static UINT32 ivp_syscall_secivp_sec_mem_map(UINT64 *args)
{
    UINT32 ret;
    UINT32 sfd;
    secivp_mem_info *buffer = NULL;

    sfd = (UINT32)(args[SECOS_PARAM_INDEX0]);
    buffer = (secivp_mem_info *)(uintptr_t)(args[SECOS_PARAM_INDEX2]);
    if (args[SECOS_PARAM_INDEX3] != sizeof(secivp_mem_info)) {
        tloge("wrong buffer_size.0x%x", args[SECOS_PARAM_INDEX3]);
        return IVP_EINVAL;
    }

    ret = hivp_sec_mem_map(buffer, sfd);
    if (ret != IVP_EOK)
        tloge("hivp_sec_mem_map fail. ret.%u", ret);

    return ret;
}

static UINT32 ivp_syscall_secivp_sec_mem_unmap(UINT64 *args)
{
    UINT32 ret;
    UINT32 sfd;
    secivp_mem_info *buffer = NULL;

    sfd = (UINT32)(args[SECOS_PARAM_INDEX0]);
    buffer = (secivp_mem_info *)(uintptr_t)(args[SECOS_PARAM_INDEX2]);
    if (args[SECOS_PARAM_INDEX3] != sizeof(secivp_mem_info)) {
        tloge("wrong buffer_size.0x%x", args[SECOS_PARAM_INDEX3]);
        return IVP_EINVAL;
    }

    ret = hivp_sec_mem_unmap(buffer, sfd);
    if (ret != IVP_EOK)
        tloge("hivp_sec_mem_unmap fail. ret.%u", ret);

    return ret;
}

static UINT32 ivp_syscall_secivp_nonsec_mem_map(UINT64 *args)
{
    UINT32 ret;
    struct sglist *sgl = NULL;
    struct smmu_domain *domain = NULL;
    secivp_mem_info *buffer = NULL;

    sgl = (struct sglist *)(uintptr_t)(args[SECOS_PARAM_INDEX0]);
    buffer = (secivp_mem_info *)(uintptr_t)(args[SECOS_PARAM_INDEX2]);
    if (args[SECOS_PARAM_INDEX3] != sizeof(secivp_mem_info) ||
        args[SECOS_PARAM_INDEX1] < sizeof(struct sglist)) {
        tloge("wrong size1 %x size3 %x", args[SECOS_PARAM_INDEX1],
            args[SECOS_PARAM_INDEX3]);
        return IVP_EINVAL;
    }

    domain = siommu_domain_grab(SEC_TASK_SEC);
    if (domain == NULL) {
        tloge("siommu_domain_grab fail");
        return IVP_EINVAL;
    }

    ret = secivp_nonsec_map(domain, buffer, sgl);
    if (ret != IVP_EOK)
        tloge("secivp_nonsec_map fail. ret.%u.", ret);

    return ret;
}

static UINT32 ivp_syscall_secivp_nonsec_mem_unmap(UINT64 *args)
{
    UINT32 ret;
    struct sglist *sgl = NULL;
    struct smmu_domain *domain = NULL;
    secivp_mem_info *buffer = NULL;

    sgl = (struct sglist *)(uintptr_t)(args[SECOS_PARAM_INDEX0]);
    buffer = (secivp_mem_info *)(uintptr_t)(args[SECOS_PARAM_INDEX2]);
    if (args[SECOS_PARAM_INDEX3] != sizeof(secivp_mem_info) ||
        args[SECOS_PARAM_INDEX1] < sizeof(struct sglist)) {
        tloge("wrong size1 %x size3 %x", args[SECOS_PARAM_INDEX1],
            args[SECOS_PARAM_INDEX3]);
        return IVP_EINVAL;
    }

    domain = siommu_domain_grab(SEC_TASK_SEC);
    if (domain == NULL) {
        tloge("siommu_domain_grab fail");
        return IVP_EINVAL;
    }

    ret = secivp_nonsec_unmap(domain, buffer, sgl);
    if (ret != IVP_EOK)
        tloge("secivp_nonsec_unmap fail. ret.%u.", ret);

    return ret;
}

static UINT32 ivp_syscall_secivp_smmu_poweron()
{
    return (UINT32)sec_smmu_poweron(SMMU_MEDIA2);
}

static UINT32 ivp_syscall_secivp_smmu_poweroff()
{
    return (UINT32)sec_smmu_poweroff(SMMU_MEDIA2);
}

static UINT32 ivp_syscall_secivp_smmu_bind()
{
    return (UINT32)sec_smmu_bind(SMMU_MEDIA2, SECSMMU_STREAMID_IVP, SECSMMU_SUBSTREAMID_IVP, 0);
}

static UINT32 ivp_syscall_secivp_smmu_unbind()
{
    return (UINT32)sec_smmu_unbind(SMMU_MEDIA2, SECSMMU_STREAMID_IVP, SECSMMU_SUBSTREAMID_IVP);
}

static int ivp_syscall(int swi_id, struct drv_param *params, UINT64 permissions)
{
    UINT32 uwRet = 0;
    /*
     * According to ARM AAPCS arguments from 5-> in a function call
     * are stored on the stack, which in this case is pointer by
     * user sp. Our own TrustedCore also push FP and LR on the stack
     * just before SWI, so skip them
     */
    if (params == NULL || params->args == 0)
        return -1;
    UINT64 *args = (UINT64 *)(uintptr_t)params->args;

    HANDLE_SYSCALL(swi_id) {
        SYSCALL_PERMISSION(SW_SYSCALL_SECIVP_SEC_MEM_MAP, permissions, IVP_GROUP_PERMISSION)
        ACCESS_CHECK_A64(args[SECOS_PARAM_INDEX2], args[SECOS_PARAM_INDEX3]);
        ACCESS_WRITE_RIGHT_CHECK(args[SECOS_PARAM_INDEX2], args[SECOS_PARAM_INDEX3]);
        uwRet = ivp_syscall_secivp_sec_mem_map(args);
        SYSCALL_END

        SYSCALL_PERMISSION(SW_SYSCALL_SECIVP_SEC_MEM_UNMAP, permissions, IVP_GROUP_PERMISSION)
        ACCESS_CHECK_A64(args[SECOS_PARAM_INDEX2], args[SECOS_PARAM_INDEX3]);
        ACCESS_WRITE_RIGHT_CHECK(args[SECOS_PARAM_INDEX2], args[SECOS_PARAM_INDEX3]);
        uwRet = ivp_syscall_secivp_sec_mem_unmap(args);
        SYSCALL_END

        SYSCALL_PERMISSION(SW_SYSCALL_SECIVP_SEC_NONMEM_MAP, permissions, IVP_GROUP_PERMISSION)
        ACCESS_CHECK_A64(args[SECOS_PARAM_INDEX0], args[SECOS_PARAM_INDEX1]);
        ACCESS_CHECK_A64(args[SECOS_PARAM_INDEX2], args[SECOS_PARAM_INDEX3]);
        ACCESS_WRITE_RIGHT_CHECK(args[SECOS_PARAM_INDEX0], args[SECOS_PARAM_INDEX1]);
        ACCESS_WRITE_RIGHT_CHECK(args[SECOS_PARAM_INDEX2], args[SECOS_PARAM_INDEX3]);
        uwRet = ivp_syscall_secivp_nonsec_mem_map(args);
        SYSCALL_END

        SYSCALL_PERMISSION(SW_SYSCALL_SECIVP_SEC_NONMEM_UNMAP, permissions, IVP_GROUP_PERMISSION)
        ACCESS_CHECK_A64(args[SECOS_PARAM_INDEX0], args[SECOS_PARAM_INDEX1]);
        ACCESS_CHECK_A64(args[SECOS_PARAM_INDEX2], args[SECOS_PARAM_INDEX3]);
        ACCESS_WRITE_RIGHT_CHECK(args[SECOS_PARAM_INDEX0], args[SECOS_PARAM_INDEX1]);
        ACCESS_WRITE_RIGHT_CHECK(args[SECOS_PARAM_INDEX2], args[SECOS_PARAM_INDEX3]);
        uwRet = ivp_syscall_secivp_nonsec_mem_unmap(args);
        SYSCALL_END

        SYSCALL_PERMISSION(SW_SYSCALL_SECIVP_SMMU_ON, permissions, IVP_GROUP_PERMISSION)
        uwRet = ivp_syscall_secivp_smmu_poweron();
        SYSCALL_END

        SYSCALL_PERMISSION(SW_SYSCALL_SECIVP_SMMU_OFF, permissions, IVP_GROUP_PERMISSION)
        uwRet = ivp_syscall_secivp_smmu_poweroff();
        SYSCALL_END

        SYSCALL_PERMISSION(SW_SYSCALL_SECIVP_SEC_BIND, permissions, IVP_GROUP_PERMISSION)
        uwRet = ivp_syscall_secivp_smmu_bind();
        SYSCALL_END

        SYSCALL_PERMISSION(SW_SYSCALL_SECIVP_SEC_UNBIND, permissions, IVP_GROUP_PERMISSION)
        uwRet = ivp_syscall_secivp_smmu_unbind();
        SYSCALL_END
    default:
        return -IVP_EINVAL;
    }

    args[SECOS_PARAM_INDEX0] = uwRet;
    return IVP_EOK;
}

DECLARE_TC_DRV(ivp_driver, 0, 0, 0, TC_DRV_MODULE_INIT, NULL, NULL, ivp_syscall, NULL, NULL);
