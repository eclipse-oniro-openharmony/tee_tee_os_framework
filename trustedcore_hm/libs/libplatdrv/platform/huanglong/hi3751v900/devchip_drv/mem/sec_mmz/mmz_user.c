/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2009-2019. All rights reserved.
 * Description: Defines the common data type of the system.
 * Author: Hisilicon
 * Create: 2009-12-16
 */

#include "mmz_struct.h"
#include "media_mem.h"
#include "sec_mmz.h"
#include "hi_tee_drv_os_hal.h"
#include "hi_tee_drv_syscall_id.h"
#include "drv_param_type.h"
#ifdef CFG_HI_TEE_SMMU_SUPPORT
#include "hi_smmu.h"
#endif
#include "mmz_user.h"

static inline long mmz_access_check(void **addr, unsigned int size)
{
    unsigned int va = *(unsigned int *)(uintptr_t)addr;
    if (hi_tee_drv_hal_user_mmap((void **)&va, (unsigned int)(size))) {
        return TEE_ERROR_ACCESS_DENIED;
    }
    *addr = (void *)va;
    return HI_SUCCESS;
}

static inline long mmz_access_read_right_check(void *addr, unsigned long size)
{
    if (hi_tee_drv_hal_read_right_check(addr, (unsigned int)(size)) == false) {
        return TEE_ERROR_ACCESS_DENIED;
    }

    return HI_SUCCESS;
}

static inline long mmz_access_write_right_check(void *addr, unsigned long size)
{
    if (hi_tee_drv_hal_write_right_check(addr, (unsigned int)(size)) == false) {
        return TEE_ERROR_ACCESS_DENIED;
    }

    return HI_SUCCESS;
}

static inline long mmz_access_end(void *addr, unsigned long size)
{
    if (hi_tee_drv_hal_user_munmap(addr, (unsigned int)(size))) {
        return TEE_ERROR_ACCESS_DENIED;
    }

    return HI_SUCCESS;
}

#ifndef HI_FAILED
#define HI_FAILED  (-1)
#endif

#ifndef HI_SUCCESS
#define HI_SUCCESS 0
#endif

int mmz_new(struct hi_mmz_buf *buf, const char *mmz_name, const char *mmb_name)
{
    unsigned long mmb;
    struct hi_mmz_buf local_buf;
    char mmzname[HIL_MAX_NAME_LEN];
    char mmbname[HIL_MAX_NAME_LEN];
    int len = 0;

    if (buf == NULL) {
        return HI_FAILED;
    }
    if (memset_s(mmzname, HIL_MAX_NAME_LEN, 0x0, HIL_MAX_NAME_LEN)) {
        return HI_FAILED;
    }
    if (memset_s(mmbname, HIL_MAX_NAME_LEN, 0x0, HIL_MAX_NAME_LEN)) {
        return HI_FAILED;
    }
    if (memset_s(&local_buf, sizeof(struct hi_mmz_buf), 0x0, sizeof(struct hi_mmz_buf))) {
        return HI_FAILED;
    }

    local_buf.bufsize = buf->bufsize;
    local_buf.alloc_type = buf->alloc_type;

    if (mmz_name != NULL) {
        len = strlen(mmz_name) + 1;
        if (memcpy_s(mmzname, HIL_MAX_NAME_LEN, mmz_name,
            (len > HIL_MAX_NAME_LEN) ? HIL_MAX_NAME_LEN : len)) {
            return HI_FAILED;
        }
    }
    if (mmb_name != NULL) {
        len = strlen(mmb_name) + 1;
        if (memcpy_s(mmbname, HIL_MAX_NAME_LEN, mmb_name,
            (len > HIL_MAX_NAME_LEN) ? HIL_MAX_NAME_LEN : len)) {
            return HI_FAILED;
        }
    }
    mmzname[HIL_MAX_NAME_LEN - 1] = '\0';
    mmbname[HIL_MAX_NAME_LEN - 1] = '\0';
    mmb = new_mmb(mmbname, local_buf.bufsize, local_buf.alloc_type, mmzname);
    if (!mmb) {
        return HI_FAILED;
    } else {
        buf->phyaddr = mmb;
    }

    return HI_SUCCESS;
}

int mmz_del(unsigned long addr)
{
    delete_mmb(addr);
    return HI_SUCCESS;
}

int mmz_alloc_and_map(struct hi_smmu_buf *buf, const char *mmz_name, const char *mmb_name)
{
    struct hi_smmu_buf local_buf;
    char mmzname[HIL_MAX_NAME_LEN];
    char mmbname[HIL_MAX_NAME_LEN];
    int len = 0, ret;
    unsigned long long phyaddr, smmuaddr;

    if (buf == NULL) {
        return HI_FAILED;
    }
    if (memset_s(mmzname, HIL_MAX_NAME_LEN, 0x0, HIL_MAX_NAME_LEN)) {
        return HI_FAILED;
    }
    if (memset_s(mmbname, HIL_MAX_NAME_LEN, 0x0, HIL_MAX_NAME_LEN)) {
        return HI_FAILED;
    }
    if (memset_s(&local_buf, sizeof(struct hi_smmu_buf), 0x0, sizeof(struct hi_smmu_buf))) {
        return HI_FAILED;
    }

    local_buf.bufsize = buf->bufsize;
    local_buf.alloc_type = buf->alloc_type;

    if (mmz_name != NULL) {
        len = strlen(mmz_name);
        if (len == strlen("SEC-MMZ2")) {
            if (!memcmp(mmz_name, "SEC-MMZ2", strlen("SEC-MMZ2"))) {
                PRINTK_CA("ZONE SMMZ2 is forbidded in this intf!\n");
            }
            return HI_FAILED;
        }
        if (memcpy_s(mmzname, HIL_MAX_NAME_LEN, mmz_name,
            ((len + 1) > HIL_MAX_NAME_LEN) ? HIL_MAX_NAME_LEN : (len + 1))) {
            return HI_FAILED;
        }
    }
    if (mmb_name != NULL) {
        len = strlen(mmb_name);
        if (memcpy_s(mmbname, HIL_MAX_NAME_LEN, mmb_name,
            ((len + 1) > HIL_MAX_NAME_LEN) ? HIL_MAX_NAME_LEN : (len + 1))) {
            return HI_FAILED;
        }
    }
    mmzname[HIL_MAX_NAME_LEN - 1] = '\0';
    mmbname[HIL_MAX_NAME_LEN - 1] = '\0';

    phyaddr = new_mmb(mmbname, local_buf.bufsize, local_buf.alloc_type, mmzname);
    if (phyaddr == 0) {
        return HI_FAILED;
    }
    local_buf.virt = remap_mmb_uk((unsigned long)phyaddr);
    if (local_buf.virt == NULL) {
        goto err;
    }
#ifdef CFG_HI_TEE_SMMU_SUPPORT
    smmuaddr = hisi_sec_map_to_sec_smmu(phyaddr, local_buf.bufsize, 0);
    if (smmuaddr == 0) {
        goto unmap_mem;
    }
#else
    smmuaddr = 0;
#endif
    ret = get_handle_id(smmuaddr, &(local_buf.handle));
    if (ret) {
        goto out;
    }
    buf->handle = local_buf.handle;
    buf->virt = local_buf.virt;
    buf->bufsize = local_buf.bufsize;
    return HI_SUCCESS;

out:
    hisi_sec_unmap_from_sec_smmu(smmuaddr, 0);
unmap_mem:
    unmap_mmb_uk(local_buf.virt);
err:
    delete_mmb(phyaddr);
    return HI_FAILED;
}

int mmz_unmap_and_free(struct hi_smmu_buf *buf)
{
    struct hi_smmu_buf local_buf;
    unsigned long long phyaddr, smmuaddr;

    if (buf == NULL) {
        return HI_FAILED;
    }

    if (memset_s(&local_buf, sizeof(struct hi_smmu_buf), 0x0, sizeof(struct hi_smmu_buf))) {
        return HI_FAILED;
    }
    local_buf.handle = buf->handle;
    local_buf.virt = buf->virt;
    local_buf.bufsize = buf->bufsize;

    if (unmap_mmb_uk(local_buf.virt)) {
        return HI_FAILED;
    }
#ifdef CFG_HI_TEE_SMMU_SUPPORT
    if (get_sec_mem_info(local_buf.handle, &smmuaddr, &phyaddr,
                         &local_buf.bufsize)) {
        PRINTK_CA("get_sec_mem_info failed, handle:0x%llx \n", local_buf.handle);
        return HI_FAILED;
    }

    if (hisi_sec_unmap_from_sec_smmu(smmuaddr, 0)) {
        return HI_FAILED;
    }
#endif
    delete_mmb(phyaddr);
    return HI_SUCCESS;
}

int TEE_IsSecMMZ(unsigned long phys_addr)
{
    return is_sec_mmz(phys_addr);
}

int TEE_IsSecMem(unsigned long phys_addr, unsigned long size)
{
    return hil_tee_is_sec_mem(phys_addr, size);
}

int TEE_IsNonSecMem(unsigned long phys_addr, unsigned long size)
{
    return hil_tee_is_nonsec_mem(phys_addr, size);
}

static int hi_mmz_driver(struct hi_tee_mmz_ioctl_data *buffer, size_t len)
{
    int res = HI_FAILED;
    struct hi_tee_mmz_ioctl_data *buf_para = NULL;
    struct hi_tee_mmz_ioctl_data buf_local;

    if (buffer == NULL || len == 0) {
        PRINTK_CA("The buffer or the len may be NULL !\n");
        return HI_FAILED;
    }
    if (memset_s((void *)&buf_local, sizeof(struct hi_tee_mmz_ioctl_data), 0x0, sizeof(struct hi_tee_mmz_ioctl_data))) {
        return HI_FAILED;
    }

    buf_para = (struct hi_tee_mmz_ioctl_data *)buffer;
    if (memcpy_s((void *)&buf_local, sizeof(struct hi_tee_mmz_ioctl_data),
        buf_para, sizeof(struct hi_tee_mmz_ioctl_data))) {
        res = HI_FAILED;
        goto out;
    }

    switch (buf_local.cmd_id) {
        case MMZ_NEW_ID: {
            if (mmz_access_write_right_check(buf_para, len) ||
                mmz_access_check(&(buf_local.mmz_name), HIL_MAX_NAME_LEN) ||
                mmz_access_read_right_check(buf_local.mmz_name, HIL_MAX_NAME_LEN) ||
                mmz_access_check(&(buf_local.mmb_name), HIL_MAX_NAME_LEN) ||
                mmz_access_read_right_check(buf_local.mmb_name, HIL_MAX_NAME_LEN)) {
                return HI_FAILED;
            }
            res = mmz_new(&(buf_local.buf), buf_local.mmz_name, buf_local.mmb_name);
            if (res == HI_SUCCESS) {
                if (memcpy_s(buf_para, sizeof(struct hi_tee_mmz_ioctl_data),
                    (void *)&buf_local, sizeof(struct hi_tee_mmz_ioctl_data))) {
                    mmz_del(buf_local.buf.phyaddr);
                    res = HI_FAILED;
                }
            }
            if (mmz_access_end(buf_local.mmb_name, HIL_MAX_NAME_LEN) ||
                mmz_access_end(buf_local.mmz_name, HIL_MAX_NAME_LEN)) {
                return HI_FAILED;
            }
            break;
        }
        case MMZ_DEL_ID:
            res = mmz_del(buf_local.addr);
            break;
        case TEE_ISSECMMZ:
            if (mmz_access_write_right_check(buf_para, len)) {
                return HI_FAILED;
            }
            buf_local.arg0 = TEE_IsSecMMZ(buf_local.phys_addr);
            if (memcpy_s(buf_para, sizeof(struct hi_tee_mmz_ioctl_data),
                (void *)&buf_local, sizeof(struct hi_tee_mmz_ioctl_data))) {
                res = HI_FAILED;
            } else {
                res = HI_SUCCESS;
            }
            break;
        case TEE_ISSECMEM:
            if (mmz_access_write_right_check(buf_para, len)) {
                return HI_FAILED;
            }
            res = TEE_IsSecMem(buf_local.phys_addr, buf_local.size);
            if (res != HI_SUCCESS) {
                break;
            }
            buf_local.arg0 = res;
            if (memcpy_s(buf_para, sizeof(struct hi_tee_mmz_ioctl_data),
                (void *)&buf_local, sizeof(struct hi_tee_mmz_ioctl_data))) {
                res = HI_FAILED;
            } else {
                res = HI_SUCCESS;
            }
            break;
        case TEE_ISNONSECMEM:
            if (mmz_access_write_right_check(buf_para, len)) {
                return HI_FAILED;
            }
            res = TEE_IsNonSecMem(buf_local.phys_addr, buf_local.size);
            if (res != HI_SUCCESS) {
                break;
            }
            buf_local.arg0 = res;
            if (memcpy_s(buf_para, sizeof(struct hi_tee_mmz_ioctl_data),
                (void *)&buf_local, sizeof(struct hi_tee_mmz_ioctl_data))) {
                res = HI_FAILED;
            } else {
                res = HI_SUCCESS;
            }
            break;
        case MMZ_ALLOC_MAPALL_ID:
            if (mmz_access_write_right_check(buf_para, len) ||
                mmz_access_check(&(buf_local.mmz_name), HIL_MAX_NAME_LEN) ||
                mmz_access_read_right_check(buf_local.mmz_name, HIL_MAX_NAME_LEN) ||
                mmz_access_check(&(buf_local.mmb_name), HIL_MAX_NAME_LEN) ||
                mmz_access_read_right_check(buf_local.mmb_name, HIL_MAX_NAME_LEN)) {
                return HI_FAILED;
            }
            res = mmz_alloc_and_map(&(buf_local.smmu_buf), buf_local.mmz_name, buf_local.mmb_name);
            if (res != HI_FAILED) {
                if (memcpy_s(buf_para, sizeof(struct hi_tee_mmz_ioctl_data),
                    (void *)&buf_local, sizeof(struct hi_tee_mmz_ioctl_data))) {
                    mmz_unmap_and_free(&(buf_local.smmu_buf));
                    res = HI_FAILED;
                } else {
                    res = HI_SUCCESS;
                }
            }
            if (mmz_access_end(buf_local.mmb_name, HIL_MAX_NAME_LEN) ||
                mmz_access_end(buf_local.mmz_name, HIL_MAX_NAME_LEN)) {
                return HI_FAILED;
            }
            break;
        case MMZ_FREE_UNMAPALL_ID:
            res = mmz_unmap_and_free(&(buf_local.smmu_buf));
            break;
        default:
            PRINTK_CA("The op: not exist ! \n");
            res = HI_FAILED;
    }

out:
    return res;
}

int hi_mmz_driver_ioctl(int swi_id, struct drv_param *params, uint64_t permissions)
{
    if (params == NULL || params->args == 0)
        return -1;
    uint64_t  *args = (uint64_t *)(uintptr_t)params->args;
    HANDLE_SYSCALL(swi_id) {
        SYSCALL_PERMISSION(HI_TEE_SYSCALL_MMZ_ID, permissions, GENERAL_GROUP_PERMISSION)
            ACCESS_CHECK(args[0], sizeof(struct hi_tee_mmz_ioctl_data));
            args[0] = hi_mmz_driver((struct hi_tee_mmz_ioctl_data *)args[0], args[1]);
        SYSCALL_END
        default:
            return -EINVAL;
    }
    return 0;
}

hi_tee_drv_hal_driver_init(mmz_drv, 0, NULL, hi_mmz_driver_ioctl, NULL, NULL);
