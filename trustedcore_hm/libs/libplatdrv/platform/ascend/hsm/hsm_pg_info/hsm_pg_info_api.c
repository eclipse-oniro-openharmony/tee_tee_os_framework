/*
* Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
* Description: hsm pg indo api file
* Author: huawei
* Create: 2020/9/3
*/
#include "tee_log.h"
#include "tee_defines.h"
#include "tee_bit_ops.h"
#include "drv_module.h"
#include "sre_access_control.h"
#include "sre_syscalls_id_ext.h"
#include "drv_mem.h"
#include <hmdrv_stub.h>
#include "drv_param_type.h"
#include "securec.h"

#include "hsm_dev_id.h"
#include "driver_common.h"
#include "hsm_pg_info_api.h"

STATIC TEE_Result get_module_core_info(PG_INFO_MNG *pg_data, uint32_t module,
                                       COMMON_PG_INFO **core_info)
{
    if (module == PG_MODULE_TYPE_CPU) {
        *core_info = &pg_data->cpu_info;
    } else if (module == PG_MODULE_TYPE_AIC) {
        *core_info = &pg_data->aic_info;
    } else if (module == PG_MODULE_TYPE_AIV) {
        *core_info = &pg_data->aiv_info;
    } else if (module == PG_MODULE_TYPE_HBM) {
        *core_info = &pg_data->hbm_info;
    } else {
        *core_info = NULL;
        tloge("invalid pg module, 0x%x.\n", module);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    return TEE_SUCCESS;
}

STATIC TEE_Result read_totalnum_and_bitmapindex(PG_INFO_MNG *pg_data, uint32_t module,
                                                uint32_t *total_num, uint32_t *bitmap_index)
{
    COMMON_PG_INFO *core_info = NULL;
    TEE_Result ret;

    ret = get_module_core_info(pg_data, module, &core_info);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    *total_num = core_info->total_num;
    *bitmap_index = core_info->bitmap_index;

    return TEE_SUCCESS;
}

STATIC TEE_Result read_pg_freq(PG_INFO_MNG *pg_data, uint32_t module, uint64_t *rsp_data)
{
    COMMON_PG_INFO *core_info = NULL;
    TEE_Result ret;

    ret = get_module_core_info(pg_data, module, &core_info);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    *rsp_data = core_info->freq;

    return TEE_SUCCESS;
}

STATIC TEE_Result read_pg_totalnum(PG_INFO_MNG *pg_data, uint32_t module, uint64_t *rsp_data)
{
    COMMON_PG_INFO *core_info = NULL;
    TEE_Result ret;

    ret = get_module_core_info(pg_data, module, &core_info);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    *rsp_data = core_info->total_num;

    return TEE_SUCCESS;
}

STATIC TEE_Result read_pg_coremap(PG_INFO_MNG *pg_data, uint32_t module,
                                  uint8_t *rsp_data, uint32_t rsp_data_len)
{
    uint32_t total_core_num;
    uint32_t bitmap_index;
    uint8_t remain_bits_num, bytes_num;
    TEE_Result ret;

    ret = read_totalnum_and_bitmapindex(pg_data, module, &total_core_num, &bitmap_index);
    if (ret != TEE_SUCCESS) {
        tloge("Invalid pg module for coremap");
        return ret;
    }

    /* every core is related to 1 bit in bitmap, 8bits a set */
    bytes_num = (total_core_num + BIT_WIDTH_BYTE - 1) / BIT_WIDTH_BYTE;
    if ((bytes_num > MAX_CORE_BITMAP_NUM) || (bitmap_index >= MAX_CORE_BITMAP_NUM)) {
        tloge("Invalid bitmap index or bytenums, 0x%x, 0x%x.\n", bytes_num, bitmap_index);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (bytes_num > 0) {
        ret = (TEE_Result)memcpy_s(rsp_data, rsp_data_len,
                                   &pg_data->bitMap[bitmap_index], bytes_num);
        if (ret != EOK) {
            tloge("Copy pg data failed, 0x%x, 0x%x.\n", bytes_num, bitmap_index);
            return TEE_ERROR_SHORT_BUFFER;
        }
    }

    remain_bits_num = total_core_num % BIT_WIDTH_BYTE;
    if (remain_bits_num > 0) {
        // Assign the valid bit mask in last byte for this module to @byte_mask
        uint8_t byte_mask = (1 << remain_bits_num) - 1;
        rsp_data[bytes_num - 1] &= byte_mask;
    }

    return TEE_SUCCESS;
}

STATIC TEE_Result read_pg_info_main(PG_INFO_MNG *pg_data, uint32_t module,
                                    uint32_t data_type, uint64_t *out_data)
{
    TEE_Result ret;
    uint64_t rsp_data = 0;

    if (data_type == PG_DATA_TYPE_FREQ) {
        ret = read_pg_freq(pg_data, module, &rsp_data);
    } else if (data_type == PG_DATA_TYPE_TOTAL_NUM) {
        ret = read_pg_totalnum(pg_data, module, &rsp_data);
    } else if (data_type == PG_DATA_TYPE_CORE_MAP) {
        ret = read_pg_coremap(pg_data, module, (uint8_t *)&rsp_data, sizeof(uint64_t));
    } else {
        tloge("invalid pg data_type, 0x%x.\n", data_type);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    *out_data = rsp_data;

    return TEE_SUCCESS;
}

TEE_Result syscall_tee_read_pg_info(uint32_t dev_id, uint32_t module, uint32_t data_type, uint64_t *out_data)
{
    TEE_Result ret;
    TEE_Result unmap_ret;
    PG_INFO_MNG *pg_data = NULL;
    uint64_t pg_info_addr = 0;
    uint64_t pg_info_paddr = 0;

    ret = drv_dev_id_verify(dev_id);
    if (ret != 0) {
        return ret;
    }

    if (out_data == NULL) {
        tloge("Invalid out data.\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    pg_info_paddr = TEE_PG_INFO_ADDR + (CHIP_OFFSET * dev_id);
    // Need to translate to va and operate specific physic space
    ret = (TEE_Result)sre_mmap(pg_info_paddr, READ_PG_INFO_LEN,
                               (uintptr_t *)&pg_info_addr, secure, non_cache);
    if (ret != 0) {
        tloge("Mmap pg info addr failed, 0x%x!\n", ret);
        return ret;
    }

    pg_data = (PG_INFO_MNG *)(uintptr_t)pg_info_addr;
    if (pg_data == NULL) {
        tloge("Invalid mapped pg addr.\n");
        ret = TEE_ERROR_BAD_PARAMETERS;
        goto exit_unmap;
    }

    if (pg_data->magic != PG_INFO_MAGIC) {
        tloge("No pg data detected, 0x%x\n", pg_data->magic);
        ret = TEE_ERROR_BAD_PARAMETERS;
        goto exit_unmap;
    }

    ret = read_pg_info_main(pg_data, module, data_type, out_data);
    if (ret != TEE_SUCCESS) {
        tloge("sre unmap nonsecure addr failed!\n");
    }

exit_unmap:
    unmap_ret = (uint32_t)sre_unmap(pg_info_addr, READ_PG_INFO_LEN);
    if (unmap_ret != 0) {
        tloge("sre unmap nonsecure addr failed!\n");
        return unmap_ret;
    }

    return ret;
}

int pg_info_get_syscall(int swi_id, struct drv_param *params, uint64_t permissions)
{
    uint64_t *args = NULL;
    uint32_t dev_id;
    uint32_t module;
    uint32_t data;
    uint64_t out_data_addr;

    if ((params == NULL) || (params->args == 0)) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    args = (uint64_t *)(uintptr_t)params->args;

    HANDLE_SYSCALL(swi_id) {
        SYSCALL_PERMISSION(SYSCALL_HSM_PG_GET, permissions, HSM_GROUP_PERMISSION)
        dev_id = args[0];
        module = args[1];
        data = args[ARRAY_INDEX2];
        out_data_addr = args[ARRAY_INDEX3];
        ACCESS_CHECK_A64(out_data_addr, READ_PG_INFO_LEN);
        ACCESS_WRITE_RIGHT_CHECK(out_data_addr, READ_PG_INFO_LEN);
        args[0] = syscall_tee_read_pg_info(dev_id, module, data, (uint64_t *)(uintptr_t)out_data_addr);
        SYSCALL_END
    default:
        return TEE_ERROR_NOT_SUPPORTED;
    }

    return TEE_SUCCESS;
}

DECLARE_TC_DRV(
    pg_info_get_driver,
    0,
    0,
    0,
    TC_DRV_MODULE_INIT,
    NULL,
    NULL,
    pg_info_get_syscall,
    NULL,
    NULL
);
