/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: hsm firmware safety upgrade
 * Author: chenyao
 * Create: 2020-07-10
 */

#include "tee_ext_api.h"
#include "tee_log.h"
#include "securec.h"
#include "hsm_efuse_api.h"
#include "efuse_lib_api.h"
#include "efuse_ta_api.h"

static uint32_t g_efuse_power_status = 0;
static uint32_t g_dev_id_max = 0;

void efuse_set_dev_id(uint32_t dev_id)
{
    g_dev_id_max = (dev_id > 1) ? 1 : 0;
}

STATIC uint32_t efuse_dev_id_verify(uint32_t dev_id)
{
    if (dev_id > g_dev_id_max) {
        tloge("dev id invaild %d.\n", dev_id);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    return TEE_SUCCESS;
}

STATIC uint32_t efuse_block_num_verify(uint32_t efuse_block_num)
{
    if (efuse_block_num > 1) {
        tloge("efuse block num invaild %d.\n", efuse_block_num);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    return TEE_SUCCESS;
}

STATIC uint32_t efuse_params_verify(uint32_t efuse_block_num,
    uint8_t *efuse_ctx, uint32_t efuse_len, uint32_t dev_id)
{
    uint32_t ret;

    if (efuse_ctx == NULL) {
        tloge("invalid params.\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if ((efuse_len == 0) || (efuse_len > EFUSE_CTX_MAX_SIZE)) {
        tloge("invalid len, 0x%x.\n", efuse_len);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    ret = efuse_dev_id_verify(dev_id);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    ret = efuse_block_num_verify(efuse_block_num);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    return TEE_SUCCESS;
}

uint32_t sec_efuse_write(uint32_t efuse_block_num, uint32_t start_bit, uint32_t dest_size,
    uint8_t *efuse_ctx, uint32_t efuse_len, uint32_t dev_id)
{
    uint32_t ret;

    ret = efuse_params_verify(efuse_block_num, efuse_ctx, efuse_len, dev_id);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    if (g_efuse_power_status == 0) {
        ret = TEE_HSM_Power_On(dev_id);
        if (ret != TEE_SUCCESS) {
            tloge("efuse power on fail in efuse, 0x%x\n", ret);
            return TEE_ERROR_BAD_STATE;
        }
        g_efuse_power_status = 1;
    }

    ret = lib_efuse_write(efuse_block_num, start_bit, dest_size, efuse_ctx, efuse_len, dev_id);
    if (ret != TEE_SUCCESS) {
        tloge("efuse write fail, ret is : %x\n", ret);
        goto exit;
    }

    return TEE_SUCCESS;

exit:
    ret = TEE_HSM_Power_Off(dev_id);
    if (ret != TEE_SUCCESS) {
        tloge("efuse power off fail, 0x%x.\n", ret);
        return TEE_ERROR_BAD_STATE;
    }
    g_efuse_power_status = 0;

    return TEE_ERROR_BAD_STATE;
}

uint32_t sec_efuse_burn(uint32_t efuse_block_num, uint32_t dev_id)
{
    uint32_t ret0;
    uint32_t ret1;

    ret0 = efuse_dev_id_verify(dev_id);
    if (ret0 != TEE_SUCCESS) {
        return ret0;
    }

    ret0 = efuse_block_num_verify(efuse_block_num);
    if (ret0 != TEE_SUCCESS) {
        return ret0;
    }

    ret0 = lib_efuse_burn(efuse_block_num, dev_id);
    if (ret0 != TEE_SUCCESS) {
        tloge("efuse burn fail, 0x%x.\n", ret0);
        goto exit;
    }

exit:
    if (g_efuse_power_status == 1) {
        ret1 = TEE_HSM_Power_Off(dev_id);
        if (ret1 != TEE_SUCCESS) {
            tloge("efuse power off fail in efuse, 0x%x.\n", ret1);
            return TEE_ERROR_BAD_STATE;
        }
        g_efuse_power_status = 0;
    }

    return ret0;
}

uint32_t sec_efuse_check(uint32_t efuse_block_num, uint32_t start_bit, uint32_t dest_size,
    uint8_t *efuse_ctx, uint32_t efuse_len, uint32_t dev_id)
{
    uint32_t ret;

    ret = efuse_params_verify(efuse_block_num, efuse_ctx, efuse_len, dev_id);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    ret = lib_efuse_check(efuse_block_num, start_bit, dest_size, efuse_ctx, efuse_len, dev_id);
    if (ret != TEE_SUCCESS) {
        tloge("efuse check fail, 0x%x\n", ret);
        return ret;
    }

    return TEE_SUCCESS;
}
