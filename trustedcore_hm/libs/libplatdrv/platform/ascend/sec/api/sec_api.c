/*
* Copyright (c) Huawei Technologies Co., Ltd. 2019-2021. All rights reserved.
* Description: the source of sec api function
* Author: huawei
* Create: 2019/12/30
*/
#include "drv_module.h"
#include "tee_defines.h"
#include "sre_access_control.h"
#include "tee_log.h"
#include "register_ops.h"
#include "timer.h"
#include <hmdrv_stub.h>
#include "sre_syscalls_id.h"

#include "securec.h"

#include "driver_common.h"
#include "sec_api.h"
#include "sec_a_hal.h"
#include "sec_internal_api.h"
#include "hsm_update_api.h"
#include "hsm_dev_id.h"
#include "oemkey_driver_hal.h"
#include "crypto_driver_adaptor.h"

static uint32_t g_sec_operating_status = 0;

static const uint8_t g_hash_sha1_result[] = {
    0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32, 0x55, 0xbf, 0xef, 0x95, 0x60, 0x18, 0x90,
    0xaf, 0xd8, 0x07, 0x09
};

static const uint8_t g_hash_sha224_result[] = {
    0xd1, 0x4a, 0x02, 0x8c, 0x2a, 0x3a, 0x2b, 0xc9, 0x47, 0x61, 0x02, 0xbb, 0x28, 0x82, 0x34, 0xc4,
    0x15, 0xa2, 0xb0, 0x1f, 0x82, 0x8e, 0xa6, 0x2a, 0xc5, 0xb3, 0xe4, 0x2f
};

static const uint8_t g_hash_sha256_result[] = {
    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
    0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
};

static const uint8_t g_hash_sha384_result[] = {
    0x38, 0xb0, 0x60, 0xa7, 0x51, 0xac, 0x96, 0x38, 0x4c, 0xd9, 0x32, 0x7e, 0xb1, 0xb1, 0xe3, 0x6a,
    0x21, 0xfd, 0xb7, 0x11, 0x14, 0xbe, 0x07, 0x43, 0x4c, 0x0c, 0xc7, 0xbf, 0x63, 0xf6, 0xe1, 0xda,
    0x27, 0x4e, 0xde, 0xbf, 0xe7, 0x6f, 0x65, 0xfb, 0xd5, 0x1a, 0xd2, 0xf1, 0x48, 0x98, 0xb9, 0x5b
};

static const uint8_t g_hash_sha512_result[] = {
    0xcf, 0x83, 0xe1, 0x35, 0x7e, 0xef, 0xb8, 0xbd, 0xf1, 0x54, 0x28, 0x50, 0xd6, 0x6d, 0x80, 0x07,
    0xd6, 0x20, 0xe4, 0x05, 0x0b, 0x57, 0x15, 0xdc, 0x83, 0xf4, 0xa9, 0x21, 0xd3, 0x6c, 0xe9, 0xce,
    0x47, 0xd0, 0xd1, 0x3c, 0x5d, 0x85, 0xf2, 0xb0, 0xff, 0x83, 0x18, 0xd2, 0x87, 0x7e, 0xec, 0x2f,
    0x63, 0xb9, 0x31, 0xbd, 0x47, 0x41, 0x7a, 0x81, 0xa5, 0x38, 0x32, 0x7a, 0xf9, 0x27, 0xda, 0x3e
};

static const uint8_t g_hash_sm3_result[] = {
    0x1a, 0xb2, 0x1d, 0x83, 0x55, 0xcf, 0xa1, 0x7f, 0x8e, 0x61, 0x19, 0x48, 0x31, 0xe8, 0x1a, 0x8f,
    0x22, 0xbe, 0xc8, 0xc7, 0x28, 0xfe, 0xfb, 0x74, 0x7e, 0xd0, 0x35, 0xeb, 0x50, 0x82, 0xaa, 0x2b
};

static const hash_zero_map_s g_hash_map[] = {
    {SHA1,      SEC_SHA1_ZERO_DATA_LEN,       g_hash_sha1_result},
    {SHA224,    SEC_SHA224_ZERO_DATA_LEN,     g_hash_sha224_result},
    {SHA256,    SEC_SHA256_ZERO_DATA_LEN,     g_hash_sha256_result},
    {SHA384,    SEC_SHA384_ZERO_DATA_LEN,     g_hash_sha384_result},
    {SHA512,    SEC_SHA512_ZERO_DATA_LEN,     g_hash_sha512_result},
    {SM3,       SEC_SM3_ZERO_DATA_LEN,        g_hash_sm3_result},
};

const unsigned char g_img_key2_salt[SEC_IMG_KEY2_SALT_LEN] = {0x4F, 0xE3, 0x42, 0xE2, 0xFE, 0x1A, 0x7F, 0x9B,
                                                              0x8E, 0xE7, 0xEB, 0x4A, 0x7C, 0x0F, 0x9E, 0x16,
                                                              0x2B, 0xCE, 0x33, 0x57, 0x6B, 0x31, 0x5E, 0xCE,
                                                              0xCB, 0xB6, 0x40, 0x68, 0x37, 0xBF, 0x51, 0xF5};
STATIC void set_operation_status(uint32_t value)
{
    g_sec_operating_status = value;
}

STATIC uint32_t get_operation_status(void)
{
    return g_sec_operating_status;
}

uint32_t sec_init(uint32_t is_first_flag)
{
    volatile uint32_t ret;

    ret = drv_dev_num_init();
    if (ret != SEC_SUCCESS) {
        tloge("drv get dev num failed, 0x%x\n", ret);
        return ret;
    }

    set_operation_status(1);

    /* only first init need reset step */
    if (is_first_flag == SEC_FIRST_INIT) {
        ret = sec_clk_rst();
        if (ret != SEC_SUCCESS) {
            tloge("sec clock reset failed, 0x%x\n", ret);
            goto OUT;
        }
    }

    ret = sec_pf_conf();
    if (ret != SEC_SUCCESS) {
        tloge("sec pf config failed, 0x%x.\n", ret);
        goto OUT;
    }

    /* bd fifo init */
    sec_bd_fifo_conf();

    /* check init */
    ret = sec_check_init();
    if (ret != SEC_SUCCESS) {
        tloge("sec check init failed, 0x%x.\n", ret);
    }

OUT:
    set_operation_status(0);
    return ret;
}

STATIC uint32_t sec_init_status_check(void)
{
    uint32_t ret;

    ret = sec_init_check();
    if (ret == SEC_SUCCESS) {
        return SEC_SUCCESS;
    }

    tloge("sec init failed, 0x%x\n", ret);
    return sec_init(SEC_NOT_FIRST_INIT);
}

uint32_t sec_km_key_req(SEC_KEY_LOAD_S key_type)
{
    uint32_t ret;

    set_operation_status(1);

    ret = sec_init_status_check();
    if (ret != SEC_SUCCESS) {
        goto OUT;
    }

    ret = km_req_key_hand((uint32_t)(key_type));
    if (ret != SEC_SUCCESS) {
        tloge("sec km key request\n");
    }

OUT:
    set_operation_status(0);
    return ret;
}

uint32_t sec_aes_sm4(SEC_AES_INFO_S *aes_sm4_info)
{
    uint32_t ret;

    set_operation_status(1);

    ret = sec_init_status_check();
    if (ret != SEC_SUCCESS) {
        goto OUT;
    }

    ret = sec_aes_sm4_bd(aes_sm4_info);
    if (ret != SEC_SUCCESS) {
        tloge("sec aes ctr failed, 0x%x.\n", ret);
        goto OUT;
    }

    dsb();

    ret = sec_add_task(aes_sm4_info->bd_addr);
    if (ret != SEC_SUCCESS) {
        tloge("sec add task failed, 0x%x.\n", ret);
        goto OUT;
    }

    dsb();

    ret = sec_task_check(aes_sm4_info->bd_addr);
    if (ret != SEC_SUCCESS) {
        tloge("sec task check failed, 0x%x.\n", ret);
    }

OUT:
    set_operation_status(0);
    return ret;
}

uint32_t sec_aes_gcm_simple(SEC_AES_GCM_INFO_S *aes_gcm_info)
{
    uint32_t ret;

    set_operation_status(1);

    ret = sec_init_status_check();
    if (ret != SEC_SUCCESS) {
        goto OUT;
    }

    ret = sec_aes_gcm_bd(aes_gcm_info);
    if (ret != SEC_SUCCESS) {
        tloge("sec aes gcm bd failed, 0x%x.\n", ret);
        goto OUT;
    }

    dsb();

    ret = sec_add_task(aes_gcm_info->bd_addr);
    if (ret != SEC_SUCCESS) {
        tloge("sec add task failed, 0x%x.\n", ret);
        goto OUT;
    }

    dsb();

    ret = sec_task_check(aes_gcm_info->bd_addr);
    if (ret != SEC_SUCCESS) {
        tloge("sec task check failed, 0x%x.\n", ret);
    }

OUT:
    set_operation_status(0);
    return ret;
}

uint32_t sec_aes_gcm_init(SEC_AES_GCM_INFO_S *aes_gcm_info)
{
    uint32_t ret;

    set_operation_status(1);

    ret = sec_init_status_check();
    if (ret != SEC_SUCCESS) {
        goto OUT;
    }

    ret = sec_aes_gcm_init_bd(aes_gcm_info);
    if (ret != SEC_SUCCESS) {
        tloge("sec aes gcm init bd failed, 0x%x.\n", ret);
        goto OUT;
    }

    dsb();

    ret = sec_add_task(aes_gcm_info->bd_addr);
    if (ret != SEC_SUCCESS) {
        tloge("sec add task failed, 0x%x.\n", ret);
        goto OUT;
    }

    dsb();

    ret = sec_task_check(aes_gcm_info->bd_addr);
    if (ret != SEC_SUCCESS) {
        tloge("sec task check failed, 0x%x.\n", ret);
    }

OUT:
    set_operation_status(0);
    return ret;
}

uint32_t sec_aes_gcm_update(SEC_AES_GCM_INFO_S *aes_gcm_info)
{
    uint32_t ret = ERR_SEC_PARAMETER_ERROR;

    set_operation_status(1);

    if ((aes_gcm_info->data_len & SEC_AES_BLOCK_MASK) != 0) {
        tloge("sec aes gcm data len wrong, 0x%x.\n", aes_gcm_info->data_len);
        goto OUT;
    }

    ret = sec_aes_gcm_update_bd(aes_gcm_info);
    if (ret != SEC_SUCCESS) {
        tloge("sec aes gcm update bd build failed, 0x%x.\n", ret);
        goto OUT;
    }

    dsb();

    ret = sec_add_task(aes_gcm_info->bd_addr);
    if (ret != SEC_SUCCESS) {
        tloge("sec add task failed, 0x%x.\n", ret);
        goto OUT;
    }

    dsb();

    ret = sec_task_check(aes_gcm_info->bd_addr);
    if (ret != SEC_SUCCESS) {
        tloge("sec task check failed, 0x%x.\n", ret);
    }

OUT:
    set_operation_status(0);
    return ret;
}

uint32_t sec_aes_gcm_final(SEC_AES_GCM_INFO_S *aes_gcm_info)
{
    uint32_t ret;

    set_operation_status(1);

    ret = sec_aes_gcm_final_bd(aes_gcm_info);
    if (ret != SEC_SUCCESS) {
        tloge("sec aes gcm final bd build failed, 0x%x.\n", ret);
        goto OUT;
    }

    dsb();

    ret = sec_add_task(aes_gcm_info->bd_addr);
    if (ret != SEC_SUCCESS) {
        tloge("sec add task failed, 0x%x.\n", ret);
        goto OUT;
    }

    dsb();

    ret = sec_final_task_check(aes_gcm_info->bd_addr);
    if (ret != SEC_SUCCESS) {
        tloge("sec task check failed, 0x%x.\n", ret);
    }

OUT:
    set_operation_status(0);
    return ret;
}

uint32_t sec_aes_gcm_km(SEC_AES_GCM_INFO_S *aes_gcm_info)
{
    uint32_t ret;

    set_operation_status(1);

    ret = sec_init_status_check();
    if (ret != SEC_SUCCESS) {
        goto OUT;
    }

    ret = sec_aes_gcm_km_bd(aes_gcm_info);
    if (ret != SEC_SUCCESS) {
        tloge("sec aes gcm km failed, 0x%x.\n", ret);
        goto OUT;
    }

    dsb();

    ret = sec_add_task(aes_gcm_info->bd_addr);
    if (ret != SEC_SUCCESS) {
        tloge("sec add task failed, 0x%x.\n", ret);
        goto OUT;
    }

    dsb();

    ret = sec_task_check(aes_gcm_info->bd_addr);
    if (ret != SEC_SUCCESS) {
        tloge("sec task check failed, 0x%x.\n", ret);
    }

OUT:
    set_operation_status(0);
    return ret;
}

uint32_t sec_hmac_simple(SEC_HMAC_INFO_S *hmac_info)
{
    uint32_t ret = ERR_SEC_PARAMETER_ERROR;

    set_operation_status(1);

    if ((hmac_info->data_len == 0) || (hmac_info->key_len == 0)) {
        tloge("Invalid len, 0x%x, 0x%x.\n", hmac_info->data_len, hmac_info->key_len);
        goto OUT;
    }

    ret = sec_init_status_check();
    if (ret != SEC_SUCCESS) {
        goto OUT;
    }

    ret = sec_hmac_bd(hmac_info);
    if (ret != SEC_SUCCESS) {
        tloge("sec_hmac bd failed, 0x%x.\n", ret);
        goto OUT;
    }

    dsb();
    ret = sec_add_task(hmac_info->bd_addr);
    if (ret != SEC_SUCCESS) {
        tloge("sec add task failed, 0x%x.\n", ret);
        goto OUT;
    }
    dsb();
    ret = sec_task_check(hmac_info->bd_addr);
    if (ret != SEC_SUCCESS) {
        tloge("sec task check failed, 0x%x.\n", ret);
    }

OUT:
    set_operation_status(0);
    return ret;
}

uint32_t sec_hmac_init(SEC_HMAC_INFO_S *hmac_info)
{
    uint32_t ret = ERR_SEC_PARAMETER_ERROR;

    set_operation_status(1);

    if (hmac_info->key_len == 0) {
        tloge("Invalid key len, 0x%x\n", hmac_info->key_len);
        goto OUT;
    }

    if ((hmac_info->data_len & SEC_HASH_BLOCK_MASK) != 0) {
        tloge("Invalid data len, 0x%x\n", hmac_info->data_len);
        goto OUT;
    }

    ret = sec_init_status_check();
    if (ret != SEC_SUCCESS) {
        goto OUT;
    }

    ret = sec_hmac_init_bd(hmac_info);
    if (ret != SEC_SUCCESS) {
        tloge("sec hmac init bd failed, 0x%x.\n", ret);
        goto OUT;
    }

    dsb();

    ret = sec_add_task(hmac_info->bd_addr);
    if (ret != SEC_SUCCESS) {
        tloge("sec add task failed, 0x%x.\n", ret);
        goto OUT;
    }

    dsb();

    ret = sec_task_check(hmac_info->bd_addr);
    if (ret != SEC_SUCCESS) {
        tloge("sec task check failed, 0x%x.\n", ret);
    }

OUT:
    set_operation_status(0);
    return ret;
}

uint32_t sec_hmac_update(SEC_HMAC_INFO_S *hmac_info)
{
    uint32_t ret = ERR_SEC_PARAMETER_ERROR;

    set_operation_status(1);

    if (hmac_info->key_len == 0) {
        tloge("Invalid key len, 0x%x\n", hmac_info->key_len);
        goto OUT;
    }

    if ((hmac_info->data_len & SEC_HASH_BLOCK_MASK) != 0) {
        tloge("Invalid data len, 0x%x\n", hmac_info->data_len);
        goto OUT;
    }

    ret = sec_hmac_update_bd(hmac_info);
    if (ret != SEC_SUCCESS) {
        tloge("sec hmac update bd failed, 0x%x.\n", ret);
        goto OUT;
    }

    dsb();

    ret = sec_add_task(hmac_info->bd_addr);
    if (ret != SEC_SUCCESS) {
        tloge("sec add task failed, 0x%x.\n", ret);
        goto OUT;
    }

    dsb();

    ret = sec_task_check(hmac_info->bd_addr);
    if (ret != SEC_SUCCESS) {
        tloge("sec task check failed, 0x%x.\n", ret);
    }

OUT:
    set_operation_status(0);
    return ret;
}

uint32_t sec_hmac_final(SEC_HMAC_INFO_S *hmac_info)
{
    uint32_t ret = ERR_SEC_PARAMETER_ERROR;

    set_operation_status(1);

    if (hmac_info->key_len == 0) {
        tloge("Invalid key len, 0x%x\n", hmac_info->key_len);
        goto OUT;
    }

    ret = sec_hmac_final_bd(hmac_info);
    if (ret != SEC_SUCCESS) {
        tloge("sec hmac final bd failed, 0x%x.\n", ret);
        goto OUT;
    }

    dsb();

    ret = sec_add_task(hmac_info->bd_addr);
    if (ret != SEC_SUCCESS) {
        tloge("sec add task failed, 0x%x.\n", ret);
        goto OUT;
    }

    dsb();

    ret = sec_task_check(hmac_info->bd_addr);
    if (ret != SEC_SUCCESS) {
        tloge("sec task check failed, 0x%x.\n", ret);
    }

OUT:
    set_operation_status(0);
    return ret;
}

STATIC uint32_t sec_hash_zero_result(SEC_HASH_INFO_S *hash_info)
{
    int32_t i;
    for (i = 0;  i < (sizeof(g_hash_map) / sizeof(hash_zero_map_s)); i++) {
        if (g_hash_map[i].hash_type == hash_info->hash_type) {
            if (memcpy_s((void *)(uintptr_t)(hash_info->result_addr), SHA_BLOCK_LEN,
                (void *)(uintptr_t)(g_hash_map[i].out_result), g_hash_map[i].data_len) != 0) {
                return CRYPTO_ERROR_OUT_OF_MEMORY;
            }
            break;
        }
    }

    if (i == (sizeof(g_hash_map) / sizeof(hash_zero_map_s))) {
        tloge("Invalid hash type, 0x%x.\n", hash_info->hash_type);
        return ERR_SEC_PARAMETER_ERROR;
    }

    return SEC_SUCCESS;
}

uint32_t sec_hash_simple(SEC_HASH_INFO_S *hash_info)
{
    uint32_t ret = ERR_SEC_PARAMETER_ERROR;

    set_operation_status(1);
    if (hash_info->data_len == 0) {
        ret = sec_hash_zero_result(hash_info);
        if (ret != SEC_SUCCESS) {
            goto OUT;
        }
        return SEC_SUCCESS;
    }

    ret = sec_init_status_check();
    if (ret != SEC_SUCCESS) {
        goto OUT;
    }

    ret = sec_hash_bd(hash_info);
    if (ret != SEC_SUCCESS) {
        tloge("sec hash bd failed, 0x%x.\n", ret);
        goto OUT;
    }

    dsb();

    ret = sec_add_task(hash_info->bd_addr);
    if (ret != SEC_SUCCESS) {
        tloge("sec add task failed, 0x%x.\n", ret);
        goto OUT;
    }

    dsb();

    ret = sec_task_check(hash_info->bd_addr);
    if (ret != SEC_SUCCESS) {
        tloge("sec task check failed, 0x%x.\n", ret);
    }

OUT:
    set_operation_status(0);
    return ret;
}

uint32_t sec_hash_init(SEC_HASH_INFO_S *hash_info)
{
    uint32_t ret = ERR_SEC_PARAMETER_ERROR;

    set_operation_status(1);

    if ((hash_info->data_len & SEC_HASH_BLOCK_MASK) != 0) {
        tloge("Invalid data len, 0x%x.\n", hash_info->data_len);
        goto OUT;
    }

    ret = sec_init_status_check();
    if (ret != SEC_SUCCESS) {
        goto OUT;
    }

    ret = sec_hash_init_bd(hash_info);
    if (ret != SEC_SUCCESS) {
        tloge("sec hash init bd failed, 0x%x.\n", ret);
        goto OUT;
    }

    dsb();

    ret = sec_add_task(hash_info->bd_addr);
    if (ret != SEC_SUCCESS) {
        tloge("sec add task failed, 0x%x.\n", ret);
        goto OUT;
    }

    dsb();

    ret = sec_task_check(hash_info->bd_addr);
    if (ret != SEC_SUCCESS) {
        tloge("sec task check failed, 0x%x.\n", ret);
    }

OUT:
    set_operation_status(0);
    return ret;
}

uint32_t sec_hash_update(SEC_HASH_INFO_S *hash_info)
{
    uint32_t ret = ERR_SEC_PARAMETER_ERROR;

    set_operation_status(1);

    if ((hash_info->data_len & SEC_HASH_BLOCK_MASK) != 0) {
        tloge("Invalid data len, 0x%x.\n", hash_info->data_len);
        goto OUT;
    }

    ret = sec_hash_update_bd(hash_info);
    if (ret != SEC_SUCCESS) {
        tloge("sec hash update bd failed, 0x%x.\n", ret);
        goto OUT;
    }

    dsb();

    ret = sec_add_task(hash_info->bd_addr);
    if (ret != SEC_SUCCESS) {
        tloge("sec add task failed, 0x%x.\n", ret);
        goto OUT;
    }

    dsb();

    ret = sec_task_check(hash_info->bd_addr);
    if (ret != SEC_SUCCESS) {
        tloge("sec task check failed, 0x%x.\n", ret);
    }

OUT:
    set_operation_status(0);
    return ret;
}

uint32_t sec_hash_final(SEC_HASH_INFO_S *hash_info)
{
    uint32_t ret;

    set_operation_status(1);

    ret = sec_hash_final_bd(hash_info);
    if (ret != SEC_SUCCESS) {
        tloge("sec hash final bd failed, 0x%x.\n", ret);
        goto OUT;
    }

    dsb();

    ret = sec_add_task(hash_info->bd_addr);
    if (ret != SEC_SUCCESS) {
        tloge("sec add task fail\n");
        goto OUT;
    }

    dsb();

    ret = sec_task_check(hash_info->bd_addr);
    if (ret != SEC_SUCCESS) {
        tloge("sec task check fail\n");
    }

OUT:
    set_operation_status(0);
    return ret;
}

uint32_t sec_pbkdf2(SEC_PBKDF2_INFO_S *pbkdf2_info)
{
    uint32_t ret;

    set_operation_status(1);

    ret = sec_init_status_check();
    if (ret != SEC_SUCCESS) {
        goto OUT;
    }

    ret = sec_pbkdf2_bd(pbkdf2_info);
    if (ret != SEC_SUCCESS) {
        tloge("sec pbkdf2 bd failed, 0x%x\n", ret);
        goto OUT;
    }

    dsb();

    ret = sec_add_task(pbkdf2_info->bd_addr);
    if (ret != SEC_SUCCESS) {
        tloge("sec add task failed, 0x%x\n", ret);
        goto OUT;
    }

    dsb();

    ret = sec_task_check(pbkdf2_info->bd_addr);
    if (ret != SEC_SUCCESS) {
        tloge("sec task check failed, 0x%x\n", ret);
    }

OUT:
    set_operation_status(0);
    return ret;
}

static void sec_pbkdf2_info_assign_value(SEC_PBKDF2_INFO_S *pbkdf2_info,
    TEE_SEC_BD *sec_provision_bd, uint8_t *provision_key)
{
    pbkdf2_info->bd_addr = (uint64_t)(uintptr_t)sec_provision_bd->sec_bd;
    pbkdf2_info->cnt = IMGK2_CNT_NUMBER;
    pbkdf2_info->hmac_type = HMAC_SHA256;
    pbkdf2_info->key_len = IMGK2_INPUT_KEY_LEN;
    pbkdf2_info->key_type = IMGK2;
    pbkdf2_info->result_addr = (uint64_t)(uintptr_t)provision_key;
    pbkdf2_info->seed_addr = (uint64_t)(uintptr_t)g_img_key2_salt;
    pbkdf2_info->seed_len = IMGK2_INPUT_SALT_LEN;
    pbkdf2_info->mac_len = IMGK2_OUTPUT_KEY_LEN;
}

uint32_t get_provision_key(uint8_t *provision_key, size_t key_size)
{
    uint32_t ret = ERR_SEC_PARAMETER_ERROR;
    SEC_PBKDF2_INFO_S pbkdf2_info = {0};
    TEE_SEC_BD sec_provision_bd = {0};
    (void)key_size;

    set_operation_status(1);

    if (provision_key == NULL) {
        tloge("Null Provision key.\n");
        goto OUT;
    }

    ret = sec_init_status_check();
    if (ret != SEC_SUCCESS) {
        goto OUT;
    }

    ret = sec_km_key_req(KEY_IMGK2);
    if (ret != SEC_SUCCESS) {
        tloge("sec gen img key2 failed, 0x%x\n", ret);
        goto OUT;
    }

    sec_pbkdf2_info_assign_value(&pbkdf2_info, &sec_provision_bd, provision_key);

    ret = sec_pbkdf2_bd(&pbkdf2_info);
    if (ret != SEC_SUCCESS) {
        tloge("sec pbkdf2 bd failed, 0x%x\n", ret);
        goto OUT;
    }

    dsb();

    ret = sec_add_task(pbkdf2_info.bd_addr);
    if (ret != SEC_SUCCESS) {
        tloge("sec add task failed, 0x%x\n", ret);
        goto OUT;
    }

    dsb();

    ret = sec_task_check(pbkdf2_info.bd_addr);
    if (ret != SEC_SUCCESS) {
        tloge("sec task check failed, 0x%x\n", ret);
    }

OUT:
    set_operation_status(0);
    return ret;
}

int32_t sec_suspend(void)
{
    volatile uint32_t timeout = SEC_SUSPEND_TIMEOUT;

    while ((get_operation_status() == 1) && (timeout != 0)) {
        SRE_SwMsleep(SEC_SUSPEND_DELAT_1MS);
        timeout--;
    }

    return 0;
}

int32_t sec_resume(void)
{
    return (int32_t)sec_init_status_check();
}

int sec_syscall(int swi_id, struct drv_param *params, uint64_t permissions)
{
    uint32_t ret;
    uint64_t provision_key_addr;
    uint64_t *args = NULL;

    if ((params == NULL) || (params->args == 0)) {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    args = (uint64_t *)(uintptr_t)params->args;

    HANDLE_SYSCALL(swi_id) {
        SYSCALL_PERMISSION(SW_SYSCALL_SEC_PRO_KEY, permissions, GENERAL_GROUP_PERMISSION)
        provision_key_addr = args[0];
        ACCESS_CHECK_A64(provision_key_addr, SEC_PROV_KEY_LEN);
        ACCESS_WRITE_RIGHT_CHECK(provision_key_addr, SEC_PROV_KEY_LEN);
        ret = get_provision_key((uint8_t *)(uintptr_t)provision_key_addr, SEC_PROV_KEY_LEN);
        args[0] = ret;
        SYSCALL_END
    default:
        return TEE_ERROR_NOT_SUPPORTED;
    }

    return 0;
}

static struct oemkey_ops_t g_oemkey_ops = {
    get_provision_key,
};

int32_t sec_hiss_init(void)
{
    return register_oemkey_ops(SEC_OEMKEY_FLAG, &g_oemkey_ops);
}

DECLARE_TC_DRV(
    sec_hiss_driver,
    0,
    0,
    0,
    TC_DRV_MODULE_INIT,
    sec_hiss_init,
    NULL,
    sec_syscall,
    sec_suspend,
    sec_resume);
