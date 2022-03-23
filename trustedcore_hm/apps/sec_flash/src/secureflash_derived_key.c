/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: secureflash_derived_key.c
 * Author: l00265041
 * Create: 2019-8-30
 */
#include "secureflash_derived_key.h"
#include "secureflash_errno.h"
#include "secureflash_interface.h"
#include <dx_cc_defs.h>
#include <sre_syscall.h>
#include <securec.h>
#include <securectype.h>
#include <ccmgr_ops_ext.h>

uint8_t g_initkey_plaintext_array[SECFLASH_INITKEY_SECURE_STORAGE_GROUP_MAX_BYTES];

static uint8_t g_secure_flash_context[SECFLASH_CONTEXT_LEN_IN_BYTES] = {
    0xa8, 0xf1, 0xcd, 0x30, 0x0e, 0x15, 0x40, 0x6d, 0xd3, 0x1e, 0xa5, 0x10, 0x0, 0x0, 0x0, 0x0 };

static uint8_t g_weaver_context[SECFLASH_CONTEXT_LEN_IN_BYTES] = {
    0xed, 0x28, 0x49, 0x34, 0xcc, 0x0e, 0xed, 0x31, 0x59, 0x03, 0xcb, 0x06, 0x0, 0x0, 0x0, 0x0 };

/*
 * @brief     : supply the aes cmac function, based on the kdr key.
 * @param[in] : data_in_ptr, a pointer to a message data, which as the derived part.
 *              data_size, the size of message data, in bytes.
 * @param[out]: derived_data, the pointer of the derived data.
 * @return    : success -- SECURE_FLASH_RET_SUCC
 *              fail    -- SECURE_FLASH_RET_ERR_x
 */
uint32_t secflash_aes_cmac_wrapper(uint8_t *data_in_ptr, uint32_t data_size, uint8_t *derived_data)
{
    uint32_t ret;

    if (!data_in_ptr || !derived_data) {
        SECFLASH_PRINT_ERROR("%s, input pointer is NULL.\n", __func__);
        return FACTORY_TEST_LAYER_ERRCODE(SECURE_FLASH_RET_ERR_1);
    }
    ret = __CC_DX_UTIL_CmacDeriveKey(DX_ROOT_KEY, data_in_ptr, data_size, derived_data);
    if (ret != SECURE_FLASH_RET_SUCC) {
        SECFLASH_PRINT_ERROR("%s, UTIL_CmacDeriveKey failed: %x\n", __func__, ret);
        return FACTORY_TEST_LAYER_ERRCODE(SECURE_FLASH_RET_ROOTKEY_DERIVED_ERR);
    }
    return SECURE_FLASH_RET_SUCC;
}

/*
 * @brief      : derived the key according to kdf algrithom in 800-108
 * @param[in]  : constant: the derivation constants
 *               batch_id: the batch id, one byte
 *               context: the 16bytes context in kdf
 * @param[out] : derived_data: output derived data buffer
 * @return     : success -- SECURE_FLASH_RET_SUCC
 *               fail    -- SECURE_FLASH_RET_ERR_x
 */
static uint32_t secflash_kdf_func(uint8_t constant, uint8_t batch_id, uint8_t *context, uint8_t *derived_data)
{
    uint8_t kdf_message[SECFLASH_KDF_MESSAGE_LEN_IN_BYTES] = {0};
    uint32_t ret;

    if (!context || !derived_data) {
        SECFLASH_PRINT_ERROR("%s invalid params.\n", __func__);
        return SECURE_FLASH_RET_ERR_1;
    }
    kdf_message[0] = 0x1; /* The first byte fixed as 0x1 */
    kdf_message[SECFLASH_LABLE_LEN_IN_BYTES - 1] = batch_id ;
    kdf_message[SECFLASH_LABLE_LEN_IN_BYTES] = constant;
    ret = memcpy_s(&kdf_message[SECFLASH_CONTEXT_START_IN_BYTES], SECFLASH_CONTEXT_LEN_IN_BYTES,
               context, SECFLASH_CONTEXT_LEN_IN_BYTES);
    if (ret != EOK) {
        SECFLASH_PRINT_ERROR("%s memcpy_s failed.\n", __func__);
        return SECURE_FLASH_RET_ERR_2;
    }
    /* L(0080) specifying the length in bits of the derived data,according to scp03 KDF */
    kdf_message[SECFLASH_KDF_MESSAGE_LEN_IN_BYTES - 1] = 0x80;

    ret = secflash_aes_cmac_wrapper(kdf_message, SECFLASH_KDF_MESSAGE_LEN_IN_BYTES, derived_data);
    if (ret != SECURE_FLASH_RET_SUCC) {
        SECFLASH_PRINT_ERROR("%s cc_aes_cmac_wrapper fail(0x%x).\n", __func__, ret);
        return SECURE_FLASH_RET_ERR_3;
    }
    return SECURE_FLASH_RET_SUCC;
}

/*
 * @brief      : get the binding key component about binding key for the secflash device
 * @param[in]  : keyset_type: the keyset type of initial key,include secure storage or weaver service
 * @param[out] : context_addr: a variable pointer which value is the start address for context componet.
 * @return     : success -- SECURE_FLASH_RET_SUCC
 *               fail    -- SECURE_FLASH_RET_ERR_x
 */
static uint32_t secflash_prepare_bindingkey_component(uint32_t keyset_type, uintptr_t *context_addr)
{
    uint32_t ret;
    uint32_t i;
    uint32_t *binding_counter_ptr = NULL;
    uint32_t efuse_count = 0;
    uint32_t binding_count;
    uint32_t weaver_binding_count, sf_binding_count;
    uint8_t valid_keyset_type[SECFLASH_KEYSET_TYPE_NUMBER] = { SECFLASH_KVN_BINDING_KEY1,
                                                               SECFLASH_KVN_BINDING_KEY2,
                                                               SECFLASH_KVN_BINDING_KEY3 };

    if (!context_addr) {
        SECFLASH_PRINT_ERROR("%s invalid pointer params.\n", __func__);
        return SECURE_FLASH_RET_ERR_2;
    }
    for (i = 0; i < SECFLASH_KEYSET_TYPE_NUMBER; i++) {
        if (valid_keyset_type[i] == keyset_type)
            break;
    }
    if (i == SECFLASH_KEYSET_TYPE_NUMBER) {
        SECFLASH_PRINT_ERROR("%s invalid params.\n", __func__);
        return SECURE_FLASH_RET_ERR_3;
    }

    ret = secflash_get_device_efuse_count(&efuse_count);
    if (ret != SECURE_FLASH_RET_SUCC) {
        SECFLASH_PRINT_ERROR("%s secflash_get_device_efuse_count failed(0x%x).\n", __func__, ret);
        return SECURE_FLASH_RET_ERR_4;
    }
    sf_binding_count = efuse_count & SECFLASH_SECURE_STORAGE_COUNT_MASK;
    weaver_binding_count = (efuse_count >> SECFLASH_WEAVER_COUNT_START_BIT) &
                            SECFLASH_SECURE_STORAGE_COUNT_MASK;

    if (sf_binding_count > SECFLASH_SECURE_STORAGE_BIT_ONE_MAX ||
        weaver_binding_count > SECFLASH_WEAVER_BIT_ONE_MAX) {
        SECFLASH_PRINT_ERROR("%s efuse binding count is invalid:%d,%d.\n",
                              __func__, sf_binding_count, weaver_binding_count);
        return SECURE_FLASH_RET_ERR_5;
    }

    if (keyset_type == SECFLASH_KVN_BINDING_KEY3) {
        binding_count = weaver_binding_count;
        binding_counter_ptr = (uint32_t *)&g_weaver_context[SECFLASH_BINDING_COUNT_START_IN_BYTES];
        *context_addr = (uintptr_t)g_weaver_context;
    } else {
        binding_count = sf_binding_count;
        binding_counter_ptr = (uint32_t *)&g_secure_flash_context[SECFLASH_BINDING_COUNT_START_IN_BYTES];
        *context_addr = (uintptr_t)g_secure_flash_context;
    }
    /* set binding count in efuse to the context component */
    *binding_counter_ptr = binding_count;

    SECFLASH_PRINT_ERROR("%s efuse_count=%x type=%d success.\n", __func__, efuse_count, keyset_type);
    return SECURE_FLASH_RET_SUCC;
}

/*
 * @brief      : compute the data about binding key for the secflash device
 * @param[in]  : batch_id: the batch id, one byte
 * @param[in]  : context_addr: a variable which value is the start address for context componet.
 * @param[out] : binding_key: output derived binding key buffer(struct secflash_keyset)
 * @return     : success -- SECURE_FLASH_RET_SUCC
 *               fail    -- SECURE_FLASH_RET_ERR_x
 */
static uint32_t secflash_compute_bindingkey_data(uint32_t batch_id, uintptr_t context_addr,
                                                 struct secflash_keyset *binding_key)
{
    uint32_t ret;
    uint32_t i;
    uint8_t derived_key[SECFLASH_KEY_LEN_IN_BYTES] = {0};
    uint8_t *key_data_ptr = NULL;
    uint8_t *context_ptr = NULL;
    uint8_t curr_batchid;
    uint8_t key_derived_constant[SECFLASH_KEYSET_SUBKEY_NUM] = { SECFLASH_CONSTANT_ENC,
                                                                 SECFLASH_CONSTANT_MAC,
                                                                 SECFLASH_CONSTANT_DEK };
    curr_batchid = (uint8_t)batch_id;
    context_ptr = (uint8_t *)context_addr;
    key_data_ptr = &binding_key->enc[0];

    SECFLASH_PRINT_ERROR("Info: batchid=%d.\n", batch_id);
    for (i = 0; i < SECFLASH_KEYSET_SUBKEY_NUM; i++) {
        ret = secflash_kdf_func(key_derived_constant[i], curr_batchid, context_ptr, derived_key);
        if (ret != SECURE_FLASH_RET_SUCC) {
            SECFLASH_PRINT_ERROR("%s i=%d,secflash_kdf_func failed(0x%x).\n", __func__, i, ret);
            return SECURE_FLASH_RET_ERR_6;
        }
        ret = memcpy_s((void *)key_data_ptr, SECFLASH_KEY_LEN_IN_BYTES,
                       (void *)derived_key, SECFLASH_KEY_LEN_IN_BYTES);
        if (ret != EOK) {
            SECFLASH_PRINT_ERROR("%s i=%d,memcpy_s failed(0x%x).\n", __func__, i, ret);
            (void)memset_s(derived_key, SECFLASH_KEY_LEN_IN_BYTES, 0, SECFLASH_KEY_LEN_IN_BYTES);
            return SECURE_FLASH_RET_ERR_7;
        }
        key_data_ptr += SECFLASH_KEY_LEN_IN_BYTES;
    }

    (void)memset_s(derived_key, SECFLASH_KEY_LEN_IN_BYTES, 0, SECFLASH_KEY_LEN_IN_BYTES);
    SECFLASH_PRINT_INFO("%s success.\n", __func__);
    return SECURE_FLASH_RET_SUCC;
}

/*
 * @brief      : derived the binding key for the secflash device
 * @param[in]  : keyset_type: the keyset type of binding key,include secure storage or weaver service
 *               batch_id: the batch id, one byte
 * @param[out] : binding_key: output derived binding key buffer(struct secflash_keyset)
 * @return     : success -- SECURE_FLASH_RET_SUCC
 *               fail    -- SECURE_FLASH_RET_ERR_x
 */
uint32_t secflash_derive_binding_key(uint32_t keyset_type, uint32_t batch_id, struct secflash_keyset *binding_key)
{
    uint32_t ret;
    uintptr_t context_addr = 0;

    if (!binding_key) {
        SECFLASH_PRINT_ERROR("%s binding_key is NULL.\n", __func__);
        return FACTORY_TEST_LAYER_ERRCODE(SECURE_FLASH_BASE_DERIVED_BINDING_KEY + SECURE_FLASH_RET_ERR_1);
    }

    ret = secflash_prepare_bindingkey_component(keyset_type, &context_addr);
    if (ret != SECURE_FLASH_RET_SUCC) {
        SECFLASH_PRINT_ERROR("%s secflash_prepare_bindingkey_component failed(0x%x).\n", __func__, ret);
        return FACTORY_TEST_LAYER_ERRCODE(SECURE_FLASH_BASE_DERIVED_BINDING_KEY + ret);
    }
    ret = secflash_compute_bindingkey_data(batch_id, context_addr, binding_key);
    if (ret != SECURE_FLASH_RET_SUCC) {
        SECFLASH_PRINT_ERROR("%s secflash_compute_bindingkey_data failed(0x%x).\n", __func__, ret);
        return FACTORY_TEST_LAYER_ERRCODE(SECURE_FLASH_BASE_DERIVED_BINDING_KEY + ret);
    }

    SECFLASH_PRINT_INFO("%s success.\n", __func__);
    return SECURE_FLASH_RET_SUCC;
}

