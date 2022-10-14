/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: tee key data code
 * Author: Li Mingjuan limingjuan@huawei.com
 * Create: 2022-04-23
 */
#include <tee_defines.h>
#include <tee_log.h>

#include "ta_load_key.h"
#ifdef CONFIG_WHITE_BOX_KEY
#include "wb_key.h"
#else
#if CONFIG_TA_DECRYPT_ECIES_MDC
#include "ecies_wrapped_key_tda4_mdc.h"
#endif
#endif

bool is_wb_protecd_ta_key(void)
{
#ifdef CONFIG_WHITE_BOX_KEY
    return true;
#else
    return false;
#endif
}

struct key_data g_key_data[] = {
#ifdef DYN_TA_SUPPORT_V3
#ifdef CONFIG_WHITE_BOX_KEY
    { WB_KEY, V3_TYPE_3072, (uint8_t *)&g_wb_key, sizeof(g_wb_key) },
#else
    { ECIES_KEY, V3_TYPE_3072, (uint8_t *)&g_ecies_key, sizeof(g_ecies_key) },
#endif
#endif
};

TEE_Result get_ta_load_key(struct key_data *key)
{
    size_t i;

    if (key == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    for (i = 0; i < (sizeof(g_key_data) / sizeof(g_key_data[0])); i++) {
        if (g_key_data[i].ta_type == key->ta_type &&
            g_key_data[i].pro_type == key->pro_type) {
            key->key_len = g_key_data[i].key_len;
            key->key = g_key_data[i].key;
            return TEE_SUCCESS;
        }
    }

    tloge("invalid ta type:%d, or key protect type:%d\n", key->ta_type, key->pro_type);
    return TEE_ERROR_BAD_PARAMETERS;
}
