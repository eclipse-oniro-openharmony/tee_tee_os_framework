/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2021. All rights reserved.
 * Description: tee key data code
 * Create: 2020.03.04
 */
#include <tee_defines.h>
#include <tee_log.h>

#include "ta_load_key.h"
#include "wb_key.h"

#ifndef CONFIG_WHITE_BOX_KEY
#include "ecies_wrapped_key.h"
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
#ifdef KEYWEST_SIGN_PUB_KEY
    { WB_KEY, V3_TYPE_3072, (uint8_t *)&g_wb_key_v3_3072_keywest, sizeof(g_wb_key_v3_3072_keywest) },
#endif
#ifdef DYN_TA_SUPPORT_V3
#ifdef CONFIG_WHITE_BOX_KEY
    { WB_KEY, V3_TYPE_2048, (uint8_t *)&g_wb_key_v3, sizeof(g_wb_key_v3) },
    { WB_KEY, V3_TYPE_3072, (uint8_t *)&g_wb_key_v3_3072, sizeof(g_wb_key_v3_3072) },
#else
    { ECIES_KEY, V3_TYPE_2048, (uint8_t *)&g_ecies_key_data_v3, sizeof(g_ecies_key_data_v3) },
    { ECIES_KEY, V3_TYPE_3072, (uint8_t *)&g_ecies_key_data_v3_3072, sizeof(g_ecies_key_data_v3_3072) },
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

