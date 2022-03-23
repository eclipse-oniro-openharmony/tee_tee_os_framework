/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2021. All rights reserved.
 * Description: tee load key code
 * Create: 2020.03.04
 */
#include "ta_load_key.h"

#include <tee_defines.h>
#include <tee_log.h>
#include <tee_mem_mgmt_api.h>
#include <tee_sharemem.h>
#include <securec.h>
#include <hongmeng.h>
#ifdef CONFIG_GENERIC_LOAD_KEY
#include "wb_tool_128_root_key.h"
#endif
#ifdef CONFIG_WHITE_BOX_KEY
#include "wb_tool_256_root_key.h"
#endif
#ifdef CONFIG_PUBKEY_SHAREMEM
struct key_size_tag_info key_size_info[] = {
    {"4096", PUB_KEY_4096_BITS},
    {"2048", PUB_KEY_2048_BITS},
    {"256", PUB_KEY_256_BITS},
};

struct key_style_tag_info key_style_info[] = {
    {"debug", PUB_KEY_DEBUG},
    {"release", PUB_KEY_RELEASE},
};
rsa_pub_key_t *g_ta_verify_key;

static int32_t get_key_len_tag(uint32_t key_len, char *tag, uint32_t tag_len)
{
    size_t i;
    errno_t ret;
    for (i = 0; i < ARRAY_SIZE(key_size_info); i++) {
        if (key_len == key_size_info[i].key_len) {
            ret = strcat_s(tag, tag_len, key_size_info[i].key_len_tag);
            if (ret == EOK)
                return 0;
            else
                return -1;
        }
    }

    return -1;
}

static int32_t get_key_style_tag(uint32_t key_len, char *tag, uint32_t tag_len)
{
    size_t i;
    errno_t ret;
    for (i = 0; i < ARRAY_SIZE(key_style_info); i++) {
        if (key_len == key_style_info[i].key_style) {
            ret = strcat_s(tag, tag_len, key_style_info[i].key_style_tag);
            if (ret == EOK)
                return 0;
            else
                return -1;
        }
    }
    return -1;
}

static int32_t get_key_len_style_tag(uint32_t key_len, uint32_t key_style, char *tag, uint32_t tag_len)
{
    int32_t ret;
    ret = get_key_len_tag(key_len, tag, tag_len);
    if (ret != 0) {
        tloge("get key len tag failed, key len is %u\n", key_len);
        return ret;
    }

    ret = get_key_style_tag(key_style, tag, tag_len);
    if (ret != 0) {
        tloge("get key style tag failed, key style is %u\n", key_style);
        return ret;
    }
    return ret;
}

static void *query_key_info(uint32_t key_len, uint32_t key_style)
{
    int ret;
    char tag[MAX_TAG_LEN] = "ta_rsa_pub_";
    uint32_t size = sizeof(*g_ta_verify_key);
    ret = get_key_len_style_tag(key_len, key_style, tag, sizeof(tag));
    if (ret != 0) {
        tloge("key tag info failed\n");
        return NULL;
    }
    if (g_ta_verify_key == NULL)
        g_ta_verify_key = TEE_Malloc(sizeof(rsa_pub_key_t), 0);

    if (g_ta_verify_key == NULL)
        return NULL;

    ret =  get_tlv_sharedmem(tag, sizeof(tag), g_ta_verify_key, &size, false);
    if (ret != 0) {
        TEE_Free(g_ta_verify_key);
        g_ta_verify_key = NULL;
        return NULL;
    } else {
        return g_ta_verify_key;
    }
}
#endif

TEE_Result get_wb_tool_key(struct wb_tool_key *tool_key)
{
    if (tool_key == NULL) {
        tloge("check tool key params error\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

#ifdef CONFIG_GENERIC_LOAD_KEY
#if (defined(DYN_TA_SUPPORT_V1)) || (defined(DYN_TA_SUPPORT_V2) && defined(CONFIG_WHITE_BOX_KEY))
    if (tool_key->tool_ver == WB_TOOL_KEY_128)
        return get_wb_tool_v1_key(tool_key);
#endif
#endif

#ifdef CONFIG_WHITE_BOX_KEY
    if (tool_key->tool_ver == WB_TOOL_KEY_256)
        return get_wb_tool_v2_key(tool_key);
#endif

    tloge("error wb tool version: %d\n", tool_key->tool_ver);
    return TEE_ERROR_BAD_PARAMETERS;
}

TEE_Result query_ta_verify_pubkey(const struct ta_verify_key *all_key, size_t all_key_num,
    struct ta_verify_key *query_key)
{
    const void *key = NULL;

#ifdef CONFIG_PUBKEY_SHAREMEM
    (void)all_key;
    (void)all_key_num;
    key = query_key_info(query_key->key_len, query_key->key_style);
#else
    if (query_key == NULL || all_key == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    for (size_t i = 0; i < all_key_num; i++) {
        if (query_key->key_len == all_key[i].key_len && query_key->key_style == all_key[i].key_style)
            key = all_key[i].key;
    }
#endif

    if (key == NULL) {
        tloge("Get verify pub key failed, invalid cons, len:%u, sec style:%s\n",
            query_key->key_len, query_key->key_style == PUB_KEY_RELEASE ? "release" : "debug");
        tloge("This sec file can't be loaded, pls check sec file style and key len\n");
        return TEE_ERROR_BAD_FORMAT;
    }

    query_key->key = key;
    return TEE_SUCCESS;
}
