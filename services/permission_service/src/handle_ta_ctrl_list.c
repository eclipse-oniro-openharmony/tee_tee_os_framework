/*
 * Copyright (C) 2022 Huawei Technologies Co., Ltd.
 * Licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */
#include "handle_ta_ctrl_list.h"
#include <string.h>
#include <securec.h>
#include <tee_log.h>
#include <tee_mem_mgmt_api.h>
#include <crypto_wrapper.h>
#include "handle_file_op.h"
#include "handle_config.h"
#include "handle_crl_cert.h"
#include "ta_verify_key.h"
#include "tee_crypto_api.h"

#define CN_OU_BUFFER_SIZE 64
#define TA_CTRL_COUNT_MAX 0XFFFF

static struct ta_ctrl_config_t g_ta_ctrl_config = {
    .ctrl_list = dlist_head_init(g_ta_ctrl_config.ctrl_list),
    .file_name = "ta_ctrl_list_file.db",
    .count     = 0,
    .lock      = PTHREAD_MUTEX_INITIALIZER,
};

static TEE_Result perm_srv_ta_ctrl_list_add_entry(struct ta_ctrl_node *entry)
{
    if (entry == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    if (pthread_mutex_lock(&g_ta_ctrl_config.lock) != 0) {
        tloge("Failed to do pthread mutex lock\n");
        return TEE_ERROR_BAD_STATE;
    }

    if (g_ta_ctrl_config.count >= TA_CTRL_COUNT_MAX) {
        tloge("TA control list count is overflow\n");
        (void)pthread_mutex_unlock(&g_ta_ctrl_config.lock);
        return TEE_ERROR_OVERFLOW;
    }

    g_ta_ctrl_config.count++;
    dlist_insert_tail(&entry->head, &g_ta_ctrl_config.ctrl_list);

    (void)pthread_mutex_unlock(&g_ta_ctrl_config.lock);
    return TEE_SUCCESS;
}

#ifdef LOG_ON
static void perm_serv_ta_ctrl_list_print(void)
{
    struct dlist_node *pos = NULL;

    tlogd("-----------------TA Ctrl List----------------------\n");
    if (pthread_mutex_lock(&g_ta_ctrl_config.lock) != 0) {
        tloge("Failed to do pthread mutex lock\n");
        return;
    }

    dlist_for_each(pos, &g_ta_ctrl_config.ctrl_list) {
        struct ta_ctrl_node *entry = dlist_entry(pos, struct ta_ctrl_node, head);
        perm_srv_print_buff((const uint8_t *)&entry->uuid, sizeof(entry->uuid));
        tlogd("TA release--------0x%x\n", entry->version);
        perm_srv_print_buff((const uint8_t *)&entry->pad, sizeof(entry->pad));
    }

    (void)pthread_mutex_unlock(&g_ta_ctrl_config.lock);
    tlogd("-------------------------------------------------------\n");
}

#else
static void perm_serv_ta_ctrl_list_print(void)
{
}
#endif

static TEE_Result perm_srv_ta_ctrl_list_update(const TEE_UUID *uuid, uint16_t version, const struct padding *pad)
{
    struct dlist_node *pos = NULL;
    struct ta_ctrl_node *entry = NULL;
    TEE_Result ret;

    /* If item with same uuid is found, update it */
    if (pthread_mutex_lock(&g_ta_ctrl_config.lock) != 0) {
        tloge("Failed to do pthread mutex lock\n");
        return TEE_ERROR_BAD_STATE;
    }

    dlist_for_each(pos, &g_ta_ctrl_config.ctrl_list) {
        entry = dlist_entry(pos, struct ta_ctrl_node, head);
        if (TEE_MemCompare(uuid, &entry->uuid, sizeof(entry->uuid)) == 0) {
            if (entry->version < version)
                entry->version = version;
            (void)pthread_mutex_unlock(&g_ta_ctrl_config.lock);
            return TEE_SUCCESS;
        }
    }

    (void)pthread_mutex_unlock(&g_ta_ctrl_config.lock);

    /* Allocate new item and add to the list */
    entry = TEE_Malloc(sizeof(*entry), 0);
    if (entry == NULL) {
        tloge("Failed to do malloc, size: 0x%x\n", sizeof(*entry));
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    entry->uuid = *uuid;
    entry->version = version;
    entry->pad = *pad;

    ret = perm_srv_ta_ctrl_list_add_entry(entry);
    if (ret != TEE_SUCCESS) {
        TEE_Free(entry);
        entry = NULL;
        tloge("Failed to add new entry to TA control list\n");
        return ret;
    }

    return TEE_SUCCESS;
}

static int32_t perm_serv_ta_get_start_buffer(uint8_t **start, uint32_t *buff_left_size,
    struct ta_ctrl_node *entry)
{
    bool check = (*buff_left_size < (sizeof(entry->uuid) + sizeof(entry->version) + sizeof(entry->pad)));
    if (check)
        return -1;

    if (memcpy_s(*start, *buff_left_size, &(entry->uuid), sizeof(entry->uuid)) != EOK) {
        tloge("Failed to do memcpy_s\n");
        return -1;
    }

    (*buff_left_size) -= (uint32_t)sizeof(entry->uuid);
    (*start) += sizeof(entry->uuid);

    if (memcpy_s(*start, *buff_left_size, &(entry->version), sizeof(entry->version)) != EOK) {
        tloge("Failed to do memcpy_s\n");
        return -1;
    }

    (*buff_left_size) -= (uint32_t)sizeof(entry->version);
    (*start) += sizeof(entry->version);

    if (memcpy_s(*start, *buff_left_size, &(entry->pad), sizeof(entry->pad)) != EOK) {
        tloge("Failed to do memcpy_s\n");
        return -1;
    }
    (*buff_left_size) -= (uint32_t)sizeof(entry->pad);
    (*start) += sizeof(entry->pad);

    return 0;
}

static int32_t perm_serv_ta_ctrl_list_to_buff(uint8_t *ctrl_body, uint32_t ctrl_body_size)
{
    struct dlist_node *pos = NULL;
    uint8_t *start = NULL;
    int32_t ret;
    start = ctrl_body;

    if (pthread_mutex_lock(&g_ta_ctrl_config.lock) != 0) {
        tloge("Failed to do pthread mutex lock\n");
        return -1;
    }

    dlist_for_each(pos, &g_ta_ctrl_config.ctrl_list) {
        struct ta_ctrl_node *entry = dlist_entry(pos, struct ta_ctrl_node, head);
        ret = perm_serv_ta_get_start_buffer(&start, &ctrl_body_size, entry);
        if (ret != 0) {
            (void)pthread_mutex_unlock(&g_ta_ctrl_config.lock);
            return ret;
        }
    }

    (void)pthread_mutex_unlock(&g_ta_ctrl_config.lock);
    return (int32_t)(start - ctrl_body);
}

static TEE_Result perm_serv_ta_ctrl_buff_to_list(const uint8_t *ctrl_body, size_t ctrl_body_size)
{
    const uint8_t *start = NULL;
    TEE_UUID uuid = { 0 };
    uint16_t version = 0;
    struct padding pad = { 0 };
    TEE_Result ret;

    bool check = (ctrl_body == NULL || ctrl_body_size == 0 ||
                  (ctrl_body_size % (sizeof(uuid) + sizeof(version) + sizeof(pad))) != 0);
    if (check) {
        tloge("the TA control list length %zu is invalid\n", ctrl_body_size);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    start = ctrl_body;

    while (ctrl_body_size >= (sizeof(uuid) + sizeof(version) + sizeof(pad))) {
        if (memcpy_s(&uuid, sizeof(uuid), start, sizeof(uuid)) != EOK) {
            tloge("Failed to do memcpy_s\n");
            return TEE_ERROR_GENERIC;
        }

        ctrl_body_size -= sizeof(uuid);
        start += sizeof(uuid);

        if (memcpy_s(&version, sizeof(version), start, sizeof(version)) != EOK) {
            tloge("Failed to do memcpy_s\n");
            return TEE_ERROR_GENERIC;
        }

        ctrl_body_size -= sizeof(version);
        start += sizeof(version);

        if (memcpy_s(&pad, sizeof(pad), start, sizeof(pad)) != EOK) {
            tloge("Failed to do memcpy_s for pad\n");
            return TEE_ERROR_GENERIC;
        }

        ctrl_body_size -= sizeof(pad);
        start += sizeof(pad);
        ret = perm_srv_ta_ctrl_list_update(&uuid, version, &pad);
        if (ret != TEE_SUCCESS) {
            tloge("Failed to update ta control list ret: 0x%x\n", ret);
            return ret;
        }
    }

    return TEE_SUCCESS;
}

TEE_Result perm_serv_global_ctrl_list_loading(void)
{
    TEE_Result ret;
    uint8_t *buff = NULL;
    int32_t file_size;
    int32_t len;

    file_size = perm_srv_file_size(g_ta_ctrl_config.file_name);
    if (file_size < 0 || file_size > TA_CTRL_LIST_MAX_SIZE) {
        tloge("CRL cert list file: %s is invalid\n", g_ta_ctrl_config.file_name);
        return TEE_ERROR_GENERIC;
    }

    if (file_size == 0) {
        tloge("CRL cert list file: %s is empty or doesn't exist\n", g_ta_ctrl_config.file_name);
        return TEE_SUCCESS;
    }

    buff = TEE_Malloc((uint32_t)file_size, 0);
    if (buff == NULL) {
        tloge("Failed to malloc buffer, size: %d\n", file_size);
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    len = perm_srv_file_read(g_ta_ctrl_config.file_name, buff, (uint32_t)file_size);
    if (len != file_size) {
        tloge("Failed to read file: %s, %d, %d\n", g_ta_ctrl_config.file_name, len, file_size);
        ret = TEE_ERROR_GENERIC;
        goto exit;
    }

    ret = perm_serv_ta_ctrl_buff_to_list(buff, (size_t)file_size);
    if (ret != TEE_SUCCESS)
        tloge("Failed to get TA control list from buff\n");

exit:
    TEE_Free(buff);
    return ret;
}

static int32_t perm_srv_multiply_overflow(uint32_t count, uint32_t entry_size)
{
    uint32_t p = count * entry_size;
    if (count != 0 && (p / count != entry_size)) {
        tloge("Product of 0x%x multiply 0x%x will overflow\n", count, entry_size);
        return -1;
    }

    return 0;
}

static int32_t perm_srv_get_ctrl_list_size(void)
{
    uint32_t buff_size;
    struct ta_ctrl_node entry;
    uint32_t entry_size = (uint32_t)(sizeof(entry.uuid) + sizeof(entry.version) + sizeof(entry.pad));
    uint32_t count;

    (void)memset_s(&entry, sizeof(entry), 0, sizeof(entry));
    if (pthread_mutex_lock(&g_ta_ctrl_config.lock) != 0) {
        tloge("Failed to do pthread mutex lock\n");
        return -1;
    }

    count = g_ta_ctrl_config.count;
    (void)pthread_mutex_unlock(&g_ta_ctrl_config.lock);

    int32_t ret = perm_srv_multiply_overflow(count, entry_size);
    if (ret != 0)
        return ret;

    buff_size = count * entry_size;
    return buff_size;
}

static TEE_Result perm_serv_global_ctrl_list_storing(void)
{
    TEE_Result tee_ret = TEE_ERROR_GENERIC;
    uint8_t *buff = NULL;
    int32_t buff_size;
    int32_t len;

    buff_size = perm_srv_get_ctrl_list_size();
    if (buff_size > TA_CTRL_LIST_MAX_SIZE || buff_size < 0) {
        tloge("Invalid TA control list buff size\n");
        return TEE_ERROR_GENERIC;
    }

    if (buff_size > 0) {
        buff = TEE_Malloc(buff_size, 0);
        if (buff == NULL) {
            tloge("Failed to malloc buffer, size: %d\n", buff_size);
            return TEE_ERROR_OUT_OF_MEMORY;
        }

        len = perm_serv_ta_ctrl_list_to_buff(buff, buff_size);
        if (len <= 0) {
            tloge("Failed to insert ctrl list to buff\n");
            goto exit;
        }

        if (perm_srv_file_write(g_ta_ctrl_config.file_name, buff, len) != 0) {
            tloge("Failed to write ctrl list to file\n");
            goto exit;
        }
    }

    tee_ret = TEE_SUCCESS;

exit:
    TEE_Free(buff);
    return tee_ret;
}

static TEE_Result perm_srv_cert_cn_check(const uint8_t *cn, size_t cn_size, const uint8_t *expected_cn,
                                         size_t expect_cn_size)
{
    bool is_invalid = (cn == NULL || cn_size == 0 || expected_cn == NULL || expect_cn_size == 0 ||
                       cn_size > CERT_UNIVERSAL_LEN || expect_cn_size > CERT_UNIVERSAL_LEN);
    if (is_invalid)
        return TEE_ERROR_GENERIC;

    if (strlen((char *)expected_cn) == cn_size && TEE_MemCompare(cn, expected_cn, cn_size) == 0)
        return TEE_SUCCESS;

    tloge("size: 0x%x, %s\n", cn_size, cn);
    tloge("Expect size: 0x%x, %s\n", expect_cn_size, expected_cn);
    return TEE_ERROR_GENERIC;
}

static TEE_Result perm_srv_cert_ou_check(const uint8_t *ou, size_t ou_size, const uint8_t *expected_ou,
                                         size_t expect_ou_size)
{
    bool is_invalid = (ou == NULL || ou_size == 0 || ou_size > CERT_UNIVERSAL_LEN || expected_ou == NULL ||
                       expect_ou_size == 0 || expect_ou_size > CERT_UNIVERSAL_LEN);
    if (is_invalid)
        return TEE_ERROR_BAD_PARAMETERS;

    if (ou_size == expect_ou_size && TEE_MemCompare(ou, expected_ou, ou_size) == 0) {
        tlogd("TA certificate type: %s\n", "Production");
        return TEE_SUCCESS;
    }

    tloge("size: 0x%x, %s\n", ou_size, ou);
    tloge("Production size: 0x%x, %s\n", expect_ou_size, expected_ou);
    return TEE_ERROR_GENERIC;
}

static TEE_Result perm_srv_ctrl_cert_check(const uint8_t *cert, size_t cert_size)
{
    const char *expected_cn = "Huawe_iTrustee_TA_Control_List";
    const char *expected_ou = "Huawei iTrustee Production";
    uint8_t cn_buff[CN_OU_BUFFER_SIZE] = { 0 };
    uint8_t ou_buff[CN_OU_BUFFER_SIZE] = { 0 };
    uint32_t ou_size = (size_t)sizeof(ou_buff);
    TEE_Result tee_ret;
    struct secure_img_data data = { 0 };

    data.cert = cert;
    data.cert_size = cert_size;
    data.cn = cn_buff;
    data.cn_size = (uint32_t)sizeof(cn_buff);
    /* Get public key, CN, OU from the cert */
    rsa_pub_key_t ctrl_list_key = { { 0 }, 0, { 0 }, 0 };
    tee_ret = tee_secure_img_parse_cert(&ctrl_list_key, &data, ou_buff, &ou_size);
    (void)memset_s(&ctrl_list_key, sizeof(ctrl_list_key), 0, sizeof(ctrl_list_key));
    if (tee_ret != TEE_SUCCESS) {
        tloge("Failed to parse ta ctrl list cert\n");
        return tee_ret;
    }

    tee_ret = perm_srv_cert_cn_check(cn_buff, data.cn_size, (uint8_t *)expected_cn, strlen(expected_cn));
    if (tee_ret != TEE_SUCCESS) {
        tloge("Failed to pass ta ctrl list certificate CN check\n");
        return tee_ret;
    }

    tee_ret = perm_srv_cert_ou_check(ou_buff, ou_size, (uint8_t *)expected_ou, strlen(expected_ou));
    if (tee_ret != TEE_SUCCESS) {
        tloge("Failed to pass ta ctrl list certificate OU check\n");
        return tee_ret;
    }

    return TEE_SUCCESS;
}

struct ctrl_verify_data {
    const uint8_t *buffer;
    size_t size;
};

static TEE_Result perm_srv_ta_ctrl_list_verify(struct ctrl_verify_data body_data, const uint8_t *signature,
                                               size_t signature_size, const uint8_t *cert, size_t cert_size)
{
    uint8_t hash_buff[SHA256_LEN] = { 0 };
    size_t hash_buff_size = sizeof(hash_buff);
    TEE_Result tee_ret;

    bool is_invaild = (body_data.buffer == NULL || body_data.size == 0 || signature == NULL || signature_size == 0 ||
                       cert == NULL || cert_size == 0);
    if (is_invaild)
        return TEE_ERROR_BAD_PARAMETERS;

    /* Verify ctrl list cert */
    uint8_t *ca_public_key = (uint8_t *)get_ca_pubkey();
    uint32_t ca_public_key_len = get_ca_pubkey_size();
    tee_ret = tee_secure_img_check_cert_validation(cert, cert_size, ca_public_key, ca_public_key_len);
    if (tee_ret != TEE_SUCCESS) {
        tloge("Failed to pass certificate validation check\n");
        return TEE_ERROR_GENERIC;
    }

    tee_ret = perm_srv_ctrl_cert_check(cert, cert_size);
    if (tee_ret != TEE_SUCCESS)
        return tee_ret;

    tee_ret = tee_secure_img_calc_hash(body_data.buffer, body_data.size, hash_buff, hash_buff_size, TEE_ALG_SHA256);
    if (tee_ret != TEE_SUCCESS) {
        tloge("Failed to calculate hash for TA control list\n");
        return tee_ret;
    }

    struct ta_verify_key verify_key = {PUB_KEY_2048_BITS, PUB_KEY_RELEASE, NULL};
    tee_ret = get_ta_verify_pubkey(&verify_key);
    if (tee_ret != TEE_SUCCESS) {
        tloge("Failed to get TA ctrl verify key\n");
        return tee_ret;
    }
    rsa_pub_key_t *ctrl_list_key = (rsa_pub_key_t *)verify_key.key;
    tee_ret = tee_secure_img_verify_signature(signature, signature_size, hash_buff, hash_buff_size, ctrl_list_key);
    if (tee_ret != TEE_SUCCESS) {
        tloge("Failed to verify signature for TA control list\n");
        return tee_ret;
    }

    return TEE_SUCCESS;
}

static TEE_Result perm_serv_ta_params_check(const uint8_t *ctrl_buff, uint32_t ctrl_buff_size,
                                            struct ta_ctrl_list_hd_t *ctrl_list_hd)
{
    bool is_invalid = (ctrl_buff == NULL || ctrl_buff_size <= sizeof(*ctrl_list_hd));
    if (is_invalid) {
        tloge("TA control list buffer is invalid buffer size is %u\n", ctrl_buff_size);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (memcpy_s(ctrl_list_hd, sizeof(*ctrl_list_hd), ctrl_buff, sizeof(*ctrl_list_hd)) != EOK) {
        tloge("perm serv ta params check fail");
        return TEE_ERROR_SECURITY;
    }

    is_invalid = ((ctrl_list_hd->body_len > TA_CTRL_LIST_MAX_SIZE) ||
                  (ctrl_list_hd->signature_len != RSA2048_SIGNATURE_LEN) || (ctrl_list_hd->cert_len > CERT_MAX_SIZE) ||
                  ((sizeof(*ctrl_list_hd) + ctrl_list_hd->body_len + ctrl_list_hd->signature_len +
                    ctrl_list_hd->cert_len) > ctrl_buff_size));
    if (is_invalid) {
        tloge("TA control list header check failed\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    return TEE_SUCCESS;
}


static TEE_Result perm_srv_check_ta_ctrl_chip(const uint8_t *ctrl_body, uint32_t *ctrl_body_size)
{
    (void)ctrl_body;
    (void)ctrl_body_size;
    tloge("OH not support this function!!");
    return TEE_ERROR_GENERIC;
}

TEE_Result perm_serv_ta_ctrl_buff_process(const uint8_t *ctrl_buff, uint32_t ctrl_buff_size)
{
    TEE_Result tee_ret;
    const uint8_t *signature = NULL;
    const uint8_t *body = NULL;
    const uint8_t *cert = NULL;
    uint32_t off_set;
    struct ta_ctrl_list_hd_t ctrl_list_hd = { 0 };
    struct ctrl_verify_data body_data = { 0 };

    tee_ret = perm_serv_ta_params_check(ctrl_buff, ctrl_buff_size, &ctrl_list_hd);
    if (tee_ret != TEE_SUCCESS)
        return tee_ret;

    off_set = (uint32_t)sizeof(ctrl_list_hd);
    body = ctrl_buff + off_set;

    off_set += ctrl_list_hd.body_len;
    signature = ctrl_buff + off_set;

    off_set += ctrl_list_hd.signature_len;
    cert = ctrl_buff + off_set;
    body_data.buffer = body;
    body_data.size = ctrl_list_hd.body_len;
    tee_ret = perm_srv_ta_ctrl_list_verify(body_data, signature, ctrl_list_hd.signature_len,
                                           cert, ctrl_list_hd.cert_len);
    if (tee_ret != TEE_SUCCESS) {
        tloge("Failed to verify TA ctrl list\n");
        return tee_ret;
    }

    tee_ret = perm_srv_check_ta_ctrl_chip(body, &(ctrl_list_hd.body_len));
    if (tee_ret != TEE_SUCCESS)
        return tee_ret;

    tee_ret = perm_serv_ta_ctrl_buff_to_list(body + TA_CTRL_CHIP_LEN,
        (size_t)ctrl_list_hd.body_len - TA_CTRL_CHIP_LEN);
    if (tee_ret != TEE_SUCCESS) {
        tloge("Failed to parse TA control buff to list\n");
        return tee_ret;
    }

    perm_serv_ta_ctrl_list_print();

    tee_ret = perm_serv_global_ctrl_list_storing();

    return tee_ret;
}

TEE_Result perm_srv_check_ta_deactivated(const TEE_UUID *uuid, uint16_t version)
{
    struct dlist_node *pos = NULL;
    TEE_Result tee_ret;

    if (uuid == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    perm_serv_ta_ctrl_list_print();

    if (pthread_mutex_lock(&g_ta_ctrl_config.lock) != 0) {
        tloge("Failed to do pthread mutex lock\n");
        return TEE_ERROR_BAD_STATE;
    }

    dlist_for_each(pos, &g_ta_ctrl_config.ctrl_list) {
        struct ta_ctrl_node *entry = dlist_entry(pos, struct ta_ctrl_node, head);
        if (TEE_MemCompare(uuid, &entry->uuid, sizeof(TEE_UUID)) == 0) {
            if (version > entry->version)
                tee_ret = TEE_SUCCESS;
            else
                tee_ret = TEE_ERROR_GENERIC;

            (void)pthread_mutex_unlock(&g_ta_ctrl_config.lock);
            return tee_ret;
        }
    }

    (void)pthread_mutex_unlock(&g_ta_ctrl_config.lock);
    return TEE_SUCCESS;
}
