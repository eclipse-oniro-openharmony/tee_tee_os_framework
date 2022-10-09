/*$$$!!Warning: Huawei key information asset. No spread without permission.$$$*/
/*CODEMARK:mJSkoqPZ5FEeD8fzH9bAQfhyPrkcI5cbzjotjI99J9PTkCMNHMtR+8Ejd3mKEkWbMFYmuIhV
lw/je6uplRzXM4SMvhun8vRGD9mNqO2kY4/aQFDUiG2CG+z+BR1XavYOLbgQ6mxl4mdMDMUc
pTTvsgNnGY+uGDhrcSrYT/yiWUcPU+7hHj/1z+1w4sei8NKrE5YtD4ycmPizGfaNhWQY5YvG
yUQ4I+iaikKhay3gs3gbvr2F/fo9kmuK6WNlljMWqZQckvm//k0TiyJFZq4NZA==#*/
/*$$$!!Warning: Deleting or modifying the preceding information is prohibited.$$$*/
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2016-2020. All rights reserved.
 * Description: permission handle crl cert
 * Author: TianJianliang tianjianliang@huawei.com
 * Create: 2016-04-01
 */
#include "handle_crl_cert.h"
#include <securec.h>
#include <tee_log.h>
#include <tee_mem_mgmt_api.h>
#include <crl_api.h>
#include <crypto_wrapper.h>
#include "handle_file_op.h"
#include "handle_config.h"

static struct revoked_config_t g_crl_revoked_config = {
    .crl_issuer_list = dlist_head_init(g_crl_revoked_config.crl_issuer_list),
    .list_file       = "crl_cert_list_file.db",
    .issuer_count    = 0,
    .revoked_count   = 0,
    .lock            = PTHREAD_MUTEX_INITIALIZER,
};

#define ISSUER_MAX_COUNT     0xFF
#define REVOKED_MAX_COUNT    0xFFFF
#define ENTRY_MAX_BUFFER_LEN 128

static TEE_Result perm_srv_issuer_list_add_node(struct crl_issuer_t *issuer_entry)
{
    if (pthread_mutex_lock(&g_crl_revoked_config.lock) != 0) {
        tloge("Failed to do pthread mutex lock\n");
        return TEE_ERROR_BAD_STATE;
    }

    if (g_crl_revoked_config.issuer_count >= ISSUER_MAX_COUNT) {
        (void)pthread_mutex_unlock(&g_crl_revoked_config.lock);
        tloge("Issuer count of CRL shouldn't be over 0xFF\n");
        return TEE_ERROR_GENERIC;
    }

    g_crl_revoked_config.issuer_count++;
    dlist_insert_tail(&issuer_entry->head, &g_crl_revoked_config.crl_issuer_list);

    (void)pthread_mutex_unlock(&g_crl_revoked_config.lock);
    return TEE_SUCCESS;
}

static TEE_Result perm_srv_revoked_list_add_node(struct crl_issuer_t *issuer_entry, struct revoked_entry_t *node)
{
    if (pthread_mutex_lock(&g_crl_revoked_config.lock) != 0) {
        tloge("Failed to do pthread mutex lock\n");
        return TEE_ERROR_BAD_STATE;
    }

    if (g_crl_revoked_config.revoked_count >= REVOKED_MAX_COUNT) {
        (void)pthread_mutex_unlock(&g_crl_revoked_config.lock);
        tloge("Revoked entry count of CRL shouldn't be over 0xFFFF\n");
        return TEE_ERROR_GENERIC;
    }

    g_crl_revoked_config.revoked_count++;
    dlist_insert_tail(&node->head, &(issuer_entry->revoked_entry_list));

    (void)pthread_mutex_unlock(&g_crl_revoked_config.lock);
    return TEE_SUCCESS;
}

static int32_t perm_srv_insert_tlv(uint8_t type, const uint8_t *value, uint32_t len, uint8_t **buf, uint32_t buf_size)
{
    bool is_invalid = (value == NULL || len == 0 || buf == NULL || *buf == NULL || (buf_size < (len + TLV_HEADER_LEN)));
    if (is_invalid)
        return -1;

    uint8_t *tmp = *buf;

    /* type */
    tmp[0] = type;
    tmp += TLV_TLEN;

    /* length */
    if (memcpy_s(tmp, buf_size - TLV_TLEN, &len, TLV_LLEN) != EOK) {
        tloge("Failed to do memcpy_s for len of TLV\n");
        return -1;
    }

    tmp += TLV_LLEN;

    if (memcpy_s(tmp, buf_size - TLV_HEADER_LEN, value, len) != EOK) {
        tloge("Failed to do memcpy_s for value of TLV\n");
        return -1;
    }
    tmp += len;

    *buf = tmp;
    return len + TLV_HEADER_LEN;
}

static int32_t perm_srv_insert_revoked_entry(uint8_t **buf, uint32_t buf_size, const struct revoked_entry_t *entry)
{
    uint8_t *start = NULL;
    uint32_t value_len;
    uint32_t package_len;
    uint32_t buff_left_size;
    uint8_t entry_buff[ENTRY_MAX_BUFFER_LEN] = { 0 };
    int32_t len;

    bool is_invalid = (buf == NULL || *buf == NULL || entry == NULL || buf_size == 0);
    if (is_invalid)
        return -1;

    start = entry_buff;
    buff_left_size = (uint32_t)sizeof(entry_buff);

    if (entry->sn_size + TLV_HEADER_LEN > buff_left_size || entry->sn_size > CERT_UNIVERSAL_LEN) {
        tloge("Buffer overflow for inserting serail number\n");
        return -1;
    }

    len = perm_srv_insert_tlv(TYPE_BITSTRING, entry->sn, entry->sn_size, &start, buff_left_size);
    if (len < 0) {
        tloge("Failed to insert tlv for inserting serial number\n");
        return -1;
    }

    buff_left_size -= len;

    if (buff_left_size < ASN1_FORMAT_TIME_SIZE + TLV_HEADER_LEN) {
        tloge("Buffer overflow for inserting revoked date\n");
        return -1;
    }

    len = perm_srv_insert_tlv(TYPE_BITSTRING, entry->revoked_date, ASN1_FORMAT_TIME_SIZE, &start, buff_left_size);
    if (len < 0) {
        tloge("Failed to insert tlv of revoked date\n");
        return -1;
    }

    buff_left_size -= len;

    value_len = (uint32_t)(start - entry_buff);
    package_len = value_len + (uint32_t)TLV_HEADER_LEN;

    if (package_len > buf_size) {
        tloge("Buffer overflow for inserting revoked entry\n");
        return -1;
    }

    len = perm_srv_insert_tlv(TYPE_SEQUENCE, entry_buff, value_len, buf, buf_size);
    if (len < 0) {
        tloge("Failed to insert revoked entry as tlv\n");
        return -1;
    }

    return package_len;
}

static int32_t perm_srv_insert_issuer_entry(uint8_t *buf, uint32_t buf_size, struct crl_issuer_t *issuer_entry)
{
    struct dlist_node *pos = NULL;
    uint8_t *start = NULL;
    uint32_t buff_left_size;
    uint32_t value_len;
    uint32_t total_len;
    int32_t len;

    bool is_invalid = (buf == NULL || issuer_entry == NULL || buf_size == 0);
    if (is_invalid)
        return -1;

    start = buf;
    buff_left_size = buf_size;

    /*
     * Reserve space for first tvl type and length
     * We don't fill it here because we don't know the length now
     */
    if (buff_left_size <= TLV_HEADER_LEN)
        return -1;

    buff_left_size -= (uint32_t)TLV_HEADER_LEN;

    start += TLV_HEADER_LEN;

    /* Fill the issuer section */
    len = perm_srv_insert_tlv(TYPE_BITSTRING, issuer_entry->issuer, issuer_entry->issuer_size, &start, buff_left_size);
    if (len < 0) {
        tloge("Failed to insert CRL cert issuer as TLV\n");
        return -1;
    }

    if (buff_left_size <= (uint32_t)len)
        return -1;

    buff_left_size -= len;

    /* Fill the revoked entry with specified issuer */
    dlist_for_each(pos, &issuer_entry->revoked_entry_list) {
        struct revoked_entry_t *entry = dlist_entry(pos, struct revoked_entry_t, head);
        len = perm_srv_insert_revoked_entry(&start, buff_left_size, entry);
        if (len < 0) {
            tloge("Failed to insert revoked entry\n");
            return len;
        }

        if (buff_left_size <= (uint32_t)len)
            return -1;

        buff_left_size -= len;
    }

    total_len = (uint32_t)(start - buf);
    value_len = total_len - (uint32_t)TLV_HEADER_LEN - (uint32_t)TLV_HEADER_LEN;

    /* Refill the TLV with type 0x30 and length */
    start = buf;
    start[0] = TYPE_SEQUENCE;
    start += TLV_TLEN;
    if (memcpy_s(start, TLV_LLEN, &value_len, TLV_LLEN) != EOK) {
        tloge("Failed to do memcpy_s for value of TLV\n");
        return -1;
    }

    return total_len;
}

#ifdef LOG_ON
void perm_srv_print_buff(const uint8_t *buff, size_t buff_size)
{
    size_t i;
    uint32_t type = sizeof(uint32_t);

    bool is_invalid = (buff == NULL || buff_size == 0);

    if (is_invalid)
        return;

    tloge("Buffer size: 0x%zu\n", buff_size);
    tloge("******************buffer context start****************\n");
    for (i = 0; i < buff_size / type; i++)
        tloge("%02x, %02x, %02x, %02x\n", buff[type * i], buff[type * i + TLV_TAG_TA_BASIC_INFO],
              buff[type * i + TLV_TAG_TA_MANIFEST_INFO], buff[type * i + TLV_TAG_TA_CONTROL_INFO]);

    for (i = 0; i < buff_size % type; i++)
        tloge("0x%02x\n", buff[buff_size - buff_size % type + i]);

    tloge("******************buffer context end****************\n");
}

static void perm_serv_global_crl_issuer_list_print(void)
{
    struct dlist_node *pos = NULL;

    if (pthread_mutex_lock(&g_crl_revoked_config.lock) != 0) {
        tloge("Failed to do pthread mutex lock\n");
        return;
    }

    /* Search for the issuer in global crl cert list */
    dlist_for_each(pos, &g_crl_revoked_config.crl_issuer_list) {
        struct dlist_node *inner = NULL;
        struct crl_issuer_t *issuer_entry = dlist_entry(pos, struct crl_issuer_t, head);

        /* Search for the sn in the revoked_entry_list with specified issuer */
        dlist_for_each(inner, &issuer_entry->revoked_entry_list) {
            struct revoked_entry_t *revoked_entry = dlist_entry(inner, struct revoked_entry_t, head);
            perm_srv_print_buff(revoked_entry->sn, revoked_entry->sn_size);
            tloge("Revocation date: %s\n", revoked_entry->revoked_date);
        }
    }

    (void)pthread_mutex_unlock(&g_crl_revoked_config.lock);
}
#else
static void perm_serv_global_crl_issuer_list_print(void)
{
}
#endif

static int32_t perm_srv_get_type_len(uint8_t *type, uint32_t *len, const uint8_t *buf, uint32_t buf_size)
{
    const uint8_t *pos = buf;

    if (buf_size < TLV_HEADER_LEN)
        return -1;

    /* type */
    *type = pos[0];
    pos += TLV_TLEN;

    /* length */
    if (memcpy_s(len, TLV_LLEN, pos, TLV_LLEN) != EOK) {
        tloge("Failed to do memcpy_s for len of TLV\n");
        return -1;
    }

    return 0;
}

static int32_t perm_srv_load_revoked_entry(uint8_t *buf, uint32_t buf_size, struct revoked_entry_t *entry)
{
    uint8_t *start = NULL;
    uint8_t type = 0;
    uint32_t len = 0;
    uint32_t buff_left_size;
    int32_t ret;

    bool is_invalid = (buf == NULL || entry == NULL || buf_size == 0);
    if (is_invalid)
        return -1;

    start = buf;
    buff_left_size = buf_size;

    /* load sequence header */
    ret = perm_srv_get_type_len(&type, &len, start, buff_left_size);
    is_invalid = (ret < 0 || type != TYPE_SEQUENCE || (len > buff_left_size - TLV_HEADER_LEN));
    if (is_invalid)
        return -1;

    start += TLV_HEADER_LEN;
    buff_left_size -= (uint32_t)TLV_HEADER_LEN;

    /* load SN */
    ret = perm_srv_get_type_len(&type, &len, start, buff_left_size);
    is_invalid = (ret < 0 || type != TYPE_BITSTRING || (len > buff_left_size - TLV_HEADER_LEN));
    if (is_invalid)
        return -1;

    start += TLV_HEADER_LEN;
    buff_left_size -= (uint32_t)TLV_HEADER_LEN;
    if (memcpy_s(entry->sn, sizeof(entry->sn), start, len) != EOK) {
        tloge("Failed to do memcpy_s for serial number\n");
        return -1;
    }

    entry->sn_size = len;
    start += len;
    buff_left_size -= len;

    /* load revoked date */
    ret = perm_srv_get_type_len(&type, &len, start, buff_left_size);
    is_invalid =
        (ret < 0 || type != TYPE_BITSTRING || (len > buff_left_size - TLV_HEADER_LEN) || len != ASN1_FORMAT_TIME_SIZE);
    if (is_invalid) {
        tloge("Failed to load revoked date, 0x%x, 0x%x, 0x%x\n", len, type, buff_left_size);
        return -1;
    }

    start += TLV_HEADER_LEN;
    if (memcpy_s(entry->revoked_date, sizeof(entry->revoked_date), start, ASN1_FORMAT_TIME_SIZE) != EOK)
        return -1;

    start += ASN1_FORMAT_TIME_SIZE;

    return (int32_t)(start - buf);
}

static int32_t perm_load_revoked_issuer(uint8_t **start, uint32_t left_size, struct crl_issuer_t *issuer_entry)
{
    int32_t ret;

    while (left_size > 0) {
        struct revoked_entry_t *entry = TEE_Malloc(sizeof(struct revoked_entry_t), 0);
        if (entry == NULL) {
            tloge("Failed to do tee malloc\n");
            return -1;
        }

        ret = perm_srv_load_revoked_entry(*start, left_size, entry);
        if (ret < 0) {
            tloge("Failed to load revoked entry\n");
            TEE_Free(entry);
            return -1;
        }

        (*start) += ret;
        left_size -= ret;
        if (perm_srv_revoked_list_add_node(issuer_entry, entry) != TEE_SUCCESS) {
            tloge("Failed to add revoked entry\n");
            TEE_Free(entry);
            return -1;
        }
    }

    return 0;
}

static int32_t perm_srv_load_issuer_entry(uint8_t *buf, uint32_t buf_size, struct crl_issuer_t *issuer_entry)
{
    uint8_t *start = buf;
    uint8_t type = 0;
    uint32_t len = 0;
    int32_t ret;
    bool is_invalid = false;
    uint32_t buff_left_size = buf_size;

    /* load sequence header */
    ret = perm_srv_get_type_len(&type, &len, start, buff_left_size);

    is_invalid = (ret < 0 || type != TYPE_SEQUENCE || (len > buff_left_size - (TLV_HEADER_LEN + TLV_HEADER_LEN)) ||
                  (buff_left_size <= (TLV_HEADER_LEN + TLV_HEADER_LEN)));
    if (is_invalid) {
        tloge("Failed to load sequence header, 0x%x, 0x%x, 0x%x\n", len, type, buff_left_size);
        return -1;
    }

    start += TLV_HEADER_LEN;
    buff_left_size -= (uint32_t)TLV_HEADER_LEN;

    ret = perm_srv_get_type_len(&type, &len, start, buff_left_size);

    is_invalid = (ret < 0 || type != TYPE_BITSTRING || (len > buff_left_size - TLV_HEADER_LEN));
    if (is_invalid) {
        tloge("Failed to load issuer header, 0x%x, 0x%x, 0x%x\n", len, type, buff_left_size);
        return -1;
    }

    start += TLV_HEADER_LEN;
    buff_left_size -= (uint32_t)TLV_HEADER_LEN;
    if (memcpy_s(issuer_entry->issuer, sizeof(issuer_entry->issuer), start, len) != EOK) {
        tloge("Failed to do memcpy_s for issuer\n");
        return -1;
    }

    issuer_entry->issuer_size = len;
    start += len;
    buff_left_size -= len;
    ret = perm_load_revoked_issuer(&start, buff_left_size, issuer_entry);
    if (ret != 0)
        return ret;

    return (int32_t)(start - buf);
}

static TEE_Result perm_srv_add_issuer_entry(const uint8_t *issuer, uint32_t issuer_size)
{
    struct dlist_node *pos = NULL;
    struct crl_issuer_t *entry = NULL;
    TEE_Result tee_ret;
    bool is_valid = false;

    /* The issuer does exist */
    if (pthread_mutex_lock(&g_crl_revoked_config.lock) != 0) {
        tloge("Failed to do pthread mutex lock\n");
        return TEE_ERROR_BAD_STATE;
    }

    dlist_for_each(pos, &g_crl_revoked_config.crl_issuer_list) {
        entry = dlist_entry(pos, struct crl_issuer_t, head);
        is_valid = ((issuer_size == entry->issuer_size) && (TEE_MemCompare(issuer, entry->issuer, issuer_size)) == 0);
        if (is_valid) {
            (void)pthread_mutex_unlock(&g_crl_revoked_config.lock);
            return TEE_SUCCESS;
        }
    }

    (void)pthread_mutex_unlock(&g_crl_revoked_config.lock);

    /* Add new issuer entry */
    entry = TEE_Malloc(sizeof(*entry), 0);
    if (entry == NULL) {
        tloge("Failed to malloc memory\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    dlist_init(&(entry->revoked_entry_list));
    if (memcpy_s(entry->issuer, sizeof(entry->issuer), issuer, issuer_size) != EOK) {
        tloge("Failed to do memcpy_s for issuer\n");
        TEE_Free(entry);
        return TEE_ERROR_GENERIC;
    }

    entry->issuer_size = issuer_size;

    /* Add new allocated issuer entry to global issuer list */
    tee_ret = perm_srv_issuer_list_add_node(entry);
    if (tee_ret != TEE_SUCCESS) {
        tloge("Failed to add issuer entry to list\n");
        TEE_Free(entry);
        entry = NULL;
    }

    return tee_ret;
}

static TEE_Result perm_srv_add_revoked_node(struct revoked_entry_t *crl_node, const uint8_t *issuer,
                                            uint32_t issuer_size)
{
    struct dlist_node *pos = NULL;
    struct crl_issuer_t *entry = NULL;
    TEE_Result tee_ret;
    bool is_valid = false;

    tee_ret = perm_srv_add_issuer_entry(issuer, issuer_size);
    if (tee_ret != TEE_SUCCESS) {
        tloge("Failed to add issuer entry\n");
        return tee_ret;
    }

    /* Find the issuer entry, add revoked entry to the issuer entry */
    if (pthread_mutex_lock(&g_crl_revoked_config.lock) != 0) {
        tloge("Failed to do pthread mutex lock\n");
        return TEE_ERROR_BAD_STATE;
    }

    dlist_for_each(pos, &g_crl_revoked_config.crl_issuer_list) {
        entry = dlist_entry(pos, struct crl_issuer_t, head);
        is_valid = ((issuer_size == entry->issuer_size) && (TEE_MemCompare(issuer, entry->issuer, issuer_size)) == 0);
        if (!is_valid)
            continue;
        (void)pthread_mutex_unlock(&g_crl_revoked_config.lock);
        return perm_srv_revoked_list_add_node(entry, crl_node);
    }

    (void)pthread_mutex_unlock(&g_crl_revoked_config.lock);
    /* The issuer entry doesn't exist */
    return TEE_ERROR_GENERIC;
}

static int32_t perm_srv_get_node_data(struct revoked_entry_t *node, const cert_list_entry_t *curr_entry,
                                      const uint8_t *issuer, uint32_t issuer_size)
{
    TEE_Result ret;

    if (memcpy_s(node->sn, sizeof(node->sn), curr_entry->serial, curr_entry->serial_size) != EOK) {
        tloge("Failed to do memcpy for serial number\n");
        return -1;
    }

    node->sn_size = curr_entry->serial_size;
    if (memcpy_s(node->revoked_date, sizeof(node->revoked_date), curr_entry->revoked_date,
                 sizeof(curr_entry->revoked_date)) != EOK) {
        tloge("Failed to do memcpy for revoked date\n");
        return -1;
    }

    ret = perm_srv_add_revoked_node(node, issuer, issuer_size);
    if (ret != TEE_SUCCESS) {
        tloge("Failed to add new revoked cert, errno: 0x%x\n", ret);
        return -1;
    }

    return EOK;
}

static TEE_Result perm_srv_global_issuer_list_update(cert_list_entry_t *entry, const uint8_t *issuer,
                                                     uint32_t issuer_size)
{
    cert_list_entry_t *curr_entry = entry;
    TEE_Result ret;

    bool is_invalid = (issuer == NULL || issuer_size == 0 || issuer_size >= CERT_LARGE_LEN);
    if (is_invalid)
        return TEE_ERROR_BAD_PARAMETERS;

    while (curr_entry != NULL) {
        bool exist = false;
        ret = perm_srv_check_cert_revoked(curr_entry->serial, curr_entry->serial_size, issuer, issuer_size, &exist);
        if (ret != TEE_SUCCESS) {
            tloge("Failed to check if cert is revoked, errno: 0x%x\n", ret);
            return ret;
        }

        if (!exist) {
            struct revoked_entry_t *node = NULL;
            node = TEE_Malloc(sizeof(*node), 0);
            if (node == NULL) {
                tloge("Failed to malloc, size: 0x%x\n", sizeof(*node));
                return TEE_ERROR_OUT_OF_MEMORY;
            }

            if (perm_srv_get_node_data(node, curr_entry, issuer, issuer_size) != EOK) {
                TEE_Free(node);
                return TEE_ERROR_GENERIC;
            }
        }
        curr_entry = curr_entry->next;
    }

    return TEE_SUCCESS;
}

static void perm_srv_crl_revoked_cert_list_cleanup(cert_list_entry_t *entry)
{
    while (entry != NULL) {
        cert_list_entry_t *next = entry->next;
        TEE_Free(entry);
        entry = next;
    }
}

static void perm_srv_crl_issuer_entry_cleanup(struct crl_issuer_t *issuer_entry)
{
    if (issuer_entry == NULL)
        return;

    struct dlist_node *inner = NULL;
    struct dlist_node *next = NULL;
    struct revoked_entry_t *entry = NULL;

    dlist_for_each_safe(inner, next, &issuer_entry->revoked_entry_list) {
        entry = dlist_entry(inner, struct revoked_entry_t, head);
        dlist_delete(&entry->head);
        TEE_Free(entry);
        entry = NULL;
    }
}

static TEE_Result perm_serv_list_ctrl_issu_load(uint8_t *start, uint32_t left_size)
{
    int32_t ret;
    TEE_Result tee_ret;

    while (left_size > 0) {
        struct crl_issuer_t *entry = NULL;
        entry = TEE_Malloc(sizeof(*entry), 0);
        if (entry == NULL) {
            tloge("Failed to malloc memory, size: 0x%x\n", sizeof(*entry));
            return TEE_ERROR_GENERIC;
        }

        dlist_init(&(entry->revoked_entry_list));
        ret = perm_srv_load_issuer_entry(start, left_size, entry);
        if (ret < 0) {
            tloge("Failed to load issuer entry\n");
            perm_srv_crl_issuer_entry_cleanup(entry);
            TEE_Free(entry);
            return TEE_ERROR_GENERIC;
        }

        start += ret;
        left_size -= ret;
        tee_ret = perm_srv_issuer_list_add_node(entry);
        if (tee_ret != TEE_SUCCESS) {
            tloge("Failed to add isser entry to list\n");
            perm_srv_crl_issuer_entry_cleanup(entry);
            TEE_Free(entry);
            return tee_ret;
        }
    }

    return TEE_SUCCESS;
}

static TEE_Result perm_serv_list_load(uint8_t *buff, int32_t file_size)
{
    TEE_Result tee_ret;
    int32_t ret;
    uint32_t buff_left_size;
    uint8_t *start = NULL;
    uint8_t type = 0;
    uint32_t len = 0;
    bool is_invalid = false;

    start = buff;
    buff_left_size = file_size;
    /* load sequence header */
    ret = perm_srv_get_type_len(&type, &len, start, buff_left_size);
    is_invalid = (ret < 0 || type != TYPE_SEQUENCE || (len > buff_left_size - TLV_HEADER_LEN));
    if (is_invalid) {
        tloge("Type len get error, %d, 0x%x, 0x%x, 0x%x\n", ret, type, len, buff_left_size);
        return TEE_ERROR_GENERIC;
    }

    start += TLV_HEADER_LEN;
    buff_left_size -= (uint32_t)TLV_HEADER_LEN;
    tee_ret = perm_serv_list_ctrl_issu_load(start, buff_left_size);
    return tee_ret;
}

TEE_Result perm_serv_global_issuer_list_loading(void)
{
    uint8_t *buff = NULL;
    TEE_Result tee_ret;
    int32_t ret;
    int32_t file_size;

    file_size = perm_srv_file_size(g_crl_revoked_config.list_file);
    if (file_size > CRL_CERT_LIST_MAX_SIZE) {
        tloge("CRL cert list file is over large\n");
        return TEE_ERROR_GENERIC;
    }

    /* CRL cert list is is empty or doesn't exist, ignore it */
    if (file_size == 0)
        return TEE_SUCCESS;

    if (file_size < 0) {
        tloge("Failed to get size of CRL cert list file\n");
        return TEE_ERROR_GENERIC;
    }

    buff = TEE_Malloc((uint32_t)file_size, 0);
    if (buff == NULL) {
        tloge("Failed to malloc buffer, size: %d\n", file_size);
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    ret = perm_srv_file_read(g_crl_revoked_config.list_file, buff, (uint32_t)file_size);
    if (ret != file_size) {
        tloge("Failed to read file ret: %d, size: %d\n", ret, file_size);
        tee_ret = TEE_ERROR_GENERIC;
        goto exit;
    }
    tee_ret = perm_serv_list_load(buff, file_size);

exit:
    TEE_Free(buff);
    return tee_ret;
}

static int32_t perm_srv_issuer_list_buff_size(void)
{
    struct revoked_entry_t revoked;
    struct crl_issuer_t issuer;
    (void)memset_s(&revoked, sizeof(revoked), 0, sizeof(revoked));
    (void)memset_s(&issuer, sizeof(issuer), 0, sizeof(issuer));

    uint8_t sn_size = (uint8_t)(sizeof(revoked.sn) + TLV_HEADER_LEN);
    uint8_t date_size = (uint8_t)(sizeof(revoked.revoked_date) + TLV_HEADER_LEN);
    uint8_t revoked_size = sn_size + date_size + (uint8_t)TLV_HEADER_LEN;
    uint16_t issuer_size = (uint16_t)(sizeof(issuer.issuer) + TLV_HEADER_LEN + TLV_HEADER_LEN);

    if (pthread_mutex_lock(&g_crl_revoked_config.lock) != 0) {
        tloge("Failed to do pthread mutex lock\n");
        return -1;
    }

    if (g_crl_revoked_config.issuer_count >= ISSUER_MAX_COUNT ||
        g_crl_revoked_config.revoked_count >= REVOKED_MAX_COUNT) {
        tloge("Issuer count of CRL is over 0xFF or revoked entry count of CRL is over 0xFFFF\n");
        (void)pthread_mutex_unlock(&g_crl_revoked_config.lock);
        return -1;
    }

    uint32_t total_size = revoked_size * g_crl_revoked_config.revoked_count +
                          issuer_size * g_crl_revoked_config.issuer_count + (uint32_t)TLV_HEADER_LEN;

    (void)pthread_mutex_unlock(&g_crl_revoked_config.lock);
    return total_size;
}

static TEE_Result per_search_global_crl(uint8_t *start, uint32_t left_size, uint32_t *value_len)
{
    struct dlist_node *pos = NULL;
    int32_t len;

    /* Search for the issuer in global crl cert list */
    if (pthread_mutex_lock(&g_crl_revoked_config.lock) != 0) {
        tloge("Failed to do pthread mutext lock\n");
        return TEE_ERROR_BAD_STATE;
    }

    dlist_for_each(pos, &g_crl_revoked_config.crl_issuer_list) {
        struct crl_issuer_t *issuer_entry = dlist_entry(pos, struct crl_issuer_t, head);

        len = perm_srv_insert_issuer_entry(start, left_size, issuer_entry);
        if (len < 0) {
            (void)pthread_mutex_unlock(&g_crl_revoked_config.lock);
            tloge("Failed to store CRL items in buffer\n");
            return TEE_ERROR_GENERIC;
        }

        start += len;
        left_size -= len;
        *value_len += (uint32_t)len;
    }

    (void)pthread_mutex_unlock(&g_crl_revoked_config.lock);
    return TEE_SUCCESS;
}

TEE_Result per_serv_global_issuer_list_storing(void)
{
    TEE_Result tee_ret;
    uint8_t *buff = NULL;
    uint8_t *start = NULL;
    uint32_t buff_left_size;
    uint32_t value_len = 0;
    uint32_t total_len;
    int32_t len;

    len = perm_srv_issuer_list_buff_size();
    if (len <= 0 || len > CRL_CERT_LIST_MAX_SIZE) {
        tloge("Invalid issuer list buffer size: %d\n", len);
        return TEE_ERROR_GENERIC;
    }

    buff = TEE_Malloc((uint32_t)len, 0);
    if (buff == NULL) {
        tloge("Failed to malloc buffer, size: %d\n", len);
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    start = buff;
    buff_left_size = len;

    /*
     * Reserve space for first tvl type and length
     * We don't fill it here because we don't know the length now
     */
    start += TLV_HEADER_LEN;
    buff_left_size -= (uint32_t)TLV_HEADER_LEN;

    tee_ret = per_search_global_crl(start, buff_left_size, &value_len);
    if (tee_ret != TEE_SUCCESS)
        goto exit;

    total_len = value_len + (uint32_t)TLV_HEADER_LEN;

    /* Refill the TLV with type 0x30 and length */
    start = buff;
    start[0] = TYPE_SEQUENCE;
    start += TLV_TLEN;
    if (memcpy_s(start, TLV_LLEN, &value_len, TLV_LLEN) != EOK) {
        tloge("Failed to do memcpy_s for value of TLV\n");
        tee_ret = TEE_ERROR_GENERIC;
        goto exit;
    }

    if (perm_srv_file_write(g_crl_revoked_config.list_file, buff, total_len) != 0) {
        tloge("Failed to write crl revoked list to file\n");
        tee_ret = TEE_ERROR_GENERIC;
        goto exit;
    }
    tee_ret = TEE_SUCCESS;

exit:
    TEE_Free(buff);
    return tee_ret;
}

TEE_Result perm_srv_check_cert_revoked(const uint8_t *sn, uint32_t sn_size, const uint8_t *issuer, uint32_t issuer_size,
                                       bool *revoked)
{
    struct dlist_node *pos = NULL;

    bool is_invalid = (sn == NULL || issuer == NULL || revoked == NULL || sn_size == 0 ||
                       sn_size > CERT_UNIVERSAL_LEN || issuer_size == 0 || issuer_size > CERT_LARGE_LEN);
    if (is_invalid)
        return TEE_ERROR_BAD_PARAMETERS;

    perm_serv_global_crl_issuer_list_print();
    /* Search for the issuer in global crl cert list */
    if (pthread_mutex_lock(&g_crl_revoked_config.lock) != 0) {
        tloge("Failed to do pthread mutex lock\n");
        return TEE_ERROR_BAD_STATE;
    }

    *revoked = false;
    dlist_for_each(pos, &g_crl_revoked_config.crl_issuer_list) {
        struct crl_issuer_t *issuer_entry = dlist_entry(pos, struct crl_issuer_t, head);
        bool is_valid = (issuer_size == issuer_entry->issuer_size &&
                         TEE_MemCompare(issuer, issuer_entry->issuer, issuer_size) == 0);
        if (!is_valid)
            continue;

        struct dlist_node *inner = NULL;
        struct dlist_node *next = NULL;

        /* Search for the sn in the revoked_entry_list with specified issuer */
        dlist_for_each_safe(inner, next, &issuer_entry->revoked_entry_list) {
            struct revoked_entry_t *entry = dlist_entry(inner, struct revoked_entry_t, head);
            is_valid = (sn_size == entry->sn_size && TEE_MemCompare(sn, entry->sn, sn_size) == 0);
            if (is_valid)
                *revoked = true;
        }
    }

    (void)pthread_mutex_unlock(&g_crl_revoked_config.lock);
    return TEE_SUCCESS;
}

TEE_Result perm_serv_crl_cert_process(const uint8_t *cert, uint32_t cert_size)
{
    cert_list_entry_t *crl_entry_list = NULL;
    TEE_Result tee_ret = TEE_ERROR_GENERIC;
    int32_t ret;
    uint8_t crl_issuer[CERT_LARGE_LEN] = { 0 };
    int32_t crl_issuer_len;
    const uint8_t *ca_public_key = get_ca_pubkey();

    bool is_invalid = (cert == NULL || cert_size == 0 || ca_public_key == NULL);
    if (is_invalid)
        return TEE_ERROR_BAD_PARAMETERS;

    /* Verify the CRL is signed by our CA center */
    ret = x509_crl_validate((uint8_t *)cert, cert_size, (uint8_t *)ca_public_key, get_ca_pubkey_size());
    if (ret <= 0) {
        tloge("Failed to validate certificate, errno: %d\n", ret);
        return TEE_ERROR_GENERIC;
    }

    crl_issuer_len = get_issuer_from_crl(crl_issuer, sizeof(crl_issuer), (uint8_t *)cert, cert_size);
    if (crl_issuer_len < 0) {
        tloge("Failed to get issuer from crl file\n");
        return TEE_ERROR_GENERIC;
    }

    crl_entry_list = TEE_Malloc(sizeof(*crl_entry_list), 0);
    if (crl_entry_list == NULL) {
        tloge("Failed to malloc memory, size: 0x%x\n", sizeof(*crl_entry_list));
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    ret = get_revocation_list_from_crl((uint8_t *)cert, cert_size, crl_entry_list);
    if (ret < 0) {
        tloge("Failed to get revocation list from crl\n");
        goto error_exit;
    }

    tee_ret = perm_srv_global_issuer_list_update(crl_entry_list, crl_issuer, crl_issuer_len);
    if (tee_ret != TEE_SUCCESS) {
        tloge("Failed to update global issuer list\n");
        goto error_exit;
    }

    perm_serv_global_crl_issuer_list_print();
    tee_ret = per_serv_global_issuer_list_storing();

error_exit:
    perm_srv_crl_revoked_cert_list_cleanup(crl_entry_list);
    return tee_ret;
}
