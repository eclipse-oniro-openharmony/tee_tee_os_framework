/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2020. All rights reserved.
 * Description: keymaster common functions
 * Create: 2012-01-17
 */

#include "km_common.h"
#include "securec.h"
#include "km_env.h"
#include "km_defines.h"

#include "km_tag_operation.h"
#include "km_attest_factory.h"
#include "km_keynode.h"

file_operations_t g_file_operation;

static bool g_auth_lock_init     = false;
static bool g_index_lock_init    = false;
static bool g_metafile_lock_init = false;
static bool g_attest_key_lock_init = false;

file_operations_t *get_file_operation_info()
{
    return &g_file_operation;
}

#ifdef DUMP_MSG
static void byte_to_hex(char *buf, char data)
{
    const char *str = "0123456789abcdef";
    *buf++ = (str[(data >> KM_NUM_FOUR) & 0x0F]);
    *buf++ = str[data & 0x0F];
}

char hex_to_byte(char c)
{
    if ((c >= '0') && (c <= '9'))
        return (c - '0');
    if ((c >= 'A') && (c <= 'F'))
        return (c - 'A' + KM_NUM_TEN);
    if ((c >= 'a') && (c <= 'f'))
        return (c - 'a' + KM_NUM_TEN);
    return 0;
}

void dump_msg(const char *info, uint8_t *data, int32_t len)
{
    if (info == NULL || data == NULL || len == 0)
        return;
    char buf[KM_NUM_ONE_HUNDRED] = { 0 };
    int32_t i, j, k;
    char *pbuf  = buf;
    char *pdata = (char *)data;

    k = len / KM_NUM_THIRTY_TWO;

    for (j = 0; j < k; j++) {
        for (i = 0; i < KM_NUM_THIRTY_TWO; i++) {
            byte_to_hex(pbuf, *pdata++);
            pbuf += KM_NUM_TWO;
        }

        buf[KM_NUM_SIXTY_FOUR] = 0;
        SLogTrace("%s : %s", info, buf);
        pbuf = buf;
    }

    k = len % KM_NUM_THIRTY_TWO;

    for (i = 0; i < k; i++) {
        byte_to_hex(pbuf, *pdata++);
        pbuf += KM_NUM_TWO;
    }
    *pbuf = 0;
    SLogTrace("%s : %s", info, buf);
}
#endif

int32_t get_next_int4(uint8_t **in)
{
    int32_t value  = -1;
    bool check = ((in != NULL) && (*in != NULL));
    if (check) {
        errno_t rc = memcpy_s((void *)&value, sizeof(int), (void *)*in, sizeof(int));
        if (rc != EOK) {
            tloge("[error]memcpy_s failed, rc=%d, line:%d\n", rc, __LINE__);
            return -1;
        }
        *in += sizeof(int);
    }
    return value;
}

static void insert_tlv_set_len(uint32_t len, uint8_t **buf, uint32_t *buf_len)
{
    if (len < KM_TLV_VALUE_LEN128) {
        (*buf[0]) = (uint8_t)len;
        (*buf)++;
        (*buf_len)--;
        if (*buf_len == 0) {
            tloge("buf not enough mem\n");
            return;
        }
    } else {
        if (len < 0x100) {
            (*buf_len) -= KM_NUM_TWO;
            if (*buf_len == 0) {
                tloge("buf not enough mem\n");
                return;
            }

            (*buf[0]) = KM_TLV_LEN_TWOBYTE;
            (*buf)++;
            (*buf[0]) = (uint8_t)len;
            (*buf)++;
        } else {
            (*buf_len) -= KM_NUM_THREE;
            if (*buf_len == 0) {
                tloge("buf not enough mem\n");
                return;
            }

            (*buf)[0] = KM_TLV_LEN_THREEBYTE;
            (*buf)++;
            (*buf)[0] = (uint8_t)(len >> KM_NUM_EIGHT);
            (*buf)++;
            (*buf)[0] = (uint8_t)(len & 0xFF);
            (*buf)++;
        }
    }
}
void insert_tlv(uint32_t type, uint32_t len, const uint8_t *value, uint8_t **buf, uint32_t *buf_len)
{
    uint32_t pad = 0;
    bool check   = ((buf == NULL) || (*buf == NULL) || (buf_len == NULL) || (*buf_len < KM_NUM_TWO));
    if (check) {
        tloge("invalid input params!\n");
        return;
    }

    (*buf)[0] = (uint8_t)type;
    (*buf)++;
    (*buf_len)--;
    if (*buf_len == 0) {
        tloge("buf not enough mem\n");
        return;
    }

    /* trim the 00 at the beginning of value */
    check = ((value != NULL) && (len != 0) && (type != KM_ASN1_OCTSTR));
    if (check) {
        while (value[0] == KM_SPACE_CHAR && len > 1) {
            value++;
            len--;
        }
    }
    /* If we have bit string, we need to put unused bits */
    check = ((type == KM_ASN1_BIT_STRING) || ((type == KM_ASN1_INT) && (value != NULL) && (value[0] > 0x7f)));
    if (check) {
        pad++;
        len++;
    }
    insert_tlv_set_len(len, buf, buf_len);

    if (pad != 0) {
        (*buf)[0] = 0;
        (*buf)++;
        (*buf_len)--;
        if (*buf_len == 0) {
            tloge("buf not enough mem\n");
            return;
        }
    }
    /* In case of BITSTRING we have already added zero octet, therefore we need to adjust length */
    check = ((len > pad) && ((len - pad) != 0) && (value != NULL));
    if (check) {
        errno_t rc = memmove_s(*buf, *buf_len, value, len - pad);
        if (rc != EOK) {
            tloge("[error]memmove_s failed, rc=%d, line:%d, len=%u\n", rc, __LINE__, len - pad);
            return;
        }
        (*buf) += (len - pad);
        (*buf_len) -= (len - pad);
    }
}

static void tlv_set_len(uint8_t **hptr_out, uint32_t *hlen_out, uint32_t len)
{
    uint8_t *hptr = *hptr_out;
    uint32_t hlen;
    if (len < KM_TLV_VALUE_LEN128) {
        hptr[0] = (uint8_t)len;
        hptr++;
        hlen = KM_NUM_FOUR;
    } else {
        if (len < KM_TLV_VALUE_LEN256) {
            hptr[0] = KM_TLV_LEN_TWOBYTE;
            hptr++;
            hptr[0] = (uint8_t)len;
            hptr++;
            hlen = KM_NUM_FIVE;
        } else {
            hptr[0] = KM_TLV_LEN_THREEBYTE;
            hptr++;
            hptr[0] = (uint8_t)(len >> KM_NUM_EIGHT);
            hptr++;
            hptr[0] = (uint8_t)(len & 0xFF);
            hptr++;
            hlen = KM_NUM_SIXE;
        }
    }
    *hptr_out = hptr;
    *hlen_out = hlen;
}
/* Similar as insert_tlv, but tag is 3-bytes */
static void insert_tlv2(const uint8_t *type, uint32_t len, const uint8_t *value, uint8_t **buf, uint32_t *buf_len)
{
    uint32_t hlen = 0;
    uint8_t header[KM_NUM_SEVEN] = { 0 };
    uint8_t *hptr                = header;
    bool check = ((buf == NULL) || (*buf == NULL) || (buf_len == NULL) || (value == NULL));
    if (check) {
        tloge("invalid input params!\n");
        return;
    }

    errno_t rc = memcpy_s(header, sizeof(header), type, KM_NUM_THREE);
    if (rc != EOK) {
        tloge("[error]memcpy_s failed, rc=%d, line:%d\n", rc, __LINE__);
        return;
    }

    hptr += KM_NUM_THREE;

    tlv_set_len(&hptr, &hlen, len);

    check = (((UINT32_MAX - hlen) < len) || (*buf_len < (hlen + len)));
    if (check) {
        tloge("invalid len:%u,%u,%u\n", hlen, len, *buf_len);
        return;
    }
    /* In case of BITSTRING we have already added zero octet, therefore we need to adjust length */
    rc = memmove_s((*buf) + hlen, (*buf_len - hlen), value, len);
    if (rc != EOK) {
        tloge("[error]memmove_s failed, rc=%d, line:%d\n", rc, __LINE__);
        return;
    }

    /* copy header safely */
    rc = memcpy_s(*buf, hlen, header, hlen);
    if (rc != EOK) {
        tloge("[error]memcpy_s failed, rc=%d, line:%d\n", rc, __LINE__);
        return;
    }

    (*buf) += hlen;
    (*buf) += (len);
    (*buf_len) -= (hlen + len);
}

#define KM_INVALID_TAG 0x1F1F
#define KM_MIN_EXT_TAG 0x1F
void insert_explicit_tlv(uint32_t type, uint32_t len, uint8_t *value, uint8_t **buf, uint32_t *buf_len, uint32_t tag)
{
    uint8_t ext_type[KM_NUM_THREE] = { 0 };
    bool check = ((buf == NULL) || (*buf == NULL) || (buf_len == NULL));
    if (check) {
        tloge("invalid input params!\n");
        return; /* no need return error code */
    }
    uint8_t *start    = NULL;
    uint8_t *end      = NULL;
    uint8_t *ptr      = *buf;
    uint32_t temp_len;
    if (tag > KM_INVALID_TAG)
        return;

    ext_type[0] = 0xa0;
    if (tag < KM_MIN_EXT_TAG) {
        ext_type[0] ^= (uint8_t)tag;
        start    = ptr + KM_NUM_FOUR;
        end      = start;
        temp_len = *buf_len - KM_NUM_FOUR;
        insert_tlv(type, len, value, &end, &temp_len);
        insert_tlv(ext_type[0], (uint32_t)(end - start), start, buf, buf_len);
    } else {
        ext_type[0] ^= KM_MIN_EXT_TAG;
        ext_type[1] = ((tag >> KM_NUM_SEVEN) & 0xFF) ^ 0x80;
        /* unset MSB in second byte */
        ext_type[KM_NUM_TWO] = tag & 0x7F;
        start                = ptr + KM_NUM_FOUR;
        end                  = start;
        temp_len             = *buf_len - KM_NUM_FOUR;
        insert_tlv(type, len, value, &end, &temp_len);
        insert_tlv2(ext_type, (uint32_t)(end - start), start, buf, buf_len);
    }
}

int init_km_mutex(void)
{
    int ret;

    if (!g_auth_lock_init) {
        ret = pthread_mutex_init(get_key_auth_lock(), NULL);
        if (ret != 0)
            return ret;
        g_auth_lock_init = true;
    }

    if (!g_index_lock_init) {
        ret = pthread_mutex_init(get_key_index_lock(), NULL);
        if (ret != 0)
            return ret;
        g_index_lock_init = true;
    }

    if (!g_metafile_lock_init) {
        ret = pthread_mutex_init(get_opera_metafile_lock(), NULL);
        if (ret != 0)
            return ret;
        g_metafile_lock_init = true;
    }

    if (!g_attest_key_lock_init) {
        ret = pthread_mutex_init(get_attest_key_lock(), NULL);
        if (ret != 0)
            return ret;
        g_attest_key_lock_init = true;
    }
    return 0;
}

void destroy_km_mutex(void)
{
    int ret;

    if (g_auth_lock_init) {
        ret = pthread_mutex_destroy(get_key_auth_lock());
        if_log(ret != 0, "destroy auth lock failed 0x%x", ret);
        g_auth_lock_init = false;
    }

    if (g_index_lock_init) {
        ret = pthread_mutex_destroy(get_key_index_lock());
        if_log(ret != 0, "destroy index lock failed 0x%x", ret);
        g_index_lock_init = false;
    }

    if (g_metafile_lock_init) {
        ret = pthread_mutex_destroy(get_opera_metafile_lock());
        if_log(ret != 0, "destroy meta lock failed 0x%x", ret);
        g_metafile_lock_init = false;
    }
}

void get_application_id(keymaster_blob_t *application_id, const keymaster_key_param_set_t *params_enforced)
{
    if (application_id == NULL) {
        tloge("null pointer");
        return;
    }
    if (get_key_param(KM_TAG_APPLICATION_ID, application_id, params_enforced) != 0) {
        tlogd("not found APPLICATION_ID\n");
        application_id->data_addr = NULL;
    }
    tlogd("application_id data length %u", application_id->data_length);
    return;
}

void erase_free_blob(keymaster_blob_t *blob)
{
    bool check_fail = (blob == NULL || blob->data_addr == NULL);
    if (check_fail) {
        tloge("erasing parameters invalid");
        return;
    }
    if (blob->data_length != 0) {
        if (memset_s(blob->data_addr, blob->data_length, 0, blob->data_length) != EOK)
            tloge("erase buffer data failed\n");
    }

    TEE_Free(blob->data_addr);
    blob->data_addr = NULL;
    blob->data_length = 0;
}

void free_blob(keymaster_blob_t *blob)
{
    if (blob != NULL) {
        TEE_Free(blob->data_addr);
        blob->data_addr = NULL;
        blob->data_length = 0;
    }
}

bool is_buff_zero(const uint8_t *buff, uint32_t len)
{
    if (buff == NULL || len == 0)
        return true;
    uint32_t i = 0;
    for (; i < len; i++) {
        if (buff[i] != 0)
            return false;
    }
    return true;
}
