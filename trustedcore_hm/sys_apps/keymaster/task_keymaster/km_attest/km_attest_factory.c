/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2016-2020. All rights reserved.
 * Description: keymaster attest factory
 * Create: 2016-05-04
 */

#include "km_attest_factory.h"
#include <timer_export.h>
#include "keymaster_defs.h"
#include "securec.h"
#include "km_attest.h"
#include "km_common.h"
#include "tee_private_api.h"
#include "crypto_wrapper.h"
#include "km_types.h"
#include "km_tag_operation.h"
#include "km_env.h"
#include "km_crypto.h"
#include "km_key_gp_sw_convert.h"
#include "openssl/sha.h"
#include "openssl/rsa.h"
#ifdef BORINGSSL_ENABLE
#include "openssl/nid.h"
#else
#include "openssl/obj_mac.h"
#endif

static uint8_t g_attest_key_salt[] = { 'k', 'e', 'y', 'a', 't', 't', 'e', 's', 't', 'a', 't', 'i', 'o', 'n' };
void km_free_cert_chain(keymaster_cert_chain_t *chain)
{
    if (chain != NULL) {
        if (chain->entries != NULL) {
            uint32_t i;
            for (i = 0; i < chain->entry_count; ++i) {
                chain->entries[i].data_addr = NULL;
                chain->entries[i].data_length = 0;
            }
            TEE_Free(chain->entries);
        }
        chain->entries     = NULL;
        chain->entry_count = 0;
    }
}

static int32_t do_sign_with_attest_key(keymaster_blob_t *out, int src, int alg, uint8_t hash_buf[SHA256_LENGTH])
{
    int32_t ret;
    if (alg == ALG_EC) {
        ecc_priv_key_t prv_key;
        ret = get_attest_key(src, alg, &prv_key);
        if (ret != TEE_SUCCESS) {
            tloge("get attest key error\n");
            return ret;
        }
        ret = ecc_sign_digest(out->data_addr, out->data_length, hash_buf, SHA256_LENGTH, &prv_key);
        if (ret < 0) {
            tloge("ecc sign failed\n");
            return AT_SIGN_ERR;
        }
        out->data_length = (uint32_t)ret;
    } else if (alg == ALG_RSA) {
        rsa_priv_key_t prv_key;
        ret = get_attest_key(src, alg, &prv_key);
        if (ret != 0) {
            tloge("get attest key error\n");
            return ret;
        }
        uint32_t out_len = out->data_length;
        ret = rsa_sign_digest(out->data_addr, &out_len, hash_buf, SHA256_LENGTH, &prv_key,
                              0, NID_sha256, RSA_PKCS1_PADDING);
        if (ret < 0) {
            tloge("rsa sign failed\n");
            return AT_SIGN_ERR;
        }
        out->data_length = out_len;
    }
    tlogd("sign_with_attest_key success\n");
    return 0;
}

int32_t sign_with_attest_key(const keymaster_blob_t *in, keymaster_blob_t *out, int src, int alg)
{
    bool condition_check = (km_buffer_vaild(in) || km_buffer_vaild(out));
    if (condition_check) {
        tloge("invalid input params!\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    uint8_t hash_buf[SHA256_LENGTH] = { 0 };
    /* hash */
    uint8_t *result = SHA256(in->data_addr, in->data_length, hash_buf);
    if (result == NULL) {
        tloge("TEE_EXT_HASH failed");
        return AT_SIGN_HASH_ERR;
    }
    condition_check = (alg == ALG_EC) || (alg == ALG_RSA);
    if (!condition_check) {
        tloge("invalid algo:%d\n", alg);
        return AT_SIGN_ERR;
    }
    /* sign */
    return do_sign_with_attest_key(out, src, alg, hash_buf);
}

static int32_t get_cert_entry_update(keymaster_blob_t *cert_entry, int32_t cert_len, const keymaster_blob_t *file_name)
{
    file_operations_t *file_ops = get_file_operation_info();
    if ((uint32_t)cert_len <= 0 || (uint32_t)cert_len > FILE_SIZE_MAX) {
        tloge("cert_len is invaild\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    uint8_t *cert_buf = (uint8_t *)TEE_Malloc((uint32_t)cert_len, TEE_MALLOC_FILL_ZERO);
    if (cert_buf == NULL) {
        tloge("malloc cert_buf failed\n");
        return AT_MEM_ERR;
    }
    int32_t ret = file_ops->read((const char *)(file_name->data_addr), cert_buf, (uint32_t)cert_len);
    if (ret != cert_len) {
        tloge("read cert file error: ret=%d and file_name=%s\n", ret, (char *)(file_name->data_addr));
        TEE_Free(cert_buf);
        cert_buf = NULL;
        (void)cert_buf;
        if (ret < 0)
            return ret;
        return AT_FILE_SIZE_ERROR;
    }
    cert_entry->data_addr        = cert_buf;
    cert_entry->data_length = (uint32_t)cert_len;
    tlogd("get_cert_entry success\n");
    return 0;
}

int32_t get_cert_entry(int src, int32_t alg, int32_t cert_num, keymaster_blob_t *cert_entry)
{
    tlogd("get_cert_entry begin\n");
    if (cert_entry == NULL) {
        tloge("invalid input params!\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    int32_t ret;
    char file_name[FILE_NAME_LEN_MAX] = { 0 };
    file_operations_t *file_ops = get_file_operation_info();
    keymaster_blob_t file_name_blob = { (uint8_t *)file_name, sizeof(file_name) };
    /* check cert file */
    ret = get_file_name(&file_name_blob, src, alg, FILE_TYPE_CERT, cert_num);
    if (ret != 0) {
        tloge("get cert[%d] file name error\n", cert_num);
        return ret;
    }

    /* read cert file */
    int32_t cert_len;
    ret = file_ops->filesize(file_name);
    if (ret < 0) {
        tloge("get file size error: ret=%d and file_name=%s\n", ret, file_name);
        return ret;
    }
    if (ret == 0) {
        tloge("file size is zero: file_name=%s\n", file_name);
        return AT_FILE_SIZE_ERROR;
    }
    cert_len = ret;
    return get_cert_entry_update(cert_entry, cert_len, &file_name_blob);
}

int32_t format_provision_chain(uint8_t *chain, uint32_t *out_len, int32_t src, int32_t alg)
{
    bool check = ((chain == NULL) || (out_len == NULL) || (*out_len < sizeof(uint32_t)));
    if (check) {
        tloge("invalid input params!\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    uint32_t i;
    file_operations_t *file_ops = get_file_operation_info();
    uint8_t *tmp = chain;
    /* format chain body; */
    tmp += sizeof(uint32_t);
    uint32_t chain_len_out = sizeof(uint32_t);
    keymaster_blob_t cert_entry = { NULL, 0 };
    for (i = 0; i < CERT_COUNT_MAX; i++) {
        int32_t ret = get_cert_entry(src, alg, i, &cert_entry);
        check = (i > 1 && ((file_ops->fs_using == STORE_SFS && ret == (int)TEE_ERROR_ITEM_NOT_FOUND) ||
            (file_ops->fs_using == STORE_RPMB && ret == (int)TEE_ERROR_RPMB_FILE_NOT_FOUND)));
        if (check) {
            break;
        } else if (ret != 0) {
            tloge("get_cert_entry error:ret =%d\n", ret);
            return ret;
        }
        uint32_t next_entry_len = sizeof(uint32_t) + cert_entry.data_length;
        if (UINT32_MAX - cert_entry.data_length < sizeof(uint32_t) || ((*out_len - chain_len_out) < next_entry_len)) {
            tloge("format chain out error: out buf len is invalid[%u]\n", *out_len);
            goto free_entry;
        }

        if (memcpy_s(tmp, *out_len - chain_len_out, (void *)(&(cert_entry.data_length)), sizeof(uint32_t)) != EOK ||
            memcpy_s(tmp + sizeof(uint32_t), *out_len - chain_len_out - sizeof(uint32_t), cert_entry.data_addr,
                cert_entry.data_length) != EOK) {
            tloge("memcpy_s failed\n");
            goto free_entry;
        }
        tmp += next_entry_len;
        chain_len_out += next_entry_len;
        free_blob(&cert_entry);
    }
    if (memcpy_s(chain, sizeof(uint32_t), &i, sizeof(i)) != EOK) {
        tloge("set chain count failed\n");
        goto free_entry;
    }
    *out_len = chain_len_out;
    return 0;
free_entry:
    free_blob(&cert_entry);
    return AT_CHAIN_OUT_ERR;
}

static int32_t build_rot_field_sub(const km_root_of_trust_t *rot, const uint8_t *rot_buf, uint32_t *rot_len,
    uint8_t *end, uint32_t *end_len)
{
    uint8_t lock_byte = (rot->device_locked == LSTATE_LOCKED) ? 0xFF : 0x00;
    insert_tlv(KM_ASN1_BOOLEAN, 1, &lock_byte, &end, end_len);
    uint8_t int_bytes[KM_NUM_FOUR] = { 0 };
    convert32l((uint32_t)rot->verified_boot_state, int_bytes);
    insert_tlv(KM_ASN1_ENUMERATED, sizeof(enum lock_color), int_bytes, &end, end_len);
    *rot_len = (uint32_t)(end - rot_buf);
    tlogd("build RootOfTrust field success, rot_len=%u\n", *rot_len);
    return 0;
}

int32_t build_rot_field(uint8_t *rot_buf, uint32_t *rot_len)
{
    tlogd("build RootOfTrust field begin\n");
    /* tlv type-value-length total size */
    bool condition = ((rot_buf == NULL) || (rot_len == NULL) || *rot_len < (SHA256_LENGTH + KM_NUM_EIGHT));
    if (condition) {
        tloge("invalid input parameters\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    km_root_of_trust_t rot;
    uint8_t *end     = rot_buf;
    uint32_t end_len = *rot_len;

    rot.device_locked       = get_verify_boot_lock_state();
    rot.verified_boot_state = get_verify_boot_color();
    condition = ((rot.verified_boot_state == LOCK_GREEN) || (rot.verified_boot_state == LOCK_YELLOW));
    if (condition) {
        /* get verifybootkey */
        get_verify_boot_key(&rot.verified_boot_key);
        uint8_t hash_buf[SHA256_LENGTH] = { 0 };
        /* adapt for mtk */
#ifdef MTK_BOOT_INFO
        errno_t ret = memcpy_s(hash_buf, SHA256_LENGTH, rot.verified_boot_key.data_addr, PUBLIC_KEY_HASH_SIZE);
        if (ret != EOK) {
            tloge("memcpy_s failed, ret=%d\n", ret);
            return (int)ret;
        }
#else
        /* hash verifybootkey */
        uint8_t *result = SHA256(rot.verified_boot_key.data_addr, rot.verified_boot_key.data_length, hash_buf);
        if (result == NULL) {
            tloge("verify boot key do hash256 failed");
            return TEE_ERROR_GENERIC;
        }
#endif
        /* do i2d convert */
        insert_tlv(KM_ASN1_OCTSTR, SHA256_LENGTH, hash_buf, &end, &end_len);
    } else {
        insert_tlv(KM_ASN1_OCTSTR, 0, NULL, &end, &end_len);
    }
    return build_rot_field_sub(&rot, rot_buf, rot_len, end, &end_len);
}


static void get_time_stamp_tee(uint8_t *time_stamp, const TEE_Date_Time *tm)
{
    bool check_fail = ((time_stamp == NULL) || (tm == NULL));
    if (check_fail) {
        tloge("time_stamp or tm is null!\n");
        return; /* no need return error code */
    }
    uint32_t year = tm->year - ((tm->year / KM_NUM_ONE_HUNDRED) * KM_NUM_ONE_HUNDRED);

    time_stamp[0] = (year / KM_NUM_TEN) + '0';
    time_stamp[1] = (year % KM_NUM_TEN) + '0';
    time_stamp[KM_NUM_TWO] = (tm->month / KM_NUM_TEN) + '0';
    time_stamp[KM_NUM_THREE] = (tm->month % KM_NUM_TEN) + '0';
    time_stamp[KM_NUM_FOUR] = (tm->day / KM_NUM_TEN) + '0';
    time_stamp[KM_NUM_FIVE] = (tm->day % KM_NUM_TEN) + '0';
    time_stamp[KM_NUM_SIXE] = (tm->hour / KM_NUM_TEN) + '0';
    time_stamp[KM_NUM_SEVEN] = (tm->hour % KM_NUM_TEN) + '0';
    time_stamp[KM_NUM_EIGHT] = (tm->min / KM_NUM_TEN) + '0';
    time_stamp[KM_NUM_NINE] = (tm->min % KM_NUM_TEN) + '0';
    time_stamp[KM_NUM_TEN] = (tm->seconds / KM_NUM_TEN) + '0';
    time_stamp[KM_NUM_ELEVEN] = (tm->seconds % KM_NUM_TEN) + '0';
    time_stamp[KM_NUM_TWELVE] = 'Z';
}

static void get_valid_time_stamp(uint8_t *time_stamp, uint64_t time_in_ms)
{
    /* format in s */
    TEE_Date_Time tee_date_time = { 0 };

    uint64_t tmp_sec = (time_in_ms >> KM_NUM_TEN);
    if (UINT64_MAX / tmp_sec < KM_NUM_ONE_THOUSAND) {
        tloge("tmp_sec * 1000 is overflow\n");
        return;
    }

    tmp_sec = tmp_sec + ((KM_NUM_THREE * tmp_sec) >> KM_NUM_SEVEN) + ((KM_NUM_NINE * tmp_sec) >> KM_NUM_FOURTEEN);
    tmp_sec = tmp_sec + ((uint32_t)(time_in_ms - (tmp_sec * KM_NUM_ONE_THOUSAND)) / KM_NUM_ONE_THOUSAND);

    __gen_sys_date_time((uint32_t)tmp_sec, (tee_date_time_kernel *)&tee_date_time);
    tlogd("tee_date_time:%d%d%d %d:%d:%dZ\n", tee_date_time.year, tee_date_time.month, tee_date_time.day,
        tee_date_time.hour, tee_date_time.min, tee_date_time.seconds);

    get_time_stamp_tee(time_stamp, &tee_date_time);
}

static int32_t get_attest_validity_sub(validity_period_t *valid, const keymaster_key_param_set_t *authorizations,
    keymaster_blob_t *batch_cert, uint64_t *usage_expire_datetime)
{
    int32_t ret = get_key_param(KM_TAG_USAGE_EXPIRE_DATETIME, usage_expire_datetime, authorizations);
    if (ret == 0) {
        get_valid_time_stamp(valid->end, *usage_expire_datetime);
        return 0;
    }
    /* the expiration date of the batch attestation key certificate must be used */
    validity_period_t vd_batch;
    ret = get_validity_from_cert(&vd_batch, batch_cert->data_addr, batch_cert->data_length);
    if (ret != 0) {
        tloge("get validity form batch cert error: %d\n", ret);
        return -1;
    }
    errno_t memcpy_ret = memcpy_s(valid->end, sizeof(valid->end), vd_batch.end, sizeof(vd_batch.end));
    if (memcpy_ret != EOK) {
        tloge("memcpy_s failed\n");
        return -1;
    }
    return 0;
}

int32_t get_attest_validity(validity_period_t *valid, const keymaster_key_param_set_t *authorizations,
    keymaster_blob_t *batch_cert)
{
    uint64_t active_datetime = 0;
    uint64_t usage_expire_datetime = UINT32_MAX;
    int32_t ret;

    /* default set to max value in ms */
    usage_expire_datetime = usage_expire_datetime * 1000UL;

    /* 1. validity's notBefore set */
    /* Using KM_TAG_ACTIVE_DATETIME as default */
    ret = get_key_param(KM_TAG_ACTIVE_DATETIME, &active_datetime, authorizations);
    if (ret != 0) {
        tlogd("KM_TAG_ACTIVE_DATETIME not found\n");
        /* else value of KM_TAG_CREATION_DATETIME must be used. */
        ret = get_key_param(KM_TAG_CREATION_DATETIME, &active_datetime, authorizations);
        if (ret != 0) {
            tloge("KM_TAG_CREATION_DATETIME not found\n");
            return -1;
        }
    }
    get_valid_time_stamp(valid->start, active_datetime);
    /* 2. validity's notAfter set */
    return get_attest_validity_sub(valid, authorizations, batch_cert, &usage_expire_datetime);
}

static int i2d_auth_list_chk_helper(const struct km_auth_list *auth_list, const uint8_t *out_buf,
    const uint32_t *out_len)
{
    bool check_fail = ((auth_list == NULL) || (out_buf == NULL) || (out_len == NULL));
    if (check_fail) {
        tloge("input params is null\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    /* out_len is guaranteed by the caller, enough buf for variable-length use */
    if (*out_len == 0) {
        tloge("out_len is invalid\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    return TEE_SUCCESS;
}
static void check_algorithm(const struct km_auth_list *auth_list, uint8_t *int_bytes, uint8_t **end, uint32_t *end_len)
{
    if (auth_list->algorithm.tag_set) {
        convert32l(auth_list->algorithm.enumerated, int_bytes);
        insert_explicit_tlv(KM_ASN1_INT, LENGTH_32L, int_bytes, end, end_len,
                            keymaster_tag_mask_type(KM_TAG_ALGORITHM));
    }
}

static void check_key_size(const struct km_auth_list *auth_list, uint8_t *int_bytes, uint8_t **end, uint32_t *end_len)
{
    if (auth_list->key_size.tag_set) {
        convert32l(auth_list->key_size.integer, int_bytes);
        insert_explicit_tlv(KM_ASN1_INT, LENGTH_32L, int_bytes, end, end_len, keymaster_tag_mask_type(KM_TAG_KEY_SIZE));
    }
}

#define auth_list_int_element_to_tlv_buf(element_name, ele_value, tag) do { \
    if (auth_list->element_name.tag_set) { \
        convert32l(auth_list->element_name.ele_value, int_bytes); \
        insert_explicit_tlv(KM_ASN1_INT, LENGTH_32L, int_bytes, end, end_len, keymaster_tag_mask_type(tag)); \
    } \
} while (0)

#define auth_list_int64_element_to_tlv_buf(element_name, ele_value, tag) do { \
    if (auth_list->element_name.tag_set) { \
        convert64l(auth_list->element_name.ele_value, long_bytes); \
        insert_explicit_tlv(KM_ASN1_INT, LENGTH_64L, long_bytes, end, end_len, keymaster_tag_mask_type(tag)); \
    } \
} while (0)

#define auth_list_null_element_to_tlv_buf(element_name, tag) do { \
    if (auth_list->element_name.tag_set) \
        insert_explicit_tlv(KM_ASN1_NULL, 0, NULL, end, end_len, keymaster_tag_mask_type(tag)); \
} while (0)

#define auth_list_buff_element_to_tlv_buf(element_name, tag) do { \
    if (auth_list->element_name.tag_set) \
        insert_explicit_tlv(KM_ASN1_OCTSTR, auth_list->element_name.blob.data_length, \
            auth_list->element_name.blob.data_addr, end, end_len, keymaster_tag_mask_type(tag)); \
} while (0)

static void i2d_auth_list_to_buffer(struct km_auth_list *auth_list, uint8_t **end, uint32_t *end_len)
{
    uint8_t int_bytes[LENGTH_32L] = { 0 };
    uint8_t long_bytes[LENGTH_64L] = { 0 };
    auth_list_int_element_to_tlv_buf(ec_curve, enumerated, KM_TAG_EC_CURVE);
    auth_list_int64_element_to_tlv_buf(rsa_public_exponent, long_integer, KM_TAG_RSA_PUBLIC_EXPONENT);
    auth_list_int64_element_to_tlv_buf(active_date_time, date_time, KM_TAG_ACTIVE_DATETIME);
    auth_list_int64_element_to_tlv_buf(origination_expire_date_time, date_time, KM_TAG_ORIGINATION_EXPIRE_DATETIME);
    auth_list_int64_element_to_tlv_buf(usage_expire_date_time, date_time, KM_TAG_USAGE_EXPIRE_DATETIME);
    auth_list_null_element_to_tlv_buf(no_auth_required, KM_TAG_NO_AUTH_REQUIRED);
    auth_list_int_element_to_tlv_buf(user_auth_type, enumerated, KM_TAG_USER_AUTH_TYPE);
    auth_list_int_element_to_tlv_buf(auth_timeout, enumerated, KM_TAG_AUTH_TIMEOUT);
    auth_list_null_element_to_tlv_buf(allow_while_on_body, KM_TAG_ALLOW_WHILE_ON_BODY);
    auth_list_null_element_to_tlv_buf(all_applications, KM_TAG_ALL_APPLICATIONS);
    auth_list_buff_element_to_tlv_buf(application_id, KM_TAG_APPLICATION_ID);
    auth_list_int64_element_to_tlv_buf(creation_date_time, date_time, KM_TAG_CREATION_DATETIME);
    auth_list_int_element_to_tlv_buf(origin, enumerated, KM_TAG_ORIGIN);
    auth_list_null_element_to_tlv_buf(rollback_resistant, KM_TAG_ROLLBACK_RESISTANT);
    auth_list_null_element_to_tlv_buf(rollback_resistance, KM_TAG_ROLLBACK_RESISTANCE);

    if (auth_list->root_of_trust.tag_set)
        insert_explicit_tlv(KM_ASN1_SEQ, auth_list->root_of_trust.blob.data_length,
            auth_list->root_of_trust.blob.data_addr, end, end_len, keymaster_tag_mask_type(KM_TAG_ROOT_OF_TRUST));
    auth_list_int_element_to_tlv_buf(os_version, integer, KM_TAG_OS_VERSION);
    auth_list_int_element_to_tlv_buf(patch_level, integer, KM_TAG_OS_PATCHLEVEL);
    auth_list_buff_element_to_tlv_buf(attestation_app_id, KM_TAG_ATTESTATION_APPLICATION_ID);
    auth_list_buff_element_to_tlv_buf(attestation_id_brand, KM_TAG_ATTESTATION_ID_BRAND);
    auth_list_buff_element_to_tlv_buf(attestation_id_device, KM_TAG_ATTESTATION_ID_DEVICE);
    auth_list_buff_element_to_tlv_buf(attestation_id_product, KM_TAG_ATTESTATION_ID_PRODUCT);
    auth_list_buff_element_to_tlv_buf(attestation_id_serial, KM_TAG_ATTESTATION_ID_SERIAL);
    while (auth_list->attestation_id_imei.count > 0) {
        insert_explicit_tlv(KM_ASN1_OCTSTR,
                            auth_list->attestation_id_imei.blob[auth_list->attestation_id_imei.count].data_length,
                            auth_list->attestation_id_imei.blob[auth_list->attestation_id_imei.count].data_addr, end,
                            end_len, keymaster_tag_mask_type(KM_TAG_ATTESTATION_ID_IMEI));
        auth_list->attestation_id_imei.count--;
    }
    auth_list_buff_element_to_tlv_buf(attestation_id_manufacturer, KM_TAG_ATTESTATION_ID_MANUFACTURER);
    auth_list_buff_element_to_tlv_buf(attestation_id_meid, KM_TAG_ATTESTATION_ID_MEID);
    auth_list_buff_element_to_tlv_buf(attestation_id_model, KM_TAG_ATTESTATION_ID_MODEL);
}

static int32_t i2d_auth_list(struct km_auth_list *auth_list, uint8_t *out_buf, uint32_t *out_len)
{
    tlogd("i2d_auth_list begin\n");
    if (i2d_auth_list_chk_helper(auth_list, out_buf, out_len) != TEE_SUCCESS) {
        tloge("the paramter of i2d_auth_list_chk_helper is bad\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    uint8_t int_bytes[LENGTH_32L] = { 0 };
    uint8_t *end = out_buf;
    uint32_t end_len = *out_len;

    /* purpose: SET of INTERGER */
    uint8_t tmp_buf_set[KM_REP_BUF_LEN] = { 0 };
    uint8_t *end_set = tmp_buf_set;
    uint32_t end_set_len = KM_REP_BUF_LEN;
    while (auth_list->purpose.count > 0) {
        convert32l(auth_list->purpose.enumerated[auth_list->purpose.count], int_bytes);
        insert_tlv(KM_ASN1_INT, LENGTH_32L, int_bytes, &end_set, &end_set_len);
        auth_list->purpose.count--;
        if (auth_list->purpose.count == 0)
            insert_explicit_tlv(KM_ASN1_SET, (uint32_t)(end_set - tmp_buf_set), tmp_buf_set, &end, &end_len,
                                keymaster_tag_mask_type(KM_TAG_PURPOSE));
    }

    /* algorithm: INTERGER */
    check_algorithm(auth_list, int_bytes, &end, &end_len);

    /* key_size: INTERGER */
    check_key_size(auth_list, int_bytes, &end, &end_len);

    /* digest: SET of INTERGER */
    end_set = tmp_buf_set;
    end_set_len = KM_REP_BUF_LEN;
    while (auth_list->digest.count > 0) {
        convert32l(auth_list->digest.enumerated[auth_list->digest.count], int_bytes);
        insert_tlv(KM_ASN1_INT, LENGTH_32L, int_bytes, &end_set, &end_set_len);
        auth_list->digest.count--;
        if (auth_list->digest.count == 0)
            insert_explicit_tlv(KM_ASN1_SET, (uint32_t)(end_set - tmp_buf_set), tmp_buf_set, &end, &end_len,
                                keymaster_tag_mask_type(KM_TAG_DIGEST));
    }

    /* padding: SET of INTERGER */
    end_set = tmp_buf_set;
    end_set_len = KM_REP_BUF_LEN;
    while (auth_list->padding.count > 0) {
        convert32l(auth_list->padding.enumerated[auth_list->padding.count], int_bytes);
        insert_tlv(KM_ASN1_INT, LENGTH_32L, int_bytes, &end_set, &end_set_len);
        auth_list->padding.count--;
        if (auth_list->padding.count == 0)
            insert_explicit_tlv(KM_ASN1_SET, (uint32_t)(end_set - tmp_buf_set), tmp_buf_set, &end, &end_len,
                                keymaster_tag_mask_type(KM_TAG_PADDING));
    }
    i2d_auth_list_to_buffer(auth_list, &end, &end_len);
    *out_len = (uint32_t)(end - out_buf);
    tlogd("i2d_auth_list success, *out_len=%u\n", *out_len);
    return 0;
}

static int build_auth_list_chk_helper(const keymaster_key_param_t *params, uint32_t auth_list_type,
    const keymaster_key_param_set_t *attest_params, const uint8_t *auth_list_buf,
    const uint32_t *auth_list_len)
{
    bool check_fail = ((params == NULL) || (attest_params == NULL) || (auth_list_buf == NULL) ||
        (auth_list_len == NULL));
    if (check_fail) {
        tloge("input params is null\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (*auth_list_len == 0) {
        tloge("params_len or auth_list_len invalid\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    check_fail = ((auth_list_type != HW_ENFORCED) && (auth_list_type != SW_ENFORCED));
    if (check_fail) {
        tloge("auth_list_type is invalid:%u\n", auth_list_type);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    return TEE_SUCCESS;
}

static void do_km_tag_algorithm(struct km_auth_list *auth_list, const keymaster_key_param_t *params, uint32_t i)
{
    auth_list->algorithm.tag_set = 1;
    auth_list->algorithm.enumerated = params[i].enumerated;
    tlogd("auth_list.algorithm=%u\n", auth_list->algorithm.enumerated);
}

static void do_km_tag_ec_curve(struct km_auth_list *auth_list, const keymaster_key_param_t *params, uint32_t i)
{
    auth_list->ec_curve.tag_set = 1;
    auth_list->ec_curve.enumerated = params[i].enumerated;
    tlogd("auth_list.ec_curve=%u\n", auth_list->ec_curve.enumerated);
}

static void do_km_tag_user_auth_type(struct km_auth_list *auth_list, const keymaster_key_param_t *params, uint32_t i)
{
    auth_list->user_auth_type.tag_set = 1;
    auth_list->user_auth_type.enumerated = params[i].enumerated;
    tlogd("auth_list.user_auth_type=%u\n", auth_list->user_auth_type.enumerated);
}

static void do_km_tag_origin(struct km_auth_list *auth_list, const keymaster_key_param_t *params, uint32_t i)
{
    auth_list->origin.tag_set = 1;
    auth_list->origin.enumerated = params[i].enumerated;
    tlogd("auth_list.origin=%u\n", auth_list->origin.enumerated);
}

static void do_km_tag_purpose(struct km_auth_list *auth_list, const keymaster_key_param_t *params, uint32_t i)
{
    auth_list->purpose.count++;
    auth_list->purpose.enumerated[auth_list->purpose.count] = params[i].enumerated;
    tlogd("auth_list.purpose count=%u, value=%u\n", auth_list->purpose.count, params[i].enumerated);
}

static void do_km_tag_padding(struct km_auth_list *auth_list, const keymaster_key_param_t *params, uint32_t i)
{
    auth_list->padding.count++;
    auth_list->padding.enumerated[auth_list->padding.count] = params[i].enumerated;
    tlogd("auth_list.padding count=%u, value=%u\n", auth_list->padding.count, params[i].enumerated);
}

static void do_km_tag_digest(struct km_auth_list *auth_list, const keymaster_key_param_t *params, uint32_t i)
{
    auth_list->digest.count++;
    auth_list->digest.enumerated[auth_list->digest.count] = params[i].enumerated;
    tlogd("auth_list.digest count=%u, value=%u\n", auth_list->digest.count, params[i].enumerated);
}

static void do_km_tag_key_size(struct km_auth_list *auth_list, const keymaster_key_param_t *params, uint32_t i)
{
    auth_list->key_size.tag_set = 1;
    auth_list->key_size.integer = params[i].integer;
    tlogd("auth_list.key_size=%u\n", auth_list->key_size.integer);
}

static void do_km_tag_auth_timeout(struct km_auth_list *auth_list, const keymaster_key_param_t *params, uint32_t i)
{
    auth_list->auth_timeout.tag_set = 1;
    auth_list->auth_timeout.integer = params[i].integer;
    tlogd("auth_list.auth_timeout=%u\n", auth_list->auth_timeout.integer);
}

static void do_km_tag_os_version(struct km_auth_list *auth_list, const keymaster_key_param_t *params, uint32_t i)
{
    auth_list->os_version.tag_set = 1;
    auth_list->os_version.integer = params[i].integer;
    tlogd("auth_list.os_version=%u\n", auth_list->os_version.integer);
}

static void do_km_tag_os_patchlevel(struct km_auth_list *auth_list, const keymaster_key_param_t *params, uint32_t i)
{
    auth_list->patch_level.tag_set = 1;
    auth_list->patch_level.integer = params[i].integer;
    tlogd("auth_list.patch_level=%u\n", auth_list->patch_level.integer);
}

static void do_km_tag_rsa_public_exponent(struct km_auth_list *auth_list, const keymaster_key_param_t *params,
    uint32_t i)
{
    auth_list->rsa_public_exponent.tag_set = 1;
    auth_list->rsa_public_exponent.long_integer = params[i].long_integer;
    tlogd("auth_list.rsa_public_exponent\n");
}

static void do_km_tag_active_datetime(struct km_auth_list *auth_list, const keymaster_key_param_t *params, uint32_t i)
{
    auth_list->active_date_time.tag_set = 1;
    auth_list->active_date_time.date_time = params[i].date_time;
    tlogd("auth_list.active_date_time\n");
}

static void do_km_tag_origination_expire_datetime(struct km_auth_list *auth_list, const keymaster_key_param_t *params,
                                                  uint32_t i)
{
    auth_list->origination_expire_date_time.tag_set = 1;
    auth_list->origination_expire_date_time.date_time = params[i].date_time;
    tlogd("auth_list.origination_expire_date_time\n");
}

static void do_km_tag_usage_expire_datetime(struct km_auth_list *auth_list, const keymaster_key_param_t *params,
    uint32_t i)
{
    auth_list->usage_expire_date_time.tag_set = 1;
    auth_list->usage_expire_date_time.date_time = params[i].date_time;
    tlogd("auth_list.usage_expire_date_time\n");
}

static void do_km_tag_creation_datetime(struct km_auth_list *auth_list, const keymaster_key_param_t *params, uint32_t i)
{
    auth_list->creation_date_time.tag_set = 1;
    auth_list->creation_date_time.date_time = params[i].date_time;
    tlogd("auth_list.creation_date_time\n");
}

static void do_km_tag_no_auth_required(struct km_auth_list *auth_list, const keymaster_key_param_t *params, uint32_t i)
{
    auth_list->no_auth_required.tag_set = 1;
    auth_list->no_auth_required.boolean = params[i].boolean;
    tlogd("auth_list.no_auth_required=%d\n", auth_list->no_auth_required.boolean);
}

static void do_km_tag_all_applications(struct km_auth_list *auth_list, const keymaster_key_param_t *params, uint32_t i)
{
    auth_list->all_applications.tag_set = 1;
    auth_list->all_applications.boolean = params[i].boolean;
    tlogd("auth_list.all_applications=%d\n", auth_list->all_applications.boolean);
}

static void do_km_tag_rollback_resistant(struct km_auth_list *auth_list, const keymaster_key_param_t *params,
    uint32_t i)
{
    auth_list->rollback_resistant.tag_set = 1;
    auth_list->rollback_resistant.boolean = params[i].boolean;
    tlogd("auth_list.rollback_resistant=%d\n", auth_list->rollback_resistant.boolean);
}

static void do_km_tag_rollback_resistance(struct km_auth_list *auth_list, const keymaster_key_param_t *params,
    uint32_t i)
{
    auth_list->rollback_resistance.tag_set = 1;
    auth_list->rollback_resistance.boolean = params[i].boolean;
    tlogd("auth_list.rollback_resistance=%d\n", auth_list->rollback_resistance.boolean);
}

static void do_km_tag_allow_while_on_body(struct km_auth_list *auth_list, const keymaster_key_param_t *params,
    uint32_t i)
{
    auth_list->allow_while_on_body.tag_set = 1;
    auth_list->allow_while_on_body.boolean = params[i].boolean;
    tlogd("auth_list.allow_while_on_body=%d\n", auth_list->allow_while_on_body.boolean);
}
static bool build_auth_is_ignored_tag(keymaster_tag_t tag)
{
    bool check = (tag == KM_TAG_INVALID || tag == KM_TAG_ASSOCIATED_DATA ||
                  tag == KM_TAG_NONCE || tag == KM_TAG_AUTH_TOKEN ||
                  tag == KM_TAG_MAC_LENGTH || tag == KM_TAG_ALL_USERS ||
                  tag == KM_TAG_USER_ID || tag == KM_TAG_USER_SECURE_ID ||
                  tag == KM_TAG_EXPORTABLE || tag == KM_TAG_RESET_SINCE_ID_ROTATION ||
                  tag == KM_TAG_ATTESTATION_CHALLENGE || tag == KM_TAG_BLOCK_MODE ||
                  tag == KM_TAG_CALLER_NONCE || tag == KM_TAG_MIN_MAC_LENGTH ||
                  tag == KM_TAG_ECIES_SINGLE_HASH_MODE || tag == KM_TAG_INCLUDE_UNIQUE_ID ||
                  tag == KM_TAG_BLOB_USAGE_REQUIREMENTS || tag == KM_TAG_BOOTLOADER_ONLY ||
                  tag == KM_TAG_HARDWARE_TYPE || tag == KM_TAG_TRUSTED_USER_PRESENCE_REQUIRED ||
                  tag == KM_TAG_TRUSTED_CONFIRMATION_REQUIRED || tag == KM_TAG_UNLOCKED_DEVICE_REQUIRED ||
                  tag == KM_TAG_VENDOR_PATCHLEVEL || tag == KM_TAT_BOOT_PATCHLEVEL ||
                  tag == KM_TAG_CONFIRMATION_TOKEN || tag == KM_TAG_MIN_SECONDS_BETWEEN_OPS ||
                  tag == KM_TAG_MAX_USES_PER_BOOT || tag == KM_TAG_APPLICATION_DATA ||
                  tag == KM_TAG_UNIQUE_ID || tag == KM_TAG_ROOT_OF_TRUST ||
                  tag == KM_TAG_KDF || tag == KM_TAG_APPLICATION_ID);
    return check;
}

typedef void (*auth_set_tag_value_fun)(struct km_auth_list *auth_list,
    const keymaster_key_param_t *params, uint32_t i);
struct auth_tag_set_fun {
    keymaster_tag_t tag;
    auth_set_tag_value_fun set_fun;
};

static void set_auth_list_tag_value(struct km_auth_list *auth_list,
    const keymaster_key_param_t *params, uint32_t params_len)
{
    struct auth_tag_set_fun tag2fun[] = {
        { KM_TAG_ALGORITHM, do_km_tag_algorithm },
        { KM_TAG_EC_CURVE, do_km_tag_ec_curve },
        { KM_TAG_USER_AUTH_TYPE, do_km_tag_user_auth_type },
        { KM_TAG_ORIGIN, do_km_tag_origin },
        { KM_TAG_PURPOSE, do_km_tag_purpose },
        { KM_TAG_PADDING, do_km_tag_padding },
        { KM_TAG_DIGEST, do_km_tag_digest },
        { KM_TAG_KEY_SIZE, do_km_tag_key_size },
        { KM_TAG_AUTH_TIMEOUT, do_km_tag_auth_timeout },
        { KM_TAG_OS_VERSION, do_km_tag_os_version },
        { KM_TAG_OS_PATCHLEVEL, do_km_tag_os_patchlevel },
        { KM_TAG_RSA_PUBLIC_EXPONENT, do_km_tag_rsa_public_exponent },
        { KM_TAG_ACTIVE_DATETIME, do_km_tag_active_datetime },
        { KM_TAG_ORIGINATION_EXPIRE_DATETIME, do_km_tag_origination_expire_datetime },
        { KM_TAG_USAGE_EXPIRE_DATETIME, do_km_tag_usage_expire_datetime },
        { KM_TAG_CREATION_DATETIME, do_km_tag_creation_datetime },
        { KM_TAG_NO_AUTH_REQUIRED, do_km_tag_no_auth_required },
        { KM_TAG_ALL_APPLICATIONS, do_km_tag_all_applications },
        { KM_TAG_ROLLBACK_RESISTANT, do_km_tag_rollback_resistant },
        { KM_TAG_ROLLBACK_RESISTANCE, do_km_tag_rollback_resistance },
        { KM_TAG_ALLOW_WHILE_ON_BODY, do_km_tag_allow_while_on_body },
    };
    uint32_t i;
    uint32_t j;
    for (i = 0; i < params_len; i++) {
        if (build_auth_is_ignored_tag(params[i].tag)) {
            continue;
        }
        for (j = 0; j < sizeof(tag2fun) / sizeof(tag2fun[0]); j++)
            if (params[i].tag == tag2fun[j].tag)
                tag2fun[j].set_fun(auth_list, params, i);
    }
}

static void auth_list_set_application_id(uint32_t auth_list_type, struct km_auth_list *auth_list,
    const keymaster_key_param_set_t *attest_params)
{
    if (auth_list_type == SW_ENFORCED) {
        if (get_key_param(KM_TAG_APPLICATION_ID, &auth_list->application_id.blob, attest_params)) {
            auth_list->application_id.tag_set = 0;
        } else {
            auth_list->application_id.tag_set = 1;
        }
        if (get_key_param(KM_TAG_ATTESTATION_APPLICATION_ID, &auth_list->attestation_app_id.blob, attest_params)) {
            auth_list->attestation_app_id.tag_set = 0;
        } else {
            auth_list->attestation_app_id.tag_set = 1;
        }
    }
}

static void auth_list_set_enforce(uint32_t auth_list_type, struct km_auth_list *auth_list)
{
    if (auth_list_type == HW_ENFORCED) {
        auth_list->os_version.tag_set = 1;
        auth_list->patch_level.tag_set = 1;
        auth_list->os_version.integer = get_verify_boot_os_version();
        auth_list->patch_level.integer = get_verify_boot_patch_level();
    } else {
        auth_list->os_version.tag_set = 0;
        auth_list->patch_level.tag_set = 0;
    }
}


static TEE_Result insert_identifiers_in_attestation(struct km_auth_list *auth_list,
    const keymaster_key_param_set_t *attest_params)
{
    if ((auth_list == NULL) || (attest_params == NULL)) {
        tloge("auth_list or attest_params is null\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    keymaster_key_param_t *params_hw = (keymaster_key_param_t *)((uint8_t *)attest_params +
                                        sizeof(attest_params->length));
    if (params_hw == NULL) {
        tloge("params_hw is null\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    uint32_t hw_enforced_len = attest_params->length;
    tlogd("hw_enforced_len is %u\n", hw_enforced_len);

    keymaster_key_param_t *params_sw = (keymaster_key_param_t *)((uint8_t *)params_hw +
        (hw_enforced_len * sizeof(keymaster_key_param_t)) + sizeof(uint32_t));
    if (params_sw == NULL) {
        tloge("params_sw is null\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    uint32_t sw_enforced_len = *(uint32_t *)((uint8_t *)params_hw + (hw_enforced_len * sizeof(keymaster_key_param_t)));

    uint8_t *extend_bufer_in = (uint8_t *)((uint8_t *)params_sw + (sw_enforced_len * sizeof(keymaster_key_param_t)));

    build_authlist(auth_list, params_hw, hw_enforced_len, extend_bufer_in);
    build_authlist(auth_list, params_sw, sw_enforced_len, extend_bufer_in);

    return TEE_SUCCESS;
}

static int32_t build_auth_list(uint32_t auth_list_type, const keymaster_key_param_t *params, uint32_t params_len,
    const keymaster_key_param_set_t *attest_params, uint8_t *auth_list_buf, uint32_t *auth_list_len)
{
    int32_t ret = build_auth_list_chk_helper(params, auth_list_type, attest_params, auth_list_buf, auth_list_len);
    if (ret != TEE_SUCCESS)
        return TEE_ERROR_BAD_PARAMETERS;
    /* auth_list_len is guaranteed by the caller, enough buf for variable-length use */
    struct km_auth_list auth_list;
    errno_t rc = memset_s(&auth_list, sizeof(struct km_auth_list), 0, sizeof(struct km_auth_list));
    if (rc != EOK) {
        tloge("[error]memset_s failed, rc=%d\n", rc);
        return rc;
    }
    /* set auth list value */
    set_auth_list_tag_value(&auth_list, params, params_len);
    /* add id identifiers for keymaster3 */
    if ((auth_list_type == HW_ENFORCED) && insert_identifiers_in_attestation(&auth_list, attest_params)) {
        tloge("insert_identifiers_in_attestation failed\n");
        return KM_ERROR_CANNOT_ATTEST_IDS;
    }
    /* set application_id from attest_params */
    auth_list_set_application_id(auth_list_type, &auth_list, attest_params);
    /* rootOfTrust field format */
    uint8_t rot_field[ATTEST_ROT_BUF_LEN] = { 0 };
    uint32_t rot_field_len = ATTEST_ROT_BUF_LEN;
    if (auth_list_type == HW_ENFORCED) {
        ret = build_rot_field(rot_field, &rot_field_len);
        if (ret != 0) {
            tloge("RootOfTrust field build error:ret=%d\n", ret);
            return ret;
        }
        auth_list.root_of_trust.tag_set = 1;
        auth_list.root_of_trust.blob.data_addr = rot_field;
        auth_list.root_of_trust.blob.data_length = rot_field_len;
    }
    /* set for tee enforced */
    auth_list_set_enforce(auth_list_type, &auth_list);

    ret = i2d_auth_list(&auth_list, auth_list_buf, auth_list_len);
    if (ret != 0) {
        tloge("i2d_auth_list error:%d\n", ret);
        return ret;
    }
    tlogd("build_auth_list success, auth_list_len=%u\n", *auth_list_len);
    return 0;
}

static int32_t build_unique_id_fill_data(uint32_t t, keymaster_blob_t application_id,
    bool reset_since_id_rotation, uint8_t *buf, uint32_t buf_len)
{
    uint8_t *p = buf;
    /* format T||C||R */
    errno_t rc = memcpy_s(p, buf_len, &t, sizeof(t));
    if (rc != EOK) {
        tloge("memcpy_s t failed, rc=%d\n", rc);
        return -1;
    }
    p += sizeof(t);
    if (application_id.data_addr != NULL && application_id.data_length != 0) {
        rc = memcpy_s(p, buf_len - sizeof(t), application_id.data_addr, application_id.data_length);
        if (rc != EOK) {
            tloge("memcpy_s application_id failed, rc=%d\n", rc);
            return -1;
        }
        p += application_id.data_length;
    }

    rc = memcpy_s(p, (buf_len - sizeof(t)) - application_id.data_length,
                  &reset_since_id_rotation, sizeof(reset_since_id_rotation));
    if (rc != EOK) {
        tloge("memcpy_s reset_since_id_rotation failed, rc=%d\n", rc);
        return -1;
    }
    return 0;
}
static int get_unique_data(const keymaster_key_param_set_t *param_set,
    const keymaster_key_param_set_t *attest_params, uint32_t *t,
    keymaster_blob_t *application_id, bool *reset_since_id_rotation)
{
    int ret;
    uint64_t creation_datetime;
    if (get_key_param(KM_TAG_CREATION_DATETIME, &creation_datetime, param_set) != 0) {
        tloge("Get creation datetime failed, Unique ID cannot be created without creation datetime\n");
        return KM_ERROR_INVALID_KEY_BLOB;
    }
    /* divide by 1000 */
    uint64_t tmp_sec = (creation_datetime >> KM_NUM_TEN);
    if (UINT64_MAX / tmp_sec < KM_NUM_ONE_THOUSAND) {
        tloge("tmp_sec * 1000 is overflow\n");
        return -1;
    }
    tmp_sec = tmp_sec + ((KM_NUM_THREE * tmp_sec) >> KM_NUM_SEVEN) + ((KM_NUM_NINE * tmp_sec) >> KM_NUM_FOURTEEN);
    tmp_sec = tmp_sec + ((uint32_t)(creation_datetime - (tmp_sec * KM_NUM_ONE_THOUSAND)) / KM_NUM_ONE_THOUSAND);
    *t = (uint32_t)tmp_sec / SECS_PER_30_DAYS; /* changes every 30 days */

    ret = get_key_param(KM_TAG_APPLICATION_ID, application_id, attest_params);
    if (ret) {
        tlogd("get_key_param of KM_TAG_APPLICATION_ID failed\n");
        application_id->data_addr = NULL;
        application_id->data_length = 0;
    }

    ret = get_key_param(KM_TAG_RESET_SINCE_ID_ROTATION, reset_since_id_rotation, attest_params);
    if (ret != 0) {
        tlogd("get_key_param of KM_TAG_RESET_SINCE_ID_ROTATION failed\n");
        *reset_since_id_rotation = 0;
    }
    return 0;
}

static int32_t get_buf_hmac(const uint8_t *buf, uint32_t buf_len, uint8_t *id_buf, uint32_t id_len)
{
    bool check_fail = (buf == NULL || id_buf == NULL);
    if (check_fail) {
        tloge("null pointer\n");
        return -1;
    }
    uint8_t hbk[AES_KEY_LEN] = { 0 };
    uint8_t hmac_result_buff[HMAC_SHA256_SIZE] = { 0 };
    /* derive key */
    if (TEE_EXT_ROOT_DeriveKey2(g_attest_key_salt, sizeof(g_attest_key_salt), hbk, AES_KEY_LEN)) {
        tloge("derive key fromm root key failed\n");
        return -1;
    }
    /* do HMAC unique id */
    if (proc_keymaster_hmac(buf, buf_len, hmac_result_buff, hbk) != 0) {
        tloge("unique id do hmac fail");
        return -1;
    }
    if (memcpy_s(id_buf, id_len, hmac_result_buff, id_len) != EOK) {
        tloge("memcpy hmac result failed\n");
        return -1;
    }
    return 0;
}

static int32_t build_unique_id_field(const keymaster_key_param_set_t *param_set,
    const keymaster_key_param_set_t *attest_params, uint8_t *id_buf, uint32_t id_len)
{
    bool check_fail = ((param_set == NULL) || (attest_params == NULL) || (id_buf == NULL) ||
        (id_len != UNIQUE_ID_BUF_LEN));
    if (check_fail) {
        tloge("input params is invalid\n");
        return (int32_t)TEE_ERROR_BAD_PARAMETERS;
    }
    uint32_t t = 0;
    keymaster_blob_t application_id = { NULL, 0 };
    bool reset_since_id_rotation = false;
    if (get_unique_data(param_set, attest_params, &t, &application_id, &reset_since_id_rotation) == -1) {
        tloge("get unique data failed.\n");
        return (int32_t)TEE_ERROR_GENERIC;
    }
    uint32_t buf_len = sizeof(uint32_t) + application_id.data_length + sizeof(bool);
    if ((UINT32_MAX - application_id.data_length) < (uint32_t)(sizeof(uint32_t) + sizeof(bool))) {
        tloge("invalide application id length!\n");
        return -1;
    }
    uint8_t *buf = (uint8_t *)TEE_Malloc(buf_len, TEE_MALLOC_FILL_ZERO);
    if (buf == NULL) {
        tloge("buf malloc failed.\n");
        return -1;
    }
    int32_t ret = build_unique_id_fill_data(t, application_id, reset_since_id_rotation, buf, buf_len);
    if (ret != 0) {
        tloge("build unique buff failed.\n");
        goto end;
    }
    ret = get_buf_hmac(buf, buf_len, id_buf, id_len);
    if (ret != 0)
        tloge("get buf hmac failed\n");
end:
    TEE_Free(buf);
    buf = NULL;
    return ret;
}

static int i2d_key_des(km_key_description_t *attest_key_des, uint8_t *out_buf, uint32_t *out_len)
{
    tlogd("i2d_key_des begin\n");
    bool check_fail = ((attest_key_des == NULL) || (out_buf == NULL) || (out_len == NULL));
    if (check_fail) {
        tloge("input params is invalid\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    /* out_len is guaranteed by the caller, enough buf for variable-length use */
    if (*out_len == 0) {
        tloge("out_len is invalid\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    uint8_t int_bytes[LENGTH_32L] = { 0 };
    uint8_t *tmp_buf = (uint8_t *)TEE_Malloc(*out_len, TEE_MALLOC_FILL_ZERO);
    if (tmp_buf == NULL) {
        tloge("tmp buf malloc failed\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    uint8_t *end = tmp_buf;
    uint8_t *ptr = out_buf;
    uint32_t end_len = *out_len;
    uint32_t ptr_len = *out_len;

    /* attestation_version: INTERGER */
    convert32l(attest_key_des->attestation_version, int_bytes);
    insert_tlv(KM_ASN1_INT, LENGTH_32L, int_bytes, &end, &end_len);

    /* attestation_security_level: INTERGER */
    convert32l((uint32_t)attest_key_des->attestation_security_level, int_bytes);
    insert_tlv(KM_ASN1_ENUMERATED, LENGTH_32L, int_bytes, &end, &end_len);
    /* keymaster_version: INTERGER */
    convert32l(attest_key_des->keymaster_version, int_bytes);
    insert_tlv(KM_ASN1_INT, LENGTH_32L, int_bytes, &end, &end_len);

    /* keymaster_security_level: INTERGER */
    convert32l((uint32_t)attest_key_des->keymaster_security_level, int_bytes);
    insert_tlv(KM_ASN1_ENUMERATED, LENGTH_32L, int_bytes, &end, &end_len);

    /* attestation_challenge: OCTET STRING */
    insert_tlv(KM_ASN1_OCTSTR, attest_key_des->attestation_challenge.data_length,
               attest_key_des->attestation_challenge.data_addr, &end, &end_len);

    /* unique_id: OCTET STRING */
    if (attest_key_des->unique_id.data_length > 0)
        insert_tlv(KM_ASN1_OCTSTR, attest_key_des->unique_id.data_length, attest_key_des->unique_id.data_addr, &end,
                   &end_len);
    else
        insert_tlv(KM_ASN1_OCTSTR, 0, NULL, &end, &end_len);

    /* sw_enforced: SEQUENCE */
    if (attest_key_des->sw_enforced.data_length > 0)
        insert_tlv(KM_ASN1_SEQ, attest_key_des->sw_enforced.data_length, attest_key_des->sw_enforced.data_addr, &end,
                   &end_len);

    /* hw_enforced: SEQUENCE */
    if (attest_key_des->hw_enforced.data_length > 0)
        insert_tlv(KM_ASN1_SEQ, attest_key_des->hw_enforced.data_length, attest_key_des->hw_enforced.data_addr, &end,
                   &end_len);

    insert_tlv(KM_ASN1_SEQ, (uint32_t)(end - tmp_buf), tmp_buf, &ptr, &ptr_len);
    *out_len = (uint32_t)(ptr - out_buf);
    TEE_Free(tmp_buf);

    tlogd("i2d_key_des success, out_len=%u\n", *out_len);
    return 0;
}
static int build_attest_exten_init_attest_key(const keymaster_key_param_set_t *attest_params,
    const keymaster_key_param_set_t *authorizations, km_key_description_t *attest_key_des)
{
    errno_t rc = memset_s(attest_key_des, sizeof(*attest_key_des), 0, sizeof(*attest_key_des));
    if (rc != EOK) {
        tloge("memset_s attest key failed\n");
        return rc;
    }
    attest_key_des->attestation_version = ATTEST_VERSION;
    attest_key_des->attestation_security_level = KM_SECURITY_LEVEL_TRUSTED_ENVIRONMENT;
    attest_key_des->keymaster_version = KEYMASTER_VERSION;
    attest_key_des->keymaster_security_level = KM_SECURITY_LEVEL_TRUSTED_ENVIRONMENT;

    int ret = get_key_param(KM_TAG_ATTESTATION_CHALLENGE, &attest_key_des->attestation_challenge, attest_params);
    if (ret != 0) {
        tloge("get_key_param of KM_TAG_ATTESTATION_CHALLENGE failed\n");
        return KM_ERROR_ATTESTATION_CHALLENGE_MISSING;
    } else {
        if (attest_key_des->attestation_challenge.data_length > ATTEST_CHALLENGE_LEN_MAX) {
            tloge("attestation challenge; only %d bytes allowed", ATTEST_CHALLENGE_LEN_MAX);
            return KM_ERROR_INVALID_INPUT_LENGTH;
        }
    }
    tlogd("attestation_challenge=%s== and len=%u\n", attest_key_des->attestation_challenge.data_addr,
          attest_key_des->attestation_challenge.data_length);

    /* unique id field format */
    bool unique_id_include = false;
    uint8_t unique_id_buf[UNIQUE_ID_BUF_LEN] = { 0 };
    uint32_t unique_id_buf_len = UNIQUE_ID_BUF_LEN;
    if (get_key_param(KM_TAG_INCLUDE_UNIQUE_ID, &unique_id_include, authorizations)) {
        tlogd("get_key_param of KM_TAG_INCLUDE_UNIQUE_ID failed\n");
        attest_key_des->unique_id.data_addr = NULL;
        attest_key_des->unique_id.data_length = 0;
    }
    tlogd("get unique_id_include=0x%x\n", unique_id_include);
    if (unique_id_include) {
        /* should set unique id */
        ret = build_unique_id_field(authorizations, attest_params, unique_id_buf, unique_id_buf_len);
        if (ret != 0) {
            tloge("build_unique_id error:ret=%d\n", ret);
            return ret;
        }
        attest_key_des->unique_id.data_addr = unique_id_buf;
        attest_key_des->unique_id.data_length = unique_id_buf_len;
    }
    return 0;
}

static int build_attest_set_hw_enforced(const keymaster_key_param_set_t *attest_params,
    const keymaster_key_param_set_t *authorizations, km_key_description_t *attest_key_des)
{
    int ret;
    keymaster_key_param_t *params_hw = (keymaster_key_param_t *)((uint8_t *)authorizations
                                       + sizeof(authorizations->length));
    uint32_t hw_enforced_len = *(uint32_t *)authorizations;
    uint32_t attestation_ids_len = attestationids_len(attest_params);
    uint32_t auth_list_hw_len = AUTH_LIST_BUF_LEN + attestation_ids_len;
    if (auth_list_hw_len < AUTH_LIST_BUF_LEN) {
        tloge("auth_list_hw_len is error %u", auth_list_hw_len);
        return -1;
    }
    uint8_t *auth_list_hw = (uint8_t *)TEE_Malloc(auth_list_hw_len, TEE_MALLOC_FILL_ZERO);
    if (auth_list_hw == NULL) {
        tloge("auth_list_hw buf malloc failed\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    ret = build_auth_list(HW_ENFORCED, params_hw, hw_enforced_len, attest_params, auth_list_hw, &auth_list_hw_len);
    if (ret != 0) {
        tloge("auth_list_hw field build error:ret=%d\n", ret);
        TEE_Free(auth_list_hw);
        return ret;
    }
    attest_key_des->hw_enforced.data_addr = auth_list_hw;
    attest_key_des->hw_enforced.data_length = auth_list_hw_len;
    return 0;
}

static int32_t build_attest_set_sw_enforced(const keymaster_key_param_set_t *attest_params,
    const keymaster_key_param_set_t *authorizations,  km_key_description_t *attest_key_des)
{
    keymaster_blob_t app_id = { NULL, 0 };
    keymaster_blob_t attestation_app_id = { NULL, 0 };

    int32_t ret = get_key_param(KM_TAG_APPLICATION_ID, &app_id, attest_params);
    if (ret != 0)
        tlogd("KM_TAG_APPLICATION_ID not found");

    ret = get_key_param(KM_TAG_ATTESTATION_APPLICATION_ID, &attestation_app_id, attest_params);
    if (ret != 0) {
        tloge("can not get KM_TAG_ATTESTATION_APPLICATION_ID\n");
        return KM_ERROR_ATTESTATION_APPLICATION_ID_MISSING;
    }

    if (((UINT32_MAX - app_id.data_length) < attestation_app_id.data_length) ||
        ((UINT32_MAX - app_id.data_length - attestation_app_id.data_length) < AUTH_LIST_BUF_LEN)) {
        tloge("Get auth_list_sw_len failed\n");
        return TEE_ERROR_OVERFLOW;
    }
    uint32_t auth_list_sw_len = AUTH_LIST_BUF_LEN + app_id.data_length + attestation_app_id.data_length;
    uint8_t *auth_list_sw = (uint8_t *)TEE_Malloc(auth_list_sw_len, TEE_MALLOC_FILL_ZERO);
    if (auth_list_sw == NULL) {
        tloge("auth_list_sw buf malloc failed\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    /* get sw_enforced params */
    keymaster_key_param_set_t *sw_enforced_offset = (keymaster_key_param_set_t *)((uint8_t *)authorizations
        + sizeof(authorizations->length) + (authorizations->length * sizeof(keymaster_key_param_t)));
    keymaster_key_param_t *params_sw = (keymaster_key_param_t *)((uint8_t *)sw_enforced_offset + sizeof(uint32_t));

    ret = build_auth_list(SW_ENFORCED, params_sw, sw_enforced_offset->length, attest_params, auth_list_sw,
        &auth_list_sw_len);
    if (ret != 0) {
        tloge("auth_list_sw field build error:ret=%d\n", ret);
        TEE_Free(auth_list_sw);
        return ret;
    }
    attest_key_des->sw_enforced.data_addr = auth_list_sw;
    attest_key_des->sw_enforced.data_length = auth_list_sw_len;
    return 0;
}
int32_t build_attestation_extension(const keymaster_key_param_set_t *attest_params,
    const keymaster_key_param_set_t *authorizations, uint8_t *attestation_ext, uint32_t *attestation_ext_len)
{
    bool check = ((attest_params == NULL) || (authorizations == NULL) || (attestation_ext == NULL) ||
        (attestation_ext_len == NULL) || (*attestation_ext_len == 0));
    if (check) {
        tloge("input params is null\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    /* out_len is guaranteed by the caller, enough buf for variable-length use */
    km_key_description_t attest_key_des;
    int32_t ret = build_attest_exten_init_attest_key(attest_params, authorizations, &attest_key_des);
    if (ret != 0) {
        tloge("init attest key fail");
        return ret;
    }
    /* get the hw_enforced params ,teeEnforced field format */
    ret = build_attest_set_hw_enforced(attest_params, authorizations, &attest_key_des);
    if (ret != 0) {
        tloge("attest key set hw enforce fail");
        return ret;
    }
    /* softwareEnforced field format */
    ret = build_attest_set_sw_enforced(attest_params, authorizations, &attest_key_des);
    if (ret != 0) {
        tloge("attest key set sw enforce fail");
        goto free_auth_list_hw;
    }
    ret = i2d_key_des(&attest_key_des, attestation_ext, attestation_ext_len);
    if (ret != 0)
        tloge("i2d_key_des error:%d\n", ret);

    TEE_Free(attest_key_des.sw_enforced.data_addr);
    attest_key_des.sw_enforced.data_addr = NULL;
free_auth_list_hw:
    TEE_Free(attest_key_des.hw_enforced.data_addr);
    attest_key_des.hw_enforced.data_addr = NULL;
    return ret;
}

static TEE_Result check_rsa_keymaterial(const keymaster_blob_t *keymaterial_blob)
{
    struct keymaterial_rsa_header *header = (struct keymaterial_rsa_header *)(keymaterial_blob->data_addr);
    if (header->magic != KM_MAGIC_NUM) {
        tloge("magic is 0x%x, soft_keymaterial is invalid\n", header->magic);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if ((keymaterial_blob->data_length - sizeof(*header)) < header->key_buff_len) {
        tloge("keymaterial_size is %u, keysize is %u, soft_keymaterial is invalid\n", keymaterial_blob->data_length,
              header->key_buff_len);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    return TEE_SUCCESS;
}

TEE_Result rsa_get_pub(const keymaster_blob_t *keymaterial_blob, rsa_pub_key_t *sw_pubkey_rsa, uint32_t version,
    const struct kb_crypto_factors *factors, uint32_t key_size)
{
    if ((keymaterial_blob == NULL || keymaterial_blob->data_addr == NULL || factors == NULL ||
        sw_pubkey_rsa == NULL)) {
        tloge("null pointer\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    struct keymaterial_rsa_header *header = (struct keymaterial_rsa_header *)(keymaterial_blob->data_addr);
    TEE_Result ret = check_rsa_keymaterial(keymaterial_blob);
    if (ret != TEE_SUCCESS)
        return ret;
    /* decrypt keymaterial */
    keymaster_blob_t encyrpted_key = { header->key, header->key_buff_len };
    keymaster_blob_t decrypt_key = { NULL, header->key_buff_len };
    decrypt_key.data_addr = (uint8_t *)TEE_Malloc(header->key_buff_len, TEE_MALLOC_FILL_ZERO);
    if (decrypt_key.data_addr == NULL) {
        tloge("buf malloc failed, size %u\n", header->key_buff_len);
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    TEE_ObjectHandle key_obj = TEE_HANDLE_NULL;
    struct keyblob_crypto_ctx ctx = {
        version, (uint32_t)TEE_MODE_DECRYPT,
#ifdef CFG_TEE_KEYMASTER_ENHANCED_KEY
        EXTRA_ITERATE,
#endif
        { header->iv, IV_LEN },
        *factors
    };
    ret = keyblob_crypto(&encyrpted_key, &decrypt_key, &ctx);
    if (ret != TEE_SUCCESS) {
        tloge("decrypt keymaterial failed, ret = 0x%x\n", ret);
        goto release;
    }

    ret = init_key_obj(KM_ALGORITHM_RSA, KM_DIGEST_NONE, key_size, &key_obj, &decrypt_key);
    if (ret != TEE_SUCCESS) {
        tloge("failed to allocate and init key object\n");
        goto release;
    }
    ret = rsa_get_pub_local(sw_pubkey_rsa, &key_obj);
release:
    erase_free_blob(&decrypt_key);
    TEE_FreeTransientObject(key_obj);
    key_obj = TEE_HANDLE_NULL;
    return ret;
}
