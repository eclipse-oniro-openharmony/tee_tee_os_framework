/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2015-2020. All rights reserved.
 * Description: keymaster key authorization process
 * Create: 2015-01-17
 */
#include "km_auth.h"
#include <dlist.h>
#include <sre_typedef.h>
#include "tee_mem_mgmt_api.h"
#include "tee_crypto_api.h"
#include "tee_log.h"
#include "keyblob.h"
#include "hw_auth_token.h"
#include "pthread.h"
#include "securec.h"
#ifdef BORINGSSL_ENABLE
#include "openssl/cipher.h"
#include <openssl/digest.h>
#else
#include "openssl/evp.h"
#endif
#include "km_types.h"
#include "km_tag_operation.h"
#include "km_keynode.h"
#include "km_env.h"
#include "km_crypto.h"
const uint8_t g_hw_auth_token_version = 0;
static key_record g_key_recode[KEY_MAX];
static uint32_t g_key_index = 0;

static inline bool is_origination_purpose(keymaster_purpose_t purpose)
{
    bool ret = (purpose == KM_PURPOSE_ENCRYPT || purpose == KM_PURPOSE_SIGN);
    return ret;
}

static inline bool is_usage_purpose(keymaster_purpose_t purpose)
{
    bool ret = (purpose == KM_PURPOSE_DECRYPT || purpose == KM_PURPOSE_VERIFY);
    return ret;
}

static int find_purpose_in_param(keymaster_purpose_t purpose, const keymaster_key_param_t *param, uint32_t length)
{
    uint32_t i;
    if (param == NULL)
        return 0;

    for (i = 0; i < length; i++) {
        bool condition_check = ((param[i].tag == KM_TAG_PURPOSE) &&
            ((purpose == param[i].enumerated) ||
            ((purpose == KM_PURPOSE_DECRYPT) && (param[i].enumerated == KM_PURPOSE_WRAP_KEY))));
        if (condition_check == true)
            return 1;
    }
    return 0;
}

static keymaster_error_t authorized_purpose(keymaster_purpose_t purpose, const keymaster_key_param_set_t *enforced)
{
    int32_t ret;
    keymaster_error_t error;
    keymaster_key_param_t *param = (keymaster_key_param_t *)((uint8_t *)enforced + sizeof(enforced->length));
    bool condition_check = (purpose == KM_PURPOSE_VERIFY || purpose == KM_PURPOSE_ENCRYPT ||
        purpose == KM_PURPOSE_SIGN || purpose == KM_PURPOSE_DECRYPT || purpose == KM_PURPOSE_DERIVE_KEY ||
        purpose == KM_PURPOSE_WRAP_KEY);
    if (condition_check) {
        ret = find_purpose_in_param(purpose, param, enforced->length);
        if (ret != 0) {
            error = KM_ERROR_OK;
        } else {
            tloge("param is null\n");
            error = KM_ERROR_INCOMPATIBLE_PURPOSE;
        }
    } else {
        error = KM_ERROR_UNSUPPORTED_PURPOSE;
    }
    /* modify return error code for VTS */
    keymaster_algorithm_t algorithm;
    ret = get_key_param(KM_TAG_ALGORITHM, &algorithm, enforced);
    if (ret != 0) {
        tloge("get_key_param of keymaster_algorithm_t failed\n");
        return error;
    }
    condition_check = (((algorithm == KM_ALGORITHM_EC) || (algorithm == KM_ALGORITHM_HMAC)) &&
        (purpose != KM_PURPOSE_SIGN) && (purpose != KM_PURPOSE_VERIFY));
    if (condition_check == true) {
        tloge("unsupport purpose with algorithm\n");
        return KM_ERROR_UNSUPPORTED_PURPOSE;
    }
    return error;
}

static int compare_seconds_between_ops(const key_auth *key_node, uint32_t time_interval)
{
    if (key_node == NULL)
        return -1;

    TEE_Time time;
    TEE_GetREETime(&time);
    bool condition_check = ((key_node->last_access_time) && (time.seconds > key_node->last_access_time) &&
        ((time.seconds - key_node->last_access_time) < time_interval));
    if (condition_check == true) {
        tloge("current time is %us, last_access is %us, time_interval is %us\n", time.seconds,
              key_node->last_access_time, time_interval);
        return -1;
    }
    return 0;
}

#define HMAC_MAX_KEY_SIZE_BITS 1024
#define HMAC_SHA256_SIZE       32
static int validate_token_signature(const hw_auth_token_t *auth_token)
{
    TEE_Result ret;
    TEE_ObjectHandle key_object = TEE_HANDLE_NULL;
    TEE_OperationHandle hmac_ops = TEE_HANDLE_NULL;
    uint8_t hmac_result_buff[HMAC_SHA256_SIZE] = { 0 };
    size_t out_size = HMAC_SHA256_SIZE;
    int32_t int_ret = 0;
    if (auth_token == NULL)
        return -1;

    key_object = hmac_sha256_generate_keyobject(get_rot());
    if (key_object == TEE_HANDLE_NULL) {
        tloge("Err input KEY, generate key object failed\n");
        return -1;
    }
    ret = init_key_operation(&hmac_ops, TEE_ALG_HMAC_SHA256, TEE_MODE_MAC, HMAC_MAX_KEY_SIZE_BITS, &key_object);
    if (ret != TEE_SUCCESS) {
        tloge("alloc and init crypto operation failed, result=0x%x\n", ret);
        int_ret = -1;
        goto op_error;
    }
    TEE_MACInit(hmac_ops, NULL, 0);
    ret = TEE_MACComputeFinal(hmac_ops, auth_token, sizeof(hw_auth_token_t) - HMAC_SIZE, (void *)hmac_result_buff,
        &out_size);
    if (ret != 0) {
        tloge("TEE MAC Compute Final failed, ret=0x%x\n", ret);
        int_ret = -1;
        goto op_error;
    }

    int_ret = TEE_MemCompare(auth_token->hmac, hmac_result_buff, HMAC_SIZE);
op_error:
    TEE_FreeTransientObject(key_object);
    key_object = TEE_HANDLE_NULL;
    TEE_FreeOperation(hmac_ops);
    hmac_ops = TEE_HANDLE_NULL;
    return int_ret;
}

/* timeout is in seconds */
static int32_t auth_token_timed_out(const hw_auth_token_t *auth_token, uint32_t timeout)
{
    if (auth_token == NULL)
        return 1;
    TEE_Time time;
    TEE_GetSystemTime(&time);
    UINT64 time_value = time.seconds;
    if (((UINT64_MAX - time.millis) / SEC_TO_MILLIS) < time_value) {
        tloge("invalid time value %llX\n", time_value);
        return -1;
    }
    time_value = (time_value * SEC_TO_MILLIS) + time.millis;
    /* get token_time in little endian */
    UINT64 token_time_stamp = ((((uint64_t)(ntoh((uint32_t)(auth_token->timestamp)))) << VAR_SHIFT_32) |
                               ntoh((uint32_t)(auth_token->timestamp >> VAR_SHIFT_32)));
    tlogd("time_value %x, %x, token_time_stamp %x, %x, timeout %u\n", (uint32_t)(time_value >> VAR_SHIFT_32),
          (uint32_t)(time_value), (uint32_t)(token_time_stamp >> VAR_SHIFT_32), (uint32_t)(token_time_stamp), timeout);
    /* cmp time in ms */
    return time_value > (token_time_stamp + (((UINT64)timeout) * SEC_TO_MILLIS));
}

static int32_t validate_signature_and_set_auth_token(const keymaster_key_param_set_t *params_enforced,
    const keymaster_key_param_set_t *sw_enforced, hw_auth_token_t *auth_token)
{
    if (params_enforced == NULL || sw_enforced == NULL || auth_token == NULL) {
        tloge("null pointer\n");
        return -1;
    }
    keymaster_blob_t auth_token_blob = { NULL, 0 };
    keymaster_key_param_t *sw_enforced_params = (keymaster_key_param_t *)((uint8_t *)sw_enforced + sizeof(uint32_t));
    if (sw_enforced_params == NULL) {
        tloge("null pointer\n");
        return -1;
    }
    bool condition_check = (get_key_param(KM_TAG_AUTH_TOKEN, &auth_token_blob, params_enforced) != 0);
    if (condition_check == true) {
        tloge("Authentication required, but auth token not provided");
        return -1;
    }
    condition_check = (auth_token_blob.data_length != sizeof(hw_auth_token_t));
    if (condition_check == true) {
        tloge("Auth token is the wrong size %u\n", auth_token_blob.data_length);
        return -1;
    }
    errno_t rc = memcpy_s(auth_token, sizeof(hw_auth_token_t), (void *)auth_token_blob.data_addr,
        sizeof(hw_auth_token_t));
    condition_check = (rc != EOK || (auth_token->version != g_hw_auth_token_version));
    if (condition_check == true) {
        tloge("Bug: Auth token is the version %u (or is not an auth token). Expected %d\n",
              (uint32_t)auth_token->version, g_hw_auth_token_version);
        return -1;
    }
    if (validate_token_signature(auth_token) != 0) {
        tloge("Auth token signature invalid\n");
        return -1;
    }
    return 0;
}

static int32_t lookup_authtoken_tag(int32_t *auth_timeout_index, int32_t *auth_type_index,
    const keymaster_key_param_set_t *sw_enforced)
{
    bool check_fail = (auth_timeout_index == NULL || auth_type_index == NULL || sw_enforced == NULL);
    if (check_fail) {
        tloge("null pointer\n");
        return -1;
    }
    keymaster_key_param_t *sw_enforced_params = (keymaster_key_param_t *)((uint8_t *)sw_enforced + sizeof(uint32_t));
    uint32_t i;
    for (i = 0; i < sw_enforced->length; i++) {
        if (sw_enforced_params[i].tag == KM_TAG_USER_AUTH_TYPE) {
            *auth_type_index = i;
            break;
        }
    }
    for (i = 0; i < sw_enforced->length; i++) {
        if (sw_enforced_params[i].tag == KM_TAG_AUTH_TIMEOUT) {
            *auth_timeout_index = i;
            break;
        }
    }
    if (*auth_type_index == -1) {
        tloge("Auth required but no auth type found\n");
        return -1;
    }
    return 0;
}

static int32_t check_auth(const hw_auth_token_t *auth_token, int32_t auth_type_index, int32_t auth_timeout_index,
    const keymaster_key_param_set_t *sw_enforced, bool is_begin_operation)
{
    bool condition = (auth_token == NULL || sw_enforced == NULL);
    if (condition) {
        tloge("null pointer\n");
        return -1;
    }
    condition = (auth_type_index < 0 || auth_type_index >= (int32_t)sw_enforced->length);
    if (condition) {
        tloge("bad type index\n");
        return -1;
    }
    keymaster_key_param_t *sw_enforced_params = (keymaster_key_param_t *)((uint8_t *)sw_enforced + sizeof(uint32_t));
    uint32_t key_auth_type_mask = sw_enforced_params[auth_type_index].integer;
    uint32_t token_auth_type    = ntoh(auth_token->authenticator_type);
    if ((key_auth_type_mask & token_auth_type) == 0) {
        tloge("Key requires match of auth type mask %x, but token contained %x\n", key_auth_type_mask, token_auth_type);
        return -1;
    }
    if ((auth_timeout_index != -1 && is_begin_operation)) {
        condition = (auth_timeout_index < 0 || auth_timeout_index >= (int32_t)sw_enforced->length);
        if (condition) {
            tloge("bad time out index\n");
            return -1;
        }
        if (auth_token_timed_out(auth_token, sw_enforced_params[auth_timeout_index].integer) != 0) {
            tloge("Auth token has timed out\n");
            return -1;
        }
    }
    return 0;
}

static int32_t auth_token_matches(const keymaster_key_param_set_t *params_enforced,
    const keymaster_key_param_set_t *sw_enforced, uint64_t user_secure_id, uint64_t op_handle, bool is_begin_operation)
{
    hw_auth_token_t auth_token = { 0 };
    bool condition_check = (params_enforced == NULL || sw_enforced == NULL);
    if (condition_check)
        return -1;

    if (validate_signature_and_set_auth_token(params_enforced, sw_enforced, &auth_token) != 0) {
        tloge("verfiy auth token failed\n");
        return -1;
    }
    int32_t auth_timeout_index = -1;
    int32_t auth_type_index = -1;
    if (lookup_authtoken_tag(&auth_timeout_index, &auth_type_index, sw_enforced) != 0) {
        tloge("lookup authtoken tag failed\n");
        return -1;
    }
    condition_check = ((auth_timeout_index == -1) && op_handle && ((uint64_t)op_handle != auth_token.challenge));
    if (condition_check == true) {
        tloge("Auth token has the challenge %llu, need %llu", auth_token.challenge, op_handle);
        return -1;
    }

    condition_check = ((user_secure_id != auth_token.user_id) && (user_secure_id != auth_token.authenticator_id));
    if (condition_check == true) {
        tloge("Auth token SIDs 0x%x,0x%x and 0x%x,0x%x do not match key SID 0x%x,0x%x\n",
              (uint32_t)(auth_token.user_id >> VAR_SHIFT_32), (uint32_t)(auth_token.user_id),
              (uint32_t)(auth_token.authenticator_id >> VAR_SHIFT_32), (uint32_t)(auth_token.authenticator_id),
              (uint32_t)(user_secure_id >> VAR_SHIFT_32), (uint32_t)(user_secure_id));
        return -1;
    }
    return check_auth(&auth_token, auth_type_index, auth_timeout_index, sw_enforced, is_begin_operation);
}

static int update_key_record_impl(key_record *record, uint32_t num, const uint8_t hmac[HMAC_SIZE])
{
    bool condition_check = (pthread_mutex_lock(get_key_index_lock()) != TEE_SUCCESS);
    if (condition_check == true) {
        tloge("keymaster1 enforcement pthread_mutex_lock failed.\n");
        return KM_ERROR_UNKNOWN_ERROR;
    }

    if (g_key_index >= num) {
        condition_check = (pthread_mutex_unlock(get_key_index_lock()) != TEE_SUCCESS);
        if (condition_check == true) {
            tloge("keymaster1 enforcement pthread_mutex_unlock failed\n");
            return KM_ERROR_UNKNOWN_ERROR;
        }
        return KM_ERROR_TOO_MANY_OPERATIONS;
    }

    if (memcpy_s(record[g_key_index].hmac, HMAC_SIZE, hmac, HMAC_SIZE)) {
        tloge("memcpy_s hmac failed\n");
        condition_check = (pthread_mutex_unlock(get_key_index_lock()) != TEE_SUCCESS);
        if (condition_check == true) {
            tloge("keymaster1 enforcement pthread_mutex_unlock 1 failed\n");
            return KM_ERROR_UNKNOWN_ERROR;
        }
        return KM_ERROR_UNKNOWN_ERROR;
    }
    record[g_key_index].used_count++;
    tlogd("can not find recode, add new one, index is %u\n", g_key_index);
    g_key_index++;
    condition_check = (pthread_mutex_unlock(get_key_index_lock()) != TEE_SUCCESS);
    if (condition_check == true) {
        tloge("keymaster1 enforcement pthread_mutex_unlock failed\n");
        return KM_ERROR_UNKNOWN_ERROR;
    }

    return KM_ERROR_OK;
}

static int update_key_record(key_record *record, uint32_t num, const uint8_t hmac[HMAC_SIZE])
{
    uint32_t i;
    if (record == NULL)
        return KM_ERROR_UNKNOWN_ERROR;
    for (i = 0; i < num; i++) {
        if (!memcmp(record[i].hmac, hmac, HMAC_SIZE)) {
            record[i].used_count++;
            tlogd("find record, record[i].used_count is %u\n", record[i].used_count);
            return KM_ERROR_OK;
        }
    }
    return update_key_record_impl(record, num, hmac);
}

void reset_key_record(void)
{
    (void)memset_s(g_key_recode, sizeof(key_record) * KEY_MAX, 0, sizeof(key_record) * KEY_MAX);
}

static uint32_t check_key_record(const key_record *record, uint32_t num, const uint8_t hmac[HMAC_SIZE])
{
    uint32_t i;
    if (record == NULL)
        return 0;

    for (i = 0; i < num; i++) {
        if (!memcmp(record[i].hmac, hmac, HMAC_SIZE))
            return record[i].used_count;
    }
    return 0;
}

static keymaster_error_t authorize_fill_sw_index(int32_t *timeout_index, int32_t *type_index, int32_t *required_index,
    const keymaster_key_param_set_t *sw_enforced)
{
    if (sw_enforced == NULL || timeout_index == NULL || type_index == NULL || required_index == NULL) {
        tloge("null pointer");
        return KM_ERROR_UNEXPECTED_NULL_POINTER;
    }
    const keymaster_key_param_t *sw_enforced_params = (keymaster_key_param_t *)((uint8_t *)sw_enforced +
        sizeof(uint32_t));
    uint32_t i;
    for (i = 0; i < sw_enforced->length; i++) {
        switch (sw_enforced_params[i].tag) {
        case KM_TAG_AUTH_TIMEOUT:
            *timeout_index = i;
            break;
        case KM_TAG_USER_AUTH_TYPE:
            *type_index = i;
            break;
        case KM_TAG_NO_AUTH_REQUIRED:
            *required_index = i;
            break;
        default:
            break;
        }
    }
    return KM_ERROR_OK;
}

static keymaster_error_t authorize_fill_hw_index(bool *authorized_by_key, const keymaster_key_param_set_t *hw_enforced)
{
    if (hw_enforced == NULL || authorized_by_key == NULL) {
        tloge("null pointer");
        return KM_ERROR_UNEXPECTED_NULL_POINTER;
    }
    keymaster_key_param_t *hw_enforced_params = (keymaster_key_param_t *)((uint8_t *)hw_enforced + sizeof(uint32_t));
    uint32_t i;
    for (i = 0; i < hw_enforced->length; i++) {
        switch (hw_enforced_params[i].tag) {
        case KM_TAG_CALLER_NONCE:
            *authorized_by_key = true;
            break;
        case KM_TAG_BOOTLOADER_ONLY:
            tloge("tag KM_TAG_BOOTLOADER_ONLY\n");
            return KM_ERROR_INVALID_KEY_BLOB;
        default:
            break;
        }
    }
    return KM_ERROR_OK;
}

static bool handle_tag_is_no_need_check(keymaster_tag_t tag)
{
    bool check = (tag == KM_TAG_PURPOSE || tag == KM_TAG_ALGORITHM || tag == KM_TAG_KEY_SIZE ||
        tag == KM_TAG_BLOCK_MODE || tag == KM_TAG_DIGEST || tag == KM_TAG_MAC_LENGTH ||
        tag == KM_TAG_PADDING || tag == KM_TAG_NONCE || tag == KM_TAG_MIN_MAC_LENGTH ||
        tag == KM_TAG_BLOB_USAGE_REQUIREMENTS || tag == KM_TAG_RSA_PUBLIC_EXPONENT ||
        tag == KM_TAG_CREATION_DATETIME || tag == KM_TAG_ORIGIN || tag == KM_TAG_ROLLBACK_RESISTANCE ||
        tag == KM_TAG_ROLLBACK_RESISTANT || tag == KM_TAG_NO_AUTH_REQUIRED || tag == KM_TAG_USER_AUTH_TYPE ||
        tag == KM_TAG_AUTH_TIMEOUT || tag == KM_TAG_ASSOCIATED_DATA || tag == KM_TAG_ALL_APPLICATIONS ||
        tag == KM_TAG_APPLICATION_ID || tag == KM_TAG_USER_ID || tag == KM_TAG_ALL_USERS ||
        tag == KM_TAG_HARDWARE_TYPE || tag == KM_TAG_TRUSTED_USER_PRESENCE_REQUIRED ||
        tag == KM_TAG_TRUSTED_CONFIRMATION_REQUIRED || tag == KM_TAG_UNLOCKED_DEVICE_REQUIRED ||
        tag == KM_TAG_VENDOR_PATCHLEVEL || tag == KM_TAT_BOOT_PATCHLEVEL || tag == KM_TAG_CONFIRMATION_TOKEN ||
        tag == KM_TAG_KDF || tag == KM_TAG_ECIES_SINGLE_HASH_MODE || tag == KM_TAG_INCLUDE_UNIQUE_ID ||
        tag == KM_TAG_ALLOW_WHILE_ON_BODY || tag == KM_TAG_EXPORTABLE || tag == KM_TAG_OS_VERSION ||
        tag == KM_TAG_OS_PATCHLEVEL || tag == KM_TAG_UNIQUE_ID || tag == KM_TAG_ATTESTATION_CHALLENGE ||
        tag == KM_TAG_RESET_SINCE_ID_ROTATION);
#ifdef CFG_TEE_KEYMASTER_ENHANCED_KEY
    if (tag == KM_TAG_HW_ENHANCED_KEY) {
        tlogd("enhanced keyblob tag found\n");
        check = true;
    }
#endif
    return check;
}

static bool handle_tag_is_invalid_tag_check(keymaster_tag_t tag)
{
    bool check = (tag == KM_TAG_INVALID || tag == KM_TAG_AUTH_TOKEN || tag == KM_TAG_ROOT_OF_TRUST ||
        tag == KM_TAG_APPLICATION_DATA || tag == KM_TAG_BOOTLOADER_ONLY);
#ifdef CFG_TEE_KEYMASTER_ENHANCED_KEY
    if (tag == KM_TAG_HW_ENHANCED_KEY_APPID) {
        tloge("enhanced appid tag found\n");
        check = true;
    }
#endif
    return check;
}

static keymaster_error_t handle_defalut_tag_proc(keymaster_tag_t tag)
{
    if (handle_tag_is_no_need_check(tag)) {
        return KM_ERROR_OK;
    } else if (handle_tag_is_invalid_tag_check(tag)) {
        tloge("!!!!!!invalid tag is 0x%x\n", tag);
        return KM_ERROR_INVALID_KEY_BLOB;
    }
    tloge("!!!!!!unsupport tag is 0x%x\n", tag);
    return KM_ERROR_UNSUPPORTED_TAG;
}

static bool is_data_time_type(keymaster_tag_t tag)
{
    bool is_date_time_type = (tag == KM_TAG_ACTIVE_DATETIME || tag == KM_TAG_ORIGINATION_EXPIRE_DATETIME ||
        tag == KM_TAG_USAGE_EXPIRE_DATETIME);
    return is_date_time_type;
}
static keymaster_error_t check_date_time_tag(const keymaster_key_param_t *params, keymaster_tag_t tag,
    const key_auth *key_node)
{
    TEE_Time time;
    TEE_GetREETime(&time);
    UINT64 time_value = time.seconds;
    bool condition_check = false;
    if (((UINT64_MAX - time.millis) / SEC_TO_MILLIS) < time_value) {
        tloge("invalid time value %llX\n", time_value);
        return KM_ERROR_UNKNOWN_ERROR;
    }
    time_value = time_value * SEC_TO_MILLIS + time.millis;
    switch (tag) {
    case KM_TAG_ACTIVE_DATETIME:
        condition_check = (time_value < params->date_time);
        if (condition_check == true) {
            tloge("key is not yet validated\n");
            return KM_ERROR_KEY_NOT_YET_VALID;
        }
        break;
    case KM_TAG_ORIGINATION_EXPIRE_DATETIME: {
        /* data time only compare seconds, ignore millisecond */
        condition_check = (is_origination_purpose(key_node->purpose) && time_value > params->date_time);
        if (condition_check == true) {
            tloge("key is not yet validated\n");
            return KM_ERROR_KEY_EXPIRED;
        }
        break;
    }
    case KM_TAG_USAGE_EXPIRE_DATETIME: {
        /* data time only compare seconds, ignore millisecond */
        condition_check = (is_usage_purpose(key_node->purpose) && time_value > params->date_time);
        if (condition_check == true) {
            tloge("key usage time is expired\n");
            return KM_ERROR_KEY_EXPIRED;
        }
        break;
    }
    default: break;
    }
    return KM_ERROR_OK;
}

static keymaster_error_t check_secureuser_id(const keymaster_key_param_set_t *params_enforced,
    const keyblob_head *keyblob, bool *authentication_required, bool *auth_token_matched, uint64_t user_secure_id)
{
    if (params_enforced == NULL || keyblob == NULL || authentication_required == NULL || auth_token_matched == NULL) {
        tloge("null pointer");
        return KM_ERROR_UNEXPECTED_NULL_POINTER;
    }
    int32_t time_out_index = -1;
    int32_t auth_type_index = -1;
    int32_t no_auth_required_index = -1;
    const uint8_t *p = (uint8_t *)keyblob;
    const keymaster_key_param_set_t *sw_enforced = (keymaster_key_param_set_t *)(p + keyblob->sw_enforced_offset);
    keymaster_error_t ret = authorize_fill_sw_index(&time_out_index, &auth_type_index, &no_auth_required_index,
        sw_enforced);
    if (ret != KM_ERROR_OK)
        return ret;
    if (no_auth_required_index != -1) {
        tloge("required_index exist\n");
        return KM_ERROR_INVALID_KEY_BLOB;
    }
    if (time_out_index != -1) {
        *authentication_required = true;
        if (!auth_token_matches(params_enforced, sw_enforced, user_secure_id, 0, true))
            *auth_token_matched = true;
    }
    return KM_ERROR_OK;
}

static keymaster_error_t check_authentication_and_nounce(bool authentication_required, bool auth_token_matched,
    bool caller_nonce_authorized, const key_auth *key_node, const keymaster_key_param_set_t *params_enforced)
{
    bool condition_check  = (authentication_required && (!auth_token_matched));
    if (condition_check == true) {
        tloge("Auth required but no matching auth token found\n");
        return KM_ERROR_KEY_USER_NOT_AUTHENTICATED;
    }
    keymaster_blob_t nonce = { 0 };
    condition_check = ((!caller_nonce_authorized) && is_origination_purpose(key_node->purpose) &&
        (!get_key_param(KM_TAG_NONCE, &nonce, params_enforced)));
    if (condition_check == true)
        return KM_ERROR_CALLER_NONCE_PROHIBITED;

    return KM_ERROR_OK;
}

static keymaster_error_t update_access_time(uint32_t min_time_out, bool update_access_count,
    const keyblob_head *keyblob, key_auth *key_node)
{
    keymaster_error_t ret;
    if (min_time_out != UINT32_MAX) {
        TEE_Time time;
        TEE_GetREETime(&time);
        key_node->last_access_time = time.seconds;
    }
    if (update_access_count == true) {
        ret = update_key_record(g_key_recode, KEY_MAX, keyblob->hmac);
        if (ret != KM_ERROR_OK) {
            tloge("update_key_record failed\n");
            return ret;
        }
    }
    return KM_ERROR_OK;
}

static keymaster_error_t check_usecount(const keymaster_key_param_t *params, const keyblob_head *keyblob,
    bool *update_access_count)
{
    bool check_fail = (params == NULL || keyblob == NULL || update_access_count == NULL);
    if (check_fail) {
        tloge("null pointer");
        return KM_ERROR_UNEXPECTED_NULL_POINTER;
    }
    *update_access_count = true;
    if (check_key_record(g_key_recode, KEY_MAX, keyblob->hmac) >= params->integer) {
        tloge("check_key_record failed\n");
        return KM_ERROR_KEY_MAX_OPS_EXCEEDED;
    }
    return KM_ERROR_OK;
}

static keymaster_error_t check_time_out(const keymaster_key_param_t *params, const key_auth *key_node,
    uint32_t *min_time_out)
{
    bool check_fail = (params == NULL || key_node == NULL || min_time_out == NULL);
    if (check_fail) {
        tloge("null pointer");
        return KM_ERROR_UNEXPECTED_NULL_POINTER;
    }
    *min_time_out = params->integer;
    if (compare_seconds_between_ops(key_node, params->integer) != 0)
        return KM_ERROR_KEY_RATE_LIMIT_EXCEEDED;
    return KM_ERROR_OK;
}

static keymaster_error_t check_and_update_access(const keyblob_head *keyblob, key_auth *key_node,
    bool *caller_nonce_authorized, const keymaster_key_param_set_t *params_enforced)
{
    uint32_t min_time_out = UINT32_MAX;
    bool update_access_count = false;
    bool auth_token_matched = false;
    bool authentication_required = false;
    const keymaster_key_param_set_t *sw_enforced = (keymaster_key_param_set_t *)((uint8_t *)keyblob +
        keyblob->sw_enforced_offset);
    keymaster_error_t ret;
    uint32_t i;
    for (i = 0; i < sw_enforced->length; i++) {
        const keymaster_key_param_t *params = &((keymaster_key_param_t *)((uint8_t *)sw_enforced +
            sizeof(uint32_t)))[i];
        keymaster_tag_t tag = params->tag;
        if (is_data_time_type(tag)) {
            ret = check_date_time_tag(params, tag, key_node);
        } else {
            switch (tag) {
            case KM_TAG_MIN_SECONDS_BETWEEN_OPS:
                ret = check_time_out(params, key_node, &min_time_out);
                break;
            case KM_TAG_MAX_USES_PER_BOOT:
                ret = check_usecount(params, keyblob, &update_access_count);
                break;
            case KM_TAG_USER_SECURE_ID:
                ret = check_secureuser_id(params_enforced, keyblob, &authentication_required, &auth_token_matched,
                    params->long_integer);
                break;
            case KM_TAG_CALLER_NONCE:
                *caller_nonce_authorized = true;
                ret = KM_ERROR_OK;
                break;
            default:
                ret = handle_defalut_tag_proc(tag);
            }
        }
        if (ret != KM_ERROR_OK)
            return ret;
    }
    ret = check_authentication_and_nounce(authentication_required, auth_token_matched, *caller_nonce_authorized,
        key_node, params_enforced);
    if (ret != KM_ERROR_OK) {
        tloge("check enforced tag failed\n");
        return ret;
    }
    return update_access_time(min_time_out, update_access_count, keyblob, key_node);
}

static keymaster_error_t authorize_begin(const keyblob_head *keyblob, const keymaster_key_param_set_t *params_enforced,
    key_auth *key_node)
{
    /* If successful, and if key has a min time between ops, this will be set to the time limit */
    bool check_fail = (keyblob == NULL || key_node == NULL);
    if (check_fail) {
        tloge("null pointer\n");
        return KM_ERROR_UNEXPECTED_NULL_POINTER;
    }
    bool caller_nonce_authorized = false;
    const uint8_t *p = (uint8_t *)keyblob;
    const keymaster_key_param_set_t *enforced = (keymaster_key_param_set_t *)(p + keyblob->hw_enforced_offset);
    keymaster_error_t ret = authorized_purpose(key_node->purpose, enforced);
    if (ret != KM_ERROR_OK) {
        tloge("check purpose failed\n");
        return ret;
    }
    tlogd("authorized_purpose success\n");
    ret = authorize_fill_hw_index(&caller_nonce_authorized, enforced);
    if (ret != KM_ERROR_OK) {
        tloge("check caller nonuce tag failed\n");
        return ret;
    }
    return check_and_update_access(keyblob, key_node, &caller_nonce_authorized, params_enforced);
}

static keymaster_error_t get_param_get(const key_auth *key_node, keymaster_key_param_set_t **enforced,
                                       keymaster_key_param_set_t **sw_enforced)
{
    uint8_t *next_addr = NULL;

    *enforced = key_node->auth_params;
    if (*enforced == NULL)
        return KM_ERROR_UNKNOWN_ERROR;
    if ((*enforced)->length == 0) {
        tloge("hwenforce length is zero.\n");
        return KM_ERROR_UNKNOWN_ERROR;
    }
    if ((*enforced)->params == NULL) {
        tloge("hwenforce param is null.\n");
        return KM_ERROR_UNKNOWN_ERROR;
    }
    next_addr = (uint8_t *)(*enforced);
    *sw_enforced = (keymaster_key_param_set_t *)(next_addr +
        sizeof(keymaster_key_param_t) * (*enforced)->length + sizeof(uint32_t));

    if ((*sw_enforced)->length == 0) {
        tloge("swenforce length is zero");
        return KM_ERROR_UNKNOWN_ERROR;
    }
    if ((*sw_enforced)->params == NULL) {
        tloge("swenforce param is null");
        return KM_ERROR_UNKNOWN_ERROR;
    }
    return KM_ERROR_OK;
}

keymaster_error_t authorize_update_finish(uint64_t op_handle, const keymaster_key_param_set_t *params_enforced)
{
    key_auth *key_node = NULL;
    uint32_t i;
    keymaster_key_param_set_t *hw_enforced = NULL;
    keymaster_key_param_set_t *sw_enforced = NULL;
    int32_t auth_type_index = -1;
    if ((get_auth_node(op_handle, &key_node) != TEE_SUCCESS) || (key_node == NULL)) {
        tloge("can't find auth node");
        return KM_ERROR_INVALID_OPERATION_HANDLE;
    }
    if (get_param_get(key_node, &hw_enforced, &sw_enforced) != KM_ERROR_OK) {
        tloge("authorize update finish get param fail");
        return KM_ERROR_UNKNOWN_ERROR;
    }
    keymaster_key_param_t *sw_enforced_params = (keymaster_key_param_t *)((uint8_t *)sw_enforced + sizeof(uint32_t));
    if (sw_enforced_params == NULL) {
        tloge("sw_enforced_params is null, sw_enforced len is %u", sw_enforced->length);
        return KM_ERROR_UNKNOWN_ERROR;
    }

    for (i = 0; i < sw_enforced->length; i++) {
        if (sw_enforced_params[i].tag == KM_TAG_NO_AUTH_REQUIRED || sw_enforced_params[i].tag == KM_TAG_AUTH_TIMEOUT) {
            /* If no auth is required or if auth is timeout-based, we have nothing to check. */
            return KM_ERROR_OK;
        } else if (sw_enforced_params[i].tag == KM_TAG_USER_AUTH_TYPE) {
            auth_type_index = i;
        }
    }

    /*
     * Note that at this point we should be able to assume that authentication is required, because
     * authentication is required if KM_TAG_NO_AUTH_REQUIRED is absent.  However, there are legacy
     * keys which have no authentication-related tags, so we assume that absence is equivalent to
     * presence of KM_TAG_NO_AUTH_REQUIRED.
     *
     * So, if we found KM_TAG_USER_AUTH_TYPE or if we find KM_TAG_USER_SECURE_ID then authentication
     * is required.  If we find neither, then we assume authentication is not required and return
     * success.
     */
    bool auth_required = (auth_type_index != -1);
    for (i = 0; i < sw_enforced->length; i++) {
        if (sw_enforced_params[i].tag == KM_TAG_USER_SECURE_ID) {
            auth_required      = true;
            int32_t iret = auth_token_matches(params_enforced, sw_enforced, sw_enforced_params[i].long_integer, 0,
                false);
            if (iret == 0)
                return KM_ERROR_OK;
        }
    }
    if (auth_required == true)
        return KM_ERROR_KEY_USER_NOT_AUTHENTICATED;
    return KM_ERROR_OK;
}

static int compare_application_info(keymaster_tag_t tag, const keymaster_key_param_t *parms_hidden, uint32_t j,
                                    const keymaster_key_param_t *params_in, const uint8_t *extend_bufer_in,
                                    uint32_t sw_enforced_len, const uint8_t *hidden_buffer)
{
    uint32_t i;
    bool condition_check = (tag != KM_TAG_APPLICATION_DATA && tag != KM_TAG_APPLICATION_ID);
    if (condition_check)
        return 0;

    if (parms_hidden[j].tag != tag)
        return 0;
    condition_check = (params_in == NULL || extend_bufer_in == NULL);
    if (condition_check) {
        tloge("params_in is null,can not find application tag:0x%x\n", tag);
        return -1;
    }
    for (i = 0; i < sw_enforced_len; i++) {
        if ((params_in + i) == NULL) {
            tloge("params_in + %u is null\n", i);
            return -1;
        }
        if (params_in[i].tag != tag)
            continue;

        /* compare length */
        if (params_in[i].blob.data_length != parms_hidden[j].blob.data_length) {
            tloge("application tag length is not match\n");
            return -1;
        }

        /* compare content */
        int32_t ret = TEE_MemCompare((void *)(hidden_buffer + parms_hidden[j].blob.data_offset),
            (void *)(extend_bufer_in + params_in[i].blob.data_offset), params_in[i].blob.data_length);
        if (ret != 0) {
            tloge("application tag buffer is not match\n");
            return -1;
        }
        tlogd("compare application tag:0x%x success, size %u\n", tag, params_in[i].blob.data_length);
        break;
    }
    if (i == sw_enforced_len) {
        tloge("can not find application tag:0x%x in param\n", tag);
        return -1;
    }

    return 0;
}

static int32_t check_decrypted_hidden_paramset(const keymaster_key_param_set_t *hidden_paramset,
    const keyblob_head *key_blob)
{
    bool check_fail = (hidden_paramset == NULL);
    if (check_fail) {
        tloge("params check failed\n");
        return -1;
    }
    uint32_t paramset_len = (key_blob->extend2_buf_offset - key_blob->hidden_offset) + key_blob->extend2_size;
    check_fail =  (paramset_len < sizeof(uint32_t) || ((paramset_len - sizeof(uint32_t)) / sizeof(keymaster_key_param_t)
        < hidden_paramset->length));
    if (check_fail) {
        tloge("invalid param set");
        return -1;
    }
    uint32_t hidden_param_size = key_blob->extend2_buf_offset - key_blob->hidden_offset;
    keymaster_key_param_t *hidden_params =
        (keymaster_key_param_t *)((uint8_t *)key_blob + key_blob->hidden_offset + sizeof(uint32_t));
    uint32_t i;
    for (i = 0; i < hidden_paramset->length; i++) {
        if (!keymaster_tag_type_valid(keymaster_tag_get_type(hidden_params[i].tag))) {
            tloge("Error: invalid tag type!\n");
            return -1;
        }
        if ((keymaster_tag_get_type(hidden_params[i].tag) == KM_BIGNUM) ||
            (keymaster_tag_get_type(hidden_params[i].tag) == KM_BYTES)) {
            uint32_t offset = hidden_params[i].blob.data_offset;
            bool invalid = (((paramset_len - hidden_param_size) < offset) ||
                (((paramset_len - hidden_param_size) - offset) < hidden_params[i].blob.data_length) ||
                ((hidden_param_size + offset + hidden_params[i].blob.data_length) > paramset_len));
            if (invalid) {
                tloge("Error: check decrypted hidden paramset extend failed\n");
                return -1;
            }
        }
    }
    tlogd("check hidden paramset pass");
    return 0;
}

int32_t authentication_key(const keyblob_head *key_blob, const keymaster_key_param_set_t *params_enforced)
{
    uint32_t j;
    /* find sw_enforced params */
    uint32_t sw_enforced_len = 0;
    keymaster_key_param_t *params_in = NULL;
    uint8_t *extend_bufer_in = NULL;
    int32_t ret;
    if (key_blob == NULL) {
        tloge("key_blob is null\n");
        return -1;
    }

    if (params_enforced != NULL) {
        uint32_t hw_enforced_len = *(uint32_t *)params_enforced;
        sw_enforced_len = *(uint32_t *)((uint8_t *)params_enforced + sizeof(uint32_t) +
            (hw_enforced_len * sizeof(keymaster_key_param_t)));
        params_in = (keymaster_key_param_t *)((uint8_t *)params_enforced + sizeof(uint32_t) +
            (hw_enforced_len * sizeof(keymaster_key_param_t) + sizeof(uint32_t)));
        extend_bufer_in = (uint8_t *)((uint8_t *)params_in + sw_enforced_len * sizeof(keymaster_key_param_t));
    }
    keymaster_key_param_set_t hidden_params = {
        *(uint32_t *)((uint8_t *)key_blob + key_blob->hidden_offset),
        (keymaster_key_param_t *)((uint8_t *)key_blob + key_blob->hidden_offset + sizeof(uint32_t))
    };
    /* decrypted hidden buffer may be invalid, we should check the buffer */
    if (check_decrypted_hidden_paramset(&hidden_params, key_blob) != 0) {
        tloge("invalid hidden paramset, param length %u\n", hidden_params.length);
        return -1;
    }
    for (j = 0; j < hidden_params.length; j++) {
        ret = compare_application_info(KM_TAG_APPLICATION_ID, hidden_params.params, j, params_in, extend_bufer_in,
                                       sw_enforced_len, (uint8_t *)key_blob + key_blob->extend2_buf_offset);
        if (ret != 0) {
            tloge("compare KM_TAG_APPLICATION_ID is failed, ret is 0x%x\n", ret);
            return ret;
        }
        ret = compare_application_info(KM_TAG_APPLICATION_DATA, hidden_params.params, j, params_in, extend_bufer_in,
                                       sw_enforced_len, (uint8_t *)key_blob + key_blob->extend2_buf_offset);
        if (ret != 0) {
            tloge("compare KM_TAG_APPLICATION_DATA is failed, ret is 0x%x\n", ret);
            return ret;
        }
    }
    return 0;
}

static uint32_t judge_is_need_to_auth(keymaster_algorithm_t algorithm, keymaster_purpose_t purpose)
{
    uint32_t no_need_to_auth = 0;
    /* Public key operations are always authorized. */
    bool condition = ((algorithm == KM_ALGORITHM_RSA || algorithm == KM_ALGORITHM_EC) &&
        (purpose == KM_PURPOSE_ENCRYPT || purpose == KM_PURPOSE_VERIFY));
    if (condition) {
        tlogd("Public key operations are always authorized\n");
        no_need_to_auth = 1;
    }
    return no_need_to_auth;
}
keymaster_error_t process_authorize_begin(keyblob_head *key_blob, const keymaster_key_param_set_t *params_enforced,
                                          key_auth *key_node)
{
    uint32_t no_need_to_auth;
    keymaster_error_t ret;
    no_need_to_auth = judge_is_need_to_auth(key_node->algorithm, key_node->purpose);
    if (!no_need_to_auth) {
        ret = authorize_begin(key_blob, params_enforced, key_node);
        if (ret != KM_ERROR_OK) {
            tloge("authorize_begin failed, ret is %d\n", ret);
            return ret;
        }
    }

    return KM_ERROR_OK;
}

int32_t check_enforce_info(uint32_t enforced_len, uint32_t hw_sw_size, uint32_t param_size,
    const keymaster_key_param_t *params_enforced, uint32_t *extend_buf_size)
{
    uint32_t i;
    bool invalid = ((params_enforced == NULL) || (extend_buf_size == NULL));
    if (invalid) {
        tloge("params_hw or extend buff is null\n");
        return -1;
    }

    *extend_buf_size = 0;
    for (i = 0; i < enforced_len; i++) {
        if (!keymaster_tag_type_valid(keymaster_tag_get_type(params_enforced[i].tag))) {
            tloge("Error: invalid tag type!\n");
            return -1;
        }
        if ((keymaster_tag_get_type(params_enforced[i].tag) == KM_BIGNUM) ||
            (keymaster_tag_get_type(params_enforced[i].tag) == KM_BYTES)) {
            uint32_t offset = params_enforced[i].blob.data_offset;
            *extend_buf_size += params_enforced[i].blob.data_length;
            invalid = (((param_size - hw_sw_size) < offset) ||
                (((param_size - hw_sw_size) - offset) < params_enforced[i].blob.data_length) ||
                ((hw_sw_size + offset + params_enforced[i].blob.data_length) > param_size));
            if (invalid) {
                tloge("Error: key_param_set_check extend check error!!!\n");
                return -1;
            }
        }
    }

    return 0;
}

static bool illegal_input_km_tag(keymaster_tag_t tag)
{
    keymaster_tag_t invalid_input_tags[] = { KM_TAG_OS_VERSION, KM_TAG_OS_PATCHLEVEL, KM_TAG_ROOT_OF_TRUST,
        KM_TAG_ROLLBACK_RESISTANT, KM_TAG_ORIGIN, KM_TAG_CREATION_DATETIME };
    uint32_t i;
    for (i = 0; i < sizeof(invalid_input_tags) / sizeof(keymaster_tag_t); i++) {
        if (tag == invalid_input_tags[i])
            return true;
    }
    return false;
}

int32_t check_km_params(const keymaster_key_param_set_t *hw_params_set,
    const keymaster_key_param_set_t *sw_params_set)
{
    keymaster_key_param_t *param1 = NULL;
    keymaster_key_param_t *param2 = NULL;
    uint32_t i, j;
    keymaster_key_param_set_t tmp_hw_param_set = { 0, NULL };
    keymaster_key_param_set_t tmp_sw_param_set = { 0, NULL };
    if (hw_params_set != NULL) {
        tmp_hw_param_set.length = hw_params_set->length;
        tmp_hw_param_set.params = (keymaster_key_param_t *)((uint8_t *)hw_params_set + sizeof(hw_params_set->length));
    }

    if (sw_params_set != NULL) {
        tmp_sw_param_set.length = sw_params_set->length;
        tmp_sw_param_set.params = (keymaster_key_param_t *)((uint8_t *)sw_params_set + sizeof(sw_params_set->length));
    }

    for (i = 0; i < tmp_hw_param_set.length + tmp_sw_param_set.length; i++) {
        if (i < tmp_hw_param_set.length)
            param1 = &(tmp_hw_param_set.params[i]);
        else
            param1 = &(tmp_sw_param_set.params[i - tmp_hw_param_set.length]);
        /* check illegal input km_tag */
        if (param1 != NULL && illegal_input_km_tag(param1->tag) == true) {
            tloge("tag 0x%x should be generated by keymaster\n", param1->tag);
            return -1;
        }
        for (j = i + 1; j < tmp_hw_param_set.length + tmp_sw_param_set.length; j++) {
            if (j < tmp_hw_param_set.length)
                param2 = &(tmp_hw_param_set.params[j]);
            else
                param2 = &(tmp_sw_param_set.params[j - tmp_hw_param_set.length]);
            /* check the same tag generated by both hw and sw. */
            if (param1 != NULL && param2 != NULL && keymaster_param_compare(param1, param2) == 0) {
                tloge("there's 2 same params, tag is 0x%x\n", param1->tag);
                return -1;
            }
        }
    }

    return 0;
}
