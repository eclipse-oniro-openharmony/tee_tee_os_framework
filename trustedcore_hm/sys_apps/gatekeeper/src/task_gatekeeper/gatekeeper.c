/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2015-2020. All rights reserved.
 * Description: gatekeeper ta main code
 * Create: 2015-08-08
 * History: 2019-01-18 jiashi restruct
 */

#include "gatekeeper.h"
#include <securec.h>
#include <limits.h>
#include <kmrot_ops_ext.h>
#include <mem_page_ops.h>
#include <product_uuid.h>
#include "product_uuid_public.h"
#include <tee_log.h>
#include <tee_ext_api.h>
#include <tee_private_api.h>
#include <tee_mem_mgmt_api.h>
#include <tee_crypto_api.h>
#include <crypto_ext_api.h>
#include <tee_object_api.h>
#include <rpmb_fcntl.h>
#include <timer_export.h>
#include <tee_internal_huk_api.h>
#include "gatekeeper_fail_record.h"
#include "gatekeeper_auth_token.h"
#include "gatekeeper_drv_call.h"
#include "pincode_api.h"
#include "tee_gk_auth_token.h"

struct password_data {
    uint8_t *buffer;
    uint32_t size;
};

#define HW_AUTH_TOKEN_VERSION 0

static uint32_t g_init_fail_record = 0;
enum authenticator_type_t {
    AUTH_NONE = 0,
    AUTH_PASSWORD = 1 << 0,
    AUTH_FINGERPRINT = 1 << 1,
    // Additional entries should be powers of 2.
    AUTH_ANY = UINT32_MAX,
};

static bool g_rpmb_status_ok = true;
static bool g_first_verify = true;
enum lock_status_t {
    INVALID_STATUS = 0x0,
    LOCK_STATUS    = 0x1,
    UNLOCK_STATUS  = 0x2,
};
static uint32_t g_lock_status = LOCK_STATUS;
static void set_lock_status(uint32_t uid, uint32_t status);

enum pincode_flag_t {
    INVALID     = 0x0,
    SUPPORT     = 0x1,
    NOT_SUPPORT = 0x2,
};

static uint32_t g_ext_pincode_flag;
#define PINCODE_FLAG_FILE "pincode_flag"

static void get_system_time(uint64_t *timestamp)
{
    TEE_Time time = {0};

    TEE_GetSystemTime(&time);
    *timestamp = (uint64_t)time.seconds * MILLISECOND + time.millis;
}

static uint32_t compute_retry_timeout(uint64_t last_checked_timestamp, uint64_t wait_time)
{
    uint64_t time_value = 0;
    get_system_time(&time_value);
    uint64_t used_time = time_value - last_checked_timestamp;

    if (wait_time > used_time) {
        tlogd("need wait %d ms\n", (int)(wait_time - used_time));
        return (uint32_t)(wait_time - used_time);
    } else {
        tlogd("user have wait %d s, no need to wait\n", TIMEOUT_MS / MILLISECOND);
        return 0;
    }
}

static TEE_Result write_primary_user_record_to_rpmb(const struct failure_record_uid_t *record_uid)
{
    TEE_Result ret;

    ret = TEE_RPMB_FS_Write(PRIMARY_RECORD_RPMB_FILENAME, (const uint8_t *)record_uid, sizeof(*record_uid));
    if (ret != TEE_SUCCESS) {
        tloge("write rpmb error:0x%08x", ret);
        /* retry */
        ret = TEE_RPMB_FS_Write(PRIMARY_RECORD_RPMB_FILENAME, (const uint8_t *)record_uid, sizeof(*record_uid));
        if (ret != TEE_SUCCESS) {
            tloge("retry write rpmb error:0x%08x", ret);
            g_rpmb_status_ok = false;
        }
    }
    /* Once the write operation is successful, g_rpmb_status_ok wiil be set to true */
    if (ret == TEE_SUCCESS) {
        ret = TEE_RPMB_FS_SetAttr(PRIMARY_RECORD_RPMB_FILENAME, TEE_RPMB_FMODE_NON_ERASURE);
        if (ret != TEE_SUCCESS)
            tloge("set attr error:0x%08X", ret);
        g_rpmb_status_ok = true;
    }

    return ret;
}

static TEE_Result write_sub_user_record_to_rpmb(void)
{
    TEE_Result ret;
    uint8_t *buffer = NULL;
    uint32_t buffer_size = 0;

    if (!read_sub_user_fail_record((struct failure_record_uid_t *)buffer, &buffer_size)) {
        tloge("read all fail record is failed");
        return TEE_ERROR_GENERIC;
    }

    tlogd("current total fail record size:%u", buffer_size);

    if (buffer_size != 0) {
        buffer = TEE_Malloc(buffer_size, 0);
        if (buffer == NULL) {
            tloge("malloc memory %u error", buffer_size);
            return TEE_ERROR_OUT_OF_MEMORY;
        }

        if (!read_sub_user_fail_record((struct failure_record_uid_t *)buffer, &buffer_size)) {
            TEE_Free(buffer);
            return TEE_ERROR_GENERIC;
        }

        ret = TEE_RPMB_FS_Write(FAIL_RECORD_RPMB_FILENAME, buffer, buffer_size);
        if (ret != TEE_SUCCESS) {
            tloge("write rpmb error:0x%08X", ret);
            /* retry */
            ret = TEE_RPMB_FS_Write(FAIL_RECORD_RPMB_FILENAME, buffer, buffer_size);
            if (ret != TEE_SUCCESS) {
                tloge("retry write rpmb error:0x%08X", ret);
                g_rpmb_status_ok = false;
            }
        }
        /* Once the write operation is successful, g_rpmb_status_ok wiil be set to true */
        if (ret == TEE_SUCCESS)
            g_rpmb_status_ok = true;

        TEE_Free(buffer);
    } else {
        ret = TEE_RPMB_FS_Rm(FAIL_RECORD_RPMB_FILENAME);
        if (ret != TEE_SUCCESS && ret != TEE_ERROR_RPMB_FILE_NOT_FOUND)
            tloge("rm rpmb error:0x%08X", ret);
    }
    return ret;
}

static TEE_Result shadow_fail_record_into_rpmb(const struct failure_record_uid_t *record_uid)
{
    if (record_uid->uid == PRIMARY_FAKE_USER_ID)
        return write_primary_user_record_to_rpmb(record_uid);
    else
        return write_sub_user_record_to_rpmb();
}

static void increment_failrecord(uint32_t uid, uint64_t secure_id, uint8_t version)
{
    struct failure_record_uid_t record_uid = {0};
    record_uid.uid = uid;
    record_uid.version = version;
    record_uid.record.secure_user_id = secure_id;

    tlogd("increment failrecord enter");

    if (!read_fail_record(&record_uid)) {
        tloge("read_fail_record secure_id 0x%llX failed\n", secure_id);
        return;
    }

    uint64_t time_value = 0;
    get_system_time(&time_value);

    record_uid.record.failure_counter++;
    record_uid.record.last_checked_timestamp = time_value;
    tlogd("failure_counter is %u", record_uid.record.failure_counter);
    tlogd("timestamp is 0x%llX", record_uid.record.last_checked_timestamp);

    if (!write_fail_record(&record_uid)) {
        tloge("write_fail_record failed\n");
        return;
    }

    tlogd("failrecord increment success\n");
    return;
}

static uint64_t get_rtc_time(void)
{
#ifndef CONFIG_RTC_TIMER
    uint64_t time_value;
    TEE_Time time;
    get_sys_rtc_time(&time);
    time_value = time.seconds * MILLISECOND + time.millis;
    return time_value;
#else
    return (uint64_t)__get_secure_rtc_time() * MILLISECOND;
#endif
}

static TEE_Result gatekeeper_increment_failcounter(uint32_t uid,
    const struct password_handle_t *password_handle, uint32_t *failure_counter)
{
    struct failure_record_uid_t record_uid = {0};
    record_uid.uid = uid;
    record_uid.version = password_handle->version;

    if (!read_fail_record(&record_uid)) {
        tloge("read_fail_record uid %u version:%c failed\n", uid, password_handle->version);
        return TEE_ERROR_GENERIC;
    }

    errno_t rc = memcpy_s(record_uid.signature, sizeof(record_uid.signature),
                          password_handle->signature, sizeof(password_handle->signature));
    if (rc != EOK) {
        tloge("mem copy fail!");
        return TEE_ERROR_SECURITY;
    }
    record_uid.record.secure_user_id = password_handle->user_id;
    record_uid.record.failure_counter++;
    record_uid.record.last_checked_timestamp = get_rtc_time();
    tlogd("increment failrecord uid:%u, secure_id:0x%llx", uid, password_handle->user_id);
    tlogd("increment failrecord failure_counter is %u", record_uid.record.failure_counter);
    tlogd("increment failrecord timestamp is 0x%llX", record_uid.record.last_checked_timestamp);

    *failure_counter = record_uid.record.failure_counter;
    if (write_fail_record(&record_uid)) {
        TEE_Result ret;

        ret = shadow_fail_record_into_rpmb(&record_uid);
        if (ret != TEE_SUCCESS) {
            tloge("write rpmb error:0x%08X", ret);
            return ret;
        }
    } else {
        tloge("write_fail_record failed\n");
        return TEE_ERROR_GENERIC;
    }

    tlogd("failrecord increment, failure_counter:%u success\n", *failure_counter);
    return TEE_SUCCESS;
}

static TEE_Result gatekeeper_get_timeout(uint32_t wait_time, struct failure_record_uid_t *record_uid, uint32_t *timeout)
{
    uint64_t time_value = get_rtc_time();
    uint64_t last_checked_timestamp = record_uid->record.last_checked_timestamp;
    uint64_t use_time = 0;

    if (time_value > last_checked_timestamp) {
        use_time = time_value - last_checked_timestamp;
        if (use_time >= wait_time)
            *timeout = 0;
        else
            *timeout = (uint32_t)(wait_time - use_time);
    } else {
        /* rtc time is reset, we should update last_checked_timestamp */
        record_uid->record.last_checked_timestamp = time_value;
        if (write_fail_record(record_uid)) {
            TEE_Result ret = shadow_fail_record_into_rpmb(record_uid);
            if (ret != TEE_SUCCESS) {
                tloge("write rpmb error:0x%08X", ret);
                return ret;
            }
        } else {
            tloge("write_fail_record failed\n");
            return TEE_ERROR_GENERIC;
        }
        *timeout = wait_time;
    }

    tlogd("use_time:%llums, timeout:%ums", use_time, *timeout);
    return TEE_SUCCESS;
}

#define TEN_TIMES_NUM   10U

static void get_wait_time_and_retry_times(uint32_t failure_counter,
    uint32_t *wait_time, uint32_t *retry_times)
{
    tlogd("get wait time and retry times, failure_counter:%u", failure_counter);

    if (failure_counter < START_FAILURE_COUNTER) {
        *wait_time = 0;
        *retry_times = START_FAILURE_COUNTER - failure_counter;
    } else if (failure_counter < MAX_FAILURE_COUNTER) {
        /* Google Solution */
        *wait_time = (uint32_t)((WAIT_TIME_UNIT << ((failure_counter - BASE_FAIL_COUNTER) /
            TEN_TIMES_NUM)) * MILLISECOND);
        *retry_times = 1;
    } else {
        *wait_time = WAIT_TIME_DAY * MILLISECOND;
        *retry_times = 1;
    }
}

static TEE_Result gatekeeper_retry_timeout(uint32_t uid,
    const struct password_handle_t *password_handle)
{
    uint32_t wait_time = 0;
    uint32_t retry_times = 0;
    uint32_t timeout = 0;
    struct failure_record_uid_t record_uid = {0};

    record_uid.uid = uid;
    record_uid.version = password_handle->version;
    bool find = read_fail_record(&record_uid);
    if (!find) {
        tloge("read fail, record is not exist!");
        return TEE_ERROR_GENERIC;
    }

    if (record_uid.record.secure_user_id != password_handle->user_id ||
        TEE_MemCompare(record_uid.signature, password_handle->signature, HMAC_SIZE) != 0) {
        tloge("secure_id or signature is error");
        return TEE_ERROR_GENERIC;
    }

    get_wait_time_and_retry_times(record_uid.record.failure_counter, &wait_time, &retry_times);
    if (wait_time == 0)
        return TEE_SUCCESS;

    TEE_Result ret = gatekeeper_get_timeout(wait_time, &record_uid, &timeout);
    if (ret != TEE_SUCCESS)
        return ret;
    else
        return (TEE_Result)timeout;
}

static TEE_Result check_fail(uint32_t uid, uint64_t secure_id, uint8_t version)
{
    uint32_t timeout = 0;

    struct failure_record_uid_t record_uid = {0};
    record_uid.uid = uid;
    record_uid.version = version;
    record_uid.record.secure_user_id = secure_id;

    bool find = read_fail_record(&record_uid);
    if (!find) {
        // add a record when the upgrade user cannot find the record.
        if (!add_fail_record(&record_uid, false)) {
            // when driver malloc fail or the number of fail record
            // above 600(the max user node) return this error.
            tloge("no memory when check fail return false");
            return TEE_ERROR_OUT_OF_MEMORY;
        }
    }

    if (record_uid.record.failure_counter >= FAIL_COUNTS) {
        timeout = compute_retry_timeout(record_uid.record.last_checked_timestamp, TIMEOUT_MS);
        if (timeout == 0) {
            record_uid.record.failure_counter = 0;
            if (!write_fail_record(&record_uid)) {
                tloge("write fail record failed\n");
                return TEE_ERROR_OUT_OF_MEMORY;
            }
        }
    }

    if (timeout != 0) {
        if (timeout > 0xFFFF)
            timeout = 0xFFFF;

        tloge("need to wait %u ms", timeout);
        // unit:ms
        return (TEE_Result)(DEAD_BASE + timeout);
    }

    return TEE_SUCCESS;
}

static int compute_hmac(const uint8_t *src, uint32_t src_size, const uint8_t *key, uint8_t *dst, uint32_t dst_len)
{
    TEE_Result ret;
    TEE_OperationHandle mac_ops = NULL;
    TEE_ObjectHandle key_obj = NULL;
    TEE_Attribute attrib = {0};
    size_t out_len = dst_len;

    ret = TEE_AllocateTransientObject(TEE_TYPE_HMAC_SHA256, HMAC_SIZE_INBITS, &key_obj);
    if (ret != TEE_SUCCESS) {
        tloge("allocate transitent object failed, ret=0x%x", ret);
        goto cleanup_1;
    }
    TEE_InitRefAttribute(&attrib, TEE_ATTR_SECRET_VALUE, (void *)key, HMAC_SIZE);
    ret = TEE_PopulateTransientObject(key_obj, &attrib, 1);
    if (ret != TEE_SUCCESS) {
        tloge("populate transitent object failed, ret=0x%x", ret);
        goto cleanup_2;
    }
    ret = TEE_AllocateOperation(&mac_ops, TEE_ALG_HMAC_SHA256, TEE_MODE_MAC, HMAC_SIZE);
    if (ret != TEE_SUCCESS) {
        tloge("allocate operation failed, ret=0x%x", ret);
        goto cleanup_2;
    }
    ret = TEE_SetOperationKey(mac_ops, key_obj);
    if (ret != TEE_SUCCESS) {
        tloge("set key failed, ret=0x%x", ret);
        goto cleanup_3;
    }
    TEE_MACInit(mac_ops, NULL, 0);
    TEE_MACUpdate(mac_ops, src, src_size);
    ret = TEE_MACComputeFinal(mac_ops, NULL, 0, dst, &out_len);
    if (ret != TEE_SUCCESS) {
        tloge("compute mac failed, ret=0x%x\n", ret);
        goto cleanup_3;
    }
    TEE_FreeOperation(mac_ops);
    TEE_FreeTransientObject(key_obj);
    return 0;

cleanup_3:
    TEE_FreeOperation(mac_ops);
cleanup_2:
    TEE_FreeTransientObject(key_obj);
cleanup_1:
    return -1;
}

static int32_t derive_hmac_key(uint64_t salt, uint8_t *key, uint32_t key_len)
{
    int32_t rc;
    TEE_Result ret;
    TEE_UUID uuid = TEE_SERVICE_GATEKEEPER;
    uint8_t *temp_buf = NULL;

    temp_buf = (uint8_t *)TEE_Malloc(sizeof(salt) + sizeof(uuid), 0);
    if (temp_buf == NULL) {
        tloge("buf malloc failed\n");
        return -1;
    }

    *(uint64_t *)temp_buf = salt;

    rc = memcpy_s(temp_buf + sizeof(salt), sizeof(uuid), &uuid, sizeof(uuid));
    if (rc != EOK) {
        tloge("copy failed, rc 0x%x\n", rc);
        goto clean;
    }

    ret = TEE_EXT_ROOT_DeriveKey2(temp_buf, sizeof(salt) + sizeof(uuid), key, key_len);
    if (ret != TEE_SUCCESS) {
        tloge("Tee DeriveKey2 EXT_ROOT failed, ret 0x%x\n", ret);
        rc = -1;
        goto clean;
    }
    rc = 0;
clean:
    TEE_Free(temp_buf);
    return rc;
}

static TEE_Result derive_interation(const uint8_t *key_temp, uint32_t key_temp_size, uint8_t *key, uint32_t key_len)
{
    TEE_Result ret = engine_power_on();
    if (ret != TEE_SUCCESS) {
        tloge("power on fail, ret:0x%x", ret);
        return ret;
    }

    struct meminfo_t data_in = {0};
    struct meminfo_t data_out = {0};
    data_in.buffer = (uintptr_t)key_temp;
    data_in.size = key_temp_size;
    data_out.buffer = (uintptr_t)key;
    data_out.size = key_len;
    ret = tee_internal_derive_key2_iter(&data_in, &data_out, GATEKEEPER_ITRATION_TIMES, DERIVE_ROOT_INTERNAL_ITRATIONS);
    if (ret != TEE_SUCCESS)
        tloge("Tee DeriveKey2 EXT_ROOT failed, ret 0x%x\n", ret);

    engine_power_off();
    return ret;
}

static int32_t iteration_derive_hmac_key(uint32_t uid, const struct gk_buffer *src,
    const struct password_handle_t *password_handle, uint8_t *key, uint32_t key_len)
{
    int32_t rc;
    TEE_Result ret;
    TEE_UUID uuid = TEE_SERVICE_GATEKEEPER;
    uint8_t *temp_buf = NULL;
    uint32_t src_size = src->size;

    temp_buf = (uint8_t *)TEE_Malloc(sizeof(password_handle->salt) + sizeof(uuid) + src_size, 0);
    if (temp_buf == NULL) {
        tloge("buf malloc failed\n");
        return -1;
    }

    *(uint64_t *)temp_buf = password_handle->salt;

    rc = memcpy_s(temp_buf + sizeof(password_handle->salt), sizeof(uuid) + src_size, &uuid, sizeof(uuid));
    if (rc != EOK) {
        tloge("copy failed, rc 0x%x\n", rc);
        goto clean;
    }

    rc = memcpy_s(temp_buf + sizeof(password_handle->salt) + sizeof(uuid), src_size,
        (uint8_t *)(uintptr_t)src->buff, src_size);
    if (rc != EOK) {
        tloge("copy failed, rc 0x%x\n", rc);
        goto clean;
    }

    uint8_t key_temp[HMAC_SIZE] = {0};
    ret = TEE_EXT_ROOT_DeriveKey2(temp_buf, sizeof(password_handle->salt) + sizeof(uuid) + src_size,
        key_temp, sizeof(key_temp));
    if (ret != TEE_SUCCESS) {
        tloge("Tee DeriveKey2 EXT_ROOT failed, ret 0x%x\n", ret);
        rc = -1;
        goto clean;
    }

    if (uid >= PRIMARY_FAKE_USER_ID && GATEKEEPER_ITRATION_TIMES != 0)
        rc = (int32_t)derive_interation(key_temp, sizeof(key_temp), key, key_len);
    else
        rc = memcpy_s(key, key_len, key_temp, sizeof(key_temp));
    (void)memset_s(key_temp, sizeof(key_temp), 0, sizeof(key_temp));
    if (rc != 0)
        goto clean;

    rc = 0;
clean:
    TEE_Free(temp_buf);
    return rc;
}

static int32_t gatekeeper_hmac_new(uint32_t uid, const struct gk_buffer *src,
    const struct password_handle_t *password_handle, uint8_t *dst, uint32_t dst_len)
{
    errno_t rc;
    uint8_t key[HMAC_SIZE] = {0};

    if (password_handle->version >= HANDLE_VERSION_6) {
        rc = iteration_derive_hmac_key(uid, src, password_handle, key, sizeof(key));
    } else {
        rc = derive_hmac_key(password_handle->salt, key, sizeof(key));
    }
    if (rc != 0) {
        tloge("deriver key fail, version:%u rc:%d", password_handle->version, rc);
        return rc;
    }

    rc = compute_hmac((uint8_t *)(uintptr_t)src->buff, src->size, key, dst, dst_len);
    if (rc != 0)
        tloge("hmac gatekeeper new fail:0x%08X", rc);

    (void)memset_s(key, sizeof(key), 0, sizeof(key));
    return rc;
}

static void *acquire_signature_data(const struct password_handle_t *password_handle,
                                    const void *password, uint32_t password_size, uint32_t *buffer_size)
{
    errno_t rc;
    uint32_t add_value = 0;
    uint32_t signature_data_size = sizeof(password_handle->version) +
                                   sizeof(password_handle->user_id) +
                                   sizeof(password_handle->flags) + password_size;

    if (signature_data_size > MAX_SIGN_SIZE) {
        tloge("signature_data malloc size is error");
        return NULL;
    }
    void *signature_data = TEE_Malloc(signature_data_size, 0);
    if (signature_data == NULL) {
        tloge("signature_data malloc memory error");
        return signature_data;
    }

    *buffer_size = signature_data_size;

    uintptr_t temp = (uintptr_t)signature_data;

    *(uint8_t *)(temp + add_value) = password_handle->version;
    add_value += sizeof(password_handle->version);

    *(uint64_t *)(temp + add_value) = password_handle->user_id;
    add_value += sizeof(password_handle->user_id);

    *(uint64_t *)(temp + add_value) = password_handle->flags;
    add_value += sizeof(password_handle->flags);

    rc = memcpy_s((void *)(temp + add_value), signature_data_size - add_value,
                  password, password_size);
    if (rc != EOK) {
        tloge("signature_data copy password fail:%d", rc);

        (void)memset_s(signature_data, signature_data_size, 0, signature_data_size);

        TEE_Free(signature_data);
        signature_data = NULL;
    }

    return signature_data;
}

static TEE_Result enroll_extra_hmac(struct password_handle_t *password_handle)
{
    uint8_t *key_factor = TEE_Malloc(MAX_KEY_SIZE, 0);
    if (key_factor == NULL)
        return TEE_ERROR_OUT_OF_MEMORY;

    struct memref_in key_id;
    key_id.buffer = (uint8_t *)(&(password_handle->user_id));
    key_id.length = sizeof(password_handle->user_id);

    struct memref_in pin;
    pin.buffer = password_handle->signature;
    pin.length = sizeof(password_handle->signature);

    struct memref_out handle;
    uint32_t sig_size = sizeof(password_handle->signature);
    handle.buffer = password_handle->signature;
    handle.size = &sig_size;

    struct memref_out key_factor_buf;
    uint32_t factor_size = MAX_KEY_SIZE;
    key_factor_buf.buffer = key_factor;
    key_factor_buf.size = &factor_size;

    TEE_Result ret = tee_ext_pincode_register_pin(&key_id, &pin, &handle, &key_factor_buf);
    if (ret != TEE_SUCCESS) {
        tloge("register pin fail, ret:0x%x", ret);
        goto clean;
    }

    if (!__add_key_factor(password_handle->user_id, key_factor_buf.buffer, *(key_factor_buf.size))) {
        tloge("add key factor fail!");
        ret = TEE_ERROR_GENERIC;
    }

clean:
    TEE_Free(key_factor);
    return ret;
}

static bool password_handle_hmac(uint32_t uid, const struct password_handle_t *password_handle,
    const struct gk_buffer *password, uint8_t *hmac, uint8_t hmac_size)
{
    bool ret = true;
    void *signature_data = NULL;
    uint32_t signature_data_size = 0;

    signature_data = acquire_signature_data(password_handle, (uint8_t *)(uintptr_t)password->buff, password->size,
                                            &signature_data_size);
    if (signature_data == NULL) {
        tloge("signature memory malloc fail");
        return false;
    }

    tlogd("the version is %u", (uint32_t)(password_handle->version));

    if ((password_handle->version == HANDLE_VERSION_3) ||
        (password_handle->version == HANDLE_VERSION_5) ||
        (password_handle->version == HANDLE_VERSION_6) ||
        (password_handle->version == HANDLE_VERSION_7)) {
        struct gk_buffer sig_data = {0};
        sig_data.buff = (uintptr_t)signature_data;
        sig_data.size = signature_data_size;
        if (gatekeeper_hmac_new(uid, &sig_data, password_handle, hmac, hmac_size) != 0) {
            tloge("gatekeeper hmac new failed");
            ret = false;
        }
    } else {
        tloge("invalid version %u", (uint32_t)(password_handle->version));
        ret = false;
    }

    (void)memset_s(signature_data, signature_data_size, 0, signature_data_size);

    TEE_Free(signature_data);
    signature_data = NULL;
    return ret;
}

static TEE_Result enroll_extra(uint32_t uid, const struct gk_buffer *pwd_hash,
    struct password_handle_t *password_handle)
{
    TEE_Result ret = enroll_extra_hmac(password_handle);
    if (ret == TEE_SUCCESS) {
        if (g_ext_pincode_flag != INVALID)
            return ret;
        g_ext_pincode_flag = SUPPORT;
        (void)TEE_RPMB_FS_Write(PINCODE_FLAG_FILE, (uint8_t *)&g_ext_pincode_flag, sizeof(g_ext_pincode_flag));
    } else {
        if (g_ext_pincode_flag == SUPPORT)
            return ret;
        /*
         * It means that g_ext_pincode_flag has not been initialized yet.
         * It is the first time that the password is set and the registration fails.
         * It is necessary to set the flag that does not support and the password version is rolled back to version 6
         */
        g_ext_pincode_flag = NOT_SUPPORT;
        (void)TEE_RPMB_FS_Write(PINCODE_FLAG_FILE, (uint8_t *)&g_ext_pincode_flag, sizeof(g_ext_pincode_flag));
        password_handle->version = HANDLE_VERSION_6;
        if (!password_handle_hmac(uid, password_handle, pwd_hash,
            password_handle->signature, sizeof(password_handle->signature))) {
            tloge("hmac for password_handle failed\n");
            return TEE_ERROR_MAC_INVALID;
        }
    }

    return TEE_SUCCESS;
}

static TEE_Result pre_generate_handle(struct password_handle_t *password_handle)
{
    TEE_GenerateRandom(&password_handle->user_id, sizeof(password_handle->user_id));
    if (password_handle->user_id == 0) {
        tloge("password_handle->user_id is 0\n");
        return TEE_ERROR_GENERIC;
    }

    password_handle->flags = 0;

    TEE_GenerateRandom(&password_handle->salt, sizeof(password_handle->salt));
    if (password_handle->salt == 0) {
        tloge("password_handle->salt is 0\n");
        return TEE_ERROR_GENERIC;
    }

    password_handle->hardware_backed = true;

    tlogd("-- create passwd handle--\n");
    return TEE_SUCCESS;
}

static TEE_Result create_gatekeeper_handle(struct gatekeeper_handle *gatekeeper_handle, uint32_t uid,
    const uint8_t *password, uint32_t password_size)
{
    struct password_handle_t *password_handle = &gatekeeper_handle->password_handle;
    TEE_Result ret;
    (void)uid;

    password_handle->version = HANDLE_VERSION_6;
    if (uid >= PRIMARY_FAKE_USER_ID &&
        tee_ext_pincode_register_pin(NULL, NULL, NULL, NULL) != PINCODE_ERR_NOT_SUPPORTED &&
        g_ext_pincode_flag != NOT_SUPPORT) {
        password_handle->version = HANDLE_VERSION_7;
        (void)tee_ext_pincode_poweron();
    }

    ret = pre_generate_handle(password_handle);
    if (ret != TEE_SUCCESS) {
        tloge("generate handle fail:0x%08x", ret);
        goto power_off;
    }

    struct gk_buffer pwd_hash = {0};
    pwd_hash.buff = (uintptr_t)password;
    pwd_hash.size = password_size;

    if (!password_handle_hmac(uid, password_handle, &pwd_hash,
        password_handle->signature, sizeof(password_handle->signature))) {
        tloge("hmac for password_handle failed\n");
        ret = TEE_ERROR_MAC_INVALID;
        goto power_off;
    }

    if (password_handle->version != HANDLE_VERSION_7)
        ret = TEE_SUCCESS;
    else
        ret = enroll_extra(uid, &pwd_hash, password_handle);

power_off:
    if (password_handle->version == HANDLE_VERSION_7)
        (void)tee_ext_pincode_poweroff();

    return ret;
}

static TEE_Result gatekeeper_clear_fail_counter(uint32_t uid,
    const struct password_handle_t *password_handle)
{
    TEE_Result ret;
    struct failure_record_uid_t record_uid = {0};

    record_uid.uid = uid;
    record_uid.version = password_handle->version;

    if (read_fail_record(&record_uid) == false) {
        tloge("cannot find record, uid:%u", uid);
        return TEE_ERROR_GENERIC;
    }
    /* if fail counter is zero, no need to clear record in rpmb */
    if (record_uid.record.failure_counter == 0)
        return TEE_SUCCESS;

    errno_t rc = memcpy_s(record_uid.signature, sizeof(record_uid.signature),
                          password_handle->signature, sizeof(password_handle->signature));
    if (rc != EOK) {
        tloge("mem copy fail!");
        return TEE_ERROR_SECURITY;
    }
    record_uid.record.secure_user_id = password_handle->user_id;
    record_uid.record.failure_counter = 0;
    record_uid.record.last_checked_timestamp = get_rtc_time();
    if (write_fail_record(&record_uid)) {
        ret = shadow_fail_record_into_rpmb(&record_uid);
        if (ret != TEE_SUCCESS) {
            tloge("write rpmb error:0x%08X", ret);
            return ret;
        }
    } else {
        tloge("clear_failrecord failed\n");
        return TEE_ERROR_GENERIC;
    }
    return TEE_SUCCESS;
}

static void gatekeeper_delete_fail_record(uint32_t uid, uint8_t version, uint64_t secure_user_id)
{
    struct failure_record_uid_t record_uid = {0};
    record_uid.uid = uid;
    record_uid.version = version;
    record_uid.record.secure_user_id = secure_user_id;
    delete_fail_record(&record_uid);
}

static TEE_Result verify_ext(const struct password_handle_t *password_handle,
    const uint8_t *signature, uint32_t sig_size,
    uint8_t *key_factor, uint32_t key_factor_size)
{
    struct memref_in key_id;
    key_id.buffer = (uint8_t *)(&(password_handle->user_id));
    key_id.length = sizeof(password_handle->user_id);

    struct memref_in pin;
    pin.buffer = signature;
    pin.length = sig_size;

    struct memref_in handle;
    handle.buffer = password_handle->signature;
    handle.length = sizeof(password_handle->signature);

    struct memref_out key_factor_buf;
    key_factor_buf.buffer = key_factor;
    key_factor_buf.size = &key_factor_size;

    TEE_Result ret = tee_ext_pincode_verify_pin(&key_id, &pin, &handle, &key_factor_buf);
    if (ret != TEE_SUCCESS) {
        tloge("register pin fail, ret:0x%x", ret);
        return ret;
    } else {
        if (!__add_key_factor(password_handle->user_id, key_factor_buf.buffer, *(key_factor_buf.size)))
            tlogw("add key factor fail!");
    }

    return TEE_SUCCESS;
}

static TEE_Result verify_extra_hmac(const struct password_handle_t *password_handle,
    const uint8_t *signature, uint32_t sig_size)
{
    uint32_t key_factor_size = MAX_KEY_SIZE;
    uint8_t *key_factor = TEE_Malloc(MAX_KEY_SIZE, 0);
    if (key_factor == NULL)
        return TEE_ERROR_OUT_OF_MEMORY;

    if (__get_key_factor(password_handle->user_id, key_factor, &key_factor_size)) {
        uint8_t hmac[HMAC_SIZE];
        uint8_t data[HMAC_SIZE + sizeof(password_handle->user_id)];
        int32_t rc = memcpy_s(data, sizeof(data), signature, sig_size);
        int32_t rc2 = memcpy_s(data + sig_size, sizeof(data) - sig_size,
            &(password_handle->user_id), sizeof(password_handle->user_id));
        if (rc != EOK || rc2 != EOK) {
            tloge("mem cpoy fail, rc:%d, rc2:%d", rc, rc2);
            TEE_Free(key_factor);
            return TEE_ERROR_SECURITY;
        }

        rc = compute_hmac(data, sizeof(data), key_factor, hmac, sizeof(hmac));
        if (rc != 0) {
            TEE_Free(key_factor);
            return TEE_ERROR_GENERIC;
        }
        rc = TEE_MemCompare(hmac, password_handle->signature, HMAC_SIZE);
        TEE_Free(key_factor);
        if (rc != 0)
            return TEE_ERROR_MAC_INVALID;
        else
            return TEE_SUCCESS;
    }

    TEE_Result ret = verify_ext(password_handle, signature, sig_size, key_factor, key_factor_size);
    if (ret != TEE_SUCCESS) {
        tloge("verify ext fail!, ret:0x%x\n", ret);
        goto clean;
    }
clean:
    TEE_Free(key_factor);
    return ret;
}

static TEE_Result do_verify(uint32_t uid, const struct password_handle_t *password_handle,
    const uint8_t *hmac, uint32_t hmac_size)
{
    if (password_handle->version < HANDLE_VERSION_7 || uid < PRIMARY_FAKE_USER_ID) {
        int32_t rc = TEE_MemCompare(hmac, password_handle->signature, HMAC_SIZE);
        if (rc != 0)
            return TEE_ERROR_MAC_INVALID;
        else
            return TEE_SUCCESS;
    } else {
        return verify_extra_hmac(password_handle, hmac, hmac_size);
    }
}

static TEE_Result check_password_increase_counter_first(uint32_t uid,
    const struct password_handle_t *password_handle, const uint8_t *hmac)
{
    TEE_Result ret;
    uint32_t wait_time = 0;
    uint32_t retry_times = 0;
    uint32_t failure_counter = 0;

    /* Preventing power-off attacks */
    ret = gatekeeper_increment_failcounter(uid, password_handle, &failure_counter);
    if (ret != TEE_SUCCESS) {
        tloge("increment failcounter fail, ret:0x%x", ret);
        return TEE_ERROR_MAC_INVALID;
    }

    if (do_verify(uid, password_handle, hmac, HMAC_SIZE) != TEE_SUCCESS) {
        get_wait_time_and_retry_times(failure_counter, &wait_time, &retry_times);
        if (wait_time != 0) {
            tloge("verify fail, need wait %u ms", wait_time);
            return wait_time;
        }
        return TEE_ERROR_MAC_INVALID;
    }

    return TEE_SUCCESS;
}

static TEE_Result check_password_increase_counter_later(uint32_t uid,
    const struct password_handle_t *password_handle, const uint8_t *hmac)
{
    TEE_Result ret;
    uint32_t wait_time = 0;
    uint32_t retry_times = 0;
    uint32_t failure_counter = 0;

    if (do_verify(uid, password_handle, hmac, HMAC_SIZE) != TEE_SUCCESS) {
        ret = gatekeeper_increment_failcounter(uid, password_handle, &failure_counter);
        if (ret != TEE_SUCCESS) {
            tloge("increment failcounter fail, ret:0x%x", ret);
            return TEE_ERROR_MAC_INVALID;
        }
        get_wait_time_and_retry_times(failure_counter, &wait_time, &retry_times);
        if (wait_time != 0) {
            tloge("verify fail, need wait %u ms", wait_time);
            return wait_time;
        }
        return TEE_ERROR_MAC_INVALID;
    }
    return TEE_SUCCESS;
}

static TEE_Result check_password_internal(uint32_t uid,
    const struct password_handle_t *password_handle,
    const uint8_t *password, uint32_t password_size)
{
    TEE_Result ret = TEE_SUCCESS;
    uint8_t hmac[HMAC_SIZE] = {0};

    struct gk_buffer pwd_hash = {0};
    pwd_hash.buff = (uintptr_t)password;
    pwd_hash.size = password_size;
    if (!password_handle_hmac(uid, password_handle, &pwd_hash, hmac, HMAC_SIZE)) {
        tloge("password_handle_hmac failed");
        return TEE_ERROR_GENERIC;
    }

    if (password_handle->version < HANDLE_VERSION_5) {
        // Preventing power-off attacks
        increment_failrecord(uid, password_handle->user_id, password_handle->version);
        if (TEE_MemCompare(hmac, password_handle->signature, HMAC_SIZE) != 0) {
            tloge("TEE_MemCompare failed, version:%u\n", (uint32_t)(password_handle->version));
            return TEE_ERROR_MAC_INVALID;
        }
        gatekeeper_delete_fail_record(uid, password_handle->version, password_handle->user_id);
    } else {
       /*
        * The rpmb status is false, which indicates that there is a failure to write the rpmb.
        * In this situation, increase the count before the verification.
        */
        if (!g_rpmb_status_ok || g_first_verify)
            ret = check_password_increase_counter_first(uid, password_handle, hmac);
        else
            ret = check_password_increase_counter_later(uid, password_handle, hmac);
        g_first_verify = false;
        if (ret != TEE_SUCCESS)
            return ret;

        ret = gatekeeper_clear_fail_counter(uid, password_handle);
        if (ret != TEE_SUCCESS)
            return TEE_ERROR_MAC_INVALID;
    }

    return ret;
}

static TEE_Result gatekeeper_add_fail_record(uint32_t uid,
    const struct password_handle_t *password_handle)
{
    // update version
    struct failure_record_uid_t record_uid = {0};
    record_uid.uid = uid;
    record_uid.version = password_handle->version;
    errno_t rc = memcpy_s(record_uid.signature, sizeof(record_uid.signature),
                          password_handle->signature, sizeof(password_handle->signature));
    if (rc != EOK) {
        tloge("mem copy fail!");
        return TEE_ERROR_SECURITY;
    }

    record_uid.record.secure_user_id = password_handle->user_id;
    record_uid.record.last_checked_timestamp = get_rtc_time();

    if (add_fail_record(&record_uid, false)) {
        TEE_Result ret = shadow_fail_record_into_rpmb(&record_uid);
        if (ret != TEE_SUCCESS) {
            tloge("write rpmb error, ret:0x%x", ret);
            return TEE_ERROR_GENERIC;
        }
    } else {
        tloge("add_fail_record failed\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    return TEE_SUCCESS;
}

static TEE_Result update_pwd(uint32_t uid, struct password_handle_t *password_handle,
                             const uint8_t *desire_pw, uint32_t desire_pw_size)
{
    TEE_Result ret;
    tlogd("-- update pwd uid --\n");

    password_handle->version = HANDLE_VERSION_6;
    if (uid >= PRIMARY_FAKE_USER_ID &&
        tee_ext_pincode_register_pin(NULL, NULL, NULL, NULL) != PINCODE_ERR_NOT_SUPPORTED &&
        g_ext_pincode_flag != NOT_SUPPORT) {
        password_handle->version = HANDLE_VERSION_7;
        (void)tee_ext_pincode_poweron();
    }

    TEE_GenerateRandom(&password_handle->salt, sizeof(password_handle->salt));
    if (password_handle->salt == 0) {
        tloge("password_handle->salt is 0\n");
        ret = TEE_ERROR_GENERIC;
        goto power_off;
    }
    struct gk_buffer password = {0};
    password.buff = (uintptr_t)desire_pw;
    password.size = desire_pw_size;
    if (!password_handle_hmac(uid, password_handle, &password, password_handle->signature, HMAC_SIZE)) {
        tloge("hmac for password_handle failed\n");
        ret = TEE_ERROR_MAC_INVALID;
        goto power_off;
    }

    if (password_handle->version != HANDLE_VERSION_7)
        ret = TEE_SUCCESS;
    else
        ret = enroll_extra(uid, &password, password_handle);

power_off:
    if (password_handle->version == HANDLE_VERSION_7)
        (void)tee_ext_pincode_poweroff();

    return ret;
}

static TEE_Result enroll_param_check(TEE_Param *params)
{
    if (params[TEE_PARAM_2].memref.buffer == NULL) {
        tloge("invalid desire_pw buffer");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    bool con = ((params[TEE_PARAM_2].memref.size == 0) ||
                (params[TEE_PARAM_2].memref.size > PASSWORD_MAX_SZIE));
    if (con) {
        tloge("invalid desire_pw_size");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (params[TEE_PARAM_3].memref.buffer == NULL) {
        tloge("invalid handle");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    con = ((params[TEE_PARAM_3].memref.size < sizeof(struct gatekeeper_handle)) ||
           (params[TEE_PARAM_3].memref.size > PAGE_SIZE));
    if (con) {
        tloge("invalid desire_pw_size");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    return TEE_SUCCESS;
}

static TEE_Result enroll_password(TEE_Param *params)
{
    TEE_Result ret;

    ret = enroll_param_check(params);
    if (ret != TEE_SUCCESS) {
        tloge("invalid param for enroll cmd");
        return ret;
    }

    uint8_t *desire_pw = (uint8_t *)params[TEE_PARAM_2].memref.buffer;
    uint32_t desire_pw_size = params[TEE_PARAM_2].memref.size;
    struct gatekeeper_handle *out_handle = (struct gatekeeper_handle *)params[TEE_PARAM_3].memref.buffer;

    if (params[TEE_PARAM_3].memref.buffer == NULL) {
        tloge("invalid uid buffer");
        (void)memset_s(desire_pw, desire_pw_size, 0, desire_pw_size);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    uint32_t uid = *(uint32_t *)params[TEE_PARAM_3].memref.buffer;
    tlogd("enroll_password, uid:%u", uid);

    ret = create_gatekeeper_handle(out_handle, uid, desire_pw, desire_pw_size);
    (void)memset_s(desire_pw, desire_pw_size, 0, desire_pw_size);
    if (ret != TEE_SUCCESS) {
        tloge("create gatekeeper handle failed, %x\n", ret);
        return ret;
    }

    ret = gatekeeper_add_fail_record(uid, &(out_handle->password_handle));
    if (ret != TEE_SUCCESS) {
        tloge("add fail record fail:0x%08X", ret);
        return ret;
    }

    params[TEE_PARAM_3].memref.size = sizeof(*out_handle);
    return ret;
}

static TEE_Result anti_brute_force_attack(uint32_t uid,
    const struct password_handle_t *password_handle)
{
    if (password_handle->version < HANDLE_VERSION_5)
        return check_fail(uid, password_handle->user_id, password_handle->version);
    else
        return gatekeeper_retry_timeout(uid, password_handle);
}

static TEE_Result modify_param_check(const TEE_Param *params)
{
    struct gatekeeper_handle *in_handle = (struct gatekeeper_handle *)params[TEE_PARAM_0].memref.buffer;
    uint32_t in_handle_size = params[TEE_PARAM_0].memref.size;
    struct password_data cur_pw = { (uint8_t *)params[TEE_PARAM_1].memref.buffer, params[TEE_PARAM_1].memref.size };
    struct password_data desire_pw = { (uint8_t *)params[TEE_PARAM_2].memref.buffer, params[TEE_PARAM_2].memref.size };
    struct gatekeeper_handle *out_handle = (struct gatekeeper_handle *)params[TEE_PARAM_3].memref.buffer;
    uint32_t out_handle_size = params[TEE_PARAM_3].memref.size;

    bool con = ((in_handle == NULL) || (in_handle_size != sizeof(*in_handle)));
    if (con) {
        tloge("invalid in_handle info:in_handle_size=%u", in_handle_size);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    con = ((cur_pw.buffer == NULL) || ((cur_pw.size == 0) || (cur_pw.size > PASSWORD_MAX_SZIE)));
    if (con) {
        tloge("invalid cur_pw info:cur pw size=%u", cur_pw.size);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    con = ((desire_pw.buffer == NULL) || ((desire_pw.size == 0) || (desire_pw.size > PASSWORD_MAX_SZIE)));
    if (con) {
        tloge("invalid desire pw info:desire pw size=%u", desire_pw.size);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    con = ((out_handle == NULL) ||
           ((out_handle_size < sizeof(*out_handle)) || (out_handle_size > PAGE_SIZE)));
    if (con) {
        tloge("invalid out_handle info:out_handle_size=%u", out_handle_size);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    return TEE_SUCCESS;
}

static TEE_Result modify_password(TEE_Param *params)
{
    TEE_Result ret = modify_param_check(params);
    if (ret != TEE_SUCCESS) {
        tloge("invalid param for modify");
        return ret;
    }

    struct gatekeeper_handle *in_handle = (struct gatekeeper_handle *)params[TEE_PARAM_0].memref.buffer;
    struct password_data cur_pw = { (uint8_t *)params[TEE_PARAM_1].memref.buffer, params[TEE_PARAM_1].memref.size };
    struct password_data desire_pw = { (uint8_t *)params[TEE_PARAM_2].memref.buffer, params[TEE_PARAM_2].memref.size };
    struct gatekeeper_handle *out_handle = (struct gatekeeper_handle *)params[TEE_PARAM_3].memref.buffer;
    struct password_handle_t *password_handle = &in_handle->password_handle;
    uint32_t uid = *(uint32_t *)params[TEE_PARAM_3].memref.buffer;

    ret = anti_brute_force_attack(uid, password_handle);
    if (ret != TEE_SUCCESS) {
        tloge("anti brute force");
        (void)memset_s(desire_pw.buffer, desire_pw.size, 0, desire_pw.size);
        (void)memset_s(cur_pw.buffer, cur_pw.size, 0, cur_pw.size);
        return ret;
    }

    ret = check_password_internal(uid, password_handle, cur_pw.buffer, cur_pw.size);
    (void)memset_s(cur_pw.buffer, cur_pw.size, 0, cur_pw.size);
    if (ret != TEE_SUCCESS) {
        tloge("check password fail:0x%08X", ret);
        (void)memset_s(desire_pw.buffer, desire_pw.size, 0, desire_pw.size);
        return ret;
    }

    ret = update_pwd(uid, password_handle, desire_pw.buffer, desire_pw.size);
    (void)memset_s(desire_pw.buffer, desire_pw.size, 0, desire_pw.size);
    if (ret != TEE_SUCCESS) {
        tloge("compare and update failed\n");
        return ret;
    }

    if (memcpy_s(out_handle, sizeof(*out_handle), in_handle, sizeof(*in_handle)) != EOK) {
        tloge("memcpy_s failed\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    params[TEE_PARAM_3].memref.size = sizeof(struct gatekeeper_handle);

    // update fail record
    ret = gatekeeper_add_fail_record(uid, &(out_handle->password_handle));
    if (ret != TEE_SUCCESS)
        tloge("add fail record fail:0x%08X", ret);

    return ret;
}

static bool generate_authtoken(struct auth_token_t *token, uint64_t user_id, uint64_t challenge)
{
    errno_t rc;
    bool ret = true;
    uint8_t rot[ROT_SIZE] = {0};
    uint64_t timestamp = 0;

    if (token == NULL) {
        tloge("input is invalid\n");
        return false;
    }
    get_system_time(&timestamp);

    token->version      = HW_AUTH_TOKEN_VERSION;
    token->challenge    = challenge;
    token->user_id      = user_id;
    token->authenticator_id     = 0x1;
    token->authenticator_type   = hton(AUTH_PASSWORD);
    token->timestamp            = ((((uint64_t)(hton((uint32_t)(timestamp)))) << BIT_32) |
                                   ntoh((uint32_t)(timestamp >> BIT_32)));

    rc = __SRE_GetKMROT(rot, ROT_SIZE);
    if (rc != 0) {
        tloge("authtoken generation get rot failed:0x%08X", rc);
        ret = false;
        goto error;
    }

    rc = compute_hmac((uint8_t *)token, sizeof(*token) - HMAC_SIZE, rot, token->hmac, HMAC_SIZE);
    if (rc != 0) {
        tloge("authtoken_hmac failed\n");
        ret = false;
        goto error;
    }

    tlogd("authtoken generation success\n");

error:
    (void)memset_s(rot, sizeof(rot), 0, sizeof(rot));

    return ret;
}

static TEE_Result verify_param_check(uint32_t param_types, TEE_Param *params)
{
    if (!check_param_type(param_types,
                          TEE_PARAM_TYPE_VALUE_INOUT,
                          TEE_PARAM_TYPE_MEMREF_INPUT,
                          TEE_PARAM_TYPE_MEMREF_INPUT,
                          TEE_PARAM_TYPE_MEMREF_INOUT)) {
        tloge("invalid params");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    bool con = (params[TEE_PARAM_1].memref.buffer == NULL) ||
               (params[TEE_PARAM_1].memref.size != sizeof(struct gatekeeper_handle));
    if (con) {
        tloge("invalid in_handle_size");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    con = (params[TEE_PARAM_2].memref.buffer == NULL) ||
          (params[TEE_PARAM_2].memref.size == 0) ||
          (params[TEE_PARAM_2].memref.size > PASSWORD_MAX_SZIE);
    if (con) {
        tloge("invalid cur_pw_size");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    con = (params[TEE_PARAM_3].memref.buffer == NULL) ||
        (params[TEE_PARAM_3].memref.size != PAGE_SIZE);
    if (con) {
        tloge("invalid param3");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    return TEE_SUCCESS;
}

/*
* input:
* params[1]: gatekeeper handle
* params[2]: current password
*
* inout:
* params[0]: in: value.a:uid, out: value.b:request_reenroll
* params[3]: in:challenge, out:authtoken
*/
static TEE_Result verify(uint32_t param_types, TEE_Param *params)
{
    TEE_Result ret = verify_param_check(param_types, params);
    if (ret != TEE_SUCCESS) {
        tloge("param check error:0x%08X", ret);
        return ret;
    }

    params[TEE_PARAM_0].value.b = false;
    struct gatekeeper_handle *in_handle = (struct gatekeeper_handle *)params[TEE_PARAM_1].memref.buffer;
    struct password_data cur_pw = { (uint8_t *)params[TEE_PARAM_2].memref.buffer, params[TEE_PARAM_2].memref.size };
    uint32_t uid = params[TEE_PARAM_0].value.a;

    struct password_handle_t *password_handle = &in_handle->password_handle;

    ret = anti_brute_force_attack(uid, password_handle);
    if (ret != TEE_SUCCESS) {
        tloge("anti brute force");
        (void)memset_s(cur_pw.buffer, cur_pw.size, 0, cur_pw.size);
        return ret;
    }

    if (password_handle->version == HANDLE_VERSION_7)
        (void)tee_ext_pincode_poweron();

    ret = check_password_internal(uid, password_handle, cur_pw.buffer, cur_pw.size);
    if (password_handle->version == HANDLE_VERSION_7)
        (void)tee_ext_pincode_poweroff();
    (void)memset_s(cur_pw.buffer, cur_pw.size, 0, cur_pw.size);
    if (ret != TEE_SUCCESS) {
        tloge("check password fail:0x%08X, version:%u, uid:%u\n", ret, password_handle->version, uid);
        return ret;
    }

    if (uid >= PRIMARY_FAKE_USER_ID &&
        tee_ext_pincode_verify_pin(NULL, NULL, NULL, NULL) != PINCODE_ERR_NOT_SUPPORTED &&
        g_ext_pincode_flag != NOT_SUPPORT) {
        if (password_handle->version < HANDLE_VERSION_7)
            params[0].value.b = true;
    } else {
        if (password_handle->version < HANDLE_VERSION_6)
            params[0].value.b = true;
    }

    uint64_t challenge = *(uint64_t *)params[TEE_PARAM_3].memref.buffer;
    struct auth_token_t *token = (struct auth_token_t *)params[TEE_PARAM_3].memref.buffer;
    params[TEE_PARAM_3].memref.size = sizeof(*token);

    if (!generate_authtoken(token, password_handle->user_id, challenge)) {
        tloge("generate authtoken failed\n");
        return TEE_ERROR_GENERIC;
    }

    if (!update_auth_token(uid, (const uint8_t *)token, sizeof(*token))) {
        tloge("store authtoken to drvier failed\n");
        return TEE_ERROR_GENERIC;
    }

    set_lock_status(uid, UNLOCK_STATUS);
    return TEE_SUCCESS;
}

static TEE_Result delete_user(uint32_t param_types, const TEE_Param *params)
{
    TEE_Result ret;
    uint32_t uid;

    if (!check_param_type(param_types,
                          TEE_PARAM_TYPE_VALUE_INPUT,
                          TEE_PARAM_TYPE_NONE,
                          TEE_PARAM_TYPE_NONE,
                          TEE_PARAM_TYPE_NONE)) {
        tloge("check param fail!");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    uid = params[TEE_PARAM_0].value.a;

    tlogd("delete user enter, uid:%u", uid);

    struct failure_record_uid_t record_uid = {0};
    record_uid.uid = uid;
    record_uid.version = HANDLE_VERSION_7;

    if (!read_fail_record(&record_uid)) {
        tloge("read failrecord failed\n");
        return TEE_ERROR_GENERIC;
    }

    (void)__delete_key_factor(record_uid.record.secure_user_id);

    if (!delete_fail_record(&record_uid)) {
        tloge("clear_failrecord failed\n");
        return TEE_ERROR_GENERIC;
    }

    if (uid == PRIMARY_FAKE_USER_ID) {
        ret = TEE_RPMB_FS_Rm(PRIMARY_RECORD_RPMB_FILENAME);
        if (ret != TEE_SUCCESS)
            tloge("rm primary record error:0x%08X", ret);
    } else {
        ret = write_sub_user_record_to_rpmb();
        if (ret != TEE_SUCCESS)
            tloge("write rpmb error:0x%08X", ret);
    }

    (void)delete_auth_token(uid);

    return ret;
}

static TEE_Result get_retry_times(uint32_t param_types, TEE_Param *params)
{
    uint32_t uid;
    struct failure_record_uid_t record_uid = {0};
    uint32_t wait_time = 0;
    uint32_t retry_times = 0;
    uint32_t timeout = 0;

    if (!check_param_type(param_types,
                          TEE_PARAM_TYPE_VALUE_INPUT,
                          TEE_PARAM_TYPE_VALUE_OUTPUT,
                          TEE_PARAM_TYPE_NONE,
                          TEE_PARAM_TYPE_NONE)) {
        tloge("param check fail!");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    uid = params[TEE_PARAM_0].value.a;

    record_uid.uid = uid;
    record_uid.version = HANDLE_VERSION_7;
    if (!read_fail_record(&record_uid)) {
        tloge("cannot find record, uid:%u", uid);
        return TEE_ERROR_ITEM_NOT_FOUND;
    }

    get_wait_time_and_retry_times(record_uid.record.failure_counter,
                                  &wait_time, &retry_times);

    if (gatekeeper_get_timeout(wait_time, &record_uid, &timeout) != TEE_SUCCESS)
        tloge("gate keeper get time out fail\n");
    if (timeout != 0)
        params[TEE_PARAM_1].value.a = 0; // Timeout status, the retry times is 0.
    else
        params[TEE_PARAM_1].value.a = retry_times;

    tlogd("get_retry_times, retry_times:%u", retry_times);

    return TEE_SUCCESS;
}

static pthread_mutex_t g_lock_status_mutex = PTHREAD_ROBUST_MUTEX_INITIALIZER;
static void set_lock_status(uint32_t uid, uint32_t status)
{
    if (uid != PRIMARY_USER_ID)
        return;

    if (gk_mutex_lock_ops(&g_lock_status_mutex) != 0) {
        tloge("get mutex lock failed\n");
        return;
    }

    g_lock_status = status;

    (void)pthread_mutex_unlock(&g_lock_status_mutex);
}

static TEE_Result gk_set_lock_status(uint32_t param_types, TEE_Param *params)
{
    if (!check_param_type(param_types,
                          TEE_PARAM_TYPE_VALUE_INPUT,
                          TEE_PARAM_TYPE_VALUE_OUTPUT,
                          TEE_PARAM_TYPE_NONE,
                          TEE_PARAM_TYPE_NONE)) {
        tloge("param check fail!");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    set_lock_status(params[TEE_PARAM_0].value.a, LOCK_STATUS);

    params[TEE_PARAM_1].value.a = 0;

    return TEE_SUCCESS;
}

static bool check_get_lock_status_permission(const caller_info *caller_info)
{
    TEE_UUID uuid = TEE_SERVICE_WALLET;
    TEE_UUID caller_uuid = caller_info->caller_identity.caller_uuid;

    if (caller_info->session_type != SESSION_FROM_TA)
        return false;

    if (TEE_MemCompare(&caller_uuid, &uuid, sizeof(uuid)) == 0)
        return true;

    return false;
}

static TEE_Result gk_get_lock_status(uint32_t param_types, TEE_Param *params, const caller_info *caller_info)
{
    if (!check_get_lock_status_permission(caller_info)) {
        tloge("no permission for get lock status\n");
        return TEE_ERROR_ACCESS_DENIED;
    }

    if (!check_param_type(param_types,
                          TEE_PARAM_TYPE_VALUE_OUTPUT,
                          TEE_PARAM_TYPE_NONE,
                          TEE_PARAM_TYPE_NONE,
                          TEE_PARAM_TYPE_NONE)) {
        tloge("param check fail!");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (gk_mutex_lock_ops(&g_lock_status_mutex) != 0) {
        tloge("get mutex lock failed\n");
        return TEE_ERROR_GENERIC;
    }

    params[TEE_PARAM_0].value.a = g_lock_status;

    (void)pthread_mutex_unlock(&g_lock_status_mutex);

    return TEE_SUCCESS;
}

static void write_record_to_mem(struct failure_record_uid_t *array, uint32_t len)
{
    for (uint32_t index = 0; index < len / sizeof(*array); index++) {
        if (!add_fail_record(&array[index], true)) {
            tloge("add fail record fail\n");
            continue;
        }

        tlogd("init fail record: index:%u uid:%u", index,  array[index].uid);
        tlogd("init fail record: index:%u version:%u", index,  array[index].version);
        tlogd("init fail record: index:%u signature[0]:%hu", index,  array[index].signature[0]);
        tlogd("init fail record: index:%u secure_user_id:0x%llx", index,  array[index].record.secure_user_id);
        tlogd("init fail record: index:%u timestamp:0x%llx", index, array[index].record.last_checked_timestamp);
        tlogd("init fail record: index:%u failure_counter:%u", index, array[index].record.failure_counter);
    }
}

static TEE_Result init_record_sub_user(void)
{
    TEE_Result ret;
    uint32_t count = 0;
    struct rpmb_fs_stat file_state = {0};
    struct failure_record_uid_t *array = NULL;

    ret = TEE_RPMB_FS_Stat(FAIL_RECORD_RPMB_FILENAME, &file_state);
    if (ret != TEE_SUCCESS) {
        tloge("Query file info error:0x%08X", ret);
        return ret;
    }

    tlogd("file size is %u", file_state.size);

    array = (struct failure_record_uid_t *)TEE_Malloc(file_state.size, 0);
    if (array == NULL) {
        tloge("malloc memory error");
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    ret = TEE_RPMB_FS_Read(FAIL_RECORD_RPMB_FILENAME, (uint8_t *)array, file_state.size, &count);
    if (ret != TEE_SUCCESS) {
        tloge("read rpmb error:0x%08X", ret);
        goto clean;
    }

    if (count != file_state.size) {
        tloge("read count error, count:%u", count);
        ret = TEE_ERROR_GENERIC;
        goto clean;
    }

    if (count % sizeof(*array) != 0) {
        tloge("rpmb file size is error, size:%u", count);
        ret = TEE_ERROR_GENERIC;
        goto clean;
    }

    write_record_to_mem(array, count);
    ret = TEE_SUCCESS;
clean:
    TEE_Free(array);
    return ret;
}

static TEE_Result init_record_primary(void)
{
    TEE_Result ret;
    uint32_t count = 0;
    struct failure_record_uid_t *buffer = NULL;
    uint32_t record_len = sizeof(struct failure_record_uid_t);

    buffer = (struct failure_record_uid_t *)TEE_Malloc(record_len, 0);
    if (buffer == NULL) {
        tloge("malloc memory error");
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    ret = TEE_RPMB_FS_Read(PRIMARY_RECORD_RPMB_FILENAME, (uint8_t *)buffer, record_len, &count);
    if (ret != TEE_SUCCESS) {
        tloge("read user file fail, ret:0x%x", ret);
        goto clean;
    }

    if (count != record_len) {
        tloge("read count error, count:%u", count);
        ret = TEE_ERROR_GENERIC;
        goto clean;
    }

    write_record_to_mem(buffer, count);
    ret = TEE_SUCCESS;
clean:
    TEE_Free(buffer);
    return ret;
}

void init_fail_record(void)
{
    TEE_Result ret;

    if (g_init_fail_record != 0) /* fail record has already been initial */
        return;

    tlogd("init_fail_record");

    if (tee_ext_pincode_register_pin(NULL, NULL, NULL, NULL) != PINCODE_ERR_NOT_SUPPORTED) {
        uint32_t count = 0;
        ret = TEE_RPMB_FS_Read(PINCODE_FLAG_FILE, (uint8_t *)&g_ext_pincode_flag, sizeof(g_ext_pincode_flag), &count);
        if (ret != TEE_SUCCESS)
            g_ext_pincode_flag = INVALID;
    }

    init_fail_list();

    ret = init_record_primary();
    if (ret != TEE_SUCCESS)
        tloge("init primary record fail, ret:0x%x", ret);

    ret = init_record_sub_user();
    if (ret != TEE_SUCCESS)
        tloge("init sub user record fail:0x%08x", ret);

    g_init_fail_record++;
    if (!duplicate_record_exist())
        return;

    struct failure_record_uid_t primary_record;
    if (read_primary_fail_record(&primary_record)) {
        ret = write_primary_user_record_to_rpmb(&primary_record);
        if (ret == TEE_SUCCESS)
            (void)write_sub_user_record_to_rpmb();
    }
}
__attribute__((visibility("default"))) TEE_Result TA_CreateEntryPoint(void)
{
    TEE_Result ret;

    ret = AddCaller_CA_exec(GATEKEEPER_HIDL_SERVICE_PKGN, GATEKEEPER_HIDL_SERVICE_UID);
    if (ret != TEE_SUCCESS)
        return ret;

    ret = AddCaller_CA_exec(SYSTEM_SERVER, SYSTEM_SERVER_SERVICE_UID);
    if (ret != TEE_SUCCESS)
        return ret;

    ret = AddCaller_TA_all();
    if (ret != TEE_SUCCESS)
        return ret;

    // init record list
    init_fail_record();

    tlogd("gatekeeper:succeed to CreateEntryPoint\n");

    return ret;
}

#define MAX_PACKAGE_NAME_LEN 255
__attribute__((visibility("default"))) TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
    TEE_Param params[TEE_PARAM_COUNT], void **session_context)
{
    caller_info gk_caller_info = {0};

    TEE_Result ret = TEE_EXT_GetCallerInfo(&gk_caller_info, sizeof(gk_caller_info));
    if (ret != TEE_SUCCESS)
        return ret;

    if (gk_caller_info.session_type == SESSION_FROM_TA)
        return TEE_SUCCESS;

    bool check_param = (TEE_PARAM_TYPE_GET(param_types, TEE_PARAM_3) == TEE_PARAM_TYPE_MEMREF_INPUT ||
                        TEE_PARAM_TYPE_GET(param_types, TEE_PARAM_3) == TEE_PARAM_TYPE_MEMREF_OUTPUT ||
                        TEE_PARAM_TYPE_GET(param_types, TEE_PARAM_3) == TEE_PARAM_TYPE_MEMREF_INOUT);
    if (!check_param)
        return TEE_ERROR_BAD_PARAMETERS;

    struct session_identity *identity = (struct session_identity *)NULL;
    uint32_t pkg_name_len = params[TEE_PARAM_3].memref.size;
    *session_context = NULL;

    if (pkg_name_len == 0 ||
        pkg_name_len >= MAX_PACKAGE_NAME_LEN) {
        tloge("Invalid size of package name len login info!\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    identity = (struct session_identity *)TEE_Malloc(sizeof(struct session_identity) + pkg_name_len, 0);
    if (identity == NULL) {
        tloge("Failed to allocate mem for session_identify\n");
        return TEE_ERROR_GENERIC;
    }

    identity->len = pkg_name_len;
    if (memmove_s((void *)(identity->val), identity->len,
                  params[TEE_PARAM_3].memref.buffer, identity->len) != EOK) {
        TEE_Free((void *)identity);
        return TEE_ERROR_SECURITY;
    }

    /* set session context */
    *session_context = (void *)identity;
    return TEE_SUCCESS;
}

static bool is_ta_access_ok(uint32_t cmd_id)
{
    if (cmd_id == GK_CMD_ID_GET_LOCK_STATUS)
        return true;
    else if (cmd_id == GK_CMD_ID_GET_AUTH_TOKEN)
        return true;
    else
        return false;
}

static bool is_identity_valid(const struct session_identity *identity, uint32_t cmd_id)
{
    if (identity == NULL)
        return false;

    bool check_hidl = (strlen(identity->val) == strlen(GATEKEEPER_HIDL_SERVICE_PKGN)) &&
                      (TEE_MemCompare(identity->val, GATEKEEPER_HIDL_SERVICE_PKGN,
                                      strlen(GATEKEEPER_HIDL_SERVICE_PKGN)) == 0);
    bool check_system_server = (strlen(identity->val) == strlen(SYSTEM_SERVER)) &&
                               (TEE_MemCompare(identity->val, SYSTEM_SERVER, strlen(SYSTEM_SERVER)) == 0) &&
                               (cmd_id == GK_CMD_ID_GET_RETRY_TIMES || cmd_id == GK_CMD_ID_SET_LOCK_STATUS);
    if (check_hidl || check_system_server)
        return true;

    return false;
}

static bool is_access_check_ok(const struct session_identity *identity, uint32_t cmd_id,
    const caller_info *caller_info)
{
    if (caller_info->session_type == SESSION_FROM_TA)
        return is_ta_access_ok(cmd_id);

    return is_identity_valid(identity, cmd_id);
}

static TEE_Result enroll_proc(uint32_t param_types, TEE_Param *params)
{
    if (check_param_type(param_types,
                         TEE_PARAM_TYPE_NONE,
                         TEE_PARAM_TYPE_NONE,
                         TEE_PARAM_TYPE_MEMREF_INPUT,
                         TEE_PARAM_TYPE_MEMREF_INOUT)) {
        tlogd("InvokeCommand enroll password");
        return enroll_password(params);
    }

    if (check_param_type(param_types,
                         TEE_PARAM_TYPE_MEMREF_INPUT,
                         TEE_PARAM_TYPE_MEMREF_INPUT,
                         TEE_PARAM_TYPE_MEMREF_INPUT,
                         TEE_PARAM_TYPE_MEMREF_INOUT)) {
        tlogd("InvokeCommand modify password");
        return modify_password(params);
    }

    return TEE_ERROR_BAD_PARAMETERS;
}

__attribute__((visibility("default"))) TEE_Result TA_InvokeCommandEntryPoint(void *session_context,
    uint32_t cmd_id, uint32_t param_types, TEE_Param params[TEE_PARAM_COUNT])
{
    TEE_Result ret;
    struct session_identity *identity = (struct session_identity *)session_context;
    caller_info caller_info = {0};

    ret = TEE_EXT_GetCallerInfo(&caller_info, sizeof(caller_info));
    if (ret != TEE_SUCCESS)
        return TEE_ERROR_ACCESS_DENIED;

    if (!is_access_check_ok(identity, cmd_id, &caller_info))
        return TEE_ERROR_ACCESS_DENIED;

    switch (cmd_id) {
    case GK_CMD_ID_ENROLL:
        ret = enroll_proc(param_types, params);
        break;
    case GK_CMD_ID_VERIFY:
        ret = verify(param_types, params);
        break;
    case GK_CMD_ID_DEL_USER:
        ret = delete_user(param_types, params);
        break;
    case GK_CMD_ID_GET_RETRY_TIMES:
        ret = get_retry_times(param_types, params);
        break;
    case GK_CMD_ID_SET_LOCK_STATUS:
        ret = gk_set_lock_status(param_types, params);
        break;
    case GK_CMD_ID_GET_LOCK_STATUS:
        ret = gk_get_lock_status(param_types, params, &caller_info);
        break;
    case GK_CMD_ID_GET_AUTH_TOKEN:
        ret = gk_get_auth_token_timestamp(param_types, params, &caller_info);
        break;
    default:
        tloge("Invalid gatekeeper CMD ID");
        ret = TEE_ERROR_INVALID_CMD;
        break;
    }

    tlogd("gatekeeper invoke cmd:%u ret=0x%x", cmd_id, ret);
    return  ret;
}

__attribute__((visibility("default"))) void TA_CloseSessionEntryPoint(void *session_context)
{
    if (session_context != NULL)
        TEE_Free(session_context);

    tlogd("gatekeeper:Succeed to CloseSession\n");
}

__attribute__((visibility("default"))) void TA_DestroyEntryPoint(void)
{
    tlogd("gatekeeper:Succeed to DestoryEntryPoint\n");
}
