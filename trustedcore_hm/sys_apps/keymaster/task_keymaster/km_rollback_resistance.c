/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2019. All rights reserved.
 * Description: keymaster rollback resistance
 * Create: 2012-01-17
 */
#if (defined(TEE_SUPPORT_RPMB_64BIT) || defined(TEE_SUPPORT_RPMB_32BIT))
#include "km_rollback_resistance.h"
#include "tee_mem_mgmt_api.h"
#include "tee_crypto_api.h"
#include "tee_ext_api.h"
#include "tee_log.h"
#include "keymaster_defs.h"
#include "securec.h"
#include "km_env.h"
#include "tee_crypto_api.h"
#include "crypto_wrapper.h"
#include "rpmb_fcntl.h"
#include "pthread.h"
#include "tee_ext_api.h"
#include "km_key_check.h"
#include "km_tag_operation.h"

#define KB_META_FILE_COUNT 10
#define METADATA_VERSION 100
static const char *g_filename_prefix = "/rollback_resistance/kb_metadatas_";

static int kmds_delete_metadata(meta_file_t *meta_file, const uint8_t *metadata, uint32_t metadata_len)
{
    int ret;
    bool condition_check = ((meta_file == NULL) || (metadata == NULL) || (metadata_len != HMAC_SIZE));
    if (condition_check == true) {
        tloge("Invalid input parameters\n");
        return -1;
    }
    if (meta_file->count_used == 0) {
        tloge("meta file hasn't any element,no need to delete\n");
        return 0;
    }

    uint32_t i = 0;
    for (; i < meta_file->count_used; i++)
        if (!TEE_MemCompare(meta_file->n[i].hmac, metadata, HMAC_SIZE)) {
            tlogd("old metadata found in kmds\n ");
            /* move the elements at [i+1]-[count_used-1] to position at [i] */
            condition_check =
                ((i != (meta_file->count_used - 1)) &&
                 memmove_s(&meta_file->n[i], sizeof(meta_element_t) * (meta_file->count_used - i - 1),
                           &meta_file->n[i + 1], sizeof(meta_element_t) * (meta_file->count_used - i - 1)));
            if (condition_check == true) {
                tloge("memmove_s failed\n");
                return -1;
            }

            ret =
                memset_s(&meta_file->n[(meta_file->count_used) - 1], sizeof(meta_element_t), 0, sizeof(meta_element_t));
            if (ret != EOK) {
                tloge("clear the last node failed\n");
                return -1;
            }

            meta_file->count_used--;
            tlogd("delete metadata successful\n");
            return 0;
        }
    tloge("delete metadata:not found, no need to delete\n");
    return 0;
}

#define ROOTSTATE_BIT 0

static bool is_rooted()
{
    uint32_t root_status = TEE_EXT_DeviceRootStatus();
    if ((root_status & (0x1 << ROOTSTATE_BIT)) != 0U) {
        tloge("Device rooted\n");
        return true;
    }
    return false;
}

/*    support notify delete operation. Do not operate file here.
 *   Return code:
 *   (KM_ERROR_OK)-->OK,
 *   (KM_ERROR_INVALID_KEY_BLOB)-->must delete the metadata
 *   ([OTHERS])-->Failed,
 */
static keymaster_error_t eima_policy_check(uint8_t compromised)
{
    keymaster_error_t ret;
    switch (compromised) {
    case KB_ENABLE:
        ret = KM_ERROR_OK;
        break;
    case KB_DISABLE:
        ret = (is_rooted() ? KM_ERROR_ROOT_OF_TRUST_ALREADY_SET : KM_ERROR_OK);
        break;
    case KB_DELETE:
        if (is_rooted()) {
            tlogd("need delete meta data with policy\n");
            ret = KM_ERROR_INVALID_KEY_BLOB;
        } else {
            ret = KM_ERROR_OK;
        }
        break;
    default:
        tloge("invalid p_compromised 0x%x\n", compromised);
        ret = KM_ERROR_INVALID_ARGUMENT;
    }
    return ret;
}

static TEE_Result handle_eima_policy_check(const ctl_eima_policy_t *key_policy, meta_file_t *kmds,
    const uint8_t *kb_hmac, uint32_t kb_hmac_len)
{
    TEE_Result ret;
    keymaster_error_t check_ret;

    check_ret = eima_policy_check(key_policy->p_compromised);
    if (check_ret == KM_ERROR_INVALID_KEY_BLOB) {
        /* Need delete metadata with policy and flush into a file. */
        ret = (TEE_Result)kmds_delete_metadata(kmds, kb_hmac, kb_hmac_len);
        if (ret != TEE_SUCCESS) {
            tloge("kmds_buffer execute eima_policy failed ret=0x%x\n", ret);
        } else {
            tlogd("execute eima_policy success, the changed buffer should be flushed back into the file\n");
            ret = TEE_ERROR_SYNC_DATA; /* The caller should flush the buffer into a file. */
        }
    } else if (check_ret != KM_ERROR_OK) {
        tloge("Keyblob eima_policy_check failed ret=0x%x\n", check_ret);
        ret = TEE_ERROR_GENERIC;
    } else {
        ret = TEE_SUCCESS;
    }
    return ret;
}

/* Return code:
 * TEE_ERROR_SYNC_DATA-->should write back the meta_file.
 * TEE_SUCCESS-->OK,
 * [Others]-->FAILED.
 */
static TEE_Result kmds_key_policy_check(const ctl_eima_policy_t *key_policy, meta_file_t *kmds, const uint8_t *kb_hmac,
                                        uint32_t kb_hmac_len)
{
    TEE_Result ret = TEE_ERROR_GENERIC;

    bool condition_check = ((key_policy == NULL) || (kmds == NULL) || (kb_hmac == NULL) || (kb_hmac_len != HMAC_SIZE));
    if (condition_check) {
        tloge("Bad input parameters\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (!key_policy->enabled)
        return TEE_SUCCESS;

    switch (key_policy->ctl_type) {
    case TYPE_CTL_NONE:
        ret = TEE_SUCCESS;
        break;
    case TYPE_CTL_EIMA_POLICY:
        ret = handle_eima_policy_check(key_policy, kmds, kb_hmac, kb_hmac_len);
        break;
    case TYPE_CTL_RESERVED:
        tlogd("reserved control type\n");
        ret = TEE_SUCCESS;
        break;
    default:
        tloge("invalid policy 0x%x\n", key_policy->ctl_type);
        return TEE_ERROR_NOT_IMPLEMENTED;
    }
    return ret;
}

static int kmds_init(meta_file_t *meta_file)
{
    errno_t ret;
    if (meta_file == NULL) {
        tloge("Invalid input parameters!\n");
        return -1;
    }

    meta_file->count      = MAX_NODE_COUNT;
    meta_file->count_used = 0;

    ret = memset_s(meta_file->n, MAX_NODE_COUNT * sizeof(meta_element_t), 0, MAX_NODE_COUNT * sizeof(meta_element_t));
    if (ret != EOK) {
        tloge("Init failed\n");
        return -1;
    }

    uint32_t i = 0;
    for (; i < meta_file->count; i++)
        meta_file->n[i].version = METADATA_VERSION;
    tlogd("meta_file_t inited\n");
    return 0;
}

/* Retrieve node index by metadata.
 * Return code:
 * value=-1,failed,
 * value>=0,the node index
 */
static int kmds_retrieve_metadata(meta_file_t *meta_file, const uint8_t *metadata, uint32_t metadata_len)
{
    int ret;
    bool condition_check = ((meta_file == NULL) || (metadata == NULL) || (metadata_len != HMAC_SIZE));
    if (condition_check) {
        tloge("Invalid input parameters\n");
        return -1;
    }

    uint32_t i = 0;
    for (; i < meta_file->count_used; i++) {
        ret = (int)TEE_MemCompare(meta_file->n[i].hmac, metadata, HMAC_SIZE);
        if (ret == 0) {
            tloge("HMAC found in kmds\n");
            return i;
        }
    }
    tloge("HMAC not found in kmds\n");
    return -1;
}

static int kmds_append_metadata(meta_file_t *meta_file, const uint8_t *metadata, uint32_t metadata_len)
{
    errno_t ret;

    bool condition_check = ((meta_file == NULL) || (metadata == NULL) || (metadata_len != HMAC_SIZE));
    if (condition_check) {
        tloge("Invalid input parameters\n");
        return -1;
    }
    if (meta_file->count <= meta_file->count_used) {
        tloge("meta file full\n");
        return -1;
    }

    uint32_t location = meta_file->count_used; /* Append an element */
    ret               = memcpy_s(meta_file->n[location].hmac, HMAC_SIZE, metadata, HMAC_SIZE);
    if (ret != EOK) {
        tloge("memcpy_s copy failed\n");
        return -1;
    }

    meta_file->n[location].version = METADATA_VERSION;
    meta_file->count_used++;
    tlogd("kmds_append_metadata successful\n");
    return 0;
}

static int kmds_update_metadata(meta_file_t *meta_file, const uint8_t *old_metadata, const uint8_t *new_metadata,
                                uint32_t metadata_len)
{
    errno_t ret;

    bool condition_check =
        ((meta_file == NULL) || (old_metadata == NULL) || (new_metadata == NULL) || (metadata_len != HMAC_SIZE));
    if (condition_check) {
        tloge("Invalid input parameters!\n");
        return -1;
    }

    uint32_t i = 0;
    for (; i < meta_file->count_used; i++)
        if (!TEE_MemCompare(meta_file->n[i].hmac, old_metadata, HMAC_SIZE)) {
            tlogd("old metadata found in kmds\n ");
            ret = memcpy_s(meta_file->n[i].hmac, HMAC_SIZE, new_metadata, HMAC_SIZE);
            if (ret != EOK) {
                tloge("memcpy_s copy failed\n");
                return -1;
            }
            tlogd("metadata updated\n");
            return 0;
        }
    tloge("metadata updating failed\n ");
    return -1;
}

/* Keey RPMB always store the valid data. */
static int check_file_integration(const meta_file_t *buffer, uint32_t read_count)
{
    bool condition_check = ((buffer == NULL) || (read_count < (sizeof(uint32_t) * DOUBLE_SIZE)));
    if (condition_check) {
        tloge("invalid parameter\n");
        return -1;
    }

    condition_check = ((buffer->count != MAX_NODE_COUNT) || (buffer->count_used > buffer->count) ||
                       (read_count != (sizeof(buffer->count) + sizeof(buffer->count_used) +
                                       (sizeof(meta_element_t) * buffer->count_used))));
    if (condition_check) {
        tloge("meta file integration verification failed\n");
        return -1;
    }
    tlogd("meta file integration verification succeeded\n");
    return 0;
}

static int32_t generate_file_name(char *out_buff, uint32_t buff_len, uint32_t index)
{
    int ret;
    bool condition_check = ((out_buff == NULL) || (buff_len < FILE_NAME_LEN) || (index >= KB_META_FILE_COUNT));
    if (condition_check) {
        tloge("Bad parameter\n");
        return -1;
    }

    ret = (int)memset_s(out_buff, buff_len, 0, buff_len);
    if (ret != EOK) {
        tloge("Bad parameter\n");
        return -1;
    }

    ret = snprintf_s(out_buff, buff_len, buff_len - 1, "%s%02d", g_filename_prefix, index);
    if (ret < 0) {
        tloge("generate_file_name failed\n");
        return -1;
    }

    tlogd("generate_file_name success\n");
    return 0;
}

/* If the hmac is found in a file, output the file name--[file_located] and its data--[outbuff]. */
TEE_Result kb_metafile_load(const uint8_t *kb_hmac, uint32_t kb_hmac_len, char *file_located,
                            uint32_t file_name_len, meta_file_t *outbuff)
{
    /* Caller should make sure the file_located has enough length. */
    bool condition_check = ((kb_hmac == NULL) || (kb_hmac_len != HMAC_SIZE) || (file_located == NULL) ||
                            (file_name_len < FILE_NAME_LEN) || (outbuff == NULL));
    if (condition_check) {
        tloge("invalid input, param may null or file name size is too small\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    char file_name[FILE_NAME_LEN] = { 0 };
    TEE_Result ret                = TEE_ERROR_GENERIC;
    uint32_t real_len             = 0;
    uint32_t i                    = 0;
    uint8_t *read_buff            = (uint8_t *)TEE_Malloc(sizeof(meta_file_t), 0);
    if (read_buff == NULL) {
        tloge("read _buffer malloc failed\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    for (; i < KB_META_FILE_COUNT; i++) {
        if (generate_file_name(file_name, FILE_NAME_LEN, i) < 0) {
            tloge("Generating file name failed\n");
            ret = TEE_ERROR_GENERIC;
            goto buff_free;
        }
        if (TEE_RPMB_FS_Read(file_name, (uint8_t *)read_buff, sizeof(meta_file_t), &real_len) != TEE_SUCCESS)
            continue;
        tlogd("File %s open, read size %u bytes\n", file_name, real_len);
        condition_check = ((check_file_integration((meta_file_t *)read_buff, real_len) == 0) &&
                           (kmds_retrieve_metadata((meta_file_t *)read_buff, kb_hmac, kb_hmac_len) >= 0));
        if (condition_check) {
            condition_check = ((snprintf_s(file_located, FILE_NAME_LEN, FILE_NAME_LEN - 1, "%s", file_name) < 0) ||
                memcpy_s((uint8_t *)outbuff, sizeof(meta_file_t), (uint8_t *)read_buff, sizeof(meta_file_t)));
            if (condition_check) {
                tloge("Copy data and filename for ouput failed\n");
                ret = TEE_ERROR_GENERIC;
                goto buff_free;
            }
            tlogd("kb_hmac found in the file %s\n", file_name);
            ret =  TEE_SUCCESS;
            goto buff_free;
        }
    }
    tloge("kb_metafile_load failed ret=0x%x\n", ret);
    ret = TEE_ERROR_ITEM_NOT_FOUND;
buff_free:
    TEE_Free(read_buff);
    read_buff = NULL;
    return ret;
}

static int alloc_read_buf(uint8_t **read_buff, uint32_t file_size)
{
    int ret_unlock;
    *read_buff = (uint8_t *)TEE_Malloc(file_size, 0);
    if (*read_buff == NULL) {
        tloge("read_buffer malloc failed");
        ret_unlock = pthread_mutex_unlock(get_opera_metafile_lock());
        check_if_unlock_failed_only_printf(ret_unlock);
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    return 0;
}

static int check_metafile_find(uint8_t **read_buff, int file_load_ret)
{
    int ret_unlock;
    if (file_load_ret) {
        tloge("kb_metafile_load failed or metadata not found ret=0x%x\n", file_load_ret);
        TEE_Free(*read_buff);
        *read_buff = NULL;
        ret_unlock = pthread_mutex_unlock(get_opera_metafile_lock());
        check_if_unlock_failed_only_printf(ret_unlock);
        return file_load_ret;
    }
    return 0;
}

/*
 * search the metadata in all specified name files in RPMB,
 * and do keyblob policy related operation.
 */
int kb_metafile_find(const uint8_t *kb_hmac, uint32_t kb_hmac_len)
{
    if ((kb_hmac == NULL) || (kb_hmac_len != HMAC_SIZE)) {
        tloge("invalid input, param may null\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    char file_name[FILE_NAME_LEN] = { 0 };
    uint32_t real_len;
    uint8_t *read_buff = NULL;
    int32_t ret = pthread_mutex_lock(get_opera_metafile_lock());
    if ((ret) != TEE_SUCCESS) {
        tloge("pthread_mutex_lock failed. ret=0x%x\n", ret);
        return ret;
    }
    int32_t ret_val = alloc_read_buf(&read_buff, sizeof(meta_file_t));
    if (ret_val != 0)
        return ret_val;
    ret     = (int32_t)kb_metafile_load(kb_hmac, kb_hmac_len, file_name, FILE_NAME_LEN, (meta_file_t *)read_buff);
    ret_val = check_metafile_find(&read_buff, ret);
    if (ret_val != 0)
        return ret_val;
    /*
     * In function 'kb_metafile_load' has checked
     * 'kmds_retrieve_metadata((meta_file_t*)read_buff,kb_hmac,kb_hmac_len)>=0', or return Non-zero error code for
     * handle.Now the meta file has been loaded and metadata exists in the buffer. The node index could not be less than
     * 0.
     */
    int32_t i = kmds_retrieve_metadata((meta_file_t *)read_buff, kb_hmac, kb_hmac_len);
    if (i < 0) {
        tloge("get i value is failed\n");
        ret = TEE_ERROR_ITEM_NOT_FOUND;
        goto unlock;
    }
    meta_file_t *tmp_file = (meta_file_t *)read_buff;
    ret = (int32_t)kmds_key_policy_check(&tmp_file->n[i].eima_policy, (meta_file_t *)read_buff, kb_hmac, kb_hmac_len);
    if ((TEE_Result)ret == TEE_ERROR_SYNC_DATA) {
        /* The buffer has been changed, it must be write back the file. */
        real_len = sizeof(uint32_t) * DOUBLE_SIZE + sizeof(meta_element_t) * tmp_file->count_used;
        if (TEE_RPMB_FS_Write(file_name, (uint8_t *)read_buff, real_len) == 0) {
            tloge("Keyblob deleted successfully according to EIMA, and return keyblob metedata non-exists\n");
            ret = TEE_ERROR_ITEM_NOT_FOUND;
            goto unlock;
        }
        tloge("Write read_buff back to file failed ret=0x%x, file=%s\n", ret, file_name);
    } else if (ret == TEE_SUCCESS) {
        tlogd("kmds_key_policy_check success\n");
    } else {
        tloge("kmds_key_policy_check failed ret=%d\n", ret);
    }
unlock:
    TEE_Free(read_buff);
    read_buff  = NULL;
    /* unlock and return */
    ret_val = pthread_mutex_unlock(get_opera_metafile_lock());
    check_if_unlock_failed_only_printf(ret_val);
    return ret;
}

static int check_metafile_write(uint8_t **read_buff, int32_t ret)
{
    int ret_unlock;
    if (ret == TEE_SUCCESS) {
        tloge("Metadata already existed,no need to append\n");
        /* If the hmac value exists, the reason could be HMAC collision or import the same keyblob twice.
         * The first reason means an error occured, should return.
         */
        TEE_Free(*read_buff);
        *read_buff = NULL;
        ret_unlock = pthread_mutex_unlock(get_opera_metafile_lock());
        check_if_unlock_failed_only_printf(ret_unlock);
        return TEE_SUCCESS;
    }
    return TEE_ERROR_BAD_STATE;
}

static int handle_rpmb_write(uint32_t index, char *file_name, const uint8_t *read_buff, uint32_t real_len)
{
    int ret;
    if (index < KB_META_FILE_COUNT) {
        /* The buffer has been filled vaild data node. Now write the buffer into the file. */
        ret = (int)TEE_RPMB_FS_Write(file_name, (uint8_t *)read_buff, real_len);
        if (ret != 0)
            tloge("TEE_RPMB_FS_Write failed ret=0x%x,fileName=%s", ret, file_name);
        else
            tlogd("kb_hmac written successfully into the file:%s\n", file_name);
    } else {
        ret = TEE_ERROR_GENERIC;
        tloge("kb_metafile_write failed ret=0x%x", ret);
    }
    return ret;
}

static int handle_generate_error(uint8_t **read_buff)
{
    int32_t ret_unlock;
    tloge("Generating file name failed\n");
    TEE_Free(*read_buff);
    *read_buff = NULL;
    ret_unlock = pthread_mutex_unlock(get_opera_metafile_lock());
    check_if_unlock_failed_only_printf(ret_unlock);
    return TEE_ERROR_GENERIC;
}

static TEE_Result handle_rpmb_file_not_found(uint8_t **read_buff, const uint8_t *kb_hmac, uint32_t kb_hmac_len,
                                             uint32_t *real_len)
{
    int32_t ret_unlock;
    /* build a new file and fill it the first metadata node. */
    if ((kmds_init((meta_file_t *)(*read_buff)) == 0) &&
        (kmds_append_metadata((meta_file_t *)(*read_buff), kb_hmac, kb_hmac_len) == 0)) {
        *real_len = sizeof(uint32_t) * DOUBLE_SIZE + sizeof(meta_element_t);
        /* build buffer success and must write back. ( i <KB_META_FILE_COUNT) */
        return TEE_SUCCESS;
    } else {
        tloge("Generate the meta_file_t with a first node data failed\n");
        TEE_Free(*read_buff);
        *read_buff  = NULL;
        ret_unlock = pthread_mutex_unlock(get_opera_metafile_lock());
        check_if_unlock_failed_only_printf(ret_unlock);
        return TEE_ERROR_GENERIC;
    }
    return TEE_SUCCESS;
}

static bool rpmb_size_need_add(uint8_t *read_buff, uint32_t real_len, const uint8_t *kb_hmac, uint32_t kb_hmac_len)
{
    if ((check_file_integration((meta_file_t *)read_buff, real_len) == 0) &&
        (real_len <= ((sizeof(uint32_t) * DOUBLE_SIZE) + ((MAX_NODE_COUNT - 1) * sizeof(meta_element_t)))) &&
        (kmds_append_metadata((meta_file_t *)read_buff, kb_hmac, kb_hmac_len) == 0))
        return true;

    return false;
}

/* There are several meta files, the function choose the first non-full file to write. */
int kb_metafile_write(const uint8_t *kb_hmac, uint32_t kb_hmac_len)
{
    if ((kb_hmac == NULL) || (kb_hmac_len != HMAC_SIZE)) {
        tloge("invalid input, param may null\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    /* search the data in all files. */
    char file_name[FILE_NAME_LEN] = { 0 };
    uint32_t real_len             = 0;
    uint32_t i                    = 0;
    uint8_t *read_buff            = NULL;
    int32_t ret                   = pthread_mutex_lock(get_opera_metafile_lock());
    if ((ret) != TEE_SUCCESS) {
        tloge("pthread_mutex_lock failed. ret=0x%x\n", ret);
        return ret;
    }
    int32_t ret_val = alloc_read_buf(&read_buff, sizeof(meta_file_t));
    if (ret_val != 0)
        return ret_val;
    ret = (int32_t)kb_metafile_load(kb_hmac, kb_hmac_len, file_name, FILE_NAME_LEN, (meta_file_t *)read_buff);
    /* if check success, read_buff will be free in check_metafile_write */
    if (check_metafile_write(&read_buff, ret) == TEE_SUCCESS)
        return TEE_SUCCESS;
    for (; i < KB_META_FILE_COUNT; i++) {
        if (generate_file_name(file_name, FILE_NAME_LEN, i) < 0)
            return handle_generate_error(&read_buff);
        ret = (int32_t)TEE_RPMB_FS_Read(file_name, (uint8_t *)read_buff, sizeof(meta_file_t), &real_len);
        if ((TEE_Result)ret == TEE_SUCCESS) {
            tlogd("File %s open, read size %u bytes\n", file_name, real_len);
            if (rpmb_size_need_add(read_buff, real_len, kb_hmac, kb_hmac_len)) {
                real_len += sizeof(meta_element_t);
                /* build buffer success and must write back.( i <KB_META_FILE_COUNT) */
                break;
            }
            tlogd("prepare buffer failed\n");
            /* if build buffer failed for the last meta file , the buffer should not be write back. */
            continue;
        } else if ((TEE_Result)ret == TEE_ERROR_RPMB_FILE_NOT_FOUND) {
            if (handle_rpmb_file_not_found(&read_buff, kb_hmac, kb_hmac_len, &real_len) == TEE_ERROR_GENERIC)
                return TEE_ERROR_GENERIC;
            break;
        } else {
            /* otherwise try to read next file. */
            tloge("Current file read failed.ret=0x%x, fileName=%s\n", ret, file_name);
            /* if build buffer failed for the last meta file , the buffer should not be write back. */
            continue;
        }
    }
    ret = handle_rpmb_write(i, file_name, read_buff, real_len);
    TEE_Free(read_buff);
    read_buff  = NULL;
    int32_t ret_unlock = pthread_mutex_unlock(get_opera_metafile_lock());
    check_if_unlock_failed_only_printf(ret_unlock);
    return ret;
}

static int32_t write_buffer_to_file(const uint8_t *read_buff, const char file_name[FILE_NAME_LEN])
{
    meta_file_t *fp = (meta_file_t *)read_buff;
    if (((UINT32_MAX - sizeof(uint32_t) * DOUBLE_SIZE) / sizeof(meta_element_t)) < fp->count_used) {
        tloge("invalid fp->count_used %u\n", fp->count_used);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    uint32_t real_len = sizeof(uint32_t) * DOUBLE_SIZE + fp->count_used * sizeof(meta_element_t);
    int32_t ret       = (int32_t)TEE_RPMB_FS_Write(file_name, (uint8_t *)read_buff, real_len);
    if (ret != 0)
        tloge("write buffer failed ret=%x,fileName=%s\n", ret, file_name);
    return ret;
}

int32_t kb_metafile_delete(const uint8_t *kb_hmac, uint32_t kb_hmac_len)
{
    uint32_t file_size = sizeof(meta_file_t);
    int32_t ret;
    int32_t ret_unlock;
    TEE_Result tee_ret;
    char file_name[FILE_NAME_LEN] = { 0 };
    bool condition_check          = ((kb_hmac == NULL) || (kb_hmac_len != HMAC_SIZE));
    if (condition_check) {
        tloge("invalid input, param may null\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    ret = pthread_mutex_lock(get_opera_metafile_lock());
    if ((ret) != TEE_SUCCESS) {
        tloge("pthread_mutex_lock failed. ret=0x%x\n", ret);
        return ret;
    }

    uint8_t *read_buff = (uint8_t *)TEE_Malloc(file_size, 0);
    if (read_buff == NULL) {
        tloge("read_buffer malloc failed");
        ret_unlock = pthread_mutex_unlock(get_opera_metafile_lock());
        check_if_unlock_failed_only_printf(ret_unlock);
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    tee_ret = kb_metafile_load(kb_hmac, kb_hmac_len, file_name, FILE_NAME_LEN, (meta_file_t *)read_buff);
    if (tee_ret != TEE_SUCCESS) {
        tloge("kb_hmac not found:0x%x\n", tee_ret);
        /* if not found hmac in rpmb file, we should return SUCCESS to keyblob delete action. */
        /* for vtscts, only return TEE_ERROR_ITEM_NOT_FOUND for error no */
        ret = (tee_ret == TEE_ERROR_ITEM_NOT_FOUND ? TEE_SUCCESS : TEE_ERROR_ITEM_NOT_FOUND);
        goto free_buf;
    }
    /* Now ,the fileName and read_buff have real data. */
    ret = kmds_delete_metadata((meta_file_t *)read_buff, kb_hmac, kb_hmac_len);
    if (ret != 0) {
        tloge("delete node failed ret=0x%x,fileName=%s\n", ret, file_name);
        goto free_buf;
    }
    /* write the buffer over the same file. */
    ret = write_buffer_to_file(read_buff, file_name);
free_buf:
    TEE_Free(read_buff);
    read_buff = NULL;
    ret_unlock = pthread_mutex_unlock(get_opera_metafile_lock());
    if ((ret_unlock) != TEE_SUCCESS) {
        tloge("pthread_mutex_unlock failed. ret=0x%x\n", ret_unlock);
        return ret_unlock;
    }
    return ret;
}

int kb_metafile_update(const uint8_t *old_kb_hmac, const uint8_t *new_kb_hmac, uint32_t kb_hmac_len)
{
    uint32_t file_size = sizeof(meta_file_t);
    int32_t ret;
    int32_t ret_unlock;
    char file_name[FILE_NAME_LEN] = { 0 };
    bool condition_check = ((old_kb_hmac == NULL) || (new_kb_hmac == NULL) || (kb_hmac_len != HMAC_SIZE));
    if (condition_check) {
        tloge("invalid input, param may null\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    ret = pthread_mutex_lock(get_opera_metafile_lock());
    if ((ret) != TEE_SUCCESS) {
        tloge("pthread_mutex_lock failed. ret=0x%x\n", ret);
        return ret;
    }
    uint8_t *read_buff = (uint8_t *)TEE_Malloc(file_size, 0);
    if (read_buff == NULL) {
        tloge("read_buffer malloc failed");
        ret_unlock = pthread_mutex_unlock(get_opera_metafile_lock());
        check_if_unlock_failed_only_printf(ret_unlock);
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    if (kb_metafile_load(old_kb_hmac, kb_hmac_len, file_name, FILE_NAME_LEN, (meta_file_t *)read_buff) != TEE_SUCCESS) {
        tloge("old_kb_hmac not found\n");
        ret = TEE_ERROR_ITEM_NOT_FOUND;
        goto error_free;
    }
    /* Now ,the fileName and read_buff have real data. */
    ret = kmds_update_metadata((meta_file_t *)read_buff, old_kb_hmac, new_kb_hmac, kb_hmac_len);
    if (ret != 0) {
        tloge("update node in kmds failed ret=0x%x,fileName=%s\n", ret, file_name);
        goto error_free;
    }
    /* write the buffer over the same file. */
    ret = write_buffer_to_file(read_buff, file_name);
error_free:
    TEE_Free(read_buff);
    read_buff = NULL;
    ret_unlock = pthread_mutex_unlock(get_opera_metafile_lock());
    if (ret_unlock != TEE_SUCCESS) {
        tloge("pthread_mutex_unlock failed. ret=0x%x\n", ret_unlock);
        return ret_unlock;
    }
    return ret;
}

TEE_Result keyblob_integrity_check(keyblob_head *keyblob, uint32_t keyblob_size)
{
    int adaptable;
    uint8_t mac_result[HMAC_SIZE]   = { 0 };
    uint8_t *p                      = (uint8_t *)keyblob;
    keymaster_blob_t application_id = { NULL, 0 };
    if (keyblob == NULL) {
        tloge("Null pointer of input parametere\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (key_blob_internal_check(keyblob, keyblob_size) != TEE_SUCCESS) {
        tloge("key_blob_internal_check failed\n");     /* check key_blob */
        return (TEE_Result)KM_ERROR_INVALID_KEY_BLOB;
    }
    /* check keyblob version and KM_TAG_OS_VERSION and KM_TAG_OS_PATCHLEVEL */
    TEE_Result tee_ret = check_keyblob_version(keyblob);
    if (tee_ret != TEE_SUCCESS && tee_ret != (TEE_Result)KM_ERROR_KEY_REQUIRES_UPGRADE) {
        tloge("key blob version check faild\n");
        return tee_ret;
    }
    if (tee_ret == (TEE_Result)KM_ERROR_KEY_REQUIRES_UPGRADE) {
        tloge("key blob need upgrade\n");
        return tee_ret;
    }
    /*
     * calculate HMAC
     * After LOCK_ORANGE was made to generate the same key with LOCK_GREEN,
     * to adapt old version, we'll check again with an adaptable color
     * after first check failed.
     *
     * If a keyblob with version500 or VERSION_510 try to verify the HMAC,
     * its keyblob hmac verification need application.data, but this function can't get that.
     * So,If keyblob version 500 or VERSION_510 do HMAC verification, it just passes.
     */
    if ((keyblob->version == VERSION_500) || (keyblob->version == VERSION_510)) {
        tloge("Verification unsupported. This version %u keyblob need a KM_TAG_APPLICATION_ID \n", keyblob->version);
        return TEE_SUCCESS;
    }
    if (keymaster_hmac(p + HMAC_SIZE, keyblob_size - HMAC_SIZE, mac_result, CHECK_ORIGINAL_LOCK_COLOR, &adaptable,
                       keyblob->version, &application_id) != 0) {
        tloge("keyblob_HMAC failed\n");
        return TEE_ERROR_GENERIC;
    }
    if (TEE_MemCompare(mac_result, keyblob->hmac, HMAC_SIZE) == 0)
        return TEE_SUCCESS;
    if (adaptable != NEED_CHECK_ADAPTABLE_COLOR) {
        tloge("HMAC compare failed\n");
        return TEE_ERROR_GENERIC;
    }
    if (keymaster_hmac(p + HMAC_SIZE, keyblob_size - HMAC_SIZE, mac_result, CHECK_ADAPTABLE_LOCK_COLOR, NULL,
                       keyblob->version, &application_id) != 0) {
        tloge("keyblob_HMAC failed\n");
        return TEE_ERROR_GENERIC;
    }
    if (TEE_MemCompare(mac_result, keyblob->hmac, HMAC_SIZE) != 0) {
        tloge("HMAC compare2 failed\n");
        return TEE_ERROR_GENERIC;
    }
    return TEE_SUCCESS;
}

TEE_Result kmds_set_keypolicy(uint8_t *kmds_data, uint8_t *hmac, const ctl_eima_policy_t *key_policy)
{
    errno_t rc;
    int32_t i;

    bool condition_check = ((kmds_data == NULL) || (hmac == NULL) || (key_policy == NULL));
    if (condition_check == true) {
        tloge("Bad input parameters\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    meta_file_t *p = (meta_file_t *)kmds_data;
    i              = kmds_retrieve_metadata(p, hmac, HMAC_SIZE);
    if (i >= 0) {
        /* set key policy in meta data */
        rc = memcpy_s(&(p->n[i].eima_policy), sizeof(ctl_eima_policy_t), key_policy, sizeof(ctl_eima_policy_t));
        if (rc != EOK) {
            tloge("key policy set failed, rc %d\n", rc);
            return TEE_ERROR_GENERIC;
        }
        tlogd("key policy set success\n");
        return TEE_SUCCESS;
    }
    tloge("can not find meta data\n");
    return TEE_ERROR_ITEM_NOT_FOUND;
}

void check_rpmb_write(TEE_Result ret)
{
    if (ret != TEE_SUCCESS)
        tloge("meta file write failed, ret = 0x%x\n", ret);
    else
        tlogd("km_key_policy_set succeed\n");
}

#endif
