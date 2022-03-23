/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description:kms file operation functions
 * Create: 2021-12-01
 */
#include "tee_log.h"
#include "kms_pub_def.h"
#include "kms_file_ops.h"

TEE_Result kms_file_write(const char *file_name, const uint8_t *buffer, uint32_t len)
{
    bool invalid_params_check = (file_name == NULL) || (buffer == NULL) || (len == 0);
    if (invalid_params_check) {
        tloge("invalid input, params may null\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    TEE_ObjectHandle handle = TEE_HANDLE_NULL;
    TEE_Result ret = TEE_CreatePersistentObject(TEE_OBJECT_STORAGE_PRIVATE, (void *)file_name, strlen(file_name),
        TEE_DATA_FLAG_ACCESS_WRITE | TEE_DATA_FLAG_CREATE, TEE_HANDLE_NULL, NULL, 0, &handle);
    if (ret != TEE_SUCCESS) {
        tloge("kms file create failed: ret = 0x%x and file name: %s\n", ret, file_name);
        return ret;
    }

    ret = TEE_WriteObjectData(handle, (void *)buffer, len);
    if (ret != TEE_SUCCESS) {
        tloge("kms file write failed: ret = 0x%x and file name: %s\n", ret, file_name);
        TEE_CloseObject(handle);
        return ret;
    }

    ret = TEE_SyncPersistentObject(handle);
    if (ret != TEE_SUCCESS)
        tloge("write %s, ret = 0x%x\n", file_name, ret);
    TEE_CloseObject(handle);
    return ret;
}

TEE_Result kms_file_read(const char *file_name, uint8_t *buffer, uint32_t *len)
{
    bool invalid_params_check = (file_name == NULL) || (buffer == NULL) || (*len == 0);
    if (invalid_params_check) {
        tloge("invalid input, params may null\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    TEE_ObjectHandle handle = TEE_HANDLE_NULL;
    uint32_t read_size = 0;
    uint32_t buffer_len = *len;
    TEE_Result ret = TEE_OpenPersistentObject(TEE_OBJECT_STORAGE_PRIVATE, (void *)file_name, strlen(file_name),
        TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_SHARE_READ, &handle);
    if (ret != TEE_SUCCESS) {
        tloge("kms file open failed: ret = 0x%x and file name: %s\n", ret, file_name);
        return ret;
    }

    uint32_t pos = 0;
    uint32_t file_size = 0;
    ret = TEE_InfoObjectData(handle, &pos, &file_size);
    if (ret != TEE_SUCCESS) {
        tloge("kms get file size failed: ret = 0x%x, and file name: %s\n", ret, file_name);
        TEE_CloseObject(handle);
        return ret;
    }
    if (file_size > buffer_len) {
        tloge("kms file read error: buffer too small");
        TEE_CloseObject(handle);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    ret = TEE_ReadObjectData(handle, buffer, file_size, &read_size);
    if (ret != TEE_SUCCESS)
        tloge("read %s, read length %u, ret = 0x%x\n", file_name, read_size, ret);
    TEE_CloseObject(handle);
    *len = read_size;
    return ret;
}

TEE_Result kms_file_rename(const char *old_file_name, const char *new_file_name)
{
    bool invalid_params_check = (old_file_name == NULL) || (new_file_name == NULL);
    if (invalid_params_check) {
        tloge("invalid input, params may null\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    TEE_ObjectHandle handle = TEE_HANDLE_NULL;
    TEE_Result ret = TEE_OpenPersistentObject(TEE_OBJECT_STORAGE_PRIVATE, (void *)old_file_name, strlen(old_file_name),
        TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_ACCESS_WRITE_META, &handle);
    if (ret != TEE_SUCCESS) {
        tloge("kms file open failed: ret = 0x%x and file name: %s\n", ret, new_file_name);
        return ret;
    }

    ret = TEE_RenamePersistentObject(handle, (void *)new_file_name, strlen(new_file_name));
    if (ret != TEE_SUCCESS)
        tloge("rename %s to %s, ret = 0x%x\n", old_file_name, new_file_name, ret);
    TEE_CloseObject(handle);
    return ret;
}

TEE_Result kms_file_remove(const char *file_name)
{
    if (file_name == NULL) {
        tloge("invalid input, params may null\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    TEE_ObjectHandle handle = TEE_HANDLE_NULL;
    TEE_Result ret = TEE_OpenPersistentObject(TEE_OBJECT_STORAGE_PRIVATE, (void *)file_name, strlen(file_name),
        TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_ACCESS_WRITE_META, &handle);
    if (ret != TEE_SUCCESS) {
        tloge("kms file open failed: ret = 0x%x and file name: %s\n", ret, file_name);
        return ret;
    }

    ret = TEE_CloseAndDeletePersistentObject1(handle);
    if (ret != TEE_SUCCESS)
        tloge("remove %s, ret = 0x%x\n", file_name, ret);
    return ret;
}
TEE_Result kms_file_access(const char *file_name)
{
    if (file_name == NULL) {
        tloge("invalid input, params may null\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    TEE_ObjectHandle handle = TEE_HANDLE_NULL;
    TEE_Result ret = TEE_OpenPersistentObject(TEE_OBJECT_STORAGE_PRIVATE, (void *)file_name, strlen(file_name),
        TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_SHARE_READ, &handle);
    if (ret != TEE_SUCCESS) {
        tlogi("%s not found\n", file_name);
        return ret;
    }
    TEE_CloseObject(handle);
    return ret;
}
