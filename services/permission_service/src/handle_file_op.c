/*$$$!!Warning: Huawei key information asset. No spread without permission.$$$*/
/*CODEMARK:mJSkoqPZ5FEeD8fzH9bAQfhyPrkcI5cbzjotjI99J9PTkCMNHMtR+8Ejd3mKEkWbMFYmuIhV
lw/je6uplRzXM4SMvhun8vRGD9mNqO2kY4/aQFDUiG2CG+z+BR1XavYOLbgQ6mxl4mdMDMUc
pTTvsgNnGY+uGDhrcSrYT/yiWUcPU+7hHj/1z+1w4sei8NKrE5YtD4ycmPizGfaNhWQY5YvG
yUQ4I+iaikKhay3gs3gbvr2F/fo9kmuK6WNlljMWqZQckvm//k0TiyJFZq4NZA==#*/
/*$$$!!Warning: Deleting or modifying the preceding information is prohibited.$$$*/
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2016-2020. All rights reserved.
 * Description: permission handle file op
 * Author: TianJianliang tianjianliang@huawei.com
 * Create: 2016-04-01
 */
#include "handle_file_op.h"
#include <string.h>
#include <tee_log.h>
#include <tee_defines.h>
#include <tee_trusted_storage_api.h>

#ifndef CONFIG_DISABLE_PERM_STORAGE

static int32_t ss_file_open(TEE_ObjectHandle *handle, const char *filename, uint32_t mode)
{
    TEE_Result ret;

    if (filename == NULL || handle == NULL || mode == 0)
        return -1;

    if (mode & TEE_DATA_FLAG_CREATE) {
        ret = TEE_CreatePersistentObject(TEE_OBJECT_STORAGE_PRIVATE, (void *)filename, strlen(filename), mode,
                                         TEE_HANDLE_NULL, NULL, 0, handle);
        if (ret != TEE_SUCCESS) {
            tloge("ss file create failed: 0x%x %s\n", ret, filename);
            return -1;
        }
        tlogd("ss file create successfully: %s\n", filename);

        ret = TEE_TruncateObjectData(*handle, 0);
        if (ret != TEE_SUCCESS) {
            tloge("ss file truncate failed: 0x%x and %s\n", ret, filename);
            TEE_CloseObject(*handle);
            return -1;
        }
    } else {
        ret = TEE_OpenPersistentObject(TEE_OBJECT_STORAGE_PRIVATE, (void *)filename, strlen(filename), mode, handle);
        if (ret != TEE_SUCCESS) {
            tloge("ss file open failed: 0x%x and %s\n", ret, filename);
            if (ret == TEE_ERROR_ITEM_NOT_FOUND) {
                tloge("file: %s not exist\n", filename);
                return 1;
            }
            return -1;
        }
    }

    return 0;
}

static int32_t ss_file_close(TEE_ObjectHandle handle, uint32_t mode)
{
    if (handle == NULL)
        return -1;

    TEE_Result ret;

    if ((mode & TEE_DATA_FLAG_ACCESS_WRITE) != 0) {
        ret = TEE_SyncPersistentObject(handle);
        if (ret != TEE_SUCCESS) {
            tloge("ss file sync error: 0x%x\n", ret);
            return -1;
        }
    }

    TEE_CloseObject(handle);
    return 0;
}

static int32_t do_ss_file_read(const char *filename, uint8_t *buf, size_t len)
{
    uint32_t mode = TEE_DATA_FLAG_ACCESS_READ;
    uint32_t read_size = 0;
    TEE_ObjectHandle handle = TEE_HANDLE_NULL;
    int32_t ret;
    TEE_Result tee_ret;

    if (filename == NULL || buf == NULL || len == 0)
        return -1;

    ret = ss_file_open(&handle, filename, mode);
    if (ret < 0) {
        tloge("ss file open error\n");
        return -1;
    }

    if (ret > 0) {
        tloge("ss file doesn't exist\n");
        return 0;
    }

    tee_ret = TEE_ReadObjectData(handle, buf, len, &read_size);
    if (tee_ret != TEE_SUCCESS) {
        tloge("ss file read error 0x%x\n", ret);
        TEE_CloseObject(handle);
        return -1;
    }

    ret = ss_file_close(handle, (uint32_t)mode);
    if (ret != 0) {
        tloge("ss file close error\n");
        return -1;
    }

    return (int32_t)read_size;
}

static int32_t do_ss_file_write(const char *filename, const uint8_t *buf, size_t len)
{
    uint32_t mode = TEE_DATA_FLAG_ACCESS_WRITE | TEE_DATA_FLAG_CREATE;
    TEE_ObjectHandle handle = TEE_HANDLE_NULL;
    TEE_Result tee_ret;
    int32_t ret;

    if (filename == NULL || buf == NULL || len == 0)
        return -1;

    tlogd("ss file write into:%s\n", filename);

    ret = ss_file_open(&handle, filename, mode);
    if (ret < 0) {
        tloge("ss file open error\n");
        return ret;
    }

    tee_ret = TEE_WriteObjectData(handle, (void *)buf, len);
    if (tee_ret != TEE_SUCCESS) {
        tloge("ss file write failed: 0x%x and %s\n", tee_ret, filename);
        TEE_CloseObject(handle);
        return -1;
    }

    ret = ss_file_close(handle, (uint32_t)mode);
    if (ret < 0) {
        tloge("ss_file close error\n");
        return ret;
    }

    tlogd("ss file write success\n");
    return ret;
}

static int32_t do_ss_file_size(const char *filename)
{
    uint32_t mode = TEE_DATA_FLAG_ACCESS_READ;
    TEE_ObjectHandle handle = TEE_HANDLE_NULL;
    TEE_Result tee_ret;
    uint32_t len = 0;
    uint32_t pos = 0;
    int32_t ret;

    if (filename == NULL)
        return -1;

    ret = ss_file_open(&handle, filename, mode);
    if (ret < 0) {
        tloge("ss file open error\n");
        return -1;
    } else if (ret > 0) {
        tloge("ss file doesn't exist\n");
        return 0;
    }

    tee_ret = TEE_InfoObjectData(handle, &pos, &len);
    if (tee_ret != TEE_SUCCESS) {
        tloge("ss file get info failed: 0x%x and %s\n", tee_ret, filename);
        TEE_CloseObject(handle);
        return -1;
    }

    ret = ss_file_close(handle, (uint32_t)mode);
    if (ret < 0) {
        tloge("ss file close error\n");
        return ret;
    }
    tlogd("ss file get info success\n");
    return (int32_t)len;
}

static int32_t do_ss_file_remove(const char *filename)
{
    TEE_Result ret;

    if (filename == NULL)
        return -1;

    uint32_t mode = TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_ACCESS_WRITE_META;
    TEE_ObjectHandle handle = NULL;
    ret = TEE_OpenPersistentObject(TEE_OBJECT_STORAGE_PRIVATE, (void *)filename, strlen(filename), mode, (&handle));
    if (ret != TEE_SUCCESS) {
        tloge("ss file remove failed: 0x%x and %s\n", ret, filename);
        return -1;
    }

    TEE_CloseAndDeletePersistentObject(handle);
    return 0;
}

static const struct file_operations g_sfs_ops = {
    .read     = do_ss_file_read,
    .write    = do_ss_file_write,
    .filesize = do_ss_file_size,
    .remove   = do_ss_file_remove,
    .fs_using = STORE_SFS,
};

static const struct file_operations *g_ops = NULL;
static const struct file_operations *perm_srv_file_op_init(void)
{
    if (g_ops != NULL)
        return g_ops;

    tlogd("use sfs to operate data\n");
    g_ops = &g_sfs_ops;

    return g_ops;
}

int32_t perm_srv_file_write(const char *filename, const uint8_t *buf, size_t len)
{
    if (filename == NULL || buf == NULL || len == 0)
        return -1;

    const struct file_operations *ops = perm_srv_file_op_init();
    return ops->write(filename, buf, len);
}

int32_t perm_srv_file_read(const char *filename, uint8_t *buf, size_t len)
{
    if (filename == NULL || buf == NULL || len == 0)
        return -1;

    const struct file_operations *ops = perm_srv_file_op_init();
    return ops->read(filename, buf, len);
}

int32_t perm_srv_file_size(const char *filename)
{
    if (filename == NULL)
        return -1;

    const struct file_operations *ops = perm_srv_file_op_init();
    return ops->filesize(filename);
}

int32_t perm_srv_file_remove(const char *filename)
{
    if (filename == NULL)
        return -1;

    const struct file_operations *ops = perm_srv_file_op_init();
    return ops->remove(filename);
}
#else
int32_t perm_srv_file_write(const char *filename, const uint8_t *buf, size_t len)
{
    (void)filename;
    (void)buf;
    (void)len;
    return 0;
}

int32_t perm_srv_file_read(const char *filename, uint8_t *buf, size_t len)
{
    (void)filename;
    (void)buf;
    (void)len;
    return 0;
}

int32_t perm_srv_file_size(const char *filename)
{
    (void)filename;
    return 0;
}

int32_t perm_srv_file_remove(const char *filename)
{
    (void)filename;
    return 0;
}
#endif
