/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2020. All rights reserved.
 * Description: keymaster file operation functions
 * Create: 2012-01-17
 */
#include "km_common.h"
#include "rpmb_fcntl.h"
#include "km_defines.h"
pthread_mutex_t g_file_operation_lock;
static int32_t do_rpmb_file_read(const char *file_name, uint8_t *buf, uint32_t len)
{
    if ((file_name == NULL) || (buf == NULL) || (len == 0)) {
        tloge("invalid input, param may null\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    uint32_t read_size = 0;

    int32_t ret = (int32_t)TEE_RPMB_FS_Read(file_name, (uint8_t *)buf, len, &read_size);
    if (ret != 0) {
        tloge("rpmb_file_read failed, ret = 0x%x, file_name = %s\n", ret, file_name);
        return ret;
    }

    tlogd("rpmb file read success!\n");
    return (int)read_size;
}

static int32_t do_rpmb_file_write(const char *file_name, uint8_t *buf, uint32_t len)
{
    if ((file_name == NULL) || (buf == NULL) || (len == 0)) {
        tloge("invalid input, param may null\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    int32_t ret = (int)TEE_RPMB_FS_Write(file_name, (uint8_t *)buf, len);
    if (ret != 0) {
        tloge("rpmb_file_write failed, ret = 0x%x, file_name = %s\n", ret, file_name);
        return ret;
    }

    ret = (int)TEE_RPMB_FS_SetAttr(file_name, TEE_RPMB_FMODE_NON_ERASURE);
    if (ret != 0) {
        tloge("rpmb set attr failed, ret = 0x%x, file_name = %s\n", ret, file_name);
        return ret;
    }

    tlogd("rpmb file write success!\n");
    return 0;
}

static int32_t do_rpmb_file_remove(const char *file_name)
{
    if (file_name == NULL) {
        tloge("invalid input, param may null.\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    int32_t ret = (int)TEE_RPMB_FS_Rm(file_name);
    if (ret != 0) {
        tloge("rpmb_file_remove failed, ret = 0x%x, file_name = %s\n", ret, file_name);
        return ret;
    }

    tlogd("rpmb file remove success!\n");
    return 0;
}

static int32_t do_rpmb_file_size(const char *file_name)
{
    if (file_name == NULL) {
        tloge("invalid input, param may null\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    struct rpmb_fs_stat stat;
    stat.size     = 0;
    stat.reserved = 0;

    int32_t ret = (int)TEE_RPMB_FS_Stat(file_name, &stat);
    if (ret != 0) {
        tloge("rpmb_file_size failed, ret = 0x%x, file_name = %s\n", ret, file_name);
        return ret;
    }

    tlogd("rpmb file get info success!\n");
    return (int)stat.size;
}

static int32_t __ss_file_open(TEE_ObjectHandle *handle, const char *file_name, uint32_t mode)
{
    if ((handle == NULL) || (file_name == NULL) || (mode == 0)) {
        tloge("invalid input, param may null\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    TEE_Result ret;
    if (mode & TEE_DATA_FLAG_CREATE) {
        ret = TEE_CreatePersistentObject(TEE_OBJECT_STORAGE_PRIVATE, (void *)file_name, strlen(file_name), mode,
                                         TEE_HANDLE_NULL, NULL, 0, handle);
        if (ret != TEE_SUCCESS) {
            tloge("!!ss file create failed: ret=0x%x and file_name=%s\n", ret, file_name);
            return (int32_t)ret;
        }
        tlogd("ss file create successfully:%s\n", file_name);

        ret = TEE_TruncateObjectData(*handle, 0);
        if (ret != TEE_SUCCESS) {
            tloge("ss file truncate failed: ret=0x%x and %s\n", ret, file_name);
            TEE_CloseObject(*handle);
            return (int)ret;
        }
    } else {
        ret = TEE_OpenPersistentObject(TEE_OBJECT_STORAGE_PRIVATE, (void *)file_name, strlen(file_name), mode, handle);
        if (ret != TEE_SUCCESS) {
            tloge("ss file open failed: ret=0x%x and %s\n", ret, file_name);
            if (ret == TEE_ERROR_ITEM_NOT_FOUND) {
                tloge("file: %s not exist!\n", file_name);
                return (int32_t)ret;
            }
            return (int)ret;
        }
    }

    return ret;
}

static int32_t __ss_file_close(TEE_ObjectHandle handle, uint32_t mode)
{
    if (handle == NULL) {
        tloge("invalid input, param may null.\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    int32_t ret = 0;

    if (mode & TEE_DATA_FLAG_ACCESS_WRITE) {
        ret = (int32_t)TEE_SyncPersistentObject(handle);
        if (ret != 0) {
            tloge("ss file sync error: ret=0x%x!\n", ret);
            return ret;
        }
    }

    TEE_CloseObject(handle);
    return ret;
}

static int32_t do_ss_file_read(const char *file_name, uint8_t *buf, uint32_t len)
{
    if ((file_name == NULL) || (buf == NULL) || (len == 0)) {
        tloge("invalid input, param may null\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    int32_t ret;
    uint32_t mode                = TEE_DATA_FLAG_ACCESS_READ;
    uint32_t read_size      = 0;
    TEE_ObjectHandle handle = { 0 };

    ret = __ss_file_open(&handle, file_name, mode);
    if (ret) {
        tloge("ss_file open error\n");
        return ret;
    }

    ret = (int32_t)TEE_ReadObjectData(handle, buf, len, &read_size);
    if (ret != 0) {
        tloge("ss_file read error ret=0x%x\n", ret);
        TEE_CloseObject(handle);
        return ret;
    }

    ret = __ss_file_close(handle, mode);
    if (ret != 0) {
        tloge("ss_file close error\n");
        return ret;
    }

    return (int)read_size;
}

static int32_t do_ss_file_write(const char *file_name, uint8_t *buf, uint32_t len)
{
    if ((file_name == NULL) || (buf == NULL) || (len == 0)) {
        tloge("invalid input, param may null\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    tlogd("ss file write into:%s\n", file_name);

    int32_t ret;
    uint32_t mode                = TEE_DATA_FLAG_ACCESS_WRITE | TEE_DATA_FLAG_CREATE;
    TEE_ObjectHandle handle = { 0 };

    ret = __ss_file_open(&handle, file_name, mode);
    if (ret) {
        tloge("ss_file open error\n");
        return ret;
    }

    ret = (int)TEE_WriteObjectData(handle, (void *)buf, len);
    if (ret != 0) {
        tloge("ss file write failed: ret=0x%x and file_name = %s\n", ret, file_name);
        TEE_CloseObject(handle);
        return ret;
    }

    ret = __ss_file_close(handle, mode);
    if (ret != 0) {
        tloge("ss_file close error\n");
        return ret;
    }

    tlogd("ss file write success!\n");
    return ret;
}

static int32_t do_ss_file_size(const char *file_name)
{
    if (file_name == NULL) {
        tloge("invalid input, param may null\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    int32_t ret;
    uint32_t mode                = TEE_DATA_FLAG_ACCESS_READ;
    TEE_ObjectHandle handle = { 0 };

    ret          = __ss_file_open(&handle, file_name, mode);
    uint32_t len = 0;
    uint32_t pos = 0;
    if (ret) {
        tloge("ss_file open error\n");
        return ret;
    }

    ret = (int)TEE_InfoObjectData(handle, &pos, &len);
    if (ret != 0) {
        tloge("ss file get info failed: ret = 0x%x and file_name = %s\n", ret, file_name);
        TEE_CloseObject(handle);
        return ret;
    }

    ret = __ss_file_close(handle, mode);
    if (ret != 0) {
        tloge("ss_file close error\n");
        return ret;
    }
    tlogd("ss file get info success!\n");
    return (int)len;
}

static int32_t do_ss_file_remove(const char *file_name)
{
    if (file_name == NULL) {
        tloge("invalid input, param may null\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    uint32_t mode                = TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_ACCESS_WRITE_META;
    TEE_ObjectHandle handle = NULL;
    int32_t ret = (int)TEE_OpenPersistentObject(TEE_OBJECT_STORAGE_PRIVATE, (void *)file_name, strlen(file_name), mode,
        (&handle));
    if (ret != 0) {
        tloge("ss file remove failed: ret = 0x%x, file_name = %s\n", ret, file_name);
        return ret;
    }
    TEE_CloseAndDeletePersistentObject(handle);
    tlogd("ss file remove success!\n");
    return ret;
}

int32_t set_file_operation(void)
{
    /* add lock for prevent ops assigned both rpmb and ss;using ops code not need lock; */
    file_operations_t *file_ops = get_file_operation_info();

    int32_t ret;
    ret = pthread_mutex_lock(&g_file_operation_lock);
    if (ret != TEE_SUCCESS) {
        tloge("set file pthread_mutex_lock failed\n");
        return ret;
    }
    if (TEE_RPMB_KEY_Status() == TEE_RPMB_KEY_SUCCESS) {
        tlogd("use rpmb to operate data!!\n");
        file_ops->read     = do_rpmb_file_read;
        file_ops->write    = do_rpmb_file_write;
        file_ops->filesize = do_rpmb_file_size;
        file_ops->remove   = do_rpmb_file_remove;
        file_ops->fs_using = STORE_RPMB;
    } else {
        tlogd("use sfs to operate data!!\n");
        file_ops->read     = do_ss_file_read;
        file_ops->write    = do_ss_file_write;
        file_ops->filesize = do_ss_file_size;
        file_ops->remove   = do_ss_file_remove;
        file_ops->fs_using = STORE_SFS;
    }
    ret = pthread_mutex_unlock(&g_file_operation_lock);
    if (ret != TEE_SUCCESS) {
        tloge("set file pthread_mutex_unlock failed\n");
        return ret;
    }

    return ret;
}
