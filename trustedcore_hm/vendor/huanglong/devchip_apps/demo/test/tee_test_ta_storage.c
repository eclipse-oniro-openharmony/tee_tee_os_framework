/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: TA test code for storage
 * Author: Hisilicon
 * Created: 2020-04-17
 */

#include "tee_test_ta_storage.h"
#include "tee_log.h"

static const char *const g_obj_id = (char *)TEE_TEST_STORAGE_OBJ_ID;
static const char *const g_init_data = (char *)TEE_TEST_STORAGE_INIT_DATA;

static TEE_Result storage_creat_persistent_object(void)
{
    TEE_ObjectHandle per_obj = NULL;
    TEE_Result ret;

    /* create object */
    ret = TEE_CreatePersistentObject(TEE_OBJECT_STORAGE_PRIVATE, (void *)g_obj_id, strlen(g_obj_id),
                                     TEE_DATA_FLAG_EXCLUSIVE,
                                     NULL, (void *)g_init_data, strlen(g_init_data), &per_obj);
    if (ret != TEE_SUCCESS) {
        tloge("TEE_CreatePersistentObject failed. file[%s] data[%s] ret[%x]\n", g_obj_id, g_init_data, ret);
    } else {
        TEE_CloseObject(per_obj);
    }

    return ret;
}

static TEE_Result storage_open_persistent_object(char *obj_id, unsigned int flags, TEE_ObjectHandle attr_obj,
                                                 bool creat, TEE_ObjectHandle *obj)
{
    TEE_ObjectHandle per_obj = NULL;
    TEE_Result ret;

    /* open object */
    ret = TEE_OpenPersistentObject(TEE_OBJECT_STORAGE_PRIVATE, (void *)obj_id, strlen(obj_id), flags, &per_obj);
    if (ret != TEE_SUCCESS && creat == true) {
        tlogd("File [%s] not exit. ret[%x]\n", obj_id, ret);
        /* create object */
        ret = TEE_CreatePersistentObject(TEE_OBJECT_STORAGE_PRIVATE, (void *)obj_id, strlen(obj_id), flags,
                                         attr_obj, (void *)g_init_data, strlen(g_init_data), &per_obj);
        if (ret != TEE_SUCCESS) {
            tloge("TEE_CreatePersistentObject failed. file[%s] data[%s] ret[0x%x]\n", obj_id, g_init_data, ret);
            per_obj = NULL;
            goto out;
        } else {
            TEE_CloseObject(per_obj);
        }

        /* open object */
        ret = TEE_OpenPersistentObject(TEE_OBJECT_STORAGE_PRIVATE, (void *)obj_id, strlen(obj_id), flags, &per_obj);
        if (ret != TEE_SUCCESS) {
            tloge("TEE_OpenPersistentObject fail. file[%s] ret[0x%x]\n", obj_id, ret);
            per_obj = NULL;
            goto out;
        }
    }

out:
    *obj = per_obj;
    return ret;
}

static TEE_Result ta_test_storage_open_persistent_object(char *obj_id, bool creat)
{
    TEE_ObjectHandle obj = NULL;
    TEE_Result ret;

    ret = storage_open_persistent_object(obj_id, TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_ACCESS_WRITE_META,
                                         NULL, creat, &obj);
    if (ret == TEE_SUCCESS) {
        TEE_CloseAndDeletePersistentObject(obj);
    } else {
        tloge("storage_open_persistent_object failed\n");
    }

    return ret;
}

static TEE_Result ta_test_storage_write_persistent_object(char *obj_id)
{
    TEE_ObjectHandle obj = NULL;
    char *data_append = (char *)"<data append>";
    TEE_Result ret;

    ret = storage_open_persistent_object(obj_id, TEE_DATA_FLAG_ACCESS_WRITE | TEE_DATA_FLAG_ACCESS_WRITE_META,
                                         NULL, true, &obj);
    if (ret != TEE_SUCCESS) {
        tloge("storage_open_persistent_object failed\n");
        return ret;
    }
    ret = TEE_WriteObjectData(obj, data_append, strlen(data_append));
    if (ret != TEE_SUCCESS) {
        tloge("TEE_WriteObjectData failed, ret[0x%x]\n", ret);
    }
    TEE_CloseAndDeletePersistentObject(obj);
    return ret;
}

static TEE_Result ta_test_storage_read_persistent_object(char *obj_id, bool creat)
{
#define BUF_SIZE 256
    TEE_ObjectHandle obj = NULL;
    char buf[BUF_SIZE];
    unsigned int count = 0;
    unsigned int read_size = strlen(g_init_data);
    TEE_Result ret;

    ret = storage_open_persistent_object(obj_id, TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_ACCESS_WRITE_META,
                                         NULL, creat, &obj);
    if (ret != TEE_SUCCESS) {
        tloge("storage_open_persistent_object failed\n");
        return ret;
    }

    TEE_MemFill(buf, 0x0, sizeof(buf));
    ret = TEE_ReadObjectData(obj, (void *)buf, read_size, &count);
    if (ret != TEE_SUCCESS) {
        tloge("TEE_ReadObjectData failed, ret[0x%x]\n", ret);
        goto exit;
    }
    buf[count] = '\0';

    /* verify date */
    if (TEE_MemCompare(buf, g_init_data, read_size) || count != read_size) {
        tloge("TEE_ReadObjectData failed, initialData[%s][0x%0x] readData[%s][0x%x]\n",
              g_init_data, read_size, buf, count);
        ret = TEE_ERROR_GENERIC;
    }

exit:
    TEE_CloseAndDeletePersistentObject(obj);
    return ret;
}

TEE_Result ta_test_storage(unsigned int cmd)
{
    TEE_Result ret;

    switch (cmd) {
        case TEE_STORAGE_CMD_CREAT:
            ret = storage_creat_persistent_object();
            break;
        case TEE_STORAGE_CMD_CREAT_EXIST:
            ret = storage_creat_persistent_object();
            if (ret != TEE_SUCCESS) {
                break;
            }
            ret = storage_creat_persistent_object();
            break;
        case TEE_STORAGE_CMD_OPEN:
            ret = ta_test_storage_open_persistent_object(g_obj_id, true);
            break;
        case TEE_STORAGE_CMD_OPEN_NONEXISTENT:
            ret = ta_test_storage_open_persistent_object(TEE_TEST_STORAGE_OBJ_IDX, false);
            break;
        case TEE_STORAGE_CMD_WRITE:
            ret = ta_test_storage_write_persistent_object(g_obj_id);
            break;
        case TEE_STORAGE_CMD_READ:
            ret = ta_test_storage_read_persistent_object(g_obj_id, true);
            break;
        case TEE_STORAGE_CMD_READ_NONEXISTENT:
            ret = ta_test_storage_read_persistent_object(TEE_TEST_STORAGE_OBJ_IDX, false);
            break;
        default:
            tloge("Invalid cmd[0x%X]!\n", cmd);
            ret = TEE_ERROR_INVALID_CMD;
            break;
    }

    return ret;
}