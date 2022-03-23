/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Secure flash msg communication management.
 * Author: tianjianliang(0029236)
 * Create: 2019-08-19
 * Notes:
 * History: 2019-08-19 tianjianliang create sf_xxx functions.
 *          2019-08-27 chengruhong realize sf_xxx functions.
 */

#include "mem_ops_ext.h"
#include "sec_flash_public.h"
#include "securec.h"
#include <stdarg.h>
#include "string.h"
#include "ta_framework.h"
#include "tee_service_public.h"
#include "tee_log.h"
#include "tee_mem_mgmt_api.h"
#include "tee_trusted_storage_api.h"

#define unused(x) (void)(x)

#if (defined CONFIG_HISI_SECFLASH) || (defined HISI_MSP_SECFLASH)


#define SECFLASH_MM_MEM_TYPE_MASK 0x08000000
#define IS_NEGATIVE 1
#define NON_DELETABLE 0x5A
#define DELETABLE 0xA5

#define TEE_OBJECT_FREE_MAGIC 0xabcdabcd

static TEE_Result tee_obj_new(TEE_ObjectHandle *object)
{
    if (object == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    *object = TEE_Malloc(sizeof(struct __TEE_ObjectHandle) + sizeof(TEE_ObjectInfo), 0);
    if (*object == NULL) {
        tloge("not available to allocate the object handle\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    (*object)->ObjectInfo = (TEE_ObjectInfo *)(*object + 1);

    return TEE_SUCCESS;
}

static TEE_Result tee_obj_free(TEE_ObjectHandle *object)
{
    if ((object == NULL) || (*object == NULL))
        return TEE_ERROR_BAD_PARAMETERS;

    (*object)->infoattrfd = (void *)TEE_OBJECT_FREE_MAGIC;

    TEE_Free(*object);
    *object = NULL;

    return TEE_SUCCESS;
}

/*
 * @brief     : Check storage_id if it indicates secflash.
 * @param[in] : storage_id, Storage id to be checked.
 * @param[out]: void.
 * @return    : Operation status: success(0) or other failure status
 */
static TEE_Result sf_check_storage_id(uint32_t storage_id)
{
    if (storage_id != TEE_OBJECT_SEC_FLASH) {
        tloge("%s, not secflash storage id=%u\n", __func__, storage_id);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    return TEE_SUCCESS;
}

/*
 * @brief     : Check object if valid.
 * @param[in] : object, Pointer.
 * @param[out]: void.
 * @return    : Operation status: success(0) or other failure status
 */
static TEE_Result sf_check_object_handle(TEE_ObjectHandle object)
{
    TEE_Result ret;

    if (object == NULL) {
        tloge("%s, null object\n", __func__);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (object->ObjectInfo == NULL) {
        tloge("%s, null object\n", __func__);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    ret = sf_check_storage_id(object->storage_id);
    return ret;
}

/*
 * @brief     : Create a new TEE_ObjectHandle.
 * @param[in] : object, Pointer to point TEE_ObjectHandle.
 * @param[out]: void.
 * @return    : Operation status: success(0) or other failure status
 */
static TEE_Result sf_new_object_handle(TEE_ObjectHandle *object, uint32_t flags)
{
    TEE_Result ret;

    ret = tee_obj_new(object);
    if (ret != TEE_SUCCESS) {
        tloge("%s\n", __func__);
        return ret;
    }
    if ((*object)->ObjectInfo == NULL) {
        tloge("invalid object info");
        tee_obj_free(object);
        return TEE_ERROR_GENERIC;
    }
    (*object)->storage_id = TEE_OBJECT_SEC_FLASH;
    (*object)->ObjectInfo->handleFlags = ((uint32_t)TEE_HANDLE_FLAG_PERSISTENT) |
        ((uint32_t)TEE_HANDLE_FLAG_INITIALIZED) | flags;
    return TEE_SUCCESS;
}

/*
 * @brief     : Free a TEE_ObjectHandle.
 * @param[in] : object, Pointer to point TEE_ObjectHandle.
 * @param[out]: void.
 * @return    : void.
 */
static void sf_free_object_handle(TEE_ObjectHandle *object)
{
    tee_obj_free(object);
    *object = NULL;
}

/*
 * @brief     : Get the mem_type.
 * @param[in] : flags, Bit 27 indicates the requested memory type.
 * @param[out]: void.
 * @return    : void.
 */
static uint32_t sf_get_mem_type(uint32_t flags)
{
    if ((flags & SECFLASH_MM_MEM_TYPE_MASK) == SECFLASH_MM_MEM_TYPE_MASK) {
        return DELETABLE;
    } else {
        return NON_DELETABLE;
    }
}

/*
 * @brief     : Check the object information.
 * @param[in] : storageID, Indicate to use secflash.
 * @param[in] : object, Pointer to point TEE_ObjectHandle.
 * @param[in] : objectID, Obejct id pointer.
 * @param[in] : objectIDLen, Obejct length.
 * @param[out]: void.
 * @return    : Operation status: success(0) or other failure status
 */
static TEE_Result sf_mm_check_object_info(uint32_t storageID, TEE_ObjectHandle *object,
    const void *objectID, uint32_t flags)
{
    TEE_Result ret;

    ret = sf_check_storage_id(storageID);
    if (ret != TEE_SUCCESS) {
        tloge("%s\n", __func__);
        return ret;
    }
    if (object == NULL || objectID == NULL) {
        tloge("%s, null object\n", __func__);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    ret = sf_new_object_handle(object, flags);
    if (ret != TEE_SUCCESS) {
        tloge("%s\n", __func__);
        return ret;
    }

    return TEE_SUCCESS;
}

/*
 * @brief     : GP TEE API create function in secflash implementation.
 * @param[in] : storageID, Indicate to use secflash.
 * @param[in] : objectID, Not used.
 * @param[in] : objectIDLen, Not used.
 * @param[in] : flags, Bit 27 indicates the requested memory type.
 * @param[in] : attributes, Not used.
 * @param[in] : initialData, Not used.
 * @param[in] : initialDataLen, The requested memory size. Cannot change after.
 * @param[out]: object, Pointer to contain the TEE_ObjectHandle.
 * @return    : Operation status: success(0) or other failure status.
 */
TEE_Result sf_creat_persistent_object(
    uint32_t storageID, const void *objectID, size_t objectIDLen,
    uint32_t flags, TEE_ObjectHandle attributes,
    const void *initialData, size_t initialDataLen, TEE_ObjectHandle *object)
{
    tee_service_ipc_msg msg = {{0}};
    tee_service_ipc_msg_rsp rsp = {0};
    uint32_t obj_id;
    TEE_Result ret;

    unused(attributes);
    unused(initialData);
    unused(objectIDLen);

    ret = sf_mm_check_object_info(storageID, object, objectID, flags);
    if (ret != TEE_SUCCESS) {
        tloge("%s\n", __func__);
        return ret;
    }

    obj_id = *((uint8_t *)objectID); /* object id is only used [0, 8] up to now */
    msg.args_data.arg0 = initialDataLen;
    msg.args_data.arg1 = sf_get_mem_type(flags);
    msg.args_data.arg2 = obj_id;
    rsp.ret = TEE_ERROR_GENERIC;

    tee_common_ipc_proc_cmd(SEC_FLASH_TASK_NAME, SEC_FLASH_MSG_MM_CREATE_CMD, &msg,
        SEC_FLASH_MSG_MM_CREATE_CMD, &rsp);

    ret = rsp.ret;
    if (ret == TEE_SUCCESS) {
        (*object)->dataName[0] = (uint8_t)obj_id;
        (*object)->ObjectInfo->maxObjectSize = initialDataLen;
        (*object)->ObjectInfo->dataPosition = 0;
    } else {
        sf_free_object_handle(object);
    }

    return ret;
}

/*
 * @brief     : GP TEE API open function in secflash implementation .
 * @param[in] : storageID, Indicate to use secflash.
 * @param[in] : objectID, Not used.
 * @param[in] : objectIDLen, Not used.
 * @param[in] : flags, Bit 27 indicates the requested memory type.
 * @param[out]: object, Pointer to contain the TEE_ObjectHandle.
 * @return    : Operation status: success(0) or other failure status.
 */
TEE_Result sf_open_persistent_object(
    uint32_t storageID,
    const void *objectID, size_t objectIDLen,
    uint32_t flags,
    TEE_ObjectHandle *object)
{
    tee_service_ipc_msg msg = {{0}};
    tee_service_ipc_msg_rsp rsp = {0};
    TEE_Result ret;
    uint32_t obj_id;

    unused(objectIDLen);

    ret = sf_mm_check_object_info(storageID, object, objectID, flags);
    if (ret != TEE_SUCCESS) {
        tloge("%s\n", __func__);
        return ret;
    }

    obj_id = *((uint8_t *)objectID); /* object id is only used [0, 8] up to now */
    msg.args_data.arg0 = sf_get_mem_type(flags);
    msg.args_data.arg1 = obj_id;
    rsp.ret = TEE_ERROR_GENERIC;

    tee_common_ipc_proc_cmd(SEC_FLASH_TASK_NAME, SEC_FLASH_MSG_MM_OPEN_CMD, &msg, SEC_FLASH_MSG_MM_OPEN_CMD, &rsp);

    ret = rsp.ret;
    if (ret == TEE_SUCCESS) {
        (*object)->dataName[0] = (uint8_t)obj_id;
        (*object)->ObjectInfo->maxObjectSize = rsp.msg.args_data.arg0;
        (*object)->ObjectInfo->dataPosition = 0;
    } else {
        sf_free_object_handle(object);
    }

    return ret;
}

/*
 * @brief     : GP TEE API read function in secflash implementation .
 * @param[in] : object, TEE_ObjectHandle containing key information.
 * @param[in] : buffer, The buffer to contain the read data.
 * @param[in] : size, The size of data to read.
 * @param[out]: count, Return the actually read data size.
 * @return    : Operation status: success(0) or other failure status.
 */
TEE_Result sf_read_object_data(TEE_ObjectHandle object, void *buffer, size_t size, uint32_t *count)
{
    char *buffer_local = NULL;
    tee_service_ipc_msg msg = {{0}};
    tee_service_ipc_msg_rsp rsp = {0};
    TEE_Result ret;
    uint32_t obj_id;

    ret = sf_check_object_handle(object);
    if (ret != TEE_SUCCESS) {
        tloge("%s\n", __func__);
        return ret;
    }

    if (buffer == NULL || size == 0 || count == NULL) {
        tloge("%s\n", __func__);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    buffer_local = tee_alloc_sharemem_aux(&g_sec_flash_uuid, size);
    if (buffer_local == NULL) {
        tloge("%s\n", __func__);
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    obj_id = object->dataName[0];
    msg.args_data.arg0 = object->ObjectInfo->dataPosition;
    msg.args_data.arg1 = size;
    msg.args_data.arg2 = sf_get_mem_type(object->ObjectInfo->handleFlags);
    msg.args_data.arg3 = (uintptr_t)buffer_local;
    msg.args_data.arg4 = obj_id;

    rsp.ret = TEE_ERROR_GENERIC;

    tee_common_ipc_proc_cmd(SEC_FLASH_TASK_NAME, SEC_FLASH_MSG_MM_READ_CMD, &msg, SEC_FLASH_MSG_MM_READ_CMD, &rsp);
    ret = rsp.ret;
    if (ret == TEE_SUCCESS) {
        if (memmove_s(buffer, size, buffer_local, size) != EOK) {
            tloge("%s\n", __func__);
            ret = TEE_ERROR_SECURITY;
        } else {
            *count = rsp.msg.args_data.arg0;
            object->ObjectInfo->dataPosition += rsp.msg.args_data.arg0;
        }
    }
    (void)__SRE_MemFreeShared(buffer_local, size);
    return ret;
}

/*
 * @brief     : GP TEE API write function in secflash implementation .
 * @param[in] : object, TEE_ObjectHandle containing key information.
 * @param[in] : buffer, The buffer containing the data to write.
 * @param[in] : size, The size of data to write.
 * @param[out]: void.
 * @return    : Operation status: success(0) or other failure status.
 */
TEE_Result sf_write_object_data(TEE_ObjectHandle object, const void *buffer, size_t size)
{
    char *buffer_local = NULL;
    tee_service_ipc_msg msg = {{0}};
    tee_service_ipc_msg_rsp rsp = {0};
    TEE_Result ret;
    uint32_t obj_id;

    ret = sf_check_object_handle(object);
    if (ret != TEE_SUCCESS) {
        tloge("%s\n", __func__);
        return ret;
    }

    if (buffer == NULL || size == 0) {
        tloge("%s, \n", __func__);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    buffer_local = tee_alloc_sharemem_aux(&g_sec_flash_uuid, size);
    if (buffer_local == NULL) {
        tloge("%s\n", __func__);
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    if (memmove_s(buffer_local, size, buffer, size) != EOK) {
        (void)__SRE_MemFreeShared(buffer_local, size);
        tloge("%s\n", __func__);
        return TEE_ERROR_SECURITY;
    }
    obj_id = object->dataName[0];
    msg.args_data.arg0 = object->ObjectInfo->dataPosition;
    msg.args_data.arg1 = size;
    msg.args_data.arg2 = sf_get_mem_type(object->ObjectInfo->handleFlags);
    msg.args_data.arg3 = (uintptr_t)buffer_local;
    msg.args_data.arg4 = obj_id;
    rsp.ret = TEE_ERROR_GENERIC;

    tee_common_ipc_proc_cmd(SEC_FLASH_TASK_NAME, SEC_FLASH_MSG_MM_WRITE_CMD, &msg, SEC_FLASH_MSG_MM_WRITE_CMD, &rsp);

    ret = rsp.ret;
    if (ret == TEE_SUCCESS)
        object->ObjectInfo->dataPosition += size;

    (void)__SRE_MemFreeShared(buffer_local, size);
    return ret;
}

/*
 * @brief     : GP TEE API, not supported by secflash.
 * @param[in] : object, Not used.
 * @param[in] : size, Not used.
 * @param[out]: void.
 * @return    : TEE_ERROR_NOT_SUPPORTED.
 */
TEE_Result sf_truncate_object_data(TEE_ObjectHandle object, size_t size)
{
    unused(object);
    unused(size);

    return TEE_ERROR_NOT_SUPPORTED;
}

/*
 * @brief     : GP TEE API seek function in secflash implementation .
 * @param[in] : object, TEE_ObjectHandle containing key information.
 * @param[in] : offset, The value to be used for changing the position.
 * @param[in] : whence, The postion changing way.
 * @param[out]: void.
 * @return    : Operation status: success(0) or other failure status.
 */
TEE_Result sf_seek_object_data(TEE_ObjectHandle object, int32_t offset, TEE_Whence whence)
{
    tee_service_ipc_msg msg = {{0}};
    tee_service_ipc_msg_rsp rsp = {0};
    TEE_Result ret;

    ret = sf_check_object_handle(object);
    if (ret != TEE_SUCCESS) {
        tloge("%s\n", __func__);
        return ret;
    }

    msg.args_data.arg0 = object->ObjectInfo->dataPosition;
    if (offset < 0) {
        msg.args_data.arg1 = IS_NEGATIVE;
        msg.args_data.arg2 = (uint32_t)(-offset);
    } else {
        msg.args_data.arg1 = 0;
        msg.args_data.arg2 = offset;
    }
    msg.args_data.arg3 = sf_get_mem_type(object->ObjectInfo->handleFlags);
    msg.args_data.arg4 = whence;
    msg.args_data.arg5 = (uint32_t)object->dataName[0];
    rsp.ret = TEE_ERROR_GENERIC;

    tee_common_ipc_proc_cmd(SEC_FLASH_TASK_NAME, SEC_FLASH_MSG_MM_SEEK_CMD, &msg, SEC_FLASH_MSG_MM_SEEK_CMD, &rsp);
    ret = rsp.ret;
    if (ret == TEE_SUCCESS)
        object->ObjectInfo->dataPosition = rsp.msg.args_data.arg0;

    return ret;
}

/*
 * @brief     : GP TEE API close-delete function in secflash implementation .
 * @param[in] : object, TEE_ObjectHandle containing key information.
 * @param[out]: void.
 * @return    : void.
 */
TEE_Result sf_close_and_delete_persistent_object(TEE_ObjectHandle object)
{
    tee_service_ipc_msg msg = {{0}};
    tee_service_ipc_msg_rsp rsp = {0};
    TEE_Result ret;

    ret = sf_check_object_handle(object);
    if (ret != TEE_SUCCESS) {
        tloge("%s\n", __func__);
        return ret;
    }

    msg.args_data.arg0 = sf_get_mem_type(object->ObjectInfo->handleFlags);
    msg.args_data.arg1 = object->dataName[0];
    rsp.ret = TEE_ERROR_GENERIC;

    tee_common_ipc_proc_cmd(SEC_FLASH_TASK_NAME, SEC_FLASH_MSG_MM_DELETE_CMD, &msg, SEC_FLASH_MSG_MM_DELETE_CMD, &rsp);
    ret = rsp.ret;
    if (ret != TEE_SUCCESS) {
        tloge("%s, failed!\n", __func__);
    } else {
        sf_free_object_handle(&object);
    }
    return ret;
}

/*
 * @brief     : GP TEE API get-info function in secflash implementation .
 * @param[in] : object, TEE_ObjectHandle containing key information.
 * @param[out]: pos, Return the current position.
 * @param[out]: len, Return the total size of allocated memory.
 * @return    : Operation status: success(0) or other failure status.
 */
TEE_Result sf_info_object_data(TEE_ObjectHandle object, uint32_t *pos, uint32_t *len)
{
    tee_service_ipc_msg msg = {{0}};
    tee_service_ipc_msg_rsp rsp = {0};
    TEE_Result ret;

    ret = sf_check_object_handle(object);
    if (ret != TEE_SUCCESS) {
        tloge("%s\n", __func__);
        return ret;
    }

    if (pos == NULL || len == NULL) {
        tloge("%s\n", __func__);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    msg.args_data.arg0 = sf_get_mem_type(object->ObjectInfo->handleFlags);
    msg.args_data.arg1 = object->ObjectInfo->dataPosition;
    msg.args_data.arg2 = object->dataName[0];
    rsp.ret = TEE_ERROR_GENERIC;

    tee_common_ipc_proc_cmd(SEC_FLASH_TASK_NAME, SEC_FLASH_MSG_MM_GET_INFO_CMD, &msg,
        SEC_FLASH_MSG_MM_GET_INFO_CMD, &rsp);
    ret = rsp.ret;
    if (ret == TEE_SUCCESS) {
        object->ObjectInfo->dataPosition = rsp.msg.args_data.arg0;
        *pos = rsp.msg.args_data.arg0;

        object->ObjectInfo->maxObjectSize = rsp.msg.args_data.arg1;
        *len = rsp.msg.args_data.arg1;
    }
    return ret;
}

/*
 * @brief     : GP TEE API, not supported by secflash.
 * @param[in] : object, Not used.
 * @param[out]: void.
 * @return    : TEE_ERROR_NOT_SUPPORTED.
 */
TEE_Result sf_sync_persistent_object(TEE_ObjectHandle object)
{
    unused(object);
    return TEE_ERROR_NOT_SUPPORTED;
}

/*
 * @brief     : GP TEE API, not supported by secflash.
 * @param[in] : object, Not used.
 * @param[in] : newObjectID, Not used.
 * @param[in] : newObjectIDLen, Not used.
 * @param[out]: void.
 * @return    : TEE_ERROR_NOT_SUPPORTED.
 */
TEE_Result sf_rename_persistent_object(
    TEE_ObjectHandle object,
    void *newObjectID,
    size_t newObjectIDLen)
{
    unused(object);
    unused(newObjectID);
    unused(newObjectIDLen);
    return TEE_ERROR_NOT_SUPPORTED;
}

/*
 * @brief     : GP TEE API close function in secflash implementation .
 * @param[in] : object, TEE_ObjectHandle containing key information.
 * @param[out]: void.
 * @return    : void.
 */
void sf_close_object(TEE_ObjectHandle object)
{
    tee_service_ipc_msg msg = {{0}};
    tee_service_ipc_msg_rsp rsp = {0};
    TEE_Result ret;

    ret = sf_check_object_handle(object);
    if (ret != TEE_SUCCESS) {
        tloge("%s\n", __func__);
        return;
    }

    msg.args_data.arg0 = sf_get_mem_type(object->ObjectInfo->handleFlags);
    msg.args_data.arg1 = object->dataName[0];
    rsp.ret = TEE_ERROR_GENERIC;

    tee_common_ipc_proc_cmd(SEC_FLASH_TASK_NAME, SEC_FLASH_MSG_MM_OPEN_CMD, &msg, SEC_FLASH_MSG_MM_OPEN_CMD, &rsp);

    if (rsp.ret != TEE_SUCCESS) {
        tloge("%s, failed!\n", __func__);
        return;
    }
    sf_free_object_handle(&object);
}
#else
TEE_Result sf_creat_persistent_object(
    uint32_t storageID,
    const void *objectID, size_t objectIDLen,
    uint32_t flags,
    TEE_ObjectHandle attributes,
    const void *initialData, size_t initialDataLen,
    TEE_ObjectHandle *object)
{
    unused(storageID);
    unused(objectID);
    unused(objectIDLen);
    unused(flags);
    unused(attributes);
    unused(initialData);
    unused(initialDataLen);
    unused(object);
    return TEE_ERROR_NOT_SUPPORTED;
}

TEE_Result sf_open_persistent_object(
    uint32_t storageID,
    const void *objectID, size_t objectIDLen,
    uint32_t flags,
    TEE_ObjectHandle *object)
{
    unused(storageID);
    unused(objectID);
    unused(objectIDLen);
    unused(flags);
    unused(object);
    return TEE_ERROR_NOT_SUPPORTED;
}

TEE_Result sf_read_object_data(TEE_ObjectHandle object, void *buffer, size_t size, uint32_t *count)
{
    unused(object);
    unused(buffer);
    unused(size);
    unused(count);
    return TEE_ERROR_NOT_SUPPORTED;
}

TEE_Result sf_write_object_data(TEE_ObjectHandle object, const void *buffer, size_t size)
{
    unused(object);
    unused(buffer);
    unused(size);
    return TEE_ERROR_NOT_SUPPORTED;
}

TEE_Result sf_truncate_object_data(TEE_ObjectHandle object, size_t size)
{
    unused(object);
    unused(size);
    return TEE_ERROR_NOT_SUPPORTED;
}

TEE_Result sf_seek_object_data(TEE_ObjectHandle object, int32_t offset, TEE_Whence whence)
{
    unused(object);
    unused(offset);
    unused(whence);
    return TEE_ERROR_NOT_SUPPORTED;
}

TEE_Result sf_close_and_delete_persistent_object(TEE_ObjectHandle object)
{
    unused(object);
    return TEE_ERROR_NOT_SUPPORTED;
}

TEE_Result sf_info_object_data(TEE_ObjectHandle object, uint32_t *pos, uint32_t *len)
{
    unused(object);
    unused(pos);
    unused(len);
    return TEE_ERROR_NOT_SUPPORTED;
}

TEE_Result sf_sync_persistent_object(TEE_ObjectHandle object)
{
    unused(object);
    return TEE_ERROR_NOT_SUPPORTED;
}

TEE_Result sf_rename_persistent_object(
    TEE_ObjectHandle object,
    void *newObjectID,
    size_t newObjectIDLen)
{
    unused(object);
    unused(newObjectID);
    unused(newObjectIDLen);
    return TEE_ERROR_NOT_SUPPORTED;
}
void sf_close_object(TEE_ObjectHandle object)
{
    unused(object);
    return;
}
#endif
