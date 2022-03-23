/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2019. All rights reserved.
 * Description: sec_flash_api function
 * Author: tjl
 * Create: 2019-08-19
 */
#ifndef _SEC_FLASH_API_H_
#define _SEC_FLASH_API_H_

#include "sec_flash_ext_api.h"

TEE_Result sf_creat_persistent_object(
    uint32_t storageID,
    const void *objectID, size_t objectIDLen,
    uint32_t flags,
    TEE_ObjectHandle attributes,
    const void *initialData, size_t initialDataLen,
    TEE_ObjectHandle *object);
TEE_Result sf_open_persistent_object(
    uint32_t storageID,
    const void *objectID, size_t objectIDLen,
    uint32_t flags,
    TEE_ObjectHandle *object);
TEE_Result sf_read_object_data(TEE_ObjectHandle object, void *buffer, size_t size, uint32_t *count);
TEE_Result sf_write_object_data(TEE_ObjectHandle object, const void *buffer, size_t size);
TEE_Result sf_truncate_object_data(TEE_ObjectHandle object, size_t size);
TEE_Result sf_seek_object_data(TEE_ObjectHandle object, int32_t offset, TEE_Whence whence);
TEE_Result sf_close_and_delete_persistent_object(TEE_ObjectHandle object);
TEE_Result sf_info_object_data(TEE_ObjectHandle object, uint32_t *pos, uint32_t *len);
TEE_Result sf_sync_persistent_object(TEE_ObjectHandle object);
TEE_Result sf_rename_persistent_object(
    TEE_ObjectHandle object,
    void *newObjectID,
    size_t newObjectIDLen);
void sf_close_object(TEE_ObjectHandle object);
#endif
