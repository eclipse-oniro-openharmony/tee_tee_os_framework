/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Create: 2022-04-25
 * Description: Secure storage expansion API, Functions in this header file are deprecated. Do not use them.
 */

#ifndef __TEE_EXT_TRUSTED_STORAGE_API_LEGACY_H
#define __TEE_EXT_TRUSTED_STORAGE_API_LEGACY_H

#include "tee_defines.h"


TEE_Result TEE_Ext_CreatePersistentObject(TEE_UUID target, uint32_t storageID, const void *objectID, size_t objectIDLen,
                                          uint32_t flags, TEE_ObjectHandle attributes, const void *initialData,
                                          size_t initialDataLen, TEE_ObjectHandle *object);

TEE_Result TEE_Ext_OpenPersistentObject(TEE_UUID target, uint32_t storageID, const void *objectID, size_t objectIDLen,
                                        uint32_t flags, TEE_ObjectHandle *object);


TEE_Result TEE_Ext_DeleteAllObjects(TEE_UUID target);

#endif