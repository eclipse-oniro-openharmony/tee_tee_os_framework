/*$$$!!Warning: Huawei key information asset. No spread without permission.$$$*/
/*CODEMARK:mJSkoqPZ5FEeD8fzH9bAQfhyPrkcI5cbzjotjI99J9PTkCMNHMtR+8Ejd3mKEkWbMFYmuIhV
lw/je6uplRzXM4SMvhun8vRGD9mNqO2kY4/aQFDUiG2CG+z+BR1XavYOLbgQ6mxl4mdMDMUc
pTTvsgNnGY+uGDhrcSrYT/yiWUcPU+7hHj/1z+1w4sei8NKrE5YtD4ycmPizGfaNhWQY5YvG
yUQ4I+iaikKhay3gs3gbvr2F/fo9kmuK6WNlljMWqZQckvm//k0TiyJFZq4NZA==#*/
/*$$$!!Warning: Deleting or modifying the preceding information is prohibited.$$$*/
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2021. All rights reserved.
 * Description: trusted stroage api for object
 * Author: Limingjuan limingjuan@huawei.com
 * Create: 2020-12-23
 */
#include "tee_object_api.h"
#include <securec.h>
#include "tee_log.h"
#include "tee_obj.h"
#include "tee_core_api.h"
#include "tee_ss_agent_api.h"
#include "tee_obj_attr.h"

#ifndef SUPPORT_GP_PANIC
#define TEE_Panic(x) \
    do { \
    } while (0)
#endif

void TEE_GetObjectInfo(TEE_ObjectHandle object, TEE_ObjectInfo *objectInfo)
{
    uint32_t pos = 0;
    uint32_t len = 0;
    TEE_Result ret;
    tlogd("TEE_GetObjectInfo start!\n");

    if (objectInfo == NULL || object == NULL) {
        tloge("bad parameter!\n");
        return;
    }
    if (check_object(object) != TEE_SUCCESS) {
        tloge("object is invalid\n");
        return;
    }

    if (object->ObjectInfo == NULL) {
        tloge("objectInfo in obj is invalid\n");
        return;
    }

    if ((object->ObjectInfo->handleFlags & TEE_HANDLE_FLAG_PERSISTENT) != 0) {
        ret = TEE_InfoObjectData(object, &pos, &len);
        if (ret != TEE_SUCCESS) {
            tloge("info object failed, ret=0x%x\n", ret);
            return;
        }
        objectInfo->dataSize = len;
        objectInfo->dataPosition = pos;
    } else {
        objectInfo->dataSize = 0;
        objectInfo->dataPosition = 0;
    }
    objectInfo->objectType = object->ObjectInfo->objectType;
#ifndef GP_SUPPORT
    objectInfo->objectSize = object->ObjectInfo->objectSize;
    objectInfo->maxObjectSize = object->ObjectInfo->maxObjectSize;
#else
    objectInfo->keySize = object->ObjectInfo->keySize;
    objectInfo->maxKeySize = object->ObjectInfo->maxKeySize;
#endif
    objectInfo->objectUsage = object->ObjectInfo->objectUsage;
    objectInfo->handleFlags = object->ObjectInfo->handleFlags;

    tlogd("TEE_GetObjectInfo end!\n");
    return;
}

TEE_Result TEE_GetObjectInfo1(
    TEE_ObjectHandle object,
    TEE_ObjectInfo *objectInfo)
{
    uint32_t pos = 0;
    uint32_t len = 0;
    TEE_Result ret;
    tlogd("TEE_GetObjectInfo1 start!\n");

    if (objectInfo == NULL || object == NULL) {
        tloge("bad parameter!\n");
        TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (check_object(object) != TEE_SUCCESS) {
        tloge("object is invalid\n");
        TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (object->ObjectInfo == NULL) {
        tloge("objectInfo in obj is invalid\n");
        TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if ((object->ObjectInfo->handleFlags & TEE_HANDLE_FLAG_PERSISTENT) != 0) {
        ret = TEE_InfoObjectData(object, &pos, &len);
        if (ret != TEE_SUCCESS) {
            tloge("info object failed, ret=0x%x\n", ret);
            TEE_Panic(TEE_ERROR_STORAGE_NOT_AVAILABLE);
            return TEE_ERROR_STORAGE_NOT_AVAILABLE;
        }
        objectInfo->dataSize = len;
        objectInfo->dataPosition = pos;
    } else {
        objectInfo->dataSize = 0;
        objectInfo->dataPosition = 0;
    }

    objectInfo->objectType = object->ObjectInfo->objectType;
    objectInfo->objectSize = object->ObjectInfo->objectSize;
    objectInfo->maxObjectSize = object->ObjectInfo->maxObjectSize;
    objectInfo->objectUsage = object->ObjectInfo->objectUsage;
    objectInfo->handleFlags = object->ObjectInfo->handleFlags;

    tlogd("TEE_GetObjectInfo1 end!\n");
    return TEE_SUCCESS;
}

void TEE_RestrictObjectUsage(TEE_ObjectHandle object, uint32_t objectUsage)
{
    tlogd("TEE_RestrictObjectUsage start!\n");

    if (object == NULL) {
        tloge("bad parameter!\n");
        return;
    }
    if (check_object(object) != TEE_SUCCESS) {
        tloge("object is invalid\n");
        return;
    }

    if (object->ObjectInfo == NULL) {
        tloge("objectInfo in obj is invalid\n");
        return;
    }
    object->ObjectInfo->objectUsage = (object->ObjectInfo->objectUsage) & (objectUsage);

    return;
}

TEE_Result TEE_RestrictObjectUsage1(
    TEE_ObjectHandle  object,
    uint32_t objectUsage)
{
    tlogd("TEE_RestrictObjectUsage1 start!\n");

    if (object == NULL) {
        tloge("bad parameter!\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (check_object(object) != TEE_SUCCESS) {
        tloge("object is invalid\n");
#ifdef SUPPORT_GP_PANIC
        TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
#endif
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (object->ObjectInfo == NULL) {
        tloge("objectInfo in obj is invalid\n");
#ifdef SUPPORT_GP_PANIC
        TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
#endif
        return TEE_ERROR_BAD_PARAMETERS;
    }
    object->ObjectInfo->objectUsage = (object->ObjectInfo->objectUsage) & (objectUsage);

    return TEE_SUCCESS;
}

static TEE_Result get_obj_attr_param_check(TEE_ObjectHandle object, size_t *size)
{
    /* Make sure the object is initialized */
    if (object == NULL || size == NULL) {
        tloge("bad parameter!\n");
        return  TEE_ERROR_BAD_PARAMETERS;
    }

    if (check_object(object) != TEE_SUCCESS) {
        tloge("object is invalid\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (object->ObjectInfo == NULL) {
        tloge("objectInfo in obj is invalid\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if ((object->ObjectInfo->handleFlags & TEE_HANDLE_FLAG_INITIALIZED) != TEE_HANDLE_FLAG_INITIALIZED) {
        tloge("obj not initialized\n");
        return  TEE_ERROR_ITEM_NOT_FOUND;
    }
    return TEE_SUCCESS;
}

TEE_Result TEE_GetObjectBufferAttribute(
    TEE_ObjectHandle object,
    uint32_t attributeID,
    void *buffer, size_t *size)
{
    void *src = NULL;
    uint32_t attrc;
    uint32_t i = 0;

    TEE_Result ret = get_obj_attr_param_check(object, size);
    if (ret != TEE_SUCCESS)
        return ret;

    /* public judge */
    if (TEE_ATTR_IS_PROTECTED(attributeID)) {
        if ((object->ObjectInfo->objectUsage & TEE_USAGE_EXTRACTABLE) == 0) {
            tloge("Access denied\n");
            return TEE_ERROR_ACCESS_DENIED;
        }
    }

    if (TEE_ATTR_IS_BUFFER(attributeID)) {
        if (object->Attribute == NULL)
            return TEE_ERROR_BAD_PARAMETERS;

        attrc = get_attr_count_for_object_type(object->ObjectInfo->objectType);
        while (i < attrc) {
            if (object->Attribute[i].attributeID != attributeID) {
                i++;
                continue;
            }

            src = object->Attribute[i].content.ref.buffer;
            if (src == NULL)
                return TEE_ERROR_BAD_STATE;

            if (buffer == NULL) {
                *size = object->Attribute[i].content.ref.length;
                return TEE_ERROR_SHORT_BUFFER;
            }
            if (*size < object->Attribute[i].content.ref.length) {
                tloge("buffer is too small\n");
                *size = object->Attribute[i].content.ref.length;
                return  TEE_ERROR_SHORT_BUFFER;
            }
            if (memmove_s(buffer, *size, src, object->Attribute[i].content.ref.length) != EOK)
                return TEE_ERROR_SECURITY;
            *size = object->Attribute[i].content.ref.length;
            return TEE_SUCCESS;
        }
        tloge("this attrbuteID is not exist\n");
        return TEE_ERROR_ITEM_NOT_FOUND;
    }
    tloge("attributeID 29 bit is wrong\n");
    return TEE_ERROR_BAD_PARAMETERS;
}

TEE_Result TEE_GetObjectValueAttribute(TEE_ObjectHandle object, uint32_t attributeID,
    uint32_t *a, uint32_t *b)
{
    uint32_t attrc;
    uint32_t i = 0;
    tlogd("TEE_GetObjectValueAttribute start!\n");

    /* Make sure the object is initialized */
    if (object == NULL || (a == NULL && b == NULL)) {
        tloge("bad parameter!\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (check_object(object) != TEE_SUCCESS) {
        tloge("object is invalid\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (object->ObjectInfo == NULL) {
        tloge("objectInfo in obj is invalid\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if ((object->ObjectInfo->handleFlags &
         TEE_HANDLE_FLAG_INITIALIZED) != TEE_HANDLE_FLAG_INITIALIZED) {
        tloge("obj not initialized\n");
        return TEE_ERROR_ITEM_NOT_FOUND;
    }

    /* public judge */
    if (TEE_ATTR_IS_PROTECTED(attributeID)) {
        if ((object->ObjectInfo->objectUsage & TEE_USAGE_EXTRACTABLE) == 0) {
            tloge("Access denied\n");
            return TEE_ERROR_ACCESS_DENIED;
        }
    }
    if (TEE_ATTR_IS_VALUE(attributeID)) {
        if (object->Attribute == NULL)
            return TEE_ERROR_BAD_PARAMETERS;
        attrc = get_attr_count_for_object_type(object->ObjectInfo->objectType);
        while (i < attrc) {
            if (object->Attribute[i].attributeID != attributeID) {
                i++;
                continue;
            }
            if (a != NULL)
                *a = object->Attribute[i].content.value.a;
            if (b != NULL)
                *b = object->Attribute[i].content.value.b;
            return TEE_SUCCESS;
        }
        return TEE_ERROR_ITEM_NOT_FOUND;
    }
    tloge("attributeID 29 bit is wrong\n");
    return TEE_ERROR_BAD_PARAMETERS;
}

void TEE_CloseObject(TEE_ObjectHandle object)
{
    if (check_object_valid(object) != TEE_SUCCESS) {
        tloge("object is invalid\n");
        TEE_Panic(TEE_ERROR_BAD_PARAMETERS);
        return;
    }

    /* save objectinfo */
    if ((object->ObjectInfo->handleFlags & TEE_HANDLE_FLAG_PERSISTENT) != 0) {
        tlogd("this is a persistent object\n");
        ss_agent_close_object(object);
    } else {
        tlogd("this is a transitent object\n");

        /* Make Persistent object to be transient object to use TEE_FreeTransientObject */
        object->ObjectInfo->handleFlags &= (~TEE_HANDLE_FLAG_PERSISTENT);
        TEE_FreeTransientObject(object);
        tlogd("TEE_CloseObject end!\n");
        return;
    }
}
