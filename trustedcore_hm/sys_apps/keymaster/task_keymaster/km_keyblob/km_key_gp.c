/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: keymaster key format transfer between GP and buffer;
 * Create: 2020-11-09
 */
#include "tee_internal_api.h"
#include "securec.h"
#include "km_defines.h"
TEE_Result gp_buffer_to_key_obj(const uint8_t *buffer, uint32_t buffer_len, TEE_ObjectHandle key_obj)
{
    uint32_t read_size = 0;
    uint32_t attr_id;
    uint32_t len;
    uint8_t *dest_buffer = NULL;
    uint32_t dest_len;
    uint32_t i;
    for (i = 0; i < key_obj->attributesLen; i++) {
        if (read_size + sizeof(attr_id) + sizeof(len) > buffer_len) {
            tloge("buffer to key: read len %u, buffer len %u", read_size, buffer_len);
            return TEE_ERROR_READ_DATA;
        }
        attr_id = *(uint32_t *)(buffer + read_size);
        read_size += sizeof(attr_id);
        len = *(uint32_t *)(buffer + read_size);
        read_size += sizeof(len);
        if (attr_id != key_obj->Attribute[i].attributeID || (read_size + len) > buffer_len) {
            /* crt mode not this attr */
            if (key_obj->Attribute[i].attributeID == TEE_ATTR_RSA_PRIVATE_EXPONENT &&
                attr_id == TEE_ATTR_RSA_PRIME1 && i < (key_obj->attributesLen - 1)) {
                key_obj->Attribute[i].content.ref.length = 0;
                i++;
            } else {
                tloge("buffer to key: key type not match key attribute 0x%x, index %u, expected attrID %x\n", attr_id,
                      i, key_obj->Attribute[i].attributeID);
                return TEE_ERROR_READ_DATA;
            }
        }

        if (object_attr_type(attr_id) == OBJECT_ATTR_BUFFER) {
            dest_buffer = key_obj->Attribute[i].content.ref.buffer;
            dest_len = key_obj->Attribute[i].content.ref.length;
            key_obj->Attribute[i].content.ref.length = len;
        } else {
            dest_buffer = (uint8_t *)&key_obj->Attribute[i].content.value;
            dest_len = sizeof(key_obj->Attribute[i].content.value);
        }
        if (len > (buffer_len - read_size) || memcpy_s(dest_buffer, dest_len, buffer + read_size, len) != EOK) {
            tloge("buffer to key: copy attribute 0x%x fail, dest %u src %u", attr_id, dest_len, len);
            return TEE_ERROR_READ_DATA;
        }
        read_size += len;
    }
    key_obj->ObjectInfo->handleFlags |= TEE_HANDLE_FLAG_INITIALIZED;
    return TEE_SUCCESS;
}

TEE_Result key_object_to_buffer(const TEE_ObjectHandle key_obj, uint8_t *kb, uint32_t *buffer_len)
{
    uint32_t len = 0;
    uint32_t attr_id;
    uint8_t *value = NULL;
    uint32_t attri_count = key_obj->attributesLen;
    uint32_t i;
    uint32_t data_len = 0;
    if (buffer_len == NULL) {
        tloge("buffer_len is null");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    /* tlv data, buffer->length not than 4k, it check in invoke check. */
    for (i = 0; i < attri_count; i++) {
        attr_id = key_obj->Attribute[i].attributeID;
        /* type, len */
        if ((data_len + sizeof(attr_id) + sizeof(len)) > *buffer_len) {
            tloge("key object to buffer: buffer len is too short, need %u", data_len);
            return TEE_ERROR_SHORT_BUFFER;
        }
        *(uint32_t *)(kb + data_len) = attr_id;
        data_len += sizeof(attr_id);
        if (object_attr_type(attr_id) == OBJECT_ATTR_BUFFER) {
            value = key_obj->Attribute[i].content.ref.buffer;
            len = key_obj->Attribute[i].content.ref.length;
        } else {
            value = (uint8_t *)&key_obj->Attribute[i].content.value;
            len = sizeof(key_obj->Attribute[i].content.value);
        }
        *(uint32_t *)(kb + data_len) = len;
        data_len += sizeof(len);
        /* store buffer or value(value) */
        if ((len > *buffer_len) || (data_len + len > *buffer_len) ||
            (memcpy_s(kb + data_len, *buffer_len - data_len, value, len) != EOK)) {
            tloge("key object to buffer: copy value failed");
            return TEE_ERROR_SHORT_BUFFER;
        }
        data_len += len;
        tlogd("key object 0x%x to buffer: buf_len is %d", attr_id, data_len);
    }
    *buffer_len = data_len;
    return TEE_SUCCESS;
}
