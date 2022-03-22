/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: msp tee tlv c file
 * Author: z00387284
 * Create: 2020-01-11
 */
#include "msp_tee_tlv.h"
#include "hisee_try_catch.h"
#include "securec.h"

#define TAG_1BYTE_LEN 1
#define TAG_2BYTE_LEN 2
#define TAG_STRUCT_TYPE_FLAG 0x20
#define TAG_BYTES_MASK  0x1F

#define LENGTH_BYTES_FLAG 0x80
#define LENGTH_1BYTE_MASK 0x7F
#define LENGTH_2BYTE_MASK 0xFF
#define LENGTH_1BYTE_NUM 0x1
#define LENGTH_2BYTE_NUM 0x2
#define LENGTH_FIELD_1BYTE_SIZE 0x1
#define LENGTH_FIELD_2BYTE_SIZE 0x2
#define LENGTH_FIELD_3BYTE_SIZE 0x3

#define BITS_MASK 0xFF

/*
 * @brief      : save tlv to struct msp_tlv_de_data
 * @param[in]  : tag, the tag of the value field
 * @param[in]  : len, the length  of the value field
 * @param[in]  : value, the src addr of the value filed for the data
 * @param[out] : tlv, the parse struct for the tlv
 * @return     : NA
 */
void msp_tee_tlv_save(uint32_t tag, uint32_t len, const uint8_t *value, struct msp_tlv_de_data *tlv)
{
    if (!value || !tlv)
        return;

    tlv->valid = true;
    tlv->tag = tag;
    tlv->len = len;
    tlv->value = value;
}

static uint8_t msp_tlv_get_tag_len(uint16_t tag)
{
    if (((tag >> BITS_OF_BYTE) & TAG_BYTES_MASK) != TAG_BYTES_MASK)
        return TAG_1BYTE_LEN;

    return TAG_2BYTE_LEN;
}

static uint32_t msp_tlv_set_tag(uint16_t tag, uint8_t *tag_value, uint32_t *tag_value_size)
{
    uint8_t tag_len;

    __TRY
    {
        tag_len = msp_tlv_get_tag_len(tag);
        throw_if(*tag_value_size < tag_len, TEE_ERROR_BAD_PARAMETERS);

        *tag_value_size = tag_len;

        if (tag_len == TAG_1BYTE_LEN) {
            *tag_value = (uint8_t)tag;
            return TEE_SUCCESS;
        }

        tag_value[0] = ((tag >> BITS_OF_BYTE) & BITS_MASK);
        tag_value[1] = (tag & BITS_MASK);

        return TEE_SUCCESS;
    }
    __CATCH
    {
        return ERR_CODE;
    }
}

static uint32_t msp_tlv_set_len(uint16_t len, uint8_t *len_value, uint32_t *len_value_size)
{
    __TRY
    {
        throw_if(*len_value_size < LENGTH_FIELD_1BYTE_SIZE, TEE_ERROR_BAD_PARAMETERS);

        if (len <= LENGTH_1BYTE_MASK) {
            *len_value = (uint8_t)len;
            *len_value_size = LENGTH_FIELD_1BYTE_SIZE;

            return TEE_SUCCESS;
        }

        throw_if(*len_value_size < LENGTH_FIELD_2BYTE_SIZE, TEE_ERROR_BAD_PARAMETERS);

        if (len <= LENGTH_2BYTE_MASK) {
            len_value[0] = LENGTH_BYTES_FLAG | LENGTH_1BYTE_NUM;
            len_value[1] = (uint8_t)len;
            *len_value_size = LENGTH_FIELD_2BYTE_SIZE;

            return TEE_SUCCESS;
        }

        throw_if(*len_value_size < LENGTH_FIELD_3BYTE_SIZE, TEE_ERROR_BAD_PARAMETERS);

        len_value[0] = LENGTH_BYTES_FLAG | LENGTH_2BYTE_NUM;
        len_value[1] = ((len >> BITS_OF_BYTE) & BITS_MASK);
        len_value[2] = (len & BITS_MASK); /* 2 means index is 2 */
        *len_value_size = LENGTH_FIELD_3BYTE_SIZE;

        return TEE_SUCCESS;
    }
    __CATCH
    {
        return ERR_CODE;
    }
}

/*
 * @brief        : set tlv for the data which's value filed is array of uint8_t
 * @param[in]    : buffer, the dest tlv buffer addr
 * @param[inout] : buffer_len, the length of the buffer for input, the real used length of the buffer for output
 * @param[in]    : tag, the tag of the value field
 * @param[in]    : len, the length  of the value filed
 * @param[in]    : value, the src addr of the value filed for the data
 * @return       : TEE_Result
 */
TEE_Result msp_set_tlv(void *buffer, uint32_t *buffer_len, uint16_t tag, uint16_t len, const uint8_t *value)
{
    uint32_t rsv_len;
    uint32_t offset = 0;
    TEE_Result result;

    __TRY
    {
        throw_if_null(buffer, TEE_ERROR_BAD_PARAMETERS);
        throw_if_null(buffer_len, TEE_ERROR_BAD_PARAMETERS);
        throw_if_null(value, TEE_ERROR_BAD_PARAMETERS);

        rsv_len = *buffer_len - offset;
        result = msp_tlv_set_tag(tag, buffer + offset, &rsv_len);
        throw_if(result != TEE_SUCCESS, result);

        offset += rsv_len;
        throw_if(*buffer_len < offset, TEE_ERROR_BAD_PARAMETERS);

        rsv_len = *buffer_len - offset;
        result = msp_tlv_set_len(len, buffer + offset, &rsv_len);
        throw_if(result != TEE_SUCCESS, result);

        offset += rsv_len;
        throw_if(*buffer_len < offset, TEE_ERROR_BAD_PARAMETERS);

        rsv_len = *buffer_len - offset;
        throw_if(rsv_len < len, TEE_ERROR_BAD_PARAMETERS);

        if (len == 0)
            return TEE_SUCCESS;

        throw_if_null(value, TEE_ERROR_BAD_PARAMETERS);

        result = memcpy_s(buffer + offset, rsv_len, value, len);
        throw_if(result != EOK, TEE_ERROR_SECURITY);

        *buffer_len = offset + len;

        return TEE_SUCCESS;
    }
    __CATCH
    {
        return ERR_CODE;
    }
}

/*
 * @brief        : set tlv for the data with type uint8_t
 * @param[in]    : buffer, the dest tlv buffer addr
 * @param[inout] : buffer_len, the length of the buffer for input, the real used length of the buffer for output
 * @param[in]    : tag, the tag of the value field
 * @param[in]    : value, the value of the data
 * @return       : TEE_Result
 */
TEE_Result msp_set_tlv_u8(void *buffer, uint32_t *buffer_len, uint16_t tag, uint8_t value)
{
    return msp_set_tlv(buffer, buffer_len, tag, sizeof(uint8_t), &value);
}

/*
 * @brief        : set tlv for the data with type u16
 * @param[in]    : buffer, the dest tlv buffer addr
 * @param[inout] : buffer_len, the length of the buffer for input, the real used length of the buffer for output
 * @param[in]    : tag, the tag of the value field
 * @param[in]    : value, the value of the data
 * @return       : TEE_Result
 */
TEE_Result msp_set_tlv_u16(void *buffer, uint32_t *buffer_len, uint16_t tag, uint16_t value)
{
    uint8_t temp[sizeof(uint16_t)] = {0};

    temp[0] = ((value >> BITS_OF_BYTE) & BITS_MASK);
    temp[1] = (value & BITS_MASK);

    return msp_set_tlv(buffer, buffer_len, tag, sizeof(uint16_t), temp);
}

/*
 * @brief      : set tlv for the data with type u32
 * @param[in]  : buffer, the dest tlv buffer addr
 * @param[inout] : buffer_len, the length of the buffer for input, the real used length of the buffer for output
 * @param[in]  : tag, the tag of the value field
 * @param[in]  : value, the value of the data
 * @return     : TEE_Result
 */
TEE_Result msp_set_tlv_u32(void *buffer, uint32_t *buffer_len, uint16_t tag, uint32_t value)
{
    uint8_t temp[sizeof(uint32_t)];
    uint8_t i;
    uint8_t size = sizeof(uint32_t);

    for (i = 0; i < sizeof(uint32_t); i++)
        temp[i] = ((value >> ((size - 1 - i) * BITS_OF_BYTE)) & BITS_MASK);

    return msp_set_tlv(buffer, buffer_len, tag, sizeof(uint32_t), temp);
}

/*
 * @brief      : tranform the byte order of the uint data
 * @param[inout]  : data, the addr of the uint data, the orign data for input, the new order data for output
 * @param[in]  : size, the bytes num of the unit data
 * @return     : NA
 */
void msp_hton_uint(uint8_t *data, uint32_t size)
{
    uint32_t value = 0;

    if (!data)
        return;

    if (size == sizeof(uint8_t))
        value = *data;
    else if (size == sizeof(uint16_t))
        value = *((uint16_t *)data);
    else if (size == sizeof(uint32_t))
        value = *((uint32_t *)data);
    else
        return;

    for (uint8_t i = 0; i < size; i++)
        data[i] = (value >> (BITS_OF_BYTE * (size - i - 1))) & BITS_MASK;
}

static uint32_t msp_tlv_get_tag(const uint8_t *data, uint32_t data_len, uint32_t *tag_len, uint32_t *tag,
                                bool *is_struct)
{
    __TRY
    {
        throw_if(data_len == 0, TEE_ERROR_BAD_PARAMETERS);
        *tag = data[0];

        /* the bit5 is indicates the tag type, 0: basic type 1: struct bype */
        *is_struct = ((data[0] & TAG_STRUCT_TYPE_FLAG) == TAG_STRUCT_TYPE_FLAG) ? true : false;

        /* if tag len is 1 */
        if ((data[0] & TAG_BYTES_MASK) != TAG_BYTES_MASK) {
            *tag_len = TAG_1BYTE_LEN;

            return TEE_SUCCESS;
        }

        /* if tag len is 2 */
        *tag_len = TAG_2BYTE_LEN;
        throw_if(data_len < *tag_len, TEE_ERROR_BAD_PARAMETERS);
        *tag = *tag << BITS_OF_BYTE;
        *tag = *tag | data[1];

        return TEE_SUCCESS;
    }
    __CATCH
    {
        return ERR_CODE;
    }
}

static uint32_t msp_tlv_get_len(const uint8_t *data, uint32_t data_len, uint32_t *len_len, uint32_t *len)
{
    uint32_t len_bytes = 1;

    __TRY
    {
        throw_if(data_len == 0, TEE_ERROR_BAD_PARAMETERS);

        if ((data[0] & LENGTH_BYTES_FLAG) == LENGTH_BYTES_FLAG) {
            len_bytes = data[0] & LENGTH_1BYTE_MASK;
            *len_len = len_bytes + 1;
            throw_if(data_len < (*len_len), TEE_ERROR_BAD_PARAMETERS);

            switch (len_bytes) {
                case LENGTH_1BYTE_NUM:
                    *len = data[1];
                    return TEE_SUCCESS;
                case LENGTH_2BYTE_NUM:
                    *len = (((uint32_t)data[1]) << BITS_OF_BYTE) | data[2]; /* 2 means index is 2 */
                    return TEE_SUCCESS;
                default:
                    throw(TEE_ERROR_BAD_PARAMETERS);
            }
        } else {
            *len_len = LENGTH_FIELD_1BYTE_SIZE;
            *len = data[0] & LENGTH_1BYTE_MASK;
        }
        return TEE_SUCCESS;
    }
    __CATCH
    {
        return ERR_CODE;
    }
}

/*
 * @brief       : parse the tlv data stream
 * @param[in]   : data, the tlv data address
 * @param[in]   : data_len, the length of the tlv data
 * @param[out]  : tlv_stru, the buffer addr of the struct which is defined by user for save the tlv data.
 * @param[int]  : tlv_stru_len, the length of the buffer tlv_stru.
 * @param[int]  : de_fun, the callback function for saving tlv data to tlv_stru
 * @return      : TEE_Result
 */
TEE_Result msp_de_tlv(const uint8_t *data, uint32_t data_len, void *tlv_stru, uint32_t tlv_stru_len, de_tlv_fun de_fun)
{
    struct msp_tlv_de_data tlv;
    uint32_t offset = 0;
    uint32_t len;
    bool is_struct = false;
    TEE_Result result;

    __TRY
    {
        throw_if_null(data, TEE_ERROR_BAD_PARAMETERS);
        throw_if_null(tlv_stru, TEE_ERROR_BAD_PARAMETERS);
        throw_if_null(de_fun, TEE_ERROR_BAD_PARAMETERS);

        while (offset < data_len) {
            result = msp_tlv_get_tag((uint8_t *)(data + offset), data_len - offset, &len, &tlv.tag, &is_struct);
            throw_if(result != TEE_SUCCESS, result);
            throw_if(len == 0, TEE_ERROR_BAD_PARAMETERS);
            offset += len;

            result = msp_tlv_get_len((uint8_t *)(data + offset), data_len - offset, &len, &tlv.len);
            throw_if(result != TEE_SUCCESS, result);
            throw_if(len == 0, TEE_ERROR_BAD_PARAMETERS);
            offset += len;

            result = de_fun(tlv.tag, tlv.len, (uint8_t *)(data + offset), tlv_stru, tlv_stru_len);
            throw_if(tlv.len == 0, TEE_ERROR_BAD_PARAMETERS);
            throw_if(result != TEE_SUCCESS, result);

            if (!is_struct)
                offset += tlv.len;
        }
        return TEE_SUCCESS;
    }
    __CATCH
    {
        return ERR_CODE;
    }
}

/*
 * @brief      : save one uint data from prase struct of tlv
 * @param[out] : dest, the dest addr of the uint data
 * @param[in]  : size, the bytes num of the dest space to save the uint data
 * @param[in]  : de_data, the parse struct of the uint data
 * @return     : TEE_Result
 */
TEE_Result msp_tlv_de_save_uint(uint8_t *dest, uint32_t size, struct msp_tlv_de_data *de_data)
{
    uint8_t i;
    uint32_t temp = 0;

    __TRY
    {
        throw_if_null(de_data, TEE_ERROR_BAD_PARAMETERS);
        if (!de_data->valid)
            return TEE_SUCCESS;

        throw_if(de_data->len > sizeof(uint32_t), TEE_ERROR_BAD_PARAMETERS);
        throw_if(de_data->len == 0, TEE_ERROR_BAD_PARAMETERS);
        throw_if_null(dest, TEE_ERROR_BAD_PARAMETERS);
        throw_if((size != sizeof(uint8_t)) && (size != sizeof(uint16_t)) && (size != sizeof(uint32_t)),
                 TEE_ERROR_BAD_PARAMETERS);

        for (i = 0; i < de_data->len; i++) {
            temp <<= BITS_OF_BYTE;
            temp |= de_data->value[i];
        }

        if (size == sizeof(uint8_t))
            *dest = (uint8_t)temp;
        else if (size == sizeof(uint16_t))
            *((uint16_t *)dest) = (uint16_t)temp;
        else
            *((uint32_t *)dest) = temp;
        return TEE_SUCCESS;
    }
    __CATCH
    {
        return ERR_CODE;
    }
}

/*
 * @brief      : save data from prase struct of tlv
 * @param[out] : dest, the dest addr of the uint data
 * @param[in]  : size, the bytes num of the dest space to save the data
 * @param[in]  : de_data, the parse struct of the uint data
 * @return     : TEE_Result
 */
TEE_Result msp_tlv_de_save_u8_list(uint8_t *dest, uint32_t *size, struct msp_tlv_de_data *de_data)
{
    uint32_t result;

    __TRY
    {
        throw_if_null(dest, TEE_ERROR_BAD_PARAMETERS);
        throw_if_null(size, TEE_ERROR_BAD_PARAMETERS);
        throw_if_null(de_data, TEE_ERROR_BAD_PARAMETERS);
        throw_if(!de_data->valid, TEE_ERROR_BAD_PARAMETERS);
        throw_if(de_data->len > *size, TEE_ERROR_BAD_PARAMETERS);
        throw_if_null(de_data->value, TEE_ERROR_BAD_PARAMETERS);

        result = memcpy_s(dest, *size, de_data->value, de_data->len);
        throw_if(result != EOK, TEE_ERROR_SECURITY);

        *size = de_data->len;

        return TEE_SUCCESS;
    }
    __CATCH
    {
        return ERR_CODE;
    }
}
