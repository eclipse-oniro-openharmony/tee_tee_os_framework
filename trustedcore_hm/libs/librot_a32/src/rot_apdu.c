/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: Root of Trust Service.
 * Author: t00360454
 * Create: 2020-02-12
 * History: 2020-02-12 t00360454 create.
 */
#include "rot_apdu.h"
#include "rot_util.h"
#include "securec.h"
#include "tee_log.h"
#include "mem_ops_ext.h"
#include "tee_inner_uuid.h"

/* msp rot sa return status word */
#define SW_SUCCESS ((uint16_t)0x9000)
#define rot_err(sw) (0xAE060000 | (sw))

/* apdu message definition */
#define APDU_HEADER_LEN_EXT 7
#define MIN_APDU_LC_EXT 0x0100
#define MAX_APDU_LC_EXT 0x7FF0
#define MAX_APDU_LE_EXT 0x7FF0
#define APDU_SW_LEN 2

#define OFFSET_CLA 0
#define OFFSET_INS 1
#define OFFSET_P1 2
#define OFFSET_P2 3
#define OFFSET_LC 4
#define OFFSET_LC_EXT 5
#define OFFSET_CDATA_EXT 7

/* apdu command data format */
/* APDU header + APDU body[Length(2Bytes) + Data(Length in Bytes) + Padding(00...)] */
#define APDU_COMMAND_DATA_LEN_IN_BYTES 2
#define OFFSET_CONTENT_EXT (OFFSET_CDATA_EXT + APDU_COMMAND_DATA_LEN_IN_BYTES)

/*
 * @brief    : calc the minimum size of response data.
 * @param[in]: length, the size of apdu response buffer in bytes.
 * @return   : the minimum size of apdu response data.
 */
uint32_t apdu_ext_get_response_size(uint32_t outer_length)
{
    return min(outer_length, MAX_APDU_LE_EXT) + APDU_SW_LEN;
}

/*
 * @brief    : calc the total size of apdu message.
 * @param[in]: length, the length of apdu command data in bytes.
 * @return   : the total size of apdu message.
 */
uint32_t apdu_ext_calc_size(uint32_t length)
{
    uint32_t data_len;

    if (length < MIN_APDU_LC_EXT - APDU_COMMAND_DATA_LEN_IN_BYTES) {
        /* pad it to extended apdu */
        data_len = MIN_APDU_LC_EXT;
    } else if (length <= MAX_APDU_LC_EXT - APDU_COMMAND_DATA_LEN_IN_BYTES) {
        data_len = APDU_COMMAND_DATA_LEN_IN_BYTES + length;
    } else {
        tloge("rot, %s, length error: %x\n", __func__, length);
        return 0;
    }

    return APDU_HEADER_LEN_EXT + data_len;
}

/*
 * @brief    : check the apdu response status word.
 * @param[in]: rapdu, the buffer of apdu response data.
 * @param[in]: rapdu_len, the real size of rapdu in bytes.
 * @return   : TEE_SUCCESS or TEE_FAIL.
 */
static TEE_Result apdu_ext_is_success(const uint8_t *rapdu, uint32_t rapdu_len)
{
    uint32_t sw_offset;
    uint16_t sw_value;

    if (rapdu_len < APDU_SW_LEN) {
        tloge("rot, %s, sa response len error: %x\n", __func__, rapdu_len);
        return TEE_ERROR_NO_DATA;
    }

    sw_offset = rapdu_len - APDU_SW_LEN;
    sw_value = get_u16(rapdu, sw_offset);
    if (sw_value != SW_SUCCESS) {
        tloge("rot, %s, sa response sw error: %x\n", __func__, sw_value);
        return rot_err(sw_value);
    }

    return TEE_SUCCESS;
}

/*
 * @brief     : alloc memory to store the apdu message.
 * @param[out]: msg, the new apdu message.
 * @param[in] : capdu_len, the length of apdu command in bytes.
 * @param[in] : rapdu_len, the maximum size of rapdu in bytes.
 * @return    : Operation status, success(0) or other failure status.
 */
TEE_Result apdu_ext_alloc_message(struct apdu_message *msg, uint32_t capdu_len, uint32_t rapdu_max_len)
{
    if (!msg) {
        tloge("rot, %s, null pointer\n", __func__);
        return TEE_ERROR_GENERIC;
    }

    TEE_UUID rot_uuid = TEE_SERVICE_ROT;

    /* alloc memory */
    msg->capdu_len = capdu_len;
    msg->capdu = (uint8_t *)tee_alloc_sharemem_aux(&rot_uuid, capdu_len);
    if (!msg->capdu) {
        tloge("rot, %s, alloc capdu failed: %x\n", __func__, capdu_len);
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    msg->rapdu = (uint8_t *)tee_alloc_sharemem_aux(&rot_uuid, rapdu_max_len);
    if (!msg->rapdu) {
        tloge("rot, %s, alloc rapdu failed: %x\n", __func__, rapdu_max_len);
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    msg->rapdu_len = (uint32_t *)tee_alloc_sharemem_aux(&rot_uuid, sizeof(uint32_t));
    if (!msg->rapdu_len) {
        tloge("rot, %s, alloc rapdu_len failed: %x\n", __func__, sizeof(uint32_t));
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    msg->rapdu_max_size = rapdu_max_len;
    *msg->rapdu_len = rapdu_max_len;
    return TEE_SUCCESS;
}

/*
 * @brief    : clear the allocated memory and free it.
 * @param[in]: msg, the apdu message.
 * @return   : void.
 */
void apdu_ext_clear_message(struct apdu_message *msg)
{
    if (!msg)
        return;

    if (msg->capdu) {
        (void)memset_s(msg->capdu, msg->capdu_len, 0, msg->capdu_len);
        (void)__SRE_MemFreeShared(msg->capdu, msg->capdu_len);
    }

    if (msg->rapdu) {
        (void)memset_s(msg->rapdu, msg->rapdu_max_size, 0, msg->rapdu_max_size);
        (void)__SRE_MemFreeShared(msg->rapdu, msg->rapdu_max_size);
    }

    if (msg->rapdu_len) {
        (void)memset_s(msg->rapdu_len, sizeof(uint32_t), 0, sizeof(uint32_t));
        (void)__SRE_MemFreeShared(msg->rapdu_len, sizeof(uint32_t));
    }

    (void)memset_s(msg, sizeof(*msg), 0, sizeof(*msg));
}

/*
 * @brief     : set apdu header.
 * @param[out]: msg, the apdu message.
 * @param[in] : cla, apdu header class.
 * @param[in] : ins, apdu header instruction.
 * @param[in] : p1, apdu header parameter 1.
 * @param[in] : p2, apdu header parameter 2.
 * @return    : Operation status, success(0) or other failure status.
 */
TEE_Result apdu_ext_set_header(struct apdu_message *msg, uint8_t cla, uint8_t ins, uint8_t p1, uint8_t p2)
{
    if (!msg || !msg->capdu) {
        tloge("rot, %s, null pointer\n", __func__);
        return TEE_ERROR_GENERIC;
    }

    if (msg->capdu_len < APDU_HEADER_LEN_EXT) {
        tloge("rot, %s, failed: %x\n", __func__, msg->capdu_len);
        return TEE_ERROR_SHORT_BUFFER;
    }

    msg->capdu[OFFSET_CLA] = cla;
    msg->capdu[OFFSET_INS] = ins;
    msg->capdu[OFFSET_P1] = p1;
    msg->capdu[OFFSET_P2] = p2;
    msg->capdu[OFFSET_LC] = 0x00;
    set_u16(msg->capdu, OFFSET_LC_EXT, msg->capdu_len - APDU_HEADER_LEN_EXT);

    return TEE_SUCCESS;
}

/*
 * @brief     : init apdu body with LV format.
 * @param[out]: tlver, the constructed BER tlv byte array.
 * @param[in] : msg, the apdu message.
 * @return    : TEE_SUCCESS or TEE_XXX.
 */
TEE_Result apdu_ext_body_init(struct ber_tlv *tlver, const struct apdu_message *msg)
{
    if (!tlver || !msg || !msg->capdu) {
        tloge("rot, %s, null pointer, %x, %x\n", __func__, tlver, msg);
        return TEE_ERROR_GENERIC;
    }

    if (msg->capdu_len < OFFSET_CONTENT_EXT) {
        tloge("rot, %s, error: capdu len = %x\n", __func__, msg->capdu_len);
        return TEE_ERROR_GENERIC;
    }

    bertlv_init(tlver, msg->capdu + OFFSET_CONTENT_EXT, msg->capdu_len - OFFSET_CONTENT_EXT);
    return TEE_SUCCESS;
}

/*
 * @brief     : append the TLV in the specified byte array to the apdu body's V.
 * @param[in] : tlver, the constructed BER tlv byte array.
 * @param[in] : tag, TLV's T.
 * @param[in] : length, TLV's L.
 * @param[in] : value, TLV's V.
 * @return    : TEE_SUCCESS or TEE_XXX.
 */
TEE_Result apdu_ext_body_append_tlv(struct ber_tlv *tlver, uint8_t tag, uint32_t length, const uint8_t *value)
{
    if (!tlver || !tlver->buffer || !value) {
        tloge("rot, %s, null pointer, %x, %x\n", __func__, tlver, value);
        return TEE_ERROR_GENERIC;
    }

    if (bertlv_append(tlver, tag, length, value) == 0) {
        tloge("rot, %s, failed: %x, %x\n", __func__, tag, length);
        return TEE_ERROR_GENERIC;
    }

    return TEE_SUCCESS;
}

/*
 * @brief     : append the V in the specified byte array to the apdu body's V.
 * @param[in] : tlver, the constructed BER tlv byte array.
 * @param[in] : length, TLV's L.
 * @param[in] : value, TLV's V.
 * @return    : TEE_SUCCESS or TEE_XXX.
 */
TEE_Result apdu_ext_body_append_v(struct ber_tlv *tlver, uint32_t length, const uint8_t *value)
{
    if (!tlver || !tlver->buffer || !value) {
        tloge("rot, %s, null pointer\n", __func__);
        return TEE_ERROR_GENERIC;
    }

    if (memcpy_s(tlver->buffer + tlver->offset, tlver->size - tlver->offset, value, length) != EOK) {
        tloge("rot, %s, memcpy failed: %x, %x\n", __func__, tlver->size - tlver->offset, length);
        return TEE_ERROR_SECURITY;
    }

    tlver->offset += length;

    return TEE_SUCCESS;
}

/*
 * @brief     : append the TLV with an u32 Value to the apdu body's V.
 * @param[in] : tlver, the constructed BER tlv byte array.
 * @param[in] : tag, TLV's T.
 * @param[in] : value, TLV's V.
 * @return    : TEE_SUCCESS or TEE_XXX.
 */
TEE_Result apdu_ext_body_append_u32(struct ber_tlv *tlver, uint8_t tag, uint32_t value)
{
    if (!tlver || !tlver->buffer) {
        tloge("rot, %s, null pointer\n", __func__);
        return TEE_ERROR_GENERIC;
    }

    if (bertlv_append_u32(tlver, tag, value) == 0) {
        tloge("rot, %s, failed: %x, %x\n", __func__, tag, value);
        return TEE_ERROR_GENERIC;
    }

    return TEE_SUCCESS;
}

/*
 * @brief     : update apdu body's L.
 * @param[in] : tlver, the constructed BER tlv byte array.
 * @param[in] : msg, the apdu message.
 * @return    : Operation status, success(0) or other failure status.
 */
TEE_Result apdu_ext_body_append_end(const struct ber_tlv *tlver, struct apdu_message *msg)
{
    if (!tlver || !tlver->buffer || !msg || !msg->capdu) {
        tloge("rot, %s, null pointer\n", __func__);
        return TEE_ERROR_GENERIC;
    }

    set_u16(msg->capdu, OFFSET_CDATA_EXT, tlver->offset);
    return TEE_SUCCESS;
}

/*
 * @brief         : check APDU status word and unpackage response data.
 * @param[in]     : msg, the apdu message.
 * @param[out]    : buffer, the buffer to store the response data.
 * @param[in/out] : size, the maximum size of buffer in bytes for input, the real size of
 *                  buffer in bytes for output.
 * @return        : Operation status, success(0) or other failure status.
 */
TEE_Result apdu_ext_unpackage_rapdu(struct apdu_message *msg, uint8_t *buffer, uint32_t *size)
{
    TEE_Result ret;
    uint32_t data_len;

    if (!msg || !msg->rapdu || !msg->rapdu_len) {
        tloge("rot, %s, null pointer\n", __func__);
        return TEE_ERROR_GENERIC;
    }

    if (*msg->rapdu_len > msg->rapdu_max_size) {
        tloge("rot, %s, illegal response, len=%x, max=%x\n", __func__, *msg->rapdu_len, msg->rapdu_max_size);
        return TEE_ERROR_SECURITY;
    }

    /* check status word */
    ret = apdu_ext_is_success(msg->rapdu, *msg->rapdu_len);
    if (ret != TEE_SUCCESS)
        return ret;

    /* unpackage apdu response data */
    if (!buffer || !size)
        return TEE_SUCCESS;

    data_len = *msg->rapdu_len - APDU_SW_LEN;
    if (data_len > *size) {
        tloge("rot, %s, rapdu_len error: %x, %x\n", __func__, *size, data_len);
        return TEE_ERROR_SHORT_BUFFER;
    }

    if (memcpy_s(buffer, *size, msg->rapdu, data_len) != EOK) {
        tloge("rot, %s, memcopy failed\n", __func__);
        return TEE_ERROR_SECURITY;
    }
    *size = data_len;

    return TEE_SUCCESS;
}
