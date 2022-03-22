/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: apdu package of ROT Service.
 * Author: t00360454
 * Create: 2020-03-23
 * History: 2020-03-23 t00360454 create.
 */
#ifndef _ROOT_OF_TRUST_APDU_H_
#define _ROOT_OF_TRUST_APDU_H_
#include <tee_internal_api.h>
#include "rot_tlv.h"

/* apdu message structure */
struct apdu_message {
    uint8_t *capdu;          /* command APDU */
    uint32_t capdu_len;      /* command APDU length */
    uint8_t *rapdu;          /* response APDU */
    uint32_t *rapdu_len;     /* response APDU length */
    uint32_t rapdu_max_size; /* the maximum size of rapdu buffer in bytes */
};

/*
 * @brief    : calc the minimum size of response data.
 * @param[in]: length, the size of apdu response buffer in bytes.
 * @return   : the minimum size of apdu response data.
 */
uint32_t apdu_ext_get_response_size(uint32_t outer_length);

/*
 * @brief    : calc the total size of apdu message.
 * @param[in]: length, the length of apdu command data in bytes.
 * @return   : the total size of apdu message.
 */
uint32_t apdu_ext_calc_size(uint32_t length);

/*
 * @brief     : alloc memory to store the apdu message.
 * @param[out]: msg, the new apdu message.
 * @param[in] : capdu_len, the length of apdu command in bytes.
 * @param[in] : rapdu_len, the maximum size of rapdu in bytes.
 * @return    : TEE_SUCCESS or TEE_XXX.
 */
TEE_Result apdu_ext_alloc_message(struct apdu_message *msg, uint32_t capdu_len, uint32_t rapdu_max_len);

/*
 * @brief    : clear the allocated memory and free it.
 * @param[in]: msg, the apdu message.
 * @return   : void.
 */
void apdu_ext_clear_message(struct apdu_message *msg);

/*
 * @brief     : set apdu header.
 * @param[out]: msg, the apdu message.
 * @param[in] : cla, apdu header class.
 * @param[in] : ins, apdu header instruction.
 * @param[in] : p1, apdu header parameter 1.
 * @param[in] : p2, apdu header parameter 2.
 * @return    : Operation status, success(0) or other failure status.
 */
TEE_Result apdu_ext_set_header(struct apdu_message *msg, uint8_t cla, uint8_t ins, uint8_t p1, uint8_t p2);

/*
 * @brief     : init apdu body with LV format.
 * @param[out]: tlver, the constructed BER tlv byte array.
 * @param[in] : msg, the apdu message.
 * @return    : TEE_SUCCESS or TEE_XXX.
 */
TEE_Result apdu_ext_body_init(struct ber_tlv *tlver, const struct apdu_message *msg);

/*
 * @brief     : append the TLV in the specified byte array to the apdu body's V.
 * @param[in] : tlver, the constructed BER tlv byte array.
 * @param[in] : tag, TLV's T.
 * @param[in] : length, TLV's L.
 * @param[in] : value, TLV's V.
 * @return    : TEE_SUCCESS or TEE_XXX.
 */
TEE_Result apdu_ext_body_append_tlv(struct ber_tlv *tlver, uint8_t tag, uint32_t length, const uint8_t *value);

/*
 * @brief     : append the V in the specified byte array to the apdu body's V.
 * @param[in] : tlver, the constructed BER tlv byte array.
 * @param[in] : length, TLV's L.
 * @param[in] : value, TLV's V.
 * @return    : TEE_SUCCESS or TEE_XXX.
 */
TEE_Result apdu_ext_body_append_v(struct ber_tlv *tlver, uint32_t length, const uint8_t *value);

/*
 * @brief     : append the TLV with an u32 Value to the apdu body's V.
 * @param[in] : tlver, the constructed BER tlv byte array.
 * @param[in] : tag, TLV's T.
 * @param[in] : value, TLV's V.
 * @return    : TEE_SUCCESS or TEE_XXX.
 */
TEE_Result apdu_ext_body_append_u32(struct ber_tlv *tlver, uint8_t tag, uint32_t value);

/*
 * @brief     : update apdu body's L.
 * @param[in] : tlver, the constructed BER tlv byte array.
 * @param[in] : msg, the apdu message.
 * @return    : TEE_SUCCESS or TEE_XXX.
 */
TEE_Result apdu_ext_body_append_end(const struct ber_tlv *tlver, struct apdu_message *msg);

/*
 * @brief         : check APDU status word and unpackage response data.
 * @param[in]     : msg, the apdu message.
 * @param[out]    : buffer, the buffer to store the response data.
 * @param[in/out] : size, the maximum size of buffer in bytes for input, the real size of
 *                  buffer in bytes for output.
 * @return        : Operation status, success(0) or other failure status.
 */
TEE_Result apdu_ext_unpackage_rapdu(struct apdu_message *msg, uint8_t *buffer, uint32_t *size);

#endif