/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: BER-TLV function of ROT Service.
 * Author: t00360454
 * Create: 2020-03-23
 * History: 2020-03-23 t00360454 create.
 */
#ifndef _ROOT_OF_TRUST_TLV_H_
#define _ROOT_OF_TRUST_TLV_H_
#include <tee_internal_api.h>

/* BER-TLV structure */
struct ber_tlv {
    uint8_t *buffer;
    uint32_t size;
    uint32_t offset;
};

/*
 * @brief    : returns the number of bytes required to represent TLV structure.
 * @param[in]: tag, TLV's tag.
 * @param[in]: len, TLV's length.
 * @return   : the byte length of the TLV.
 */
uint32_t bertlv_size(uint8_t tag, uint32_t len);

/*
 * @brief     : init the BER TLV.
 * @param[out]: dst, the constructed BER tlv byte array.
 * @param[in] : buffer, the buffer of byte array.
 * @param[in] : max_size, maximum size of the buffer in bytes.
 * @return    : void.
 */
void bertlv_init(struct ber_tlv *dst, uint8_t *buffer, uint32_t max_size);

/*
 * @brief     : append the TLV in the specified byte array to the constructed BER tlv in the
 *              specified output byte array.
 * @param[out]: dst, the constructed BER tlv byte array.
 * @param[in] : tag, TLV's T.
 * @param[in] : length, TLV's L.
 * @param[in] : value, TLV's V.
 * @return    : the size of the resulting output TLV.
 */
uint32_t bertlv_append(struct ber_tlv *dst, uint8_t tag, uint32_t length, const uint8_t *value);

/*
 * @brief     : append the TLV with a u32 value to the constructed BER tlv in the specified output byte array.
 * @param[out]: dst, the constructed BER tlv byte array.
 * @param[in] : tag, TLV's T.
 * @param[in] : value, TLV's V.
 * @return    : the size of the resulting output TLV.
 */
uint32_t bertlv_append_u32(struct ber_tlv *dst, uint8_t tag, uint32_t value);

#endif
