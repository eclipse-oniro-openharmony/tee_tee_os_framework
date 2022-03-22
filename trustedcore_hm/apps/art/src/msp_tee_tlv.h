/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: msp tee tlv header file
 * Author     : z00387284
 * Create     : 2020/01/11
 */

#ifndef __MSP_TEE_TLV_H__
#define __MSP_TEE_TLV_H__
#include "tee_internal_api.h"

#define BITS_OF_BYTE 8

/* de means decode and encode */
struct msp_tlv_de_data {
    uint32_t valid;
    uint32_t tag;
    uint32_t len;
    const uint8_t *value;
};

/*
 * @brief      : save tlv to struct msp_tlv_de_data
 * @param[in]  : tag, the tag of the value field
 * @param[in]  : len, the lehgth  of the value filed
 * @param[in]  : value, the src addr of the value filed for the data
 * @param[out] : tlv, the parse struct for the tlv
 * @return     : NA
 */
void msp_tee_tlv_save(uint32_t tag, uint32_t len, const uint8_t *value, struct msp_tlv_de_data *tlv);

/*
 * @brief        : set tlv for the data which's value filed is array of u8
 * @param[in]    : buffer, the dest tlv buffer addr
 * @param[inout] : buffer_len, the length of the buffer for input, the real used length of the buffer for output
 * @param[in]    : tag, the tag of the value field
 * @param[in]    : len, the lehgth  of the value filed
 * @param[in]    : value, the src addr of the value filed for the data
 * @return       : TEE_Result
 */
TEE_Result msp_set_tlv(void *buffer, uint32_t *buffer_len, uint16_t tag, uint16_t len, const uint8_t *value);

/*
 * @brief        : set tlv for the data with type u8
 * @param[in]    : buffer, the dest tlv buffer addr
 * @param[inout] : buffer_len, the length of the buffer for input, the real used length of the buffer for output
 * @param[in]    : tag, the tag of the value field
 * @param[in]    : value, the value of the data
 * @return       : TEE_Result
 */
TEE_Result msp_set_tlv_u8(void *buffer, uint32_t *buffer_len, uint16_t tag, uint8_t value);

/*
 * @brief        : set tlv for the data with type u16
 * @param[in]    : buffer, the dest tlv buffer addr
 * @param[inout] : buffer_len, the length of the buffer for input, the real used length of the buffer for output
 * @param[in]    : tag, the tag of the value field
 * @param[in]    : value, the value of the data
 * @return       : TEE_Result
 */
TEE_Result msp_set_tlv_u16(void *buffer, uint32_t *buffer_len, uint16_t tag, uint16_t value);

/*
 * @brief        : set tlv for the data with type u32
 * @param[in]    : buffer, the dest tlv buffer addr
 * @param[inout] : buffer_len, the length of the buffer for input, the real used length of the buffer for output
 * @param[in]    : tag, the tag of the value field
 * @param[in]    : value, the value of the data
 * @return       : TEE_Result
 */
TEE_Result msp_set_tlv_u32(void *buffer, uint32_t *buffer_len, uint16_t tag, uint32_t value);

/*
 * @brief        : tranform the byte order of the uint data
 * @param[inout] : data, the addr of the uint data, the orign data for input, the new order data for output
 * @param[in]    : size, the bytes num of the unit data
 * @return       : NA
 */
void msp_hton_uint(uint8_t *data, uint32_t size);

#define msp_set_hton(uint_x) msp_hton_uint((uint8_t *)&(uint_x), sizeof(uint_x))
#define msp_set_ntoh(uint_x) msp_set_hton(uint_x)

/*
 * @brief       : the type of tlv parse callback func
 * @param[in]   : tag, the tag of the value field
 * @param[in]   : len, the lehgth  of the value filed
 * @param[in]   : value, the src addr of the value filed for the data
 * @param[out]  : tlv_stru, the buffer addr of the struct which is defined by user for save the tlv data.
 * @param[int]  : tlv_stru_len, the length of the buffer tlv_stru.
 * @return      : TEE_Result
 */
typedef TEE_Result (*de_tlv_fun)(uint32_t tag, uint32_t len, const uint8_t *value, void *tlv_stru,
                                 uint32_t tlv_stru_len);
/*
 * @brief       : parse the tlv data stream
 * @param[in]   : data, the tlv data address
 * @param[in]   : data_len, the length of the tlv data
 * @param[out]  : tlv_stru, the buffer addr of the struct which is defined by user for save the tlv data.
 * @param[int]  : tlv_stru_len, the length of the buffer tlv_stru.
 * @param[int]  : de_fun, the callback function for saving tlv data to tlv_stru
 * @return      : TEE_Result
 */
TEE_Result msp_de_tlv(const uint8_t *data, uint32_t data_len, void *tlv_stru, uint32_t tlv_stru_len, de_tlv_fun de_fun);

/*
 * @brief      : save one uint data from prase struct of tlv
 * @param[out] : dest, the dest addr of the uint data
 * @param[in]  : size, the bytes num of the dest space to save the uint data
 * @param[in]  : de_data, the parse struct of the uint data
 * @return     : TEE_Result
 */
TEE_Result msp_tlv_de_save_uint(uint8_t *dest, uint32_t size, struct msp_tlv_de_data *de_data);
#define msp_tlv_de_save_u(mem, de_data) msp_tlv_de_save_uint((uint8_t *)&mem, sizeof(mem), (de_data));

/*
 * @brief      : save data from prase struct of tlv
 * @param[out] : dest, the dest addr of the uint data
 * @param[in]  : size, the bytes num of the dest space to save the data
 * @param[in]  : de_data, the parse struct of the uint data
 * @return     : TEE_Result
 */
TEE_Result msp_tlv_de_save_u8_list(uint8_t *dest, uint32_t *size, struct msp_tlv_de_data *de_data);

#endif /* __MSP_TEE_TLV_H__ */
