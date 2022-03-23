/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: BER-TLV of ROT Service.
 * Author: t00360454
 * Create: 2020-02-12
 * History: 2020-02-12 t00360454 create.
 */
#include "rot_tlv.h"
#include "rot_util.h"
#include "securec.h"

/* BER-TLV definition */
#define BER_LEN_OCTETS_ONE_BYTE_MAX_VALUE 0x7F
#define BER_LEN_OCTETS_TWO_BYTE_MAX_VALUE 0xFF
#define BER_LEN_OCTETS_FIRST_BYTE_VALUE 0x80
#define BER_LEN_OCTETS_ONE_BYTE_LEN 1
#define BER_LEN_OCTETS_TWO_BYTE_LEN 2
#define BER_LEN_OCTETS_THREE_BYTE_LEN 3

/*
 * @brief    : returns the number of bytes required to represent TLV structure.
 * @param[in]: tag, TLV's tag.
 * @param[in]: len, TLV's length.
 * @return   : the byte length of the TLV.
 */
uint32_t bertlv_size(uint8_t tag, uint32_t len)
{
    uint8_t octets;

    if (len <= BER_LEN_OCTETS_ONE_BYTE_MAX_VALUE)
        octets = BER_LEN_OCTETS_ONE_BYTE_LEN;
    else if (len <= BER_LEN_OCTETS_TWO_BYTE_MAX_VALUE)
        octets = BER_LEN_OCTETS_TWO_BYTE_LEN;
    else
        octets = BER_LEN_OCTETS_THREE_BYTE_LEN;

    /* the byte length of the T(1) + L(octets)+V(len) */
    return sizeof(tag) + octets + len;
}

/*
 * @brief     : init the BER TLV.
 * @param[out]: dst, the constructed BER tlv byte array.
 * @param[in] : buffer, the buffer of byte array.
 * @param[in] : max_size, maximum size of the buffer in bytes.
 * @return    : void.
 */
void bertlv_init(struct ber_tlv *dst, uint8_t *buffer, uint32_t max_size)
{
    if (!dst)
        return;

    dst->buffer = buffer;
    dst->size = max_size;
    dst->offset = 0;
}

/*
 * @brief     : append the TLV in the specified byte array to the constructed BER tlv in the
 *              specified output byte array.
 * @param[out]: dst, the constructed BER tlv byte array.
 * @param[in] : tag, TLV's T.
 * @param[in] : length, TLV's L.
 * @param[in] : value, TLV's V.
 * @return    : the size of the resulting output TLV.
 */
uint32_t bertlv_append(struct ber_tlv *dst, uint8_t tag, uint32_t length, const uint8_t *value)
{
    uint32_t size = bertlv_size(tag, length);
    uint32_t offset;
    uint8_t *p = NULL;

    if (!dst || !dst->buffer || !value)
        return 0;

    if (size > dst->size - dst->offset || dst->offset > dst->size)
        return 0;

    offset = dst->offset;
    p = dst->buffer;

    /* append tag */
    p[offset++] = tag;

    /* append length */
    if (length <= BER_LEN_OCTETS_ONE_BYTE_MAX_VALUE) {
        p[offset++] = length;
    } else if (length <= BER_LEN_OCTETS_TWO_BYTE_MAX_VALUE) {
        p[offset++] = BER_LEN_OCTETS_FIRST_BYTE_VALUE | BER_LEN_OCTETS_ONE_BYTE_LEN;
        p[offset++] = length;
    } else {
        p[offset++] = BER_LEN_OCTETS_FIRST_BYTE_VALUE | BER_LEN_OCTETS_TWO_BYTE_LEN;
        set_u16(p, offset, length);
        offset += BER_LEN_OCTETS_TWO_BYTE_LEN;
    }

    /* append value */
    if (length > 0) {
        if (memcpy_s(p + offset, dst->size - offset, value, length) != EOK)
            return 0;
        offset += length;
    }

    if (offset - dst->offset != size)
        return 0;

    /* update constructed BER TLV */
    dst->offset = offset;
    return offset;
}

/*
 * @brief     : append the TLV with a u32 value to the constructed BER tlv in the specified output byte array.
 * @param[out]: dst, the constructed BER tlv byte array.
 * @param[in] : tag, TLV's T.
 * @param[in] : value, TLV's V.
 * @return    : the size of the resulting output TLV.
 */
uint32_t bertlv_append_u32(struct ber_tlv *dst, uint8_t tag, uint32_t value)
{
    uint8_t buf[sizeof(uint32_t)] = {0};

    set_u32(buf, 0, value);
    return bertlv_append(dst, tag, sizeof(uint32_t), buf);
}
