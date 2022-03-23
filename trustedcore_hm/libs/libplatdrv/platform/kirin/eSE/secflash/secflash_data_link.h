/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: secure flash module driver.
 * Create: 2019/9/3
 */

#ifndef _SECFLASH_H_
#define _SECFLASH_H_

#include "types.h"
#ifdef SECFLASH_TEE
#include "sre_typedef.h"
#endif
#include "secflash_def.h"

#define SECFLASH_RET_SUCCESS 0
#define SECFLASH_RET_INVALID_PARAMETER 0x01
#define SECFLASH_RET_INVALID_BLOCK 0x02
#define SECFLASH_RET_INVALID_STATE 0x03
#define SECFLASH_RET_CRC_ERROR 0x04
#define SECFLASH_RET_OTHER_ERR 0x05
#define SECFLASH_RET_TIME_OUT 0x06
#define SECFLASH_RET_BUSY 0x07
#define SECFLASH_RET_ERR 0x08
#define SECFLASH_RET_BUF_TOO_SMALL 0x09
#define SECFLASH_RET_DRV_NACK 0x0a
#define SECFLASH_RET_DRV_TIMEOUT 0x0b
#define SECFLASH_RET_DRV_OTHER 0x0c
#define SECFLASH_RET_DTS_ERR 0x0d
#define SECFLASH_RET_DTS_ABSENCE 0x0e

#define SECFLASH_RESET_TYPE_SOFT 0
#define SECFLASH_RESET_TYPE_HARD 1

/*  NOTE  define same as secureflash_boot.h */
#define SECFLASH_CHIP_TYPE_NXP 0xa5c89cea
#define SECFLASH_CHIP_TYPE_ST 0xe59a6b89

struct secflash_block_handle {
    enum trans_state block_state;
    uint32_t block_type;
    uint32_t (*block_handle)(struct block_info *pinfo, uint32_t type);
};

struct sblock_decode_handle {
    enum sblock_type type;
    uint32_t (*decode_handle)(struct block_info *pblock, uint32_t s_type, uint8_t *pbuf, uint32_t len);
};

struct secflash_cip_info {
    uint8_t category_indi;
    uint8_t compact_header;
    uint8_t product_name[HB_PRODUCT_NAME_LEN];
    uint8_t firmware_version[HB_FIRMWARE_VERSION_LEN];
    uint8_t status_indi[HB_STATUS_INDICATOR_LEN];
};

/*
 * @brief      : secflash_init: initialize in boot up.
 *               CIP process here.
 * @param      : ptype: Detected chip type. SECFLASH_CHIP_TYPE_NXP or
 *               SECFLASH_CHIP_TYPE_ST if not NULL
 * @return secflash_RET_SUCCESS(0) if success, other if failed.
 */
uint32_t secflash_init(uint32_t *ptype);

/*
 * @brief           : secflash_transceive: Send receive app data, chaining
 *                    if exceed data link layer block size.
 * @param pinbuf    : input data buffer.
 * @param inbuflen  : input buffer length.
 * @param indatalen : app data length in buffer.
 * @param poutbuf   : out app data buffer.
 * @param outbuflen : out buffer length.
 * @param outdatalen: Expect to receive app data length.
 * @return secflash_RET_SUCCESS(0) if success, other if failed.
 */
uint32_t secflash_transceive(uint8_t *pinbuf, uint32_t inbuflen,
                             uint32_t indatalen, uint8_t *poutbuf,
                             uint32_t outbuflen, uint32_t *outdatalen);

/*
 * @brief       : secflash_chip_rese: Reset flash chip by type.
 * @param pinbuf: SECFLASH_RESET_TYPE_SOFT or SECFLASH_RESET_TYPE_HARD
 * @return secflash_RET_SUCCESS(0) if success, other if failed.
 */
uint32_t secflash_chip_reset(uint32_t type);

/*
 * @brief      : secflash_power_save: Set chip to power saving mode.
 * @return secflash_RET_SUCCESS(0) if success, other if failed.
 */
uint32_t secflash_power_save(void);
uint32_t block_transeive_with_retry(enum trans_state state);

/*
 * @brief      : get the secure flash device cip information in fastboot, according to GP secure flash protocol.
 * @param[out] : cip_info: return the device cip information, according to GP secure flash protocol.
 * @return     : success -- SECFLASH_OK
 *               fail    -- SECFLASH_ERROR
 */
uint32_t secflash_get_cip_info(struct secflash_cip_info *cip_info);

#endif
