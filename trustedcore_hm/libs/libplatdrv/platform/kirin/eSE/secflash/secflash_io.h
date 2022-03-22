/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: secure flash module driver.
 * Create: 2019/9/3
 */

#ifndef _SECFLASH_IO_H_
#define _SECFLASH_IO_H_

#include "types.h"
#ifdef SECFLASH_TEE
#include "sre_typedef.h"
#endif

enum secflash_io_rw_flag {
    SECFLASH_READ,
    SECFLASH_WRITE,
};

struct secflash_io_rwgt {
    uint32_t value;
    uint64_t tick;
    enum secflash_io_rw_flag rw_flag;
};

/*
 * @brief : secflash time sequence struct, follow GP 0.39.
 * @param : bwt: Block Waiting Time; mpot: Minimum Polling Time; rwgt: Read Write Guard Time.
 */
struct secflash_io_time {
    uint32_t bwt;
    uint32_t pot;
    struct secflash_io_rwgt rwgt;
};

/*
 * @brief           : secflash_io_init: data link io init
 * @param pavailable: in secflash available.SECFLASH_TRUE or SECFLASH_FALSE
 * @return RET_Ok(0) if success, other if failed.
 */
uint32_t secflash_io_init(uint32_t *pavailable);

/*
 * @brief        : secflash_io_read: reset by data link
 * @param buf    : data buffer
 * @param buflen : buffer len
 * @param plen[in/out] : buffer len to read
 * @param timeout      : Time limitation in msecond
 * @return RET_Ok(0) if success, other if failed.
 */
uint32_t secflash_io_read(uint8_t *buf, uint32_t buflen, uint32_t *plen, uint32_t timeout);

/*
 * @brief     : secflash_io_write: write data.
 * @param buf : data buffer
 * @param len : buffer len
 */
uint32_t secflash_io_write(uint8_t *buf, uint32_t len);

/*
 * @brief : secflash_io_hard_reset: hard reset via gpio io.
 */
uint32_t secflash_io_hard_reset(uint32_t delay);

/*
 * @brief     : set the secflash time sequence(GP 0.39).
 * @param[in] : bwt: Block Waiting Time; mpot: Minimum Polling Time; rwgt: Read Write Guard Time.
 */
void secflash_io_set_time_sequence(uint32_t bwt, uint32_t mpot, uint32_t rwgt);

/*
 * @brief : calculate crc value.
 * @return crc value
 */
uint16_t block_calc_crc(uint8_t *buf, uint32_t buflen);

void trace_hex(const uint8_t *buf, const uint32_t buflen);

/*
 * @brief : secflash_io_addr_exchange: exchenge the secflash addr.
 */
void secflash_io_addr_exchange(void);

void secflash_io_get_type(uint32_t *ptype);

#endif

