/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: secure flash module driver.
 * Create: 2019/9/3
 */

#include "secflash_io.h"
#include "secflash_timer.h"
#include "i3c.h"
#include "secflash_data_link.h"
#include "secflash_def.h"

#ifdef SECFLASH_TEE
#include "sre_typedef.h"
#include "hisi_debug.h"
#include "hisi_boot.h"
#include "boot_sharedmem.h"
#include "gpio.h"
#else
#include "debug.h"
#include "secureflash_boot.h"
#include "../../../plat/hisilicon/kirin990/include/kirin990_gpio.h"
#endif

#define SECFLASH_GPIO 280
#define NXP_ADDR 0x48
#define ST_ADDR 0x0C
#define DELAY_TIMES_WRITE 10
#define DELAY_TIMES_READ 20

#define DELAY_TIME_GPIO 500
#define POLL_TIMES 10
#define POLL_BYTE 0
#define POLL_LEN 1
#define NOP_COUNT 500
#define SECFLASH_CRC32_POLY 0x8408

#define SECFLASH_MAKEERR(e, l)                                \
    (SECFLASH_MODULE_DATA_LINK_IO | (((l) & 0x000000FF) << 4) | (e))

#ifndef unused
#define unused(x) (void)(x)
#endif

uint32_t g_addr;
uint32_t g_gpio_num;

static struct secflash_io_time g_secflash_time;

#ifdef SECFLASH_TEE
/*  NOTE porting from factory code */
#define SECFLASH_ST_EXIST_MAGIC      0xe59a6b89
#define SECFLASH_NXP_EXIST_MAGIC     0xa5c89cea
#define SECFLASH_IS_ABSENCE_MAGIC    0x70eb2c2d

struct secflash_dts_info {
    unsigned int fabricator_id;
    unsigned int chip_version;
    unsigned int total_size;
    unsigned int interface;
    unsigned int reset_gpio_num;
};

struct secflash_status_info {
    struct secflash_dts_info parsed_dts_value;
    unsigned int device_status;
    unsigned int device_efuse_counter;
    unsigned int reserved;
};
#endif

static void secflash_io_set_time_default(void)
{
    g_secflash_time.bwt = PROTO_DEFAULT_BWT;
    g_secflash_time.pot = PROTO_DEFAULT_MPOT;
    g_secflash_time.rwgt.value = PROTO_DEFAULT_RWGT;
    g_secflash_time.rwgt.rw_flag = SECFLASH_WRITE;
    g_secflash_time.rwgt.tick = secflash_get_timer_value();
}

/*
 * @brief     : set the secflash time sequence(GP 0.39).
 * @param[in] : bwt: Block Waiting Time; mpot: Minimum Polling Time; rwgt: Read Write Guard Time.
 */
void secflash_io_set_time_sequence(uint32_t bwt, uint32_t mpot, uint32_t rwgt)
{
    g_secflash_time.bwt = bwt;
    g_secflash_time.pot = mpot;
    g_secflash_time.rwgt.value = rwgt;
}

static void secflash_io_do_rwgt(enum secflash_io_rw_flag flag)
{
    if (g_secflash_time.rwgt.rw_flag == flag)
        return;
    secflash_timer_delay(g_secflash_time.rwgt.tick, g_secflash_time.rwgt.value);
}

static void secflash_io_rwgt_tick(enum secflash_io_rw_flag flag)
{
    g_secflash_time.rwgt.rw_flag = flag;
    g_secflash_time.rwgt.tick = secflash_get_timer_value();
}

void trace_hex(const uint8_t *buf, const uint32_t buflen)
{
    uint32_t i;

    /* check buffer len in uplayer */
    for (i = 0; i < buflen; i++)
        SECFLASH_PRINT("0x%02x, ", buf[i]);
    SECFLASH_PRINT("\n");
    unused(buf);
}

/*
 * @brief : calculate crc value.
 * @return crc value
 */
uint16_t block_calc_crc(uint8_t *buf, uint32_t buflen)
{
    /* init value */
    /* ignore alg spec using magic value */
    uint16_t crc = 0xFFFF;
    uint16_t i = 0;
    int32_t bit;
    uint16_t word[sizeof(uint16_t)] = {0};

    /* check param in uplayer */
    if (!buf) {
        SECFLASH_ERR();
        return 0;
    }
    /* ignore alg spec using magic value */
    for (; i < buflen; i++) {
        crc ^= buf[i];
        for (bit = BITS_IN_BYTE; bit > 0; --bit) {
            if ((crc & 0x0001) == 0x0001)
                crc = (uint16_t)((crc >> 1) ^ SECFLASH_CRC32_POLY);
            else
                crc >>= 1;
        }
    }
    crc ^= 0xFFFF;

    /* ignore alg spec using magic value */
    if (g_addr == NXP_ADDR) {
        word[0] = (crc & 0xFF); /* 0xFF : get low 8 bit */
        word[1] = ((crc >> BITS_IN_BYTE) & 0xFF); /* 0xFF : get low 8 bit */
        crc = (word[0] << BITS_IN_BYTE) | word[1];
    }

    return crc;
}

#ifdef SECFLASH_TEE
static int32_t block_read(uint8_t bus_num, uint8_t slave, uint8_t *data, uint16_t len, uint8_t mode)
{
    int32_t ret;

    /* parameters check in hisi_i3c_block_read */
    hisi_i3c_init(bus_num);
    ret = hisi_i3c_block_read(bus_num, slave, data, len, mode);

    hisi_i3c_exit(bus_num);

    return ret;
}

static int32_t block_write(uint8_t bus_num, uint8_t slave, uint8_t *data, uint16_t len, uint8_t mode)
{
    int32_t ret;

    /* parameters check in hisi_i3c_block_write */
    hisi_i3c_init(bus_num);
    ret = hisi_i3c_block_write(bus_num, slave, data, len, mode);

    hisi_i3c_exit(bus_num);

    return ret;
}
#endif

/*
 * @brief           : secflash_io_init: data link io init
 * @param pavailable: in secflash available.SECFLASH_TRUE or SECFLASH_FALSE
 * @return RET_Ok(0) if success, other if failed.
 */
uint32_t secflash_io_init(uint32_t *pavailable)
{
    uint32_t ret;
    uint32_t device_status;
    struct secflash_status_info sinfo;

    if (!pavailable) {
        SECFLASH_ERR();
        return SECFLASH_MAKEERR(SECFLASH_RET_INVALID_PARAMETER, __LINE__);
    }

#ifndef SECFLASH_TEE
    ret = secflash_get_device_status(&sinfo);
    if (ret != SECFLASH_RET_SUCCESS) {
        SECFLASH_ERR();
        return SECFLASH_MAKEERR(SECFLASH_RET_DTS_ERR, __LINE__);
    }
#else
    ret = get_shared_mem_info(TEEOS_SHARED_MEM_SECFLASH, (uint32_t *)&sinfo, sizeof(sinfo));
    if (ret != SRE_OK) {
        SECFLASH_ERR();
        return SECFLASH_MAKEERR(SECFLASH_RET_DTS_ERR, __LINE__);
    }
#endif
    g_gpio_num = sinfo.parsed_dts_value.reset_gpio_num;
    device_status = sinfo.device_status;

    if (device_status == SECFLASH_NXP_EXIST_MAGIC) { /* nxp */
        SECFLASH_TRACE("==N!");
        g_addr = NXP_ADDR;
        *pavailable = SECFLASH_TRUE;
    } else if (device_status == SECFLASH_ST_EXIST_MAGIC) { /* ST */
        SECFLASH_TRACE("==S!");
        g_addr = ST_ADDR;
        *pavailable = SECFLASH_TRUE;
    } else {
        SECFLASH_TRACE("invalied!");
        *pavailable = SECFLASH_FALSE;
        SECFLASH_ERR();
        return SECFLASH_MAKEERR(SECFLASH_RET_DTS_ABSENCE, __LINE__);
    }

    secflash_io_set_time_default();

#ifndef SECFLASH_TEE
    set_gpio_direction(g_gpio_num, GPIO_DIR_OUT);
    set_gpio_value(g_gpio_num, GPIOMUX_HIGH);
    secflash_udelay(BLOCK_DERESET_TIME);
#endif

    return SECFLASH_RET_SUCCESS;
}

static uint32_t secflash_io_read_inf_crc(uint8_t *buf, uint16_t len, uint32_t *plen)
{
    uint32_t ret;

    if (!buf || !plen) {
        SECFLASH_ERR();
        return SECFLASH_MAKEERR(SECFLASH_RET_INVALID_PARAMETER, __LINE__);
    }
    if (len > BLOCK_INF_MAX_LEN) {
        SECFLASH_ERR();
        SECFLASH_LOG("secflash:read data ifs error!\n");
        return SECFLASH_MAKEERR(SECFLASH_RET_INVALID_BLOCK, __LINE__);
    }
    len += BLOCK_CRC_LEN;
#ifdef SECFLASH_TEE
    ret = block_read(I3C4, g_addr, buf + BLOCK_OFFSET_INFO, len, I3C_MODE_I2C);
#else
    ret = i3c_block_read(I3C_4, g_addr, buf + BLOCK_OFFSET_INFO, len, I3C_MODE_I2C);
#endif
    if (ret == I3C_OK) {
        trace_hex(buf, len + BLOCK_OFFSET_INFO);
        *plen = BLOCK_OFFSET_INFO + len;
        ret = SECFLASH_RET_SUCCESS;
    } else {
        SECFLASH_ERR();
        ret = SECFLASH_MAKEERR(SECFLASH_RET_DRV_OTHER, __LINE__);
    }
    return ret;
}

/*
 * @brief        : secflash_io_read: reset by data link
 * @param buf    : data buffer
 * @param buflen : buffer len
 * @param plen[in/out] : buffer len to read
 * @param timeout      : Time limitation in msecond
 * @return RET_Ok(0) if success, other if failed.
 */
uint32_t secflash_io_read(uint8_t *buf, uint32_t buflen, uint32_t *plen, uint32_t timeout)
{
    int32_t ret_i;
    uint32_t ret = SECFLASH_MAKEERR(SECFLASH_RET_ERR, __LINE__);
    uint16_t len = BLOCK_OFFSET_INFO;
    uint64_t pot_tick;
    uint64_t bwt_tick_begin, bwt_tick_end;

    if (!buf || !plen || buflen > BLOCK_MAX_LEN) {
        SECFLASH_ERR();
        return SECFLASH_MAKEERR(SECFLASH_RET_INVALID_PARAMETER, __LINE__);
    }

    SECFLASH_PRINT("io r%s, %d, 0x%x, time:%u\n", __func__, __LINE__, g_addr, timeout);
    *plen = 0;

    secflash_io_do_rwgt(SECFLASH_READ);
    bwt_tick_begin = secflash_get_timer_value();
    bwt_tick_end = secflash_get_timer_value();
    do {
        pot_tick = secflash_get_timer_value();

        /* check ret_i and reread */
#ifdef SECFLASH_TEE
        ret_i = block_read(I3C4, g_addr, buf, len, I3C_MODE_I2C);
#else
        ret_i = i3c_block_read(I3C_4, g_addr, buf, len, I3C_MODE_I2C);
#endif
        if (ret_i == I3C_OK) {
            if (buf[BLOCK_OFFSET_NAD] == BLOCK_NAD_SE2H) {
                len = ((uint16_t)buf[BLOCK_OFFSET_LEN_H] << BITS_IN_BYTE) |
                       (uint16_t)buf[BLOCK_OFFSET_LEN_L];
                ret = secflash_io_read_inf_crc(buf, len, plen);
            }
        } else { /* i3c err */
            ret = SECFLASH_MAKEERR(SECFLASH_RET_DRV_OTHER, __LINE__);
            secflash_timer_delay(pot_tick, g_secflash_time.pot + I2C_FAST_SPEED_ONE_BYTE_TIME);
        }
        bwt_tick_end = secflash_get_timer_value();
    /* bwt_tick_end must be larger then bwt_tick_begin,
     * the conditions of inversion will occur in 150000 years later, it is impossible
     */
    } while (ret != SECFLASH_RET_SUCCESS && SECLFASH_TICK2US(bwt_tick_end - bwt_tick_begin) < timeout);
    if (ret != SECFLASH_RET_SUCCESS) {
        SECFLASH_ERR_RET();
        SECFLASH_LOG("DLINK: I3C ERR[%d]\n", ret_i);
    }
    secflash_io_rwgt_tick(SECFLASH_READ);
    return ret;
}

/*
 * @brief     : secflash_io_write: write data.
 * @param buf : data buffer
 * @param len : buffer len
 */
uint32_t secflash_io_write(uint8_t *buf, uint32_t len)
{
    uint32_t ret;
    int32_t ret_i;
    uint16_t len_in;
    uint64_t pot_tick;
    uint64_t bwt_tick_begin, bwt_tick_end;

    if (!buf || len > IBLOCK_MAX_LEN) {
        SECFLASH_ERR();
        return SECFLASH_MAKEERR(SECFLASH_RET_INVALID_PARAMETER, __LINE__);
    }
    SECFLASH_PRINT("io w%s, %d, 0x%x, len:%u\n", __func__, __LINE__, g_addr, len);
    trace_hex(buf, len);
    len_in = (uint16_t)len;
    secflash_io_do_rwgt(SECFLASH_WRITE);
    bwt_tick_begin = secflash_get_timer_value();
    bwt_tick_end = secflash_get_timer_value();
    do {
        pot_tick = secflash_get_timer_value();
#ifdef SECFLASH_TEE
        ret_i = block_write(I3C4, g_addr, buf, len_in, I3C_MODE_I2C);
#else
        ret_i = i3c_block_write(I3C_4, g_addr, buf, len_in, I3C_MODE_I2C);
#endif
        if (ret_i == I3C_OK) {
            ret = SECFLASH_RET_SUCCESS;
        } else {
            ret = SECFLASH_MAKEERR(SECFLASH_RET_DRV_OTHER, __LINE__);
            secflash_timer_delay(pot_tick, g_secflash_time.pot + I2C_FAST_SPEED_ONE_BYTE_TIME);
        }
        bwt_tick_end = secflash_get_timer_value();
    /* bwt_tick_end must be larger then bwt_tick_begin,
     * the conditions of inversion will occur in 150000 years later, it is impossible
     */
    } while (ret != SECFLASH_RET_SUCCESS && SECLFASH_TICK2US(bwt_tick_end - bwt_tick_begin) < g_secflash_time.bwt);

    if (ret != SECFLASH_RET_SUCCESS) {
        SECFLASH_ERR_RET();
        SECFLASH_LOG("DLINK: I3C ERR[%d]\n", ret_i);
    }

    secflash_io_rwgt_tick(SECFLASH_WRITE);
    return ret;
}

/*
 * @brief : secflash_io_hard_reset: hard reset via gpio io.
 */
uint32_t secflash_io_hard_reset(uint32_t delay)
{
    SECFLASH_PRINT("io hard reset%s, %d, pwt:%u\n", __func__, __LINE__, delay);
#ifdef SECFLASH_TEE
    gpio_set_direction_output(g_gpio_num);
    gpio_set_value(g_gpio_num, GPIOMUX_LOW);
    secflash_udelay(DELAY_TIME_GPIO);
    gpio_set_value(g_gpio_num, GPIOMUX_HIGH);
#else
    set_gpio_direction(g_gpio_num, GPIO_DIR_OUT);
    set_gpio_value(g_gpio_num, GPIOMUX_LOW);
    secflash_udelay(DELAY_TIME_GPIO);
    set_gpio_value(g_gpio_num, GPIOMUX_HIGH);

#endif
    secflash_udelay(delay);

    return SECFLASH_RET_SUCCESS;
}

/*
 * @brief : secflash_io_addr_exchange: exchenge the secflash addr.
 */
void secflash_io_addr_exchange(void)
{
    if (g_addr == NXP_ADDR)
        g_addr = ST_ADDR;
    else
        g_addr = NXP_ADDR;
}

void secflash_io_get_type(uint32_t *ptype)
{
    if (!ptype) {
        SECFLASH_ERR();
        return;
    }
    if (g_addr == NXP_ADDR)
        *ptype = SECFLASH_NXP_EXIST_MAGIC;
    else
        *ptype = SECFLASH_ST_EXIST_MAGIC;
}

