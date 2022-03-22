/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: only open in debug version for datalink test.
 * Create: 2019/9/3
 */

#include "secflash_data_link.h"
#include "securec.h"
#include "secflash_def.h"
#include "secflash_io.h"
#include "secflash_scp03_test.h"
#include "secflash_scp03_comm.h"
#include "secflash_scp03_calc.h"
#include "secureflash_common.h"
#ifdef SECFLASH_TEE
#include "hisi_debug.h"
#else
#include "debug.h"
#include <delay_timer.h>
#endif

#define SECFLASH_MAKEERR(e, l)                                \
    (SECFLASH_MODULE_DATA_LINK | (((l) & 0x000000FF) << 4) | (e))

#define ST_3_BLOCK_LEN      260
#define OUTBUF_SMALL_LEN    1
#define BLOCK_COUNT_16      16
#define BLOCK_COUNT_48      48
#define GET_CASE_TYPE       10
#define IFS_MAX_LEN         7
#define IO_TRANSCEIVE_TIMEOUT 1000
#define IFS_TEST_64         0x64

enum test_case_id {
    /* sblock test */
    SECFLASH_SBLOCK_CIP_1 = 1,
    SECFLASH_SBLOCK_WTX_2,
    SECFLASH_SBLOCK_IFS_3,
    SECFLASH_SBLOCK_SWR_4,
    SECFLASH_SBLOCK_RELEASE_5,
    SECFLASH_SBLOCK_ABORT_6,
    SECFLASH_SBLOCK_RESYNCH_7,
    SECFLASH_SBLOCK_NUM_MAX,
    /* iblock test */
    SECFLASH_IBLOCK_SELECT_100 = 100,
    SECFLASH_IBLOCK_INIT_UPDATE_101,
    SECFLASH_IBLOCK_MULTI_102,
    SECFLASH_IBLOCK_TEE_103,
    SECFLASH_IBLOCK_OUT_BUF_104,
    SECFLASH_IBLOCK_NUM_MAX,
    /* func test */
    SECFLASH_STATE_110 = 110,
    SECFLASH_HARD_RESET_111,
    SECFLASH_SOFT_RESET_112,
    SECFLASH_POWER_SAVE_113,
    SECFLASH_INIT_CASE_114,
    SECFLASH_GET_CIP_INFO_115,
    SECLFASH_FUN_NUM_MAX,
    /* chain test */
    SECFLASH_CHAIN_EVEN_120 = 120,
    SECFLASH_CHAIN_ODD_121,
    SECLFASH_CHAIN_NUM_MAX,
};

struct datalink_test {
    enum test_case_id case_id;
    uint32_t (*test_handle)(uint32_t case_id);
};

struct io_transceive {
    uint8_t *bufin;
    uint32_t bufin_len;
    uint8_t *bufout;
    uint32_t bufout_len;
    uint32_t *plen;
    uint32_t timeout;
    uint32_t rwgt;
};

uint8_t g_rbuf[BLOCK_MAX_LEN] = {0};
uint8_t g_outbuf[BLOCK_INF_MAX_LEN] = {0};
uint32_t g_outlen;

static uint32_t secflash_datalink_sblock_test(uint32_t case_id)
{
    uint32_t ret;
    uint32_t type_table[SECFLASH_SBLOCK_NUM_MAX] = {
        SEND_S_CIP, SEND_S_CIP, SEND_S_WTX, SEND_S_IFS, SEND_S_SWR, SEND_S_RELEASE, SEND_S_ABORT, SEND_S_RESYNCH
    };

    if (case_id >= SECFLASH_SBLOCK_NUM_MAX) {
        SECFLASH_ERR();
        return SECFLASH_MAKEERR(SECFLASH_RET_INVALID_PARAMETER, __LINE__);
    }
    SECFLASH_PRINT("%s, %d\n", __func__, __LINE__);
    ret = block_transeive_with_retry(type_table[case_id]);
    if (ret != SECFLASH_RET_SUCCESS)
        SECFLASH_ERR();

    return ret;
}

static uint32_t secflash_datalink_iblock_select_test(uint32_t unused)
{
    uint32_t ret;
    uint8_t inbuf[] = {
        0x01, 0xA4, 0x04, 0x00, 0x0D, 0xA0, 0x00, 0x00, 0x04, 0x76, 0x57, 0x56,
        0x52, 0x43, 0x4F, 0x4D, 0x4D, 0x30
    };

    g_outlen = 0;
    ret = secflash_transceive(inbuf, sizeof(inbuf), sizeof(inbuf), g_outbuf, sizeof(g_outbuf), &g_outlen);
    if (ret != SECFLASH_RET_SUCCESS) {
        SECFLASH_ERR();
        return ret;
    }
    SECFLASH_PRINT("%s, %d, outlen:%u\n", __func__, __LINE__, g_outlen);
    trace_hex(g_outbuf, g_outlen);
    return ret;
}

static uint32_t secflash_datalink_iblock_init_updata_test(uint32_t unused)
{
    uint32_t ret;
    uint8_t init_updata[] = {
        0x80, 0x30, 0x30, 0x00, 0x08, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x00
    };

    ret = secflash_transceive(init_updata, sizeof(init_updata), sizeof(init_updata), g_outbuf,
                              sizeof(g_outbuf), &g_outlen);
    if (ret != SECFLASH_RET_SUCCESS) {
        SECFLASH_ERR();
        return ret;
    }
    SECFLASH_PRINT("%s, %d, outlen:%u\n", __func__, __LINE__, g_outlen);
    trace_hex(g_outbuf, g_outlen);
    return ret;
}

static uint32_t secflash_datalink_iblock_multi_test(uint32_t unused)
{
    uint32_t ret;
    uint8_t st_3block[ST_3_BLOCK_LEN] = {0xff};

    ret = secflash_transceive(st_3block, ST_3_BLOCK_LEN, ST_3_BLOCK_LEN, g_outbuf, sizeof(g_outbuf), &g_outlen);
    if (ret != SECFLASH_RET_SUCCESS) {
        SECFLASH_ERR();
        return ret;
    }
    SECFLASH_PRINT("%s, %d, outlen:%u\n", __func__, __LINE__, g_outlen);
    trace_hex(g_outbuf, g_outlen);
    return ret;
}

static uint32_t secflash_datalink_iblock_tee_test(uint32_t unused)
{
    uint32_t ret;
    uint8_t tee_case[] = {
        0x01, 0xa4, 0x04, 0x00, 0x10, 0xF0, 0xBB, 0xAA, 0xCE, 0xAA, 0x68, 0x77,
        0x5F, 0x77, 0x65, 0x61, 0x76, 0x65, 0x72, 0x00, 0x00
    };

    ret = secflash_transceive(tee_case, sizeof(tee_case), sizeof(tee_case), g_outbuf, sizeof(g_outbuf), &g_outlen);
    if (ret != SECFLASH_RET_SUCCESS) {
        SECFLASH_ERR();
        return ret;
    }
    SECFLASH_PRINT("%s, %d, outlen:%u\n", __func__, __LINE__, g_outlen);
    trace_hex(g_outbuf, g_outlen);
    return ret;
}

static uint32_t secflash_datalink_iblock_out_buf_test(uint32_t unused)
{
    uint32_t ret;
    uint8_t inbuf[] = {
        0x01, 0xA4, 0x04, 0x00, 0x0D, 0xA0, 0x00, 0x00, 0x04, 0x76, 0x57, 0x56,
        0x52, 0x43, 0x4F, 0x4D, 0x4D, 0x30
    };

    g_outlen = 0;
    ret = secflash_transceive(inbuf, sizeof(inbuf), sizeof(inbuf), g_outbuf, OUTBUF_SMALL_LEN, &g_outlen);
    if (ret != SECFLASH_RET_SUCCESS) {
        SECFLASH_ERR();
        return ret;
    }
    SECFLASH_PRINT("%s, %d, outlen:%u\n", __func__, __LINE__, g_outlen);
    trace_hex(g_outbuf, g_outlen);
    return ret;
}

static uint32_t secflash_datalink_hard_reset_test(uint32_t unused)
{
    uint32_t ret;

    ret = secflash_chip_reset(SECFLASH_RESET_TYPE_HARD);
    if (ret != SECFLASH_RET_SUCCESS)
        SECFLASH_ERR();
    return ret;
}

static uint32_t secflash_datalink_soft_reset_test(uint32_t unused)
{
    uint32_t ret;

    ret = secflash_chip_reset(SECFLASH_RESET_TYPE_SOFT);
    if (ret != SECFLASH_RET_SUCCESS)
        SECFLASH_ERR();
    return ret;
}

static uint32_t secflash_datalink_power_save_test(uint32_t unused)
{
    uint32_t ret;

    ret = secflash_power_save();
    if (ret != SECFLASH_RET_SUCCESS)
        SECFLASH_ERR();
    return ret;
}

static uint32_t secflash_datalink_init_test(uint32_t unused)
{
    uint32_t ret;
    uint32_t type;

    ret = secflash_init(&type);
    if (ret != SECFLASH_RET_SUCCESS) {
        SECFLASH_ERR();
        return ret;
    }
    if (type != SECFLASH_ST_EXIST_MAGIC && type != SECFLASH_NXP_EXIST_MAGIC) {
        SECFLASH_ERR();
        return type;
    }
    SECFLASH_PRINT("secflash type: %x\n", type);
    return ret;
}

static uint32_t secflash_get_cip_info_test(uint32_t unused)
{
    uint32_t ret;
    uint32_t i;
    struct secflash_cip_info cip_info;

    ret = secflash_get_cip_info(&cip_info);
    if (ret != SECFLASH_RET_SUCCESS) {
        SECFLASH_ERR_RET();
        return ret;
    }

    SECFLASH_PRINT("category indicator: %x\n", cip_info.category_indi);
    SECFLASH_PRINT("compact_header: %x\n", cip_info.compact_header);
    for (i = 0; i < HB_PRODUCT_NAME_LEN; i++)
        SECFLASH_PRINT("product name: %x", cip_info.product_name[i]);

    SECFLASH_PRINT("\n");
    for (i = 0; i < HB_FIRMWARE_VERSION_LEN; i++)
        SECFLASH_PRINT("firmware_version: %x", cip_info.firmware_version[i]);

    SECFLASH_PRINT("\n");
    for (i = 0; i < HB_STATUS_INDICATOR_LEN; i++)
        SECFLASH_PRINT("status_indi: %x", cip_info.status_indi[i]);

    SECFLASH_PRINT("\n");
    return ret;
}

static uint32_t secflash_io_transceive(struct io_transceive *data)
{
    uint32_t ret;

    if (!data) {
        SECFLASH_ERR();
        return SECFLASH_MAKEERR(SECFLASH_RET_INVALID_PARAMETER, __LINE__);
    }
    ret = secflash_io_write(data->bufin, data->bufin_len);
    if (ret != SECFLASH_RET_SUCCESS) {
        SECFLASH_ERR_RET();
        return ret;
    }
    ret = secflash_io_read(data->bufout, data->bufout_len, data->plen, data->timeout);
    if (ret != SECFLASH_RET_SUCCESS)
        SECFLASH_ERR_RET();
    return ret;
}

static uint32_t secflash_datalink_test_set_ifs(uint32_t ifs)
{
    if (ifs > BLOCK_INF_MAX_LEN) {
        SECFLASH_ERR();
        return SECFLASH_MAKEERR(SECFLASH_RET_INVALID_PARAMETER, __LINE__);
    }

    uint32_t ret;
    uint16_t crc;
    uint32_t plen;
    uint8_t ifs_buf[IFS_MAX_LEN];
    uint8_t ifs_rsp[IFS_MAX_LEN];
    struct io_transceive data;

    ifs_buf[BLOCK_OFFSET_NAD] = BLOCK_NAD_H2SE;
    ifs_buf[BLOCK_OFFSET_PCB] = IFS_REQ;
    ifs_buf[BLOCK_OFFSET_LEN_H] = 0;
    ifs_buf[BLOCK_OFFSET_LEN_L] = SBLOCK_IFS_LEN_BYTE;
    ifs_buf[SBLOCK_OFFSET_IFS] = ifs;
    crc = block_calc_crc(ifs_buf, IFS_MAX_LEN - BLOCK_CRC_LEN);
    ifs_buf[BLOCK_OFFSET_CRC_H(IFS_MAX_LEN)] = (crc >> BITS_IN_BYTE) & FF_IN_BYTE;
    ifs_buf[BLOCK_OFFSET_CRC_L(IFS_MAX_LEN)] = crc & FF_IN_BYTE;

    data.bufin = ifs_buf;
    data.bufin_len = IFS_MAX_LEN;
    data.bufout = ifs_rsp;
    data.bufout_len = IFS_MAX_LEN;
    data.plen = &plen;
    data.rwgt = PROTO_DEFAULT_RWGT;
    data.timeout = IO_TRANSCEIVE_TIMEOUT;
    ret = secflash_io_transceive(&data);
    if (ret != SECFLASH_RET_SUCCESS)
        SECFLASH_ERR();
    return ret;
}

static uint32_t secflash_datalink_chain_even_test(uint32_t unused)
{
    uint32_t ret;
    uint32_t block_index = 0;
    uint32_t block_count = BLOCK_COUNT_16;
    uint8_t buffer[BLOCK_COUNT_16 * SECFLASH_BLOCK_BYTE_LEN];
    uint32_t buffer_max_length = BLOCK_COUNT_16 * SECFLASH_BLOCK_BYTE_LEN;

    ret = secflash_write_blocks(MODULE_ID, block_index, block_count, buffer);
    if (ret != SECFLASH_SUCCESS) {
        SECFLASH_PRINT("%s, status:%x EXEC Err\n", __func__, ret);
        return ret;
    }

    ret = secflash_read_blocks(MODULE_ID, block_index, block_count, buffer, buffer_max_length);
    if (ret != SECFLASH_SUCCESS) {
        SECFLASH_PRINT("%s, status:%x EXEC Err\n", __func__, ret);
        return ret;
    }

    return SECFLASH_RET_SUCCESS;
}

static uint32_t secflash_datalink_chain_odd_test(uint32_t unused)
{
    uint32_t ret;
    uint32_t block_index = 0;
    uint32_t block_count = BLOCK_COUNT_16;
    uint8_t buffer[BLOCK_COUNT_16 * SECFLASH_BLOCK_BYTE_LEN];
    uint32_t buffer_max_length = BLOCK_COUNT_16 * SECFLASH_BLOCK_BYTE_LEN;

    ret = secflash_datalink_test_set_ifs(IFS_TEST_64);
    if (ret != SECFLASH_RET_SUCCESS) {
        SECFLASH_ERR_RET();
        return ret;
    }
    ret = secflash_write_blocks(MODULE_ID, block_index, block_count, buffer);
    if (ret != SECFLASH_SUCCESS) {
        SECFLASH_PRINT("%s, ret:%x EXEC Err\n", __func__, ret);
        return ret;
    }
    ret = secflash_read_blocks(MODULE_ID, block_index, block_count, buffer, buffer_max_length);
    if (ret != SECFLASH_SUCCESS) {
        SECFLASH_PRINT("%s, ret:%x EXEC Err\n", __func__, ret);
        return ret;
    }
    ret = secflash_datalink_test_set_ifs(BLOCK_INF_MAX_LEN);
    if (ret != SECFLASH_RET_SUCCESS) {
        SECFLASH_ERR_RET();
        return ret;
    }

    return SECFLASH_RET_SUCCESS;
}

static void block_set_crc(uint8_t *buf, uint32_t buflen, uint16_t crc)
{
    /* check param in uplayer */
    buf[BLOCK_OFFSET_CRC_H(buflen)] = (crc >> BITS_IN_BYTE) & FF_IN_BYTE;
    buf[BLOCK_OFFSET_CRC_L(buflen)] = crc & FF_IN_BYTE;
}

static uint32_t secflash_rblock_len_err_test(uint32_t unused)
{
    uint8_t buf[SBLOCK_BASE_LEN] = { BLOCK_NAD_H2SE, CIP_REQ, 0x00, 0x01 };
    uint16_t crc;
    uint32_t ret;

    crc = block_calc_crc(buf, SBLOCK_BASE_LEN);
    block_set_crc(buf, SBLOCK_BASE_LEN, crc);
    ret = secflash_io_write(buf, SBLOCK_BASE_LEN);
    if (ret != SECFLASH_RET_SUCCESS) {
        SECFLASH_ERR_RET();
        return ret;
    }

    return ret;
}

static struct datalink_test g_datalink_test_table[] = {
    { SECFLASH_SBLOCK_CIP_1,           secflash_datalink_sblock_test },
    { SECFLASH_SBLOCK_WTX_2,           secflash_datalink_sblock_test },
    { SECFLASH_SBLOCK_IFS_3,           secflash_datalink_sblock_test },
    { SECFLASH_SBLOCK_SWR_4,           secflash_datalink_sblock_test },
    { SECFLASH_SBLOCK_RELEASE_5,       secflash_datalink_sblock_test },
    { SECFLASH_SBLOCK_ABORT_6,         secflash_datalink_sblock_test },
    { SECFLASH_SBLOCK_RESYNCH_7,       secflash_datalink_sblock_test },
    { SECFLASH_IBLOCK_SELECT_100,      secflash_datalink_iblock_select_test },
    { SECFLASH_IBLOCK_INIT_UPDATE_101, secflash_datalink_iblock_init_updata_test },
    { SECFLASH_IBLOCK_MULTI_102,       secflash_datalink_iblock_multi_test },
    { SECFLASH_IBLOCK_TEE_103,         secflash_datalink_iblock_tee_test },
    { SECFLASH_IBLOCK_OUT_BUF_104,     secflash_datalink_iblock_out_buf_test },
    { SECFLASH_HARD_RESET_111,         secflash_datalink_hard_reset_test },
    { SECFLASH_SOFT_RESET_112,         secflash_datalink_soft_reset_test },
    { SECFLASH_POWER_SAVE_113,         secflash_datalink_power_save_test },
    { SECFLASH_INIT_CASE_114,          secflash_datalink_init_test },
    { SECFLASH_GET_CIP_INFO_115,       secflash_get_cip_info_test },
    { SECFLASH_CHAIN_EVEN_120,         secflash_datalink_chain_even_test },
    { SECFLASH_CHAIN_ODD_121,          secflash_datalink_chain_odd_test },
};

uint32_t secflash_datalink_test(uint32_t function_id, uint32_t param1, uint32_t param2)
{
    uint32_t ret, table_size, i;

    ERROR("function=%u,p1=%u,p2=%u\n", function_id, param1, param2);
    table_size = ARRAY_SIZE(g_datalink_test_table);
    for (i = 0; i < table_size; i++) {
        if (g_datalink_test_table[i].case_id == function_id)
            break;
    }
    if (i >= table_size) {
        SECFLASH_ERR();
        return SECFLASH_MAKEERR(SECFLASH_RET_INVALID_PARAMETER, __LINE__);
    }
    ret = g_datalink_test_table[i].test_handle(function_id);
    if (ret != SECFLASH_RET_SUCCESS)
        ERROR("DLINK: TEST FAIL! ret = %x\n", ret);
    return ret;
}

