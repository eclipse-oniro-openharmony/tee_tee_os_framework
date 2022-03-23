/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: secure flash module driver.
 * Create: 2019/9/3
 */

#ifndef _SECFLASH__DEF_H_
#define _SECFLASH__DEF_H_

#include "types.h"
#include "tee_log.h" /* uart_printf_func */
#ifdef SECFLASH_TEE
#include "sre_typedef.h"
#endif
#ifndef SECFLASH_TEE
#include "hisi_mntn.h"
#endif

#ifdef SECFLASH_DATA_LINK_DEBUG
#ifdef SECFLASH_TEE
#define SECFLASH_TRACE(c) uart_printf_func("DLINK:%s, %s:%d\n", c, __func__, __LINE__)
#define SECFLASH_PRINT(...)  uart_printf_func(__VA_ARGS__)
#else
#define SECFLASH_TRACE(c) hisi_mntn_log("DLINK:%s, %s:%d\n", c, __func__, __LINE__)
#define SECFLASH_PRINT(...) hisi_mntn_log(__VA_ARGS__)
#endif
#else
#define SECFLASH_TRACE(s)
#define SECFLASH_PRINT(...)
#endif

#ifdef SECFLASH_TEE
#define SECFLASH_ERR() HISI_PRINT_ERROR("DLINK:%s:%d\n", __func__, __LINE__)
#define SECFLASH_ERR_RET() HISI_PRINT_ERROR("DLINK:%s:%d, 0x%08x\n", __func__, __LINE__, ret)
#define SECFLASH_LOG(...) uart_printf_func(__VA_ARGS__)
#else
#define SECFLASH_ERR() hisi_mntn_log("DLINK:%s:%d\n", __func__, __LINE__)
#define SECFLASH_ERR_RET() hisi_mntn_log("DLINK:%s:%d, 0x%08x\n", __func__, __LINE__, ret)
#define SECFLASH_LOG(...) hisi_mntn_log(__VA_ARGS__)
#endif

#define SECFLASH_MODULE_DATA_LINK 0x4000
#define SECFLASH_MODULE_DATA_LINK_IO 0x5000

#define SECFLASH_GETERR(e)      ((e) & 0x0000000F)

#define PROTO_DEFAULT_RNACK_TIMES 2
#define PROTO_RETRY_MAX 2
/* opt */
#define PROTO_DEFAULT_BWT (1 * 1000 * 1000) /* 1s */

#define PROTO_DEFAULT_MPOT 300 /* GP default is 5ms, 300us for performance */
#define PROTO_DEFAULT_PWT 32000 /* GP default is 25ms, 32ms for supplier supplier default */
#define PROTO_DEFAULT_RWGT 200 /* GP default is 10us, 200us for supplier supplier default */

#define BIT1 0x0
#define BIT2 0x1
#define BIT3 0x2
#define BIT4 0x3
#define BIT5 0x4
#define BIT6 0x5
#define BIT7 0x6
#define BIT8 0x7
#define GET_BIT(b, n) (((b) & (1u << (n))) >> (n))

#define BITS_IN_BYTE 8
#define FF_IN_BYTE 0xFF

#define SECFLASH_TRUE 1
#define SECFLASH_FALSE 0

#define BLOCK_DEFAULT_CLK_STRETCH 0
#define PROTO_DEFAULT_MCF 400 /* khz */
#define BLOCK_BYTE_ZERO 0x00
#define BLOCK_TIME_1000 1000 /* us */
#define BLOCK_CRC_LEN 2
#define BLOCK_SEQNO_MASK 1
#define BLOCK_LOOP_COUNT_LIMIT 64
#define BLOCK_DERESET_TIME 32000 /* us */

#ifndef I3C_BUG_WORKAROUND
#define BLOCK_INF_MAX_LEN 254
#else
#define BLOCK_INF_MAX_LEN 48
#endif

#define BLOCK_IFS_1BYTE_MAX (BLOCK_INF_MAX_LEN + 6)
#define BLOCK_MAX_LEN (BLOCK_BASE_LEN + BLOCK_INF_MAX_LEN)
#define BLOCK_IFS_DEFAULT BLOCK_INF_MAX_LEN

#define BLOCK_NAD_H2SE 0x21
#define BLOCK_NAD_SE2H 0x12

#define BLOCK_OFFSET_NAD 0
#define BLOCK_OFFSET_PCB 1
#define BLOCK_OFFSET_LEN_H 2
#define BLOCK_OFFSET_LEN_L 3
#define BLOCK_OFFSET_INFO 4
#define BLOCK_OFFSET_CRC_H(l) ((l) - 2)
#define BLOCK_OFFSET_CRC_L(l) ((l) - 1)
#define BLOCK_CRC_DATA_LEN(l) ((l) - 2)
#define BLOCK_BASE_LEN 6
#define BLOCK_PCB_TYPE_BIT BIT8

static inline void BLOCK_ENCODE_LEN(uint8_t *buf, uint32_t len)
{
    buf[BLOCK_OFFSET_LEN_H] = (uint8_t)((len >> BITS_IN_BYTE) & FF_IN_BYTE);
    buf[BLOCK_OFFSET_LEN_L] = (uint8_t)(len & FF_IN_BYTE);
}

static inline uint32_t BLOCK_DECODE_LEN(uint8_t *buf)
{
    return ((uint32_t)buf[BLOCK_OFFSET_LEN_H] << BITS_IN_BYTE) | (uint32_t)buf[BLOCK_OFFSET_LEN_L];
}

#define SBLOCK_BASE_LEN BLOCK_BASE_LEN
#define SBLOCK_MAX_LEN (SBLOCK_BASE_LEN + SBLOCK_CIP_MAX_LEN)
#define SBLOCK_P_FIELD_LEN 4
/* TOD add limit */
#define SBLOCK_WTX_MULTI 1
#define SBLOCK_WTX_DEFAULT 1
#define SBLOCK_PCB_TYPE_BIT BIT7
#define SBLOCK_IFS_LEN_BYTE 1
#define SBLOCK_IFS_LEN_2BYTE 2
#define SBLOCK_WTX_LEN_1BYTE 1

#define SBLOCK_OFFSET_IFS BLOCK_OFFSET_INFO

/* CIP */
#define SBLOCK_OFFSET_CIP_PVER BLOCK_OFFSET_INFO /* 01 */
#define SBLOCK_VALUE_CIP_PVER 0x01
#define SBLOCK_OFFSET_CIP_RID (SBLOCK_OFFSET_CIP_PVER + 1)
#define SBLOCK_OFFSET_CIP_RID_LEN 5
/* 02 */
#define SBLOCK_OFFSET_CIP_PLID                                                 \
    (SBLOCK_OFFSET_CIP_RID + SBLOCK_OFFSET_CIP_RID_LEN)
#define SBLOCK_VALUE_CIP_PLID 0x02
/* PLP var */
#define SBLOCK_OFFSET_CIP_LPLP (SBLOCK_OFFSET_CIP_PLID + 1)
#define SBLOCK_VALUE_CIP_LPLP 0x08
#define SBLOCK_OFFSET_CIP_PLP_CONF (SBLOCK_OFFSET_CIP_LPLP + 1)
#define SBLOCK_OFFSET_CIP_PLP_PWT (SBLOCK_OFFSET_CIP_PLP_CONF + 1)
#define SBLOCK_OFFSET_CIP_PLP_MCF (SBLOCK_OFFSET_CIP_PLP_PWT + 1)
#define SBLOCK_OFFSET_CIP_PLP_MCF_L (SBLOCK_OFFSET_CIP_PLP_MCF + 1)
#define SBLOCK_OFFSET_CIP_PLP_PST (SBLOCK_OFFSET_CIP_PLP_MCF + 2)
#define SBLOCK_OFFSET_CIP_PLP_MPOT (SBLOCK_OFFSET_CIP_PLP_PST + 1)
#define SBLOCK_OFFSET_CIP_PLP_RWGT (SBLOCK_OFFSET_CIP_PLP_MPOT + 1)
#define SBLOCK_OFFSET_CIP_PLP_RWGT_L (SBLOCK_OFFSET_CIP_PLP_RWGT + 1)
/* DLLP var */
#define SBLOCK_OFFSET_CIP_LDLLP (SBLOCK_OFFSET_CIP_PLP_RWGT + 2)
#define SBLOCK_VALUE_CIP_LDLLP 0x04
#define SBLOCK_OFFSET_CIP_DLLP_BWT (SBLOCK_OFFSET_CIP_LDLLP + 1)
#define SBLOCK_OFFSET_CIP_DLLP_BWT_L (SBLOCK_OFFSET_CIP_DLLP_BWT + 1)
#define SBLOCK_OFFSET_CIP_DLLP_IFSC (SBLOCK_OFFSET_CIP_DLLP_BWT + 2)
#define SBLOCK_OFFSET_CIP_DLLP_IFSC_L (SBLOCK_OFFSET_CIP_DLLP_IFSC + 1)
/* HB var */
#define SBLOCK_OFFSET_CIP_LHB (SBLOCK_OFFSET_CIP_DLLP_IFSC + 2)
#define SBLOCK_OFFSET_CIP_HB (SBLOCK_OFFSET_CIP_LHB + 1)
#define HB_CATEGORY_INDICATOR SBLOCK_OFFSET_CIP_HB
#define HB_COMPACT_HEADER (SBLOCK_OFFSET_CIP_HB + 1)
#define HB_PRODUCT_NAME (SBLOCK_OFFSET_CIP_HB + 2)
#define HB_PRODUCT_NAME_LEN 6
#define HB_FIRMWARE_VERSION (SBLOCK_OFFSET_CIP_HB + 8)
#define HB_FIRMWARE_VERSION_LEN 3
#define HB_STATUS_INDICATOR (SBLOCK_OFFSET_CIP_HB + 11)
#define HB_STATUS_INDICATOR_LEN 3
#define SBLOCK_CIP_HB_MAX_LEN 26
#define SBLOCK_CIP_MAX_LEN 48

#define RBLOCK_LEN 6
#define RBLOCK_NR_MASK 0x10
#define RBLOCK_TYPE_BIT_H BIT2
#define RBLOCK_TYPE_BIT_L BIT1
#define RBLOCK_NS_BIT BIT5

#define IBLOCK_MAX_LEN (BLOCK_INF_MAX_LEN + BLOCK_BASE_LEN)
#define IBLOCK_NR_MASK 0x40
#define IBLOCK_MBIT_MASK 0x20
#define IBLOCK_NS_BIT BIT7
#define IBLOCK_MBIT BIT6

enum secflash_state {
    STATE_IDLE,
    STATE_TRANS,
    STATE_UNAVAILABLE,
};

enum iblock_type {
    UNCHAIN = 0x00,
    CHAIN = 0x01,
};

struct iblock_info {
    uint32_t type;
    uint32_t seqno;    /* Sequence number */
    uint32_t totallen; /* Invalid block if 0 */
    uint32_t sendlen;
    uint32_t tosendlen; /* next to send length */
    uint8_t *pdata;     /* Information field */
    uint8_t *prspbuf;   /* response buffer provided by caller */
    uint32_t rspbuflen;
    uint32_t *prsplen;
    uint32_t recvlen;
    uint32_t len; /* buf valid len */
    uint8_t buf[IBLOCK_MAX_LEN];
};

enum rblock_type {
    RACK = 0x80,
    RNACK_CRC = 0x81,
    RNACK_OTHER = 0x82
};

struct rblock_info {
    uint32_t type;
    uint32_t seqno;
    uint32_t len;
    uint8_t buf[RBLOCK_LEN];
};

enum trans_state {
    TRANS_STATE_IDLE,
    SEND_IFRAME,
    SEND_S_RESYNCH,
    SEND_S_RESYNCH_RSP,
    SEND_S_IFS,
    SEND_S_IFS_RSP,
    SEND_S_ABORT,
    SEND_S_ABORT_RSP,
    SEND_S_WTX,
    SEND_S_WTX_RSP,
    SEND_S_CIP,
    SEND_S_CIP_RSP,
    SEND_S_RELEASE,
    SEND_S_SWR,
    SEND_R_ACK,
    SEND_R_NACK_CRC,
    SEND_R_NACK_OTHER,
};

enum sblock_type {
    RESYNCH_REQ = 0xC0 | 0x00,
    RESYNCH_RSP = 0xE0 | 0x00,
    IFS_REQ = 0xC0 | 0x01,
    IFS_RSP = 0xE0 | 0x01,
    ABORT_REQ = 0xC0 | 0x02,
    ABORT_RSP = 0xE0 | 0x02,
    WTX_REQ = 0xC0 | 0x03,
    WTX_RSP = 0xE0 | 0x03,
    CIP_REQ = 0xC0 | 0x04,
    CIP_RSP = 0xE0 | 0x04,
    RELEASE_REQ = 0xC0 | 0x06,
    RELEASE_RSP = 0xE0 | 0x06,
    SWR_REQ = 0xC0 | 0x0F,
    SWR_RSP = 0xE0 | 0x0F,
};

struct sblock_info {
    uint32_t type;
    uint32_t len;
    uint8_t buf[SBLOCK_MAX_LEN];
};

enum block_type {
    INVALID,
    IBLOCK,
    RBLOCK,
    SBLOCK,
};

struct block_info {
    enum block_type type;
    struct iblock_info iblock;
    struct rblock_info rblock;
    struct sblock_info sblock;
};

struct secflash_context {
    uint32_t clk_stretch;
    uint32_t pwt;
    uint32_t mcf;
    uint32_t pst;
    uint32_t mpot;
    uint32_t rwgt;
    uint32_t bwt;
    uint32_t ifs;

    uint32_t seqno;
    int32_t retry_max;
    int32_t retry_n;
    uint32_t wtx;
    enum secflash_state state;
    enum trans_state next_trans;
    struct block_info tx_last_block; /* Last tx */
    struct block_info tx_next_block; /* Current tx */
    struct block_info rxblock;
    uint8_t rbuf[BLOCK_MAX_LEN]; /* receive buffer */
};
#endif

