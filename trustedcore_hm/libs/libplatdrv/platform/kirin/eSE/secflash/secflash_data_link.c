/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: secure flash module driver.
 * Create: 2019/9/3
 */

#include "secflash_data_link.h"
#include "securec.h"
#include "secflash_def.h"
#include "secflash_io.h"
#ifdef SECFLASH_TEE
#include "hisi_debug.h"
#else
#include "debug.h"
#endif

#define SECFLASH_MAKEERR(e, l)                                \
    (SECFLASH_MODULE_DATA_LINK | (((l) & 0x000000FF) << 4) | (e))

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof(arr[0]))
#endif

#ifndef unused
#define unused(x) (void)(x)
#endif

static uint32_t iblock_chain_abort(void);
static uint32_t iblock_chain_set_next(struct iblock_info *pinfo);
static struct secflash_context g_ctx;

/*
 * @brief      : ctx_init: init the context module.
 * @info       : in this file, prefix ctx in the function name, denote
 *               the some operation for context
 */
static void ctx_init(uint32_t state)
{
    g_ctx.state = state;
    g_ctx.next_trans = TRANS_STATE_IDLE;
    g_ctx.seqno = BLOCK_BYTE_ZERO;

    g_ctx.retry_max = PROTO_RETRY_MAX;
    g_ctx.retry_n = 0;
    g_ctx.wtx = SBLOCK_WTX_DEFAULT;
    g_ctx.tx_last_block.type = INVALID;
    g_ctx.tx_next_block.type = INVALID;
    g_ctx.rxblock.type = INVALID;
}

static void ctx_set_default(void)
{
    g_ctx.ifs = BLOCK_IFS_DEFAULT;
    g_ctx.clk_stretch = BLOCK_DEFAULT_CLK_STRETCH;
    g_ctx.mcf = PROTO_DEFAULT_MCF;
    g_ctx.rwgt = PROTO_DEFAULT_RWGT;
    g_ctx.pst = 0;
    g_ctx.bwt = PROTO_DEFAULT_BWT;
    g_ctx.mpot = PROTO_DEFAULT_MPOT;
    g_ctx.pwt = PROTO_DEFAULT_PWT;
}

static uint32_t ctx_set_tx_last(void)
{
    errno_t ret_s;

    /* tx_last_block and tx_next_block are the same size , there is no risk */
    ret_s = memcpy_s(&g_ctx.tx_last_block, sizeof(struct block_info),
                     &g_ctx.tx_next_block, sizeof(struct block_info));
    if (ret_s != EOK) {
        SECFLASH_ERR();
        return SECFLASH_MAKEERR(SECFLASH_RET_ERR, __LINE__);
    }

    return SECFLASH_RET_SUCCESS;
}

static uint32_t ctx_get_ifs(void)
{
    return g_ctx.ifs;
}

static uint8_t *ctx_get_recv_buf(void)
{
    return g_ctx.rbuf;
}

static uint32_t ctx_get_pwt(void)
{
    return g_ctx.pwt;
}

static uint32_t ctx_set_next_seqno(void)
{
    g_ctx.seqno ^= BLOCK_SEQNO_MASK;
    return g_ctx.seqno;
}

static void ctx_set_wtx(uint32_t wtx)
{
    g_ctx.wtx = wtx;
}

static uint32_t ctx_get_wtx(void)
{
    return g_ctx.wtx;
}

static uint32_t ctx_get_seqno(void)
{
    return g_ctx.seqno;
}

static uint32_t ctx_get_state(void)
{
    return g_ctx.state;
}

static void ctx_set_state(uint32_t state)
{
    g_ctx.state = state;
}

static struct block_info *ctx_get_recv_block(void)
{
    return &g_ctx.rxblock;
}

static struct block_info *ctx_get_next_block(void)
{
    return &g_ctx.tx_next_block;
}

static enum trans_state ctx_get_trans_state(void)
{
    return g_ctx.next_trans;
}

static void ctx_set_trans_state(enum trans_state state)
{
    g_ctx.next_trans = state;
}

static uint32_t ctx_get_timeout(void)
{
    return g_ctx.bwt * g_ctx.wtx;
}

static int32_t ctx_get_retry_count(void)
{
    return g_ctx.retry_max - g_ctx.retry_n;
}

static int32_t ctx_retry_count_add(void)
{
    return g_ctx.retry_n++;
}

static void ctx_reset_retry(void)
{
    g_ctx.retry_n = 0;
}

static uint32_t ctx_set_recv_info(uint8_t *buf, uint32_t len, uint32_t last)
{
    struct iblock_info *pblock = &g_ctx.tx_next_block.iblock;
    errno_t ret_s;
    /* check buffer len in uplayer */
    if (!buf || len > BLOCK_INF_MAX_LEN) {
        SECFLASH_ERR();
        return SECFLASH_MAKEERR(SECFLASH_RET_INVALID_PARAMETER, __LINE__);
    }
    /* check data */
    if (pblock->recvlen + len > pblock->rspbuflen) {
        SECFLASH_ERR();
        return SECFLASH_MAKEERR(SECFLASH_RET_BUF_TOO_SMALL, __LINE__);
    }
    ret_s = memcpy_s(pblock->prspbuf + pblock->recvlen, pblock->rspbuflen - pblock->recvlen, buf, len);
    if (ret_s != EOK) {
        SECFLASH_ERR();
        return SECFLASH_MAKEERR(SECFLASH_RET_ERR, __LINE__);
    }
    pblock->recvlen += len;
    /* if receive last block of unchian, set response information */
    if (!pblock->prsplen) {
        SECFLASH_ERR();
        return SECFLASH_MAKEERR(SECFLASH_RET_INVALID_PARAMETER, __LINE__);
    }
    if (last == SECFLASH_TRUE)
        *pblock->prsplen = pblock->recvlen;

    return SECFLASH_RET_SUCCESS;
}

static struct block_info *ctx_get_last_tx_block(void)
{
    return &g_ctx.tx_last_block;
}

/*
 * @brief      : block_check_crc: check receive data CRC.
 * @info       : in this file, prefix block in the function name, denote
 *               the some common operation for block.
 * @param      : buf: receive data, len: buf len.
 * @return     : secflash_RET_SUCCESS(0) if success, other if failed.
 */
static uint32_t block_check_crc(uint8_t *buf, uint32_t len)
{
    if (!buf || len < BLOCK_CRC_LEN) {
        SECFLASH_ERR();
        return SECFLASH_MAKEERR(SECFLASH_RET_INVALID_PARAMETER, __LINE__);
    }
    uint16_t rcrc = (buf[BLOCK_OFFSET_CRC_H(len)] << BITS_IN_BYTE) | buf[BLOCK_OFFSET_CRC_L(len)];
    uint16_t crc = block_calc_crc(buf, BLOCK_CRC_DATA_LEN(len));

    if (rcrc != crc) {
        SECFLASH_PRINT("%s, %d, %u %u\n", __func__, __LINE__, rcrc, crc);
        SECFLASH_ERR();
        return SECFLASH_MAKEERR(SECFLASH_RET_CRC_ERROR, __LINE__);
    }

    return SECFLASH_RET_SUCCESS;
}

static void block_set_crc(uint8_t *buf, uint32_t buflen, uint16_t crc)
{
    /* check param in uplayer */
    buf[BLOCK_OFFSET_CRC_H(buflen)] = (crc >> BITS_IN_BYTE) & FF_IN_BYTE;
    buf[BLOCK_OFFSET_CRC_L(buflen)] = crc & FF_IN_BYTE;
}

static uint32_t block_do_resync(void)
{
    ctx_init(STATE_IDLE);

    return SECFLASH_RET_SUCCESS;
}

static uint32_t block_do_ifs(uint8_t *buf, uint32_t buflen)
{
    uint32_t ifs;

    if (!buf || buflen > SBLOCK_IFS_LEN_2BYTE) {
        SECFLASH_ERR();
        return SECFLASH_MAKEERR(SECFLASH_RET_INVALID_PARAMETER, __LINE__);
    }
    if (buflen == SBLOCK_IFS_LEN_BYTE) {
        ifs = buf[SBLOCK_OFFSET_IFS];
        if (ifs < BLOCK_INF_MAX_LEN) {
            SECFLASH_TRACE("cecv ifs");
            g_ctx.ifs = ifs;
        }
    }
    if (buflen == SBLOCK_IFS_LEN_2BYTE) {
        ifs = (((uint32_t)buf[SBLOCK_OFFSET_IFS] << BITS_IN_BYTE) |
              ((uint32_t)buf[SBLOCK_OFFSET_IFS + SBLOCK_IFS_LEN_BYTE]));
        if (ifs < BLOCK_INF_MAX_LEN) {
            SECFLASH_TRACE("cecv ifs");
            g_ctx.ifs = ifs;
        }
    }

    return SECFLASH_RET_SUCCESS;
}

static void block_trace_hb(const uint8_t *buf, const uint32_t buflen)
{
    uint32_t i;

    /* check param in uplayer */
#ifdef SECFLASH_TEE
    HISI_PRINT_INFO("%s:\n", "historical byte:");

    for (i = 0; i < buflen; i++)
        HISI_PRINT_INFO("0x%02x, ", buf[i]);
    HISI_PRINT_INFO("\n");
#else
    NOTICE("%s:\n", "historical byte:");

    for (i = 0; i < buflen; i++)
        NOTICE("0x%02x, ", buf[i]);
    NOTICE("\n");
#endif
    unused(buf);
}

static uint32_t sblock_recv_cip(uint8_t *buf, uint32_t len)
{
    uint32_t temp;

    SECFLASH_TRACE("RUN");
    if (!buf || len < BLOCK_BASE_LEN) {
        SECFLASH_ERR();
        return SECFLASH_MAKEERR(SECFLASH_RET_INVALID_PARAMETER, __LINE__);
    }
    if (len > (SBLOCK_CIP_MAX_LEN + BLOCK_BASE_LEN)) {
        SECFLASH_ERR();
        return SECFLASH_MAKEERR(SECFLASH_RET_INVALID_BLOCK, __LINE__);
    }
    if (buf[SBLOCK_OFFSET_CIP_PVER] != SBLOCK_VALUE_CIP_PVER) {
        SECFLASH_ERR();
        return SECFLASH_MAKEERR(SECFLASH_RET_INVALID_BLOCK, __LINE__);
    }
    if (buf[SBLOCK_OFFSET_CIP_PLID] != SBLOCK_VALUE_CIP_PLID) {
        SECFLASH_ERR();
        return SECFLASH_MAKEERR(SECFLASH_RET_INVALID_BLOCK, __LINE__);
    }
    /* PLP */
    g_ctx.clk_stretch = GET_BIT(buf[SBLOCK_OFFSET_CIP_PLP_CONF], BIT1);
    g_ctx.pwt = buf[SBLOCK_OFFSET_CIP_PLP_PWT] * BLOCK_TIME_1000;
    g_ctx.mcf = (buf[SBLOCK_OFFSET_CIP_PLP_MCF] << BITS_IN_BYTE) | buf[SBLOCK_OFFSET_CIP_PLP_MCF_L];
    g_ctx.pst = buf[SBLOCK_OFFSET_CIP_PLP_PST] * BLOCK_TIME_1000;
    g_ctx.mpot = buf[SBLOCK_OFFSET_CIP_PLP_MPOT] * BLOCK_TIME_1000;
    temp = (buf[SBLOCK_OFFSET_CIP_PLP_RWGT] << BITS_IN_BYTE) | buf[SBLOCK_OFFSET_CIP_PLP_RWGT_L];
    g_ctx.rwgt = temp;

    /* DLLP */
    temp = (buf[SBLOCK_OFFSET_CIP_DLLP_BWT] << BITS_IN_BYTE) | buf[SBLOCK_OFFSET_CIP_DLLP_BWT_L];
    g_ctx.bwt = temp * BLOCK_TIME_1000;
    secflash_io_set_time_sequence(g_ctx.bwt, PROTO_DEFAULT_MPOT, g_ctx.rwgt);

    temp = (buf[SBLOCK_OFFSET_CIP_DLLP_IFSC] << BITS_IN_BYTE) | buf[SBLOCK_OFFSET_CIP_DLLP_IFSC_L];
    if (temp < BLOCK_INF_MAX_LEN)
        g_ctx.ifs = temp;
    else
        g_ctx.ifs = BLOCK_INF_MAX_LEN;

    /* HB */
    temp = buf[SBLOCK_OFFSET_CIP_LHB];
    if (temp > SBLOCK_CIP_HB_MAX_LEN) {
        SECFLASH_ERR();
        return SECFLASH_MAKEERR(SECFLASH_RET_INVALID_BLOCK, __LINE__);
    }
    block_trace_hb(buf + SBLOCK_OFFSET_CIP_HB, temp);

    return SECFLASH_RET_SUCCESS;
}

static uint32_t block_addressing(uint32_t *ptype)
{
    uint32_t ret;

    SECFLASH_TRACE("addr 1");
    ret = block_transeive_with_retry(SEND_S_CIP);
    if (ret == SECFLASH_RET_SUCCESS) {
        if (ptype)
            secflash_io_get_type(ptype);
        return ret;
    }
    ret = secflash_io_hard_reset(ctx_get_pwt());
    if (ret != SECFLASH_RET_SUCCESS) {
        SECFLASH_ERR_RET();
        return ret;
    }
    secflash_io_addr_exchange();
    SECFLASH_TRACE("addr 2");
    ret = block_transeive_with_retry(SEND_S_CIP);
    if (ret != SECFLASH_RET_SUCCESS) {
        secflash_io_addr_exchange();
        SECFLASH_ERR_RET();
        ctx_set_state(STATE_UNAVAILABLE);
    } else {
        if (ptype)
            secflash_io_get_type(ptype);
    }

    return ret;
}

/*
 * @brief      : sblock_init: sblock encode in this function by GP0.39
 * @param      : pinfo: the struct of sblock.
 * @return     : secflash_RET_SUCCESS(0) if success, other if failed.
 */
static uint32_t sblock_init(struct sblock_info *pinfo)
{
    if (!pinfo) {
        SECFLASH_ERR();
        return SECFLASH_MAKEERR(SECFLASH_RET_INVALID_PARAMETER, __LINE__);
    }
    /* if pinfo is not NULL, buf must not NULL */
    pinfo->buf[BLOCK_OFFSET_NAD] = BLOCK_NAD_H2SE;
    uint16_t crc;

    SECFLASH_TRACE(__func__);

    switch (pinfo->type) {
    case RESYNCH_REQ:
    case RESYNCH_RSP:
    case ABORT_REQ:
    case ABORT_RSP:
    case CIP_REQ:
    /* Do not need CIP RSP */
    case RELEASE_REQ:
    /* Do not need RELEASE RSP */
    case SWR_REQ:
        /* Do not need SWR RSP */
        /* pcb */
        pinfo->buf[BLOCK_OFFSET_PCB] = pinfo->type;
        /* len */
        BLOCK_ENCODE_LEN(pinfo->buf, 0);
        pinfo->len = SBLOCK_BASE_LEN;
        break;
    case IFS_REQ:
    case IFS_RSP:
        /* pcb */
        pinfo->buf[BLOCK_OFFSET_PCB] = pinfo->type;
        /* info */
        pinfo->buf[BLOCK_OFFSET_INFO] = BLOCK_INF_MAX_LEN;
        /* len */
        if (BLOCK_INF_MAX_LEN <= BLOCK_IFS_1BYTE_MAX) {
            /* One byte len */
            BLOCK_ENCODE_LEN(pinfo->buf, SBLOCK_IFS_LEN_BYTE);
            pinfo->len = SBLOCK_BASE_LEN + SBLOCK_IFS_LEN_BYTE;
        } else {
            /* 2: Two byte len */
            BLOCK_ENCODE_LEN(pinfo->buf, SBLOCK_IFS_LEN_2BYTE);
            pinfo->len = SBLOCK_BASE_LEN + SBLOCK_IFS_LEN_2BYTE;
        }
        break;
    case WTX_REQ:
    case WTX_RSP:
        BLOCK_ENCODE_LEN(pinfo->buf, 0);
        /* pcb */
        pinfo->buf[BLOCK_OFFSET_PCB] = pinfo->type;
        BLOCK_ENCODE_LEN(pinfo->buf, SBLOCK_WTX_LEN_1BYTE);
        /* info */
        pinfo->buf[BLOCK_OFFSET_INFO] = ctx_get_wtx();
        pinfo->len = SBLOCK_BASE_LEN + SBLOCK_WTX_LEN_1BYTE;
        break;
    default:
        SECFLASH_ERR();
        return SECFLASH_MAKEERR(SECFLASH_RET_INVALID_PARAMETER, __LINE__);
    }

    crc = block_calc_crc(pinfo->buf, pinfo->len - BLOCK_CRC_LEN);
    block_set_crc(pinfo->buf, pinfo->len, crc);

    return SECFLASH_RET_SUCCESS;
}

static uint32_t sblock_send(struct sblock_info *pinfo)
{
    uint32_t ret;

    SECFLASH_TRACE(__func__);
    /* check params */
    if (!pinfo) {
        SECFLASH_ERR();
        return SECFLASH_MAKEERR(SECFLASH_RET_INVALID_PARAMETER, __LINE__);
    }

    ret = sblock_init(pinfo);
    if (ret != SECFLASH_RET_SUCCESS) {
        SECFLASH_ERR();
        return ret;
    }

    ret = secflash_io_write(pinfo->buf, pinfo->len);
    if (ret != SECFLASH_RET_SUCCESS) {
        SECFLASH_ERR();
        return ret;
    }
    struct block_info *pblock = ctx_get_next_block();

    if (!pblock) {
        SECFLASH_ERR();
        return SECFLASH_MAKEERR(SECFLASH_RET_INVALID_PARAMETER, __LINE__);
    }
    pblock->type = SBLOCK;

    return ret;
}

static uint32_t sblock_resynch_req_handle(struct block_info *pblock, uint32_t s_type, uint8_t *unused_buf,
                                          uint32_t unused_len)
{
    if (!pblock) {
        SECFLASH_ERR();
        return SECFLASH_MAKEERR(SECFLASH_RET_INVALID_PARAMETER, __LINE__);
    }
    unused(unused_buf);
    unused(unused_len);
    pblock->sblock.type = s_type;
    ctx_init(SEND_S_RESYNCH_RSP);
    return SECFLASH_RET_SUCCESS;
}

static uint32_t sblock_resynch_rsp_handle(struct block_info *pblock, uint32_t s_type, uint8_t *unused_buf,
                                          uint32_t unused_len)
{
    uint32_t ret;

    if (!pblock) {
        SECFLASH_ERR();
        return SECFLASH_MAKEERR(SECFLASH_RET_INVALID_PARAMETER, __LINE__);
    }
    unused(unused_buf);
    unused(unused_len);
    pblock->sblock.type = s_type;
    /* ifs */
    ctx_set_state(STATE_IDLE);
    ret = block_transeive_with_retry(SEND_S_IFS);
    if (ret != SECFLASH_RET_SUCCESS)
        SECFLASH_ERR();
    ctx_set_state(STATE_TRANS);
    ctx_init(SEND_IFRAME);
    return ret;
}

static uint32_t sblock_ifs_req_handle(struct block_info *pblock, uint32_t s_type, uint8_t *pbuf, uint32_t len)
{
    uint32_t ret, ilen;

    /* len has checked by uplayer */
    if (!pblock || !pbuf) {
        SECFLASH_ERR();
        return SECFLASH_MAKEERR(SECFLASH_RET_INVALID_PARAMETER, __LINE__);
    }
    pblock->sblock.type = s_type;
    ilen = len - BLOCK_BASE_LEN;
    ret = block_do_ifs(pbuf, ilen);
    if (ret != SECFLASH_RET_SUCCESS) {
        SECFLASH_ERR();
        return ret;
    }
    ctx_set_trans_state(SEND_S_IFS_RSP);
    return SECFLASH_RET_SUCCESS;
}

static uint32_t sblock_abort_req_handle(struct block_info *pblock, uint32_t s_type, uint8_t *unused_buf,
                                        uint32_t unused_len)
{
    uint32_t ret;

    if (!pblock) {
        SECFLASH_ERR();
        return SECFLASH_MAKEERR(SECFLASH_RET_INVALID_PARAMETER, __LINE__);
    }
    unused(unused_buf);
    unused(unused_len);
    pblock->sblock.type = s_type;
    ret = iblock_chain_abort();
    if (ret != SECFLASH_RET_SUCCESS) {
        SECFLASH_ERR();
        return ret;
    }
    ctx_set_trans_state(SEND_S_ABORT_RSP);
    return SECFLASH_RET_SUCCESS;
}

static uint32_t sblock_wtx_req_handle(struct block_info *pblock, uint32_t s_type, uint8_t *pbuf, uint32_t len)
{
    uint32_t temp;

    /* len has checked by uplayer */
    if (!pblock || !pbuf || len < BLOCK_BASE_LEN || len > BLOCK_MAX_LEN) {
        SECFLASH_ERR();
        return SECFLASH_MAKEERR(SECFLASH_RET_INVALID_PARAMETER, __LINE__);
    }
    pblock->sblock.type = s_type;
    temp = (uint32_t)pbuf[BLOCK_OFFSET_INFO];
    if (temp > 0)
        ctx_set_wtx(temp);
    ctx_set_trans_state(SEND_S_WTX_RSP);
    return SECFLASH_RET_SUCCESS;
}

static uint32_t sblock_cip_rsp_handle(struct block_info *pblock, uint32_t s_type, uint8_t *pbuf, uint32_t len)
{
    uint32_t ret, ilen;

    /* len has checked by uplayer */
    if (!pblock || !pbuf) {
        SECFLASH_ERR();
        return SECFLASH_MAKEERR(SECFLASH_RET_INVALID_PARAMETER, __LINE__);
    }
    pblock->sblock.type = s_type;
    ilen = BLOCK_DECODE_LEN(pbuf);
    if (ilen > SBLOCK_CIP_MAX_LEN) {
        SECFLASH_ERR();
        return SECFLASH_MAKEERR(SECFLASH_RET_INVALID_BLOCK, __LINE__);
    }
    ret = sblock_recv_cip(pbuf, len);
    if (ret != SECFLASH_RET_SUCCESS) {
        SECFLASH_ERR();
        return ret;
    }
    ctx_set_trans_state(TRANS_STATE_IDLE);
    return SECFLASH_RET_SUCCESS;
}

static uint32_t sblock_other_hanlde(struct block_info *pblock, uint32_t s_type, uint8_t *unused_buf,
                                    uint32_t unused_len)
{
    if (!pblock) {
        SECFLASH_ERR();
        return SECFLASH_MAKEERR(SECFLASH_RET_INVALID_PARAMETER, __LINE__);
    }
    unused(unused_buf);
    unused(unused_len);
    pblock->sblock.type = s_type;
    ctx_set_trans_state(TRANS_STATE_IDLE);
    return SECFLASH_RET_SUCCESS;
}

static struct sblock_decode_handle g_sblock_handle_table[] = {
    { RESYNCH_REQ, sblock_resynch_req_handle },
    { RESYNCH_RSP, sblock_resynch_rsp_handle },
    { IFS_REQ,     sblock_ifs_req_handle     },
    { IFS_RSP,     sblock_other_hanlde       },
    { ABORT_REQ,   sblock_abort_req_handle   },
    { ABORT_RSP,   sblock_other_hanlde       },
    { WTX_REQ,     sblock_wtx_req_handle     },
    { WTX_RSP,     sblock_other_hanlde       },
    { CIP_REQ,     sblock_other_hanlde       },
    { CIP_RSP,     sblock_cip_rsp_handle     },
    { RELEASE_REQ, sblock_other_hanlde       },
    { RELEASE_RSP, sblock_other_hanlde       },
    { SWR_REQ,     sblock_other_hanlde       },
    { SWR_RSP,     sblock_other_hanlde       },
};

static uint32_t sblock_decode(uint8_t *pbuf, uint32_t len, uint8_t *poutbuf, uint32_t *poutlen)
{
    uint32_t i, table_size, ret;
    struct block_info *pblock = ctx_get_recv_block();

    /* poutbuf and poutlen not be used in this function; len has checked by uplayer */
    if (!pbuf || !pblock) {
        SECFLASH_ERR();
        return SECFLASH_MAKEERR(SECFLASH_RET_INVALID_PARAMETER, __LINE__);
    }
    uint8_t pcb = pbuf[BLOCK_OFFSET_PCB];

    unused(poutbuf);
    unused(poutlen);
    pblock->type = SBLOCK;
    table_size = ARRAY_SIZE(g_sblock_handle_table);
    if (pcb != WTX_REQ)
        ctx_set_wtx(SBLOCK_WTX_DEFAULT);

    for (i = 0; i < table_size; i++) {
        if (g_sblock_handle_table[i].type == pcb)
            break;
    }
    if (i >= table_size || !g_sblock_handle_table[i].decode_handle) {
        SECFLASH_ERR();
        return SECFLASH_MAKEERR(SECFLASH_RET_INVALID_BLOCK, __LINE__);
    }
    ret = g_sblock_handle_table[i].decode_handle(pblock, g_sblock_handle_table[i].type, pbuf, len);
    if (ret != SECFLASH_RET_SUCCESS)
        SECFLASH_ERR();
    return ret;
}

/*
 * @brief      : rblock_init: rblock encode in this function by GP0.39
 * @param      : pinfo: the struct of rblock.
 * @return     : secflash_RET_SUCCESS(0) if success, other if failed.
 */
static uint32_t rblock_init(struct rblock_info *pinfo)
{
    uint16_t crc;
    struct block_info *pblock = NULL;

    if (!pinfo) {
        SECFLASH_ERR();
        return SECFLASH_MAKEERR(SECFLASH_RET_INVALID_PARAMETER, __LINE__);
    }
    /* check other param in uplayer */
    pinfo->buf[BLOCK_OFFSET_NAD] = BLOCK_NAD_H2SE;
    BLOCK_ENCODE_LEN(pinfo->buf, 0);
    pinfo->len = RBLOCK_LEN;

    switch (pinfo->type) {
    case RACK:
    case RNACK_CRC:
    case RNACK_OTHER:
        /* pcb */
        pinfo->buf[BLOCK_OFFSET_PCB] = pinfo->type;
        break;
    default:
        SECFLASH_ERR();
        break;
    }
    pblock = ctx_get_recv_block();
    if (!pblock) {
        SECFLASH_ERR();
        return SECFLASH_MAKEERR(SECFLASH_RET_INVALID_PARAMETER, __LINE__);
    }
    pinfo->seqno = pblock->iblock.seqno;
    if (pinfo->seqno == BLOCK_SEQNO_MASK)
        pinfo->buf[BLOCK_OFFSET_PCB] &= (~RBLOCK_NR_MASK);
    else
        pinfo->buf[BLOCK_OFFSET_PCB] |= RBLOCK_NR_MASK;

    crc = block_calc_crc(pinfo->buf, pinfo->len - BLOCK_CRC_LEN);
    block_set_crc(pinfo->buf, pinfo->len, crc);

    return SECFLASH_RET_SUCCESS;
}

static uint32_t rblock_send(struct rblock_info *pinfo)
{
    uint32_t ret;

    if (!pinfo) {
        SECFLASH_ERR();
        return SECFLASH_MAKEERR(SECFLASH_RET_INVALID_PARAMETER, __LINE__);
    }

    ret = rblock_init(pinfo);
    if (ret != SECFLASH_RET_SUCCESS) {
        SECFLASH_ERR();
        return ret;
    }

    ret = secflash_io_write(pinfo->buf, pinfo->len);
    if (ret != SECFLASH_RET_SUCCESS) {
        SECFLASH_ERR();
        return ret;
    }

    ret = ctx_set_tx_last();
    if (ret != SECFLASH_RET_SUCCESS) {
        SECFLASH_ERR();
        return ret;
    }

    return ret;
}

static uint32_t rblock_no_err_handle(void)
{
    uint32_t ret;
    struct block_info *precv = ctx_get_recv_block();
    struct block_info *pnext = ctx_get_next_block();
    struct block_info *plast = ctx_get_last_tx_block();

    if (!precv || !pnext || !plast) {
        SECFLASH_ERR();
        return SECFLASH_MAKEERR(SECFLASH_RET_INVALID_PARAMETER, __LINE__);
    }
    precv->rblock.type = RACK;
    ctx_reset_retry();
    if (plast->iblock.seqno != precv->rblock.seqno && plast->iblock.type == CHAIN) {
        ctx_set_next_seqno();
        /* send next chain */
        ret = iblock_chain_set_next(&pnext->iblock);
        if (ret != SECFLASH_RET_SUCCESS) {
            SECFLASH_ERR();
            return ret;
        }
        ctx_set_trans_state(SEND_IFRAME);
    } else {
        /* resynch */
        ctx_set_trans_state(SEND_S_RESYNCH);
    }
    return SECFLASH_RET_SUCCESS;
}

static uint32_t rblock_decode(uint8_t *pbuf, uint32_t len)
{
    uint32_t ret, temp;

    /* len has checked by uplayer */
    if (!pbuf || len < BLOCK_BASE_LEN) {
        SECFLASH_ERR();
        return SECFLASH_MAKEERR(SECFLASH_RET_INVALID_PARAMETER, __LINE__);
    }
    uint8_t pcb = pbuf[BLOCK_OFFSET_PCB];
    struct block_info *precv = ctx_get_recv_block();
    struct block_info *plast = ctx_get_last_tx_block();

    if (!precv || !plast) {
        SECFLASH_ERR();
        return SECFLASH_MAKEERR(SECFLASH_RET_INVALID_PARAMETER, __LINE__);
    }
    ctx_set_wtx(SBLOCK_WTX_DEFAULT);

    precv->type = RBLOCK;
    precv->rblock.seqno = GET_BIT(pcb, RBLOCK_NS_BIT);

    temp = BLOCK_DECODE_LEN(pbuf);
    /* check length not 0 */
    if (temp != 0) {
        SECFLASH_ERR();
        return SECFLASH_MAKEERR(SECFLASH_RET_INVALID_BLOCK, __LINE__);
    }

    if (plast->type == INVALID) {
        SECFLASH_ERR();
        /* ignore */
        return SECFLASH_RET_SUCCESS;
    }

    if ((GET_BIT(pcb, RBLOCK_TYPE_BIT_H) == BLOCK_BYTE_ZERO) &&
        (GET_BIT(pcb, RBLOCK_TYPE_BIT_L) == BLOCK_BYTE_ZERO)) {
        /* no err */
        ret = rblock_no_err_handle();
        if (ret != SECFLASH_RET_SUCCESS)
            SECFLASH_ERR_RET();
    } else if ((GET_BIT(pcb, RBLOCK_TYPE_BIT_H) == BLOCK_BYTE_ZERO) &&
               (GET_BIT(pcb, RBLOCK_TYPE_BIT_L) != BLOCK_BYTE_ZERO)) {
        /* crc err */
        SECFLASH_ERR();
        precv->rblock.type = RNACK_CRC;
        ret = SECFLASH_MAKEERR(SECFLASH_RET_CRC_ERROR, __LINE__);
    } else if ((GET_BIT(pcb, RBLOCK_TYPE_BIT_H) != BLOCK_BYTE_ZERO) &&
               (GET_BIT(pcb, RBLOCK_TYPE_BIT_L) == BLOCK_BYTE_ZERO)) {
        /* other err */
        SECFLASH_ERR();
        precv->rblock.type = RNACK_OTHER;
        ret = SECFLASH_MAKEERR(SECFLASH_RET_OTHER_ERR, __LINE__);
    } else {
        /* format err */
        SECFLASH_ERR();
        ret = SECFLASH_MAKEERR(SECFLASH_RET_INVALID_BLOCK, __LINE__);
    }

    return ret;
}

static uint32_t iblock_get_tx_info(uint32_t *pchain, uint32_t *pseqno)
{
    uint32_t ret;
    struct block_info *pblock = ctx_get_next_block();

    if (!pchain || !pseqno || !pblock) {
        SECFLASH_ERR();
        return SECFLASH_MAKEERR(SECFLASH_RET_INVALID_PARAMETER, __LINE__);
    }

    /* check iblock invalid */
    if (pblock->iblock.totallen == 0) {
        SECFLASH_TRACE("ignore");
        ret = SECFLASH_MAKEERR(SECFLASH_RET_INVALID_BLOCK, __LINE__);
        return ret;
    }

    /* check seq NO */
    *pchain = pblock->iblock.type;
    *pseqno = pblock->iblock.seqno;

    return SECFLASH_RET_SUCCESS;
}

static uint32_t iblock_decode(uint8_t *pbuf, uint32_t len)
{
    /* len has checked by uplayer */
    if (!pbuf || len < BLOCK_BASE_LEN) {
        SECFLASH_ERR();
        return SECFLASH_MAKEERR(SECFLASH_RET_INVALID_PARAMETER, __LINE__);
    }

    uint32_t ret, ilen, seqno, chain;
    uint8_t pcb = pbuf[BLOCK_OFFSET_PCB];
    struct block_info *pblock = ctx_get_recv_block();

    if (!pblock) {
        SECFLASH_ERR();
        return SECFLASH_MAKEERR(SECFLASH_RET_INVALID_PARAMETER, __LINE__);
    }
    ilen = BLOCK_DECODE_LEN(pbuf);
    ctx_set_wtx(SBLOCK_WTX_DEFAULT);

    /* get seqno */
    ret = iblock_get_tx_info(&chain, &seqno);
    if (ret != SECFLASH_RET_SUCCESS) {
        ctx_set_trans_state(TRANS_STATE_IDLE);
        return SECFLASH_RET_SUCCESS;
    }

    pblock->type = IBLOCK;
    pblock->iblock.seqno = GET_BIT(pcb, IBLOCK_NS_BIT);
    if (GET_BIT(pcb, IBLOCK_MBIT))
        pblock->iblock.type = CHAIN;
    else
        pblock->iblock.type = UNCHAIN;

    /* check seqno */
    if (chain == UNCHAIN) {
        /* tx unchain */
        if (pblock->iblock.type == CHAIN) {
            /* NOTE check seqno */
            ret = ctx_set_recv_info(pbuf + BLOCK_OFFSET_INFO, ilen, SECFLASH_FALSE);
            if (ret != SECFLASH_RET_SUCCESS)
                SECFLASH_ERR();
            ctx_set_trans_state(SEND_R_ACK);
            return SECFLASH_RET_SUCCESS;
        }
        /* UNCHAIN */
        ctx_set_next_seqno();
        ret = ctx_set_recv_info(pbuf + BLOCK_OFFSET_INFO, ilen, SECFLASH_TRUE);
        if (ret != SECFLASH_RET_SUCCESS)
            SECFLASH_ERR();
        ctx_set_trans_state(TRANS_STATE_IDLE);
    } else {
        /* tx chain */
        if (pblock->iblock.type == UNCHAIN) {
            ctx_set_next_seqno();
            ret = ctx_set_recv_info(pbuf + BLOCK_OFFSET_INFO, ilen, SECFLASH_TRUE);
            if (ret != SECFLASH_RET_SUCCESS)
                SECFLASH_ERR();
        }
        /* NOTE check seqno */
        ctx_set_trans_state(TRANS_STATE_IDLE);
    }
    return ret;
}

static void iblock_set_mbit(struct iblock_info *pinfo, uint32_t m)
{
    /* pinfo has checked by uplayer */
    if (m == SECFLASH_TRUE)
        pinfo->buf[BLOCK_OFFSET_PCB] |= IBLOCK_MBIT_MASK;
    else
        pinfo->buf[BLOCK_OFFSET_PCB] &= (~IBLOCK_MBIT_MASK);
}

static void iblock_set_ns(struct iblock_info *pinfo, uint32_t ns)
{
    /* pinfo has checked by uplayer */
    if (ns == BLOCK_SEQNO_MASK)
        pinfo->buf[BLOCK_OFFSET_PCB] |= IBLOCK_NR_MASK;
    else
        pinfo->buf[BLOCK_OFFSET_PCB] &= (~IBLOCK_NR_MASK);
}

/*
 * @brief      : iblock_init: iblock encode in this function by GP0.39
 * @param      : pinfo: the struct of iblock.
 * @return     : secflash_RET_SUCCESS(0) if success, other if failed.
 */
static uint32_t iblock_init(struct iblock_info *pinfo, uint8_t *pdata, uint32_t len,
                            uint8_t *poutbuf, uint32_t outbuflen, uint32_t *outdatalen)
{
    errno_t ret_s;
    uint16_t crc;
    uint32_t ifs = ctx_get_ifs();

    if (!pinfo || !pdata) { /* other pointer not be used */
        SECFLASH_ERR();
        return SECFLASH_MAKEERR(SECFLASH_RET_INVALID_PARAMETER, __LINE__);
    }
    (void)memset_s(pinfo->buf, sizeof(pinfo->buf), 0, sizeof(pinfo->buf));

    /* info */
    if (len > ifs) {
        pinfo->type = CHAIN;
        pinfo->len = ifs + BLOCK_BASE_LEN;
        iblock_set_mbit(pinfo, SECFLASH_TRUE);
        pinfo->tosendlen = ifs;
        BLOCK_ENCODE_LEN(pinfo->buf, ifs);
    } else {
        pinfo->type = UNCHAIN;
        pinfo->len = len + BLOCK_BASE_LEN;
        iblock_set_mbit(pinfo, SECFLASH_FALSE);
        pinfo->tosendlen = len;
        BLOCK_ENCODE_LEN(pinfo->buf, len);
    }
    pinfo->seqno = ctx_get_seqno();
    iblock_set_ns(pinfo, pinfo->seqno);

    pinfo->totallen = len;
    pinfo->sendlen = 0;
    pinfo->pdata = pdata;
    pinfo->prspbuf = poutbuf;
    pinfo->rspbuflen = outbuflen;
    pinfo->prsplen = outdatalen;
    pinfo->recvlen = 0;

    /* NAD set only once */
    pinfo->buf[BLOCK_OFFSET_NAD] = BLOCK_NAD_H2SE;

    ret_s = memcpy_s(pinfo->buf + BLOCK_OFFSET_INFO, IBLOCK_MAX_LEN - BLOCK_OFFSET_INFO,
                     pinfo->pdata + pinfo->sendlen, pinfo->tosendlen);
    if (ret_s != EOK) {
        SECFLASH_ERR();
        return SECFLASH_MAKEERR(SECFLASH_RET_ERR, __LINE__);
    }

    /* crc */
    crc = block_calc_crc(pinfo->buf, pinfo->len - BLOCK_CRC_LEN); /* pinfo->len > BLOCK_CRC_LEN always stand up */
    block_set_crc(pinfo->buf, pinfo->len, crc);

    return SECFLASH_RET_SUCCESS;
}

static uint32_t iblock_chain_set_next(struct iblock_info *pinfo)
{
    errno_t ret_s;
    uint16_t crc;
    uint32_t ifs = ctx_get_ifs();

    if (!pinfo || pinfo->type != CHAIN) {
        SECFLASH_ERR();
        return SECFLASH_MAKEERR(SECFLASH_RET_INVALID_PARAMETER, __LINE__);
    }

    if ((pinfo->tosendlen + pinfo->sendlen) > pinfo->totallen) {
        pinfo->sendlen = pinfo->totallen;
        pinfo->tosendlen = 0;
        return SECFLASH_RET_SUCCESS;
    }

    /* info and PCB */
    pinfo->sendlen += pinfo->tosendlen;
    if ((pinfo->totallen - pinfo->sendlen) > ifs) {
        pinfo->tosendlen = ifs;
        iblock_set_mbit(pinfo, SECFLASH_TRUE);
        BLOCK_ENCODE_LEN(pinfo->buf, ifs);
    } else {
        pinfo->tosendlen = pinfo->totallen - pinfo->sendlen;
        iblock_set_mbit(pinfo, SECFLASH_FALSE);
        BLOCK_ENCODE_LEN(pinfo->buf, pinfo->tosendlen);
    }

    pinfo->len = pinfo->tosendlen + BLOCK_BASE_LEN;
    pinfo->seqno = ctx_get_seqno();
    iblock_set_ns(pinfo, pinfo->seqno);

    /* info field */
    ret_s = memcpy_s(pinfo->buf + BLOCK_OFFSET_INFO, IBLOCK_MAX_LEN - BLOCK_OFFSET_INFO,
                     pinfo->pdata + pinfo->sendlen, pinfo->tosendlen);
    if (ret_s != EOK) {
        SECFLASH_ERR();
        return SECFLASH_MAKEERR(SECFLASH_RET_ERR, __LINE__);
    }

    crc = block_calc_crc(pinfo->buf, pinfo->len - BLOCK_CRC_LEN);
    block_set_crc(pinfo->buf, pinfo->len, crc);

    return SECFLASH_RET_SUCCESS;
}

static uint32_t iblock_chain_abort(void)
{
    struct block_info *pnext = ctx_get_next_block();

    if (!pnext) {
        SECFLASH_ERR();
        return SECFLASH_MAKEERR(SECFLASH_RET_INVALID_PARAMETER, __LINE__);
    }
    struct iblock_info *pinfo = &(pnext->iblock);

    if (!pinfo->prsplen) {
        SECFLASH_ERR();
        return SECFLASH_MAKEERR(SECFLASH_RET_INVALID_PARAMETER, __LINE__);
    }
    /* check status in iblock chain */
    if (pinfo->type != CHAIN) {
        SECFLASH_TRACE("ignore");
        return SECFLASH_RET_SUCCESS;
    }

    *pinfo->prsplen = 0;
    pinfo->recvlen = 0;

    return SECFLASH_RET_SUCCESS;
}

static uint32_t iblock_send(struct iblock_info *pinfo)
{
    uint32_t ret;
    struct block_info *pblock = ctx_get_recv_block();

    if (!pinfo || !pblock) {
        SECFLASH_ERR();
        return SECFLASH_MAKEERR(SECFLASH_RET_INVALID_PARAMETER, __LINE__);
    }
    if (pinfo->type == CHAIN && (pinfo->tosendlen + pinfo->sendlen) > pinfo->totallen) {
        SECFLASH_ERR();
        return SECFLASH_MAKEERR(SECFLASH_RET_BUF_TOO_SMALL, __LINE__);
    }

    /* check params before send */
    if (pinfo->totallen == 0) {
        SECFLASH_ERR();
        return SECFLASH_MAKEERR(SECFLASH_RET_INVALID_PARAMETER, __LINE__);
    }

    if (ctx_get_trans_state() != SEND_IFRAME) {
        SECFLASH_ERR();
        return SECFLASH_MAKEERR(SECFLASH_RET_BUSY, __LINE__);
    }

    if (pinfo->tosendlen == 0) {
        SECFLASH_ERR();
        return SECFLASH_MAKEERR(SECFLASH_RET_INVALID_PARAMETER, __LINE__);
    }

    if (pinfo->len != (pinfo->tosendlen + BLOCK_BASE_LEN)) {
        SECFLASH_ERR();
        return SECFLASH_MAKEERR(SECFLASH_RET_INVALID_PARAMETER, __LINE__);
    }

    pblock->rblock.type = RNACK_OTHER;
    ret = secflash_io_write(pinfo->buf, pinfo->len);
    if (ret != SECFLASH_RET_SUCCESS) {
        SECFLASH_ERR();
        return ret;
    }
    pblock = ctx_get_next_block();
    if (!pblock) {
        SECFLASH_ERR();
        return SECFLASH_MAKEERR(SECFLASH_RET_INVALID_PARAMETER, __LINE__);
    }
    pblock->type = IBLOCK;
    ret = ctx_set_tx_last();
    if (ret != SECFLASH_RET_SUCCESS) {
        SECFLASH_ERR();
        return ret;
    }

    /* set complete idle in recv iblock */
    return ret;
}

/* out sblock_info */
static uint32_t block_recv(void)
{
    uint32_t ret, ilen, temp;
    uint8_t *rbuf = ctx_get_recv_buf();
    uint32_t len = 0;

    if (!rbuf) {
        SECFLASH_ERR();
        return SECFLASH_MAKEERR(SECFLASH_RET_INVALID_PARAMETER, __LINE__);
    }
    /* get block */
    ret = secflash_io_read(rbuf, BLOCK_MAX_LEN, &len, ctx_get_timeout());
    if (ret != SECFLASH_RET_SUCCESS) {
        SECFLASH_ERR();
        return ret;
    }

    if (len < BLOCK_BASE_LEN || len > BLOCK_MAX_LEN) {
        SECFLASH_ERR();
        return SECFLASH_MAKEERR(SECFLASH_RET_INVALID_BLOCK, __LINE__);
    }

    /* check NAD */
    if (rbuf[BLOCK_OFFSET_NAD] != BLOCK_NAD_SE2H) {
        SECFLASH_ERR();
        return SECFLASH_MAKEERR(SECFLASH_RET_INVALID_BLOCK, __LINE__);
    }

    /* check crc */
    ret = block_check_crc(rbuf, len);
    if (ret != SECFLASH_RET_SUCCESS) {
        SECFLASH_ERR();
        return SECFLASH_MAKEERR(SECFLASH_RET_CRC_ERROR, __LINE__);
    }

    /* check len */
    ilen = len - BLOCK_BASE_LEN;
    temp = BLOCK_DECODE_LEN(rbuf);
    if (ilen != temp) {
        SECFLASH_ERR();
        return SECFLASH_MAKEERR(SECFLASH_RET_INVALID_BLOCK, __LINE__);
    }

    /* Check type and into subtype */
    if (GET_BIT(rbuf[BLOCK_OFFSET_PCB], BLOCK_PCB_TYPE_BIT) != BLOCK_BYTE_ZERO) {
        if (GET_BIT(rbuf[BLOCK_OFFSET_PCB], SBLOCK_PCB_TYPE_BIT) != BLOCK_BYTE_ZERO) {
            /* sblock */
            SECFLASH_TRACE("s recv!");
            return sblock_decode(rbuf, len, NULL, NULL);
        }
        /* rblock */
        SECFLASH_TRACE("r recv!");
        return rblock_decode(rbuf, len);
    }
    /* iblock */
    SECFLASH_TRACE("i recv!");
    ret = iblock_decode(rbuf, len);
    if (ret != SECFLASH_RET_SUCCESS)
        SECFLASH_ERR();
    return ret;
}

static uint32_t block_soft_reset(void)
{
    uint32_t ret;
    struct block_info *pblock = NULL;

    SECFLASH_TRACE("RUN");
    ret = block_transeive_with_retry(SEND_S_SWR);
    if (ret != SECFLASH_RET_SUCCESS) {
        SECFLASH_ERR();
        return ret;
    }
    pblock = ctx_get_recv_block();
    if (!pblock) {
        SECFLASH_ERR();
        return SECFLASH_MAKEERR(SECFLASH_RET_INVALID_PARAMETER, __LINE__);
    }
    if (pblock->type == SBLOCK && pblock->sblock.type == SWR_RSP) {
        SECFLASH_TRACE("swr rsp success");
        ret = SECFLASH_RET_SUCCESS;
    } else {
        SECFLASH_ERR();
        ret = SECFLASH_MAKEERR(SECFLASH_RET_ERR, __LINE__);
    }

    return ret;
}

static uint32_t iblock_send_handle(struct block_info *pinfo, uint32_t type)
{
    uint32_t ret;

    if (!pinfo) {
        SECFLASH_ERR();
        return SECFLASH_MAKEERR(SECFLASH_RET_INVALID_PARAMETER, __LINE__);
    }
    unused(type);
    ret = iblock_send(&pinfo->iblock);
    if (ret != SECFLASH_RET_SUCCESS)
        SECFLASH_ERR();
    return ret;
}

static uint32_t rblock_send_handle(struct block_info *pinfo, uint32_t type)
{
    uint32_t ret;

    if (!pinfo) {
        SECFLASH_ERR();
        return SECFLASH_MAKEERR(SECFLASH_RET_INVALID_PARAMETER, __LINE__);
    }

    if (type == RNACK_OTHER)
        ctx_retry_count_add();

    pinfo->rblock.type = type;
    ret = rblock_send(&pinfo->rblock);
    if (ret != SECFLASH_RET_SUCCESS)
        SECFLASH_ERR();
    return ret;
}

static uint32_t sblock_send_handle(struct block_info *pinfo, uint32_t type)
{
    uint32_t ret;

    if (!pinfo) {
        SECFLASH_ERR();
        return SECFLASH_MAKEERR(SECFLASH_RET_INVALID_PARAMETER, __LINE__);
    }

    if (type == RESYNCH_RSP) {
        ret = block_do_resync();
        if (ret != SECFLASH_RET_SUCCESS)
            SECFLASH_ERR();
    }
    pinfo->sblock.type = type;
    ret = sblock_send(&pinfo->sblock);
    if (ret != SECFLASH_RET_SUCCESS)
        SECFLASH_ERR();
    return ret;
}

static struct secflash_block_handle g_block_handle_table[] = {
    { TRANS_STATE_IDLE,   0,           NULL               },
    { SEND_IFRAME,        0,           iblock_send_handle },
    { SEND_S_RESYNCH,     RESYNCH_REQ, sblock_send_handle },
    { SEND_S_RESYNCH_RSP, RESYNCH_RSP, sblock_send_handle },
    { SEND_S_IFS,         IFS_REQ,     sblock_send_handle },
    { SEND_S_IFS_RSP,     IFS_RSP,     sblock_send_handle },
    { SEND_S_ABORT,       ABORT_REQ,   sblock_send_handle },
    { SEND_S_ABORT_RSP,   ABORT_RSP,   sblock_send_handle },
    { SEND_S_WTX,         WTX_REQ,     sblock_send_handle },
    { SEND_S_WTX_RSP,     WTX_RSP,     sblock_send_handle },
    { SEND_S_CIP,         CIP_REQ,     sblock_send_handle },
    { SEND_S_CIP_RSP,     CIP_RSP,     sblock_send_handle },
    { SEND_S_RELEASE,     RELEASE_REQ, sblock_send_handle },
    { SEND_S_SWR,         SWR_REQ,     sblock_send_handle },
    { SEND_R_ACK,         RACK,        rblock_send_handle },
    { SEND_R_NACK_CRC,    RNACK_CRC,   rblock_send_handle },
    { SEND_R_NACK_OTHER,  RNACK_OTHER, rblock_send_handle },
};

uint32_t block_transeive(void)
{
    uint32_t trans_state_now, block_type_now, table_size;
    uint32_t ret;
    struct block_info *pinfo = ctx_get_next_block();

    SECFLASH_TRACE("trans begin");
    trans_state_now = ctx_get_trans_state();
    table_size = ARRAY_SIZE(g_block_handle_table);
    if (trans_state_now < SEND_IFRAME || trans_state_now >= table_size ||
        !g_block_handle_table[trans_state_now].block_handle) {
        SECFLASH_ERR();
        ctx_set_trans_state(TRANS_STATE_IDLE);
        return SECFLASH_MAKEERR(SECFLASH_RET_INVALID_PARAMETER, __LINE__);
    }
    block_type_now = g_block_handle_table[trans_state_now].block_type;
    ret = g_block_handle_table[trans_state_now].block_handle(pinfo, block_type_now);
    if (ret != SECFLASH_RET_SUCCESS) {
        /* retry or reset */
        SECFLASH_ERR();
        return ret;
    }
    ret = ctx_set_tx_last();
    if (ret != SECFLASH_RET_SUCCESS) {
        SECFLASH_ERR();
        return ret;
    }
    ret = block_recv();
    if (ret != SECFLASH_RET_SUCCESS)
        SECFLASH_ERR();
    return ret;
}

uint32_t block_transeive_with_retry(enum trans_state state)
{
    uint32_t ret = SECFLASH_MAKEERR(SECFLASH_RET_ERR, __LINE__);
    int32_t count = BLOCK_LOOP_COUNT_LIMIT;

    if (ctx_get_state() != STATE_IDLE) {
        SECFLASH_ERR();
        return SECFLASH_MAKEERR(SECFLASH_RET_BUSY, __LINE__);
    }
    ctx_set_state(STATE_TRANS);
    ctx_set_trans_state(state);

    ctx_reset_retry();
    while (ctx_get_retry_count() > 0) {
        SECFLASH_TRACE("RETRY");
        if (count <= 0) {
            ret = SECFLASH_MAKEERR(SECFLASH_RET_TIME_OUT, __LINE__);
            SECFLASH_ERR_RET();
            break;
        }

        ret = block_transeive();
        if (ret == SECFLASH_RET_SUCCESS) {
            ctx_reset_retry();
            break;
        } else if (SECFLASH_GETERR(ret) == SECFLASH_RET_CRC_ERROR ||
                   SECFLASH_GETERR(ret) == SECFLASH_RET_OTHER_ERR) {
            SECFLASH_ERR();
            ctx_retry_count_add();
            count--;
            continue;
        } else {
            SECFLASH_ERR_RET();
            break;
        }
    }

    ctx_set_state(STATE_IDLE);
    ctx_set_trans_state(TRANS_STATE_IDLE);

    return ret;
}

/*
 * @brief      : secflash_init: initialize in boot up.
 *               CIP process here.
 * @param      : ptype: Detected chip type. SECFLASH_CHIP_TYPE_NXP or
 *               SECFLASH_CHIP_TYPE_ST if not NULL
 * @return secflash_RET_SUCCESS(0) if success, other if failed.
 */
uint32_t secflash_init(uint32_t *ptype)
{
    /* ptype not be used in this function */
    uint32_t ret;
    uint32_t available;

    SECFLASH_TRACE("init start");

    /* check available */
    ret = secflash_io_init(&available);
    if (ret != SECFLASH_RET_SUCCESS) {
        SECFLASH_ERR_RET();
        return ret;
    }
    if (available == SECFLASH_FALSE) {
        SECFLASH_TRACE("not support!");
        return SECFLASH_RET_SUCCESS;
    }

    SECFLASH_TRACE("init 1");
    ctx_set_default();

    ctx_init(STATE_IDLE);

#ifdef SECFLASH_TEE
    ret = secflash_io_hard_reset(ctx_get_pwt());
    if (ret != SECFLASH_RET_SUCCESS) {
        SECFLASH_ERR_RET();
        return ret;
    }
#endif

    SECFLASH_TRACE("init 2");

    /* addressing by ifs */
    ret = block_addressing(ptype);
    if (ret != SECFLASH_RET_SUCCESS) {
        SECFLASH_ERR_RET();
        ctx_set_state(STATE_UNAVAILABLE);
        return ret;
    }

    /* soft_reset for supplier */
    ret = block_soft_reset();
    if (ret != SECFLASH_RET_SUCCESS) {
        SECFLASH_ERR_RET();
        return ret;
    }

    /* ifs */
    ret = block_transeive_with_retry(SEND_S_IFS);
    if (ret != SECFLASH_RET_SUCCESS) {
        SECFLASH_ERR_RET();
        return ret;
    }

    SECFLASH_TRACE("init end");

    return ret;
}

static uint32_t secflash_transceive_check(uint8_t *pinbuf, uint32_t inbuflen, uint32_t indatalen, uint8_t *poutbuf,
                                          uint32_t outbuflen, uint32_t *outdatalen)
{
    /* check status */
    if (ctx_get_state() == STATE_TRANS) {
        SECFLASH_ERR();
        return SECFLASH_MAKEERR(SECFLASH_RET_BUSY, __LINE__);
    }
    if (ctx_get_state() == STATE_UNAVAILABLE) {
        SECFLASH_ERR();
        return SECFLASH_MAKEERR(SECFLASH_RET_INVALID_STATE, __LINE__);
    }

    /* check params */
    if (!pinbuf || !poutbuf || !outdatalen) {
        SECFLASH_ERR();
        return SECFLASH_MAKEERR(SECFLASH_RET_INVALID_PARAMETER, __LINE__);
    }

    if (inbuflen == 0 || indatalen == 0 || indatalen > inbuflen || outbuflen == 0 || *outdatalen > outbuflen) {
        SECFLASH_ERR();
        return SECFLASH_MAKEERR(SECFLASH_RET_INVALID_PARAMETER, __LINE__);
    }

    /* check status */
    if (ctx_get_state() != STATE_IDLE) {
        SECFLASH_ERR();
        return SECFLASH_MAKEERR(SECFLASH_RET_BUSY, __LINE__);
    }
    return SECFLASH_RET_SUCCESS;
}

static uint32_t secflash_transceive_execute(void)
{
    uint32_t ret = SECFLASH_RET_ERR;
    int32_t count = BLOCK_LOOP_COUNT_LIMIT;

    ctx_reset_retry();
    while ((ctx_get_trans_state() != TRANS_STATE_IDLE) && (ctx_get_retry_count() > 0)) {
        if (count <= 0) {
            ret = SECFLASH_MAKEERR(SECFLASH_RET_TIME_OUT, __LINE__);
            SECFLASH_ERR_RET();
            break;
        }

        ret = block_transeive();
        if (ret == SECFLASH_RET_SUCCESS) {
            ctx_reset_retry();
        } else if (SECFLASH_GETERR(ret) == SECFLASH_RET_CRC_ERROR ||
                   SECFLASH_GETERR(ret) == SECFLASH_RET_OTHER_ERR) {
            SECFLASH_ERR();
            ctx_retry_count_add();
            count--;
            continue;
        } else {
            SECFLASH_ERR_RET();
            break;
        }
    }

    return ret;
}

static uint32_t secflash_transceive_done(struct iblock_info *pinfo)
{
    struct block_info *pnext = ctx_get_next_block();

    ctx_set_state(STATE_IDLE);
    ctx_set_trans_state(TRANS_STATE_IDLE);

    /* for csec, never be NULL */
    if (!pinfo || !pnext) {
        SECFLASH_ERR();
        return SECFLASH_MAKEERR(SECFLASH_RET_INVALID_PARAMETER, __LINE__);
    }
    pnext->type = INVALID;
    pinfo->totallen = 0;
    return SECFLASH_RET_SUCCESS;
}

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
uint32_t secflash_transceive(uint8_t *pinbuf, uint32_t inbuflen, uint32_t indatalen, uint8_t *poutbuf,
                             uint32_t outbuflen, uint32_t *outdatalen)
{
    struct block_info *pnext = ctx_get_next_block();

    if (!pnext) {
        SECFLASH_ERR();
        return SECFLASH_MAKEERR(SECFLASH_RET_INVALID_PARAMETER, __LINE__);
    }
    struct iblock_info *pinfo = &(pnext->iblock);
    uint32_t ret;

    /* check status and params before transceive with secflash */
    ret = secflash_transceive_check(pinbuf, inbuflen, indatalen, poutbuf, outbuflen, outdatalen);
    if (ret != SECFLASH_RET_SUCCESS) {
        SECFLASH_ERR();
        return ret;
    }

    ctx_set_state(STATE_TRANS);
    /* process send */
    ctx_set_trans_state(SEND_IFRAME);
    ret = iblock_init(pinfo, pinbuf, indatalen, poutbuf, outbuflen, outdatalen);
    if (ret != SECFLASH_RET_SUCCESS) {
        SECFLASH_ERR_RET();
        ctx_set_state(STATE_IDLE);
        ctx_set_trans_state(TRANS_STATE_IDLE);
        return ret;
    }
    ret = secflash_transceive_execute();
    if (ret != SECFLASH_RET_SUCCESS) {
        SECFLASH_ERR_RET();
        ctx_set_state(STATE_IDLE);
        ctx_set_trans_state(TRANS_STATE_IDLE);
        return ret;
    }
    /* state must be reset in secflash_transceive_done, even if secflash_transceive_done is error */
    ret = secflash_transceive_done(pinfo);
    if (ret != SECFLASH_RET_SUCCESS)
        SECFLASH_ERR_RET();
    return ret;
}

/*
 * @brief       : secflash_chip_rese: Reset flash chip by type.
 * @param pinbuf: SECFLASH_RESET_TYPE_SOFT or SECFLASH_RESET_TYPE_HARD
 * @return secflash_RET_SUCCESS(0) if success, other if failed.
 */
uint32_t secflash_chip_reset(uint32_t type)
{
    uint32_t ret;

    if (type == SECFLASH_RESET_TYPE_SOFT) {
        SECFLASH_TRACE("sreset");
        /* check status */
        if (ctx_get_state() == STATE_TRANS) {
            SECFLASH_ERR();
            return SECFLASH_MAKEERR(SECFLASH_RET_BUSY, __LINE__);
        }
        if (ctx_get_state() == STATE_UNAVAILABLE) {
            SECFLASH_ERR();
            return SECFLASH_MAKEERR(SECFLASH_RET_INVALID_STATE, __LINE__);
        }

        ret = block_soft_reset();
        if (ret != SECFLASH_RET_SUCCESS) {
            SECFLASH_ERR_RET();
            return ret;
        }
        ctx_init(STATE_IDLE);
    } else {
        SECFLASH_TRACE("hreset");
        ctx_init(STATE_UNAVAILABLE);
        ret = secflash_io_hard_reset(ctx_get_pwt());
        if (ret != SECFLASH_RET_SUCCESS) {
            SECFLASH_ERR_RET();
            return ret;
        }
        ctx_set_state(STATE_IDLE);
        ctx_set_trans_state(TRANS_STATE_IDLE);
    }

    /* ifs */
    ret = block_addressing(NULL);
    if (ret != SECFLASH_RET_SUCCESS) {
        SECFLASH_ERR_RET();
        ctx_set_state(STATE_UNAVAILABLE);
        return ret;
    }

    /* cip */
    ret = block_transeive_with_retry(SEND_S_CIP);
    if (ret != SECFLASH_RET_SUCCESS) {
        SECFLASH_ERR_RET();
        return ret;
    }
    /* In order to circumvent the supplier problem */
    if (type == SECFLASH_RESET_TYPE_HARD) {
        ret = block_soft_reset();
        if (ret != SECFLASH_RET_SUCCESS) {
            SECFLASH_ERR_RET();
            return ret;
        }
        ctx_init(STATE_IDLE);
    }

    return ret;
}

/*
 * @brief      : secflash_power_save: Set chip to power saving mode.
 * @return secflash_RET_SUCCESS(0) if success, other if failed.
 */
uint32_t secflash_power_save(void)
{
    uint32_t ret;
    struct block_info *precv = NULL;

    SECFLASH_TRACE("psave");
    if (ctx_get_state() == STATE_TRANS) {
        SECFLASH_ERR();
        return SECFLASH_MAKEERR(SECFLASH_RET_BUSY, __LINE__);
    }
    if (ctx_get_state() == STATE_UNAVAILABLE) {
        SECFLASH_ERR();
        return SECFLASH_MAKEERR(SECFLASH_RET_INVALID_STATE, __LINE__);
    }

    ret = block_transeive_with_retry(SEND_S_RESYNCH);
    if (ret != SECFLASH_RET_SUCCESS) {
        SECFLASH_ERR_RET();
        return ret;
    }

    ret = block_transeive_with_retry(SEND_S_RELEASE);
    if (ret != SECFLASH_RET_SUCCESS) {
        SECFLASH_ERR_RET();
        return ret;
    }
    precv = ctx_get_recv_block();
    if (!precv) {
        SECFLASH_ERR();
        return SECFLASH_MAKEERR(SECFLASH_RET_INVALID_PARAMETER, __LINE__);
    }
    if (precv->type == SBLOCK && precv->sblock.type == RELEASE_RSP) {
        SECFLASH_TRACE("power save ok!");
        ret = SECFLASH_RET_SUCCESS;
    } else {
        SECFLASH_ERR();
        ret = SECFLASH_MAKEERR(SECFLASH_RET_ERR, __LINE__);
    }

    return ret;
}

/*
 * @brief      : get the secure flash device cip information in fastboot, according to GP secure flash protocol.
 * @param[out] : cip_info: return the device cip information, according to GP secure flash protocol.
 * @return     : success -- SECFLASH_OK
 *               fail    -- SECFLASH_ERROR
 */
uint32_t secflash_get_cip_info(struct secflash_cip_info *cip_info)
{
    uint32_t ret;
    uint8_t *rbuf = NULL;
    uint8_t pcb;
    uint8_t hb_len;

    if (!cip_info) {
        SECFLASH_ERR();
        return SECFLASH_MAKEERR(SECFLASH_RET_INVALID_PARAMETER, __LINE__);
    }
    ret = block_transeive_with_retry(SEND_S_CIP);
    if (ret != SECFLASH_RET_SUCCESS) {
        SECFLASH_ERR_RET();
        return ret;
    }
    rbuf = ctx_get_recv_buf(); /* this rbuf len must be 260 byte */
    if (!rbuf) {
        SECFLASH_ERR();
        return SECFLASH_MAKEERR(SECFLASH_RET_INVALID_BLOCK, __LINE__);
    }
    pcb = rbuf[BLOCK_OFFSET_PCB];
    if (pcb != CIP_RSP) {
        SECFLASH_ERR();
        return SECFLASH_MAKEERR(SECFLASH_RET_INVALID_BLOCK, __LINE__);
    }
    hb_len = rbuf[SBLOCK_OFFSET_CIP_LHB];
    if (hb_len > SBLOCK_CIP_HB_MAX_LEN) {
        SECFLASH_ERR();
        return SECFLASH_MAKEERR(SECFLASH_RET_INVALID_BLOCK, __LINE__);
    }
    cip_info->category_indi = rbuf[HB_CATEGORY_INDICATOR];
    cip_info->compact_header = rbuf[HB_COMPACT_HEADER];
    ret = memcpy_s(cip_info->product_name, HB_PRODUCT_NAME_LEN, rbuf + HB_PRODUCT_NAME, HB_PRODUCT_NAME_LEN);
    if (ret != EOK) {
        SECFLASH_ERR_RET();
        return SECFLASH_MAKEERR(SECFLASH_RET_ERR, __LINE__);
    }
    ret = memcpy_s(cip_info->firmware_version, HB_FIRMWARE_VERSION_LEN,
                   rbuf + HB_FIRMWARE_VERSION, HB_FIRMWARE_VERSION_LEN);
    if (ret != EOK) {
        SECFLASH_ERR_RET();
        return SECFLASH_MAKEERR(SECFLASH_RET_ERR, __LINE__);
    }
    ret = memcpy_s(cip_info->status_indi, HB_STATUS_INDICATOR_LEN,
                   rbuf + HB_STATUS_INDICATOR, HB_STATUS_INDICATOR_LEN);
    if (ret != EOK) {
        SECFLASH_ERR_RET();
        return SECFLASH_MAKEERR(SECFLASH_RET_ERR, __LINE__);
    }
    return SECFLASH_RET_SUCCESS;
}
