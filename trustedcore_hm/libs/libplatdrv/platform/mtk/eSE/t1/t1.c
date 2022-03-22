/*****************************************************************************
 * Copyright Gemalto, unpublished work, created 2015. This computer program
 * includes Confidential, Proprietary Information and is a Trade Secret of
 * Gemalto. All use, disclosure, and/or reproduction is prohibited unless
 * authorised in writing by an officer of Gemalto. All Rights Reserved.
 *
 * Gemalto licenses this file to you under the libse-gto Gemalto License.
 * See NOTICE file for more information regarding copyright ownership.
 * A copy of libse-gto Gemalto License is available in LICENSE file included
 * in source code distribution of libse-gto Gemalto. You can ask a copy of the
 * License by contacting Gemalto (http://www.gemalto.com).
 ****************************************************************************/

/**
 * @file
 * $Author$
 * $Revision$
 * $Date$
 *
 * T=1 implementation.
 *
 */
#include <stddef.h>
#include <errno.h>
#include "spi.h"
#include "t1.h"
#include "tee_log.h"
#include <sre_sys.h>
#include <memory.h>
#include "sre_task.h"
#include "sre_dev_relcb.h"
#include "securec.h"
#include "sre_syscalls_id_ext.h"
#include <hmdrv_stub.h> // hack for `HANDLE_SYSCALL`
#include "spi_common.h"

#define T1_RETURN_OK 0
#define T1_RETURN_ERROR   (-1)
#define T1_REQUEST_RESYNC 0x00
#define T1_REQUEST_IFS    0x01
#define T1_REQUEST_ABORT  0x02
#define T1_REQUEST_WTX    0x03
#define T1_REQUEST_RESET  0x05 /* Custom RESET for SPI version */

#define MAX_RETRIES 3
#define READ_LEN 3

#define MAX_WTX_ROUNDS 9
#define DEBUG 0

#ifndef unused
#define unused(x) (void)(x)
#endif

enum gpiomux_output_value {
    GPIOMUX_LOW = 0,
    GPIOMUX_HIGH,
};

static int isot1_block_send(struct t1_state *t1, void *buf, size_t n);
static int isot1_block_recv(struct t1_state *t1, void *buf, size_t n);

static uint8_t lrc8(const void *s, size_t n)
{
    const uint8_t *p = s;
    uint8_t        c = 0;

    if (p)
        while (n--)
            c ^= *p++;
    return c;
}

static void t1_init_recv_window(struct t1_state *t1, void *buf, size_t n)
{
    t1->recv.start = t1->recv.end = buf;
    t1->recv.size  = n;
}

static ptrdiff_t t1_recv_window_free_size(struct t1_state *t1)
{
    return (ptrdiff_t)t1->recv.size - (t1->recv.end - t1->recv.start);
}

static void t1_recv_window_append(struct t1_state *t1, const void *buf, int n)
{
    ptrdiff_t free = t1_recv_window_free_size(t1);
    errno_t ret;
    if (n > free)
        n = (int)free;
    if (n > 0) {
        ret = memcpy_s(t1->recv.end, t1->recv.size, buf, (size_t)n);
        if (ret != EOK) {
            tloge("t1_recv_window_append memcpy_s fail %d\n", ret);
        }
        t1->recv.end += n;
    }
}

static ptrdiff_t t1_recv_window_size(struct t1_state *t1)
{
    return t1->recv.end - t1->recv.start;
}

static void t1_close_recv_window(struct t1_state *t1)
{
    t1->recv.start = t1->recv.end;
    t1->recv.size  = 0;
}

static void t1_init_send_window(struct t1_state *t1, const void *buf, size_t n)
{
    t1->send.start = buf;
    t1->send.end   = t1->send.start + n;
}

static ptrdiff_t t1_send_window_size(struct t1_state *t1)
{
    return t1->send.end - t1->send.start;
}

static void t1_close_send_window(struct t1_state *t1)
{
    t1->send.end = t1->send.start;
}

static int do_chk(struct t1_state *t1, uint8_t *buf)
{
    unused(t1);
    int n = 3 + buf[2];

    buf[n] = lrc8(buf, n);
    n++;
    return n;
}

static int chk_is_good(struct t1_state *t1, const uint8_t *buf)
{
    unused(t1);
    int n = 3 + buf[2];

    return buf[n] == lrc8(buf, n);
}

static int write_iblock(struct t1_state *t1, uint8_t *buf)
{
    ptrdiff_t n = t1_send_window_size(t1);
    uint8_t pcb;
    errno_t ret;

    /* Card asking for more data whereas nothing is left.*/
    if (n <= 0)
        return -EBADMSG;

    if (n > t1->ifsc)
        n = t1->ifsc, pcb = 0x20;
    else
        pcb = 0;

    if (t1->send.next)
        pcb |= 0x40;

    buf[0] = t1->nad;
    buf[1] = pcb;
    buf[2] = (uint8_t)n;
    // buffer data start from 3
    ret = memcpy_s(buf + 3, BUFFER_MAX - 3, t1->send.start, (size_t)n);
    if (ret != EOK) {
        tloge("write_iblock memcpy_s fail %d\n", ret);
    }
    return do_chk(t1, buf);
}

static int write_rblock(struct t1_state *t1, int n, uint8_t *buf)
{
    buf[0] = t1->nad;
    buf[1] = 0x80 | (n & 3);
    if (t1->recv.next)
        buf[1] |= 0x10;
    buf[2] = 0;
    return do_chk(t1, buf);
}

static int write_request(struct t1_state *t1, int request, uint8_t *buf)
{
    buf[0] = t1->nad;
    buf[1] = 0xC0 | request;

    request &= 0x1F;
    if (T1_REQUEST_IFS == request) {
        /* On response, resend card IFS, else this is request for device IFS */
        buf[2] = 1;
        if (buf[1] & 0x20)
            buf[3] = t1->ifsc;
        else
            buf[3] = t1->ifsd;
    } else if (T1_REQUEST_WTX == request) {
        buf[2] = 1;
        buf[3] = t1->wtx;
    } else
        buf[2] = 0;

    return do_chk(t1, buf);
}

static void ack_iblock(struct t1_state *t1)
{
    ptrdiff_t n = t1_send_window_size(t1);
    if (n > t1->ifsc)
        n = t1->ifsc;
    t1->send.start += n;

    /* Next packet sequence number */
    t1->send.next ^= 1;
}

/* 0 if not more block, 1 otherwize */
static int parse_iblock(struct t1_state *t1, uint8_t *buf)
{
    uint8_t pcb  = buf[1];
    uint8_t next = !!(pcb & 0x40);

    if (t1->recv.next == next) {
        t1->recv.next ^= 1;
        t1_recv_window_append(t1, buf + 3, buf[2]);
        t1->recv_size += buf[2];
    }

    /* 1 if more to come */
    return !!(pcb & 0x20);
}

static int parse_rblock(struct t1_state *t1, uint8_t *buf)
{
    int r = 0;
    uint8_t pcb = buf[1];
    uint8_t next = !!(pcb & 0x10);

    switch (pcb & 0x2F) {
        case 0:
            t1->retries = MAX_RETRIES;
            if ((t1->send.next ^ next) != 0)
                /* Acknowledge previous block */
                ack_iblock(t1);
            break;

        case 1:
            t1->retries--;
            t1->send.next = next;
            r = -EREMOTEIO;
            /* CRC error on previous block, will resend */
            break;

        case 2:
            /* Error */
            t1->state.halt = 1; r = -EIO;
            break;

        default:
            t1->state.halt = 1; r = -EOPNOTSUPP;
            break;
    }
    return r;
}

static int parse_request(struct t1_state *t1, uint8_t *buf)
{
    int n = 0;

    uint8_t request = buf[1] & 0x3F;

    t1->request = request;
    switch (request) {
        case T1_REQUEST_RESYNC:
            n = -EOPNOTSUPP;
            break;

        case T1_REQUEST_IFS:
            if (buf[2] != 1)
                n = -EBADMSG;
            else if ((buf[3] == 0) || (buf[3] == 0xFF))
                n = -EBADMSG;
            else
                t1->ifsc = buf[3];
            break;

        case T1_REQUEST_ABORT:
            if (buf[2] == 0) {
                t1->state.aborted = 1;
                t1_close_send_window(t1);
                t1_close_recv_window(t1);
            } else
                n = -EBADMSG;
            break;

        case T1_REQUEST_WTX:
            if (buf[2] > 1) {
                n = -EBADMSG;
                break;
            } else if (buf[2] == 1) {
                t1->wtx = buf[3];
                if (t1->wtx_max_rounds) {
                    t1->wtx_rounds--;
                    if (t1->wtx_rounds <= 0) {
                        t1->retries = 0;
                        n = -EBADE;
                    }
                }
            }
            break;

        default:
            n = -EOPNOTSUPP;
            break;
    }

    /* Prepare response for next loop step */
    if (n == 0)
        t1->state.reqresp = 1;

    return n;
}

/* Find if ATR is changing IFSC value */
static void parse_atr(struct t1_state *t1)
{
    const uint8_t *atr = t1->atr;
    size_t n = t1->atr_length;
    int c, y, tck;
    int proto = 0;
    int ifsc = -1;

    /* Parse T0 byte */
    tck = y = (n > 0 ? atr[0] : 0);

    /* Parse interface bytes */
    for (size_t j = 1; j < n; j++) {
        c = atr[j];
        tck ^= c;

        if ((y & 0xF0) == 0x80)
            /* This is TDi byte */
            y = c, proto |= (1 << (c & 15));
        else if (y >= 16) {
            /* First TA for T=1 */
            if ((ifsc < 0) && ((y & 0x1F) == 0x11))
                ifsc = c;
            /* Clear interface byte flag just seen */
            y &= y - 16;
        } else /* No more interface bytes */
            y = -1;
    }

    /* If TA for T=1 seen and ATR checksum is valid */
    if ((proto & 2) && (tck == 0))
        t1->ifsc = (uint8_t)ifsc;
}

/* 1 if expected response, 0 if reemit I-BLOCK, negative value is error */
static int parse_response(struct t1_state *t1, uint8_t *buf, uint16_t bLen)
{
    int r;
    uint8_t pcb = buf[1];
    int ret;
    r = 0;

    if (bLen > BUFFER_MAX) {
        tloge("bLen is too large %d\n", bLen);
        return -EBADMSG;
    }
    /* Not a response ? */
    if (pcb & 0x20) {
        pcb &= 0x1F;
        if (pcb == t1->request) {
            r = 1;
            switch (pcb) {
                case T1_REQUEST_IFS:
                    if ((buf[2] != 1) && (buf[3] != t1->ifsd))
                        r = -EBADMSG;
                    break;

                case T1_REQUEST_RESET:
                    t1->need_reset = 0;
                    if (buf[2] <= sizeof(t1->atr)) {
                        t1->atr_length = buf[2];
                        if (t1->atr_length) {
                            ret = memcpy_s(t1->atr, sizeof(t1->atr), buf + 3, t1->atr_length);
                            if (ret != EOK) {
                                tloge("parse_response memcpy_s error ret %d\n", ret);
                                r = -EBADMSG;
                            }
                        }
                        parse_atr(t1);
                    } else
                        r = -EBADMSG;
                    break;

                case T1_REQUEST_ABORT:
                case T1_REQUEST_RESYNC:
                default:
                    /* We never emitted those requests */
                    r = -EBADMSG;
                    break;
            }
        }
    }
    return r;
}

enum { T1_IBLOCK, T1_RBLOCK, T1_SBLOCK };

static int block_kind(const uint8_t *buf)
{
    if ((buf[1] & 0x80) == 0)
        return T1_IBLOCK;
    else if ((buf[1] & 0x40) == 0)
        return T1_RBLOCK;
    else
        return T1_SBLOCK;
}

static int read_block(struct t1_state *t1)
{
    int n;

    t1->timeout = t1->bwt * (t1->wtx ? t1->wtx : 1);

    n = isot1_block_recv(t1, t1->buf, sizeof(t1->buf));
    tloge("isot1_block_recv (%d) %02x %02x %02x %02x\n", n, t1->buf[0], t1->buf[1], t1->buf[2], t1->buf[3]);

    t1->wtx = 1;

    if (n < 0)
        return n;
    else if (n < 3)
        return -EBADMSG;
    else {
        if (!chk_is_good(t1, t1->buf))
            return -EREMOTEIO;

        if (t1->buf[0] != t1->nadc)
            return -EBADMSG;

        if (t1->buf[2] == 255)
            return -EBADMSG;
    }

    return n;
}

static int t1_loop(struct t1_state *t1)
{
    int len;
    int n = 0;

    /* Will happen on first run */
    if (t1->need_reset) {
        t1->state.request = 1;
        t1->request = T1_REQUEST_RESET;
    }

    while (!t1->state.halt && t1->retries) {
        if (t1->state.request)
            n = write_request(t1, t1->request, t1->buf);
        else if (t1->state.reqresp) {
            n = write_request(t1, 0x20 | t1->request, t1->buf);
            /* If response is not seen, card will repost request */
            t1->state.reqresp = 0;
        } else if (t1->state.badcrc)
            /* "1" -> T1_RBLOCK_CRC_ERROR */
            n = write_rblock(t1, 1, t1->buf);
        else if (t1->state.timeout)
            n = write_rblock(t1, 0, t1->buf);
        else if (t1_send_window_size(t1))
            n = write_iblock(t1, t1->buf);
        else if (t1->state.aborted)
            n = -EPIPE;
        else if (t1_recv_window_size(t1) >= 0)
            /* Acknowledges block received so far */
            n = write_rblock(t1, 0, t1->buf);
        else
            /* Card did not send an I-BLOCK for response */
            n = -EBADMSG;

        if (n < 0)
            break;

        len = isot1_block_send(t1, t1->buf, n);
        if (len < 0) {
            /* failure to send is permanent, give up immediately */
            n = len;
            break;
        }

        n = read_block(t1);
        if (n < 0) {
            t1->retries--;
            switch (n) {
                /* Error that trigger recovery */
                case -EREMOTEIO:
                    /* Emit checksum error R-BLOCK */
                    t1->state.badcrc = 1;
                    continue;

                case -ETIMEDOUT:
                    /* resend block */
                    t1->state.timeout = 1;
                    /* restore checksum failure error */
                    if (t1->state.badcrc)
                        n = -EREMOTEIO;
                    continue;

                /* Block read implementation failed */
                case -EBADMSG: /* fall through */

                /* Other errors are platform specific and not recoverable. */
                default:
                    t1->retries = 0;
                    continue;
            }
            /* Shall never reach this line */
            break;
        }

        if (t1->state.badcrc)
            if ((t1->buf[1] & 0xEF) == 0x81) {
                /* Resent bad checksum R-BLOCK when response is CRC failure. */
                t1->retries--;
                n = -EREMOTEIO;
                continue;
            }

        t1->state.badcrc  = 0;
        t1->state.timeout = 0;

        if (t1->state.request) {
            if (block_kind(t1->buf) == T1_SBLOCK) {
                n = parse_response(t1, t1->buf, sizeof(t1->buf));
                switch (n) {
                    case 0:
                        /* Asked to emit same former I-BLOCK */
                        break;

                    case 1:
                        t1->state.request = 0;
                        /* Nothing to do ? leave */
                        if (t1_recv_window_free_size(t1) == 0)
                            t1->state.halt = 1, n = 0;
                        t1->retries = MAX_RETRIES;
                        continue;

                    default: /* Negative return is error */
                        t1->state.halt = 1;
                        continue;
                }
            }
            /* Re-emit request until response received */
            t1->retries--;
            n = -EBADE;
        } else {
            switch (block_kind(t1->buf)) {
                case T1_IBLOCK:
                    t1->retries = MAX_RETRIES;
                    if (t1_send_window_size(t1))
                        /* Acknowledges last IBLOCK sent */
                        ack_iblock(t1);
                    n = parse_iblock(t1, t1->buf);
                    if (t1->state.aborted)
                        continue;
                    if (t1->recv_size > t1->recv_max) {
                        /* Too much data received */
                        n = -EMSGSIZE;
                        t1->state.halt = 1;
                        continue;
                    }
                    if ((n == 0) && (t1_send_window_size(t1) == 0))
                        t1->state.halt = 1;
                    t1->wtx_rounds = t1->wtx_max_rounds;
                    break;

                case T1_RBLOCK:
                    n = parse_rblock(t1, t1->buf);
                    t1->wtx_rounds = t1->wtx_max_rounds;
                    break;

                case T1_SBLOCK:
                    n = parse_request(t1, t1->buf);
                    if (n == 0)
                        /* Send request response on next loop. */
                        t1->state.reqresp = 1;
                    else if ((n == -EBADMSG) || (n == -EOPNOTSUPP))
                        t1->state.halt = 1;
                    break;
            }
        }
    }
    return n;
}

static void t1_clear_states(struct t1_state *t1)
{
    t1->state.halt    = 0;
    t1->state.request = 0;
    t1->state.reqresp = 0;
    t1->state.badcrc  = 0;
    t1->state.timeout = 0;
    t1->state.aborted = 0;

    t1->wtx     = 1;
    t1->timeout = 0;
    t1->retries = MAX_RETRIES;
    t1->request = 0xFF;

    t1->wtx_rounds = t1->wtx_max_rounds;

    t1->send.start = t1->send.end = NULL;
    t1->recv.start = t1->recv.end = NULL;
    t1->recv.size  = 0;

    t1->recv_size = 0;  /* Also count discarded bytes */
}

static int t1_is_closed(struct t1_state *t1)
{
    return t1->state.closed;
}

void isot1_init(struct t1_state *t1)
{
    t1->state.closed = 0;
    t1_clear_states(t1);

    t1->ifsc = 32;
    t1->ifsd = 32;
    t1->bwt  = 300;     /* milliseconds */

    t1->nad  = 0x12;
    t1->nadc = 0x21;

    t1->send.next = 0;
    t1->recv.next = 0;

    t1->need_reset = 1;

    t1->wtx_max_rounds = MAX_WTX_ROUNDS;

    t1->recv_max  = 65536 + 2; /* Maximum for extended APDU response */
    t1->recv_size = 0;
}

void isot1_release(struct t1_state *t1)
{
    t1->state.closed = 1;
}

int isot1_transceive(struct t1_state *t1, const void *snd_buf,
    size_t snd_len, void *rcv_buf, size_t rcv_len)
{
    int n;

    if (t1_is_closed(t1))
        return -ENOENT;

    t1_clear_states(t1);

    t1_init_send_window(t1, snd_buf, snd_len);
    t1_init_recv_window(t1, rcv_buf, rcv_len);

    n = t1_loop(t1);
    if (n == 0)
        /* Received APDU response */
        n = (int)t1_recv_window_size(t1);
    return n;
}

int isot1_negotiate_ifsd(struct t1_state *t1, int ifsd)
{
    if (t1_is_closed(t1))
        return -ENOENT;

    t1_clear_states(t1);
    t1->state.request = 1;

    t1->request = T1_REQUEST_IFS;
    t1->ifsd    = ifsd;
    return t1_loop(t1);
}

int isot1_reset(struct t1_state *t1)
{
    if (t1_is_closed(t1))
        return -ENOENT;

    t1_clear_states(t1);
    t1->need_reset = 1;

    return t1_loop(t1);
}

int isot1_get_atr(struct t1_state *t1, void *atr, size_t n)
{
    int r = 0;
    errno_t ret;

    if (t1_is_closed(t1))
        return -ENOENT;

    if (t1->need_reset)
        r = isot1_reset(t1);
    if (r >= 0) {
        if (t1->atr_length <= n) {
            r = t1->atr_length;
            ret = memcpy_s(atr, n, t1->atr, r);
            if (ret != EOK) {
                tloge("isot1_get_atr memcpy_s fail %d\n", ret);
            }
        } else
            r = -EFAULT;
    }
    return r;
}

#define TEST_LEN  100
#define READ 0
#define WRITE 1
#define T1_DEBUG  1
#define T1_INFO  1
#define ESE_INFO_LEN 11
#define RAM_ADDR_ESE_CONFIG         (0x367FFC00)        //eSE use 0x365FFC00~0x365FFCFF
#define READY 1
#define NOT_READY 0
#define ERROR (-1)
#define MAX_FRAME_SIZE  300
#define FRAME_HEADER_SIZE 3
#define MAX_DATA_SIZE (MAX_FRAME_SIZE - FRAME_HEADER_SIZE)

#define MAX_PRINT_BYTE  50
#define MAX_PRINT_BUF   (MAX_PRINT_BYTE * 2 + 2)
#define ESE_RET_SUCCESS                      0
#define ESE_RET_FAIL                         (-1)

unsigned int spi_bus_addr;
unsigned int gpio_spi_cs;
unsigned int gpio_ese_irq;
unsigned int gpio_ese_reset;
unsigned int gpio_svdd_pwr_req;
unsigned int spi_switch_need;          // 1: needed;   0: not needed;
unsigned int gpio_spi_switch;
unsigned int nfc_ese_num;
unsigned int nfc_ese_type;

struct t1_state g_t1;

#ifdef ESE_DEBUG
#define ESE_DBG(fmt, args...)  tloge("[eSE-t1]"fmt, ##args)
#else
#define ESE_DBG(fmt, args...)
#endif

void hex_print_line(unsigned char *buf, int bufLen)
{
    int i, j;
    int len;
    int ret;
    char tmpStr[MAX_PRINT_BUF];
    int packageNum = MAX_PRINT_BYTE;
    if (NULL == buf) {
        SLogError("Null Pointer when HexPrint!\n");
        return;
    }
    for (i = 0; i <= bufLen / packageNum; i++) {
        (void)memset_s(tmpStr, sizeof(tmpStr), 0, sizeof(tmpStr));
        len = (i == bufLen / packageNum) ? (bufLen % packageNum) : packageNum;
        for (j = 0; j < len; j++) {
            // j is less than MAX_PRINT_BYTE, the length of 1 byte in hex string is 2
            ret = snprintf_s(&tmpStr[j * 2], sizeof(tmpStr) - j * 2, 2, "%02X", buf[i * packageNum + j]);
            if (ret < 0) {
                SLogError("HexPrint snprintf_s fail\n");
                return;
            }
        }
        SLogTrace("HexPrint[%d]:%s \n", i, tmpStr);
    }
}

static void hex_print(unsigned char *buf, int blen, int opcode)
{
    int i;
    if (NULL == buf) {
        tloge("Null Pointer when hex_print!\n");
        return;
    }

    if (READ == opcode) {
        tloge("NFCC--->DH#read(%d)\n", blen);
    } else {
        tloge("DH--->NFCC#write(%d)\n", blen);
    }
    hex_print_line(buf, blen);
}

static int t1_dev_write(char *buf, int count)
{
    int ret = T1_RETURN_ERROR;
    struct spi_transaction_info  write_data;

    write_data.reg_addr = NULL;
    write_data.reg_len = 0;
    write_data.buf_addr = buf;
    write_data.buf_len = count;

    if (NULL == buf) {
        tloge("Null Pointer when t1_dev_write!\n");
        return ret;
    }
    ret = ese_driver_spi_full_duplex(&write_data, NULL);
    if (ret != ESE_RET_SUCCESS) {
        return ret;
    }
    return count;
}

static int t1_dev_read(char  *buf, int count)
{
    int ret = T1_RETURN_ERROR;
    struct spi_transaction_info write_data;
    struct spi_transaction_info read_data;

    write_data.reg_addr = NULL;
    write_data.reg_len = 0;
    write_data.buf_addr = NULL;
    write_data.buf_len = 0;
    read_data.reg_addr = NULL;
    read_data.reg_len = 0;
    read_data.buf_addr = buf;
    read_data.buf_len = count;
    if (NULL == buf) {
        tloge("Null Pointer when t1_dev_read!\n");
        return ret;
    }
    ret = ese_driver_spi_full_duplex(&write_data, &read_data);
    if (ret != ESE_RET_SUCCESS) {
        return ret;
    }
    return count;
}

static int isot1_block_send(struct t1_state *t1, void *buf, size_t n)
{
    unused(t1);
    int count;
    char * cbuf = (char *)buf;
    tloge("send - Enter len=%d \n", n);

    // call to the spi bird wrapper
    count = t1_dev_write(buf, n);

    tloge("isot1_block_send (%d) %02x %02x %02x %02x,count %d\n", n, cbuf[0], cbuf[1], cbuf[2], cbuf[3], count);

    if (count == 0) {
        tloge("ERROR:Failed to send data to device\n");
        return -1;
    }
    return count;
}

static int isot1_block_recv(struct t1_state *t1, void *buf, size_t n)
{
    int r = 0; /* SPI read response, negative on error, 0 if SPI channel is closed */
    int len = -1; /* block length (-1 when not known) */
    unsigned int i = 0; /* number of block bytes received so far */
    unsigned mstime = 0; /* estimated elapsed time in milliseconds */
    unsigned char *p = buf;

    /* poll for NAD byte */
    while ((i == 0) && (mstime < t1->timeout)) {
        r = t1_dev_read((char *)p, 1);
        if (r == 1) {
            if (p[0])
                /* NAD byte seen */
                i += 1;
            else {
                int msdelay = 2; /* ms */
                SRE_DelayMs(msdelay);
                mstime += msdelay;
            }
        } else {
            tloge("ERROR:Failed to receive data from device, 1.\n");
            return -1;
        }
    }
    if ((i == 0) && (mstime >= t1->timeout))
        r = -ETIMEDOUT;

    if (i > 0 && (i + READ_LEN) < n) {
        /* get PCB, LEN bytes and LRC or first data byte */
        r = t1_dev_read((char *)p + i, READ_LEN);
        if (r == READ_LEN) {
            i += READ_LEN;
            len = 4 + p[2];
            if (len > 4) {
                /* block is more than 4 bytes, get missing bytes */
                r = t1_dev_read((char *)p + i, len - i);
                if (r != (int)(len - i)) {
                    tloge("ERROR:Failed to receive data from device, len-i.\n");
                    return -1;
                }
            }
        } else {
            tloge("ERROR:Failed to receive data from device, 3.\n");
            return -1;
        }
    } else if ((i + READ_LEN) >= n) {
        tloge("ERROR: value i:%d is large than buf len:%d\n", i, n);
        return -1;
    }
    return r > 0 ? len : r;
}

void t1_gpio_control(int control)
{
    tloge("[t1_gpio_control] enter");
    set_gpio_data_out(GPIO19_MODE, GPIO19_DATAOUT_OFFSET, control);
    tloge("[t1_gpio_control] exit\n");
}

void t1_spi_cs_set(u32 control)
{
    tloge("[t1_spi_cs_set]exit\n");
}

int t1_scard_release_cb(void *data);

int t1_scard_connect(int reader_id, void *p_atr, unsigned int *atr_len)
{
    unused(reader_id);
    unused(p_atr);
    unused(atr_len);

    t1_spi_cs_set(GPIOMUX_LOW);
    tloge("[t1_scard_connect] set cs high low.\n");
    t1_gpio_control(GPIOMUX_HIGH);
    SRE_DelayMs(2); // delay 2ms to pull up cs to avoid power leakage
    t1_spi_cs_set(GPIOMUX_HIGH);
    SRE_DelayMs(5); // delay 5ms to pull up svdd pwr request
    tloge("[t1_scard_connect] set cs high end.\n");
    isot1_init(&g_t1);

    /* Note: put this at the end of this function after connect successfully,
     * this register se disconnect callback to current task,
     * in case of se disconnect call missing when task exit */
    tloge("[t1_scard_connect]before SRE_TaskRegister_DevRelCb.\n");
    int ret = SRE_TaskRegister_DevRelCb((DEV_RELEASE_CALLBACK)t1_scard_release_cb, NULL);
    if (ret) {
        (void)t1_scard_disconnect(0);
        tloge("SRE_TaskRegister_DevRelCb for scard error:%d\n", ret); /*lint !e515 */
        return ret;
    }

    return 0;
}

int t1_scard_disconnect(int reader_id)
{
    unused(reader_id);
    isot1_release(&g_t1);
    t1_spi_cs_set(GPIOMUX_LOW);
    tloge("[t1_scard_disconnect] set cs high low.\n");

    t1_gpio_control(GPIOMUX_LOW);

    /* unregister se release callback to current task */
    (void)SRE_TaskUnRegister_DevRelCb((DEV_RELEASE_CALLBACK)t1_scard_release_cb, NULL);

    return 0;
}

int t1_scard_release_cb(void *data)
{
    unused(data);
    return t1_scard_disconnect(0);
}

int t1_scard_transmit(int reader_id , unsigned char *p_cmd , unsigned int cmd_len ,
    unsigned char *p_rsp , unsigned int *rsp_len)
{
    int ret = -1;
    int rev_len;

    unused(reader_id);
    if (NULL == p_cmd || NULL == p_rsp) {
        tloge("Null Pointer when t1_scard_transmit!\n");
        return ret;
    }

    hex_print(p_cmd,  cmd_len, WRITE);

    rev_len = isot1_transceive(&g_t1, p_cmd, cmd_len, p_rsp, *rsp_len);

    if (rev_len <= 0) {
        tloge("ESE t1 apdu recieve failed, %d\n", rev_len);
        return ret;
    }

    *rsp_len = rev_len;
    hex_print(p_rsp,  rev_len, READ);
    ret = 0;

    return ret;
}

int t1_scard_get_ese_type(void)
{
    /* init ese config if first run */
    return 1;
}

int t1_factory_test(void)
{
    unsigned char response[258] = {0};
    unsigned char test_cmd[] = {0x00, 0xA4, 0x04, 0x00, 0x08, 0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00};
    unsigned int response_len = 258;
    int ret;
    unsigned int i;

    tloge("%s: eSE factory test begin ~~~~~~~~\n", __func__);

    t1_scard_connect(0, NULL, NULL);
    tloge("%s: eSE t1_scard_connect    end ~~~~~~~~\n", __func__);
    ret = t1_scard_transmit(0, test_cmd, sizeof(test_cmd), response, &response_len);

    t1_scard_disconnect(0);

    if (ret) {
        tloge("%s: eSE factory test fail because of transmit fail\n", __func__);
        return -1;
    }
    hex_print_line(response, response_len);
    if (response_len <= 2) {
        tloge("%s: eSE factory test fail because of response_len:%d too short\n", __func__, response_len);
        return -1;
    }

    // compare
    if (response[response_len - 2] != 0x90 || response[response_len - 1] != 0x00) {
        tloge("%s: eSE factory test fail because of response 0x%x%x is not 0x9000\n", __func__,
            response[response_len - 2], response[response_len - 1]);
        return -1;
    }

    tloge("%s: eSE factory test success\n", __func__);
    return 0;
}
