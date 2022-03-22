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
 * ISO7816 T=1 interface.
 *
 */

#ifndef ISO7816_T1_H
#define ISO7816_T1_H

#include <stdint.h>

struct t1_transport; /* Forward declaration of platform transport */

struct t1_state {
    /* Pointer to platform transport.
     * Not used by engine, to be managed by transport layer and transport
     * setup.
     */
    struct t1_transport *transport;

    struct {
        /* Ordered by decreasing priority */
        unsigned closed  : 1;   /* Prevent any loop run           */
        unsigned halt    : 1;   /* Halt dispatch loop             */
        unsigned request : 1;   /* Build a SBLOCK request         */
        unsigned reqresp : 1;   /* Build a SBLOCK response        */
        unsigned badcrc  : 1;   /* Build a RBLOCK for CRC error   */
        unsigned timeout : 1;   /* Resend S-BLOCK or send R-BLOCK */
        unsigned aborted : 1;   /* Abort was requested            */
    } state;

    uint8_t ifsc; /* IFS for card        */
    uint8_t ifsd; /* IFS for device      */
    uint8_t nad;  /* NAD byte for device */
    uint8_t nadc; /* NAD byte for card   */
    uint8_t wtx;  /* Read timeout scaler */

    unsigned bwt;     /* Block Waiting Timeout */
    unsigned timeout; /* Polling for response timeout */

    uint8_t retries;  /* Remaining retries in case of incorrect block       */
    uint8_t request;  /* Current pending request, valid only during request */

    int wtx_rounds;     /* Limit number of WTX round from card    */
    int wtx_max_rounds; /* Maximum number of WTX rounds from card */

    uint8_t need_reset; /* Need to send a reset on first start            */
    uint8_t atr[32];    /* ISO7816 defines ATR with a maximum of 32 bytes */
    uint8_t atr_length; /* Never over 32                                  */

    /* Emission window */
    struct t1_send {
        const uint8_t *start;
        const uint8_t *end;
        uint8_t        next; /* N(S) */
    } send;

    /* Reception window */
    struct t1_recv {
        uint8_t *start;
        uint8_t *end;
        uint8_t  next; /* N(R) */
        size_t   size; /* Maximum window size */
    } recv;

    size_t recv_max;  /* Maximum number of expected bytes on reception */
    size_t recv_size; /* Received number of bytes so far */

    /* Max size is:
     *  - 3 bytes header,
     *  - 254 bytes data,
     *  - 2 bytes CRC
     *
     * Use 255 bytes data in case of invalid block length of 255.
     */
    uint8_t buf[3 + 255 + 2];
};

void isot1_init(struct t1_state *t1);
void isot1_release(struct t1_state *t1);
int isot1_transceive(struct t1_state *t1, const void *snd_buf,
                     size_t snd_len, void *rcv_buf, size_t rcv_len);
int isot1_reset(struct t1_state *t1);
int isot1_get_atr(struct t1_state *t1, void *atr, size_t n);

/* Only used for ISO-7816 test scenarios, eSE does not use it */
int isot1_negotiate_ifsd(struct t1_state *t1, int ifsd);

int t1_factory_test(void);
int t1_scard_connect(int reader_id, void *p_atr, unsigned int *atr_len);
int t1_scard_disconnect(int reader_id);
int t1_scard_transmit(int reader_id , unsigned char *p_cmd , unsigned int cmd_len ,
    unsigned char *p_rsp , unsigned int *rsp_len);

#endif /* ISO7816_T1_H */
