/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: common code in mailbox driver
 */
#include "mbx_common.h"

static struct mailbox g_mailbox = {0};

static void rx_tail(struct session *session, union msg_head *rx_head)
{
#ifdef SUPPORT_MBX_INTERRUPT
    hi_u32 handle = 0;
#endif

    if (!rx_head->bits.ongoing) {
    session->rx_status &= ~SESSION_BUSY;
#ifdef SUPPORT_MBX_INTERRUPT
    handle = GEN_SESSION_HANDLE(rx_head->bits.num, rx_head->bits.port);
    /* Call session callback func */
    if (session->func) {
        session->func(handle, session->data);
    }
#endif
    } else {
        session->rx_status |= SESSION_BUSY;
    }

    return;
}

static hi_s32 rx(struct session *session, union msg_head *rx_head)
{
    hi_s32 i, j, rd_idx, wr_idx, empty_len;
    hi_u32 tmp_data;

    if (g_mailbox.initalized != HI_TRUE) {
        return HI_ERR_MAILBOX_NOT_INIT;
    }
    if ((session == NULL) || (rx_head == NULL)) {
        return HI_ERR_MAILBOX_INVALID_HANDLE;
    }

    session->rx_status |= SESSION_BUSY;
    wr_idx = session->rx_buf.wr_idx;
    rd_idx = session->rx_buf.rd_idx;
    if (rd_idx > wr_idx) {
        empty_len = rd_idx - wr_idx;
    } else {
        empty_len = session->rx_buf.size + rd_idx - wr_idx;
    }
    if (rx_head->bits.msg_len >= empty_len) {
        session->rx_status &= ~SESSION_BUSY;
        return HI_ERR_MAILBOX_ERR_RECEIVE;
    }
    for (i = 0; i < rx_head->bits.msg_len / 4; i++) { /* copy 4 bytes for each time */
        tmp_data = MBX_READL(session->rx_reg->argv + i);
        for (j = 0; j < 4; j++) { /* copy 4 bytes in a register */
            session->rx_buf.addr[wr_idx++] = (tmp_data >> (8 * j)) & 0xFF; /* 8 bits offset with 0xFF mask */
            wr_idx %= session->rx_buf.size;
        }
    }
    if (rx_head->bits.msg_len % 4) { /* copy left bytes less then 4 bytes */
        tmp_data = MBX_READL(session->rx_reg->argv + i);
        for (j = 0; j < rx_head->bits.msg_len % 4; j++) { /* copy for less 4 bytes in a register */
            session->rx_buf.addr[wr_idx++] = (tmp_data >> (8 * j)) & 0xFF; /* 8 bits offset with 0xFF mask */
            wr_idx %= session->rx_buf.size;
        }
    }
    session->rx_buf.wr_idx = wr_idx;
    /* Clean rx pending status */
    MBX_WRITEL(0x00, (session->rx_reg->pending));
    rx_tail(session, rx_head);

    return HI_MBX_SUCCESS;
}

static struct session *__find_session(hi_u32 session_num, hi_u32 session_port)
{
    struct session *session = NULL;
    struct session *tmp = NULL;

    MBX_LIST_FOR_EACH_ENTRY(session, tmp, &g_mailbox.list_head, node) {
        if ((session->num == session_num) && (session->port == session_port)) {
            return session;
        }
    }

    MBX_LIST_FOR_EACH_ENTRY(session, tmp, &g_mailbox.list_head, node) {
        if ((session->num == session_num) && (session->port == 0)) {
            return session;
        }
    }

    return NULL;
}

hi_s32 mbx_rx_msg(hi_void *rx_head_addr)
{
    struct session *session = NULL;
    union msg_head rx_head = {.head = 0};
    hi_s32 ret;

    if (g_mailbox.initalized != HI_TRUE) {
        return HI_ERR_MAILBOX_NOT_INIT;
    }
    rx_head.head = MBX_READL(rx_head_addr);
    session = __find_session(rx_head.bits.num, rx_head.bits.port);
    if (session == NULL) {
        return HI_ERR_MAILBOX_INVALID_HANDLE;
    }
    if (MBX_READL((session->rx_reg->pending)) != 0) {
        if (rx_head.bits.msg_len != 0) {
            ret = rx(session, &rx_head);
            if (ret != HI_MBX_SUCCESS) {
                MBX_ERR_PRINT("Receive in mbx_rx_msg and ret:0x%x\n", ret);
                return ret;
            }
        }
    } else {
        return HI_ERR_MAILBOX_ERR_RECEIVE;
    }

    return HI_MBX_SUCCESS;
}

static hi_s32 async_tx(hi_u32 handle, const hi_u8 *msg, hi_u32 msg_len)
{
    hi_u32 i;
    hi_s32 rd_idx;
    hi_s32 wr_idx;
    hi_u32 empty_len;
    struct session *session = NULL;

    if (g_mailbox.initalized != HI_TRUE) {
        return HI_ERR_MAILBOX_NOT_INIT;
    }
    if (msg_len == 0) {
        return HI_ERR_MAILBOX_INVALID_PARA;
    }
    session = __find_session(SESSION_HANDLE_NUM(handle), SESSION_HANDLE_PORT(handle));
    if (session == NULL) {
        return HI_ERR_MAILBOX_INVALID_HANDLE;
    }
    if (session->tx_buf.addr == NULL) {
        return HI_ERR_MAILBOX_NOT_SUPPORT;
    }
    wr_idx = session->tx_buf.wr_idx;
    rd_idx = session->tx_buf.rd_idx;
    if (rd_idx > wr_idx) {
        empty_len = rd_idx - wr_idx;
    } else {
        empty_len = session->tx_buf.size + rd_idx - wr_idx;
    }
    if (msg_len >= empty_len) {
        session->tx_status = HI_ERR_MAILBOX_NO_MEMORY;
        return HI_ERR_MAILBOX_NO_MEMORY;
    }

    for (i = 0; i < msg_len; i++) {
        session->tx_buf.addr[wr_idx++] = msg[i];
        wr_idx %= session->tx_buf.size;
    }
    session->tx_buf.wr_idx = wr_idx;
    session->tx_status = HI_ERR_MAILBOX_PENDING;

    return HI_ERR_MAILBOX_NOT_SUPPORT;
}

static hi_s32 sync_tx_to_reg(struct session *session, const hi_u8 *msg, hi_u32 msg_len, hi_s32 tx_count)
{
    hi_u32 i, tmp_data;

    if ((session == NULL) || (msg == NULL)) {
        return HI_ERR_MAILBOX_INVALID_HANDLE;
    }

    for (i = 0; i < msg_len / 4; i++) { /* write body data with 4 bytes every times */
        tmp_data = 0;
        if (memcpy_s(&tmp_data, sizeof(tmp_data), &msg[i * 4 + tx_count], sizeof(hi_s32))) { /* offset 4 step */
            MBX_ERR_PRINT("memcpy_s failed\n");
            return HI_MBX_FAILURE;
        }
        MBX_WRITEL(tmp_data, session->tx_reg->argv + i);
    }
    if (msg_len % 4) { /* for left data that less than 4 bytes */
        tmp_data = 0;
        if (memcpy_s(&tmp_data, sizeof(tmp_data), &msg[i * 4 + tx_count], msg_len % 4)) { /* offset 4 step */
            MBX_ERR_PRINT("memcpy_s failed\n");
            return HI_MBX_FAILURE;
        }
        MBX_WRITEL(tmp_data, session->tx_reg->argv + i);
    }

    return HI_MBX_SUCCESS;
}

static hi_s32 sync_tx(hi_u32 handle, const hi_u8 *msg, hi_u32 msg_len, hi_u32 timeout)
{
    hi_s32 tx_count, ret, status;
    struct session *session = NULL;
    union msg_head tx_head = {.head = 0};

    if (g_mailbox.initalized != HI_TRUE) {
        return HI_ERR_MAILBOX_NOT_INIT;
    }
    if (msg_len == 0) {
        return HI_ERR_MAILBOX_INVALID_PARA;
    }
    session = __find_session(SESSION_HANDLE_NUM(handle), SESSION_HANDLE_PORT(handle));
    if (session == NULL) {
        return HI_ERR_MAILBOX_INVALID_HANDLE;
    }

    tx_count = 0;
    while (1) {
        mutex_lock(session->tx_reg->lock);
        status = MBX_READL((session->tx_reg->pending));
        mutex_unlock(session->tx_reg->lock);
        if (status) {
            MBX_UDELAY(MBX_DELAY_TIME);
            if (timeout > MBX_DELAY_TIME) {
                timeout = timeout - MBX_DELAY_TIME;
            } else {
                return HI_ERR_MAILBOX_TIMEOUT;
            }
            continue;
        }
        /* break until sending completion */
        if (msg_len <= 0) {
            break;
        }
        mutex_lock(session->tx_reg->lock);
        /* write head data */
        tx_head.bits.num = session->num;
        tx_head.bits.port = SESSION_HANDLE_PORT(handle);
        tx_head.bits.msg_len = msg_len / session->tx_reg->argv_size ? \
                               session->tx_reg->argv_size : msg_len % session->tx_reg->argv_size;
        msg_len -= tx_head.bits.msg_len;
        if (msg_len == 0) {
            tx_head.bits.ongoing = HI_FALSE;
            session->tx_status = HI_MBX_SUCCESS;
        } else {
            tx_head.bits.ongoing = HI_TRUE;
            session->tx_status = HI_ERR_MAILBOX_PENDING;
        }
        MBX_WRITEL(tx_head.head, session->tx_reg->head);
        ret = sync_tx_to_reg(session, msg, tx_head.bits.msg_len, tx_count);
        if (ret != HI_MBX_SUCCESS) {
            mutex_unlock(session->tx_reg->lock);
            return ret;
        }
        /* trigger rx interrupt in other side */
        MBX_WRITEL(0x01, session->tx_reg->trigger_rx); /* write 0x01 to trigger */
        tx_count += tx_head.bits.msg_len;
        mutex_unlock(session->tx_reg->lock);
    }

    return HI_MBX_SUCCESS;
}

hi_s32 mbx_tx(hi_u32 handle, const hi_u8 *msg, hi_u32 msg_len, hi_u32 *tx_len, hi_u32 timeout)
{
    hi_s32 ret;

    if (tx_len == NULL) {
        return HI_ERR_MAILBOX_INVALID_PARA;
    }
    if (g_mailbox.initalized != HI_TRUE) {
        *tx_len = 0;
        return HI_ERR_MAILBOX_NOT_INIT;
    }
    if (msg == NULL) {
        *tx_len = 0;
        return HI_ERR_MAILBOX_INVALID_PARA;
    }
    if (msg_len == 0) {
        *tx_len = 0;
        return HI_ERR_MAILBOX_INVALID_PARA;
    }
    if (timeout == 0) {
        ret = async_tx(handle, msg, msg_len);
        if (ret != HI_MBX_SUCCESS) {
            *tx_len = 0;
            return ret;
        }
    } else {
        ret = sync_tx(handle, msg, msg_len, timeout);
        if (ret != HI_MBX_SUCCESS) {
            *tx_len = 0;
            return ret;
        }
    }
    *tx_len = msg_len;

    return HI_MBX_SUCCESS;
}

hi_s32 mbx_rx(hi_u32 handle, hi_u8 *msg, hi_u32 msg_len, hi_u32 *rx_len, hi_u32 timeout)
{
    struct session *session = NULL;
    hi_s32 status, rd_idx, wr_idx;
    hi_u32 i, len;

    if (g_mailbox.initalized != HI_TRUE) {
        *rx_len = 0;
        return HI_ERR_MAILBOX_NOT_INIT;
    }
    if ((msg == NULL) || (msg_len == 0) || (rx_len == NULL)) {
        return HI_ERR_MAILBOX_INVALID_PARA;
    }

    session = __find_session(SESSION_HANDLE_NUM(handle), SESSION_HANDLE_PORT(handle));
    if (session == NULL) {
        *rx_len = 0;
        return HI_ERR_MAILBOX_INVALID_HANDLE;
    }
    rd_idx = session->rx_buf.rd_idx;
    wr_idx = session->rx_buf.wr_idx;
    status = session->rx_status & SESSION_BUSY;
    while (status || !(wr_idx - rd_idx)) {
        MBX_UDELAY(MBX_DELAY_TIME);
        /* Receive message with polling mode if not support interrupt */
        mbx_polling_rx();
        if (timeout > MBX_DELAY_TIME) {
            timeout = timeout - MBX_DELAY_TIME;
        }
        if (timeout <= MBX_DELAY_TIME) {
            *rx_len = 0;
            return HI_ERR_MAILBOX_TIMEOUT;
        }
        rd_idx = session->rx_buf.rd_idx;
        wr_idx = session->rx_buf.wr_idx;
        status = session->rx_status & SESSION_BUSY;
    }
    if (wr_idx > rd_idx) {
        len = wr_idx - rd_idx;
    } else {
        len = session->rx_buf.size + wr_idx - rd_idx;
    }
    len = msg_len > len ? len : msg_len;
    for (i = 0; i < len; i++) {
        msg[i] = session->rx_buf.addr[rd_idx++];
        rd_idx %= session->rx_buf.size;
    }
    session->rx_buf.rd_idx = rd_idx;
    *rx_len = len;

    return HI_MBX_SUCCESS;
}

hi_s32 mbx_register_irq_callback(hi_u32 handle, session_callback func, hi_void *data)
{
    struct session *session = NULL;

    if (g_mailbox.initalized != HI_TRUE) {
        return HI_ERR_MAILBOX_NOT_INIT;
    }
    session = __find_session(SESSION_HANDLE_NUM(handle), SESSION_HANDLE_PORT(handle));
    if (session == NULL) {
        return HI_ERR_MAILBOX_INVALID_HANDLE;
    }
    session->func = func;
    session->data = data;

    return HI_MBX_SUCCESS;
}

static struct session *mbx_alloc_session(hi_u32 session_id, hi_u32 rx_buf_size, hi_u32 tx_buf_size)
{
    struct session *session = NULL;
    struct session *tmp = NULL;
    hi_u32 port;
    hi_s32 ret;

    (void)tx_buf_size;
    port = 0;

/* find the minimun port of free session in the list */
retry:
    MBX_LIST_FOR_EACH_ENTRY(session, tmp, &g_mailbox.list_head, node) {
        if (session->num == SESSION_ID_NUM(session_id)) {
            if (port == session->port) {
                port++;
                goto retry;
            }
        }
    }

    session = (struct session *)MBX_MALLOC(sizeof(struct session));
    if (session == NULL) {
        return NULL;
    }
    ret = memset_s(session, sizeof(struct session), 0, sizeof(struct session));
    if (ret != HI_SUCCESS) {
        return NULL;
    }

    session->num = SESSION_ID_NUM(session_id);
    session->port = port;
    if (rx_buf_size > 0) {
        session->rx_buf.addr = (hi_u8 *)MBX_MALLOC(rx_buf_size);
        if (!session->rx_buf.addr) {
            return NULL;
        }
        session->rx_buf.size = rx_buf_size;
    } else {
        session->rx_buf.addr = NULL;
        session->rx_buf.size = 0;
    }
    session->rx_buf.rd_idx = 0;
    session->rx_buf.wr_idx = 0;

    /* Not support tx with buffer */
    session->tx_buf.addr = NULL;
    session->tx_buf.size = 0;
    session->tx_buf.rd_idx = 0;
    session->tx_buf.wr_idx = 0;

    return session;
}

hi_s32 mbx_open(hi_u32 session_id, hi_u32 rx_buf_size, hi_u32 tx_buf_size)
{
    struct session *session = NULL;

    if (g_mailbox.initalized != HI_TRUE) {
        return HI_ERR_MAILBOX_NOT_INIT;
    }
    if (rx_buf_size == 0) {
        return HI_ERR_MAILBOX_NOT_SUPPORT;
    }

    if (SESSION_ID_SIDE0(session_id) != g_mailbox.local_cpu && \
            SESSION_ID_SIDE1(session_id) != g_mailbox.local_cpu) {
        return HI_ERR_MAILBOX_NOT_SUPPORT;
    }
    if (SESSION_ID_SIDE0(session_id) >= CPU_MAX || \
            SESSION_ID_SIDE1(session_id) >= CPU_MAX) {
        return HI_ERR_MAILBOX_NOT_SUPPORT;
    }
    mutex_lock(&g_mailbox.list_lock);
    session = mbx_alloc_session(session_id, rx_buf_size, tx_buf_size);
    if (session == NULL) {
        mutex_unlock(&g_mailbox.list_lock);
        return HI_ERR_MAILBOX_NO_MEMORY;
    }
    init_mailbox_reg(session, session_id, &g_mailbox);
    if ((session->tx_reg == NULL) || (session->rx_reg == NULL)) {
        if (session->rx_buf.addr != NULL) {
            MBX_FREE(session->rx_buf.addr);
            session->rx_buf.addr = NULL;
        }
        if (session->tx_buf.addr != NULL) {
            MBX_FREE(session->tx_buf.addr);
            session->tx_buf.addr = NULL;
        }
        MBX_FREE(session);
        mutex_unlock(&g_mailbox.list_lock);
        return HI_ERR_MAILBOX_NOT_SUPPORT;
    }
    MBX_LIST_ADD(&session->node, &g_mailbox.list_head);
    mutex_unlock(&g_mailbox.list_lock);

    return GEN_SESSION_HANDLE(session->num, session->port);
}

hi_s32 mbx_close(hi_u32 handle)
{
    struct session *session = NULL;

    if (g_mailbox.initalized != HI_TRUE) {
        return HI_ERR_MAILBOX_NOT_INIT;
    }
    session = __find_session(SESSION_HANDLE_NUM(handle), SESSION_HANDLE_PORT(handle));
    if (session == NULL) {
        return HI_ERR_MAILBOX_INVALID_HANDLE;
    }
    if (session->tx_reg != NULL) {
        MBX_FREE(session->tx_reg);
        session->tx_reg = NULL;
    }
    if (session->rx_reg != NULL) {
        MBX_FREE(session->rx_reg);
        session->rx_reg = NULL;
    }
    if (session->rx_buf.addr != NULL) {
        MBX_FREE(session->rx_buf.addr);
        session->rx_buf.addr = NULL;
    }
    if (session->tx_buf.addr != NULL) {
        MBX_FREE(session->tx_buf.addr);
        session->tx_buf.addr = NULL;
    }
    mutex_lock(&g_mailbox.list_lock);
    MBX_LIST_DEL(&session->node);
    MBX_FREE(session);
    session = NULL;
    mutex_unlock(&g_mailbox.list_lock);

    return HI_MBX_SUCCESS;
}

struct mailbox *get_mailbox_data(hi_void)
{
    return &g_mailbox;
}
