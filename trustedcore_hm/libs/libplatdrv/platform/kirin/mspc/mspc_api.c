/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: mspc driver for SE_API.
 * Create: 2019/11/9
 */

#include <mspc_api.h>
#include <mspc.h>
#include <mspc_errno.h>
#include <mspc_power.h>
#include <mspc_ipc.h>
#include <mspc_test_performance.h>
#include <mspc_tpdu.h>
#include <register_ops.h>
#include <sys/usrsyscall_ext.h>
#include <sre_typedef.h>
#include <securec.h>
#include <sre_sys.h>

#define MSPC_APDU_DOING                 0x5A000000
#define MSPC_APDU_DONE                  0x5A000001
#define MSPC_APDU_ABORT                 0x5A000002

#define MSPC_APDU_WAIT_TIME             7 /* 7s */

#define MSPC_LOCAL_BUFF_SIZE            (5 * 1024)
#define MSPC_LOCAL_BUFF_FREE            0x5A
#define MSPC_LOCAL_BUFF_BUSY            0xA5

#define MSPC_THIS_MODULE                MSPC_MODULE_API

enum {
    MSPC_API_INVALID_CMD_ERR            = MSPC_ERRCODE(0x10),
    MSPC_API_SEND_ACK_ERR               = MSPC_ERRCODE(0x11),
    MSPC_API_RECV_ACK_ERR               = MSPC_ERRCODE(0x12),
    MSPC_API_GET_MBX_RAM_ERR            = MSPC_ERRCODE(0x13),
    MSPC_API_SEND_APDU_ERR              = MSPC_ERRCODE(0x14),
    MSPC_API_MUTEX_ERR                  = MSPC_ERRCODE(0x15),
    /* Donnot modify it, see CAUTION in mspc_errno.h. */
    MSPC_API_RESET_ERR                  = MSPC_ERRCODE(0x16),
};

enum {
    MSPC_SEND_APDU                      = 0x376C,
    MSPC_RECV_APDU                      = 0xC893,
};

static struct mspc_work_data g_mspc_apdu;
static volatile uint32_t g_apdu_send_flag;
static volatile uint32_t g_apdu_recv_flag;
static pthread_mutex_t g_apdu_connect_mutex;
static pthread_mutex_t g_apdu_send_mutex;
static pthread_mutex_t g_apdu_recv_mutex;
static pthread_mutex_t g_apdu_work_mutex;
static uint8_t g_local_apdu_buff[MSPC_LOCAL_BUFF_SIZE];
static uint32_t volatile g_local_buff_flag = MSPC_LOCAL_BUFF_FREE;
static uint32_t g_local_data_size;

struct mspc_log_data {
    uint32_t send_len;
    uint32_t recv_len;
    uint32_t send_enter;
    uint32_t recv_enter;
    uint32_t recv_irq;
    uint32_t local_recv;
};

static struct mspc_log_data g_mspc_api_info;

static void mspc_dump_api_log(void)
{
    tloge("%s:begin dump!\n", __func__);
    tloge("send len:0x%x!\n", g_mspc_api_info.send_len);
    tloge("recv len:0x%x!\n", g_mspc_api_info.recv_len);
    tloge("send enter:0x%x!\n", g_mspc_api_info.send_enter);
    tloge("recv enter:0x%x!\n", g_mspc_api_info.recv_enter);
    tloge("recv irq:0x%x!\n", g_mspc_api_info.recv_irq);
    tloge("local recv:0x%x!\n", g_mspc_api_info.local_recv);
    tloge("left size is:0x%x!\n", g_mspc_apdu.left_size);
    tloge("status is:0x%x!\n", g_mspc_apdu.status);
    mspc_power_status_dump();
}

int32_t mspc_connect(uint32_t vote_id, void *p_atr, uint32_t *len)
{
    int32_t ret;
    (void)p_atr;
    (void)len;

    mspc_record_start_time();
    if (vote_id >= MSPC_MAX_VOTE_ID) {
        tloge("mspc:Invalid id:%u\n", vote_id);
        return MSPC_ERRCODE(INVALID_PARAM);
    }

    pthread_mutex_lock(&g_apdu_connect_mutex);
    ret = mspc_power_on(vote_id);
    pthread_mutex_unlock(&g_apdu_connect_mutex);
    if (ret != MSPC_OK)
        tloge("mspc connect power on failed:%d\n", ret);

    mspc_record_end_time(MSPC_FUNC_CONNECT);
    return ret;
}

int32_t mspc_disconnect(uint32_t vote_id)
{
    int32_t ret;

    mspc_record_start_time();
    if (vote_id >= MSPC_MAX_VOTE_ID) {
        tloge("mspc:Invalid id:%u\n", vote_id);
        return MSPC_ERRCODE(INVALID_PARAM);
    }

    pthread_mutex_lock(&g_apdu_connect_mutex);
    ret = mspc_power_off(vote_id);
    pthread_mutex_unlock(&g_apdu_connect_mutex);
    if (ret != MSPC_OK)
        tloge("mspc connect power on failed:%d\n", ret);

    mspc_record_end_time(MSPC_FUNC_DISCONNECT);
    return ret;
}

int32_t scard_send(int32_t reader_id, uint8_t *cmd, uint32_t cmd_len)
{
    int32_t ret;
    (void)reader_id;

    mspc_record_start_time();
#ifdef MSP_EXT_TPDU
    ret = mspc_extended_apdu_process(cmd, cmd_len);
#else
    ret = mspc_send_apdu(cmd, cmd_len);
#endif
    if (ret == MSPC_OK)
        ret = SRE_OK;

    mspc_record_end_time(MSPC_FUNC_SCARD_SEND);
    return ret;
}

int32_t scard_receive(uint8_t *rsp, uint32_t *rsp_len)
{
    int32_t ret;

    mspc_record_start_time();
#ifdef MSP_EXT_TPDU
    ret = mspc_tpdu_receive(rsp, rsp_len);
#else
    ret = mspc_receive_apdu(rsp, rsp_len);
#endif
    if (ret == MSPC_OK)
        ret = SRE_OK;
    mspc_record_end_time(MSPC_FUNC_SCARD_RECV);
    return ret;
}

int32_t scard_get_status(void)
{
    return mspc_get_status();
}

static uint32_t mspc_get_send_flag(void)
{
    return g_apdu_send_flag;
}

static uint32_t mspc_get_recv_flag(void)
{
    return g_apdu_recv_flag;
}

static void mspc_clear_apdu_work(void)
{
    (void)memset_s(&g_mspc_apdu, sizeof(g_mspc_apdu), 0, sizeof(g_mspc_apdu));
}

static int32_t mspc_check_send_process_param(struct mspc_cmd_info *cmd_data)
{
    if (!cmd_data) {
        tloge("%s:Invalid param!\n", __func__);
        return MSPC_ERRCODE(INVALID_PARAM);
    }

    if (cmd_data->ack != MSPC_CMD_ACK_OK) {
        tloge("%s:ACK error:%u\n", __func__, cmd_data->ack);
        return MSPC_API_SEND_ACK_ERR;
    }
    return MSPC_OK;
}

int32_t mspc_send_apdu_process(struct mspc_cmd_info *cmd_data)
{
    int32_t ret = MSPC_OK;
    uint32_t send_size = 0;
    uint32_t mbx_addr = 0;

    (void)pthread_mutex_lock(&g_apdu_work_mutex);
    /* If the last sending is aborted,  finish the data transmit. */
    if (g_apdu_send_flag != MSPC_APDU_DOING) {
        tloge("%s:send is aborted!\n", __func__);
        goto exit;
    }

    ret = mspc_check_send_process_param(cmd_data);
    if (ret != MSPC_OK) {
        g_mspc_apdu.status = ret;
        goto exit;
    }

    /* send left data if it exist. */
    if (g_mspc_apdu.left_size != 0) {
        ret = mspc_ipc_get_mbx_ram(IPC_TEE_FASTMBOX, &send_size, &mbx_addr);
        if (ret != MSPC_OK || send_size == 0) {
            g_mspc_apdu.status = MSPC_API_GET_MBX_RAM_ERR;
            goto exit;
        }
        send_size = g_mspc_apdu.left_size > send_size ?
                send_size : g_mspc_apdu.left_size;

        cmd_data->cmd = MSPC_CMD_SEND_APDU;
        cmd_data->ack = MSPC_CMD_ACK_OK;
        cmd_data->data = g_mspc_apdu.buffer;
        cmd_data->block_size = send_size;
        cmd_data->block_index++;

        ret = mspc_send_msg(cmd_data);
        if (ret != MSPC_OK) {
            g_mspc_apdu.status = MSPC_API_SEND_APDU_ERR;
            ret = MSPC_API_SEND_APDU_ERR;
            goto exit;
        } else {
            g_mspc_apdu.buffer += send_size;
            g_mspc_apdu.left_size -= send_size;
        }
    }
    if (g_mspc_apdu.left_size == 0) {
        /* Send done. */
        g_mspc_apdu.status = MSPC_CMD_ACK_OK;
    } else {
        /* Wait for next msg. */
        (void)pthread_mutex_unlock(&g_apdu_work_mutex);
        return MSPC_OK;
    }
exit:
    /*
     * Before wiriting g_apdu_send_flag, we need to make sure that
     * g_mspc_apdu.status has been written.
     */
    data_sync();
    g_apdu_send_flag = MSPC_APDU_DONE;
    mspc_clear_apdu_work();
    (void)pthread_mutex_unlock(&g_apdu_work_mutex);
    return ret;
}

static int32_t mspc_pack_cmd_msg(struct mspc_cmd_info *cmd,
                                 uint8_t *p_cmd, uint32_t cmd_len)
{
    int32_t ret;
    uint32_t send_size = 0;
    uint32_t mbx_addr = 0;

    g_mspc_apdu.buffer = p_cmd;
    g_mspc_apdu.left_size = cmd_len;
    g_mspc_apdu.status = MSPC_CMD_ACK_NULL;
    ret = mspc_ipc_get_mbx_ram(IPC_TEE_FASTMBOX, &send_size, &mbx_addr);
    if (ret != MSPC_OK || send_size == 0) {
        tloge("%s:get mailbox size:%x failed!\n", __func__, send_size);
        return MSPC_API_SEND_APDU_ERR;
    }

    send_size = g_mspc_apdu.left_size > send_size ?
                send_size : g_mspc_apdu.left_size;

    cmd->cmd    = MSPC_CMD_SEND_APDU;
    cmd->ack    = MSPC_CMD_ACK_NULL;
    cmd->data   = g_mspc_apdu.buffer;
    cmd->size   = g_mspc_apdu.left_size;
    cmd->block_size = send_size;

    g_mspc_apdu.buffer    += send_size;
    g_mspc_apdu.left_size -= send_size;

    return MSPC_OK;
}

static int32_t mspc_wait_apdu_done(uint32_t type)
{
    struct timespec start_ts = {0};
    struct timespec end_ts = {0};
    uint32_t (*get_flag_func)(void) = NULL;
    uint32_t flag;

    if (type == MSPC_SEND_APDU)
        get_flag_func = &mspc_get_send_flag;
    else
        get_flag_func = &mspc_get_recv_flag;

    clock_gettime(CLOCK_MONOTONIC, &start_ts);
    flag = get_flag_func();
    while (flag == MSPC_APDU_DOING) {
        clock_gettime(CLOCK_MONOTONIC, &end_ts);
        if (end_ts.tv_sec < start_ts.tv_sec ||
            end_ts.tv_sec - start_ts.tv_sec > MSPC_APDU_WAIT_TIME ) {
            tloge("%s:timeout!end:%d, start:%d,time:%d, type:0x%x\n",__func__,
                  end_ts.tv_sec, start_ts.tv_sec, MSPC_APDU_WAIT_TIME, type);
            return MSPC_ERRCODE(TIMEOUT_ERR);
        }
        flag = get_flag_func();
    }
    return MSPC_OK;
}

static int32_t mspc_set_send_work(uint8_t *p_cmd, uint32_t cmd_len, uint32_t *left_size)
{
    int32_t ret;
    struct mspc_cmd_info cmd;

    (void)memset_s(&cmd, sizeof(struct mspc_cmd_info),
                   0, sizeof(struct mspc_cmd_info));

    if (!p_cmd) {
        tloge("%s:Invalid param!\n", __func__);
        return MSPC_ERRCODE(INVALID_PARAM);
    }

    ret = mspc_wait_native_ready(MSPC_WAIT_READY_TIMEOUT);
    if (ret != MSPC_OK) {
        tloge("%s:mspc is unready!\n", __func__);
        return ret;
    }

    (void)pthread_mutex_lock(&g_apdu_work_mutex);
    ret = mspc_pack_cmd_msg(&cmd, p_cmd, cmd_len);
    if (ret != MSPC_OK) {
        tloge("%s:pack msg failed!\n", __func__);
        goto exit;
    }
    /* Clear local buffer flag. */
    g_local_buff_flag = MSPC_LOCAL_BUFF_FREE;
    g_apdu_send_flag = MSPC_APDU_DOING;

    ret = mspc_send_msg(&cmd);
    if (ret != MSPC_OK)
        tloge("%s:send cmd failed:ret=0x%x\n", __func__, (uint32_t)ret);

    *left_size = g_mspc_apdu.left_size;

exit:
    (void)pthread_mutex_unlock(&g_apdu_work_mutex);
    return ret;
}

int32_t mspc_send_apdu(uint8_t *p_cmd, uint32_t cmd_len)
{
    int32_t ret;
    uint32_t left_size = 0;

    (void)pthread_mutex_lock(&g_apdu_send_mutex);
    (void)memset_s(&g_mspc_api_info, sizeof(g_mspc_api_info), 0, sizeof(g_mspc_api_info));
    g_mspc_api_info.send_len = cmd_len;
    g_mspc_api_info.send_enter = 1;

    ret = mspc_set_send_work(p_cmd, cmd_len, &left_size);
    if (ret != MSPC_OK) {
        tloge("%s:set work failed!\n", __func__);
        goto exit;
    }

    /* All data has been sent. */
    if (left_size == 0)
        goto exit;

    /* wait for all data been sent done. */
    ret = mspc_wait_apdu_done(MSPC_SEND_APDU);
    if (ret != MSPC_OK)
        goto exit;

    /*
     * Before reading g_mspc_apdu.status, we need to make sure that
     * all data has been written.
     */
    data_sync();
    /* Judge whether sending is sucessful. */
    if (g_mspc_apdu.status != MSPC_CMD_ACK_OK) {
        ret = g_mspc_apdu.status;
        tloge("%s:status is 0x%x\n", __func__, g_mspc_apdu.status);
        goto exit;
    }

exit:
    (void)pthread_mutex_lock(&g_apdu_work_mutex);
    g_apdu_send_flag = MSPC_APDU_DONE;
    if (ret != MSPC_OK)
        mspc_dump_api_log();
    mspc_clear_apdu_work();
    (void)pthread_mutex_unlock(&g_apdu_work_mutex);
    pthread_mutex_unlock(&g_apdu_send_mutex);
    return ret;
}

static int32_t mspc_check_recv_process_param(struct mspc_cmd_info *cmd_data)
{
    uint32_t recv_size;

    if (!cmd_data) {
        tloge("%s:Invalid param!\n", __func__);
        return MSPC_ERRCODE(INVALID_PARAM);
    }

    if (cmd_data->ack != MSPC_CMD_ACK_OK) {
        tloge("%s:ACK error:%u\n", __func__, cmd_data->ack);
        return MSPC_API_RECV_ACK_ERR;
    }

    if (cmd_data->block_index == 0)
        g_mspc_apdu.left_size = cmd_data->size;

    if (g_mspc_apdu.left_size > g_mspc_apdu.buffer_size) {
        tloge("%s:Size error, recv:%u, buff:%u\n",
              __func__, g_mspc_apdu.left_size,
              g_mspc_apdu.buffer_size);
        return MSPC_ERRCODE(OVERFLOW_ERR);
    }

    recv_size = cmd_data->block_size;

    if (recv_size <= 0 || recv_size > g_mspc_apdu.left_size ||
        recv_size > g_mspc_apdu.buffer_size) {
        tloge("%s:Invalid size:%u\n", __func__, recv_size);
        return MSPC_ERRCODE(OVERFLOW_ERR);
    }

    return MSPC_OK;
}

static int32_t mspc_store_local_data(struct mspc_cmd_info *cmd_data)
{
    uint32_t recv_size;

    g_mspc_api_info.local_recv = 1;
    if (cmd_data->ack != MSPC_CMD_ACK_OK) {
        tloge("%s:ACK error:%u\n", __func__, cmd_data->ack);
        return MSPC_API_RECV_ACK_ERR;
    }

    recv_size = cmd_data->block_size;
    g_mspc_apdu.left_size = cmd_data->size;

    if (recv_size <= 0 || recv_size > MSPC_LOCAL_BUFF_SIZE ||
        recv_size > g_mspc_apdu.left_size) {
        tloge("%s:Invalid size:%u\n", __func__, recv_size);
        return MSPC_ERRCODE(OVERFLOW_ERR);
    }

    mspc_mailbox_data_copy(g_local_apdu_buff, cmd_data->data, recv_size);

    g_local_data_size = recv_size;
    g_local_buff_flag = MSPC_LOCAL_BUFF_BUSY;
    g_mspc_apdu.left_size -= recv_size;

    return MSPC_OK;
}

static int32_t mspc_recv_work(struct mspc_cmd_info *cmd_data)
{
    int32_t ret;
    uint32_t recv_size;
    uint8_t *recv_addr = NULL;

    ret = mspc_check_recv_process_param(cmd_data);
    if (ret != MSPC_OK) {
        g_mspc_apdu.status = ret;
        g_mspc_apdu.recv_size = 0;
        /*
         * Before wiriting g_apdu_send_flag, we need to make sure that
         * g_mspc_apdu.status has been written.
         */
        data_sync();
        g_apdu_recv_flag = MSPC_APDU_DONE;
        return ret;
    }

    recv_size = cmd_data->block_size;
    recv_addr = g_mspc_apdu.buffer;
    mspc_mailbox_data_copy(recv_addr, cmd_data->data, recv_size);

    cmd_data->ack = MSPC_CMD_ACK_OK;
    cmd_data->data = NULL;
    cmd_data->block_size = 0;
    cmd_data->block_index++;
    g_mspc_apdu.left_size -= recv_size;
    g_mspc_apdu.buffer_size -= recv_size;
    g_mspc_apdu.recv_size += recv_size;
    g_mspc_apdu.buffer += recv_size;

    if (g_mspc_apdu.left_size == 0) {
        /* All data have been received. */
        g_mspc_apdu.status = MSPC_CMD_ACK_OK;
        /*
         * Before wiriting g_apdu_send_flag, we need to make sure that
         * g_mspc_apdu.status has been written.
         */
        data_sync();
        g_apdu_recv_flag = MSPC_APDU_DONE;
        return MSPC_OK;
    }

    ret = mspc_send_msg(cmd_data);
    if (ret != MSPC_OK) {
        g_mspc_apdu.recv_size = 0;
        g_apdu_recv_flag = MSPC_APDU_ABORT;
        tloge("%s:send msg failed:0x%x\n", __func__, ret);
    }

    return ret;
}

int32_t mspc_receive_apdu_process(struct mspc_cmd_info *cmd_data)
{
    int32_t ret;

    g_mspc_api_info.recv_irq = 1;

    if (!cmd_data) {
        tloge("%s:Invalid param!\n", __func__);
        return MSPC_ERRCODE(INVALID_PARAM);
    }

    (void)pthread_mutex_lock(&g_apdu_work_mutex);
    if (g_apdu_recv_flag == MSPC_APDU_DOING) {
        ret = mspc_recv_work(cmd_data);
    } else {
        if (g_local_buff_flag == MSPC_LOCAL_BUFF_FREE) {
            ret = mspc_store_local_data(cmd_data);
        } else {
            tloge("%s:no buffer to recv!\n", __func__);
            ret = MSPC_ERROR;
        }
    }
    (void)pthread_mutex_unlock(&g_apdu_work_mutex);
    return ret;
}

static int32_t mspc_recv_local_data(void)
{
    int32_t ret;
    struct mspc_cmd_info cmd;

    (void)memset_s(&cmd, sizeof(cmd), 0, sizeof(cmd));

    if (g_local_buff_flag != MSPC_LOCAL_BUFF_BUSY)
        return MSPC_OK;

    if (g_mspc_apdu.buffer_size < g_local_data_size) {
        tloge("%s:recv buffer overflow!size:%u, data:%u\n",
              __func__, g_mspc_apdu.buffer_size, g_local_data_size);
        return MSPC_ERRCODE(OVERFLOW_ERR);
    }
    ret = memcpy_s(g_mspc_apdu.buffer, g_mspc_apdu.buffer_size,
                   g_local_apdu_buff, g_local_data_size);
    if (ret != EOK) {
        tloge("%s: memcpy failed!ret:%d\n", __func__, ret);
        return MSPC_ERRCODE(LIBC_COPY_ERR);
    }
    g_mspc_apdu.buffer_size -= g_local_data_size;
    g_mspc_apdu.recv_size += g_local_data_size;
    g_mspc_apdu.buffer += g_local_data_size;
    g_local_buff_flag = MSPC_LOCAL_BUFF_FREE;
    g_local_data_size = 0;

    if (g_mspc_apdu.left_size == 0) {
        /* All data have been received. */
        g_mspc_apdu.status = MSPC_CMD_ACK_OK;
        g_apdu_recv_flag = MSPC_APDU_DONE;
        return MSPC_OK;
    }

    /* Send to MSPC to get remain data. */
    cmd.cmd = MSPC_CMD_RECV_APDU;
    cmd.ack = MSPC_CMD_ACK_OK;
    cmd.data = NULL;
    cmd.block_size = 0;
    cmd.block_index++;
    ret = mspc_send_msg(&cmd);
    if (ret != MSPC_OK) {
        g_mspc_apdu.recv_size = 0;
        g_apdu_recv_flag = MSPC_APDU_ABORT;
    }

    return ret;
}

static int32_t mspc_set_recv_work(uint8_t *p_rsp, uint32_t len)
{
    int32_t ret;

    ret = mspc_wait_native_ready(MSPC_WAIT_READY_TIMEOUT);
    if (ret != MSPC_OK) {
        tloge("%s:mspc is unready!\n", __func__);
        return ret;
    }

    (void)pthread_mutex_lock(&g_apdu_work_mutex);
    g_mspc_apdu.buffer = p_rsp;
    g_mspc_apdu.buffer_size = len;
    g_mspc_apdu.recv_size = 0;
    g_mspc_apdu.status = MSPC_CMD_ACK_NULL;

    g_apdu_recv_flag = MSPC_APDU_DOING;
    ret = mspc_recv_local_data();
    (void)pthread_mutex_unlock(&g_apdu_work_mutex);
    if (ret != MSPC_OK)
        tloge("%s:recv local data failed!\n", __func__);

    return ret;
}

int32_t mspc_receive_apdu(uint8_t *p_rsp, uint32_t *rsp_len)
{
    int32_t ret;
    uint32_t volatile status;

    if (!p_rsp || !rsp_len) {
        tloge("%s: Invalid param!\n", __func__);
        return MSPC_ERRCODE(INVALID_PARAM);
    }

    (void)pthread_mutex_lock(&g_apdu_recv_mutex);
    g_mspc_api_info.recv_len = *rsp_len;
    g_mspc_api_info.recv_enter = 1;

    ret = mspc_set_recv_work(p_rsp, *rsp_len);
    if (ret != MSPC_OK) {
        tloge("%s:set work failed!\n", __func__);
        goto exit;
    }

    /* wait for all data been received done. */
    ret = mspc_wait_apdu_done(MSPC_RECV_APDU);
    if (ret != MSPC_OK)
        goto exit;

    /*
     * Before reading g_mspc_apdu.status, we need to make sure that
     * all data has been written.
     */
    data_sync();
    status = g_mspc_apdu.status;
    /* Judge whether receiveing is successful. */
    if (status != MSPC_CMD_ACK_OK) {
        ret = status;
        tloge("%s:status is 0x%x\n", __func__, status);
        goto exit;
    }

    *rsp_len = g_mspc_apdu.recv_size;
exit:
    (void)pthread_mutex_lock(&g_apdu_work_mutex);
    g_apdu_recv_flag = MSPC_APDU_DONE;
    g_local_buff_flag = MSPC_LOCAL_BUFF_FREE;
    if (ret != MSPC_OK)
        mspc_dump_api_log();
    mspc_clear_apdu_work();
    (void)pthread_mutex_unlock(&g_apdu_work_mutex);
    (void)pthread_mutex_unlock(&g_apdu_recv_mutex);
    return ret;
}

int32_t mspc_init_apdu_process(struct mspc_cmd_info *cmd_data)
{
    (void)cmd_data;

    (void)pthread_mutex_lock(&g_apdu_work_mutex);
    if (g_apdu_send_flag == MSPC_APDU_DOING) {
        g_mspc_apdu.status = MSPC_API_RESET_ERR;
        g_apdu_send_flag = MSPC_APDU_ABORT;
    }

    if (g_apdu_recv_flag == MSPC_APDU_DOING) {
        g_mspc_apdu.status = MSPC_API_RESET_ERR;
        g_apdu_recv_flag = MSPC_APDU_ABORT;
    }
    (void)pthread_mutex_unlock(&g_apdu_work_mutex);
    return MSPC_OK;
}

int32_t mspc_get_status(void)
{
    return SCARD_STATUS_RECEIVE_READY;
}

int32_t mspc_api_init(void)
{
    int32_t ret;

    ret = pthread_mutex_init(&g_apdu_connect_mutex, NULL);
    ret += pthread_mutex_init(&g_apdu_send_mutex, NULL);
    ret += pthread_mutex_init(&g_apdu_recv_mutex, NULL);
    ret += pthread_mutex_init(&g_apdu_work_mutex, NULL);
    if (ret != SRE_OK) {
        tloge("MSPC: Create apdu mutex lock failed! ret=%d\n", ret);
        return MSPC_API_MUTEX_ERR;
    }

    return MSPC_OK;
}
