/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Add the file to support extended command for MSP.
 * Create: 2019-09-09
 * History: 2019-09-09 Creat the file.
 */
#include "hisee_tpdu.h"
#include "errno.h"
#include "sre_sys.h"
#include "securec.h"
#include "se_hal.h"
#include "ipc_msg.h"
#include "pthread.h"
#include "tee_log.h"
#include "hisee_try_catch.h"
#include "hisee_err_no.h"

pthread_mutex_t g_apdu_send_lock;
#define BYTE_MASK 0xFF
#define hisee_tpdu_make_short(w1, w2) (((w1) << BIT_COUNT_PER_BYTE) | (w2))
#define TPDU_SUCCESS 0x9000
static unsigned char g_cmd_tpdu[MAX_BLOCK_SIZE_OF_EXTENDED_APDU];
static unsigned char g_cmd_cla;
static unsigned char g_response_msg[ENVELOPE_RESPONSE_LENGTH];
static unsigned int g_tpdu_response_status;
static unsigned int g_ext_tpdu_tag;

/*
 * @brief      : hisee_tpdu_construct_command: Construct tpdu command.
 * @param[in]  : block_id: the data number index.
 * @param[in]  : cmd_data: the buffer containing the data to be sent.
 * @param[in]  : state: the tag whether the command is last.
 *
 * @return     : HISEE_SUCCESS: successful
 *               HISEE_FAILURE: failed
 */
static int hisee_tpdu_construct_command(int block_id,
                                        unsigned char *cmd_data,
                                        unsigned int cmd_len,
                                        unsigned int state)
{
    int ret;

    __TRY {
        /* Set the envelope  header info */
        g_cmd_tpdu[ENVELOPE_CLA_OFFSET] = g_cmd_cla;
        g_cmd_tpdu[ENVELOPE_INS_OFFSET] = (unsigned char)ENVELOPE_INS;
        g_cmd_tpdu[ENVELOPE_P1_OFFSET] = (unsigned char)state;
        g_cmd_tpdu[ENVELOPE_P2_OFFSET] = (unsigned char)block_id;
        g_cmd_tpdu[ENVELOPE_C6_OFFSET] = (unsigned char)((cmd_len >>
            BIT_COUNT_PER_BYTE) & BYTE_MASK);
        g_cmd_tpdu[ENVELOPE_C7_OFFSET] = (unsigned char)(cmd_len & BYTE_MASK);

        /* Set the envelope data body */
        ret = memcpy_s((void *)(g_cmd_tpdu + ENVELOPE_HEAD_LENGTH),
                       sizeof(g_cmd_tpdu) - ENVELOPE_HEAD_LENGTH,
                       (void *)cmd_data, cmd_len);
        throw_if_with_para(ret != EOK, HISEE_FAILURE,
            tpdu_err_value(HISEE_TPDU_ERR, HISEE_TPDU_CONT_CMD_ERR));
        ret = HISEE_SUCCESS;
        return ret;
        }
    __CATCH {
        (void)memset_s((void *)(g_cmd_tpdu), sizeof(g_cmd_tpdu), 0,
                       sizeof(g_cmd_tpdu));
        return ERR_CODE;
    }
}

/*
 * @brief        : hisee_tpdu_wait_receive_ready:
 *                 wait for tpdu receive status ready.
 *
 * @param[in]    : timeout: the time to wait.(ms)
 *
 * @return       : HISEE_SUCCESS: receive status ready.
 *                 HISEE_FAILURE: receive status not ready.
 */
static int hisee_tpdu_wait_receive_ready(int timeout)
{
    int loopcount;

    __TRY {
        /* every loop delay 1 ms. */
        loopcount = timeout;
        while (scard_get_status() != SCARD_STATUS_RECEIVE_READY) {
            SRE_DelayMs(1);
            hm_yield();
            throw_if_with_para(loopcount <= 0, HISEE_FAILURE,
                tpdu_err_value(HISEE_TPDU_ERR, HISEE_TPDU_WAIT_READT_ERR));
            loopcount--;
        }
        return HISEE_SUCCESS;
    }
    __CATCH {
        return ERR_CODE;
    }
}

/*
 * @brief      : hisee_tpdu_abnormal_receive_data:
 *               process  tpdu response abnormal.
 *
 * @param[in]  : rsp_data: The buffer to receive data.
 * @param[in]  : rsp_len: The size of buffer and also be
 *               the size of data as output.
 *
 * @return     : HISEE_SUCCESS: receive ok.
 *               HISEE_FAILURE: receive error happen.
 */
int hisee_tpdu_abnormal_receive_data(unsigned char *rsp_data,
                                     unsigned int *rsp_len)
{
    unsigned char *data_addr = NULL;
    int ret;

    __TRY {
        ret = hisee_tpdu_check_para_and_cos_ready(rsp_data, rsp_len);
        throw_if_with_para(ret != HISEE_SUCCESS, HISEE_FAILURE,
            tpdu_err_value(HISEE_TPDU_ERR, HISEE_TPDU_ABNORMAL_RECE_ERR_A));
        g_ext_tpdu_tag = EXT_TPDU_NO_TAG;
        g_tpdu_response_status = TPDU_RESPONSE_NORMAL;

        /* get data addr & data size */
        data_addr = g_response_msg;
        throw_if_with_para(*rsp_len < (unsigned int)ENVELOPE_RESPONSE_LENGTH,
            HISEE_FAILURE, tpdu_err_value(HISEE_TPDU_ERR,
            HISEE_TPDU_ABNORMAL_RECE_ERR_B));

        ret = memcpy_s((void *)rsp_data, *rsp_len, (void *)data_addr,
            ENVELOPE_RESPONSE_LENGTH);
        throw_if_with_para(ret != EOK, HISEE_FAILURE,
            tpdu_err_value(HISEE_TPDU_ERR, HISEE_TPDU_ABNORMAL_RECE_ERR_C));
        *rsp_len = (unsigned int)ENVELOPE_RESPONSE_LENGTH;
        return HISEE_SUCCESS;
    }
    __CATCH {
        return ERR_CODE;
    }
}

/*
 * @brief      : hisee_tpdu_response_process: Process tpdu response message.
 *
 * @param[in]  : p_response_para: the buffer which save tpdu response message.
 * @param[in]  : response_len: the size of the tpdu response message.
 *
 * @return     : HISEE_SUCCESS: successful
 *               HISEE_FAILURE: failed
 */
static int hisee_tpdu_response_process(unsigned char *response_para,
                                       unsigned int response_len)
{
    int ret = HISEE_FAILURE;
    int response_sw;

    __TRY {
        /*
         * 1.If the TPDU response message length is not two, return
         * HISEE_FAILURE
         */
        throw_if_with_para(response_len != ENVELOPE_RESPONSE_LENGTH, ret,
            tpdu_err_value(HISEE_TPDU_ERR, HISEE_TPDU_RESP_PROCESS_ERR_A));
        /* 2.If the TPDU response message is 0x9000, return HISEE_SUCCESS */
        response_sw = hisee_tpdu_make_short(response_para[0], response_para[1]);
        if (response_sw == TPDU_SUCCESS) {
            ret = HISEE_SUCCESS;
        } else {
            g_tpdu_response_status = TPDU_RESPONSE_ABNORMAL;
            /*
             * 3.TPDU error status return as whole command response and
             * print in TEE log
             */
            throw_with_para(HISEE_FAILURE, tpdu_err_value(HISEE_TPDU_ERR, HISEE_TPDU_RESP_PROCESS_ERR_C));
        }
        return ret;
    }
    __CATCH {
        return ERR_CODE;
    }
}

/*
 * @brief      : hisee_tpdu_construct_and_send: construct TPDU and send.
 *
 * @param[in]  : pipe_type: the type of pipe: SE_API or
 *               INSE_ENCRYPTION or the other.
 * @param[in]  : cmd_data: the buffer to  send.
 * @param[in]  : index: the index of the data block.

 *
 * @return     : HISEE_SUCCESS: successful
 *               HISEE_FAILURE: failed
 */
static int hisee_tpdu_construct_and_send(enum se_pipe_type pipe_type,
                                         unsigned char *cmd_data,
                                         unsigned int index)
{
    int ret;
    unsigned char *cmd_data_temp = NULL;

    __TRY {
        cmd_data_temp = cmd_data + index * ENVELOPE_MAX_CDATA_SIZE;
        /* Construct tpdu command */
        ret = hisee_tpdu_construct_command(index, cmd_data_temp,
            ENVELOPE_MAX_CDATA_SIZE, ENVELOPE_P1_STATE_MORE);
        throw_if_with_para(ret != HISEE_SUCCESS, HISEE_FAILURE,
            tpdu_err_value(HISEE_TPDU_ERR, HISEE_TPDU_CONT_AND_SEND_ERR_A));
        ret = hisee_tpdu_ipc_send(pipe_type, g_cmd_tpdu,
            MAX_BLOCK_SIZE_OF_EXTENDED_APDU);
        throw_if_with_para(ret != HISEE_SUCCESS, HISEE_FAILURE,
            tpdu_err_value(HISEE_TPDU_ERR, HISEE_TPDU_CONT_AND_SEND_ERR_B));
        return HISEE_SUCCESS;
    }
    __CATCH {
        return ERR_CODE;
    }
}

/*
 * @brief      : hisee_tpdu_last: construct last TPDU and send.
 *
 * @param[in]  : pipe_type: the type of pipe: SE_API or
 *               INSE_ENCRYPTION or the other.
 * @param[in]  : cmd_data: the buffer to  send.
 * @param[in]  : cmd_size: command buffer size.
 * @param[in]  : index: the index of the data block.

 *
 * @return     : HISEE_SUCCESS: successful
 *               HISEE_FAILURE: failed
 */
static int hisee_tpdu_last(enum se_pipe_type pipe_type,
                           unsigned char *cmd_data,
                           unsigned int cmd_size,
                           unsigned int index)
{
    int ret;
    unsigned char *cmd_data_temp = NULL;

    __TRY {
        cmd_data_temp = cmd_data + index * ENVELOPE_MAX_CDATA_SIZE;
        ret = hisee_tpdu_construct_command(index, cmd_data_temp,
            cmd_size - index * ENVELOPE_MAX_CDATA_SIZE,
            ENVELOPE_P1_STATE_LAST);
        throw_if_with_para(ret != HISEE_SUCCESS, HISEE_FAILURE,
            tpdu_err_value(HISEE_TPDU_ERR, HISEE_TPDU_LAST_A));
        ret = hisee_tpdu_ipc_send(pipe_type, g_cmd_tpdu, cmd_size - index *
            ENVELOPE_MAX_CDATA_SIZE + ENVELOPE_HEAD_LENGTH);
        throw_if_with_para(ret != HISEE_SUCCESS, HISEE_FAILURE,
            tpdu_err_value(HISEE_TPDU_ERR, HISEE_TPDU_LAST_B));
        return HISEE_SUCCESS;
    }
    __CATCH {
        return ERR_CODE;
    }
}

/*
 * @brief      : hisee_tpdu_one_block: one TPDU process.
 *
 * @param[in]  : pipe_type: the type of pipe: SE_API or
 *               INSE_ENCRYPTION or the other.
 * @param[in]  : cmd_data: the buffer to  send.
 * @param[in]  : index: the index of the data block.

 *
 * @return     : HISEE_SUCCESS: successful
 *               HISEE_FAILURE: failed
 */
static int hisee_tpdu_one_block(enum se_pipe_type pipe_type,
                                unsigned char *cmd_data,
                                unsigned int index)
{
    int ret;
    unsigned int response_length = ENVELOPE_RESPONSE_LENGTH;

    __TRY {
        ret = hisee_tpdu_construct_and_send(pipe_type, cmd_data, index);
        throw_if_with_para(ret != HISEE_SUCCESS, HISEE_FAILURE,
            tpdu_err_value(HISEE_TPDU_ERR, HISEE_TPDU_ONE_BLOCK_A));
        /* Receive timeout process */
        ret = hisee_tpdu_wait_receive_ready(ENVELOPE_RECEIVE_TIMEOUT);
        throw_if_with_para(ret != HISEE_SUCCESS, HISEE_FAILURE,
            tpdu_err_value(HISEE_TPDU_ERR, HISEE_TPDU_ONE_BLOCK_B));
        /* Receive response message */
        ret = hisee_tpdu_ipc_receive(pipe_type, g_response_msg,
            &response_length);
        throw_if_with_para(ret != HISEE_SUCCESS, HISEE_FAILURE,
            tpdu_err_value(HISEE_TPDU_ERR, HISEE_TPDU_ONE_BLOCK_C));
        return HISEE_SUCCESS;
    }
    __CATCH {
        return ERR_CODE;
    }
}

/*
 * @brief      : hisee_extended_apdu_check_param: check param.
 *
 * @param[in]  : cmd_data: the buffer to  send.
 * @param[in]  : cmd_len: the size of the data to send.
 *
 * @return     : HISEE_SUCCESS: successful
 *               HISEE_FAILURE: failed
 */
static int hisee_extended_apdu_check_para(unsigned char *cmd_data,
                                          unsigned int cmd_len)
{
    int ret = HISEE_FAILURE;

    __TRY {
        throw_if_with_para(!cmd_data, ret,
            tpdu_err_value(HISEE_TPDU_ERR, HISEE_TPDU_CHECK_PARA_A));
        throw_if_with_para(cmd_len == 0 || cmd_len > MAX_EXT_COMMAND_LENGTH,
            ret, tpdu_err_value(HISEE_TPDU_ERR, HISEE_TPDU_CHECK_PARA_B));
        return HISEE_SUCCESS;
    }
    __CATCH {
        return ERR_CODE;
    }
}

/*
 * @brief      : hisee_extended_apdu_process: Called by SE_API pipe to
 *               send extended apdu data to hisee.
 *
 * @param[in]  : pipe_type: the type of pipe: SE_API or
 *               INSE_ENCRYPTION or the other.
 * @param[in]  : cmd_data: the buffer to  send.
 * @param[in]  : cmd_len: the size of the data to send.
 *
 * @return     : HISEE_SUCCESS: successful
 *               HISEE_FAILURE: failed
 */
int hisee_extended_apdu_process(enum se_pipe_type pipe_type,
                                unsigned char *cmd_data,
                                unsigned int cmd_len)
{
    int ret = HISEE_FAILURE;
    unsigned int i = 0;
    unsigned int size = cmd_len;
    unsigned int response_length = ENVELOPE_RESPONSE_LENGTH;
    unsigned int block_count;
    unsigned int extended_lock_flag = 0;

    __TRY {
        ret = hisee_extended_apdu_check_para(cmd_data, cmd_len);
        throw_if_with_para(ret != HISEE_SUCCESS, HISEE_FAILURE,
            tpdu_err_value(HISEE_TPDU_ERR, HISEE_TPDU_EXTEND_PROCESS_ERR_A));

        ret = pthread_mutex_init(&g_apdu_send_lock, NULL);
        throw_if_with_para(ret != SRE_OK, HISEE_FAILURE,
            tpdu_err_value(HISEE_TPDU_ERR, HISEE_TPDU_EXTEND_PROCESS_ERR_B));

        /* Wait for apdu semaphore mutex */
        ret = pthread_mutex_lock(&g_apdu_send_lock);
        throw_if_with_para(ret != SRE_OK, HISEE_FAILURE,
            tpdu_err_value(HISEE_TPDU_ERR, HISEE_TPDU_EXTEND_PROCESS_ERR_C));

        extended_lock_flag = TPDU_PROCESS_LOCK_IN;
        g_tpdu_response_status = TPDU_RESPONSE_NORMAL;
        g_ext_tpdu_tag = EXT_TPDU_YES_TAG;
        g_cmd_cla = cmd_data[CMD_CLA_OFFSET];
        /* 1. Calculate the remain transmit data block count block_count */
        block_count = (size % ENVELOPE_MAX_CDATA_SIZE != 0) ?
            (size / ENVELOPE_MAX_CDATA_SIZE + 1) : (size / ENVELOPE_MAX_CDATA_SIZE);
        /*
         * 2. The front block_count-1 data block's response is received in this
         * function and the last one is in scard_syscall
         */
        for (i = 0; i < block_count - 1; i++) {
            ret = hisee_tpdu_one_block(pipe_type, cmd_data, i);
            throw_if_with_para(ret != HISEE_SUCCESS, HISEE_FAILURE,
                tpdu_err_value(HISEE_TPDU_ERR, HISEE_TPDU_EXTEND_PROCESS_ERR_D));
            /*
             * 3.Judge middle TPDU response, if not 0x9000,
             * return the error status.
             */
            ret = hisee_tpdu_response_process(g_response_msg, response_length);
            /*
             * Here return HISEE_SUCCESS is intend to
             * return value as whole cmd response.
             */
            throw_if_with_para(ret != HISEE_SUCCESS, HISEE_SUCCESS,
                tpdu_err_value(HISEE_TPDU_ERR, HISEE_TPDU_EXTEND_PROCESS_ERR_E));
        }
        /* 4.Send the last data block */
        ret = hisee_tpdu_last(pipe_type, cmd_data, size, i);
        throw_if_with_para(ret != HISEE_SUCCESS, HISEE_FAILURE,
                tpdu_err_value(HISEE_TPDU_ERR, HISEE_TPDU_EXTEND_PROCESS_ERR_F));
        /* Release the apdu semaphore mutex */
        ret = pthread_mutex_unlock(&g_apdu_send_lock);
        throw_if_with_para(ret != SRE_OK, HISEE_FAILURE,
                tpdu_err_value(HISEE_TPDU_ERR, HISEE_TPDU_EXTEND_PROCESS_ERR_G));
        ret = HISEE_SUCCESS;
        return ret;
    }
    __CATCH {
        /* Release the apdu semaphore mutex */
        if(extended_lock_flag != TPDU_PROCESS_LOCK_IN)
            return ERR_CODE;
        /* If lock, just do unlock; if have unlocked fail, do retry */
        if (pthread_mutex_unlock(&g_apdu_send_lock) != SRE_OK) {
            tloge("%s:Release apdu semaphore mutex failed!\n", __func__);
        }
        return ERR_CODE;
    }
}

/*
 * @brief     : hisee_tpdu_get_response_status: get tpdu response status.
 *
 * @param[in] : void.
 *
 * @return    : tpdu response status
 */
unsigned int hisee_tpdu_get_response_status(void)
{
    return g_tpdu_response_status;
}

/*
 * @brief      : hisee_tpdu_get_ext_tag: get extended command tag.
 *
 * @param[in]  : void.
 *
 * @return     : extended command tag.
 */
unsigned int hisee_tpdu_get_ext_tag(void)
{
    return g_ext_tpdu_tag;
}

/*
 * @brief      : hisee_tpdu_get_ext_tag: get extended command tag.
 *
 * @param[in]  : extended command tag.
 *
 * @return     : void.
 */
void hisee_tpdu_set_ext_tag(unsigned int tag)
{
    g_ext_tpdu_tag = tag;
}

