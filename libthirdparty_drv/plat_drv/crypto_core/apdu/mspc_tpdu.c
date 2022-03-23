/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: Add the file to support extended command for MSP.
 * Create: 2019-09-09
 */
#include <mspc_tpdu.h>
#include <mspc_api.h>
#include <mspc_errno.h>
#include <mspc_try_catch.h>
#include <mspc_err_no.h>
#include <errno.h>
#include <sre_sys.h>
#include <securec.h>
#include <se_hal.h>
#include <pthread.h>
#include <tee_log.h>

pthread_mutex_t g_apdu_send_lock;
#define BYTE_MASK 0xFF
#define mspc_tpdu_make_short(w1, w2) (((w1) << BIT_COUNT_PER_BYTE) | (w2))
#define TPDU_SUCCESS 0x9000
static uint8_t g_cmd_tpdu[MAX_BLOCK_SIZE_OF_EXTENDED_APDU];
static uint8_t g_cmd_cla;
static uint8_t g_response_msg[ENVELOPE_RESPONSE_LENGTH];
static uint32_t g_tpdu_response_status;
static uint32_t g_ext_tpdu_tag;

/*
 * @brief      : mspc_tpdu_construct_command: Construct tpdu command.
 * @param[in]  : block_id: the data number index.
 * @param[in]  : cmd_data: the buffer containing the data to be sent.
 * @param[in]  : state: the tag whether the command is last.
 *
 * @return     : MSPC_OK: successful
 *               MSPC_ERROR: failed
 */
static int mspc_tpdu_construct_command(int block_id,
                                        uint8_t *cmd_data,
                                        uint32_t cmd_len,
                                        uint32_t state)
{
    int ret;

    __TRY {
        /* Set the envelope  header info */
        g_cmd_tpdu[ENVELOPE_CLA_OFFSET] = g_cmd_cla;
        g_cmd_tpdu[ENVELOPE_INS_OFFSET] = (uint8_t)ENVELOPE_INS;
        g_cmd_tpdu[ENVELOPE_P1_OFFSET] = (uint8_t)state;
        g_cmd_tpdu[ENVELOPE_P2_OFFSET] = (uint8_t)block_id;
        g_cmd_tpdu[ENVELOPE_C6_OFFSET] = (uint8_t)((cmd_len >>
            BIT_COUNT_PER_BYTE) & BYTE_MASK);
        g_cmd_tpdu[ENVELOPE_C7_OFFSET] = (uint8_t)(cmd_len & BYTE_MASK);

        /* Set the envelope data body */
        ret = memcpy_s((void *)(g_cmd_tpdu + ENVELOPE_HEAD_LENGTH),
                       sizeof(g_cmd_tpdu) - ENVELOPE_HEAD_LENGTH,
                       (void *)cmd_data, cmd_len);
        throw_if_with_para(ret != EOK, MSPC_ERROR,
            tpdu_err_value(MSPC_TPDU_ERR, MSPC_TPDU_CONT_CMD_ERR));
        ret = MSPC_OK;
        return ret;
        }
    __CATCH {
        (void)memset_s((void *)(g_cmd_tpdu), sizeof(g_cmd_tpdu), 0,
                       sizeof(g_cmd_tpdu));
        return ERR_CODE;
    }
}

/*
 * @brief      : mspc_tpdu_abnormal_receive_data:
 *               process  tpdu response abnormal.
 *
 * @param[in]  : rsp_data: The buffer to receive data.
 * @param[in]  : rsp_len: The size of buffer and also be
 *               the size of data as output.
 *
 * @return     : MSPC_OK: receive ok.
 *               MSPC_ERROR: receive error happen.
 */
int32_t mspc_tpdu_abnormal_receive_data(uint8_t *rsp_data,
                                     uint32_t *rsp_len)
{
    uint8_t *data_addr = NULL;
    int ret;

    __TRY {
        throw_if_with_para(!rsp_data || !rsp_len, MSPC_ERROR,
                tpdu_err_value(MSPC_TPDU_ERR, MSPC_TPDU_ABNORMAL_RECE_ERR_A));
        g_ext_tpdu_tag = EXT_TPDU_NO_TAG;
        g_tpdu_response_status = TPDU_RESPONSE_NORMAL;

        /* get data addr & data size */
        data_addr = g_response_msg;
        throw_if_with_para(*rsp_len < (uint32_t)ENVELOPE_RESPONSE_LENGTH,
            MSPC_ERROR, tpdu_err_value(MSPC_TPDU_ERR,
            MSPC_TPDU_ABNORMAL_RECE_ERR_B));

        ret = memcpy_s((void *)rsp_data, *rsp_len, (void *)data_addr,
            ENVELOPE_RESPONSE_LENGTH);
        throw_if_with_para(ret != EOK, MSPC_ERROR,
            tpdu_err_value(MSPC_TPDU_ERR, MSPC_TPDU_ABNORMAL_RECE_ERR_C));
        *rsp_len = (uint32_t)ENVELOPE_RESPONSE_LENGTH;
        return MSPC_OK;
    }
    __CATCH {
        return ERR_CODE;
    }
}

/*
 * @brief      : mspc_tpdu_receive: precevie tpdu data.
 *
 * @param[in]  : rsp_data: The buffer to receive data.
 * @param[in]  : rsp_len: The size of buffer and also be
 *               the size of data as output.
 *
 * @return     : MSPC_OK: receive ok.
 *               MSPC_ERROR: receive error happen.
 */
int32_t mspc_tpdu_receive(uint8_t *rsp_data, uint32_t *rsp_len)
{
    if (g_tpdu_response_status == TPDU_RESPONSE_ABNORMAL &&
        g_ext_tpdu_tag == EXT_TPDU_YES_TAG) {
        g_ext_tpdu_tag = EXT_TPDU_NO_TAG;
        return mspc_tpdu_abnormal_receive_data(rsp_data, rsp_len);
    } else {
        return mspc_receive_apdu(rsp_data, rsp_len);
    }
}

/*
 * @brief      : mspc_tpdu_response_process: Process tpdu response message.
 *
 * @param[in]  : p_response_para: the buffer which save tpdu response message.
 * @param[in]  : response_len: the size of the tpdu response message.
 *
 * @return     : MSPC_OK: successful
 *               MSPC_ERROR: failed
 */
static int mspc_tpdu_response_process(uint8_t *response_para,
                                       uint32_t response_len)
{
    int ret = MSPC_ERROR;
    int response_sw;

    __TRY {
        /*
         * 1.If the TPDU response message length is not two, return
         * MSPC_ERROR
         */
        throw_if_with_para(response_len != ENVELOPE_RESPONSE_LENGTH, ret,
            tpdu_err_value(MSPC_TPDU_ERR, MSPC_TPDU_RESP_PROCESS_ERR_A));
        /* 2.If the TPDU response message is 0x9000, return MSPC_OK */
        response_sw = mspc_tpdu_make_short(response_para[0], response_para[1]);
        if (response_sw == TPDU_SUCCESS) {
            ret = MSPC_OK;
        } else {
            g_tpdu_response_status = TPDU_RESPONSE_ABNORMAL;
            /*
             * 3.TPDU error status return as whole command response and
             * print in TEE log
             */
            throw_with_para(MSPC_ERROR, tpdu_err_value(MSPC_TPDU_ERR, MSPC_TPDU_RESP_PROCESS_ERR_C));
        }
        return ret;
    }
    __CATCH {
        return ERR_CODE;
    }
}

/*
 * @brief      : mspc_tpdu_construct_and_send: construct TPDU and send.
 *
 * @param[in]  : cmd_data: the buffer to  send.
 * @param[in]  : index: the index of the data block.

 *
 * @return     : MSPC_OK: successful
 *               MSPC_ERROR: failed
 */
static int32_t mspc_tpdu_construct_and_send(uint8_t *cmd_data, uint32_t index)
{
    int32_t ret;
    uint8_t *cmd_data_temp = NULL;

    __TRY {
        cmd_data_temp = cmd_data + index * ENVELOPE_MAX_CDATA_SIZE;
        /* Construct tpdu command */
        ret = mspc_tpdu_construct_command(index, cmd_data_temp,
            ENVELOPE_MAX_CDATA_SIZE, ENVELOPE_P1_STATE_MORE);
        throw_if_with_para(ret != MSPC_OK, MSPC_ERROR,
            tpdu_err_value(MSPC_TPDU_ERR, MSPC_TPDU_CONT_AND_SEND_ERR_A));
        ret = mspc_send_apdu(g_cmd_tpdu, MAX_BLOCK_SIZE_OF_EXTENDED_APDU);
        throw_if_with_para(ret != MSPC_OK, MSPC_ERROR,
            tpdu_err_value(MSPC_TPDU_ERR, MSPC_TPDU_CONT_AND_SEND_ERR_B));
        return MSPC_OK;
    }
    __CATCH {
        return ERR_CODE;
    }
}

/*
 * @brief      : mspc_tpdu_last: construct last TPDU and send.
 *
 * @param[in]  : cmd_data: the buffer to  send.
 * @param[in]  : cmd_size: command buffer size.
 * @param[in]  : index: the index of the data block.

 *
 * @return     : MSPC_OK: successful
 *               MSPC_ERROR: failed
 */
static int mspc_tpdu_last(uint8_t *cmd_data,
                          uint32_t cmd_size,
                          uint32_t index)
{
    int ret;
    uint8_t *cmd_data_temp = NULL;

    __TRY {
        cmd_data_temp = cmd_data + index * ENVELOPE_MAX_CDATA_SIZE;
        ret = mspc_tpdu_construct_command(index, cmd_data_temp,
            cmd_size - index * ENVELOPE_MAX_CDATA_SIZE,
            ENVELOPE_P1_STATE_LAST);
        throw_if_with_para(ret != MSPC_OK, MSPC_ERROR,
            tpdu_err_value(MSPC_TPDU_ERR, MSPC_TPDU_LAST_A));
        ret = mspc_send_apdu(g_cmd_tpdu, cmd_size - index *
            ENVELOPE_MAX_CDATA_SIZE + ENVELOPE_HEAD_LENGTH);
        throw_if_with_para(ret != MSPC_OK, MSPC_ERROR,
            tpdu_err_value(MSPC_TPDU_ERR, MSPC_TPDU_LAST_B));
        return MSPC_OK;
    }
    __CATCH {
        return ERR_CODE;
    }
}

/*
 * @brief      : mspc_tpdu_one_block: one TPDU process.
 *
 * @param[in]  : cmd_data: the buffer to  send.
 * @param[in]  : index: the index of the data block.

 *
 * @return     : MSPC_OK: successful
 *               MSPC_ERROR: failed
 */
static int32_t mspc_tpdu_one_block(uint8_t *cmd_data, uint32_t index)
{
    int32_t ret;
    uint32_t response_length = ENVELOPE_RESPONSE_LENGTH;

    __TRY {
        ret = mspc_tpdu_construct_and_send(cmd_data, index);
        throw_if_with_para(ret != MSPC_OK, MSPC_ERROR,
            tpdu_err_value(MSPC_TPDU_ERR, MSPC_TPDU_ONE_BLOCK_A));
        /* Receive response message */
        ret = mspc_receive_apdu(g_response_msg, &response_length);
        throw_if_with_para(ret != MSPC_OK, MSPC_ERROR,
            tpdu_err_value(MSPC_TPDU_ERR, MSPC_TPDU_ONE_BLOCK_C));
        return MSPC_OK;
    }
    __CATCH {
        return ERR_CODE;
    }
}

/*
 * @brief      : mspc_extended_apdu_check_param: check param.
 *
 * @param[in]  : cmd_data: the buffer to  send.
 * @param[in]  : cmd_len: the size of the data to send.
 *
 * @return     : MSPC_OK: successful
 *               MSPC_ERROR: failed
 */
static int32_t mspc_extended_apdu_check_para(uint8_t *cmd_data, uint32_t cmd_len)
{
    int ret = MSPC_ERROR;

    __TRY {
        throw_if_with_para(!cmd_data, ret,
            tpdu_err_value(MSPC_TPDU_ERR, MSPC_TPDU_CHECK_PARA_A));
        throw_if_with_para(cmd_len == 0 || cmd_len > MAX_EXT_COMMAND_LENGTH,
            ret, tpdu_err_value(MSPC_TPDU_ERR, MSPC_TPDU_CHECK_PARA_B));
        return MSPC_OK;
    }
    __CATCH {
        return ERR_CODE;
    }
}

/*
 * @brief      : mspc_extended_apdu_process: Called by SE_API pipe to
 *               send extended apdu data to mspc.
 *
 * @param[in]  : cmd_data: the buffer to  send.
 * @param[in]  : cmd_len: the size of the data to send.
 *
 * @return     : MSPC_OK: successful
 *               MSPC_ERROR: failed
 */
int32_t mspc_extended_apdu_process(uint8_t *cmd_data, uint32_t cmd_len)
{
    int ret = MSPC_ERROR;
    uint32_t i = 0;
    uint32_t size = cmd_len;
    uint32_t response_length = ENVELOPE_RESPONSE_LENGTH;
    uint32_t block_count;
    uint32_t extended_lock_flag = 0;

    __TRY {
        g_ext_tpdu_tag = EXT_TPDU_NO_TAG;
        if (cmd_len <= MAX_NORMAL_COMMAND_LENGTH)
            return mspc_send_apdu(cmd_data, cmd_len);
        ret = mspc_extended_apdu_check_para(cmd_data, cmd_len);
        throw_if_with_para(ret != MSPC_OK, MSPC_ERROR,
            tpdu_err_value(MSPC_TPDU_ERR, MSPC_TPDU_EXTEND_PROCESS_ERR_A));

        ret = pthread_mutex_init(&g_apdu_send_lock, NULL);
        throw_if_with_para(ret != SRE_OK, MSPC_ERROR,
            tpdu_err_value(MSPC_TPDU_ERR, MSPC_TPDU_EXTEND_PROCESS_ERR_B));

        /* Wait for apdu semaphore mutex */
        ret = pthread_mutex_lock(&g_apdu_send_lock);
        throw_if_with_para(ret != SRE_OK, MSPC_ERROR,
            tpdu_err_value(MSPC_TPDU_ERR, MSPC_TPDU_EXTEND_PROCESS_ERR_C));

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
            ret = mspc_tpdu_one_block(cmd_data, i);
            throw_if_with_para(ret != MSPC_OK, MSPC_ERROR,
                tpdu_err_value(MSPC_TPDU_ERR, MSPC_TPDU_EXTEND_PROCESS_ERR_D));
            /*
             * 3.Judge middle TPDU response, if not 0x9000,
             * return the error status.
             */
            ret = mspc_tpdu_response_process(g_response_msg, response_length);
            /*
             * Here return MSPC_OK is intend to
             * return value as whole cmd response.
             */
            throw_if_with_para(ret != MSPC_OK, MSPC_OK,
                tpdu_err_value(MSPC_TPDU_ERR, MSPC_TPDU_EXTEND_PROCESS_ERR_E));
        }
        /* 4.Send the last data block */
        ret = mspc_tpdu_last(cmd_data, size, i);
        throw_if_with_para(ret != MSPC_OK, MSPC_ERROR,
                tpdu_err_value(MSPC_TPDU_ERR, MSPC_TPDU_EXTEND_PROCESS_ERR_F));
        /* Release the apdu semaphore mutex */
        ret = pthread_mutex_unlock(&g_apdu_send_lock);
        throw_if_with_para(ret != SRE_OK, MSPC_ERROR,
                tpdu_err_value(MSPC_TPDU_ERR, MSPC_TPDU_EXTEND_PROCESS_ERR_G));
        ret = MSPC_OK;
        return ret;
    }
    __CATCH {
        /* Release the apdu semaphore mutex */
        if(extended_lock_flag != TPDU_PROCESS_LOCK_IN)
            return ERR_CODE;
        /* If lock, just do unlock; if have unlocked fail, do retry */
        if (pthread_mutex_unlock(&g_apdu_send_lock) != SRE_OK)
            tloge("%s:Release apdu semaphore mutex failed!\n", __func__);
        return ERR_CODE;
    }
}

