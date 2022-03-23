/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Implementation of the private GP SCP03 functions
 *              for secure flash communication.
 * Author: aaron.shen
 * Create: 2019/08/20
 */

#include "secflash_scp03_comm.h"
#include "secflash_scp03_calc.h"
#include "secureflash_interface.h"
#include "sre_syscalls_ext.h"
#include "tee_log.h"
#include "tee_crypto_api.h"
#include <sre_syscall.h>
#include <securec.h>
#include "ccmgr_ops_ext.h"

uint32_t g_batch_id;
uint16_t g_vendor_id;
uint8_t g_sec_level;
uint8_t g_secflash_init_status;
uint8_t g_mac_chaining[SECFLASH_CMAC_TOTAL_LENGTH];
uint8_t g_encrypt_iv[SECFLASH_IV_BYTE_LEN];

struct scp_challenge g_secflash_challenge;
struct sec_counter g_secflash_count;
struct secflash_keyset g_binding_key;
struct session_sec_channel_key g_session_key;

/*
 * @brief     : get batch ID value
 * @param[in] : NA.
 * @return    : g_batch_id.
 */
uint32_t secflash_get_batch_id(void)
{
    return g_batch_id;
}

/*
 * @brief     : the process called by the APIs to check the ERR count
 * @param[in] : status, SECFLASH_SUCCESS or others
 * @return    : NA.
 */
static void secflash_error_process(uint32_t status)
{
    if (status == SECFLASH_SUCCESS) {
        g_secflash_count.right_count++;
        /* if the right count accumulate to max, err count can clear */
        if (g_secflash_count.right_count >= MAX_RIGHT_COUNTER) {
            g_secflash_count.error_count = 0;
            g_secflash_count.right_count = MAX_RIGHT_COUNTER;
        }
    } else {
        g_secflash_count.error_count++;
        /* once we got the err,clear the right count */
        g_secflash_count.right_count = 0;
        if (g_secflash_count.error_count >= MAX_ERR_COUNTER) {
            tloge("%s, error count Max\n", __func__);
            g_secflash_init_status = SECFLASH_COUNT_ERR;
            g_secflash_count.error_count = MAX_ERR_COUNTER;
        }
    }
}

/*
 * @brief     : the base response check called by the APIs
 *              to check the response length and sw.
 * @param[in] : response_apdu, the pointer of response apdu to be check
 *              response_length, the apdu length,
 *              expect_value, the response cmd length, block_index
 *                            block_count and rmac to be checked.
 * @return    : SECFLASH_SUCCESS or others
 */
static uint32_t secflash_response_check(const uint8_t *response_apdu, uint32_t response_length,
    struct check_info expect_value)
{
    uint16_t sw;

    if (!response_apdu) {
        tloge("%s, Err response_apdu NULL\n", __func__);
        return SECFLASH_FAILURE | POINTER_NULL;
    }

    if (response_length < GP_SW_LENGTH) { /* '2' sw length */
        tloge("%s, Err response length\n", __func__);
        return SECFLASH_FAILURE | RESPONSE_LENGTH_ERR;
    }

    sw = (response_apdu[response_length - GP_SW_LENGTH] << ONE_BYTE_BITS_OFFSET) + response_apdu[response_length - 1];
    if (sw != GP_SUCCESS_SW) { /* SUCCESS: 9000 */
        tloge("%s, Err sw:%x\n", __func__, sw);
        if (sw == GP_TDS_SW)
            (void)secflash_reset(0); /* soft reset once receiving 69FF status words */
        return SECFLASH_FAILURE | sw;
    }

    if (response_length != expect_value.response_length) {
        tloge("%s, Err length:%x\n", __func__, response_length);
        return SECFLASH_FAILURE | RESPONSE_LENGTH_ERR;
    }

    return SECFLASH_SUCCESS;
}

/*
 * @brief     : the cmd response process called by the APIs
 *              to check the response info.
 * @param[in] : response_apdu, the pointer of response apdu to be check
 *              response_length, the apdu length,
 *              expect_value, the response cmd length, block_index
 *                           block_count and rmac to be checked.
 * @return    : SECFLASH_SUCCESS or others
 */
static uint32_t secflash_response_process(uint8_t *response_apdu, uint32_t response_length,
    struct check_info expect_value)
{
    uint32_t status;

    status = secflash_response_check(&response_apdu[0], response_length, expect_value);
    if (status != SECFLASH_SUCCESS)
        return status;

    /* external auth response has no other value need to be check */
    if (expect_value.ins == GP_INS_EXTERNAL_AUTHENTICATE)
        return SECFLASH_SUCCESS;

    if (expect_value.ins == GP_INS_INITIALIZE_UPDATE) {
        g_vendor_id = (response_apdu[0] << ONE_BYTE_BITS_OFFSET) + response_apdu[1];
        /* batch id offset is 2 */
        g_batch_id = response_apdu[SECFLASH_VENDOR_ID];
        /* offset '10': KVN; '11': PVN; '12': i */
        if (response_apdu[SECFLASH_INFORMATION_LEN] != SECFLASH_KVN_BINDING_KEY ||
            response_apdu[SECFLASH_INFORMATION_LEN + ONE_BYTES_OFFSET] != SECFLASH_PROTOCOL_VERSION_NUMBER ||
            response_apdu[SECFLASH_INFORMATION_LEN + TWO_BYTES_OFFSET] != SECFLASH_I_PARAMETER) {
            tloge("%s, Err kvn:%x PVN:%x i:%x\n", __func__, response_apdu[SECFLASH_INFORMATION_LEN],
                  response_apdu[SECFLASH_INFORMATION_LEN + ONE_BYTES_OFFSET],
                  response_apdu[SECFLASH_INFORMATION_LEN + TWO_BYTES_OFFSET]);
            return SECFLASH_FAILURE | RESPONSE_KEY_INFO_ERR;
        }
        /* initialize update response has no other value need to be check */
        return SECFLASH_SUCCESS;
    }

    status = secflash_verify_rmac(&response_apdu[0], response_length, &g_mac_chaining[0], &g_session_key.srmac[0]);
    if (status != SECFLASH_SUCCESS) {
        tloge("%s, Err:%x\n", __func__, status);
        return status;
    }

    if (expect_value.ins == GP_INS_WRITE_DATA || expect_value.ins == GP_INS_READ_DATA ||
        expect_value.ins == GP_INS_ERASE_BLOCK) {
        if ((uint32_t)((response_apdu[0] << ONE_BYTE_BITS_OFFSET) + response_apdu[ONE_BYTES_OFFSET]) !=
                                                                                            expect_value.block_index ||
            ((uint32_t)((response_apdu[TWO_BYTES_OFFSET] << ONE_BYTE_BITS_OFFSET) +
                          response_apdu[THREE_BYTES_OFFSET])) != expect_value.block_count) {
            status = SECFLASH_FAILURE | BLOCK_VERIFY_ERR;
            tloge("%s, Err index:%x count:%x\n", __func__,
                  expect_value.block_index, expect_value.block_count);
        }
    }

    return status;
}

/*
 * @brief      : the initialize_update cmd derivate before send to secflash.
 * @param[in]  : apdu, the pointer of apdu buffer.
 *               len, the length of apdu buffer.
 * @return     : success of failure
 */
static uint32_t secflash_initialize_update_cmd_derivate(uint8_t *apdu, uint32_t len)
{
    uint32_t status;

    /* initialize update cmd */
    apdu[CLA] = GP_CLA_COMMAND;
    apdu[INS] = GP_INS_INITIALIZE_UPDATE;
    apdu[P1] = SECFLASH_KVN_BINDING_KEY;
    apdu[P2] = 0x0;
    apdu[LC] = SECFLASH_CHALLENGE_LENGTH;

    status = memcpy_s(&apdu[CDATA], len - CDATA, &g_secflash_challenge.host_challenge[0], SECFLASH_CHALLENGE_LENGTH);
    if (status != EOK)
        return SECFLASH_FAILURE | MEMCPY_ERR;

    /* Le */
    apdu[CDATA + SECFLASH_CHALLENGE_LENGTH] = 0x0;

    return SECFLASH_SUCCESS;
}

/*
 * @brief     : security channel initialize update and response process.
 * @param[in] : NA.
 * @return    : success of failure
 */
static uint32_t secflash_initialize_update(void)
{
    uint8_t apdu[SECFLASH_INITIALIZE_UPDATE_CMD_LEN] = {0};
    uint8_t response_apdu[SECFLASH_INITIALIZE_UPDATE_RESP_LEN] = {0};
    uint32_t response_length = SECFLASH_INITIALIZE_UPDATE_RESP_LEN;
    struct check_info expect_value;
    int32_t ret;
    uint32_t status;

    if (g_secflash_init_status == SECFLASH_COUNT_ERR) {
        tloge("%s, Err InitStatus\n", __func__);
        return SECFLASH_FAILURE | ERROR_COUNT_ERR;
    }

    status = secflash_initialize_update_cmd_derivate(&apdu[0], SECFLASH_INITIALIZE_UPDATE_CMD_LEN);
    if (status != SECFLASH_SUCCESS) {
        tloge("%s, Err init updata derivate:%x\n", __func__, status);
        return status;
    }

#if SECFLASH_DEBUG
    dump_data("initialize_update cmd data", &apdu[0], SECFLASH_INITIALIZE_UPDATE_CMD_LEN);
#endif

    /* send cmd and get response */
    ret = __scard_transmit(SECFLASH_SCARD_TRANS_ID, &apdu[0], SECFLASH_INITIALIZE_UPDATE_CMD_LEN,
                           &response_apdu[0], &response_length);
    if (ret) {
        tloge("%s, Err Transmit:%x\n", __func__, ret);
        return SECFLASH_FAILURE | ((uint32_t)ret & 0xffff);
    }

#if SECFLASH_DEBUG
    dump_data("initialize_update resp data", &response_apdu[0], response_length);
#endif

    (void)memset_s(&expect_value, sizeof(struct check_info), 0, sizeof(struct check_info));
    expect_value.ins = GP_INS_INITIALIZE_UPDATE;
    expect_value.response_length = SECFLASH_INITIALIZE_UPDATE_RESP_LEN;
    expect_value.kvn = SECFLASH_KVN_BINDING_KEY;
    status = secflash_response_process(&response_apdu[0], response_length, expect_value);
    if (status != SECFLASH_SUCCESS) {
        tloge("%s, Err initial update resp Process:%x\n", __func__, status);
        return status;
    }

    ret = memcpy_s(&g_secflash_challenge.card_challenge[0], SECFLASH_CHALLENGE_LENGTH,
                      &response_apdu[SECFLASH_INFORMATION_LEN + SECFLASH_KEY_INFORMATION_LEN],
                      SECFLASH_CHALLENGE_LENGTH);
    ret += memcpy_s(&g_secflash_challenge.card_cryptogram[0], SECFLASH_CHALLENGE_LENGTH,
                       &response_apdu[SECFLASH_INFORMATION_LEN + SECFLASH_KEY_INFORMATION_LEN +
                       SECFLASH_CHALLENGE_LENGTH], SECFLASH_CHALLENGE_LENGTH);
    if (ret != EOK)
        return SECFLASH_FAILURE | MEMCPY_ERR;

    return SECFLASH_SUCCESS;
}

/*
 * @brief      : the write cmd derivate before send to secflash.
 * @param[in]  : apdu, the pointer of apdu buffer.
 *               len, the length of apdu buffer.
 * @return     : success of failure
 */
static uint32_t secflash_external_auth_cmd_derivate(uint8_t *apdu, uint32_t len)
{
    struct data_info mac_chaining_data;
    uint32_t status;

    /* external authenticate cmd */
    apdu[CLA] = GP_CLA_COMMAND_SECURE_MESSAGING;
    apdu[INS] = GP_INS_EXTERNAL_AUTHENTICATE;
    /* P1: set security level */
    apdu[P1] = GP_SECURITY_LEVEL;
    g_sec_level = GP_SECURITY_LEVEL;
    apdu[P2] = 0x0;
    apdu[LC] = SECFLASH_CRYPTOGRAM_LENGTH; /* include length of C-MAC */
    status = memcpy_s(&apdu[CDATA], len - CDATA, &g_secflash_challenge.host_cryptogram[0], SECFLASH_CHALLENGE_LENGTH);
    if (status != EOK)
        return SECFLASH_FAILURE | MEMCPY_ERR;

    /* calculate the MAC value */
    mac_chaining_data.data = &g_mac_chaining[0];
    mac_chaining_data.data_length = SECFLASH_CMAC_TOTAL_LENGTH;
    status = secflash_calculate_cmac(&apdu[0], SECFLASH_CHALLENGE_LENGTH, 0, mac_chaining_data, &g_session_key.smac[0]);
    if (status != SECFLASH_SUCCESS) {
        tloge("%s, Err external auth calc cmac:%X\n", __func__, status);
        return status;
    }

    status = memcpy_s(&apdu[CDATA + SECFLASH_CHALLENGE_LENGTH], len - (CDATA + SECFLASH_CHALLENGE_LENGTH),
                      &g_mac_chaining[0], SECFLASH_CMAC_LENGTH);
    if (status != EOK)
        return SECFLASH_FAILURE | MEMCPY_ERR;

    return SECFLASH_SUCCESS;
}

/*
 * @brief     : security channel external_authenticate and response process.
 * @param[in] : NA.
 * @return    : success of failure
 */
static uint32_t secflash_external_authenticate(void)
{
    uint8_t apdu[SECFLASH_EXTERNAL_AUTHENTICATE_CMD_LEN] = {0};
    uint8_t response_apdu[SECFLASH_EXTERNAL_AUTHENTICATE_RESP_LEN] = {0};
    uint32_t response_length = SECFLASH_EXTERNAL_AUTHENTICATE_RESP_LEN;
    struct check_info expect_value;
    int ret;
    uint32_t status;

    if (g_secflash_init_status == SECFLASH_COUNT_ERR) {
        tloge("%s, Err InitStatus\n", __func__);
        return SECFLASH_FAILURE | ERROR_COUNT_ERR;
    }

    status = secflash_external_auth_cmd_derivate(&apdu[0], SECFLASH_EXTERNAL_AUTHENTICATE_CMD_LEN);
    if (status != SECFLASH_SUCCESS) {
        tloge("%s, Err external auth derivate:%x\n", __func__, status);
        return status;
    }

#if SECFLASH_DEBUG
    dump_data("External_authenticate cmd data", &apdu[0], SECFLASH_EXTERNAL_AUTHENTICATE_CMD_LEN);
#endif

    /* send cmd and get response */
    ret = __scard_transmit(SECFLASH_SCARD_TRANS_ID, &apdu[0], SECFLASH_EXTERNAL_AUTHENTICATE_CMD_LEN,
                           &response_apdu[0], &response_length);
    if (ret) {
        tloge("%s, Err Transmit:%x\n", __func__, ret);
        return SECFLASH_FAILURE | ((uint32_t)ret & 0xffff);
    }

#if SECFLASH_DEBUG
    dump_data("External_authenticate resp data", &response_apdu[0], response_length);
#endif

    (void)memset_s(&expect_value, sizeof(struct check_info), 0, sizeof(struct check_info));
    expect_value.ins = GP_INS_EXTERNAL_AUTHENTICATE;
    expect_value.response_length = SECFLASH_EXTERNAL_AUTHENTICATE_RESP_LEN;
    status = secflash_response_process(&response_apdu[0], response_length, expect_value);
    if (status != SECFLASH_SUCCESS) {
        tloge("%s, Err external auth resp Process:%x\n", __func__, status);
        return status;
    }

    g_secflash_count.encryption_count = 1;

    return SECFLASH_SUCCESS;
}

/*
 * @brief     : check the security channel can be used or not.
 * @param[in] : NA.
 * @param[out]: NA.
 * @return    : success of failure
 */
static uint32_t secflash_channel_status_check(void)
{
    if (g_secflash_init_status == SECFLASH_INIT_START)
        return SECFLASH_FAILURE | CHANNEL_STATUS_ERR;
    else if (g_secflash_init_status == SECFLASH_COUNT_ERR)
        return SECFLASH_FAILURE | ERROR_COUNT_ERR;
    else
        return SECFLASH_SUCCESS;
}

/*
 * @brief     : build and authenticate security channel, include
 *              initialize update and external authenticate.
 * @param[in] : NA.
 * @return    : success of failure
 */
static uint32_t secflash_authenticate_channel(void)
{
    uint32_t status;

    /* get host challenge */
    (void)__CC_CRYS_RND_GenerateVector(SECFLASH_CHALLENGE_LENGTH, &g_secflash_challenge.host_challenge[0]);

#if SECFLASH_DEBUG
    dump_data("host challenge", &g_secflash_challenge.host_challenge[0], SECFLASH_CHALLENGE_LENGTH);
#endif

    /* initialize update and response process */
    status = secflash_initialize_update();
    if (status != SECFLASH_SUCCESS) {
        tloge("%s, Err initialize_update:%x\n", __func__, status);
        goto error_process;
    }

    /* get key */
    status = secflash_derive_binding_key(SECFLASH_KVN_BINDING_KEY, g_batch_id, &g_binding_key);
    if (status != SECFLASH_SUCCESS) {
        tloge("%s, Err get_key:%x\n", __func__, status);
        goto error_process;
    }

    /* calculate session keys through g_initial/binding_key */
    status = secflash_generate_session_keys(&g_binding_key, &g_secflash_challenge.host_challenge[0],
                                            &g_secflash_challenge.card_challenge[0], &g_session_key);
    if (status != SECFLASH_SUCCESS) {
        tloge("%s, Err genSessionKey:%x\n", __func__, status);
        goto error_process;
    }

    /* verify card cryptogram through g_session_key */
    status = secflash_verify_card_cryptogram(&g_secflash_challenge, &g_session_key.smac[0]);
    if (status != SECFLASH_SUCCESS) {
        tloge("%s, Err verifyCard:%x\n", __func__, status);
        goto error_process;
    }

    /* calculate host cryptogram through g_session_key */
    status = secflash_calculate_host_cryptogram(&g_secflash_challenge, &g_session_key.smac[0]);
    if (status != SECFLASH_SUCCESS) {
        tloge("%s, Err calcHost:%x\n", __func__, status);
        goto error_process;
    }

    (void)memset_s(&g_mac_chaining[0], SECFLASH_CMAC_TOTAL_LENGTH, 0, SECFLASH_CMAC_TOTAL_LENGTH);

    /* external authenticate and response process */
    status = secflash_external_authenticate();
    if (status != SECFLASH_SUCCESS) {
        tloge("%s, Err external_auth:%x\n", __func__, status);
        goto error_process;
    }

    g_secflash_init_status = SECFLASH_INIT_FINISHED;

error_process:
    (void)memset_s(&g_binding_key, sizeof(struct secflash_keyset), 0, sizeof(struct secflash_keyset));
    /* err or right process */
    secflash_error_process(status);
    return status;
}

/*
 * @brief      : check the write cmd block count ir right or not.
 * @param[in]  : block_count, the block count of data to be write
 * @return     : success of failure
 */
static uint32_t secflash_write_count_check(uint32_t block_count)
{
    if (block_count > MAX_WRITE_BLOCKS_COUNT || block_count == 0)
        return SECFLASH_FAILURE | BLOCK_COUNT_OVER;
    else
        return SECFLASH_SUCCESS;
}

/*
 * @brief      : the write/read/erase cmd info(pointer/index/count) check.
 * @param[in]  : block_index, the block id of data to be write
 *               block_count, the block count of data to be write
 *               buffer, the pointer of write/read data
 *               buffer_max_length, the max length of the buffer
 *               ins, the cmd ins.
 * @return     : success of failure
 */
static uint32_t secflash_cmd_info_check(uint32_t block_count, const uint8_t *buffer,
    uint32_t buffer_max_length, uint8_t ins)
{
    uint32_t read_length;
    uint32_t response_length;
    uint32_t status;

    status = secflash_channel_status_check();
    if (status != SECFLASH_SUCCESS) {
        tloge("%s, status:%x Err InitStatus:%x\n", __func__, status, g_secflash_init_status);
        return status;
    }

    switch (ins) {
    case GP_INS_WRITE_DATA:
        if (!buffer) {
            tloge("%s, Err write Buffer NULL\n", __func__);
            return SECFLASH_FAILURE | POINTER_NULL;
        }
        status = secflash_write_count_check(block_count);
        if (status != SECFLASH_SUCCESS) {
            tloge("%s, Err write blockCount:%x\n", __func__, block_count);
            return status;
        }
        break;
    case GP_INS_READ_DATA:
        if (!buffer) {
            tloge("%s, Err read Buffer NULL\n", __func__);
            return SECFLASH_FAILURE | POINTER_NULL;
        }
        /*
         * '4'-Response Data: 2bytes block index & 2bytes block count
         * '2'-SW
         */
        read_length = SECFLASH_BLOCK_BYTE_LEN * block_count;
        response_length = SECFLASH_READ_BLOCK_RESP_DATA_OFFSET + read_length + SECFLASH_CMAC_LENGTH + GP_SW_LENGTH;
        if ((block_count > MAX_WRITE_BLOCKS_COUNT && block_count != MAX_READ_BLOCKS_COUNT) ||  block_count == 0 ||
            read_length > buffer_max_length || response_length > SECFLASH_READ_BLOCK_RESP_LEN) {
            tloge("%s, Err read length:%x\n", __func__, read_length);
            return SECFLASH_FAILURE | BLOCK_COUNT_OVER;
        }
        break;
    case GP_INS_ERASE_BLOCK:
        /* only support 1page=1k erase */
        if (block_count % PAGE_BLOCKS_COUNT != 0) {
            tloge("%s, Err erase block count:%x\n", __func__, block_count);
            return SECFLASH_FAILURE | BLOCK_COUNT_NOT_PAGE;
        }
        break;
    default:
        tloge("%s, Err cmd ins:%x\n", __func__, ins);
        return SECFLASH_FAILURE | INS_ERR;
    }

    return SECFLASH_SUCCESS;
}

/*
 * @brief      : the derivated write cmd encrypt and calc cmac.
 * @param[in]  : info, the cmd info used for derivation.
 *               data_length, the data length.
 *               extended_length, the data is extended or not.
 * @return     : success of failure
 */
static uint32_t secflash_write_cmd_process(struct cmd_derivate_info *info, uint32_t data_length,
    uint8_t extended_length)
{
    struct data_info mac_chaining_data;
    uint32_t ret;
    uint32_t status;

       /* encrypt the data */
    status = secflash_encrypt_sensitive_data(info, g_encrypt_iv);
    if (status != SECFLASH_SUCCESS)
        return status;

    mac_chaining_data.data = &g_mac_chaining[0];
    mac_chaining_data.data_length = SECFLASH_CMAC_TOTAL_LENGTH;
    status = secflash_calculate_cmac(&info->cmd[0], data_length + SECFLASH_WRITE_COUNT_LEN, extended_length,
                                     mac_chaining_data, &g_session_key.smac[0]);
    if (status != SECFLASH_SUCCESS) {
        tloge("%s, Err write calc cmac:%x\n", __func__, status);
        return status;
    }
    ret = memcpy_s(&info->cmd[CDATA + extended_length * GP_ADD_EXTENDED_LENGTH + SECFLASH_WRITE_COUNT_LEN +
                              data_length], info->cmd_length - (CDATA + extended_length * GP_ADD_EXTENDED_LENGTH +
                                                                SECFLASH_WRITE_COUNT_LEN + data_length),
                   &g_mac_chaining[0], SECFLASH_CMAC_LENGTH);
    if (ret != EOK) {
        tloge("%s, memcpy failed:%x\n", __func__, data_length);
        return SECFLASH_FAILURE | MEMCPY_ERR;
    }

    return SECFLASH_SUCCESS;
}

/*
 * @brief      : the write cmd derivate before send to secflash.
 * @param[in]  : info, the cmd info used for derivation.
 * @return     : success of failure
 */
static uint32_t secflash_write_cmd_derivate(struct cmd_derivate_info *info)
{
    uint32_t data_length;
    uint8_t extended_length = 0;
    uint32_t lc;
    uint32_t status;

    /* check the moduleid and get the phy block index */
    status = secflash_get_phys_addr(info->module_id, info->block_index, info->block_count, &info->phy_block_index);
    if (status != SECFLASH_SUCCESS)
        return status;

    data_length = SECFLASH_BLOCK_BYTE_LEN * info->block_count;
    lc = SECFLASH_WRITE_COUNT_LEN + data_length + SECFLASH_CMAC_LENGTH;
    if (lc > 0xff)
        extended_length = 1; /* extended length */

    /* CLA~P2 + Lc + Data + MAC */
    info->cmd[CLA] = GP_CLA_COMMAND_SECURE_MESSAGING;
    info->cmd[INS] = GP_INS_WRITE_DATA;
    info->cmd[P1] = (uint8_t)(info->phy_block_index >> ONE_BYTE_BITS_OFFSET);
    info->cmd[P2] = (uint8_t)(info->phy_block_index & 0xff);
    if (extended_length == 0) {
        info->cmd[LC] = lc;
    } else {
        info->cmd[LC] = 0;
        info->cmd[LC + ONE_BYTES_OFFSET] = (uint8_t)(lc >> ONE_BYTE_BITS_OFFSET);
        info->cmd[LC + TWO_BYTES_OFFSET] = (uint8_t)(lc & 0xff);
    }

    info->cmd[CDATA + extended_length * GP_ADD_EXTENDED_LENGTH] = (uint8_t)(info->block_count >> ONE_BYTE_BITS_OFFSET);
    info->cmd[CDATA + extended_length * GP_ADD_EXTENDED_LENGTH + ONE_BYTES_OFFSET] =
                                                                                    (uint8_t)(info->block_count & 0xff);
    info->data_out = &info->cmd[CDATA + extended_length * GP_ADD_EXTENDED_LENGTH + SECFLASH_WRITE_COUNT_LEN];
    info->max_data_buf = info->cmd_length -
                         (CDATA + extended_length * GP_ADD_EXTENDED_LENGTH + SECFLASH_WRITE_COUNT_LEN);

    /* write cmd process */
    status = secflash_write_cmd_process(info, data_length, extended_length);
    if (status != SECFLASH_SUCCESS)
        return status;

    /* refresh cmd length */
    info->cmd_length = CDATA + extended_length * GP_ADD_EXTENDED_LENGTH + SECFLASH_WRITE_COUNT_LEN +
                       data_length + SECFLASH_CMAC_LENGTH;
    return status;
}

/*
 * @brief      : write data(blocks) to security flash
 * @param[in]  : moduld_id, the ID of partition
 *               block_index, the block id of data to be write
 *               block_count, the block count of data to be write
 *               write_buffer, the pointer of write data
 * @return     : success of failure
 */
uint32_t secflash_write_blocks(uint32_t module_id, uint32_t block_index, uint32_t block_count,
    uint8_t *write_buffer)
{
    uint8_t cmd[SECFLASH_WRITE_BLOCK_CMD_LEN] = {0};
    uint8_t response_apdu[SECFLASH_WRITE_BLOCK_RESP_LEN] = {0};
    uint32_t response_length = SECFLASH_WRITE_BLOCK_RESP_LEN;
    struct cmd_derivate_info info = {0};
    struct check_info expect_value;
    int ret;
    uint32_t status;

    status = secflash_cmd_info_check(block_count, write_buffer, 0, GP_INS_WRITE_DATA);
    if (status != SECFLASH_SUCCESS)
        goto error_process;

    info.module_id = module_id;
    info.block_index = block_index;
    info.block_count = block_count;
    info.cmd = &cmd[0];
    info.cmd_length = SECFLASH_WRITE_BLOCK_CMD_LEN;
    info.data = write_buffer;
    status = secflash_write_cmd_derivate(&info);
    if (status != SECFLASH_SUCCESS)
        goto error_process;

#if SECFLASH_DEBUG
    dump_data("Write_blocks cmd data", &cmd[0], info.cmd_length);
#endif
    /* send cmd and get response */
    ret = __scard_transmit(SECFLASH_SCARD_TRANS_ID, &cmd[0], info.cmd_length, &response_apdu[0], &response_length);
    if (ret) {
        tloge("%s, Err Transmit:%x\n", __func__, ret);
        status = SECFLASH_FAILURE | ((uint32_t)ret & 0xffff);
        goto error_process;
    }

#if SECFLASH_DEBUG
    dump_data("Write_blocks resp data", &response_apdu[0], response_length);
#endif

    (void)memset_s(&expect_value, sizeof(struct check_info), 0, sizeof(struct check_info));
    expect_value.ins = GP_INS_WRITE_DATA;
    expect_value.response_length = SECFLASH_WRITE_BLOCK_RESP_LEN;
    expect_value.block_count = block_count;
    expect_value.block_index = info.phy_block_index;
    status = secflash_response_process(&response_apdu[0], response_length, expect_value);
    if (status != SECFLASH_SUCCESS)
        tloge("%s, Err Write resp Process:%x\n", __func__, status);

error_process:
    /* err or right process */
    secflash_error_process(status);
    return status;
}

/*
 * @brief      : the read cmd derivate before send to secflash.
 * @param[in]  : info, the cmd info used for derivation.
 * @return     : success of failure
 */
static uint32_t secflash_read_cmd_derivate(struct cmd_derivate_info *info)
{
    struct data_info mac_chaining_data;
    uint8_t extended_length = 0;
    uint32_t ret;
    uint32_t status;

    /* check the moduleid and get the phy block index */
    status = secflash_get_phys_addr(info->module_id, info->block_index, info->block_count, &info->phy_block_index);
    if (status != SECFLASH_SUCCESS) {
        tloge("%s, Err read cmd get addr:%x\n", __func__, status);
        return status;
    }

    info->cmd[CLA]  = GP_CLA_COMMAND_SECURE_MESSAGING;
    info->cmd[INS]  = GP_INS_READ_DATA;
    info->cmd[P1] = (uint8_t)(info->phy_block_index >> ONE_BYTE_BITS_OFFSET);
    info->cmd[P2] = (uint8_t)(info->phy_block_index & 0xff);
    /* NXP chip LC uses CASE4E format once read data length is bigger than 256bytes(16&256 blocks) */
    if (g_vendor_id == SECFLASH_FACTORY_NXP_VENDOR_ID && info->block_count >= MAX_WRITE_BLOCKS_COUNT) {
        info->cmd[LC] = 0;
        info->cmd[LC + ONE_BYTES_OFFSET] = 0;
        info->cmd[LC + TWO_BYTES_OFFSET] = SECFLASH_READ_CMD_DATA_FIELD_LEN + SECFLASH_CMAC_LENGTH;
        extended_length = 1;
    } else {
        info->cmd[LC] = SECFLASH_READ_CMD_DATA_FIELD_LEN + SECFLASH_CMAC_LENGTH;
    }
    info->cmd[CDATA + extended_length * GP_ADD_EXTENDED_LENGTH] = (uint8_t)(info->block_count >> ONE_BYTE_BITS_OFFSET);
    info->cmd[CDATA + extended_length * GP_ADD_EXTENDED_LENGTH + ONE_BYTES_OFFSET] =
                                                                                    (uint8_t)(info->block_count & 0xff);

    mac_chaining_data.data = &g_mac_chaining[0];
    mac_chaining_data.data_length = SECFLASH_CMAC_TOTAL_LENGTH;
    status = secflash_calculate_cmac(&info->cmd[0], SECFLASH_READ_CMD_DATA_FIELD_LEN, extended_length,
                                     mac_chaining_data, &g_session_key.smac[0]);
    if (status != SECFLASH_SUCCESS) {
        tloge("%s, Err read calc cmac:%x\n", __func__, status);
        return status;
    }

    ret = memcpy_s(&info->cmd[CDATA + extended_length * GP_ADD_EXTENDED_LENGTH + SECFLASH_READ_CMD_DATA_FIELD_LEN],
                   info->cmd_length - (CDATA + extended_length * GP_ADD_EXTENDED_LENGTH +
                                       SECFLASH_READ_CMD_DATA_FIELD_LEN), &g_mac_chaining[0], SECFLASH_CMAC_LENGTH);
    if (ret != EOK) {
        tloge("%s, memcpy failed:%x\n", __func__, info->cmd_length);
        return SECFLASH_FAILURE | MEMCPY_ERR;
    }

    /* refresh cmd length */
    info->cmd_length = CDATA + extended_length * GP_ADD_EXTENDED_LENGTH + SECFLASH_READ_CMD_DATA_FIELD_LEN +
                       SECFLASH_CMAC_LENGTH;
    return SECFLASH_SUCCESS;
}

/*
 * @brief      : the received read response process.
 * @param[in]  : response_apdu, the response apdu data buffer.
 *               response_real_length, the response data length.
 *               phy_block_index, the expect phy block index.
 *               block_count, the expect block count.
 * @return     : success of failure
 */
static uint32_t secflash_read_response_process(uint8_t *response_apdu, uint32_t response_real_length,
    uint32_t phy_block_index, uint32_t block_count)
{
    struct check_info expect_value;

    (void)memset_s(&expect_value, sizeof(struct check_info), 0, sizeof(struct check_info));
    expect_value.ins = GP_INS_READ_DATA;
    expect_value.response_length = SECFLASH_READ_BLOCK_RESP_DATA_OFFSET +  SECFLASH_BLOCK_BYTE_LEN * block_count +
                                   SECFLASH_CMAC_LENGTH + GP_SW_LENGTH;
    expect_value.block_count = block_count;
    expect_value.block_index = phy_block_index;
    return secflash_response_process(response_apdu, response_real_length, expect_value);
}

/*
 * @brief      : read data(blocks) from security flash.
 * @param[in]  : moduld_id, the ID of partition
 *               block_index, the block id of data to be read
 *		 block_count, the block count of data to be read
 *               read_buffer, the pointer of read data buffer
 *               buffer_max_length, the max bytes length of read buffer.
 * @return     : success of failure
 */
uint32_t secflash_read_blocks(uint32_t module_id, uint32_t block_index, uint32_t block_count,
    uint8_t *read_buffer, uint32_t buffer_max_length)
{
    uint8_t cmd[SECFLASH_READ_BLOCK_CMD_LEN] = {0};
    uint8_t *response_apdu = NULL;
    uint32_t response_real_length = SECFLASH_READ_BLOCK_RESP_LEN;
    struct cmd_derivate_info info = {0};
    int32_t ret;
    uint32_t status;

    status = secflash_cmd_info_check(block_count, read_buffer, buffer_max_length, GP_INS_READ_DATA);
    if (status != SECFLASH_SUCCESS)
        goto error_process;

    info.module_id = module_id;
    info.block_index = block_index;
    info.block_count = block_count;
    info.cmd = &cmd[0];
    info.cmd_length = SECFLASH_READ_BLOCK_CMD_LEN;
    status = secflash_read_cmd_derivate(&info);
    if (status != SECFLASH_SUCCESS)
        goto error_process;

#if SECFLASH_DEBUG
    dump_data("Read_blocks cmd data", &cmd[0], SECFLASH_READ_BLOCK_CMD_LEN);
#endif

    response_apdu = TEE_Malloc(SECFLASH_READ_BLOCK_RESP_LEN, 0);
    if (!response_apdu) {
        status = SECFLASH_FAILURE | MALLOC_ERR;
        goto error_process;
    }

    /* send cmd and get response */
    ret = __scard_transmit(SECFLASH_SCARD_TRANS_ID, &cmd[0], info.cmd_length, response_apdu, &response_real_length);
    if (ret) {
        tloge("%s, Err Transmit:%x\n", __func__, ret);
        status = SECFLASH_FAILURE | ((uint32_t)ret & 0xffff);
        goto error_process;
    }

#if SECFLASH_DEBUG
    dump_data("Read_blocks resp data", response_apdu, response_real_length);
#endif

    status = secflash_read_response_process(response_apdu, response_real_length, info.phy_block_index, block_count);
    if (status != SECFLASH_SUCCESS)
        goto error_process;

    /* decrypt the read data: offset is 4 */
    status = secflash_decrypt_sensitive_data(&info, g_encrypt_iv, &response_apdu[SECFLASH_READ_BLOCK_RESP_DATA_OFFSET],
                                             read_buffer, SECFLASH_BLOCK_BYTE_LEN * block_count);

error_process:
    if (response_apdu)
        TEE_Free(response_apdu);
    response_apdu = NULL;
    /* err or right process */
    secflash_error_process(status);
    return status;
}

/*
 * @brief      : the erase cmd derivate before send to secflash.
 * @param[in]  : info, the cmd info used for derivation.
 * @return     : success of failure
 */
static uint32_t secflash_erase_cmd_derivate(struct cmd_derivate_info *info)
{
    struct data_info mac_chaining_data;
    uint32_t ret;
    uint32_t status;

    /* check the moduleid and get the phy block index */
    status = secflash_get_phys_addr(info->module_id, info->block_index, info->block_count,
                                    &info->phy_block_index);
    if (status != SECFLASH_SUCCESS) {
        tloge("%s, Err erase cmd get addr:%x\n", __func__, status);
        return status;
    }

    info->cmd[CLA] = GP_CLA_COMMAND_SECURE_MESSAGING;
    info->cmd[INS] = GP_INS_ERASE_BLOCK;
    info->cmd[P1] = (uint8_t)(info->phy_block_index >> ONE_BYTE_BITS_OFFSET);
    info->cmd[P2] = (uint8_t)(info->phy_block_index & 0xff);
    info->cmd[LC] = SECFLASH_ERASE_CMD_DATA_FIELD_LEN + SECFLASH_CMAC_LENGTH;
    info->cmd[CDATA] = (uint8_t)(info->block_count >> ONE_BYTE_BITS_OFFSET);
    info->cmd[CDATA + 1] = (uint8_t)(info->block_count & 0xff);

    /* calculate cmd cmac: Data Field is 2 bytes */
    mac_chaining_data.data = &g_mac_chaining[0];
    mac_chaining_data.data_length = SECFLASH_CMAC_TOTAL_LENGTH;
    status = secflash_calculate_cmac(&info->cmd[0], SECFLASH_ERASE_CMD_DATA_FIELD_LEN, 0, mac_chaining_data,
                                     &g_session_key.smac[0]);
    if (status != SECFLASH_SUCCESS) {
        tloge("%s, Err erase calc cmac:%x\n", __func__, status);
        return status;
    }

    ret = memcpy_s(&info->cmd[CDATA + SECFLASH_ERASE_CMD_DATA_FIELD_LEN],
                   info->cmd_length - (CDATA + SECFLASH_ERASE_CMD_DATA_FIELD_LEN),
                   &g_mac_chaining[0], SECFLASH_CMAC_LENGTH);
    if (ret != EOK) {
        tloge("%s, memcpy failed:%x\n", __func__, info->cmd_length);
        return SECFLASH_FAILURE | MEMCPY_ERR;
    }

    return SECFLASH_SUCCESS;
}

/*
 * @brief      : erase security flash blocks(1 page = 1k).
 * @param[in]  : moduld_id, the ID of partition to be erase
 *               block_index, the block id of data to be erase
 *		 block_count, the block count of data to be erase
 * @return     : success of failure
 */
uint32_t secflash_erase_blocks(uint32_t module_id, uint32_t block_index, uint32_t block_count)
{
    uint8_t cmd[SECFLASH_ERASE_BLOCK_CMD_LEN] = {0};
    uint8_t response_apdu[SECFLASH_ERASE_BLOCK_RESP_LEN] = {0};
    uint32_t response_length = SECFLASH_ERASE_BLOCK_RESP_LEN;
    struct cmd_derivate_info info = {0};
    struct check_info expect_value;
    int32_t ret;
    uint32_t status;

    status = secflash_cmd_info_check(block_count, NULL, 0, GP_INS_ERASE_BLOCK);
    if (status != SECFLASH_SUCCESS) {
        tloge("%s, Err check erase cmd info:%x\n", __func__, status);
        goto error_process;
    }

    info.module_id = module_id;
    info.block_index = block_index;
    info.block_count = block_count;
    info.cmd = &cmd[0];
    info.cmd_length = SECFLASH_ERASE_BLOCK_CMD_LEN;
    info.data = NULL;
    status = secflash_erase_cmd_derivate(&info);
    if (status != SECFLASH_SUCCESS)
        goto error_process;

#if SECFLASH_DEBUG
    dump_data("Erase_blocks cmd data", &cmd[0], SECFLASH_ERASE_BLOCK_CMD_LEN);
#endif
    /* send cmd and get response */
    ret = __scard_transmit(SECFLASH_SCARD_TRANS_ID, &cmd[0], info.cmd_length, &response_apdu[0], &response_length);
    if (ret) {
        tloge("%s, Err Transmit:%x\n", __func__, ret);
        status = SECFLASH_FAILURE | ((uint32_t)ret & 0xffff);
        goto error_process;
    }

#if SECFLASH_DEBUG
    dump_data("Erase_blocks resp data", &response_apdu[0], response_length);
#endif
    (void)memset_s(&expect_value, sizeof(struct check_info), 0, sizeof(struct check_info));
    expect_value.ins = GP_INS_ERASE_BLOCK;
    expect_value.response_length = SECFLASH_ERASE_BLOCK_RESP_LEN;
    expect_value.block_count = block_count;
    expect_value.block_index = info.phy_block_index;
    status = secflash_response_process(&response_apdu[0], response_length, expect_value);
    if (status != SECFLASH_SUCCESS) {
        tloge("%s, Err Erase resp process:%x\n", __func__, status);
        goto error_process;
    }

error_process:
    /* err or right process */
    secflash_error_process(status);
    return status;
}

/*
 * @brief      : reset the security flash, called by upper user
 *               the function only called when binding key channel established.
 * @param[in]  : reset_type, SOFTWARE OR HARDWARE
 * @return     : NA
 */
uint32_t secflash_reset(uint8_t reset_type)
{
    uint32_t status;

    status = __secflash_chip_reset(reset_type);
    if (status != SECFLASH_SUCCESS) {
        tloge("%s, resetType:%x\n", __func__, reset_type);
        return status;
    }

    status = secflash_authenticate_channel();
    tloge("%s, auth channel status:%x\n", __func__, status);

    return status;
}

/*
 * @brief      : set security flash to power saving mode, called by upper user
 * @param[in]  : NA
 * @return     : NA
 */
uint32_t secflash_power_saving(void)
{
    uint32_t status;

    status = __secflash_power_save();
    tloge("%s, status:%x\n", __func__, status);
    return status;
}

/*
 * @brief      : initialize the scp03 security channel and other status flags
 * @param[in]  : NA
 * @return     : NA
 */
uint32_t secflash_scp03_init(void)
{
    uint32_t status;
    /* huawei.hisilicon ASIC II */
    uint8_t context[SECFLASH_IV_BYTE_LEN] = {0x68, 0x75, 0x61, 0x77, 0x65, 0x69, 0x2e, 0x68,
                                             0x69, 0x73, 0x69, 0x6c, 0x69, 0x63, 0x6f, 0x6e};

    g_batch_id = 0;
    g_vendor_id = 0;
    g_sec_level = 0;

    (void)memset_s(&g_mac_chaining[0], SECFLASH_CMAC_TOTAL_LENGTH, 0, SECFLASH_CMAC_TOTAL_LENGTH);
    (void)memset_s(&g_binding_key, sizeof(struct secflash_keyset), 0, sizeof(struct secflash_keyset));

    (void)memset_s(&g_secflash_count, sizeof(struct sec_counter), 0, sizeof(struct sec_counter));
    (void)memset_s(&g_secflash_challenge, sizeof(struct scp_challenge), 0, sizeof(struct scp_challenge));

    status = secflash_aes_cmac_wrapper(&context[0], SECFLASH_IV_BYTE_LEN, &g_encrypt_iv[0]);
    if (status != SECFLASH_SUCCESS) {
        tloge("%s, generate base IV err:%x\n", __func__, status);
        return SECFLASH_FAILURE | AES_SET_IV_ERR;
    }

    g_secflash_init_status = SECFLASH_INIT_START;
    status = secflash_authenticate_channel();
    tloge("%s, auth channel status:%x\n", __func__, status);
    return status;
}
