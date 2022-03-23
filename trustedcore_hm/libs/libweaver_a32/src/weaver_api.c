/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: .c file for <weaver project>
 * Author: c00351135
 * Create: 2019-09-10
 */

#include "weaver_api.h"
#include "sec_flash_ext_api.h"
#include "mspc_ext_api.h"
#include "msp_tee_se_ext_api.h"
#include "tee_common.h"
#include "sre_syscall.h"
#include "string.h"
#include "tee_internal_se_api.h"
#include "tee_log.h"
#include "securec.h"

#define WEAVER_MAX_READERS 16
#define WEAVER_MAX_READER_LEN 16
#define WEAVER_MAX_READER_NAME_LEN 16
#define WEAVER_MAX_DATA_LEN 100

#define WEAVER_TLV_SLOTID_TAG 0x10
#define WEAVER_TLV_SLOTID_LEN 0x04
#define WEAVER_TLV_KEY_TAG 0x20
#define WEAVER_TLV_KEY_LEN 0x14
#define WEAVER_TLV_VALUE_TAG 0x30
#define WEAVER_TLV_VALUE_LEN 0x14
#define WEAVER_TLV_TIME_TAG 0x50
#define WEAVER_TLV_TIME_LEN 0x04

#define WEAVER_INPUT_LEN_GETSLOTS 5
#define WEAVER_INPUT_LEN_WRITE 55
#define WEAVER_INPUT_LEN_READ 40
#define WEAVER_INPUT_LEN_GETSTATUS 14

#define WEAVER_SLOTID_MASK 0xFFFF7FFF
#define WEAVER_SLOTID_MAX 64
#define WEAVER_GETSLOTS_RSP_OK_LEN 6
#define WEAVER_GETSLOTS_SW1_OK 0x90
#define WEAVER_GETSLOTS_SW2_OK 0x00
#define WEAVER_GETSLOTS_TAG_SLOT 3
#define WEAVER_GETSLOTS_SW1TAG 4
#define WEAVER_GETSLOTS_SW2TAG 5
#define WEAVER_WRITE_KEYLEN 16
#define WEAVER_WRITE_VALUELEN 16
#define WEAVER_WRITE_SLOTTAG 7
#define WEAVER_WRITE_KEYTAG 11
#define WEAVER_WRITE_KEYLENTAG 12
#define WEAVER_WRITE_KEYDATATAG 13
#define WEAVER_WRITE_KEYHASHTAG 29
#define WEAVER_WRITE_VALUETAG 33
#define WEAVER_WRITE_VALUELENTAG 34
#define WEAVER_WRITE_VALUEDATATAG 35
#define WEAVER_WRITE_DATAHASHTAG 51
#define WEAVER_WRITE_RSP_OK_LEN 2
#define WEAVER_WRITE_SW1_OK 0x90
#define WEAVER_WRITE_SW2_OK 0x00
#define WEAVER_WRITE_SW1TAG 0
#define WEAVER_WRITE_SW2TAG 1
#define WEAVER_READ_TAG_VALUE 3
#define WEAVER_READ_VALUE_SIZE 16
#define WEAVER_READ_KEYLEN 16
#define WEAVER_READ_RSP_OK_LEN 25
#define WEAVER_READ_SW1_OK 0x90
#define WEAVER_READ_SW2_OK 0x00
#define WEAVER_READ_SW1TAG 23
#define WEAVER_READ_SW2TAG 24
#define WEAVER_READ_SW1TAG1 7
#define WEAVER_READ_SW2TAG1 8
#define WEAVER_READ_STATUSTAG 0
#define WEAVER_READ_SLOTTAG 7
#define WEAVER_READ_KEYTAG 11
#define WEAVER_READ_KEYLENTAG 12
#define WEAVER_READ_KEYDATATAG 13
#define WEAVER_READ_KEYHASHTAG 29
#define WEAVER_READ_TIMETAG 33
#define WEAVER_READ_TIMELENTAG 34
#define WEAVER_READ_TIMEDATATAG 35
#define WEAVER_READ_LETAG 39
#define WEAVER_READ_RESP_LEN 0x00
#define WEAVER_GETSTATUS_SLOTTAG 5
#define WEAVER_GETSTATUS_TIMETAG 9
#define WEAVER_GETSTATUS_LETAG 13
#define WEAVER_GETSTATUS_RSP_OK_LEN 10
#define WEAVER_GETSTATUS_SW1_OK 0x90
#define WEAVER_GETSTATUS_SW2_OK 0x00
#define WEAVER_GETSTATUS_TAG_TIMEOUT 0
#define WEAVER_GETSTATUS_TAG_FAILURE_COUNT 4
#define WEAVER_GETSTATUS_SW1TAG 8
#define WEAVER_GETSTATUS_SW2TAG 9
#define WEAVER_GETSTATUS_RESP_LEN 0x08
#define WEAVER_GETSTATUS_SOFTWARE_ERROR 0
#define WEAVER_GETSTATUS_HARDWARE_ERROR 1
#define WEAVER_GETSTATUS_UNKNOW_ERROR 2
#define WEAVER_GETSTATUS_ERROR 0xE2100000
#define WEAVER_GETSTATUS_MASK 0xFFF00000
#define WEAVER_GETSTATUS_ERROR_4B 0x00004B00
#define WEAVER_GETSTATUS_ERROR_4D 0x00004D00
#define WEAVER_GETSTATUS_MASK_4B 0x0000FF00
#define WEAVER_GETSTATUS_MASK_4D 0x0000FF00
#define WEAVER_OPEN_CHANNEL_ERROR_BSP1 0xa4010002
#define WEAVER_OPEN_CHANNEL_ERROR_BSP2 0xa4020002
#define WEAVER_OPEN_CHANNEL_ERROR_BSP3 0xa4020016

#define WEAVER_GETSLOTS_SW1TAG_ERROR 0
#define WEAVER_GETSLOTS_SW2TAG_ERROR 1
#define WEAVER_READ_SW1TAG1_ERROR 0
#define WEAVER_READ_SW2TAG1_ERROR 1
#define WEAVER_GETSTATUS_SW1TAG_ERROR 0
#define WEAVER_GETSTATUS_SW2TAG_ERROR 1

#define BYTE_SWIFT 8
#define BYTE2_SWIFT 256
#define BYTE3_SWIFT (256 * 256)
#define BYTE4_SWIFT (256 * 256 * 256)
#define TAG_TIMEOUT1 6
#define TAG_TIMEOUT2 5
#define TAG_TIMEOUT3 4
#define TAG_TIMEOUT4 3

#define FIRST_PARAM 0
#define SECOND_PARAM 1
#define THIRD_PARAM 2
#define FOURTH_PARAM 3
#define PARAM_NUM 4

#define FIRST_PARAM_RIGHT_OFFSET 24
#define SECOND_PARAM_RIGHT_OFFSET 16
#define THIRD_PARAM_RIGHT_OFFSET 8
#define EIGHT_BIT_OFFSET 0xff
#define PARAM_LEFT_OFFSET 8

#define READ_SUCCESS 0x00
#define READ_WRONG_KEY 0x7f
#define READ_BACK_OFF 0x76

#define APDU_SLOT_BIT_SIZE 4
#define APDU_TIME_BIT_SIZE 4
#define APDU_FAILCNT_BIT_SIZE 4
#define APDU_TIMEOUT_BIT_SIZE 4

#define HMAC_SHA256_SIZE 32
#define BLOCK_SIZE_MAX 256
#define HMAC_SHA256_SIZE 32
#define APDU_HASH_SIZE 4

#define WEAVER_SECURE_LOG_LEN 2
#define WEAVER_NVM_DATA_SIZE (0 * 1024)
#define WEAVER_SA_VERSION 0x10001

#ifdef DEF_ENG
#define WEAVER_LOG_ON
#endif

TEE_SEServiceHandle g_weaver_service;
TEE_SEReaderHandle g_weaver_reader;
TEE_SESessionHandle g_weaver_session;
TEE_SEChannelHandle g_weaver_channel;
bool g_weaver_channel_open = false;

#ifdef WEAVER_LOG_ON
static void weaver_dump(uint8_t *name, uint8_t *buf, uint32_t len)
{
    len = WEAVER_SECURE_LOG_LEN;
    SLogTrace("%s", name);
    for (uint32_t i = 0; i < len; i++)
        SLogTrace("%02x ", buf[i]);

    SLogTrace("weaver_data_flag");
}
#endif

static void weaver_data_clear(uint8_t *buf, uint32_t len)
{
    if (memset_s(buf, len, 0, len) != EOK)
        SLogTrace("data_clear fail");
}

static void weaver_put_uint32(uint32_t value, uint8_t *ptr, uint32_t len)
{
    if (!ptr || len != sizeof(uint32_t)) {
        SLogError("input parameter is invalid in %s", __func__);
        return;
    }
    ptr[FIRST_PARAM] = (value >> FIRST_PARAM_RIGHT_OFFSET) & EIGHT_BIT_OFFSET;
    ptr[SECOND_PARAM] = (value >> SECOND_PARAM_RIGHT_OFFSET) & EIGHT_BIT_OFFSET;
    ptr[THIRD_PARAM] = (value >> THIRD_PARAM_RIGHT_OFFSET) & EIGHT_BIT_OFFSET;
    ptr[FOURTH_PARAM] = (value) & EIGHT_BIT_OFFSET;
}

static uint32_t weaver_get_uint32(uint8_t *ptr, uint32_t len)
{
    uint32_t value;

    if (!ptr || len != sizeof(uint32_t)) {
        SLogError("input parameter is invalid in %s", __func__);
        return -1;
    }
    value = ptr[FIRST_PARAM];
    value <<= PARAM_LEFT_OFFSET;
    value |= ptr[SECOND_PARAM];
    value <<= PARAM_LEFT_OFFSET;
    value |= ptr[THIRD_PARAM];
    value <<= PARAM_LEFT_OFFSET;
    value |= ptr[FOURTH_PARAM];

    return value;
}

static TEE_Result weaver_calc_hash(
    const uint8_t *src_data,
    uint32_t src_len,
    uint8_t *dest_data,
    uint32_t dest_len)
{
    TEE_OperationHandle cryptoOps = NULL;
    uint8_t hash[HMAC_SHA256_SIZE];
    size_t hash_len = sizeof(hash);

    if (!src_data || !dest_data) {
        SLogError("weaver clac hash input param NULL");
        return MSPWEAVER_ERROR_CALCHASH_INPUT_NULL;
    }
    TEE_Result ret = TEE_AllocateOperation(&cryptoOps, TEE_ALG_SHA256,
        TEE_MODE_DIGEST, 0);
    if (ret) {
        SLogError("weaver TEE_AllocateOperation, failed %x", ret);
        goto EXIT;
    }
    uint32_t loop = src_len / BLOCK_SIZE_MAX;
    for (uint32_t i = 0; i < loop; i++) {
        ret = TEE_DigestUpdate(cryptoOps, src_data + i * BLOCK_SIZE_MAX,
            BLOCK_SIZE_MAX);
        if (ret) {
            SLogError("weaver TEE_DigestUpdate, failed %x", ret);
            goto EXIT;
        }
    }
    ret = TEE_DigestDoFinal(cryptoOps, src_data + loop * BLOCK_SIZE_MAX,
        src_len % BLOCK_SIZE_MAX, hash, &hash_len);
    if (ret) {
        SLogError("weaver TEE_DigestDoFinal, fail ret=%x, src_len=%x",
            ret, src_len % BLOCK_SIZE_MAX);
        goto EXIT;
    }

    errno_t rc = memcpy_s(dest_data, dest_len, hash, dest_len);
    if (rc != EOK) {
        ret = (TEE_Result)MSPWEAVER_ERROR_CALCHASH_MEMCPY_FAILED;
        SLogError("weaver calc hash memcpy failed %x", ret);
        goto EXIT;
    }

EXIT:
    TEE_FreeOperation(cryptoOps);
    return ret;
}

static TEE_Result weaver_check_hash(
    const uint8_t *src_data,
    uint32_t src_len,
    const uint8_t *hash_data,
    uint32_t hash_size)
{
    uint8_t hash[HMAC_SHA256_SIZE] = {0};
    uint32_t hash_len = sizeof(hash);
    TEE_Result ret;

    ret = weaver_calc_hash(src_data, src_len, hash, hash_len);
    if (ret) {
        SLogError("weaver check hash (calculate)fail");
        return (TEE_Result)MSPWEAVER_ERROR_CHECKHASH_FAILED;
    }
    if (!memcmp(hash, hash_data, hash_size)) {
        return MSPWEAVER_ERROR_OK;
    }
    SLogError("weaver check hash (compare) fail");
    return (TEE_Result)MSPWEAVER_ERROR_CHECKHASH_MEMCMP_FAILED;
}

static TEE_Result weaver_get_msp_reader(TEE_SEReaderHandle *msp_reader)
{
    TEE_Result ret;
    TEE_SEReaderHandle readerHandles[WEAVER_MAX_READERS];

    char reader_name[WEAVER_MAX_READER_NAME_LEN] = {0};
    uint32_t reader_count = WEAVER_MAX_READERS;
    uint32_t name_len = WEAVER_MAX_READER_NAME_LEN - 1;

    ret = TEE_SEServiceGetReaders(
        g_weaver_service,
        readerHandles,
        &reader_count);
    if (ret) {
        SLogError("Get readers failed, ret=0x%x.", ret);
        return ret;
    }

    SLogTrace("reader_count: %u", reader_count);
    if (reader_count > WEAVER_MAX_READERS) {
        SLogError("reader_count is over 16");
        return (TEE_Result)MSPWEAVER_ERROR_READERS_EXCEEDS_MAX;
    }
    uint32_t i;

    for (i = 0; i < reader_count; i++) {
        name_len = WEAVER_MAX_READER_NAME_LEN - 1;
        if (memset_s(reader_name, WEAVER_MAX_READER_NAME_LEN, 0, WEAVER_MAX_READER_NAME_LEN) != EOK) {
            return (TEE_Result)MSPWEAVER_ERROR_MSP_READER_MEMSET_FAILED;
            SLogTrace("reader_name_clear fail");
        }
        if (!readerHandles[i]) {
            continue;
        }
        ret = TEE_SEReaderGetName(readerHandles[i], reader_name, &name_len);
#ifdef WEAVER_LOG_ON
        SLogTrace("Reader %d ret=0x%x", i, ret);
#endif
        if (ret) {
            continue;
        } else {
            SLogTrace("%d->%s", i, reader_name);
        }

        if (!strcmp(reader_name, "msp")) {
            (*msp_reader) = readerHandles[i];
            break;
        }
    }
    if (i == reader_count) {
        SLogError("msp reader not found");
        ret = (TEE_Result)MSPWEAVER_ERROR_MSP_READER_NOT_FOUND;
    }
#ifdef WEAVER_LOG_ON
    SLogTrace("g_weaver_reader = %x, reader_len = %d\n",
        readerHandles[i], reader_count);
    SLogTrace("reader_name = %s\n", reader_name);
#endif
    return ret;
}

#ifdef SUPPORT_DYN_WEAVER
static TEE_Result weaver_applet_load_install(void)
{
    TEE_Result ret;

    /* hisi.weaver(5 spaces) */
    uint8_t sa_aid[] = {
        0x68, 0x69, 0x73, 0x69, 0x2e, 0x77, 0x65, 0x61,
        0x76, 0x65, 0x72, 0x20, 0x20, 0x20, 0x20, 0x20
    };
    /* hisi.weaver(4 spaces + '0') */
    uint8_t sa_instance_id[] = {
        0x68, 0x69, 0x73, 0x69, 0x2e, 0x77, 0x65, 0x61,
        0x76, 0x65, 0x72, 0x20, 0x20, 0x20, 0x20, 0x30
    };
    uint32_t sa_aid_len = sizeof(sa_aid);
    struct sa_status status = { 0 };
    struct sa_status_detail detail_status = { 0 };
    struct msp_install_sa_info install_sa_info = { 0 };

    ret = TEE_EXT_MSPGetStatus(sa_aid, sa_aid_len, &detail_status);
    if ((ret) && (ret != TEE_ERROR_NEED_LOAD_SA)) {
        SLogError("TEE_EXT_MSPGetStatus fail, ret=0x%x\n", ret);
        return (TEE_Result)MSPWEAVER_ERROR_SA_GETSTATUS_FAILED;
    }
    if (detail_status.sa_lfc == SA_LCS_NO_LOAD) {
        ret = TEE_EXT_MSPLoadSA(NULL, 0, sa_aid, sa_aid_len);
        if (ret) {
            SLogError("TEE_EXT_MSPLoadSA fail, ret=0x%x\n", ret);
            return (TEE_Result)MSPWEAVER_ERROR_SA_LOAD_FAILED;
        }
    }
    errno_t rc = memcpy_s(install_sa_info.sa_aid, sa_aid_len, sa_aid, sa_aid_len);
    if (rc != EOK) {
        SLogError("weaver memcpy_s fail\n");
        return (TEE_Result)MSPWEAVER_ERROR_SA_AID_MEMCPY_FAILED;
    }
    rc = memcpy_s(install_sa_info.sa_instance_id, sa_aid_len, sa_instance_id, sa_aid_len);
    if (rc != EOK) {
        SLogError("weaver memcpy_s fail\n");
        return (TEE_Result)MSPWEAVER_ERROR_SA_INSTANCE_AID_MEMCPY_FAILED;
    }
    install_sa_info.version = WEAVER_SA_VERSION;
    install_sa_info.nvm_data_size = WEAVER_NVM_DATA_SIZE;

    if (detail_status.sa_lfc != SA_LCS_INSTALLED) {
        ret = TEE_EXT_MSPInstallSA(&install_sa_info, &status);
        if (ret) {
            SLogError("TEE_EXT_MSPInstallSA fail, ret=0x%x\n", ret);
            return (TEE_Result)MSPWEAVER_ERROR_SA_INSTALL_FAILED;
        }
    }
#ifdef WEAVER_LOG_ON
    SLogTrace("TEE_EXT_MSPInstallSA, ret=0x%x\n", ret);
    SLogTrace("sa_version = %x\n", status.sa_version);
    SLogTrace("sa_lfc = %x\n", status.sa_lfc);
    SLogTrace("sa_instance_num = %x\n", status.sa_instance_num);
    SLogTrace("sa_instance_id = %x\n",
        status.instance_status[0].sa_instance_id);
    SLogTrace("sa_select_status = %x\n",
        status.instance_status[0].sa_select_status);
#endif
    return ret;
}
#endif

static TEE_Result weaver_open_msp(void)
{
    TEE_Result ret;

#ifdef SUPPORT_DYN_WEAVER
    ret = weaver_applet_load_install();
    if (ret) {
        SLogError("applet_load_install fail, ret=0x%x\n", ret);
        return ret;
    }
#endif

    ret = TEE_SEServiceOpen(&g_weaver_service);
    if (ret) {
        SLogError("TEE_SEServiceOpen fail, ret=0x%x\n", ret);
        return ret;
    }

    ret = weaver_get_msp_reader(&g_weaver_reader);
    if (ret) {
        SLogError("weaver_get_msp_reader fail, ret=0x%x\n", ret);
        return ret;
    }
    ret = TEE_SEReaderOpenSession(g_weaver_reader, &g_weaver_session);
    if (ret) {
        SLogError("OpenSession fail, ret=0x%x\n", ret);
        return ret;
    }

#ifdef SUPPORT_DYN_WEAVER
    /* hisi.weaver(4 spaces) + '0'*/
    uint8_t aid[] = { 0x68, 0x69, 0x73, 0x69, 0x2e, 0x77, 0x65, 0x61,
        0x76, 0x65, 0x72, 0x20, 0x20, 0x20, 0x20, 0x30 };
#else
    /* hisi.weaver(5 spaces) */
    uint8_t aid[] = { 0x68, 0x69, 0x73, 0x69, 0x2e, 0x77, 0x65, 0x61,
        0x76, 0x65, 0x72, 0x20, 0x20, 0x20, 0x20, 0x20 };
#endif

    TEE_SEAID weaver_aid = {aid, sizeof(aid)};

    SLogTrace("OpenLogicalChannel start\n");
    ret = TEE_SESessionOpenLogicalChannel(
        g_weaver_session,
        &weaver_aid,
        &g_weaver_channel);
    if (ret) {
        SLogError("OpenLogicalChannel fail, ret=0x%x\n", ret);
        return ret;
    }

#ifdef WEAVER_LOG_ON
    SLogTrace("g_weaver_session = %x\n", g_weaver_session);
    SLogTrace("g_weaver_channel = %x\n", g_weaver_channel);
#endif
    SLogTrace("%s = success\n", __func__);
    return ret;
}

#ifdef SUPPORT_STK_WEAVER // support mspc clock throttling
bool g_msp_is_power_voted = false;

static void weaver_msp_power_on_process(void)
{
    TEE_Result ret;

    if (!g_msp_is_power_voted) {
        ret = TEE_EXT_MspcPowerOn(MSPC_WEAVER_SECTIMER_VOTE_ID);
        g_msp_is_power_voted = true;
        if (ret) {
            SLogError("msp_power_on fail, ret = 0x%x\n", ret);
        } else {
            SLogTrace("msp_power_on\n");
        }
    }
}

static void weaver_msp_power_off_process(void)
{
    TEE_Result ret;

    if (g_msp_is_power_voted) {
        ret = TEE_EXT_MspcPowerOff(MSPC_WEAVER_SECTIMER_VOTE_ID);
        g_msp_is_power_voted = false;
        if (ret) {
            SLogError("msp_power_off fail, ret = 0x%x\n", ret);
        } else {
            SLogTrace("msp_power_off\n");
        }
    }
}

static void weaver_msp_power_process(bool flag)
{
    if (flag) {
        weaver_msp_power_on_process();
    } else {
        weaver_msp_power_off_process();
    }
}
#else
static void weaver_msp_power_process(bool flag)
{
    (void)flag;
    return;
}
#endif

static void weaver_closechannel(void)
{
    if (g_weaver_channel) {
        TEE_SEChannelClose(g_weaver_channel);
        g_weaver_channel = NULL;
    }
}

static void weaver_closesession(void)
{
    if (g_weaver_session) {
        TEE_SESessionCloseChannels(g_weaver_session);
        g_weaver_session = NULL;
    }
}

static void weaver_closereader(void)
{
    if (g_weaver_reader) {
        TEE_SEReaderCloseSessions(g_weaver_reader);
        g_weaver_reader = NULL;
    }
}

static void weaver_closeservice(void)
{
    if (g_weaver_service) {
        TEE_SEServiceClose(g_weaver_service);
        g_weaver_service = NULL;
    }
}

static void weaver_close_msp(void)
{
    weaver_closechannel();

    weaver_closesession();

    weaver_closereader();

    weaver_closeservice();
}

static TEE_Result weaver_process_apdu_fail(
    uint32_t base,
    uint8_t sw1,
    uint8_t sw2)
{
    TEE_Result ret;

    (void)base;
    ret = (((uint32_t)sw1) << BYTE_SWIFT) | (uint32_t)sw2;
    return ret;
}

static TEE_Result weaver_get_slots_check(uint32_t *num_slots)
{
    TEE_Result ret = MSPWEAVER_ERROR_OK;

    if (!num_slots) {
        SLogError("param num_slots NULL\n");
        ret = (TEE_Result)MSPWEAVER_ERROR_GETSLOTS_CHECK_PARAM_FAILED;
    }

    return ret;
}

static TEE_Result weaver_slotid_check(uint32_t slotid)
{
    uint32_t temp = slotid & WEAVER_SLOTID_MASK;

    if (temp >= WEAVER_SLOTID_MAX) {
        return (TEE_Result)MSPWEAVER_ERROR_SLOTID_EXCEEDS_MAX;
    }
    return MSPWEAVER_ERROR_OK;
}

static TEE_Result weaver_get_slots_process(
    uint8_t *rsp,
    uint32_t rsplen,
    uint32_t *num_slots)
{
    TEE_Result ret = MSPWEAVER_ERROR_OK;
    uint32_t slots;
    uint32_t base = MSPWEAVER_ERROR_GETSLOTS_NOT9000;
    uint8_t sw1 = rsp[WEAVER_GETSLOTS_SW1TAG_ERROR];
    uint8_t sw2 = rsp[WEAVER_GETSLOTS_SW2TAG_ERROR];

    if (rsplen == WEAVER_GETSLOTS_RSP_OK_LEN &&
        rsp[WEAVER_GETSLOTS_SW1TAG] == WEAVER_GETSLOTS_SW1_OK &&
        rsp[WEAVER_GETSLOTS_SW2TAG] == WEAVER_GETSLOTS_SW2_OK) {
            slots = (uint32_t)rsp[WEAVER_GETSLOTS_TAG_SLOT];
    } else {
        slots = 0;
        ret = weaver_process_apdu_fail(base, sw1, sw2);
        SLogError("rsp:%02x%02x...,len:%d fail\n",
            sw1, sw2, rsplen);
    }
    (*num_slots) = slots;
    return ret;
}

static TEE_Result weaver_get_slots_misc(uint32_t *num_slots)
{
    TEE_Result ret;

    ret = weaver_get_slots_check(num_slots);
    if (ret != MSPWEAVER_ERROR_OK) {
        SLogError("param num_slots NULL\n");
        return ret;
    }

    if (!g_weaver_channel_open) {
#ifdef WEAVER_LOG_ON
        SLogTrace("reopen channel\n");
#endif
        ret = weaver_open_msp();
        if (ret != MSPWEAVER_ERROR_OK) {
            SLogError("getslots open_msp fail, ret=0x%x\n", ret);
            g_weaver_channel_open = false;
            weaver_close_msp();
        }
    }
    return ret;
}

#ifdef SUPPORT_MSP_WEAVER
TEE_Result TEE_EXT_WeaverGetNumSlots(uint32_t *num_slots)
{
    TEE_Result ret;
    uint32_t status_info = 0;

    ret = TEE_EXT_SecFlashIsAvailable(&status_info);
    if (ret) {
        SLogError("SecFlash fail, ret=0x%x\n", ret);
        return ret;
    }
    if (status_info == SECFLASH_IS_ABSENCE_MAGIC) {
        SLogError("SecFlash fail, status_info=0x%x\n", status_info);
        return (TEE_Result)MSPWEAVER_ERROR_GETSLOTS_SECFLASH_IS_ABSENCE;
    }

    ret = weaver_get_slots_misc(num_slots);
    if (ret) {
        SLogError("weaver_get_slots_misc fail\n");
        return ret;
    }

    uint8_t rsp[WEAVER_MAX_DATA_LEN] = {0};
    uint32_t rsplen = sizeof(rsp);
    uint32_t inputlen = WEAVER_INPUT_LEN_GETSLOTS;
    uint8_t get_slots[] = { 0x80, 0x02, 0x00, 0x00, 0x04 };

    g_weaver_channel_open = true;
    ret = TEE_SEChannelTransmit(
        g_weaver_channel,
        get_slots,
        inputlen,
        rsp,
        &rsplen);
    if (ret) {
        g_weaver_channel_open = false;
        weaver_close_msp();
        SLogError("Transmit get_slots fail, ret=0x%x\n", ret);
        return ret;
    }
    g_weaver_channel_open = false;
    weaver_close_msp();

#ifdef WEAVER_LOG_ON
    SLogTrace("send:%d", inputlen);
    weaver_dump((uint8_t *)"get_slots->send:", get_slots, inputlen);
    SLogTrace("recv:%d", rsplen);
    weaver_dump((uint8_t *)"get_slots->resp:", rsp, rsplen);
#endif

    return weaver_get_slots_process(rsp, rsplen, num_slots);
}
#else
TEE_Result TEE_EXT_WeaverGetNumSlots(uint32_t *num_slots)
{
    (void)num_slots;
    (void)weaver_get_slots_misc;
    (void)weaver_get_slots_process;
#ifdef WEAVER_LOG_ON
    (void)weaver_dump;
#endif
    return (TEE_Result)MSPWEAVER_ERROR_MSP_WEAVER_INVALID;
}
#endif

static TEE_Result weaver_write_check(
    const uint8_t *key,
    uint32_t key_len,
    const uint8_t *value,
    uint32_t value_len)
{
    TEE_Result ret = MSPWEAVER_ERROR_OK;

    if (!key || !value) {
        SLogError("param write NULL\n");
        ret = (TEE_Result)MSPWEAVER_ERROR_WRITE_CHECK_PARAM_NULL;
    }
    if (key_len != WEAVER_WRITE_KEYLEN ||
        value_len != WEAVER_WRITE_VALUELEN) {
        SLogError("param write len invalid\n");
        ret = (TEE_Result)MSPWEAVER_ERROR_WRITE_CHECK_PARAM_LEN;
    }
    return ret;
}

static TEE_Result weaver_write_pack(
    uint32_t slotid,
    uint8_t *write,
    const uint8_t *key,
    const uint8_t *value)
{
    TEE_Result ret;

    weaver_put_uint32(slotid, &write[WEAVER_WRITE_SLOTTAG], APDU_SLOT_BIT_SIZE);

    write[WEAVER_WRITE_KEYTAG] = WEAVER_TLV_KEY_TAG; // tag
    write[WEAVER_WRITE_KEYLENTAG] = WEAVER_TLV_KEY_LEN; // len

    errno_t rc = memcpy_s(&write[WEAVER_WRITE_KEYDATATAG],
        WEAVER_MAX_DATA_LEN - WEAVER_WRITE_KEYDATATAG,
        key, WEAVER_WRITE_KEYLEN);
    if (rc != EOK) {
        SLogError("weaver memcpy_s fail\n");
        ret = (TEE_Result)MSPWEAVER_ERROR_WRITE_PACK_MEMCPY_FAILED;
        return ret;
    }

    ret = weaver_calc_hash(key, WEAVER_WRITE_KEYLEN,
        &write[WEAVER_WRITE_KEYHASHTAG], APDU_HASH_SIZE);
    if (ret) {
        SLogError("weaver write add hash fail\n");
        ret = (TEE_Result)MSPWEAVER_ERROR_WRITE_PACK_CALCHASH_FAILED;
        return ret;
    }

    write[WEAVER_WRITE_VALUETAG] = WEAVER_TLV_VALUE_TAG; // tag
    write[WEAVER_WRITE_VALUELENTAG] = WEAVER_TLV_VALUE_LEN; // len
    rc = memcpy_s(&write[WEAVER_WRITE_VALUEDATATAG],
        WEAVER_MAX_DATA_LEN - WEAVER_WRITE_VALUEDATATAG,
        value, WEAVER_WRITE_VALUELEN);
    if (rc != EOK) {
        SLogError("weaver memcpy_s fail\n");
        ret = (TEE_Result)MSPWEAVER_ERROR_WRITE_PACK_MEMCPY_FAILED;
        return ret;
    }

    ret = weaver_calc_hash(value, WEAVER_WRITE_VALUELEN,
        &write[WEAVER_WRITE_DATAHASHTAG], APDU_HASH_SIZE);
    if (ret) {
        SLogError("weaver write add hash fail\n");
        ret = (TEE_Result)MSPWEAVER_ERROR_WRITE_PACK_CALCHASH_FAILED;
        return ret;
    }
    return ret;
}

static TEE_Result weaver_write_process(
    uint8_t *rsp,
    uint32_t rsplen)
{
    TEE_Result ret;
    uint32_t base = MSPWEAVER_ERROR_WRITE_NOT9000;
    uint8_t sw1 = rsp[WEAVER_WRITE_SW1TAG];
    uint8_t sw2 = rsp[WEAVER_WRITE_SW2TAG];

    if (rsplen == WEAVER_WRITE_RSP_OK_LEN &&
        sw1 == WEAVER_WRITE_SW1_OK &&
        sw2 == WEAVER_WRITE_SW2_OK) {
            ret = MSPWEAVER_ERROR_OK;
    } else {
        ret = weaver_process_apdu_fail(base, sw1, sw2);
        SLogError("rsp:%02x%02x...,len:%d fail\n",
            sw1, sw2, rsplen);
    }

    return ret;
}

static TEE_Result weaver_write_misc(
    uint32_t slotid,
    const uint8_t *key,
    uint32_t key_len,
    const uint8_t *value,
    uint32_t value_len)
{
    TEE_Result ret;

    ret = weaver_slotid_check(slotid);
    if (ret) {
        SLogError("weaver write check slotid fail\n");
        return ret;
    }
    ret = weaver_write_check(key, key_len, value, value_len);
    if (ret) {
        SLogError("weaver write check fail\n");
        return ret;
    }
    if (!g_weaver_channel_open) {
        SLogTrace("weaver reopen channel\n");
        ret = weaver_open_msp();
        if (ret) {
            SLogError("weaver write opensa fail, ret=0x%x\n", ret);
            g_weaver_channel_open = false;
            weaver_close_msp();
        }
    }
    return ret;
}

#ifdef SUPPORT_MSP_WEAVER
TEE_Result TEE_EXT_WeaverWrite(
    uint32_t slotid,
    const uint8_t *key,
    uint32_t key_len,
    const uint8_t *value,
    uint32_t value_len)
{
    TEE_Result ret;

    ret = weaver_write_misc(slotid, key, key_len, value, value_len);
    if (ret) {
        SLogError("weaver_write_misc fail\n");
        return ret;
    }

    uint32_t inputlen = WEAVER_INPUT_LEN_WRITE;
    uint8_t write[WEAVER_MAX_DATA_LEN] = { 0x80, 0x04, 0x00, 0x00, 0x32,
        0x10, 0x04, 0x00, 0x00, 0x00 };

    ret = weaver_write_pack(slotid, write, key, value);
    if (ret) {
        SLogError("weaver write check fail\n");
        return ret;
    }

    uint8_t rsp[WEAVER_MAX_DATA_LEN] = {0};
    uint32_t rsplen = sizeof(rsp);

    g_weaver_channel_open = true;
    ret = TEE_SEChannelTransmit(
        g_weaver_channel,
        write,
        inputlen,
        rsp,
        &rsplen);
    if (ret) {
        g_weaver_channel_open = false;
        weaver_close_msp();
        SLogError("Transmit write fail, ret=0x%x\n", ret);
        return ret;
    }
    g_weaver_channel_open = false;
    weaver_close_msp();

#ifdef WEAVER_LOG_ON
    SLogTrace("send:%d", inputlen);
    weaver_dump((uint8_t *)"write->send:", write, inputlen);
    SLogTrace("recv:%d", rsplen);
    weaver_dump((uint8_t *)"write->resp:", rsp, rsplen);
#endif

    ret = weaver_write_process(rsp, rsplen);
    weaver_data_clear(write, WEAVER_MAX_DATA_LEN);
    weaver_data_clear(rsp, WEAVER_MAX_DATA_LEN);
    return ret;
}
#else
TEE_Result TEE_EXT_WeaverWrite(
    uint32_t slotid,
    const uint8_t *key,
    uint32_t key_len,
    const uint8_t *value,
    uint32_t value_len)
{
    (void)slotid;
    (void)key;
    (void)key_len;
    (void)value;
    (void)value_len;
    (void)weaver_write_misc;
    (void)weaver_write_process;
    (void)weaver_write_pack;
    (void)weaver_data_clear;
    return (TEE_Result)MSPWEAVER_ERROR_MSP_WEAVER_INVALID;
}
#endif

static TEE_Result weaver_read_process_wrong_key(
    uint8_t *rsp,
    uint32_t rsplen,
    uint8_t *status,
    uint32_t *value_len,
    uint32_t *timeout)
{
    TEE_Result ret = MSPWEAVER_ERROR_OK;

    if (!rsp || !status || !value_len || !timeout) {
        SLogError("weaver process WRONG_KEY input NULL\n");
        return (TEE_Result)MSPWEAVER_ERROR_READ_WRONGKEY_PARAM_NULL;
    }

    bool msp_power_flag = (bool)rsp[TAG_TIMEOUT4];
    (void)rsplen;
    (*value_len) = 0;
    (*status) = READ_WRONG_KEY;
    (*timeout) = (uint32_t)rsp[TAG_TIMEOUT1] +
        (uint32_t)rsp[TAG_TIMEOUT2] * BYTE2_SWIFT +
        (uint32_t)rsp[TAG_TIMEOUT3] * BYTE3_SWIFT +
        (uint32_t)rsp[TAG_TIMEOUT4] * BYTE4_SWIFT;
    weaver_msp_power_process(msp_power_flag);
#ifdef WEAVER_LOG_ON
    SLogTrace("weaver READ_WRONG_KEY timeout=%d\n", (*timeout));
#endif
    return ret;
}

static TEE_Result weaver_read_process_back_off(
    uint8_t *rsp,
    uint32_t rsplen,
    uint8_t *status,
    uint32_t *value_len,
    uint32_t *timeout)
{
    TEE_Result ret = MSPWEAVER_ERROR_OK;

    if (!rsp || !status || !value_len || !timeout) {
        SLogError("weaver process BACK_OFF input NULL\n");
        return (TEE_Result)MSPWEAVER_ERROR_READ_BACKOFF_PARAM_NULL;
    }

    bool msp_power_flag = (bool)rsp[TAG_TIMEOUT4];
    (void)rsplen;
    (*value_len) = 0;
    (*status) = READ_BACK_OFF;
    (*timeout) = (uint32_t)rsp[TAG_TIMEOUT1] +
        (uint32_t)rsp[TAG_TIMEOUT2] * BYTE2_SWIFT +
        (uint32_t)rsp[TAG_TIMEOUT3] * BYTE3_SWIFT +
        (uint32_t)rsp[TAG_TIMEOUT4] * BYTE4_SWIFT;
    weaver_msp_power_process(msp_power_flag);
#ifdef WEAVER_LOG_ON
    SLogTrace("weaver READ_BACK_OFF timeout=%d\n", (*timeout));
#endif
    return ret;
}

static TEE_Result weaver_read_process_success(
    uint8_t *rsp,
    uint32_t rsplen,
    uint8_t *status,
    uint8_t *value,
    uint32_t *value_len,
    uint32_t *timeout)
{
    TEE_Result ret;

    if (!rsp || !status || !value_len || !timeout) {
        SLogError("weaver process SUCCESS input NULL\n");
        return (TEE_Result)MSPWEAVER_ERROR_READ_SUCCESS_PARAM_NULL;
    }
    ret = weaver_check_hash(&rsp[WEAVER_READ_TAG_VALUE], WEAVER_READ_VALUE_SIZE,
        &rsp[WEAVER_READ_TAG_VALUE + WEAVER_READ_VALUE_SIZE], APDU_HASH_SIZE);
    if (ret) {
        SLogError("weaver check_hash fail\n");
        ret = (TEE_Result)MSPWEAVER_ERROR_READ_CHECKHASH_FAILED;
        return ret;
    }
    errno_t rc = memcpy_s(value, WEAVER_READ_VALUE_SIZE,
        &rsp[WEAVER_READ_TAG_VALUE], WEAVER_READ_VALUE_SIZE);
    if (rc != EOK) {
        SLogError("weaver memcpy_s fail\n");
        ret = (TEE_Result)MSPWEAVER_ERROR_READ_MEMCPY_FAILED;
        return ret;
    }
    ret = MSPWEAVER_ERROR_OK;
    (void)rsplen;
    (*value_len) = WEAVER_READ_VALUE_SIZE;
    (*timeout) = 0;
    (*status) = READ_SUCCESS;
    weaver_msp_power_process(false);
#ifdef WEAVER_LOG_ON
    SLogTrace("weaver READ_SUCCESS\n");
#endif
    return ret;
}

static TEE_Result weaver_read_process(
    uint8_t *rsp,
    uint32_t rsplen,
    uint8_t *status,
    uint8_t *value,
    uint32_t *value_len,
    uint32_t *timeout)
{
    TEE_Result ret;
    uint32_t base = MSPWEAVER_ERROR_READ_NOT9000;
    uint8_t sw1 = rsp[WEAVER_READ_SW1TAG1_ERROR];
    uint8_t sw2 = rsp[WEAVER_READ_SW2TAG1_ERROR];

    if (rsplen == WEAVER_READ_RSP_OK_LEN &&
        rsp[WEAVER_READ_SW1TAG] == WEAVER_READ_SW1_OK &&
        rsp[WEAVER_READ_SW2TAG] == WEAVER_READ_SW2_OK) {
        ret = weaver_read_process_success(rsp, rsplen, status,
            value, value_len, timeout);
    } else if (rsp[WEAVER_READ_STATUSTAG] == READ_WRONG_KEY &&
        rsp[WEAVER_READ_SW1TAG1] == WEAVER_READ_SW1_OK &&
        rsp[WEAVER_READ_SW2TAG1] == WEAVER_READ_SW2_OK) {
        ret = weaver_read_process_wrong_key(rsp, rsplen, status,
            value_len, timeout);
    } else if (rsp[WEAVER_READ_STATUSTAG] == READ_BACK_OFF &&
        rsp[WEAVER_READ_SW1TAG1] == WEAVER_READ_SW1_OK &&
        rsp[WEAVER_READ_SW2TAG1] == WEAVER_READ_SW2_OK) {
        ret = weaver_read_process_back_off(rsp, rsplen, status,
            value_len, timeout);
    } else {
        (*value_len) = 0;
        ret = weaver_process_apdu_fail(base, sw1, sw2);
        SLogError("rsp:%02x%02x,len:%d fail\n",
            sw1, sw2, rsplen);
    }

    return ret;
}

static TEE_Result weaver_read_check(
    const uint8_t *key,
    uint32_t key_len,
    uint8_t *status,
    uint8_t *value,
    uint32_t *value_len,
    uint32_t *timeout)
{
    TEE_Result ret = MSPWEAVER_ERROR_OK;

    if (!key || !value || !value_len) {
        SLogError("param read NULL\n");
        return (TEE_Result)MSPWEAVER_ERROR_READ_CHECK_PARAM_NULL;
    }
    if (!status || !timeout) {
        SLogError("param read status NULL\n");
        ret = (TEE_Result)MSPWEAVER_ERROR_READ_CHECK_PARAM_NULL;
    }
    if (key_len != WEAVER_READ_KEYLEN) {
        SLogError("param read len invalid\n");
        ret = (TEE_Result)MSPWEAVER_ERROR_READ_CHECK_PARAM_LEN;
    }
    if ((*value_len) < WEAVER_READ_VALUE_SIZE) {
        SLogError("param read value len invalid\n");
        ret = (TEE_Result)MSPWEAVER_ERROR_READ_CHECK_PARAM_LEN;
    }
    return ret;
}

static TEE_Result weaver_read_pack(
    uint32_t slotid,
    uint8_t *read,
    const uint8_t *key)
{
    TEE_Result ret;

    weaver_put_uint32(slotid, &read[WEAVER_READ_SLOTTAG], APDU_SLOT_BIT_SIZE);

    read[WEAVER_READ_KEYTAG] = WEAVER_TLV_KEY_TAG; // tag
    read[WEAVER_READ_KEYLENTAG] = WEAVER_TLV_KEY_LEN; // len

    errno_t rc = memcpy_s(&read[WEAVER_READ_KEYDATATAG],
        WEAVER_MAX_DATA_LEN - WEAVER_READ_KEYDATATAG,
        key, WEAVER_READ_KEYLEN);
    if (rc != EOK) {
        SLogError("weaver memcpy_s fail\n");
        ret = (TEE_Result)MSPWEAVER_ERROR_READ_PACK_MEMCPY_FAILED;
        return ret;
    }

    ret = weaver_calc_hash(key, WEAVER_READ_KEYLEN,
        &read[WEAVER_READ_KEYHASHTAG], APDU_HASH_SIZE);
    if (ret) {
        SLogError("weaver write add hash fail\n");
        ret = (TEE_Result)MSPWEAVER_ERROR_READ_PACK_CALCHASH_FAILED;
        return ret;
    }

    uint32_t time;

    read[WEAVER_READ_TIMETAG] = WEAVER_TLV_TIME_TAG; // tag
    read[WEAVER_READ_TIMELENTAG] = WEAVER_TLV_TIME_LEN; // len
    time = __get_secure_rtc_time();
    weaver_put_uint32(time, &read[WEAVER_READ_TIMEDATATAG], APDU_TIME_BIT_SIZE);
    read[WEAVER_READ_LETAG] = WEAVER_READ_RESP_LEN; // rsp len

    return ret;
}

static TEE_Result weaver_read_misc(
    uint32_t slotid,
    const uint8_t *key,
    uint32_t key_len,
    uint8_t *status,
    uint8_t *value,
    uint32_t *value_len,
    uint32_t *timeout)
{
    TEE_Result ret;

    ret = weaver_slotid_check(slotid);
    if (ret) {
        SLogError("read check slotid fail\n");
        return ret;
    }
    ret = weaver_read_check(key, key_len, status, value, value_len, timeout);
    if (ret) {
        SLogError("read check fail\n");
        return ret;
    }
    if (!g_weaver_channel_open) {
        SLogTrace("reopen channel\n");
        ret = weaver_open_msp();
        if (ret) {
            SLogError("read open_msp fail, ret=0x%x\n", ret);
            g_weaver_channel_open = false;
            weaver_close_msp();
        }
    }
    return ret;
}

#ifdef SUPPORT_MSP_WEAVER
TEE_Result TEE_EXT_WeaverRead(
    uint32_t slotid,
    const uint8_t *key,
    uint32_t key_len,
    uint8_t *status,
    uint8_t *value,
    uint32_t *value_len,
    uint32_t *timeout)
{
    TEE_Result ret;

    ret = weaver_read_misc(slotid, key, key_len,
        status, value, value_len, timeout);
    if (ret) {
        SLogError("weaver_read_misc fail\n");
        return ret;
    }

    uint8_t read[WEAVER_MAX_DATA_LEN] = { 0x80, 0x06, 0x00, 0x00, 0x22,
        0x10, 0x04, 0x00, 0x00, 0x00 };
    uint32_t inputlen = WEAVER_INPUT_LEN_READ;

    ret = weaver_read_pack(slotid, read, key);
    if (ret) {
        SLogError("weaver read pack fail\n");
        return ret;
    }

    uint8_t rsp[WEAVER_MAX_DATA_LEN] = {0};
    uint32_t rsplen = sizeof(rsp);

    g_weaver_channel_open = true;
    ret = TEE_SEChannelTransmit(
        g_weaver_channel,
        read,
        inputlen,
        rsp,
        &rsplen);
    if (ret) {
        g_weaver_channel_open = false;
        weaver_close_msp();
        SLogError("Transmit read fail, ret=0x%x\n", ret);
        return ret;
    }
    g_weaver_channel_open = false;
    weaver_close_msp();

#ifdef WEAVER_LOG_ON
    SLogTrace("TEE_SEChannelTransmit=%x\n", ret);
    SLogTrace("send:%d", inputlen);
    weaver_dump((uint8_t *)"read->send:", read, inputlen);
    SLogTrace("recv:%d", rsplen);
    weaver_dump((uint8_t *)"read->resp:", rsp, rsplen);
#endif

    ret = weaver_read_process(rsp, rsplen, status, value, value_len, timeout);
    weaver_data_clear(read, WEAVER_MAX_DATA_LEN);
    weaver_data_clear(rsp, WEAVER_MAX_DATA_LEN);
    return ret;
}
#else
TEE_Result TEE_EXT_WeaverRead(
    uint32_t slotid,
    const uint8_t *key,
    uint32_t key_len,
    uint8_t *status,
    uint8_t *value,
    uint32_t *value_len,
    uint32_t *timeout)
{
    (void)slotid;
    (void)key;
    (void)key_len;
    (void)status;
    (void)value;
    (void)value_len;
    (void)timeout;
    (void)weaver_read_misc;
    (void)weaver_read_pack;
    (void)weaver_read_process;
    (void)weaver_data_clear;
    return (TEE_Result)MSPWEAVER_ERROR_MSP_WEAVER_INVALID;
}
#endif

TEE_Result TEE_EXT_WeaverErase(uint32_t slotid)
{
    (void)slotid;
    TEE_Result ret = MSPWEAVER_ERROR_OK;

    if (!g_weaver_channel_open) {
        SLogTrace("reopen channel\n");
        ret = weaver_open_msp();
        if (ret) {
            SLogError("erase open_msp fail, ret=0x%x\n", ret);
            g_weaver_channel_open = false;
            weaver_close_msp();
            return ret;
        }
    }
    g_weaver_channel_open = false;
    weaver_close_msp();

    return ret;
}

TEE_Result TEE_EXT_WeaverEraseAll(void)
{
    TEE_Result ret = MSPWEAVER_ERROR_OK;

    if (!g_weaver_channel_open) {
        SLogTrace("reopen channel\n");
        ret = weaver_open_msp();
        if (ret) {
            SLogError("eraseall open_msp fail, ret=0x%x\n", ret);
            g_weaver_channel_open = false;
            weaver_close_msp();
            return ret;
        }
    }
    g_weaver_channel_open = false;
    weaver_close_msp();

    return ret;
}

static TEE_Result weaver_get_status_check(
    uint32_t *fail_count,
    uint32_t *timeout)
{
    TEE_Result ret = MSPWEAVER_ERROR_OK;

    if (!fail_count) {
        SLogError("get_status param fail_count NULL\n");
        ret = (TEE_Result)MSPWEAVER_ERROR_GETSTATUS_CHECK_PARAM_COUNT;
    }
    if (!timeout) {
        SLogError("get_status param timeout NULL\n");
        ret = (TEE_Result)MSPWEAVER_ERROR_GETSTATUS_CHECK_PARAM_TIME;
    }

    return ret;
}

static TEE_Result weaver_get_status_pack(
    uint32_t slotid,
    uint8_t *get_status)
{
    TEE_Result ret = MSPWEAVER_ERROR_OK;

    weaver_put_uint32(slotid, &get_status[WEAVER_GETSTATUS_SLOTTAG],
        APDU_SLOT_BIT_SIZE);

    uint32_t time;

    time = __get_secure_rtc_time();
    weaver_put_uint32(time, &get_status[WEAVER_GETSTATUS_TIMETAG], APDU_TIME_BIT_SIZE);
    get_status[WEAVER_GETSTATUS_LETAG] = WEAVER_GETSTATUS_RESP_LEN; // rsp len

    return ret;
}

static TEE_Result weaver_get_status_process(
    uint8_t *rsp,
    uint32_t rsplen,
    uint32_t *fail_count,
    uint32_t *timeout)
{
    TEE_Result ret = MSPWEAVER_ERROR_OK;
    uint32_t base = MSPWEAVER_ERROR_GETSTATUS_NOT9000;
    uint8_t sw1 = rsp[WEAVER_GETSTATUS_SW1TAG_ERROR];
    uint8_t sw2 = rsp[WEAVER_GETSTATUS_SW2TAG_ERROR];
    bool msp_power_flag = (bool)rsp[WEAVER_GETSTATUS_TAG_TIMEOUT];

    if (rsplen == WEAVER_GETSTATUS_RSP_OK_LEN &&
        rsp[WEAVER_GETSTATUS_SW1TAG] == WEAVER_GETSTATUS_SW1_OK &&
        rsp[WEAVER_GETSTATUS_SW2TAG] == WEAVER_GETSTATUS_SW2_OK) {
            (*timeout) = weaver_get_uint32(
                &rsp[WEAVER_GETSTATUS_TAG_TIMEOUT],
                APDU_TIMEOUT_BIT_SIZE);
            (*fail_count) = weaver_get_uint32(
                &rsp[WEAVER_GETSTATUS_TAG_FAILURE_COUNT],
                APDU_FAILCNT_BIT_SIZE);
        weaver_msp_power_process(msp_power_flag);
    } else {
        (*timeout) = 0;
        (*fail_count) = 0;
        ret = weaver_process_apdu_fail(base, sw1, sw2);
        SLogError("rsp:%02x%02x,len:%d fail\n",
            sw1, sw2, rsplen);
    }

    return ret;
}

static TEE_Result weaver_get_status_misc(
    uint32_t slotid,
    uint32_t *fail_count,
    uint32_t *timeout)
{
    TEE_Result ret;

    ret = weaver_slotid_check(slotid);
    if (ret) {
        SLogError("GetStatus check slotid fail\n");
        return ret;
    }
    ret = weaver_get_status_check(fail_count, timeout);
    if (ret) {
        SLogError("param fail_count or timeout NULL\n");
        return ret;
    }
    if (!g_weaver_channel_open) {
        SLogTrace("reopen channel\n");
        ret = weaver_open_msp();
    }
    if (ret) {
        SLogError("getstatus open_msp fail, ret=0x%x\n", ret);
        g_weaver_channel_open = false;
        weaver_close_msp();
    }
    return ret;
}

#ifdef SUPPORT_MSP_WEAVER
TEE_Result TEE_EXT_WeaverGetStatus(
    uint32_t slotid,
    uint32_t *fail_count,
    uint32_t *timeout)
{
    TEE_Result ret;
    uint32_t status_info = 0;

    ret = TEE_EXT_SecFlashIsAvailable(&status_info);
    if (ret) {
        SLogError("SecFlash fail, ret=0x%x\n", ret);
        return ret;
    }
    if (status_info == SECFLASH_IS_ABSENCE_MAGIC) {
        SLogError("SecFlash fail, status_info=0x%x\n", status_info);
        return (TEE_Result)MSPWEAVER_ERROR_GETSTATUS_SECFLASH_IS_ABSENCE;
    }

    ret = weaver_get_status_misc(slotid, fail_count, timeout);
    if (ret) {
        SLogError("weaver_get_status_misc fail\n");
        return ret;
    }

    uint8_t rsp[WEAVER_MAX_DATA_LEN] = {0};
    uint32_t rsplen = sizeof(rsp);
    uint32_t inputlen = WEAVER_INPUT_LEN_GETSTATUS;
    uint8_t get_status[WEAVER_MAX_DATA_LEN] = { 0x80, 0x40, 0x00, 0x00, 0x08 };

    ret = weaver_get_status_pack(slotid, get_status);
    if (ret) {
        SLogError("weaver get_status pack fail\n");
        return ret;
    }
    g_weaver_channel_open = true;
    ret = TEE_SEChannelTransmit(
        g_weaver_channel,
        get_status,
        inputlen,
        rsp,
        &rsplen);
    if (ret) {
        g_weaver_channel_open = false;
        weaver_close_msp();
        SLogError("Transmit get_status fail, ret=0x%x\n", ret);
        return ret;
    }
    g_weaver_channel_open = false;
    weaver_close_msp();

#ifdef WEAVER_LOG_ON
    SLogTrace("send:%d", inputlen);
    weaver_dump((uint8_t *)"get_status->send:", get_status, inputlen);
    SLogTrace("recv:%d", rsplen);
    weaver_dump((uint8_t *)"get_status->resp:", rsp, rsplen);
#endif

    ret = weaver_get_status_process(rsp, rsplen, fail_count, timeout);
    return ret;
}
#else
TEE_Result TEE_EXT_WeaverGetStatus(
    uint32_t slotid,
    uint32_t *fail_count,
    uint32_t *timeout)
{
    (void)slotid;
    (void)fail_count;
    (void)timeout;
    (void)weaver_get_status_misc;
    (void)weaver_get_status_process;
    (void)weaver_get_status_pack;
    return (TEE_Result)MSPWEAVER_ERROR_MSP_WEAVER_INVALID;
}
#endif

static TEE_Result weaver_get_error_check(uint32_t error)
{
    TEE_Result ret = MSPWEAVER_ERROR_OK;

    if ((error & WEAVER_GETSTATUS_MASK) != WEAVER_GETSTATUS_ERROR) {
        ret = (TEE_Result)WEAVER_GETSTATUS_UNKNOW_ERROR;
    }
    return ret;
}

static uint32_t weaver_get_error_tpye(uint32_t error)
{
    uint32_t ret = MSPWEAVER_ERROR_TYPE_SOFTWARE;

    SLogTrace("weaver input error = 0x%x", error);
    if (TEE_EXT_IsMspcHardwareErrno(error)) {
        SLogTrace("HardwareErrno: error = 0x%x", error);
        ret = MSPWEAVER_ERROR_TYPE_HARDWARE;
    }

    return ret;
}

#ifdef SUPPORT_MSP_WEAVER
TEE_Result TEE_EXT_WeaverGetErrorType(uint32_t error)
{
    TEE_Result ret;
    uint32_t type;

    (void)weaver_get_error_check;
    type = weaver_get_error_tpye(error);
    if (type == MSPWEAVER_ERROR_TYPE_SOFTWARE) {
        ret = (TEE_Result)WEAVER_GETSTATUS_SOFTWARE_ERROR;
    } else if (type == MSPWEAVER_ERROR_TYPE_HARDWARE) {
        ret = (TEE_Result)WEAVER_GETSTATUS_HARDWARE_ERROR;
    } else {
        ret = (TEE_Result)WEAVER_GETSTATUS_UNKNOW_ERROR;
    }
    return ret;
}
#else
TEE_Result TEE_EXT_WeaverGetErrorType(uint32_t error)
{
    (void)error;
    (void)weaver_get_error_tpye;
    (void)weaver_get_error_check;
    return (TEE_Result)MSPWEAVER_ERROR_MSP_WEAVER_INVALID;
}
#endif
