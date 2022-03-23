/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: antiroll-back token sa communication.
 * Author: aaron.shen
 * Create: 2020-03-21
 */

#include "art_comm.h"
#include "msp_tee_se_ext_api.h"
#include "samgr_common.h"
#include "securec.h"
#include "tee_commom_public_service.h"
#include "tee_common.h"
#include "tee_internal_api.h"
#include "tee_internal_se_api.h"
#include "tee_log.h"

/* sa related information */
#define SA_AID_LEN 16
#define MSP_READER_NAME_LEN 4 /* "msp" */
#define MAX_READER_NUM 4

#define ART_MAX_READERS             16
#define ART_MAX_READER_LEN          16
#define ART_MAX_RSP_APDU_LEN        261
#define ONE_BYTES_OFFSET            1
#define TWO_BYTES_OFFSET            2
#define ONE_BYTE_BITS_OFFSET        8

#define GP_SUCCESS_SW            0x9000
#define ART_GP_SW_RSP_LEN        2
#define GP_ADD_EXTENDED_LENGTH   2

#define ART_APDU_CMD_HEADER    5
#define ART_BASE_CMD_LEN       (ART_APDU_CMD_HEADER + sizeof(TEE_UUID))

#define ART_ALLOC_CMD_LEN      (ART_BASE_CMD_LEN)
#define ART_ALLOC_RSP_LEN      (ART_GP_SW_RSP_LEN + sizeof(uint32_t))

#define ART_PROCESS_COUNTER_CMD_LEN       (ART_BASE_CMD_LEN + sizeof(uint32_t))
#define ART_PROCESS_COUNTER_RSP_LEN       (ART_GP_SW_RSP_LEN + sizeof(uint32_t))

#define ART_PROCESS_INCREASE   0x5A
#define ART_PROCESS_READ       0xA5

#define ART_SA_VERSION         0x10001

/* Error num except GP SW:0x66** */
enum ART_ERROR_NUM {
    PARA_ERR = 0x6601,
    RESPONSE_LENGTH_ERR,
    MEMCPY_ERR,
    READER_COUNT_ERR,
    READER_FIND_ERR,
    OPEN_CHANNEL_ERR
};

enum apdu_cmd_offset {
    CLA = 0,
    INS,
    P1,
    P2,
    LC,
    CDATA
};

enum ART_cmd_ins {
    ART_INS_ALLOC_OBJECT = 0x01,
    ART_INS_READ_COUNTER_OBJECT = 0x02,
    ART_INS_INCREASE_COUNTER_OBJECT = 0x04,
};

#if ART_DEBUG_ON
#define MAX_DUMP_DATA_LEN            512

void dump_data(char *info, uint8_t *data, uint16_t len)
{
    uint16_t i;
    uint16_t print_len;

    if (!info || !data)
        return;

    tloge("%s (len=0x%x) :", info, len);
    /* dump 512 bytes data only */
    print_len = (len > MAX_DUMP_DATA_LEN) ? MAX_DUMP_DATA_LEN : len;
    for (i = 0; i < print_len; i++)
        tloge("%02x", data[i]);

    tloge("\n");
}

#endif

static TEE_SEServiceHandle g_art_service;
static TEE_SEReaderHandle g_art_reader;
static TEE_SESessionHandle g_art_session;
static TEE_SEChannelHandle g_art_channel;
bool g_art_channel_open = false;

/*
 * @brief     : the base response check called by the APIs to check the response length and sw.
 * @param[in] : response_apdu, the pointer of response apdu to be check
 *              response_length, the apdu length,
 *              expect_response_length, the response cmd length.
 * @return    : art_SUCCESS or others
 */
static TEE_Result art_response_check(const uint8_t *response_apdu, uint32_t response_length,
    uint32_t expect_response_length)
{
    uint16_t sw;

    if (response_apdu == NULL) {
        tloge("%s, Err response_apdu NULL\n", __func__);
        return ART_TEE_FAILURE | PARA_ERR;
    }

    if (response_length < ART_GP_SW_RSP_LEN) { /* '2' sw length */
        tloge("%s, Err response length\n", __func__);
        return ART_TEE_FAILURE | RESPONSE_LENGTH_ERR;
    }

    sw = (response_apdu[response_length - ART_GP_SW_RSP_LEN] << ONE_BYTE_BITS_OFFSET) +
         response_apdu[response_length - 1];
    if (sw != GP_SUCCESS_SW) { /* SUCCESS: 9000 */
        tloge("%s, Err sw:%x\n", __func__, sw);
        return ART_MSP_FAILURE | sw; /* MSP err num */
    }

    if (response_length != expect_response_length) {
        tloge("%s, Err length:%x\n", __func__, response_length);
        return ART_TEE_FAILURE | RESPONSE_LENGTH_ERR;
    }

    return ART_SUCCESS;
}

/*
 * @brief     : close the channel to msp art SA.
 * @param[in] : void.
 * @return    : TEE_SUCCESS or ERROR.
 */
static void art_close_channel(void)
{
    if (g_art_channel) {
        TEE_SEChannelClose(g_art_channel);
        g_art_channel = NULL;
    }
}

/*
 * @brief     : close the channel opened on the art session.
 * @param[in] : void.
 * @return    : TEE_SUCCESS or ERROR.
 */
static void art_close_session(void)
{
    if (g_art_session) {
        TEE_SESessionClose(g_art_session);
        g_art_session = NULL;
    }
}

/*
 * @brief     : close the session opened on the art reader.
 * @param[in] : void.
 * @return    : TEE_SUCCESS or ERROR.
 */
static void art_close_reader(void)
{
    if (g_art_reader) {
        TEE_SEReaderCloseSessions(g_art_reader);
        g_art_reader = NULL;
    }
}

/*
 * @brief     : release all SE resources allocated by the art service.
 * @param[in] : void.
 * @return    : TEE_SUCCESS or ERROR.
 */
static void art_close_service(void)
{
    if (g_art_service) {
        TEE_SEServiceClose(g_art_service);
        g_art_service = NULL;
    }
}

/*
 * @brief     : find the MSP reader.
 * @param[in] : void.
 * @return    : TEE_SUCCESS or ERROR.
 */
static TEE_Result art_open_msp_reader(void)
{
    TEE_Result ret;
    uint32_t i;
    uint32_t reader_count = ART_MAX_READERS;
    TEE_SEReaderHandle art_reader_handles[ART_MAX_READERS];
    char reader_name[ART_MAX_READER_LEN] = {0};
    uint32_t name_len = sizeof(reader_name) - 1;

    ret = TEE_SEServiceOpen(&g_art_service);
    if (ret != TEE_SUCCESS) {
        tloge("%s ServiceOpen fail=0x%x\n", __func__, ret);
        return ret;
    }

    ret = TEE_SEServiceGetReaders(g_art_service, art_reader_handles, &reader_count);
    if (ret != TEE_SUCCESS) {
        tloge("%s GetReaders fail=0x%x\n", __func__, ret);
        goto EXIT;
    }

    if (reader_count > ART_MAX_READERS) {
        tloge("%S readerCount is invalid 0x%x", __func__, reader_count);
        ret = ART_TEE_FAILURE | READER_COUNT_ERR;
        goto EXIT;
    }

    for (i = 0; i < reader_count; i++) {
        ret = TEE_SEReaderGetName(art_reader_handles[i], reader_name, &name_len);
        if (ret != TEE_SUCCESS)
            continue;

        if (!strcmp(reader_name, "msp")) {
            g_art_reader = art_reader_handles[i];
            break;
        }
    }

    if (i == reader_count) {
        tloge("%s MSP not found", __func__);
        ret = ART_TEE_FAILURE | READER_FIND_ERR;
        goto EXIT;
    }

    return ret;
EXIT:
    art_close_service();
    return ret;
}

/*
 * @brief     : close the MSP reader.
 * @param[in] : void.
 * @return    : TEE_SUCCESS or ERROR.
 */
static void art_close_msp_reader(void)
{
    art_close_reader();

    art_close_service();
}

/*
 * @brief     : open the MSP logic channel.
 * @param[in] : void.
 * @return    : TEE_SUCCESS or ERROR.
 */
static TEE_Result art_open_msp_channel(void)
{
    TEE_Result ret;
#ifdef SUPPORT_DYN_ART
    /* "hisi.sa.art    0" */
    uint8_t aid[] = { 0x68, 0x69, 0x73, 0x69, 0x2e, 0x73, 0x61, 0x2e, 0x61, 0x72, 0x74, 0x20, 0x20, 0x20, 0x20, 0x30 };
#else
    uint8_t aid[] = { 0x68, 0x69, 0x73, 0x69, 0x2e, 0x73, 0x61, 0x2e, 0x61, 0x72, 0x74, 0x20, 0x20, 0x20, 0x20, 0x20 };
#endif
    TEE_SEAID art_aid[] = { {aid, sizeof(aid)}, };
    uint32_t num_of_aids = sizeof(art_aid) / sizeof(art_aid[0]);
    uint32_t i;
    uint8_t rsp[ART_MAX_RSP_APDU_LEN];
    uint32_t rsp_len = ART_MAX_RSP_APDU_LEN;

    ret = TEE_SEReaderOpenSession(g_art_reader, &g_art_session);
    if (ret != TEE_SUCCESS) {
        tloge("%s ReaderOpenSession fail=0x%x\n", __func__, ret);
        return ret;
    }

    for (i = 0; i < num_of_aids; i++) {
        ret = TEE_SESessionOpenLogicalChannel(g_art_session, &art_aid[i], &g_art_channel);
        if (ret != TEE_SUCCESS)
            continue;

        ret = TEE_SEChannelGetSelectResponse(g_art_channel, rsp, &rsp_len);
        if (ret != TEE_SUCCESS) {
            art_close_channel();
            continue;
        }

        ret = art_response_check(rsp, rsp_len, ART_GP_SW_RSP_LEN);
        if (ret != ART_SUCCESS) {
            art_close_channel();
            continue;
        }
        break;
    }

    if (i == num_of_aids) {
        tloge("%s Open logic channel failed=0x%x", __func__, ret);
        ret = ART_TEE_FAILURE | OPEN_CHANNEL_ERR;
        goto EXIT;
    }

#if ART_DEBUG_ON
    tlogd("art_session = %x\n", g_art_session);
    tlogd("art_channel = %x\n", g_art_channel);
#endif

    g_art_channel_open = true;
    return ret;
EXIT:
    art_close_session();
    return ret;
}

/*
 * @brief     : close the MSP logic channel.
 * @param[in] : void.
 * @return    : void.
 */
static void art_close_msp_channel(void)
{
    if (g_art_channel_open == true) {
        art_close_channel();
        art_close_session();
        g_art_channel_open = false;
    }
}

#ifdef SUPPORT_DYN_ART
static TEE_Result art_applet_load_install(void)
{
    TEE_Result ret;
    /* "hisi.sa.art + 5 spaces " */
    uint8_t sa_aid[] = {
        0x68, 0x69, 0x73, 0x69, 0x2e, 0x73, 0x61, 0x2e,
        0x61, 0x72, 0x74, 0x20, 0x20, 0x20, 0x20, 0x20
    };
    /* "hisi.sa.art + 4 spaces + '0'" */
    uint8_t instance_id[] = {
        0x68, 0x69, 0x73, 0x69, 0x2e, 0x73, 0x61, 0x2e,
        0x61, 0x72, 0x74, 0x20, 0x20, 0x20, 0x20, 0x30
    };
    uint32_t sa_aid_len = sizeof(sa_aid);
    struct sa_status status = { 0 };
    struct sa_status_detail detail_status = { 0 };
    struct msp_install_sa_info install_sa_info;

    (void)memset_s(&install_sa_info, sizeof(install_sa_info), 0, sizeof(install_sa_info));
    ret = sa_mgr_get_sa_status(&sa_aid[0], sa_aid_len, &detail_status);
    if (ret != TEE_SUCCESS && ret != TEE_ERROR_NEED_LOAD_SA) {
        tloge("%s get Status fail, ret=0x%x\n",  __func__, ret);
        return ret;
    }

    if (detail_status.sa_lfc == SA_LCS_NO_LOAD) {
        ret = sa_mgr_load_sa(NULL, 0, &sa_aid[0], sa_aid_len);
        if (ret != TEE_SUCCESS) {
            tloge("%s load SA fail, ret=0x%x\n",  __func__, ret);
            return ret;
        }
    }

    if (detail_status.sa_lfc == SA_LCS_INSTALLED)
        return TEE_SUCCESS;

    ret = memcpy_s(install_sa_info.sa_aid, SA_AID_LEN, sa_aid, sa_aid_len);
    if (ret != EOK)
        ret = ART_TEE_FAILURE | MEMCPY_ERR;

    ret = memcpy_s(install_sa_info.sa_instance_id, SA_INSTANCE_ID_LEN, instance_id, sizeof(instance_id));
    if (ret != EOK)
        ret = ART_TEE_FAILURE | MEMCPY_ERR;

    install_sa_info.version = ART_SA_VERSION;

    ret = sa_mgr_install_sa(&install_sa_info, &status);
    if (ret != TEE_SUCCESS) {
        tloge("%s install SA fail, ret=0x%x\n",  __func__, ret);
        return ret;
    }

    return ret;
}
#endif

/*
 * @brief     : select the MSP logic channel.
 * @param[in] : void.
 * @return    : void.
 */
static TEE_Result art_select_sa(void)
{
    TEE_Result ret;

#ifdef SUPPORT_DYN_ART
    ret = art_applet_load_install();
    if (ret != TEE_SUCCESS) {
        tloge("%s load fail=0x%x\n", __func__, ret);
        return ret;
    }
#endif

    ret = art_open_msp_reader();
    if (ret != TEE_SUCCESS) {
        tloge("%s Open fail=0x%x\n", __func__, ret);
        return ret;
    }

    ret = art_open_msp_channel();
    if (ret != TEE_SUCCESS) {
        tloge("%s OpenChannel fail=0x%x\n", __func__, ret);
        art_close_msp_reader();
        return ret;
    }

    return ART_SUCCESS;
}

/*
 * @brief     : deselect the MSP logic channel.
 * @param[in] : void.
 * @return    : void.
 */
static void art_deselect_sa(void)
{
    art_close_msp_channel();

    art_close_msp_reader();
}

/*
 * @brief     : call msp ART SA to alloc counter.
 * @param[in] : uuid, the current TA specila id.
 * @param[out]: counter_num, the size of counter number have been alloced.
 * @return    : SUCCESS or FAIL
 */
TEE_Result art_sa_alloc(TEE_UUID *uuid, uint32_t *counter_num)
{
    TEE_Result ret;
    uint8_t cmd[ART_ALLOC_CMD_LEN] = {0};
    uint8_t rsp[ART_ALLOC_RSP_LEN] = {0};
    uint32_t rsp_len = ART_ALLOC_RSP_LEN;

    if (uuid == NULL || counter_num == NULL)
        return ART_TEE_FAILURE | PARA_ERR;

    ret = art_select_sa();
    if (ret != TEE_SUCCESS)
        return ret;

    cmd[CLA] = 0x0;
    cmd[INS] = ART_INS_ALLOC_OBJECT;
    cmd[P1] = 0x0;
    cmd[P2] = 0x0;
    cmd[LC] = sizeof(TEE_UUID);
    ret = memcpy_s(&cmd[CDATA], ART_ALLOC_CMD_LEN - CDATA, uuid, sizeof(TEE_UUID));
    if (ret != EOK) {
        ret = ART_TEE_FAILURE | MEMCPY_ERR;
        goto EXIT_PROCESS;
    }

    ret = TEE_SEChannelTransmit(g_art_channel, cmd, ART_ALLOC_CMD_LEN, rsp, &rsp_len);
    if (ret != TEE_SUCCESS) {
        tloge("%s Transmit fail=0x%x\n", __func__, ret);
        goto EXIT_PROCESS;
    }

#if ART_DEBUG_ON
    dump_data("send sa alloc", cmd, ART_ALLOC_CMD_LEN);
    dump_data("response", rsp, rsp_len);
#endif

    ret = art_response_check(rsp, rsp_len, ART_ALLOC_RSP_LEN);
    if (ret != ART_SUCCESS) {
        tloge("%s response check error=0x%x\n", __func__, ret);
        goto EXIT_PROCESS;
    }

    ret = memcpy_s(counter_num, sizeof(uint32_t), rsp, sizeof(uint32_t));
    if (ret != EOK)
        ret = ART_TEE_FAILURE | MEMCPY_ERR;
    else
        ret = ART_SUCCESS;

EXIT_PROCESS:
    art_deselect_sa();
    return ret;
}

/*
 * @brief     : build command buffer.
 * @param[in] : process_opt, read OR increase process flag.
 *              uuid, the current TA specila id.
 *              counter_id, the id of counter have been alloced.
 *              cmd, command buffer.
 * @param[out]: void
 * @return    : SUCCESS or FAIL
 */
static TEE_Result art_build_cmd(TEE_UUID *uuid, uint8_t process_opt, uint32_t counter_id, uint8_t *cmd)
{
    TEE_Result ret;

    cmd[CLA] = 0x0;
    cmd[P1] = 0x0;
    cmd[P2] = 0x0;
    cmd[LC] = sizeof(TEE_UUID) + sizeof(uint32_t); /* uuid + counter id */
    if (process_opt == ART_PROCESS_INCREASE)
        cmd[INS] = ART_INS_INCREASE_COUNTER_OBJECT;
    else
        cmd[INS] = ART_INS_READ_COUNTER_OBJECT;
    ret = memcpy_s(&cmd[CDATA], ART_PROCESS_COUNTER_CMD_LEN - CDATA, uuid, sizeof(TEE_UUID));
    if (ret != EOK) {
        return ART_TEE_FAILURE | MEMCPY_ERR;
    }
    ret = memcpy_s(&cmd[CDATA + sizeof(TEE_UUID)], ART_PROCESS_COUNTER_CMD_LEN - CDATA - sizeof(TEE_UUID),
                   &counter_id, sizeof(uint32_t));
    if (ret != EOK) {
        return ART_TEE_FAILURE | MEMCPY_ERR;
    }

    return ART_SUCCESS;
}

/*
 * @brief     : call msp art SA to read OR increase the uuid counter.
 * @param[in] : process_opt, read OR increase process flag.
 *              uuid, the current TA specila id.
 *              counter_id, the id of counter have been alloced.
 * @param[out]: counter, the counter value of the uuid.
 * @return    : SUCCESS or FAIL
 */
static TEE_Result art_sa_process_counter(TEE_UUID *uuid, uint8_t process_opt, uint32_t counter_id, uint32_t *counter)
{
    TEE_Result ret;
    uint8_t cmd[ART_PROCESS_COUNTER_CMD_LEN] = {0};
    uint8_t rsp[ART_PROCESS_COUNTER_RSP_LEN] = {0};
    uint32_t rsp_len = ART_PROCESS_COUNTER_RSP_LEN;

    ret = art_select_sa();
    if (ret != TEE_SUCCESS)
        return ret;

    ret = art_build_cmd(uuid, process_opt, counter_id, cmd);
    if (ret != ART_SUCCESS) {
        goto EXIT_PROCESS;
    }

    ret = TEE_SEChannelTransmit(g_art_channel, cmd, ART_PROCESS_COUNTER_CMD_LEN, rsp, &rsp_len);
    if (ret != TEE_SUCCESS) {
        tloge("%s Transmit fail=0x%x\n", __func__, ret);
        goto EXIT_PROCESS;
    }

#if ART_DEBUG_ON
    dump_data("send sa counter", cmd, ART_PROCESS_COUNTER_CMD_LEN);
    dump_data("response", rsp, rsp_len);
#endif

    ret = art_response_check(rsp, rsp_len, ART_PROCESS_COUNTER_RSP_LEN);
    if (ret != ART_SUCCESS) {
        tloge("%s response check error=0x%x\n", __func__, ret);
        goto EXIT_PROCESS;
    }

    ret = memcpy_s(counter, sizeof(uint32_t), rsp, sizeof(uint32_t));
    if (ret != EOK)
        ret = ART_TEE_FAILURE | MEMCPY_ERR;
    else
        ret = ART_SUCCESS;
#if ART_DEBUG_ON
    tloge("%s get counter=0x%x\n", __func__, *counter);
#endif

EXIT_PROCESS:
    art_deselect_sa();
    return ret;
}

/*
 * @brief     : call msp art SA to read the uuid counter.
 * @param[in] : uuid, the current TA specila id.
 *              counter_id, the id of counter have been alloced.
 * @param[out]: counter, the counter value of the uuid.
 * @return    : SUCCESS or FAIL
 */
TEE_Result art_sa_read_counter(TEE_UUID *uuid, uint32_t counter_id, uint32_t *counter)
{
    if (uuid == NULL || counter == NULL)
        return ART_TEE_FAILURE | PARA_ERR;

    return art_sa_process_counter(uuid, ART_PROCESS_READ, counter_id, counter);
}

/*
 * @brief     : call msp art SA to increase the uuid counter.
 * @param[in] : uuid, the current TA specila id.
 *              counter_id, the id of counter have been alloced.
 * @return    : SUCCESS or FAIL
 */
TEE_Result art_sa_increase_counter(TEE_UUID *uuid, uint32_t counter_id, uint32_t *counter)
{
    if (uuid == NULL || counter == NULL)
        return ART_TEE_FAILURE | PARA_ERR;

    return art_sa_process_counter(uuid, ART_PROCESS_INCREASE, counter_id, counter);
}
