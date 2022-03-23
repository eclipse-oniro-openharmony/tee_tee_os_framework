/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Secure flash sa communication.
 * Author: aaron.shen
 * Create: 2020-01-05
 */

#include "secflash_sa_comm.h"
#include "msp_tee_se_ext_api.h"
#include "tee_internal_se_api.h"
#include "tee_internal_api.h"
#include "tee_common.h"
#include "tee_log.h"
#include "securec.h"

#define ONE_BYTES_OFFSET                 1
#define TWO_BYTES_OFFSET                 2
#define ONE_BYTE_BITS_OFFSET             8

#define SECFLASH_MAX_READERS             16
#define SECFLASH_MAX_READER_LEN          16
#define SECFLASH_MAX_READ_BLOCKS_COUNT   512
#define SECFLASH_BLOCK_BYTE_LEN          16
#define SECFLASH_MAX_READ_WRITE_BYTE_LEN  (SECFLASH_MAX_READ_BLOCKS_COUNT * SECFLASH_BLOCK_BYTE_LEN)
#define SECFLASH_MAX_RSP_APDU_LEN        261
#define SECFLASH_EXTENDED_RSP_READ_LEN   256

#define SECFLASH_SUCCESS            TEE_SUCCESS

#define GP_SUCCESS_SW               0x9000
#define SECFLASH_GP_SW_RSP_LEN      2
#define GP_ADD_EXTENDED_LENGTH      2

#define SECFLASH_APDU_CMD_HEADER    5
#define SECFLASH_BASE_CMD_LEN       (SECFLASH_APDU_CMD_HEADER + sizeof(TEE_UUID))

#define SECFLASH_ALLOC_CMD_LEN      (SECFLASH_BASE_CMD_LEN + sizeof(uint32_t))

#define SECFLASH_OPEN_CMD_LEN       SECFLASH_BASE_CMD_LEN
#define SECFLASH_OPEN_RSP_LEN       (SECFLASH_GP_SW_RSP_LEN + sizeof(uint32_t))

#define SECFLASH_READ_CMD_LEN       (SECFLASH_BASE_CMD_LEN + sizeof(uint32_t) + sizeof(uint32_t))
#define SECFLASH_READ_MAX_RSP_LEN   (sizeof(uint32_t) + SECFLASH_MAX_READ_WRITE_BYTE_LEN + SECFLASH_GP_SW_RSP_LEN)

#define SECFLASH_SEEK_CMD_LEN       (SECFLASH_BASE_CMD_LEN + sizeof(uint32_t) + sizeof(uint32_t) + sizeof(uint32_t))
#define SECFLASH_SEEK_RSP_LEN       (SECFLASH_GP_SW_RSP_LEN + sizeof(uint32_t))

#define SECFLASH_GET_INFO_CMD_LEN   (SECFLASH_BASE_CMD_LEN + sizeof(uint32_t))
#define SECFLASH_GET_INFO_RSP_LEN   (sizeof(uint32_t) + sizeof(uint32_t) + SECFLASH_GP_SW_RSP_LEN)

#define SECFLASH_SA_VERSION         0x10001

/* Error num except GP SW:0x6*** */
enum ERROR_NUM {
    PARA_ERR = 0x6601,
    RESPONSE_LENGTH_ERR,
    MEMCPY_ERR,
    MALLOC_ERR,
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

enum secflash_cmd_ins {
    SECFLASH_INS_CREAT_OBJECT = 0x01,
    SECFLASH_INS_DELECT_OBJECT = 0x02,
    SECFLASH_INS_OPEN_OBJECT = 0x04,
    SECFLASH_INS_SEEK_OBJECT_DATA = 0x06,
    SECFLASH_INS_READ_OBJECT_DATA = 0x09,
    SECFLASH_INS_WRITE_OBJECT_DATA = 0x0A,
    SECFLASH_INS_GET_INFO = 0x0C,
    SECFLASH_INS_SET_CURRENT_UUID = 0x0E
};

#if SECFLASH_DEBUG_ON
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

static TEE_SEServiceHandle g_secflash_service;
static TEE_SEReaderHandle g_secflash_reader;
static TEE_SESessionHandle g_secflash_session;
static TEE_SEChannelHandle g_secflash_channel;
bool g_secflash_channel_open = false;

/*
 * @brief     : the base response check called by the APIs to check the response length and sw.
 * @param[in] : response_apdu, the pointer of response apdu to be check
 *              response_length, the apdu length,
 *              expect_response_length, the response cmd length.
 * @return    : SECFLASH_SUCCESS or others
 */
static TEE_Result secflash_response_check(const uint8_t *response_apdu, uint32_t response_length,
    uint32_t expect_response_length)
{
    uint16_t sw;

    if (response_apdu == NULL) {
        tloge("%s, Err response_apdu NULL\n", __func__);
        return SECFLASH_TEE_FAILURE | PARA_ERR;
    }

    if (response_length < SECFLASH_GP_SW_RSP_LEN) { /* '2' sw length */
        tloge("%s, Err response length\n", __func__);
        return SECFLASH_TEE_FAILURE | RESPONSE_LENGTH_ERR;
    }

    sw = (response_apdu[response_length - SECFLASH_GP_SW_RSP_LEN] << ONE_BYTE_BITS_OFFSET) +
         response_apdu[response_length - 1];
    if (sw != GP_SUCCESS_SW) { /* SUCCESS: 9000 */
        tloge("%s, Err sw:%x\n", __func__, sw);
        return SECFLASH_MSP_FAILURE | sw; /* MSP err code */
    }

    if (response_length != expect_response_length) {
        tloge("%s, Err length:%x\n", __func__, response_length);
        return SECFLASH_TEE_FAILURE | RESPONSE_LENGTH_ERR;
    }

    return SECFLASH_SUCCESS;
}

/*
 * @brief     : close the channel to msp secflash SA.
 * @param[in] : void.
 * @return    : TEE_SUCCESS or ERROR.
 */
static void secflash_close_channel(void)
{
    if (g_secflash_channel) {
        TEE_SEChannelClose(g_secflash_channel);
        g_secflash_channel = NULL;
    }
}

/*
 * @brief     : close the channel opened on the secflash session.
 * @param[in] : void.
 * @return    : TEE_SUCCESS or ERROR.
 */
static void secflash_close_session(void)
{
    if (g_secflash_session) {
        TEE_SESessionClose(g_secflash_session);
        g_secflash_session = NULL;
    }
}

/*
 * @brief     : close the session opened on the secflash reader.
 * @param[in] : void.
 * @return    : TEE_SUCCESS or ERROR.
 */
static void secflash_close_reader(void)
{
    if (g_secflash_reader) {
        TEE_SEReaderCloseSessions(g_secflash_reader);
        g_secflash_reader = NULL;
    }
}

/*
 * @brief     : release all SE resources allocated by the secflash service.
 * @param[in] : void.
 * @return    : TEE_SUCCESS or ERROR.
 */
static void secflash_close_service(void)
{
    if (g_secflash_service) {
        TEE_SEServiceClose(g_secflash_service);
        g_secflash_service = NULL;
    }
}

/*
 * @brief     : find the MSP reader.
 * @param[in] : void.
 * @return    : TEE_SUCCESS or ERROR.
 */
static TEE_Result secflash_open_msp_reader(void)
{
    TEE_Result ret;
    uint32_t i;
    uint32_t reader_count = SECFLASH_MAX_READERS;
    TEE_SEReaderHandle secflash_reader_handles[SECFLASH_MAX_READERS];
    char reader_name[SECFLASH_MAX_READER_LEN] = {0};
    uint32_t name_len = sizeof(reader_name) - 1;

    ret = TEE_SEServiceOpen(&g_secflash_service);
    if (ret != TEE_SUCCESS) {
        tloge("%s ServiceOpen fail=0x%x\n", __func__, ret);
        return ret;
    }

    ret = TEE_SEServiceGetReaders(g_secflash_service, secflash_reader_handles, &reader_count);
    if (ret != TEE_SUCCESS) {
        tloge("%s GetReaders fail=0x%x\n", __func__, ret);
        goto EXIT;
    }

    if (reader_count > SECFLASH_MAX_READERS) {
        tloge("%S readerCount is invalid 0x%x", __func__, reader_count);
        ret = SECFLASH_TEE_FAILURE | READER_COUNT_ERR;
        goto EXIT;
    }

    for (i = 0; i < reader_count; i++) {
        ret = TEE_SEReaderGetName(secflash_reader_handles[i], reader_name, &name_len);
        if (ret != TEE_SUCCESS)
            continue;
        else
            tloge("%s ReaderGetName:%s", __func__, reader_name);

        if (!strcmp(reader_name, "msp")) {
            g_secflash_reader = secflash_reader_handles[i];
            break;
        }
    }

    if (i == reader_count) {
        tloge("%s secure flash not found", __func__);
        ret = SECFLASH_TEE_FAILURE | READER_FIND_ERR;
        goto EXIT;
    }

    return ret;
EXIT:
    secflash_close_service();
    return ret;
}

/*
 * @brief     : close the MSP reader.
 * @param[in] : void.
 * @return    : TEE_SUCCESS or ERROR.
 */
static void secflash_close_msp_reader(void)
{
    secflash_close_reader();

    secflash_close_service();
}

/*
 * @brief     : open the MSP logic channel.
 * @param[in] : void.
 * @return    : TEE_SUCCESS or ERROR.
 */
static TEE_Result secflash_open_msp_channel(void)
{
    TEE_Result ret;
#ifdef SUPPORT_DYN_SECFLASH
    /* "hisi.secflash + 4 spaces + '0'" */
    uint8_t aid[] = { 0x68, 0x69, 0x73, 0x69, 0x2e, 0x73, 0x65, 0x63, 0x66, 0x6c, 0x61, 0x73, 0x68, 0x20, 0x20, 0x30 };
#else
    uint8_t aid[] = { 0x68, 0x69, 0x73, 0x69, 0x2e, 0x73, 0x65, 0x63, 0x66, 0x6c, 0x61, 0x73, 0x68, 0x20, 0x20, 0x20 };
#endif
    TEE_SEAID secflash_aid[] = { {aid, sizeof(aid)}, };
    uint32_t num_of_aids = sizeof(secflash_aid) / sizeof(secflash_aid[0]);
    uint32_t i;
    uint8_t rsp[SECFLASH_MAX_RSP_APDU_LEN];
    uint32_t rsp_len = SECFLASH_MAX_RSP_APDU_LEN;

    ret = TEE_SEReaderOpenSession(g_secflash_reader, &g_secflash_session);
    if (ret != TEE_SUCCESS) {
        tloge("%s ReaderOpenSession fail=0x%x\n", __func__, ret);
        return ret;
    }

    for (i = 0; i < num_of_aids; i++) {
        ret = TEE_SESessionOpenLogicalChannel(g_secflash_session, &secflash_aid[i], &g_secflash_channel);
        if (ret != TEE_SUCCESS) {
            tloge("%s SessionOpenLogicalChannel fail=0x%x\n", __func__, ret);
            continue;
        }

        ret = TEE_SEChannelGetSelectResponse(g_secflash_channel, rsp, &rsp_len);
        if (ret != TEE_SUCCESS) {
            tloge("%s", "Get select response failed", __func__);
            secflash_close_channel();
            continue;
        }

        ret = secflash_response_check(rsp, rsp_len, SECFLASH_GP_SW_RSP_LEN);
        if (ret != SECFLASH_SUCCESS) {
            tloge("%s Response error:0x%x len:0x%x\n", __func__, rsp_len);
            secflash_close_channel();
            continue;
        }
        break;
    }

    if (i == num_of_aids) {
        tloge("%s Open logic channel failed=0x%x", __func__, ret);
        ret = SECFLASH_TEE_FAILURE | OPEN_CHANNEL_ERR;
        goto EXIT;
    }

    g_secflash_channel_open = true;
    return ret;
EXIT:
    secflash_close_session();
    return ret;
}

/*
 * @brief     : close the MSP logic channel.
 * @param[in] : void.
 * @return    : void.
 */
static void secflash_close_msp_channel(void)
{
    if (g_secflash_channel_open == true) {
        secflash_close_channel();
        secflash_close_session();
        g_secflash_channel_open = false;
    }
}

#ifdef SUPPORT_DYN_SECFLASH
static TEE_Result secflash_applet_load_install(void)
{
    TEE_Result ret;
    /* "hisi.secflash + 5 spaces" */
    uint8_t sa_aid[] = {
        0x68, 0x69, 0x73, 0x69, 0x2e, 0x73, 0x65, 0x63,
        0x66, 0x6c, 0x61, 0x73, 0x68, 0x20, 0x20, 0x20
    };
    /* "hisi.secflash + 4 spaces + '0'" */
    uint8_t instance_id[] = {
        0x68, 0x69, 0x73, 0x69, 0x2e, 0x73, 0x65, 0x63,
        0x66, 0x6c, 0x61, 0x73, 0x68, 0x20, 0x20, 0x30
    };
    uint32_t sa_aid_len = sizeof(sa_aid);
    struct sa_status status = { 0 };
    struct sa_status_detail detail_status = { 0 };
    struct msp_install_sa_info install_sa_info;

    (void)memset_s(&install_sa_info, sizeof(install_sa_info), 0, sizeof(install_sa_info));
    ret = TEE_EXT_MSPGetStatus(&sa_aid[0], sa_aid_len, &detail_status);
    if (ret != TEE_SUCCESS && ret != TEE_ERROR_NEED_LOAD_SA) {
        tloge("%s get Status fail, ret=0x%x\n",  __func__, ret);
        return ret;
    }

    if (detail_status.sa_lfc == SA_LCS_NO_LOAD) {
        ret = TEE_EXT_MSPLoadSA(NULL, 0, &sa_aid[0], sa_aid_len);
        if (ret != TEE_SUCCESS) {
            tloge("%s load SA fail, ret=0x%x\n",  __func__, ret);
            return ret;
        }
    }

    if (detail_status.sa_lfc == SA_LCS_INSTALLED)
        return TEE_SUCCESS;

    ret = memcpy_s(install_sa_info.sa_aid, SA_AID_LEN, sa_aid, sa_aid_len);
    if (ret != EOK)
        ret = SECFLASH_TEE_FAILURE | MEMCPY_ERR;

    ret = memcpy_s(install_sa_info.sa_instance_id, SA_INSTANCE_ID_LEN, instance_id, sizeof(instance_id));
    if (ret != EOK)
        ret = SECFLASH_TEE_FAILURE | MEMCPY_ERR;

    install_sa_info.version = SECFLASH_SA_VERSION;

    ret = TEE_EXT_MSPInstallSA(&install_sa_info, &status);
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
 * @return    : TEE_SUCCESS or ERROR.
 */
static TEE_Result secflash_select_sa(void)
{
    TEE_Result ret;

#ifdef SUPPORT_DYN_SECFLASH
    ret = secflash_applet_load_install();
    if (ret != TEE_SUCCESS) {
        tloge("%s load fail=0x%x\n", __func__, ret);
        return ret;
    }
#endif

    ret = secflash_open_msp_reader();
    if (ret != TEE_SUCCESS) {
        tloge("%s GetMSP reader fail=0x%x\n", __func__, ret);
        return ret;
    }

    ret = secflash_open_msp_channel();
    if (ret != TEE_SUCCESS) {
        tloge("%s GetMSP channel fail=0x%x\n", __func__, ret);
        secflash_close_msp_reader();
        return ret;
    }

    return TEE_SUCCESS;
}

/*
 * @brief     : deselect the MSP logic channel.
 * @param[in] : void.
 * @return    : TEE_SUCCESS or ERROR.
 */
static void secflash_deselect_sa(void)
{
    secflash_close_msp_channel();

    secflash_close_msp_reader();
}

/*
 * @brief     : call msp secflash SA to alloc.
 * @param[in] : info.obj_id, the id of a TA request.
 *              info.mem_type, the type of memory of a TA request.
 *              size, the size of memory requested.
 * @return    : SUCCESS or FAIL
 */
TEE_Result secflash_sa_alloc(struct object_info info, uint32_t size)
{
    TEE_Result ret;
    uint8_t cmd[SECFLASH_ALLOC_CMD_LEN] = {0};
    uint8_t rsp[SECFLASH_GP_SW_RSP_LEN] = {0};
    uint32_t rsp_len = SECFLASH_GP_SW_RSP_LEN;

    if (info.uuid == NULL)
        return SECFLASH_TEE_FAILURE | PARA_ERR;

    ret = secflash_select_sa();
    if (ret != TEE_SUCCESS) {
        tloge("%s OpenChannel fail=0x%x\n", __func__, ret);
        return ret;
    }

    cmd[CLA] = 0x0;
    cmd[INS] = SECFLASH_INS_CREAT_OBJECT;
    cmd[P1] = info.obj_id;
    cmd[P2] = info.mem_type;
    cmd[LC] = sizeof(TEE_UUID) + sizeof(uint32_t);
    ret = memcpy_s(&cmd[CDATA], SECFLASH_ALLOC_CMD_LEN - CDATA, info.uuid, sizeof(TEE_UUID));
    ret += memcpy_s(&cmd[CDATA + sizeof(TEE_UUID)], SECFLASH_ALLOC_CMD_LEN - CDATA - sizeof(TEE_UUID),
                    &size, sizeof(uint32_t));
    if (ret != EOK) {
        ret = SECFLASH_TEE_FAILURE | MEMCPY_ERR;
        goto EXIT_PROCESS;
    }

    ret = TEE_SEChannelTransmit(g_secflash_channel, cmd, SECFLASH_ALLOC_CMD_LEN, rsp, &rsp_len);
    if (ret != TEE_SUCCESS) {
        tloge("%s Transmit fail=0x%x\n", __func__, ret);
        goto EXIT_PROCESS;
    }

#if SECFLASH_DEBUG_ON
    dump_data("send sa alloc", cmd, SECFLASH_ALLOC_CMD_LEN);
    dump_data("response", rsp, rsp_len);
#endif

    ret = secflash_response_check(rsp, rsp_len, SECFLASH_GP_SW_RSP_LEN);
    if (ret != SECFLASH_SUCCESS)
        tloge("%s response check error=0x%x\n", __func__, ret);

EXIT_PROCESS:
    secflash_deselect_sa();
    return ret;
}

/*
 * @brief     : call msp secflash SA to select the specific allocated memory.
 * @param[in] : object_info
 *                  obj_id, the id of a TA request.
 *                  mem_type,the type of memory of a TA request.
 *              len, the size pointer max length.
 * @param[out]: size, the size of memory have been alloced.
 * @return    : SUCCESS or FAIL
 */
TEE_Result secflash_sa_select(struct object_info info, uint32_t *size, uint32_t len)
{
    TEE_Result ret;
    uint8_t cmd[SECFLASH_OPEN_CMD_LEN] = {0};
    uint8_t rsp[SECFLASH_OPEN_RSP_LEN] = {0};
    uint32_t rsp_len = SECFLASH_OPEN_RSP_LEN;

    if (info.uuid == NULL || size == NULL)
        return SECFLASH_TEE_FAILURE | PARA_ERR;

    ret = secflash_select_sa();
    if (ret != TEE_SUCCESS) {
        tloge("%s OpenChannel fail=0x%x\n", __func__, ret);
        return ret;
    }

    cmd[CLA] = 0x0;
    cmd[INS] = SECFLASH_INS_OPEN_OBJECT;
    cmd[P1] = info.obj_id;
    cmd[P2] = info.mem_type;
    cmd[LC] = sizeof(TEE_UUID);
    ret = memcpy_s(&cmd[CDATA], SECFLASH_OPEN_CMD_LEN - CDATA, info.uuid, sizeof(TEE_UUID));
    if (ret != EOK) {
        ret = SECFLASH_TEE_FAILURE | MEMCPY_ERR;
        goto EXIT_PROCESS;
    }

    ret = TEE_SEChannelTransmit(g_secflash_channel, cmd, SECFLASH_OPEN_CMD_LEN, rsp, &rsp_len);
    if (ret != TEE_SUCCESS) {
        tloge("%s Transmit fail=0x%x\n", __func__, ret);
        goto EXIT_PROCESS;
    }

#if SECFLASH_DEBUG_ON
    dump_data("send sa open", cmd, SECFLASH_OPEN_CMD_LEN);
    dump_data("response", rsp, rsp_len);
#endif

    ret = secflash_response_check(rsp, rsp_len, SECFLASH_OPEN_RSP_LEN);
    if (ret != SECFLASH_SUCCESS) {
        tloge("%s response check error=0x%x\n", __func__, ret);
        goto EXIT_PROCESS;
    }

    ret = memcpy_s(size, len, rsp, sizeof(uint32_t));
    if (ret != EOK)
        ret = SECFLASH_TEE_FAILURE | MEMCPY_ERR;

#if SECFLASH_DEBUG_ON
    tloge("%s get size=0x%x\n", __func__, *size);
#endif

EXIT_PROCESS:
    secflash_deselect_sa();
    return ret;
}

/*
 * @brief     : the sa read cmd derivate before send to secflash.
 * @param[in] : info, The information of a TA request.
 *              pos, The current position of the allocated memory.
 *              size, The size of data to read.
 * @param[out]: cmd, the read cmd pointer.
 * @return    : Operation status: success(0) or other failure status
 */
static TEE_Result secflash_sa_read_cmd_derivate(struct object_info info, uint32_t pos, uint32_t size,
    uint8_t *cmd)
{
    TEE_Result ret;

    ret = secflash_select_sa();
    if (ret != TEE_SUCCESS)
        return ret;

    cmd[CLA] = 0;
    cmd[INS] = SECFLASH_INS_READ_OBJECT_DATA;
    cmd[P1] = info.obj_id;
    cmd[P2] = info.mem_type;
    cmd[LC] = 0;
    cmd[LC + ONE_BYTES_OFFSET] = (uint8_t)(SECFLASH_EXTENDED_RSP_READ_LEN >> ONE_BYTE_BITS_OFFSET);
    cmd[LC + TWO_BYTES_OFFSET] = (uint8_t)(SECFLASH_EXTENDED_RSP_READ_LEN & 0xff);

    ret = memcpy_s(&cmd[CDATA + GP_ADD_EXTENDED_LENGTH], SECFLASH_EXTENDED_RSP_READ_LEN,
                   info.uuid, sizeof(TEE_UUID));
    ret += memcpy_s(&cmd[CDATA + GP_ADD_EXTENDED_LENGTH + sizeof(TEE_UUID)],
                    SECFLASH_EXTENDED_RSP_READ_LEN - sizeof(TEE_UUID), &pos, sizeof(uint32_t));
    ret += memcpy_s(&cmd[CDATA + GP_ADD_EXTENDED_LENGTH + sizeof(TEE_UUID) + sizeof(uint32_t)],
                    SECFLASH_EXTENDED_RSP_READ_LEN - sizeof(TEE_UUID) - sizeof(uint32_t), &size, sizeof(uint32_t));
    if (ret != EOK)
        return SECFLASH_TEE_FAILURE | MEMCPY_ERR;

    return SECFLASH_SUCCESS;
}

/*
 * @brief     : call msp secflash SA to read data from the specific allocated memory.
 * @param[in] : info, The information of a TA request.
 *              pos, The current position of the allocated memory.
 *              size, The size of data to read.
 * @param[out]: buffer, The buffer to contain the read data.
 *              count, Return the actually read data size.
 * @return    : Operation status: success(0) or other failure status
 */
TEE_Result secflash_sa_read(struct object_info info, uint32_t pos, uint32_t size, uint8_t *buffer,
    uint32_t *count)
{
    TEE_Result ret;
    uint32_t read_data_length;
    uint32_t data_length;
    uint8_t *cmd = NULL;
    uint8_t *rsp = NULL;

    if (info.uuid == NULL || buffer == NULL || count == NULL || size > SECFLASH_MAX_READ_WRITE_BYTE_LEN)
        return SECFLASH_TEE_FAILURE | PARA_ERR;

    data_length = CDATA + GP_ADD_EXTENDED_LENGTH + SECFLASH_EXTENDED_RSP_READ_LEN;
    cmd = TEE_Malloc(data_length, 0);
    if (cmd == NULL)
        return SECFLASH_TEE_FAILURE | MALLOC_ERR;

    ret =  secflash_sa_read_cmd_derivate(info, pos, size, cmd);
    if (ret != SECFLASH_SUCCESS)
        goto EXIT_PROCESS;

    read_data_length = sizeof(uint32_t) + size + SECFLASH_GP_SW_RSP_LEN;
    rsp = TEE_Malloc(read_data_length, 0);
    if (rsp == NULL) {
        ret = SECFLASH_TEE_FAILURE | MALLOC_ERR;
        goto EXIT_PROCESS;
    }

    ret = TEE_SEChannelTransmit(g_secflash_channel, cmd, data_length, rsp, &read_data_length);
    if (ret != TEE_SUCCESS)
        goto EXIT_PROCESS;

#if SECFLASH_DEBUG_ON
    dump_data("response", rsp, read_data_length);
#endif

    ret = secflash_response_check(rsp, read_data_length, sizeof(uint32_t) + size + SECFLASH_GP_SW_RSP_LEN);
    if (ret != SECFLASH_SUCCESS)
        goto EXIT_PROCESS;

    ret = memcpy_s(count, sizeof(uint32_t), rsp, sizeof(uint32_t));
    ret += memcpy_s(buffer, size, (uint8_t *)(rsp + sizeof(uint32_t)), *count);
    if (ret != EOK) {
        ret = SECFLASH_TEE_FAILURE | MEMCPY_ERR;
        goto EXIT_PROCESS;
    }

EXIT_PROCESS:
    if (cmd != NULL) {
        TEE_Free(cmd);
        cmd = NULL;
    }

    if (rsp != NULL) {
        TEE_Free(rsp);
        rsp = NULL;
    }

    secflash_deselect_sa();
    return ret;
}

/*
 * @brief     : the sa write cmd derivate before send to secflash.
 * @param[in] : info, The information of a TA request.
 *              pos, The current position of the allocated memory.
 *              size, The size of data to write.
 *              buffer, The buffer containing data to write.
 * @param[out]: cmd, the write cmd pointer.
 * @return    : Operation status: success(0) or other failure status
 */
static TEE_Result secflash_sa_write_cmd_derivate(struct object_info info, uint32_t pos, uint32_t size,
    uint8_t *buffer, uint8_t *cmd)
{
    TEE_Result ret;
    uint8_t extended_length = 0;
    uint32_t data_length;

    data_length = sizeof(TEE_UUID) + sizeof(uint32_t) + sizeof(uint32_t) + size;  /* uuid / pos / size / data */
    if (data_length > 0xff)
        extended_length = 1; /* extended length */

    ret = secflash_select_sa();
    if (ret != TEE_SUCCESS)
        return ret;

    cmd[CLA] = 0x0;
    cmd[INS] = SECFLASH_INS_WRITE_OBJECT_DATA;
    cmd[P1] = info.obj_id;
    cmd[P2] = info.mem_type;
    if (extended_length == 0) {
        cmd[LC] = data_length;
    } else {
        cmd[LC] = 0;
        cmd[LC + ONE_BYTES_OFFSET] = (uint8_t)(data_length >> ONE_BYTE_BITS_OFFSET);
        cmd[LC + TWO_BYTES_OFFSET] = (uint8_t)(data_length & 0xff);
    }
    ret = memcpy_s(&cmd[CDATA + extended_length * GP_ADD_EXTENDED_LENGTH], data_length,
                   info.uuid, sizeof(TEE_UUID));
    ret += memcpy_s(&cmd[CDATA + extended_length * GP_ADD_EXTENDED_LENGTH + sizeof(TEE_UUID)],
                    data_length - sizeof(TEE_UUID), &pos, sizeof(uint32_t));
    ret += memcpy_s(&cmd[CDATA + extended_length * GP_ADD_EXTENDED_LENGTH + sizeof(TEE_UUID) + sizeof(uint32_t)],
                    data_length - sizeof(TEE_UUID) - sizeof(uint32_t), &size, sizeof(uint32_t));
    ret += memcpy_s(&cmd[CDATA + extended_length * GP_ADD_EXTENDED_LENGTH + sizeof(TEE_UUID) + sizeof(uint32_t)
                         + sizeof(uint32_t)], size, buffer, size);
    if (ret != EOK)
        return SECFLASH_TEE_FAILURE | MEMCPY_ERR;

    return SECFLASH_SUCCESS;
}

/*
 * @brief     : call msp secflash SA to write data into the specific allocated memory.
 * @param[in] : info, The information of a TA request.
 *              pos, The current position of the allocated memory.
 *              size, The size of data to write.
 *              buffer, The buffer containing data to write.
 * @param[out]: void.
 * @return    : Operation status: success(0) or other failure status
 */
TEE_Result secflash_sa_write(struct object_info info, uint32_t pos, uint32_t size, uint8_t *buffer)
{
    TEE_Result ret;
    uint8_t extended_length = 0;
    uint32_t data_length;
    uint8_t *cmd = NULL;
    uint8_t rsp[SECFLASH_GP_SW_RSP_LEN] = {0};
    uint32_t rsp_len = SECFLASH_GP_SW_RSP_LEN;

    if (info.uuid == NULL || buffer == NULL || size > SECFLASH_MAX_READ_WRITE_BYTE_LEN)
        return SECFLASH_TEE_FAILURE | PARA_ERR;

    data_length = sizeof(TEE_UUID) + sizeof(uint32_t) + sizeof(uint32_t) + size;  /* uuid / pos / size / data */
    if (data_length > 0xff)
        extended_length = 1; /* extended length */

    cmd = TEE_Malloc(CDATA + extended_length * GP_ADD_EXTENDED_LENGTH + data_length, 0);
    if (cmd == NULL)
        return SECFLASH_TEE_FAILURE | MALLOC_ERR;

    ret =  secflash_sa_write_cmd_derivate(info, pos, size, buffer, cmd);
    if (ret != SECFLASH_SUCCESS)
        goto EXIT_PROCESS;

    ret = TEE_SEChannelTransmit(g_secflash_channel, cmd, CDATA + extended_length * GP_ADD_EXTENDED_LENGTH + data_length,
                                rsp, &rsp_len);
    if (ret != TEE_SUCCESS)
        goto EXIT_PROCESS;

#if SECFLASH_DEBUG_ON
    dump_data("send sa write", cmd, CDATA + extended_length * GP_ADD_EXTENDED_LENGTH + data_length);
    dump_data("response", rsp, rsp_len);
#endif

    ret = secflash_response_check(rsp, rsp_len, SECFLASH_GP_SW_RSP_LEN);
    if (ret != SECFLASH_SUCCESS)
        tloge("%s response check error=0x%x\n", __func__, ret);

EXIT_PROCESS:
    if (cmd != NULL) {
        TEE_Free(cmd);
        cmd = NULL;
    }
    secflash_deselect_sa();
    return ret;
}

/*
 * @brief     : call msp secflash SA to change the current position of the specific allocated memory.
 * @param[in] : info, The information of a TA request.
 *              pos, The current position of the allocated memory.
 *              offset, The value to be used for changing the position.
 *              whence, The postion changing way.
 * @param[out]: pos, The changed position
 * @return    : Operation status: success(0) or other failure status
 */
TEE_Result secflash_sa_set_offset(struct object_info info, uint32_t *pos, int32_t offset, TEE_Whence whence)
{
    TEE_Result ret;
    uint8_t cmd[SECFLASH_SEEK_CMD_LEN] = {0};
    uint8_t rsp[SECFLASH_SEEK_RSP_LEN] = {0};
    uint32_t rsp_len = SECFLASH_SEEK_RSP_LEN;

    if (info.uuid == NULL || pos == NULL)
        return SECFLASH_TEE_FAILURE | PARA_ERR;

    ret = secflash_select_sa();
    if (ret != TEE_SUCCESS)
        return ret;

    cmd[CLA] = 0x0;
    cmd[INS] = SECFLASH_INS_SEEK_OBJECT_DATA;
    cmd[P1] = info.obj_id;
    cmd[P2] = info.mem_type;
    cmd[LC] = sizeof(TEE_UUID) + sizeof(uint32_t) + sizeof(uint32_t) + sizeof(uint32_t); /* uuid/ pos/ size/ whence */
    ret = memcpy_s(&cmd[CDATA], SECFLASH_SEEK_CMD_LEN - CDATA, info.uuid, sizeof(TEE_UUID));
    ret += memcpy_s(&cmd[CDATA + sizeof(TEE_UUID)], SECFLASH_SEEK_CMD_LEN - CDATA - sizeof(TEE_UUID),
                    pos, sizeof(uint32_t));
    ret += memcpy_s(&cmd[CDATA + sizeof(TEE_UUID) + sizeof(uint32_t)],
                    SECFLASH_SEEK_CMD_LEN - CDATA - sizeof(TEE_UUID) - sizeof(uint32_t), &offset, sizeof(uint32_t));
    ret += memcpy_s(&cmd[CDATA + sizeof(TEE_UUID) + sizeof(uint32_t) + sizeof(uint32_t)],
                    SECFLASH_SEEK_CMD_LEN - CDATA - sizeof(TEE_UUID) - sizeof(uint32_t) - sizeof(uint32_t),
                    &whence, sizeof(uint32_t));
    if (ret != EOK) {
        ret = SECFLASH_TEE_FAILURE | MEMCPY_ERR;
        goto EXIT_PROCESS;
    }

    ret = TEE_SEChannelTransmit(g_secflash_channel, cmd, SECFLASH_SEEK_CMD_LEN, rsp, &rsp_len);
    if (ret != TEE_SUCCESS) {
        tloge("%s Transmit fail=0x%x\n", __func__, ret);
        goto EXIT_PROCESS;
    }

#if SECFLASH_DEBUG_ON
    dump_data("send sa seek", cmd, SECFLASH_SEEK_CMD_LEN);
    dump_data("response", rsp, rsp_len);
#endif

    ret = secflash_response_check(rsp, rsp_len, SECFLASH_SEEK_RSP_LEN);
    if (ret != SECFLASH_SUCCESS)
        goto EXIT_PROCESS;

    ret = memcpy_s(pos, sizeof(uint32_t), rsp, sizeof(uint32_t));
    if (ret != EOK)
        ret = SECFLASH_TEE_FAILURE | MEMCPY_ERR;

#if SECFLASH_DEBUG_ON
    tloge("%s get pos=0x%x\n", __func__, *pos);
#endif

EXIT_PROCESS:
    secflash_deselect_sa();
    return ret;
}

/*
 * @brief     : call msp secflash SA to free the specific type allocated memory.
 * @param[in] : obj_info, The information of a TA request.
 * @param[out]: void
 * @return    : Operation status: success(0) or other failure status
 */
TEE_Result secflash_sa_free(struct object_info info)
{
    TEE_Result ret;
    uint8_t cmd[SECFLASH_BASE_CMD_LEN] = {0};
    uint8_t rsp[SECFLASH_GP_SW_RSP_LEN] = {0};
    uint32_t rsp_len = SECFLASH_GP_SW_RSP_LEN;

    if (info.uuid == NULL)
        return SECFLASH_TEE_FAILURE | PARA_ERR;

    ret = secflash_select_sa();
    if (ret != TEE_SUCCESS) {
        tloge("%s OpenChannel fail=0x%x\n", __func__, ret);
        return ret;
    }

    cmd[CLA] = 0x0;
    cmd[INS] = SECFLASH_INS_DELECT_OBJECT;
    cmd[P1] = info.obj_id;
    cmd[P2] = info.mem_type;
    cmd[LC] = sizeof(TEE_UUID);
    ret = memcpy_s(&cmd[CDATA], SECFLASH_BASE_CMD_LEN - CDATA, info.uuid, sizeof(TEE_UUID));
    if (ret != EOK) {
        ret = SECFLASH_TEE_FAILURE | MEMCPY_ERR;
        goto EXIT_PROCESS;
    }

    ret = TEE_SEChannelTransmit(g_secflash_channel, cmd, SECFLASH_BASE_CMD_LEN, rsp, &rsp_len);
    if (ret != TEE_SUCCESS) {
        tloge("%s Transmit fail=0x%x\n", __func__, ret);
        goto EXIT_PROCESS;
    }

#if SECFLASH_DEBUG_ON
    dump_data("send sa free", cmd, SECFLASH_BASE_CMD_LEN);
    dump_data("response", rsp, rsp_len);
#endif

    ret = secflash_response_check(rsp, rsp_len, SECFLASH_GP_SW_RSP_LEN);
    if (ret != SECFLASH_SUCCESS) {
        tloge("%s response check error=0x%x\n", __func__, ret);
        goto EXIT_PROCESS;
    }

EXIT_PROCESS:
    secflash_deselect_sa();
    return ret;
}

/*
 * @brief     : call msp secflash SA to get the current position and size of allocated memory.
 * @param[in] : obj_info, The information of a TA request.
 *              cur_pos, The current position of the allocated memory.
 * @param[out]: pos, Set to the valid current position.
 *              len, Set to be the size of the allocated memory.
 * @return    : Operation status: success(0) or other failure status
 */
TEE_Result secflash_sa_get_info(struct object_info info, uint32_t cur_pos, uint32_t *pos, uint32_t *len)
{
    TEE_Result ret;
    uint8_t cmd[SECFLASH_GET_INFO_CMD_LEN] = {0};
    uint8_t rsp[SECFLASH_GET_INFO_RSP_LEN] = {0};
    uint32_t rsp_len = SECFLASH_GET_INFO_RSP_LEN;

    if (info.uuid == NULL)
        return SECFLASH_TEE_FAILURE | PARA_ERR;

    ret = secflash_select_sa();
    if (ret != TEE_SUCCESS) {
        tloge("%s OpenChannel fail=0x%x\n", __func__, ret);
        return ret;
    }

    cmd[CLA] = 0x0;
    cmd[INS] = SECFLASH_INS_GET_INFO;
    cmd[P1] = info.obj_id;
    cmd[P2] = info.mem_type;
    cmd[LC] = sizeof(TEE_UUID) + sizeof(uint32_t);
    ret = memcpy_s(&cmd[CDATA], SECFLASH_GET_INFO_CMD_LEN - CDATA, info.uuid, sizeof(TEE_UUID));
    ret += memcpy_s(&cmd[CDATA + sizeof(TEE_UUID)], SECFLASH_GET_INFO_CMD_LEN - CDATA - sizeof(TEE_UUID),
                    &cur_pos, sizeof(uint32_t));
    if (ret != EOK) {
        ret = SECFLASH_TEE_FAILURE | MEMCPY_ERR;
        goto EXIT_PROCESS;
    }

    ret = TEE_SEChannelTransmit(g_secflash_channel, cmd, SECFLASH_GET_INFO_CMD_LEN, rsp, &rsp_len);
    if (ret != TEE_SUCCESS) {
        tloge("%s Transmit fail=0x%x\n", __func__, ret);
        goto EXIT_PROCESS;
    }

#if SECFLASH_DEBUG_ON
    dump_data("send sa get info", cmd, SECFLASH_GET_INFO_CMD_LEN);
    dump_data("response", rsp, rsp_len);
#endif

    ret = secflash_response_check(rsp, rsp_len, SECFLASH_GET_INFO_RSP_LEN);
    if (ret != SECFLASH_SUCCESS) {
        tloge("%s response check error=0x%x\n", __func__, ret);
        goto EXIT_PROCESS;
    }

    ret = memcpy_s(pos, sizeof(uint32_t), rsp, sizeof(uint32_t));
    ret += memcpy_s(len, sizeof(uint32_t), (uint8_t *)(rsp + sizeof(uint32_t)), sizeof(uint32_t));
    if (ret != EOK)
        ret = SECFLASH_TEE_FAILURE | MEMCPY_ERR;

#if SECFLASH_DEBUG_ON
    tloge("%s get pos=0x%x len=0x%x\n", __func__, *pos, *len);
#endif

EXIT_PROCESS:
    secflash_deselect_sa();
    return ret;
}

