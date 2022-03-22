/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: samgr common func.
 * Author: x00225909
 * Create: 2020-07-02
 * Notes:
 * History: 2020-07-02 x00225909 create
 */
#include "samgr_common.h"
#include <hm_msg_type.h>
#include "hisee_try_catch.h"
#include "msg_ops.h"
#include "msp_tee_se_ext_api.h"
#include "msp_tee_se_ext_api_tlv.h"
#include "securec.h"
#include "sre_syscall.h"
#include "tee_commom_public_service.h"
#include "tee_common.h"
#include "tee_internal_api.h"
#include "tee_internal_se_api.h"
#include "tee_log.h"

#define TEE_MAX_READER_NUM 16
#define READER_NAME_LEN 0x10

#define APDU_RES_MAX_LENGTH 256
#define BITS_OF_BYTE 8

#define SW_CMD_RSP_SUCC 0x9000

#define SW_ALREADY_INSTALLED_SA 0x6A29
#define SW_NOT_NEED_LOAD_SA 0x6A2d
#define SW_NEED_LOAD_SA 0x6A2e
#define SW_SA_NEED_UPDATE_SA 0x6A2f
#define SW_NVM_DATA_SIZE_DIFF 0x6A30

#define SA_MGR_ID_LEN 8

#define BASIC_CHANNEL 0
#define LOGICAL_CHANNEL 1

#define OPEN_BASIC_CHANNEL_TIMEOUT 100

struct msg_buffer {
    void *buffer;
    uint32_t buffer_len;
};

static uint32_t msp_tee_se_ext_malloc_buffer(struct msg_buffer *buffer, uint32_t len)
{
    __TRY
    {
        buffer->buffer = (char *)TEE_Malloc(len, 0);
        throw_if_null(buffer->buffer, TEE_ERROR_OUT_OF_MEMORY);
        buffer->buffer_len = len;
        return TEE_SUCCESS;
    }
    __CATCH
    {
        return ERR_CODE;
    }
}

/* char-->u8 */
static uint32_t msp_tee_se_ext_get_sw_from_apdu_repsonse(const uint8_t *response, uint32_t response_len, uint16_t *sw)
{
    __TRY
    {
        throw_if(response_len > APDU_RES_MAX_LENGTH, TEE_ERROR_BAD_PARAMETERS);
        throw_if(response_len < APDU_RES_MIN_LENGTH, TEE_ERROR_BAD_PARAMETERS);
        throw_if_null(response, TEE_ERROR_BAD_PARAMETERS);
        throw_if_null(sw, TEE_ERROR_BAD_PARAMETERS);

        /* the last 2 bytes of response is status words */
        *sw = (uint8_t)response[response_len - 1] | ((uint8_t)response[response_len - 2] << BITS_OF_BYTE);
        return TEE_SUCCESS;
    }
    __CATCH
    {
        return ERR_CODE;
    }
}

static TEE_Result msp_install_for_load(TEE_SEChannelHandle channel_handle, const uint8_t *sa_aid, uint32_t sa_aid_len,
                                       uint32_t image_size)
{
    TEE_Result result;
    struct apdu_install_for_load command = {0};
    struct msg_buffer response = {0};
    uint16_t sw;

    __TRY
    {
        throw_if_null(sa_aid, TEE_ERROR_BAD_PARAMETERS);
        throw_if(sa_aid_len != SA_AID_LEN, TEE_ERROR_BAD_PARAMETERS);

        /* malloc response mem */
        result = msp_tee_se_ext_malloc_buffer(&response, APDU_RES_MAX_LENGTH);
        throw_if(result != TEE_SUCCESS, result);

        result = msp_tee_se_set_install_for_load(&command, sa_aid, sa_aid_len, image_size);
        throw_if(result != TEE_SUCCESS, TEE_ERROR_GENERIC);

        /* send msg to msp */
        result =
            TEE_SEChannelTransmit(channel_handle, &command, sizeof(command), response.buffer, &response.buffer_len);
        throw_if(result != TEE_SUCCESS, result);

        result = msp_tee_se_ext_get_sw_from_apdu_repsonse(response.buffer, response.buffer_len, &sw);
        throw_if(result != TEE_SUCCESS, result);

        throw_if((sw != SW_CMD_RSP_SUCC) && (sw != SW_NOT_NEED_LOAD_SA),
                 TEE_ERROR_GENERIC);

        TEE_Free(response.buffer);
        response.buffer = NULL;
        return TEE_SUCCESS;
    }
    __CATCH
    {
        if (response.buffer != NULL) {
            TEE_Free(response.buffer);
            response.buffer = NULL;
        }
        return ERR_CODE;
    }
}

static TEE_Result msp_load(TEE_SEChannelHandle channel_handle, const uint8_t *sa_image, uint32_t sa_image_len)
{
    TEE_Result result;
    uint8_t *command = NULL;
    struct msg_buffer response = {0};
    struct command_info_load_sa com_msg = {0};
    uint16_t sw;

    __TRY
    {
        /* malloc command mem */
        command = TEE_Malloc(EXT_APDU_HEADER_LEN + MAX_EXT_APDU_DATA_LEN + 1, 0);
        throw_if_null(command, TEE_ERROR_OUT_OF_MEMORY);

        /* malloc response mem */
        result = msp_tee_se_ext_malloc_buffer(&response, APDU_RES_MAX_LENGTH);
        throw_if(result != TEE_SUCCESS, result);

        (void)memset_s(&com_msg, sizeof(com_msg), 0, sizeof(com_msg));
        com_msg.left_len = sa_image_len;

        while ((com_msg.left_len) > 0) {
            /*
             * left length is:
             * (a) more than max extended apdu data length
             * (b) less than max extended apdu data length, more than max standard
             * apdu data (c) length less than max standard apdu data length
             */
            result = msp_tee_se_set_load_command_apdu(command, &com_msg, sa_image);
            throw_if(result != TEE_SUCCESS, result);

            result = TEE_SEChannelTransmit(channel_handle, command, com_msg.command_len, response.buffer,
                                           &response.buffer_len);
            throw_if(result != TEE_SUCCESS, result);

            result = msp_tee_se_ext_get_sw_from_apdu_repsonse(response.buffer, response.buffer_len, &sw);
            throw_if(result != TEE_SUCCESS, result);

            if (sw == SW_NOT_NEED_LOAD_SA)
                break;
            throw_if(sw != SW_CMD_RSP_SUCC, TEE_ERROR_GENERIC);
        }

        TEE_Free(command);
        command = NULL;
        TEE_Free(response.buffer);
        response.buffer = NULL;
        return TEE_SUCCESS;
    }
    __CATCH
    {
        if (command != NULL) {
            TEE_Free(command);
            command = NULL;
        }
        if (response.buffer != NULL) {
            TEE_Free(response.buffer);
            response.buffer = NULL;
        }
        return ERR_CODE;
    }

    return result;
}

static TEE_Result msp_open_channel(TEE_SESessionHandle *session_handle,
                                   TEE_SEChannelHandle *channel_handle, uint32_t channel)
{
    TEE_Result result;
    TEE_SEAID seaid;
    uint8_t sa_mgr_id[SA_MGR_ID_LEN] = {0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00};
    uint32_t timeout = OPEN_BASIC_CHANNEL_TIMEOUT;

    seaid.buffer = sa_mgr_id;
    seaid.bufferLen = sizeof(sa_mgr_id);

    if (channel == LOGICAL_CHANNEL) {
        result = TEE_SESessionOpenLogicalChannel(*session_handle, &seaid, channel_handle);
        return result;
    }

    while (1) {
        result = TEE_SESessionOpenBasicChannel(*session_handle, &seaid, channel_handle);
        if (result == TEE_SUCCESS || result != TEE_ERROR_ACCESS_CONFLICT)
            return result;

        __SRE_SwMsleep(1);
        timeout--;
        if (timeout == 0) {
            tloge("retry open basic channel timeout!\n");
            return result;
        }
    };
}

static void msp_disconnect(TEE_SEServiceHandle *service_handle, TEE_SESessionHandle *session_handle,
                           TEE_SEChannelHandle *channel_handle)
{
    if (*channel_handle != NULL) {
        TEE_SEChannelClose(*channel_handle);
        *channel_handle = NULL;
    }

    if (*session_handle != NULL) {
        TEE_SESessionClose(*session_handle);
        *session_handle = NULL;
    }

    if (*service_handle != NULL) {
        TEE_SEServiceClose(*service_handle);
        *service_handle = NULL;
    }
}

static TEE_Result msp_connect(TEE_SEServiceHandle *service_handle, TEE_SEReaderHandle *reader_handle_list,
                              TEE_SESessionHandle *session_handle, TEE_SEChannelHandle *channel_handle,
                              uint32_t channel)
{
    TEE_Result result;
    uint32_t reader_count = TEE_MAX_READER_NUM;
    char reader_name[READER_NAME_LEN] = {0};
    uint32_t reader_name_len;
    uint8_t i;

    __TRY
    {
        result = TEE_SEServiceOpen(service_handle);
        throw_if(result != TEE_SUCCESS, result);

        result = TEE_SEServiceGetReaders(*service_handle, reader_handle_list, &reader_count);
        throw_if(result != TEE_SUCCESS, result);

        throw_if_with_para(reader_count > TEE_MAX_READER_NUM, TEE_ERROR_GENERIC, reader_count);

        for (i = 0; i < reader_count; i++) {
            reader_name_len = READER_NAME_LEN;
            result = TEE_SEReaderGetName(reader_handle_list[i], reader_name, &reader_name_len);
            if (result != TEE_SUCCESS) {
                continue;
            }
            if (memcmp(reader_name, "msp", reader_name_len) == 0) {
                break;
            }
        }
        if (i == reader_count) {
            result = TEE_ERROR_ITEM_NOT_FOUND;
            throw_if(result != TEE_SUCCESS, result);
        }
        result = TEE_SEReaderOpenSession(reader_handle_list[i], session_handle);
        throw_if(result != TEE_SUCCESS, result);

        result = msp_open_channel(session_handle, channel_handle, channel);
        throw_if(result != TEE_SUCCESS, result);

        return TEE_SUCCESS;
    }
    __CATCH
    {
        msp_disconnect(service_handle, session_handle, channel_handle);
        return ERR_CODE;
    }
}

/*
 * @brief      : sa mgr load sa
 * @param[in]  : sa_image, the sa image
 * @param[in]  : sa_image_len, the length of the sa image
 * @param[in]  : sa_aid, the sa aid
 * @param[in]  : sa_aid_len, the length of the sa aid
 * @return     : TEE_Result
 */
TEE_Result sa_mgr_load_sa(const uint8_t *sa_image, uint32_t sa_image_len, const uint8_t *sa_aid, uint32_t sa_aid_len)
{
    TEE_Result result;
    TEE_SEServiceHandle service_handle = NULL;
    TEE_SEReaderHandle reader_handle_list[TEE_MAX_READER_NUM] = {0};
    TEE_SESessionHandle session_handle = NULL;
    TEE_SEChannelHandle channel_handle = NULL;

    __TRY
    {
        throw_if_null(sa_aid, TEE_ERROR_BAD_PARAMETERS);
        throw_if(sa_aid_len != SA_AID_LEN, TEE_ERROR_BAD_PARAMETERS);

        result =
            msp_connect(&service_handle, reader_handle_list, &session_handle, &channel_handle, BASIC_CHANNEL);
        throw_if(result != TEE_SUCCESS, result);

        if (sa_image_len == 0) {
            /* for pre-installed SA: strongbox, weaver, ROT etc */
            result = msp_install_for_load(channel_handle, sa_aid, sa_aid_len, sa_image_len);
            throw_if(result != TEE_SUCCESS, result);
        } else {
            /* for post_loaded SA: facial, fingerprint */
            throw_if_null(sa_image, TEE_ERROR_BAD_PARAMETERS);
            result = msp_install_for_load(channel_handle, sa_aid, sa_aid_len, sa_image_len);
            throw_if(result != TEE_SUCCESS, result);

            result = msp_load(channel_handle, sa_image, sa_image_len);
            throw_if(result != TEE_SUCCESS, result);
        }

        msp_disconnect(&service_handle, &session_handle, &channel_handle);
        return TEE_SUCCESS;
    }
    __CATCH
    {
        msp_disconnect(&service_handle, &session_handle, &channel_handle);
        return ERR_CODE;
    }
}

static TEE_Result msp_install_for_install(TEE_SEChannelHandle channel_handle,
                                          const struct msp_install_sa_info *install_sa_info,
                                          struct sa_status_detail *status)
{
    TEE_Result result;
    struct apdu_install_for_install command = {0};
    struct msg_buffer response = {0};
    uint16_t sw;

    __TRY
    {
        /* malloc response mem */
        result = msp_tee_se_ext_malloc_buffer(&response, APDU_RES_MAX_LENGTH);
        throw_if(result != TEE_SUCCESS, result);

        /* set apdu command */
        result = msp_tee_se_set_install_for_install(&command, install_sa_info);
        throw_if(result != TEE_SUCCESS, result);

        result =
            TEE_SEChannelTransmit(channel_handle, &command, sizeof(command), response.buffer, &response.buffer_len);
        throw_if(result != TEE_SUCCESS, result);

        /* get the sa status from the response */
        result = msp_tee_se_get_sa_status_from_apdu_repsonse(response.buffer, response.buffer_len, status);
        throw_if(result != TEE_SUCCESS, result);

        /* get the sw from the response */
        result = msp_tee_se_ext_get_sw_from_apdu_repsonse(response.buffer, response.buffer_len, &sw);
        throw_if(result != TEE_SUCCESS, result);

        throw_if(sw == SW_NEED_LOAD_SA, TEE_ERROR_NEED_LOAD_SA);
        throw_if(sw == SW_ALREADY_INSTALLED_SA, TEE_ERROR_ALREADY_INSTALLED_SA);
        throw_if(sw == SW_SA_NEED_UPDATE_SA, TEE_ERROR_NEED_UPDATE_SA);
        throw_if(sw == SW_NVM_DATA_SIZE_DIFF, TEE_ERROR_NVM_DATA_SIZE_DIFF);
        throw_if(sw != SW_CMD_RSP_SUCC, TEE_ERROR_GENERIC);

        TEE_Free(response.buffer);
        response.buffer = NULL;

        return TEE_SUCCESS;
    }
    __CATCH
    {
        if (response.buffer) {
            TEE_Free(response.buffer);
            response.buffer = NULL;
        }
        return ERR_CODE;
    }
}

/*
 * @brief      : sa mgr install sa
 * @param[in]  : install_sa_info, the info about installing sa, see the struct msp_install_sa_info
 * @param[out] : status, the sa status, see the struct sa_status
 * @return     : TEE_Result
 */
TEE_Result sa_mgr_install_sa(const struct msp_install_sa_info *install_sa_info, struct sa_status *status)
{
    TEE_Result result;
    TEE_SEServiceHandle service_handle = NULL;
    TEE_SEReaderHandle reader_handle_list[TEE_MAX_READER_NUM] = {0};
    TEE_SESessionHandle session_handle = NULL;
    TEE_SEChannelHandle channel_handle = NULL;
    struct sa_status_detail status_detail = {0};

    __TRY
    {
        throw_if_null(install_sa_info, TEE_ERROR_BAD_PARAMETERS);
        throw_if_null(status, TEE_ERROR_BAD_PARAMETERS);

        /* the 15 bytes of sa_intance_id need be same as the sa_aid, not support multi-instance now */
        throw_if(memcmp(install_sa_info->sa_aid, install_sa_info->sa_instance_id, SA_AID_LEN - 1) != 0,
                 TEE_ERROR_BAD_PARAMETERS);
        /* the last byte of sa_intance_id need be '0'~'9', not support multi-instance now */
        throw_if((install_sa_info->sa_instance_id)[SA_AID_LEN - 1] > '9', TEE_ERROR_BAD_PARAMETERS);
        throw_if((install_sa_info->sa_instance_id)[SA_AID_LEN - 1] < '0', TEE_ERROR_BAD_PARAMETERS);

        /* connect msp */
        result =
            msp_connect(&service_handle, reader_handle_list, &session_handle, &channel_handle, BASIC_CHANNEL);
        throw_if(result != TEE_SUCCESS, result);

        /* send install msg */
        result = msp_install_for_install(channel_handle, install_sa_info, &status_detail);
        throw_if(result != TEE_SUCCESS, result);

        status->sa_version = status_detail.sa_version;
        status->sa_lfc = status_detail.sa_lfc;
        status->sa_instance_num = status_detail.sa_instance_num;

        result = memcpy_s(&status->instance_status, sizeof(status->instance_status), &status_detail.instance_status,
                          sizeof(status_detail.instance_status));
        throw_if(result != EOK, TEE_ERROR_SECURITY);

        msp_disconnect(&service_handle, &session_handle, &channel_handle);

        return result;
    }
    __CATCH
    {
        msp_disconnect(&service_handle, &session_handle, &channel_handle);
        return ERR_CODE;
    }
}

static TEE_Result msp_tee_se_get_sa_status(TEE_SEChannelHandle channel_handle,
                                           const uint8_t *sa_aid, uint32_t sa_aid_len,
                                           struct sa_status_detail *status)
{
    TEE_Result result;
    struct apdu_get_status_private command = {0};
    struct msg_buffer response = {0};
    uint16_t sw;

    __TRY
    {
        throw_if_null(sa_aid, TEE_ERROR_BAD_PARAMETERS);
        throw_if(sa_aid_len != SA_AID_LEN, TEE_ERROR_BAD_PARAMETERS);
        throw_if_null(status, TEE_ERROR_BAD_PARAMETERS);

        result = msp_tee_se_ext_malloc_buffer(&response, APDU_RES_MAX_LENGTH);
        throw_if(result != TEE_SUCCESS, result);

        /* add apdu command header */
        result = msp_tee_se_set_get_sa_status(&command, sa_aid, sa_aid_len);

        result =
            TEE_SEChannelTransmit(channel_handle, &command, sizeof(command), response.buffer, &response.buffer_len);
        throw_if(result != TEE_SUCCESS, result);

        /* get the sw from the response */
        result = msp_tee_se_ext_get_sw_from_apdu_repsonse(response.buffer, response.buffer_len, &sw);
        throw_if(result != TEE_SUCCESS, result);
        throw_if(sw == SW_NEED_LOAD_SA, TEE_ERROR_NEED_LOAD_SA);
        throw_if(sw != SW_CMD_RSP_SUCC, TEE_ERROR_GENERIC);

        result = msp_tee_se_get_sa_status_from_apdu_repsonse(response.buffer, response.buffer_len, status);
        throw_if(result != TEE_SUCCESS, result);

        TEE_Free(response.buffer);
        response.buffer = NULL;
        return result;
    }
    __CATCH
    {
        if (response.buffer) {
            TEE_Free(response.buffer);
            response.buffer = NULL;
        }
        return ERR_CODE;
    }
}

/*
 * @brief      : sa mgr get sa status
 * @param[in]  : sa_aid, the sa aid
 * @param[in]  : sa_aid_len, the length of sa aid
 * @param[out] : status, the sa status, see the struct sa_status_detail
 * @return     : TEE_Result
 */
TEE_Result sa_mgr_get_sa_status(const uint8_t *sa_aid, uint32_t sa_aid_len, struct sa_status_detail *status)
{
    TEE_Result result;
    TEE_SEServiceHandle service_handle = NULL;
    TEE_SEReaderHandle reader_handle_list[TEE_MAX_READER_NUM] = {0};
    TEE_SESessionHandle session_handle = NULL;
    TEE_SEChannelHandle channel_handle = NULL;

    __TRY
    {
        throw_if_null(sa_aid, TEE_ERROR_BAD_PARAMETERS);
        throw_if_null(status, TEE_ERROR_BAD_PARAMETERS);
        throw_if(sa_aid_len != SA_AID_LEN, TEE_ERROR_BAD_PARAMETERS);

        result =
            msp_connect(&service_handle, reader_handle_list, &session_handle, &channel_handle, LOGICAL_CHANNEL);
        throw_if(result != TEE_SUCCESS, result);

        result = msp_tee_se_get_sa_status(channel_handle, sa_aid, sa_aid_len, status);
        throw_if(result != TEE_SUCCESS, result);

        msp_disconnect(&service_handle, &session_handle, &channel_handle);
        return result;
    }
    __CATCH
    {
        msp_disconnect(&service_handle, &session_handle, &channel_handle);
        return ERR_CODE;
    }
}

