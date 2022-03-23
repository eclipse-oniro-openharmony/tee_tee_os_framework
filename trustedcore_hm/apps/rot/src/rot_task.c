/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: Rot of Trust task management.
 * Author: t00360454
 * Create: 2020-02-10
 * History: 2020-02-10 t00360454 create
 */
#include "rot_task.h"
#include <hm_msg_type.h>
#include "msp_tee_se_ext_api.h"
#include "securec.h"
#include "tee_log.h"
#include "tee_config.h"
#include "product_uuid.h"
#include "product_uuid_public.h"
#include "tee_commom_public_service.h"

/* sa related information */
#define SA_AID_LEN 16
#define MSP_READER_NAME_LEN 4 /* "msp" */
#define MAX_READER_NUM 4

static uint8_t g_rot_saaid[] = {
    0x68, 0x69, 0x73, 0x69, 0x2E, 0x73, 0x61, 0x2E,
    0x72, 0x6F, 0x74, 0x20, 0x20, 0x20, 0x20, 0x20
}; /* "hisi.sa.rot     " */

static uint8_t g_rot_instance_saaid[] = {
    0x68, 0x69, 0x73, 0x69, 0x2E, 0x73, 0x61, 0x2E,
    0x72, 0x6F, 0x74, 0x20, 0x20, 0x20, 0x20, 0x30
}; /* "hisi.sa.rot    0" */
#define ROT_SA_VERSION 0x01

static TEE_UUID g_uuid_white_list[] = {
    TEE_SERVICE_PKI, /* Huks TA */
#if DEF_ENG
    { 0x9cb38838, 0x2766, 0x42be, {0x8b, 0x7b, 0x0d, 0x18, 0x4a, 0x99, 0x60, 0x61} }, /* Test TA1 */
    { 0x9cb38838, 0x2766, 0x42be, {0x8b, 0x7b, 0x0d, 0x18, 0x4a, 0x99, 0x60, 0x62} }, /* Test TA2 */
#endif
};

static struct rot_entry g_rot_entry_info = {
    ARRAY_SIZE(g_uuid_white_list),
    g_uuid_white_list,
    { (uint8_t *)&g_rot_instance_saaid, SA_AID_LEN },
    NULL,
    NULL,
    { 'm', 's', 'p', '\0' },
    MSP_READER_NAME_LEN,
    NULL,
    NULL
};

static enum ROT_ERR_CODE get_reader(struct rot_entry *entry)
{
    TEE_SEReaderHandle reader_handle[MAX_READER_NUM] = { 0 };
    char reader_name[MAX_READER_NAME_LEN] = { 0 };
    uint32_t reader_num;
    uint32_t name_len;
    TEE_Result ret;
    uint8_t i;

    if (entry->reader)
        return ROT_SUCCESS;

    reader_num = ARRAY_SIZE(reader_handle);
    ret = TEE_SEServiceGetReaders(entry->service, reader_handle, &reader_num);
    if (ret != TEE_SUCCESS) {
        tloge("rot, %s, TEE_SEServiceGetReaders failed, %x\n", __func__, ret);
        return ROT_GET_READER_HANDLE_FAILED;
    }

    /* Get the msp reader */
    for (i = reader_num; i > 0; i--) {
        name_len = sizeof(reader_name);
        ret = TEE_SEReaderGetName(reader_handle[i-1], reader_name, &name_len);
        if (ret != TEE_SUCCESS) {
            tloge("rot, %s, TEE_SEReaderGetName failed, %x\n", __func__, ret);
            return ROT_GET_READER_NAME_FAILED;
        }
        if (name_len == entry->name_len && (memcmp(reader_name, entry->reader_name, name_len) == 0)) {
            entry->reader = reader_handle[i-1];
            return ROT_SUCCESS;
        }
    }

    tloge("rot, %s, msp reader does not exist\n", __func__);
    return ROT_GET_READER_FAILED;
}

static TEE_Result msp_rot_sa_load_install(void)
{
    TEE_Result ret;
    int result;
    struct sa_status status = { 0 };
    struct sa_status_detail detail_status = { 0 };
    struct msp_install_sa_info install_sa_info;

    (void)memset_s(&install_sa_info, sizeof(install_sa_info), 0, sizeof(install_sa_info));

    ret = TEE_EXT_MSPGetStatus(g_rot_saaid, sizeof(g_rot_saaid), &detail_status);
    if ((ret != TEE_SUCCESS) && (ret != TEE_ERROR_NEED_LOAD_SA)) {
        tloge("rot, %s, TEE_EXT_MSPGetStatus, %x\n", __func__, ret);
        return ret;
    }
    if (detail_status.sa_lfc == SA_LCS_NO_LOAD) {
        ret = TEE_EXT_MSPLoadSA(NULL, 0, g_rot_saaid, sizeof(g_rot_saaid));
        if (ret != TEE_SUCCESS) {
            tloge("rot, %s, TEE_EXT_MSPLoadSA, %x\n", __func__, ret);
            return ret;
        }
    }
    if (detail_status.sa_lfc == SA_LCS_INSTALLED) {
        return ret;
    }

    result = memcpy_s(install_sa_info.sa_aid, sizeof(install_sa_info.sa_aid), g_rot_saaid, sizeof(g_rot_saaid));
    if (result != EOK) {
        tloge("rot, %s, memcpy_s sa aid, %x\n", __func__, ret);
        return TEE_ERROR_SECURITY;
    }
    result = memcpy_s(install_sa_info.sa_instance_id, sizeof(install_sa_info.sa_instance_id), g_rot_instance_saaid,
                      sizeof(g_rot_instance_saaid));
    if (result != EOK) {
        tloge("rot, %s, memcpy_s instance, %x\n", __func__, ret);
        return TEE_ERROR_SECURITY;
    }
    install_sa_info.version = ROT_SA_VERSION;
    ret = TEE_EXT_MSPInstallSA(&install_sa_info, &status);
    if (ret != TEE_SUCCESS) {
        tloge("rot, %s, TEE_EXT_MSPInstallSA, %x\n", __func__, ret);
        return ret;
    }
    return ret;
}

static enum ROT_ERR_CODE select_sa(struct rot_entry *entry)
{
    TEE_Result ret;
    enum ROT_ERR_CODE rot_ret;

    /* Load and install ROT sa */
    ret = msp_rot_sa_load_install();
    if (ret != TEE_SUCCESS) {
        tloge("rot, %s, msp_rot_sa_load_install failed, %x\n", __func__, ret);
        return ROT_OP_SA_LOAD_INSTALL_FAILED;
    }

    /* Open service */
    if (!entry->service) {
        ret = TEE_SEServiceOpen(&entry->service);
        if (ret != TEE_SUCCESS) {
            tloge("rot, %s, TEE_SEServiceOpen failed, %x\n", __func__, ret);
            return ROT_OPEN_SERVICE_FAILED;
        }
    }

    /* Get reader */
    rot_ret = get_reader(entry);
    if (rot_ret != ROT_SUCCESS)
        return rot_ret;

    /* open session */
    if (!entry->se_session) {
        ret = TEE_SEReaderOpenSession(entry->reader, &entry->se_session);
        if (ret != TEE_SUCCESS) {
            tloge("rot, %s, TEE_SEReaderOpenSession failed, %x\n", __func__, ret);
            return ROT_OPEN_SESSION_FAILED;
        }
    }

    /* Open logical channel and select the sa */
    if (!entry->se_channel) {
        ret = TEE_SESessionOpenLogicalChannel(entry->se_session, &entry->sa_aid, &entry->se_channel);
        if (ret != TEE_SUCCESS) {
            tloge("rot, %s, TEE_SESessionOpenLogicalChannel failed, %x\n", __func__, ret);
            return ROT_OPEN_LOGICAL_CHANNEL_FAILED;
        }
    }

    return ROT_SUCCESS;
}

static void deselect_sa(struct rot_entry *entry)
{
    /* Close channel */
    if (entry->se_session) {
        TEE_SESessionCloseChannels(entry->se_session);
        entry->se_channel = NULL;
    }

    /* Close session */
    if (entry->reader) {
        TEE_SEReaderCloseSessions(entry->reader);
        entry->se_session = NULL;
        entry->reader = NULL;
    }

    /* Close service */
    if (entry->service) {
        TEE_SEServiceClose(entry->service);
        entry->service = NULL;
    }
}

static enum ROT_ERR_CODE check_uuid(uint32_t sender, struct rot_entry *entry)
{
    TEE_UUID cur_ta = {0};
    uint32_t ret;
    uint32_t i;

    ret = (uint32_t)tee_common_get_uuid_by_sender(sender, &cur_ta, sizeof(TEE_UUID));
    if (ret != TEE_SUCCESS) {
        tloge("rot, %s, tee_common_get_uuid_by_sender failed, %x\n", __func__, ret);
        return ROT_GET_UUID_FAILED;
    }

    for (i = 0; i < entry->uuid_number; i++) {
        if (memcmp(&entry->ta_uuid[i], &cur_ta, sizeof(cur_ta)) == 0)
            return ROT_SUCCESS;
    }

    tloge("rot, %s, uuid invalid\n", __func__);
    return ROT_UUID_INVALID;
}

enum ROT_ERR_CODE rot_transmit_apdu_message(char *capdu, uint32_t capdu_length, char *rapdu, uint32_t *rapdu_length,
                                            uint32_t sender)
{
    struct rot_entry *entry = &g_rot_entry_info;
    TEE_Result tmp_ret;
    enum ROT_ERR_CODE ret = ROT_UUID_INVALID;

    if (!capdu || !rapdu || !rapdu_length)
        return ROT_NULL_POINTER;

    if (capdu_length == 0)
        return ROT_WRONG_LENGTH;

    ret = check_uuid(sender, entry);
    if (ret != ROT_SUCCESS)
        return ret;

    ret = select_sa(entry);
    if (ret != ROT_SUCCESS)
        goto close_service;

    tmp_ret = TEE_SEChannelTransmit(entry->se_channel, capdu, capdu_length, rapdu, rapdu_length);
    if (tmp_ret != TEE_SUCCESS) {
        tloge("rot, %s, TEE_SEChannelTransmit failed, %x\n", __func__, tmp_ret);
        ret = ROT_CMD_TRANSMIT_FAILED;
    }

close_service:
    deselect_sa(entry);
    return ret;
}
