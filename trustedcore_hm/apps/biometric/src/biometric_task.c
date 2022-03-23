/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: fingerprint agent
 * Author: gongyanan
 * Create: 2019-9-21
 */

#include "biometric_task.h"
#include "biometric_try_catch.h"
#include "securec.h"
#include "string.h"
#include "tee_common.h"
#include "tee_service_public.h"
#include "tee_commom_public_service.h"
#include "tee_internal_se_api.h"
#include "tee_ext_api.h"
#include "msp_tee_se_ext_api.h"

#define MSP_SA_ID_LEN       16
#define MSP_READER_NAME_LEN 4

static uint8_t g_finger_print_sa_aid[MSP_SA_ID_LEN] = {'h', 'i', 's', 'i',
                                                       '.', 'f', 'i', 'n',
                                                       'g', 'e', 'r', 'p',
                                                       'r', 'i', 'n', ' '};

static uint8_t g_face_recog_sa_aid[MSP_SA_ID_LEN] = {'h', 'i', 's', 'i',
                                                     '.', 'f', 'a', 'c',
                                                     'e', 'r', 'e', 'c',
                                                     'o', 'g', ' ', ' '};

static struct bio_entry g_finger_print = {
    0x00,
#ifdef DEF_ENG
    { 0x9cb38838, 0x2766, 0x42be, { 0x8b, 0x7b, 0x0d, 0x18, 0x4a, 0x99, 0x60, 0x61 } },
#else
    { 0xaeb4632b, 0x83ca, 0x4aef, { 0x95, 0x84, 0xae, 0x3c, 0x11, 0xba, 0x8f, 0x8c } },
#endif
    {(uint8_t *)&g_finger_print_sa_aid, SA_AID_LEN},
    NULL,
    NULL,
    {'m', 's', 'p', '\0'},
    MSP_READER_NAME_LEN,
    NULL,
    NULL};
static struct bio_entry g_face_recognition = {
    0x00,
#ifdef DEF_ENG
    { 0x9cb38838, 0x2766, 0x42be, { 0x8b, 0x7b, 0x0d, 0x18, 0x4a, 0x99, 0x60, 0x62 } },
#else
    { 0xe8014913, 0xe501, 0x4d44, { 0xa9, 0xd6, 0x05, 0x8e, 0xc3, 0xb9, 0x3b, 0x90 } },
#endif
    {(uint8_t *)&g_face_recog_sa_aid, SA_AID_LEN},
    NULL,
    NULL,
    {'m', 's', 'p', '\0'},
    MSP_READER_NAME_LEN,
    NULL,
    NULL};

static uint32_t bio_check_uuid(uint32_t sender, struct bio_entry **entry);
static uint32_t bio_select_sa(struct bio_entry *entry);

static void close_logical_channel(struct bio_entry *entry)
{
    /* Close channel */
    if (entry->se_session != NULL) {
        TEE_SESessionCloseChannels(entry->se_session);
        entry->se_channel = NULL;
    }

    /* Close session */
    if (entry->reader != NULL) {
        TEE_SEReaderCloseSessions(entry->reader);
        entry->se_session = NULL;
        entry->reader = NULL;
    }

    /* Close service */
    if (entry->service != NULL) {
        TEE_SEServiceClose(entry->service);
        entry->service = NULL;
    }
}

static void bio_sa_init(struct bio_entry *entry)
{
    close_logical_channel(entry);
    entry->sa_status = SA_IS_CLOSED;
}

uint32_t bio_sa_load(const uint8_t *sa_image, uint32_t image_length, uint32_t sender)
{
    uint32_t res;
    uint32_t is_loaded_success;
    struct bio_entry *cur_recog_type = NULL;
    struct sa_status_detail detail_status = { 0 };

    __TRY {
        /* check the uuid is allowed */
        res = bio_check_uuid(sender, &cur_recog_type);
        THROW_IF(res != BIO_SUCCESS, BIO_UUID_INVALID);

        /* Image is already loaded */
        if (cur_recog_type->sa_status >= SA_IS_LOADED)
            return BIO_SUCCESS;

        res = TEE_EXT_MSPGetStatus(cur_recog_type->sa_aid.buffer, cur_recog_type->sa_aid.bufferLen, &detail_status);
        if ((res != TEE_SUCCESS) && (res != TEE_ERROR_NEED_LOAD_SA)) {
            tloge("bio, %s, TEE_EXT_MSPGetStatus, %x\n", __func__, res);
            return res;
        }

        if (detail_status.sa_lfc == SA_LCS_NO_LOAD) {
            is_loaded_success = TEE_EXT_MSPLoadSA(sa_image,
                                                  image_length,
                                                  cur_recog_type->sa_aid.buffer,
                                                  cur_recog_type->sa_aid.bufferLen);
            THROW_IF(is_loaded_success != TEE_SUCCESS, BIO_IMAGE_LOADED_FAIL);
        }

        cur_recog_type->sa_status = SA_IS_LOADED;

        return BIO_SUCCESS;
    }
    __CATCH {
        return ERR_CODE;
    }
}

uint32_t bio_sa_install(struct msp_install_sa_info *sa_info, struct sa_status *status, uint32_t sender)
{
    uint32_t res;
    uint32_t is_installed_success;
    struct bio_entry *cur_recog_type = NULL;
    struct sa_status_detail detail_status = { 0 };

    __TRY {
        /* check the uuid is allowed */
        res = bio_check_uuid(sender, &cur_recog_type);
        THROW_IF(res != BIO_SUCCESS, BIO_UUID_INVALID);

        /* Image not loaded */
        THROW_IF(cur_recog_type->sa_status < SA_IS_LOADED, BIO_SA_NOT_LOADED);

        /* Image is already loaded */
        if (cur_recog_type->sa_status >= SA_IS_INSTALLED)
            return BIO_SUCCESS;

        if (memcpy_s(sa_info->sa_aid, SA_AID_LEN, cur_recog_type->sa_aid.buffer,
                     cur_recog_type->sa_aid.bufferLen) != EOK) {
            return BIO_WRONG_LENGTH;
        }

        if (memcpy_s(sa_info->sa_instance_id, SA_INSTANCE_ID_LEN, cur_recog_type->sa_aid.buffer,
                     cur_recog_type->sa_aid.bufferLen) != EOK) {
            return BIO_WRONG_LENGTH;
        }

        res = TEE_EXT_MSPGetStatus(cur_recog_type->sa_aid.buffer, cur_recog_type->sa_aid.bufferLen, &detail_status);
        if ((res != TEE_SUCCESS) && (res != TEE_ERROR_NEED_LOAD_SA)) {
            tloge("bio, %s, TEE_EXT_MSPGetStatus, %x\n", __func__, res);
            return res;
        }

        if (detail_status.sa_lfc == SA_LCS_INSTALLED) {
            tloge("bio, %s, bio sa already installed\n", __func__);
        } else {
            /* only one instance is supported for one bio SA, so '0' is hardcoded here */
            sa_info->sa_instance_id[SA_AID_LEN - 1] = '0';

            is_installed_success = TEE_EXT_MSPInstallSA(sa_info, status);
            THROW_IF(is_installed_success != TEE_SUCCESS, BIO_IMAGE_LOADED_FAIL);
        }

        cur_recog_type->sa_status = SA_IS_INSTALLED;

        return BIO_SUCCESS;
    }
    __CATCH {
        return ERR_CODE;
    }
}

uint32_t bio_sa_start(uint32_t sender)
{
    // Install apdu command
    char apdu_buffer[INSTALL_APDU_LEN] = {0};
    struct bio_entry *cur_recog_type = NULL;
    uint32_t res;

    __TRY {
        /* check the uuid is allowed */
        res = bio_check_uuid(sender, &cur_recog_type);
        THROW_IF(res != BIO_SUCCESS, BIO_UUID_INVALID);

        /* Image not installed */
        THROW_IF(cur_recog_type->sa_status < SA_IS_INSTALLED, BIO_SA_NOT_INSTALLED);

        /* has already started  */
        if (cur_recog_type->sa_status >= SA_IS_STARTED)
            return BIO_SUCCESS;

        /* Select SA according to the SA_AID */
        res = bio_select_sa(cur_recog_type);
        THROW_IF(res != BIO_SUCCESS, res);

        cur_recog_type->sa_status = SA_IS_STARTED;

        /* clear the mem */
        (void)memset_s(apdu_buffer, sizeof(apdu_buffer), 0, sizeof(apdu_buffer));

        return BIO_SUCCESS;
    }
    __CATCH {
        return ERR_CODE;
    }
}

uint32_t bio_send_command(char *apdu_buffer, uint32_t apdu_length, char *out_buffer, uint32_t *out_length,
                          uint32_t sender)
{
    struct bio_entry *cur_recog_type = NULL;
    uint32_t res;

    __TRY {
        THROW_IF_NULL(apdu_buffer, BIO_NULL_POINTER);
        THROW_IF_NULL(out_buffer, BIO_NULL_POINTER);
        THROW_IF_NULL(out_length, BIO_NULL_POINTER);
        THROW_IF(apdu_length == 0, BIO_WRONG_LENGTH);
        THROW_IF(apdu_length > APDU_MAX_LENGTH, TEE_ERROR_BAD_PARAMETERS);
        THROW_IF(*out_length < APDU_RES_MIN_LENGTH, BIO_WRONG_LENGTH);

        res = bio_check_uuid(sender, &cur_recog_type);
        THROW_IF((res != BIO_SUCCESS), BIO_UUID_INVALID);
        THROW_IF((cur_recog_type->sa_status < SA_IS_STARTED), BIO_SA_NOT_STARTED);

        res = TEE_SEChannelTransmit(cur_recog_type->se_channel, apdu_buffer, apdu_length, out_buffer, out_length);
        THROW_IF((res != TEE_SUCCESS), BIO_SEND_COMMAND_ERROR);
        return BIO_SUCCESS;
    }
    __CATCH {
        return ERR_CODE;
    }
}

uint32_t bio_sa_close(uint32_t sender)
{
    struct bio_entry *cur_recog_type = NULL;
    uint32_t res;

    __TRY {
        res = bio_check_uuid(sender, &cur_recog_type);
        THROW_IF((res != BIO_SUCCESS), BIO_UUID_INVALID);

        /* has already close  */
        if (cur_recog_type->sa_status == SA_IS_CLOSED)
            return BIO_SUCCESS;

        bio_sa_init(cur_recog_type);
        return BIO_SUCCESS;
    }
    __CATCH {
        return ERR_CODE;
    }
}

uint32_t bio_sa_reinit(uint32_t sender)
{
    struct bio_entry *cur_recog_type = NULL;
    uint32_t res;

    __TRY {
        res = bio_check_uuid(sender, &cur_recog_type);
        THROW_IF((res != BIO_SUCCESS), BIO_UUID_INVALID);
        bio_sa_init(cur_recog_type);
        return BIO_SUCCESS;
    }
    __CATCH {
        return ERR_CODE;
    }
}

/*
 * Check if the uuid is in the white list
 */
static uint32_t bio_check_uuid(uint32_t sender, struct bio_entry **entry)
{
    TEE_UUID cur_ta = {0};
    uint32_t res;

    __TRY {
        res = (uint32_t)tee_common_get_uuid_by_sender(sender, &cur_ta, sizeof(TEE_UUID));
        THROW_IF((res != TEE_SUCCESS), res);

        if (memcmp(&(g_finger_print.ta_uuid), &cur_ta, sizeof(TEE_UUID)) == 0) {
            *entry = &g_finger_print;
            return BIO_SUCCESS;
        } else if (memcmp(&(g_face_recognition.ta_uuid), &cur_ta, sizeof(TEE_UUID)) == 0) {
            *entry = &g_face_recognition;
            return BIO_SUCCESS;
        } else
            THROW(BIO_UUID_INVALID);
    }
    __CATCH {
        return ERR_CODE;
    }
}

static uint32_t bio_select_sa(struct bio_entry *entry)
{
    TEE_SEReaderHandle reader_handle[READER_NUM];
    uint32_t reader_len = 0;
    uint8_t i = 0;
    char reader_name[READER_NAME_LEN];
    uint32_t name_len = READER_NAME_LEN;
    uint32_t result;
    uint8_t local_sa_aid_buf[SA_AID_LEN];
    TEE_SEAID local_sa_aid = {local_sa_aid_buf, SA_AID_LEN};

    __TRY {
        if (entry->service == NULL) {
            result = TEE_SEServiceOpen(&(entry->service));
            THROW_IF_WITH_PARA(result != TEE_SUCCESS, BIO_OPEN_SERVICE_FAIL, result);
        }

        /* Get reader */
        if (entry->reader == NULL) {
            reader_len = READER_NUM;
            result = TEE_SEServiceGetReaders(entry->service, reader_handle, &reader_len);
            THROW_IF_WITH_PARA(result != TEE_SUCCESS, BIO_GET_READER_FAIL, result);

            /* name_len can not be zero, start from 0, Get reader handle */
            for (i = 0; i < reader_len; i++) {
                /* Get reader name */
                name_len = READER_NAME_LEN;
                result = TEE_SEReaderGetName(reader_handle[i], reader_name, &name_len);
                if (result != TEE_SUCCESS) {
                    continue;
                }

                if ((name_len == entry->name_len) && (memcmp(reader_name, entry->reader_name, name_len) == 0)) {
                    entry->reader = reader_handle[i];
                    break;
                }
            }

            /* check the reader */
            THROW_IF_NULL(entry->reader, BIO_GET_READER_FAIL);
        }

        /* sCard connect */
        if (entry->se_session == NULL) {
            result = TEE_SEReaderOpenSession(entry->reader, &entry->se_session);
            THROW_IF_WITH_PARA(result != TEE_SUCCESS, BIO_OPEN_SESSION_FAIL, result);
        }

        /* Open logical channel */
        /* Get SA AID of this entry */
        if (entry->se_channel == NULL) {
            if (memcpy_s(local_sa_aid.buffer, SA_AID_LEN, entry->sa_aid.buffer, SA_AID_LEN) != EOK) {
                THROW(BIO_SECURE_ERROR);
            }
            local_sa_aid.buffer[SA_AID_LEN - 1] = '0';

            result = TEE_SESessionOpenLogicalChannel(entry->se_session, &local_sa_aid, &entry->se_channel);
            THROW_IF_WITH_PARA(result != TEE_SUCCESS, BIO_OPNE_LOGICAL_CHANNEL_FAIL, result);
        }

        return BIO_SUCCESS;
    }
    __CATCH {
        close_logical_channel(entry);
        return ERR_CODE;
    }
}
