/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: fingerprint agent
 * Author: gongyanan
 * Create: 2019-9-21
 */
#ifndef __BIOMATRIC_TASK_H
#define __BIOMATRIC_TASK_H

#include "tee_internal_se_api.h"
#include "msp_tee_se_ext_api.h"

#define APDU_MAX_LENGTH (32 * 1024 - 16)
#define APDU_RES_MAX_LENGTH 256
#define APDU_RES_MIN_LENGTH 2

#define READER_NUM 4
#define READER_NAME_LEN 16
#define SA_AID_LEN 16
#define TA_UUID_LEN 16
#define USER_ID_LEN 1

#define INSTALL_APDU_LEN 31
#define APDU_HEAD_LEN 5
#define APDU_P1P1_LEN 2
#define APDU_PATAM_LEN 5

/* SA current status */
enum bio_sa_status_enum {
    SA_IS_CLOSED = 0,
    SA_IS_LOADED,
    SA_IS_INSTALLED,
    SA_IS_STARTED
};

struct bio_entry {
    uint8_t sa_status;
    TEE_UUID ta_uuid;
    TEE_SEAID sa_aid;

    TEE_SEServiceHandle service;
    TEE_SEReaderHandle reader;
    uint8_t reader_name[READER_NAME_LEN];
    size_t name_len;
    TEE_SESessionHandle se_session;
    TEE_SEChannelHandle se_channel;
};

enum BIO_STATUS {
    BIO_SUCCESS = 0x0,
    BIO_NULL_POINTER,
    BIO_UUID_INVALID,
    BIO_WRONG_LENGTH,
    BIO_START_SA_FAIL,
    BIO_SA_NOT_STARTED,
    BIO_SEND_COMMAND_ERROR,
    BIO_OPEN_SERVICE_FAIL,
    BIO_GET_READER_FAIL,
    BIO_GET_NAME_FAIL,
    BIO_OPEN_SESSION_FAIL,
    BIO_OPNE_LOGICAL_CHANNEL_FAIL,
    BIO_IMAGE_LOADED_FAIL,
    BIO_SA_NOT_LOADED,
    BIO_SA_NOT_INSTALLED,
    BIO_SELECT_SA_FAIL,
    BIO_LOGICAL_CHANNEL_INVALID,
    BIO_RES_WRONG_LENGTH,
    BIO_SECURE_ERROR
};

uint32_t bio_sa_start(uint32_t sender);
uint32_t bio_sa_load(const uint8_t *sa_image, uint32_t image_length, uint32_t sender);
uint32_t bio_sa_install(struct msp_install_sa_info *sa_info, struct sa_status *status, uint32_t sender);
uint32_t bio_send_command(char *apdu_buffer, uint32_t apdu_length, char *out_buffer, uint32_t *out_length,
                          uint32_t sender);
uint32_t bio_sa_close(uint32_t sender);
uint32_t bio_sa_reinit(uint32_t sender);

#endif
