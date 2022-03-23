/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: Root of Trust Task management.
 * Author: t00360454
 * Create: 2020-02-10
 */
#ifndef _ROOT_OF_TURST_TASK_H_
#define _ROOT_OF_TURST_TASK_H_

#include "tee_defines.h"
#include "tee_internal_se_api.h"

#define MAX_READER_NAME_LEN 16
struct rot_entry {
    uint32_t uuid_number;
    TEE_UUID *ta_uuid;
    TEE_SEAID sa_aid;

    TEE_SEServiceHandle service;
    TEE_SEReaderHandle reader;
    uint8_t reader_name[MAX_READER_NAME_LEN];
    size_t name_len;
    TEE_SESessionHandle se_session;
    TEE_SEChannelHandle se_channel;
};

enum ROT_ERR_CODE {
    ROT_SUCCESS = TEE_SUCCESS,
    ROT_NULL_POINTER = 0xA4060001,
    ROT_WRONG_LENGTH,
    ROT_GET_UUID_FAILED,
    ROT_UUID_INVALID,
    ROT_OPEN_SERVICE_FAILED,
    ROT_GET_READER_HANDLE_FAILED,
    ROT_GET_READER_NAME_FAILED,
    ROT_GET_READER_FAILED,
    ROT_OPEN_SESSION_FAILED,
    ROT_OPEN_LOGICAL_CHANNEL_FAILED,
    ROT_CMD_TRANSMIT_FAILED,
    ROT_OP_SA_LOAD_INSTALL_FAILED
};

enum ROT_ERR_CODE rot_transmit_apdu_message(char *capdu, uint32_t capdu_length, char *rapdu, uint32_t *rapdu_length,
                                            uint32_t sender);
#endif
