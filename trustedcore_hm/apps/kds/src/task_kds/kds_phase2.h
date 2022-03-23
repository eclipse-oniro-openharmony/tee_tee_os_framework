/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: Definations for kds phase two.
 * Create: 2020-06-28
 */

#ifndef KDS_PHASE2_H
#define KDS_PHASE2_H

#include "tee_core_api.h"

#define HMAC_MSG_LENGTH 44
#define MAIN_KEY_LENGTH 32
#define HMAC_LENGTH 32
#define MAC_PLAINT_DATA_SIZE 255
#define MAX_HUK_DATA_SIZE 256
#define SALT_SIZE 16

#define TARGET_ID_LENGTH 32
#define DF_LENGTH 8
#define MAX_PATH_LENGTH 256
#define REQ_SIZE sizeof(KdsHukReqInfos)
#define DATA_SIZE sizeof(KdsHukDataInfos)

#define MAX_DATA_LEN 256
#define MAX_EXTEND_INFO_LEN 1024

typedef struct {
    uint32_t reqType;
    uint32_t extInfoSize; // Upper limit is 1024 bytes.
    uint8_t targetId[TARGET_ID_LENGTH];
    uint8_t driveFactor[DF_LENGTH];
    uint8_t extInfo[MAX_EXTEND_INFO_LEN];
} KdsHukReqInfos;

typedef struct {
    uint32_t data1Size; // Upper limit is 256 bytes.
    uint32_t data2Size; // Upper limit is 256 bytes.
    uint32_t extInfoSize; // Upper limit is 1024 bytes.
    uint8_t data1[MAX_DATA_LEN];
    uint8_t data2[MAX_DATA_LEN];
    uint8_t extInfo[MAX_EXTEND_INFO_LEN];
} KdsHukDataInfos;

TEE_Result AddCaller();
TEE_Result HandleCaCommandReq(uint32_t paramTypes, TEE_Param *params);

#endif