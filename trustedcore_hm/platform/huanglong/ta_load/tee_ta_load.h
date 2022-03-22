/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: policy definitions
 * Create: 2020-09-10
 */

#ifndef TEE_TA_LOAD_H
#define TEE_TA_LOAD_H
#include "ta_framework.h"

#define MAX_HEADER_SIZE 0x400
#define RESERVE_SIZE 128

typedef struct {
    uint32_t img_version;
    uint32_t identity_len;
    uint32_t header_len;
    uint32_t image_len;
    uint32_t total_len;
    TEE_UUID srv_uuid;
    int8_t   *service_name;
    uint32_t service_name_len;
    int32_t  multi_instance;
    int32_t  multi_session;
    int32_t  multi_command;
    uint32_t heap_size;
    uint32_t stack_size;
    int32_t  instance_keep_alive;
    uint8_t *manifest_buf;
    uint8_t manifest_str_len;
    int8_t   *img_buf;
    uint32_t img_buf_len;
    uint32_t img_buf_offset;
} teec_image_info;

/* Hisilicon private data for ta load */
typedef struct {
    TEE_UUID srv_uuid;
    int32_t  single_instance;
    int32_t  multi_session;
    int32_t  multi_command;
    uint32_t heap_size;
    uint32_t stack_size;
    int32_t  instance_keep_alive;
    int8_t   service_name[SERVICE_NAME_MAX];   /* TA name */
    uint32_t service_name_len;
    int8_t   reserve[RESERVE_SIZE];
} HISI_TA_MANIFEST;

int32_t is_third_identity(uint8_t *buffer, uint32_t size);
TEE_Result process_header_third(uint8_t *image, uint32_t size, teec_image_info *img_info);
TEE_Result process_body_third(uint8_t *body, uint32_t size, teec_image_info *img_info);
void process_end_third(void);

#endif
