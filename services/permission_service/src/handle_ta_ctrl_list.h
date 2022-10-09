/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2016-2020. All rights reserved.
 * Description: handle ta ctrl
 * Author: TianJianliang tianjianliang@huawei.com
 * Create: 2016-04-01
 */
#ifndef PERMISSION_SERVICE_HANDLE_TA_CTRL_LIST_H
#define PERMISSION_SERVICE_HANDLE_TA_CTRL_LIST_H

#include <dlist.h>
#include <tee_defines.h>
#include <pthread.h>

#define PADDING_SIZE          7
#define TA_CTRL_LIST_MAX_SIZE 8192
#define RSA2048_SIGNATURE_LEN 256
#define SHA256_LEN            32
#define SHA512_LEN            64
#define CERT_MAX_SIZE         2048
#define CERT_UNIVERSAL_LEN    64
#define HASH_UPDATA_LEN       1024
#define TA_CTRL_MAGIC_NUM     0x12361215
#define TA_CTRL_CHIP_LEN      4

struct padding {
    uint16_t reserved[PADDING_SIZE];
};

struct ta_ctrl_node {
    struct dlist_node head;
    TEE_UUID uuid;
    uint16_t version;
    struct padding pad;
};

struct ta_ctrl_config_t {
    struct dlist_node ctrl_list;
    char *file_name;
    uint16_t count;
    pthread_mutex_t lock;
};

struct ta_ctrl_list_hd_t {
    uint32_t magic_num;
    uint32_t version;
    uint32_t body_len;
    uint32_t signature_len;
    uint32_t cert_len;
};

TEE_Result perm_serv_global_ctrl_list_loading(void);
TEE_Result perm_srv_check_ta_deactivated(const TEE_UUID *uuid, uint16_t version);
TEE_Result perm_serv_ta_ctrl_buff_process(const uint8_t *ctrl_buff, uint32_t ctrl_buff_size);
#endif
