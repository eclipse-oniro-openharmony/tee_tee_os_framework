/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: HSM fuzz service test client api
 * Author: chenyao
 * Create: 2021-06-17
 */
#ifndef _HSM_FUZZ_API_H_
#define _HSM_FUZZ_API_H_

#define  IMG_ADDR_SIZE                  8
#define  IMG_LEN_SIZE                   4
#define  IMG_ID_SIZE                    4

TEE_Result TEE_HSM_SERVICE_FUZZ(uint8_t *service_msg, uint32_t msg_size, uint8_t *service_data, uint32_t data_size);

typedef struct {
    uint32_t    cmd;
    uint32_t    ddr_para_num;
    uint32_t    param_len_0;
    uint32_t    param_len_1;
    uint32_t    param_len_2;
    uint32_t    param_len_3;
    uint32_t    param_len_4;
    uint32_t    param_len_5;
    uint32_t    param_len_6;
    uint32_t    param_len_7;
    uint8_t     *buffer;
    uint32_t    buffer_len;
} FUZZ_SERVICE_S;


#endif
