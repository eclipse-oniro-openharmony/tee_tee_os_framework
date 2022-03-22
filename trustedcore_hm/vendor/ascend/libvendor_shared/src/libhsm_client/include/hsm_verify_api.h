/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: HSM verify api function
 * Author: chenyao
 * Create: 2020-05-21
 */
#ifndef _HSM_VERIFY_API_H_
#define _HSM_VERIFY_API_H_

#define  IMG_ADDR_SIZE                  8
#define  IMG_LEN_SIZE                   4
#define  IMG_ID_SIZE                    4

TEE_Result TEE_HSM_SOC_VERIFY(uint32_t dev_id, uint64_t image_addr, uint32_t image_len, uint32_t img_id);
TEE_Result TEE_HSM_Hboot1a_Trans(uint32_t dev_id);

#endif
