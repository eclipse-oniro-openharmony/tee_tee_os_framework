/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: HSM rpmb ak key provide api head
 * Author: chenyao
 * Create: 2020-05-06
 */
#ifndef _HSM_RPMB_API_H_
#define _HSM_RPMB_API_H_

#define HSM_RPMB_KEY_LEN                        32
#define HSM_RPMB_WRAPPING_KEY_LEN               80
#define HSM_RPMB_FILE_LEN                       9
#define HSM_RPMB_BUFFER_LEN                     128

TEE_Result TEE_HSM_GenRpmbKey(uint32_t dev_id, uint8_t *rpmb_key);
TEE_Result TEE_HSM_GenRpmbWrappingKey(uint32_t dev_id, uint8_t *rpmb_wrapping_key);

#endif
