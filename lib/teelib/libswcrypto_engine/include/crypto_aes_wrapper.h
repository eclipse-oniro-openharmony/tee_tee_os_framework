/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Create: 2022-04-01
 * Description: soft aes engine
 */
#ifndef __CRYPTO_AES_WRAPPER_H__
#define __CRYPTO_AES_WRAPPER_H__

#include <stdint.h>
#include <tee_defines.h>
#include <chinadrm.h>

TEE_Result aes_key_wrap(struct cdrm_params *params);
TEE_Result aes_key_unwrap(struct cdrm_params *params);
#endif
