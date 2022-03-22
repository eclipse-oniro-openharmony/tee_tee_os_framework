/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: wb_aes_decrypt
 * Create: 2019-01-17
 */
#ifndef __WB_AES_DECRYPT_H
#define __WB_AES_DECRYPT_H

#include "wb_aes_util.h"

void wb_aes_decrypt(const uint8_t *input, uint8_t *output);
int wb_aes_decrypt_cbc(const uint8_t *iv, const uint8_t *input, uint32_t in_len, uint8_t *output, uint32_t *out_len);

#endif /* WB_AES_DECRYPT_H_ */
