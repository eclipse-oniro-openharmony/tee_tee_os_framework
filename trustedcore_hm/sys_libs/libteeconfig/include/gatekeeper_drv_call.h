/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description:  gatekeeper driver call for TA
 * Create: 2021-06-08
 */
#ifndef GATEKEEPER_DRV_CALL_H
#define GATEKEEPER_DRV_CALL_H
#include <stdint.h>

bool __add_key_factor(uint64_t secure_id, const uint8_t *key_factor, uint32_t key_len);
bool __delete_key_factor(uint64_t secure_id);
bool __get_key_factor(uint64_t secure_id, uint8_t *key_factor, uint32_t *key_len);
#endif
