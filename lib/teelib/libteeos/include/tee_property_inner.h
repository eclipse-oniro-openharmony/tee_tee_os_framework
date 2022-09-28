/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2019. All rights reserved.
 * Description: Tee base property implementation header file used in inner
 * Create: 2012-01-20
 */
#ifndef TEE_PROPERTY_INNER_H
#define TEE_PROPERTY_INNER_H

#include <stdint.h>

void init_non_std_property(char *buff, uint32_t len);

uint32_t tee_get_ta_api_level(void);

#endif
