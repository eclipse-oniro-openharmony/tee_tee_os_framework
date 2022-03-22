/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: secboot for get cert on kunpeng platform
 * Create: 2021-04
 */
#ifndef KUNPENG_DRV_GETCERT_H
#define KUNPENG_DRV_GETCERT_H

#include <stdint.h>
#include <unistd.h>
#define SHARED_MEM_CERTKEY "certkey"
int32_t get_certkey_info(uint8_t *buf, size_t len);

#endif
