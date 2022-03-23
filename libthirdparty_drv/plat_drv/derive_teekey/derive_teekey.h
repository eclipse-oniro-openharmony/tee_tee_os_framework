/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: plat capability, key derive
 * Create: 2021-05
 */
#include <stdint.h>
#include <tee_log.h>

#ifdef __cplusplus
extern "C" {
#endif

/* plat derive teekey */
#define PLAT_TEEKEY_SIZE  16
uint32_t plat_derive_teekey(uint8_t *key, uint32_t size);
uint32_t seb_derive_provkey(uint8_t *key, uint32_t *seed);

#ifdef __cplusplus
}
#endif

