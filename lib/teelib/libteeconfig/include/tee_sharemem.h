/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: tee sharemem api
 * Create: 2021-08-16
 */
#ifndef TEE_SHAREMEM_H
#define TEE_SHAREMEM_H

#include <stdint.h>

#define MAX_TAG_LEN 32

/*
 * when clear_flag is true, sharedmem buffer will be memset to zero
 * after sharedmem acquired firstly
 */
int32_t get_tlv_sharedmem(const char *type, uint32_t type_size,
                          void *buffer, uint32_t *size, bool clear_flag);
int32_t tee_get_chip_type(char *buffer, uint32_t buffer_len);

int32_t tee_shared_mem(const char *type, uint32_t type_size, void *buffer, uint32_t *buffer_size, bool clear_flag);
int32_t tee_get_oemkey_info(uint8_t *oem_key, size_t key_size);
#endif
