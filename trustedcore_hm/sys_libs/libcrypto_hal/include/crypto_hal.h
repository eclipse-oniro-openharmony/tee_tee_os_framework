/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: Crypto API at driver adaptor.
 * Create: 2020-03-20
 */
#ifndef CRYPTO_HAL_H
#define CRYPTO_HAL_H

#include <stdbool.h>
#include <tee_mem_mgmt_api.h>
#include <crypto_driver_adaptor.h>
#include <crypto_syscall.h>

#define CRYPTO_PADDING_LEN    16
#define MAX_CRYPTO_DATA_LEN   (500 * 1024)
#define MAX_RANDOM_SIZE       0x100000

struct crypto_cache_t {
    void *buffer;
    uint32_t total_len;
    uint32_t effective_len;
};

struct ctx_handle_t *alloc_ctx_handle(uint32_t alg_type, uint32_t engine);
int32_t tee_crypto_ctx_copy(const struct ctx_handle_t *src_ctx, struct ctx_handle_t *dest_ctx);
void tee_crypto_ctx_free(struct ctx_handle_t *ctx);
int32_t tee_crypto_generate_random(void *buffer, uint32_t size);
int32_t tee_crypto_check_alg_support(uint32_t alg_type);

#endif
