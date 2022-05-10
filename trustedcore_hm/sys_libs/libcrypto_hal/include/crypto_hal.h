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

#define MAX_CRYPTO_RANDOM_LEN (500 * 1024)
#define MAX_CRYPTO_CTX_SIZE   (1024 * 1024)
#define TYPE_DRV_OPEN          2


struct crypto_cache_t {
    void *buffer;
    uint32_t total_len;
    uint32_t effective_len;
};

struct ctx_handle_t *alloc_ctx_handle(uint32_t alg_type, uint32_t engine);
int32_t tee_crypto_ctx_copy(const struct ctx_handle_t *src_ctx, struct ctx_handle_t *dest_ctx);
void tee_crypto_ctx_free(struct ctx_handle_t *ctx);
void tee_crypto_free_sharemem(struct ctx_handle_t *ctx);
int32_t tee_crypto_generate_random(void *buffer, uint32_t size, bool is_hw_rand);
int32_t tee_crypto_check_alg_support(uint32_t alg_type);
struct ctx_handle_t *driver_alloc_ctx_handle(uint32_t alg_type, uint32_t engine, struct ctx_handle_t *ctx);
int64_t get_ctx_fd_handle(uint32_t alg_type, bool is_copy_ctx);
int32_t driver_ctx_buffer_prepare(const struct ctx_handle_t *src_ctx, struct ctx_handle_t *dest_ctx);
#ifdef OPENSSL_ENABLE
void tee_crypto_free_opensssl_drbg(void);
#endif
#endif
