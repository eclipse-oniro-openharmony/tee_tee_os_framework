/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: Crypto API at driver adaptor.
 * Create: 2020-04-02
 */
#ifndef CRYPTO_SYSCALL_H
#define CRYPTO_SYSCALL_H

#include <stdint.h>
#include <stdbool.h>

#define AES_MAC_LEN          16
#define CIPHER_CACHE_LEN     16
#define ARG0_INDEX           0
#define ARG1_INDEX           1
#define ARG2_INDEX           2
#define ARG3_INDEX           3
#define ARG4_INDEX           4
#define ARG5_INDEX           5
#define ARG6_INDEX           6
#define MMAP_PTR0_INDEX      0
#define MMAP_PTR1_INDEX      1
#define MMAP_PTR2_INDEX      2
#define MMAP_PTR3_INDEX      3
#define MMAP_PTR4_INDEX      4
#define TMP_ADDR0_INDEX      0
#define TMP_ADDR1_INDEX      1
#define TMP_ADDR2_INDEX      2
#define TMP_ADDR3_INDEX      3
#define TMP_ADDR4_INDEX      4
#define MAP_PARAM_MAX        3
#define TMP_ADDR_MAX         5
#define CACHED_RANDOM_SIZE   4096
#define ONE_BLOCK_SIZE       16
#define TOTAL_RANDOM_BLOCK   (CACHED_RANDOM_SIZE / ONE_BLOCK_SIZE)

struct ctx_handle_t {
    uint64_t ctx_buffer;
    uint32_t ctx_size;
    uint32_t engine;
    uint32_t alg_type;
    uint32_t direction;
    bool is_support_ae_update;
    uint64_t cache_buffer;
    uint8_t cbc_mac_buffer[AES_MAC_LEN];
    uint32_t tag_len;
    uint8_t cipher_cache_data[CIPHER_CACHE_LEN];
    uint32_t cipher_cache_len;
    void (*free_context)(uint64_t *);
    uint64_t aad_cache;
    uint32_t aad_size;
    uint32_t driver_ability;
    uint64_t fd;
};

bool check_ctx_size(uint32_t engine, uint32_t alg_type, uint32_t ctx_size, uint32_t driver_ability);
#endif
