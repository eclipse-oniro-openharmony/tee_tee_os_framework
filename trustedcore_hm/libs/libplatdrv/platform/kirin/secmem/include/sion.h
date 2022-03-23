/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: moved from teeos, secmem ion memory operation
 * Create: 2019-11-08
 */
#ifndef KIRIN_SECMEM_INCLUDE_SION_H
#define KIRIN_SECMEM_INCLUDE_SION_H
#include <sre_typedef.h>

/*
 * @ingroup SECURE_ION
 * sion pool type, now we support face identification, and iris identification.
 */
 typedef enum {
    SION_POOL_FACE = 0,
    SION_POOL_IRIS,
    SION_POOL_MAX
} SION_POOL_TYPE;

s32 sion_pool_flag_set(u32 type);
s32 sion_pool_flag_unset(u32 type);
#endif /* KIRIN_SECMEM_INCLUDE_SION_H */
