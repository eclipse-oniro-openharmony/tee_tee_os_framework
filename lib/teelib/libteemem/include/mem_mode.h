/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: memory secure/cache/user mode macro definition
 * Create: 2019-11-08
 */
#ifndef LIBTEEMEM_MEM_MODE_H
#define LIBTEEMEM_MEM_MODE_H

typedef enum {
    USED_BY_SVC = 0,
    USED_BY_USR = 1
} user_mode_type;

typedef enum {
    CACHE = 1,
    NON_CACHE = 0,
    CACHE_MODE_DEVICE = 2
} cache_mode_type;

typedef enum {
    SECURE = 0,
    NON_SECURE = 1
} secure_mode_type;

typedef enum {
    MAP_ORIGIN = 0,
    MAP_SECURE = 1,
    MAP_NONSECURE = 2
} map_type;

#endif /* LIBTEEMEM_MEM_MODE_H */
