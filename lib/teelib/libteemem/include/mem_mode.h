/*
 * Copyright (C) 2022 Huawei Technologies Co., Ltd.
 * Licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
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
