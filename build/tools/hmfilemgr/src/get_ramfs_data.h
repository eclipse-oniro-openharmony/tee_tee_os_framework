/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2020. All rights reserved.
 * Description: Procedure for reading ramfs data (for AArch64)
 * Create: 2018-05-08
 */
#ifndef _GET_RAMFS_DATA_H_
#define _GET_RAMFS_DATA_H_

#include <stddef.h>

void *get_ramfs_data(size_t *ramfs_size);
extern char g_ramfs_data[];
extern size_t g_ramfs_size;
#endif /* _GET_RAMFS_DATA_H_ */
