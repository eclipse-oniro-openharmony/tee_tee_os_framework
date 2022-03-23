/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: This file is for io memory copy
 * Create: 2021-04
 */

#ifndef PLATDRV_IO_OPERATION_H
#define PLATDRV_IO_OPERATION_H

void read_from_io(void *to, const volatile void *from, unsigned long count);
void write_to_io(volatile void *to, const void *from, unsigned long count);

#endif
