/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: Provide parameter transportation buffer between drivers and frame.
 * Create: 2020-05-18
 */
#ifndef DRV_PARAM_OPS_H
#define DRV_PARAM_OPS_H

#include <stdint.h>

int32_t copy_from_client(uint64_t src, uint32_t src_size, uintptr_t dst, uint32_t dst_size);
int32_t copy_to_client(uintptr_t src, uint32_t src_size, uint64_t dst, uint32_t dst_size);
#endif
