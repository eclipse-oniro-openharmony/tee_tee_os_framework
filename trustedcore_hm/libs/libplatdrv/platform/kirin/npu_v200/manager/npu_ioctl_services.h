/*
 * npu_ioctl_services.h
 *
 * Copyright (c) 2012-2020 Huawei Technologies Co., Ltd.
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 */

#ifndef __NPU_IOCTL_SERVICE_H__
#define __NPU_IOCTL_SERVICE_H__
#include "npu_proc_ctx.h"

void npu_init_ioctl_call(void);
int npu_proc_ioctl_call(npu_proc_ctx_t *proc_ctx, unsigned int cmd, uintptr_t arg);

#endif /* __NPU_IOCTL_SERVICE_H__ */
