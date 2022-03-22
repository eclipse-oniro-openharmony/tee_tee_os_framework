/*
 * npu_pm.h
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

#ifndef __NPU_PM_H__
#define __NPU_PM_H__
#include "npu_dev_ctx.h"

int npu_powerup(npu_dev_ctx_t *dev_ctx);
int npu_powerdown(npu_dev_ctx_t *dev_ctx);

#endif /* __NPU_PM_H__ */
