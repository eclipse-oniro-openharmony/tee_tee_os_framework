/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: interface for seceng control dft.
 * Author: m00475438
 * Create: 2019/11/02
 */
#ifndef __HAL_ENGCTRL_DFT_H__
#define __HAL_ENGCTRL_DFT_H__
#include <common_define.h>

void hal_engctrl_sysrst_restore(void);
void hal_engctrl_sysrst_save(void);

/* se config save & restore */
#define SECENG_SYSRST_SAVE() \
	hal_engctrl_sysrst_save()

#define SECENG_SYSRST_RESTORE() \
	hal_engctrl_sysrst_restore()

#endif /* __HAL_ENGCTRL_DFT_H__ */
