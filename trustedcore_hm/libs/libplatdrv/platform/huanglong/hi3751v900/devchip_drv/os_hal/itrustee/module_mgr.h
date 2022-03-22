/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: module register api
 * Author: Hisilicon
 * Created: 2019-12-03
 */

#ifndef _MODULE_MGR_H
#define _MODULE_MGR_H

#include "hi_tee_drv_os_hal.h"

#ifdef __cplusplus
extern "C"
{
#endif

int tee_hisilicon_ioctl(const unsigned int module, const unsigned int cmd, void *args, const size_t size);
int tee_drv_module_register(const unsigned int module, hi_tee_hal_syscall fn);

#ifdef __cplusplus
}
#endif

#endif /* _MODULE_MGR_H */

