/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2017-2019. All rights reserved.
 * Description: seceng platform depend include
 * Author     : m00475438
 * Create     : 2017/12/22
 */
#ifndef __SECENG_PLAT_H__
#define __SECENG_PLAT_H__
#include <common_define.h>
#include <common_engctrl.h>
#include <pal_libc.h>
#include <pal_cpu.h>
#include <osl_os.h>
#include <pal_memory.h>
#include <pal_baseaddr.h>
#include <pal_interrupt.h>
#include <pal_timer.h>
#include <pal_nv_cfg.h>
#include <pal_log.h>
#include <pal_exception.h>
#include <pal_compiler.h>
#include <common_utils.h>

#include <seceng_timer.h>
#include <seceng_flowctrl.h>
#include <seceng_register.h>
#include <seceng_ctrl.h>
#include <seceng_utils.h>

#if defined(FEATURE_DFT_ENABLE)
#undef PRIVATE
#define PRIVATE

#undef INIT_TEXT
#define INIT_TEXT
#endif /* FEATURE_DFT_ENABLE */

#endif/* __SECENG_PLAT_H__ */
