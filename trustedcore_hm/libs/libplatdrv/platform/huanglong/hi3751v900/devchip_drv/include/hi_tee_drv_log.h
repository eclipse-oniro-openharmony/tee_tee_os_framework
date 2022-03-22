/*
 * Copyright (C) Hisilicon Technologies Co., Ltd. 2019. All rights reserved.
 * Description: Tee log drv.
 */

#ifndef __TEE_DRV_LOG_H__
#define __TEE_DRV_LOG_H__

#include "hi_log.h"
#include "hi_type_dev.h"
#include "hi_tee_module_id.h"

#ifdef __cplusplus
extern "C" {
#endif

hi_s32  hi_drv_log_set_level(hi_mod_id module_id, hi_tee_log_level log_level);
hi_s32  hi_drv_log_get_level(hi_mod_id module_id, hi_tee_log_level *log_level_ptr);
hi_void hi_drv_log_print_key(hi_mod_id module_id, hi_tee_log_level log_level, hi_char *addr, hi_u32 len);
hi_void hi_log_print(hi_u32 log_level, hi_u32 module_id, const hi_u8 *func_name,
                     hi_u32 line_num, const hi_char *format, ...);

#ifdef __cplusplus
}
#endif

#endif /* __TEE_DRV_LOG_H__ */

