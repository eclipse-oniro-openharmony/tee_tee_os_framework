/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: keyladder session node list manager.
 * Author: Hisilicon hisecurity team
 * Create: 2019-06-25
 */
#ifndef __DRV_KLAD_SW_H__
#define __DRV_KLAD_SW_H__

#include "drv_klad_hw_define.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif /* end of #ifdef __cplusplus */

hi_s32 fmw_klad_ioctl(unsigned int cmd, hi_void *arg, hi_u32 len);

hi_void hi_tee_drv_hkl_ins_init(hi_void);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* end of #ifdef __cplusplus */

#endif  /* __DRV_KLAD_SW_H__ */
