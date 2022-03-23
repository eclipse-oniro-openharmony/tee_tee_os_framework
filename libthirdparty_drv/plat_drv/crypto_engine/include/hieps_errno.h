/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: This file defines error number.
 * Author: w00371137, wangyuzhu4@@huawei.com
 * Create: 2019-01-31
 */

#ifndef __HIEPS_ERRNO_H__
#define __HIEPS_ERRNO_H__

#define HIEPS_OK                            0x0
#define HIEPS_ERROR                         0xF000
#define HIEPS_TIMEOUT_ERR                   0xF001
#define HIEPS_ALLOC_ERR                     0xF002
#define HIEPS_PARAM_ERR                     0xF003
#define HIEPS_MUTEX_ERR                     0xF004
#define HIEPS_CFG_CLK_SRC_ERR               0xF005
#define HIEPS_CFG_CLK_DIV_ERR               0xF006
#define HIEPS_CFG_DDR_L3_CACHE_ERR          0xF007
#define HIEPS_CFG_DDR_CACHE_ERR             0xF008
#define HIEPS_WAIT_SMC_ERR                  0xF009
#define HIEPS_WAIT_BSP_ERR                  0xF00A
#define HIEPS_CONFLICT_ERR                  0xF00B
#define HIEPS_STATUS_ERR                    0xF00C
#define HIEPS_INVALID_PROC_ERR              0xF00D
#define HIEPS_TIMER_ERR                     0xF00E
#define HIEPS_BIND_ERR                      0xF00F
#define HIEPS_MAP_ERR                       0xF010
#define HIEPS_DUP_ERR                       0xF011
#define HIEPS_MMU_INIT_ERR                  0xF012
#define HIEPS_MMU_EXIT_ERR                  0xF013
#define HIEPS_MMU_HASH_ERR                  0xF014
#define HIEPS_MMU_CMP_ERR                   0xF015
#define HIEPS_MMU_COMM_ERR                  0xF016
#define HIEPS_MMU_TCU_ERR                   0xF017
#define HIEPS_MMU_CRPPTO_ERR                0xF018
#define HIEPS_MMU_TIME_OUT_ERR              0xF019


#endif /* __HIEPS_ERRNO_H__ */
