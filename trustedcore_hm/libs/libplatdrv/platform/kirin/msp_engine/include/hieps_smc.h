/*
 * @file   : hieps_smc.h
 * @brief  :
 * @par    : Copyright (c) 2017-2033, HUAWEI Technology Co., Ltd.
 * @date   : 2019/01/04
 * @author : w00371137, wangyuzhu4@@huawei.com
 * @note   :
 */
#ifndef __HIEPS_SMC_H__
#define __HIEPS_SMC_H__

#include <eps_ddr_layout_define.h>

#define HIEPS_SMC_RET_FLAG_ADDR          (EPS_TEEOS_SMC_RET_FLAG_ADDR(HIEPS_DDR_SPACE_BASE_ADDR))
#define HIEPS_SMC_WAIT_TIME              100000  /* 100000 x 5us = 500ms */

#define HIEPS_SMC_FID                    0x85000080  // teeos to atf smc fid
#define DELAYTIME                        10               // delay 10ms
#define WAITTIMES                        100               // wait for 1s
#define HIEPS_TEEOS_SUCCESS              0x0
#define HIEPS_TEEOS_ERROR                0xd0
#define HIEPS_TEEOS_MALLOC_ERROR         0xd1
#define HIEPS_TEEOS_CMD_ERROR            0xd2
#define HIEPS_TEEOS_DATA_ERROR           0xd3
#define HIEPS_TEEOS_PARM_ERROR           0xd4
#define HIEPS_TEEOS_RESULT_ERROR         0xd5
#define HIEPS_TEEOS_LOOP_TEST_DATA_ERROR 0xd6
#define HIEPS_TEEOS_TIMEOUT_ERROR        0xd7
#define HIEPS_TEEOS_SMC_ERROR            0xd8
#define HIEPS_TEEOS_SYSCALL_ERROR        0xd9
#define HIEPS_TEEOS_MMAP_ERROR           0xda
#define HIEPS_TEEOS_SECENG_ERROR         0xdb
#define HIEPS_RETURN_DRR_FLAG_IS_NULL    0x00
#define HIEPS_RETURN_DRR_FLAG_IS_GETTED  0xff
#define HIEPS_ATF_KERNEL_TEST_SUCCESS    0xC96B3F74
#define MAXDATALEN                       16384  /* 16k  */

enum hieps_smc_status {
	HIEPS_SMC_RUNNING         = 0x3C,
	HIEPS_SMC_DONE            = 0xC3,
};

enum hieps_smc_cmd_type {
	HIEPS_POWER_ON_CMD          = 0x1001,
	HIEPS_POWER_OFF_CMD         = 0x1002,
	HIEPS_DVFS_CMD              = 0x1003,
	HIEPS_KDR_SET_CMD           = 0x1004,
	HIEPS_GET_LCS_CMD           = 0x1005,
	HIEPS_SYNC_CMA_ALLOC_CMD    = 0x1006,
	HIEPS_GET_SMX_CMD           = 0x1007,
	HIEPS_SET_SMX_CMD           = 0x1008,
	HIEPS_GET_EFUSE_LITE_CMD    = 0x1009,
	HIEPS_TCU_POWER_ON_CMD      = 0x100a,
	HIEPS_TCU_POWER_OFF_CMD     = 0x100b,
	HIEPS_TCU_POWER_DEFAULT_CMD = 0x100c,
	HIEPS_POWER_DEFAULT_CMD     = 0x100d,

	/* TODO:test cmd, need add macro. */
	HIEPS_LOOP_TEST_CMD         = 0x2001, /* Test the whole process. */
	HIEPS_ATF_TEEOS_TEST_CMD    = 0x2002, /* Test teeos <-> atf. Donot use in kernel. */
	HIEPS_ATF_KERNEL_TEST_CMD   = 0x2003, /* Test kernel <-> atf. */
	HIEPS_CMD_END,
};

uint32_t hieps_smc_send_process(uint64_t arg0, uint64_t arg1, uint64_t arg2, uint64_t arg3);

#endif /* __HIEPS_SMC_H__ */
