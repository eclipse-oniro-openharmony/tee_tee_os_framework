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
#define HIEPS_SMC_WAIT_TIME              20000  /* 20000 x 5us = 100ms */

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
#define PARMSIZE                         64     /* Each parameter occupies 64 bytes */
#define PARMNUM                          6      /* num parameter is 5, The first one is the quantity */
#define MAXDATALEN                       16384  /* 16k  */

enum hieps_smc_status {
	HIEPS_SMC_RUNNING         = 0x3C,
	HIEPS_SMC_DONE            = 0xC3,
};

enum hieps_smc_cmd_type {
	HIEPS_POWER_ON_CMD        = 0x1001,
	HIEPS_POWER_OFF_CMD       = 0x1002,
	HIEPS_DVFS_CMD            = 0x1003,
	HIEPS_KDR_SET_CMD         = 0x1004,
	HIEPS_GET_LCS_CMD         = 0x1005,
	HIEPS_SYNC_CMA_ALLOC_CMD  = 0x1006,
	HIEPS_GET_SMX_CMD         = 0x1007,
	HIEPS_SET_SMX_CMD         = 0x1008,
	HIEPS_GET_EFUSE_LITE_CMD  = 0x1009,
	HIEPS_TCU_POWER_ON_CMD    = 0x100a,
	HIEPS_TCU_POWER_OFF_CMD   = 0x100b,
	/* TODO:test cmd, need add macro. */
	HIEPS_LOOP_TEST_CMD       = 0x2001, /* Test the whole process. */
	HIEPS_ATF_TEEOS_TEST_CMD  = 0x2002, /* Test teeos <-> atf. Donot use in kernel. */
	HIEPS_ATF_KERNEL_TEST_CMD = 0x2003, /* Test kernel <-> atf. */
	HIEPS_CMD_END,
};

enum cmd_list {
	HIEPS_POWERON = 1,          /* hieps power on  */
	HIEPS_POWEROFF = 2,         /* hieps power off */
	HIEPS_LOOP_TEST = 3,        /* loop test */
	HIEPS_CA_TA_TEST = 4,       /* ca-->ta test */
	HIEPS_TA_DRIVES_TEST = 5,   /* ta-->teeos test */
	HIEPS_DRIVES_ATF_TEST = 6,  /* teeos-->atf test */
	HIEPS_ATF_KERNEL_TEST = 7,  /* atf-->kernel test */
	HIEPS_SECENG_TEST = 8,      /* seceng test */
	HIEPS_FACTORY_TEST = 9,     /* factory test */
	HIEPS_ECALL = 10,           /* hieps ecall test */
	HIEPS_HELP  = 11,           /* hieps help */
	COMMON_TEST = 12,           /* General test cmd */
};

struct msptest_to_tee_parms {
	char parm[PARMNUM][PARMSIZE];
	uint32_t parm_num;
	uint32_t ion_test_flag;
	uint32_t real_data_len;
	uint32_t max_data_len;
	uint32_t ion_sharefd;
	uint32_t ion_len;
	uint32_t cma_phy;
	uint32_t cma_len;
};

uint32_t hieps_smc_send_process(uint64_t arg0, uint64_t arg1, uint64_t arg2, uint64_t arg3);

#endif /* __HIEPS_SMC_H__ */
