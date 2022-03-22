/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: Header file for mspc test.
 * Author : w00371137
 * Create: 2020/01/14
 */

#ifndef __MSPC_TEST_H__
#define __MSPC_TEST_H__

#include <tee_log.h>
#include <hieps_smc.h>
#include <msptest_interface.h>

uint32_t mspc_driver_test(uint32_t num,
                          const struct msptest_to_tee_parms *parm_info,
                          char *iodata);
#endif /* __MSPC_TEST_H__ */
