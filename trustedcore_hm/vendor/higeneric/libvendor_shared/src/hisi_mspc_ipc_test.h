 /*
  * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
  * Description: Header file for MSPC IPC test drivers
  * Author : z00452790
  * Create: 2020/07/07
  */

#ifndef __HISI_MSPC_TASK_H__
#define __HISI_MSPC_TASK_H__

#include "stdint.h"

#ifdef CONFIG_HISI_MSPC_IPC_TEST
int32_t __mspc_ipc_test(uint8_t *msg, uint32_t len);
int32_t __mspc_ddr_read(uint32_t addr, uint32_t len, uint8_t *buff, uint32_t *bufflen);
int32_t __mspc_ddr_write(uint8_t *buff, uint32_t bufflen, uint32_t addr);
#endif

#endif /* end of __HISI_MSPC_TASK_H__ */
