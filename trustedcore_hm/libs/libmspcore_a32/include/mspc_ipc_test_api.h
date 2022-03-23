/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: Header file for msp core extend api.
 * Author : z00452790
 * Create: 2020/06/09
 */

#ifndef __MSPC_IPC_TEST_EXT_API_H__
#define __MSPC_IPC_TEST_EXT_API_H__

#include <tee_internal_api.h>
struct mspc_ipc_test_msg {
    uint32_t data[8];  /* 8: ipc data register number */
};

/*
 * @brief  : Provide ipc test, 8 data registers can be configured externally.
 */
TEE_Result TEE_EXT_MspcIpcTest(struct mspc_ipc_test_msg *msg);

/*
 * @brief  : Provide ddr read data interface.
 * ddr read mspc 4.99M offset:0x320000 size:512K
 */
TEE_Result TEE_EXT_MspcDdrRead(uint32_t addr, uint32_t len, uint8_t *buff, uint32_t *buffLen);

/*
 * @brief  : Provide ddr write data interface.
 * ddr write mspc 4.99M offset:0x320000 size:512K
 */
TEE_Result TEE_EXT_MspcDdrWrite(uint8_t *buff, uint32_t buffLen, uint32_t addr);

#endif /* __MSPC_IPC_TEST_EXT_API_H__ */
