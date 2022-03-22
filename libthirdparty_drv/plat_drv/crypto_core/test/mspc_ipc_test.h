/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: Header file for mspc test.
 * Author : z00452790
 * Create: 2020/06/09
 */

#ifndef __MSPC_IPC_TEST_H__
#define __MSPC_IPC_TEST_H__

#include <tee_log.h>
#include <register_ops.h>
#include <mspc_mem_layout.h>

#define MSPC_DDR_TEST_OFFSET 0x320000  /* sa ddr */
#define MSPC_DDR_TEST_START MSPC_DDR_START_ADDR + MSPC_DDR_TEST_OFFSET
#define MSPC_DDR_TEST_SIZE   0x80000   /* 512k   */
#define read_byte(addr)      (*(volatile unsigned char *)  ((uintptr_t)(addr)))
#define write_byte(addr, val) {W_DWB; \
    (*(volatile unsigned char *)((uintptr_t)(addr)) = (val));\
    W_DWB;}

struct mspc_ipc_test_msg {
    uint32_t data[8];  /* 8: mspc ipc data register number */
};
int32_t mspc_ipc_test(struct mspc_ipc_test_msg *msg);
int32_t mspc_ddr_read(uint32_t addr, uint32_t len, uint8_t *buff, uint32_t *buff_len);
int32_t mspc_ddr_write(uint8_t *buff, uint32_t buff_len, uint32_t addr);

#endif /* __MSPC_IPC_TEST_H__ */
