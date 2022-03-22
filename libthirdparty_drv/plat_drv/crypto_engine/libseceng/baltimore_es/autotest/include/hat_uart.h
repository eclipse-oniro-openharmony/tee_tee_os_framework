/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: uart port entry for autotest
 * Author     : m00475438
 * Create     : 2019/08/11
 */
#ifndef __HAT_UART_H__
#define __HAT_UART_H__
#include <common_define.h>

/**
 *    [ HAT For UART ]
 *                           |-------------------- [size] --------------------|
 * | ----- shell line ------ | 1B | 1B |-- 2B- -|---- 4B ----|---- [len] -----|
 * ---------------------------------------------------------------------------
 * | '{test_req:[size]}\r\n' |0x5A|0x02| [CRC]  |   [len]    |  [PACKET Data] |
 *           -----------------------------------------------------------------
 * | '{test_rsp:[size]}\r\n' |0x5A|0x03| [CRC]  |   [len]    |  [PACKET Data] |
 *           -----------------------------------------------------------------
 */

err_bsp_t hat_uart_pkt_hook(char ch);
err_bsp_t hat_uart_pkt_sniff(const char *cmd, u32 cmd_len);

#endif /* __HAT_UART_H__ */
