/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: io entry for autotest
 * Author     : m00475438
 * Create     : 2019/08/11
 */
#ifndef __HAT_ENTRY_H__
#define __HAT_ENTRY_H__
#include <common_define.h>

enum hat_port {
	HAT_PORT_PACK = 0, /* raw autotest frame */
	HAT_PORT_UART, /* uart package of autotest frame */
	HAT_PORT_MAX
};

u32 hat_cur_port(void);
u32 hat_entry_counter(u32 port);
u32 hat_packet_max_size(void);
err_bsp_t hat_process(u32 port, u8 *pdata, u32 *psize);

#endif /* __HAT_ENTRY_H__ */
