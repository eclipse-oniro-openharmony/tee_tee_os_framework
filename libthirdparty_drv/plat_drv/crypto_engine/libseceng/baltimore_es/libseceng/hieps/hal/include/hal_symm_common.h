/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: hal-level common struct for hal module
 * Author: l00370476, liuchong13@huawei.com
 * Create: 2019/07/25
 */
#ifndef __HAL_SYMM_COMMON_H__
#define __HAL_SYMM_COMMON_H__
#include <pal_types.h>

#define ADDR_NUMS 2
enum addr_type {
	ADDR_TYPE_CPU    = 0,
	ADDR_TYPE_MASTER = 1,
};

enum strategy {
	STRATEGY_HIGH_SECRURITY = 0,
	STRATEGY_HIGH_PERF,
	STRATEGY_MAX,
};

struct data_addr {
	u32        type;
	pal_addr_t addr;
};

struct build_rxaddr {
	u32   ip_idx;
	u8    *pdin[ADDR_NUMS];
	u32   dinlen[ADDR_NUMS];
	pal_master_addr_t *rxaddr;
};

struct build_txaddr {
	u32   ip_idx;
	u8    *pdout[ADDR_NUMS];
	u32   doutlen[ADDR_NUMS];
	pal_master_addr_t *txaddr;
};

/*
 * creat buf from workspace, copy pdin to workspace, support multi-pdin.
 */
err_bsp_t hal_symm_build_rxaddr(struct build_rxaddr *pbrx);

/*
 * creat buf from workspace. support multi-pdin.
 */
err_bsp_t hal_symm_build_txaddr(struct build_txaddr *pbtx);

err_bsp_t hal_symm_output_workspace(u32 ip_idx,
				    u8 *pdout, u32 doutlen, u32 offset);

err_bsp_t hal_symm_clr_workspace(u32 ip_idx, u32 clrsize);

u32 hal_symm_choose_ip_idx(u32 strategy);

#endif
