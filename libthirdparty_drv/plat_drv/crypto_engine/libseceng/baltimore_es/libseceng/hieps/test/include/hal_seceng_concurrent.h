/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: seceng ip concurrent test entry.
 * Author: l00441158, lisen10@huawei.com
 * Create: 2019/09/25
 */
#ifndef __HAL_SECENG_CONCURRENT_H__
#define __HAL_SECENG_CONCURRENT_H__
#include <common_define.h>

enum concurrent_ip_type {
	CONCURRENT_IP_RSA = 0,
	CONCURRENT_IP_ECC,
	CONCURRENT_IP_SCE,

	CONCURRENT_IP_MAX
};

union concurrent_alg_info {
	u32 value;
	struct {
		u32 alg      : 8;
		u32 ip_idx   : 8;
		u32 ip_type  : 8; /* ::concurrent_ip_type */
		u32 reserved : 8;
	} info;
};

struct concurrent_alg_param {
	union concurrent_alg_info alg;
	pal_handle_t parg;
};

/* for concurrent ip test */
typedef err_bsp_t (*ip_start_func_t)(u32 ip_idx);
typedef err_bsp_t (*ip_check_done_t)(u32 ip_idx);
typedef err_bsp_t (*ip_run_alg_t)(union concurrent_alg_info alg_info,
				  pal_handle_t alg_ctx);

typedef err_bsp_t (*ip_register_agent_t)(u32 ip_idx,
					 pal_callback_t start_callback);

struct concurrent_ip_handler {
	ip_start_func_t start;
	ip_check_done_t check_done;
	ip_run_alg_t    compute;
	ip_register_agent_t agent;
};

typedef err_bsp_t (*ip_load_handler)(struct concurrent_ip_handler *phandler);

/* set perf status */
void hal_concurrent_set_perf(u32 is_perf);

/* basic run test */
err_bsp_t hal_concurrent_run_test(u32 alg_num, u32 is_stress,
				  struct concurrent_alg_param **pparam_list);

/* loop test */
err_bsp_t hal_concurrent_loop_test(u32 loop_num, u32 alg_num, u32 is_stress,
				   struct concurrent_alg_param **pparam_list);

#endif
