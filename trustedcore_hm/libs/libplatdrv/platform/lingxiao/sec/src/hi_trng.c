/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2017-2019. All rights reserved.
 * Description: trng 随机数产生模块
 * Author: hsan
 * Create: 2017-4-11
 * History: 2017-4-11初稿完成
 *          2019-1-31 hsan code restyle
 */

#include "hi_trng.h"
#include "hi_sec_api.h"
#include "hi_sec_reg_trng.h"
#include "sre_log.h"

#define HI_TRNG_CHECK_QOTA 10000
#define HI_TRNG_READY      0x3

static hi_int32 hi_trng_get_32bit(hi_uint32 *value)
{
	struct hi_sdk_l0_reg_trng_hisc_com_trng_fifo_ready_s fifo_ready;
	hi_uint32 qota = HI_TRNG_CHECK_QOTA;

	/*
	 * 如果在初始化后，多次查询trng_data_ready状态，
	 * 均不能等于2'b11时（可设置在10ms内都没有查询ready状态），
	 * 表明trng模块可能被攻击，进行中断异常处理；如果为2'b11，
	 * 则可以读取随机数寄存器获取随机数。
	 */
	do {
		hi_sdk_l0_read_reg(
			HI_SDK_L0_REG_TRNG_HISC_COM_TRNG_FIFO_READY_BASE,
			(hi_uint32 *)&fifo_ready);
		if (fifo_ready.trng_data_ready == HI_TRNG_READY)
			break;

		qota--;
		hi_udelay(1);
	} while (qota > 0);

	if (fifo_ready.trng_data_ready != HI_TRNG_READY || qota == 0)
		return HI_RET_FAIL;

	hi_sdk_l0_read_reg(HI_SDK_L0_REG_TRNG_HISC_COM_TRNG_FIFO_DATA_BASE,
			   value);

	return HI_RET_SUCC;
}

/* 获取真随机数 */
hi_int32 hi_sec_trng_get(struct hi_sec_trng *rng)
{
	struct hi_sdk_l0_reg_trng_hisc_com_trng_fifo_data_s fifo_data;
	hi_uint32 index;
	hi_uint32 cnt = HI_RNG_DATALEN / sizeof(hi_uint32);
	hi_uint32 *rand = HI_NULL;
	hi_int32 ret;

	if (rng == HI_NULL)
		return HI_RET_NULLPTR;

	rand = (hi_uint32 *)rng->rng;
	for (index = 0; index < cnt; index++, rand++) {
		ret = hi_trng_get_32bit((hi_uint32 *)&fifo_data);
		if (ret != HI_RET_SUCC)
			return ret;
		*rand = fifo_data.trng_fifo_data;
	}

	return HI_RET_SUCC;
}
