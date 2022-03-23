/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2017-2019. All rights reserved.
 * Description: kdf秘钥派生模块
 * Author: hsan
 * Create: 2017-4-11
 * History: 2017-4-11初稿完成
 *          2019-1-31 hsan code restyle
 */

#include "hi_kdf.h"
#include "hi_sec_api.h"
#include "hi_sec_reg_kdf.h"
#include "sre_log.h"
#include "securec.h"

#ifdef HI_VERSION_DEBUG
#define hi_kdf_printmemdes(dbglevel,src,len,fmt,arg...) \
    hi_memdes(HI_KSOC_SDK_L2_SCRTY, dbglevel, src, len, (hi_uchar8 *)fmt, ##arg)
#define hi_kdf_systrace(ret, arg1, arg2, arg3, arg4) \
    hi_systrace(HI_KSOC_SDK_L2_SCRTY, ret, arg1, arg2, arg3, arg4)
#define hi_kdf_debug(level, fmt, arg...) \
    hi_debug(HI_KSOC_SDK_L2_SCRTY, level, fmt, ##arg)
#define hi_kdf_print(level, fmt, arg...) \
    hi_print(HI_KSOC_SDK_L2_SCRTY, level, fmt, ##arg)
#else
#define hi_kdf_printmemdes(dbglevel, src, len, fmt, arg...)
#define hi_kdf_systrace(ret, arg1, arg2, arg3, arg4)
#define hi_kdf_debug(module, level, fmt, arg...)
#define hi_kdf_print(module, dbglevel, fmt, arg...)
#endif

static hi_int32 hi_kdf_is_busy(hi_void)
{
	hi_int32 ret = HI_RET_SUCC;
	hi_uint32 timeout = (1000 * 1000) / 10;
	struct hi_sdk_l0_reg_kdf_hisc_kdf_busy_s kdf_busy;
	/* 
	 * 读取KDF_BUSY状态寄存器（偏移地址0x00）
	 * 如果KDF_BUSY为0x1，则等待（可设置等待超时，可设置为1s
	 */
	while (--timeout) {
		hi_sdk_l0_read_reg(HI_SDK_L0_REG_KDF_HISC_KDF_BUSY_BASE,
			(hi_uint32 *)&kdf_busy);
		if (!kdf_busy.kdf_busy)
			break;
		hi_udelay(10);
	}
	if (!timeout) {
		hi_kdf_systrace(HI_RET_TIMEOUT, kdf_busy.kdf_busy, 0, 0, 0);
		ret = HI_RET_TIMEOUT;
	}
	return ret;
}

static hi_void hi_kdf_clr_intst(hi_void)
{
	struct hi_sdk_l0_reg_kdf_hisc_kdf_int_st_s int_st;
	/*
	 * 配置KDF_ALARM（偏移地址0x0C）清除中断输出信号
	 * 避免历史中中断状态对本次操作产生影响
	 */
	int_st.resv_0 = 0;
	int_st.kdf_int = 1;           /* 写1清零 */
	int_st.kdf_busy_wr_alarm = 1; /* 写1清零 */
	hi_sdk_l0_write_reg(HI_SDK_L0_REG_KDF_HISC_KDF_INT_ST_BASE,
		(hi_uint32 *)&int_st);
}

static hi_void hi_kdf_config_key(hi_uint32 base_addr, 
	hi_uint32 *key, hi_uint32 key_num)
{
	hi_uint32 i;
	hi_uint32 addr;

	for (i = 0; i < key_num; i++, key++) {
		addr = base_addr + i * sizeof(base_addr);
		hi_sdk_l0_write_reg(addr, key);
	}
}

static hi_void hi_kdf_get_key(hi_uint32 base_addr, 
	hi_uint32 *key, hi_uint32 key_num)
{
	hi_uint32 i;
	hi_uint32 addr;

	for (i = 0; i < key_num; i++, key++) {
		addr = base_addr + i * sizeof(base_addr);
		hi_sdk_l0_read_reg(addr, key);
	}
}

/* kdf设备秘钥派生 */
hi_uint32 hi_kdf_to_dev(struct hi_sec_pbkdf2 *para)
{
	struct hi_sdk_l0_reg_kdf_hisc_kdf_busy_s kdf_busy;
	struct hi_sdk_l0_reg_kdf_hisc_kdf_int_st_s int_st;
	hi_uint32 value;

	if (para == HI_NULL)
		return HI_RET_NULLPTR;
	if (hi_kdf_is_busy())
		return HI_RET_TIMEOUT;

	hi_kdf_clr_intst();

	/* 配置参数PSK（偏移地址0x20~0x3C），PSK有256bit，需要分8次配置 */
	hi_kdf_config_key(HI_SDK_L0_REG_KDF_HISC_KDF_PSK0_BASE,
		(hi_uint32 *)para->passwd, 8);

	/* 配置参数SN（偏移地址0x60~06C），SN有128bit，需要分4次配置 */
	hi_kdf_config_key(HI_SDK_L0_REG_KDF_HISC_KDF_SN0_BASE,
		(hi_uint32 *)para->salt, 4);

	/* 配置模式KDF_MODE（偏移地址0x04），配置选择设备密钥派生模式 */
	value = 0;
	hi_sdk_l0_write_reg(HI_SDK_L0_REG_KDF_HISC_KDF_MODE_BASE, &value);

	/* 配置HMAC迭代次数KDF_ITERATION（偏移地址0x08），最小配置值为0x1 */
	value = para->iter;
	hi_sdk_l0_write_reg(HI_SDK_L0_REG_KDF_HISC_KDF_ITERATION_BASE, &value);

    __asm__ volatile("isb");
    __asm__ volatile("dsb sy");

	/*
	 * 配置KDF_BUSY为0x1（偏移地址0x00）
	 * 则启动KDF开始计算同时清除历史中断输出KDF_INT；
	 * KDF计算完成后，会将KDF_BUSY拉低；
	 */
	kdf_busy.kdf_busy = 1;
	hi_sdk_l0_write_reg(HI_SDK_L0_REG_KDF_HISC_KDF_BUSY_BASE,
		(hi_uint32 *)&kdf_busy);

	/*
	 * 等待KDF模块的中断信号KDF_INT或读取KDF模块的KDF_BUSY状态寄存器；
	 * 如果KDF_INT中断拉高或KDF_BUSY从0x1更新为0x0；则进入一下步骤；
	 * 否则等待（可设置等待超时，设置时间为1s）；
	 */
	if (hi_kdf_is_busy())
		return HI_RET_TIMEOUT;

	/*
	 * 判断KDF是否有KDF_ALARM异常中断，如果有，
	 * 则需要读取KDF_ALARM_STATE状态（偏移地址0x0C），获取异常中断信息；
	 */
	hi_sdk_l0_read_reg(HI_SDK_L0_REG_KDF_HISC_KDF_INT_ST_BASE,
		(hi_uint32 *)&int_st);
	if (int_st.kdf_busy_wr_alarm) {
		hi_kdf_systrace(HI_RET_FAIL, 0, 0, 0, 0);
		return HI_RET_FAIL;
	}

	/*
	 * 读取KDF_RSLT密钥派生结果（偏移地址0x70~0x8C）
	 * KDF_RSLT有256bit，分8次读取；
	 */
	hi_kdf_get_key(HI_SDK_L0_REG_KDF_HISC_KDF_RSLT0_BASE,
		(hi_uint32 *)para->dk, 8);

	hi_kdf_systrace(HI_RET_SUCC, 0, 0, 0, 0);

	return HI_RET_SUCC;
}

/* kdf存储秘钥派生 */
hi_uint32 hi_kdf_to_store(struct hi_sec_kdf_internal *para)
{
	struct hi_sdk_l0_reg_kdf_hisc_kdf_busy_s kdf_busy;
	struct hi_sdk_l0_reg_kdf_hisc_kdf_int_st_s int_st;
	hi_uint32 value;

	if (para == HI_NULL)
		return HI_RET_NULLPTR;
	if (hi_kdf_is_busy())
		return HI_RET_TIMEOUT;

	hi_kdf_clr_intst();

	/* 配置参数CPU_KEY（偏移地址0x40~0x5C），CPU_KEY有256bit，分8次配置 */
	hi_kdf_config_key(HI_SDK_L0_REG_KDF_HISC_KDF_CPU_KEY0_BASE,
		(hi_uint32 *)para->key, 8);

	/* 配置模式KDF_MODE（偏移地址0x04），配置选择存储密钥派生模式； */
	value = 1;
	hi_sdk_l0_write_reg(HI_SDK_L0_REG_KDF_HISC_KDF_MODE_BASE, &value);

	/* 配置HMAC迭代次数KDF_ITERATION（偏移地址0x08），最小配置值为0x1 */
	value = para->iter;
	hi_sdk_l0_write_reg(HI_SDK_L0_REG_KDF_HISC_KDF_ITERATION_BASE, &value);

    __asm__ volatile("isb");
    __asm__ volatile("dsb sy");

	/*
	 * 配置KDF_BUSY为0x1（偏移地址0x00）
	 * 则启动KDF开始计算同时清除历史中断输出KDF_INT；
	 * KDF计算完成后，会将KDF_BUSY拉低
	 */
	kdf_busy.kdf_busy = 1;
	hi_sdk_l0_write_reg(HI_SDK_L0_REG_KDF_HISC_KDF_BUSY_BASE,
		(hi_uint32 *)&kdf_busy);

	/*
	 * 等待KDF模块的中断信号KDF_INT或读取KDF模块的KDF_BUSY状态寄存器；
	 * 如果KDF_INT中断拉高或KDF_BUSY从0x1更新为0x0；则进入一下步骤；
	 * 否则等待（可设置等待超时，设置时间为1s）
	 */
	if (hi_kdf_is_busy())
		return HI_RET_TIMEOUT;

	/*
	 * 判断KDF是否有KDF_ALARM异常中断，如果有，
	 * 则需要读取KDF_ALARM_STATE状态（偏移地址0x0C），获取异常中断信息
	 */
	hi_sdk_l0_read_reg(HI_SDK_L0_REG_KDF_HISC_KDF_INT_ST_BASE,
		(hi_uint32 *)&int_st);
	if (int_st.kdf_busy_wr_alarm) {
		hi_kdf_systrace(HI_RET_FAIL, 0, 0, 0, 0);
		return HI_RET_FAIL;
	}

    hi_kdf_get_key(HI_SDK_L0_REG_KDF_HISC_KDF_RSLT0_BASE, (hi_uint32 *)para->dk, 8);

	hi_kdf_systrace(HI_RET_SUCC, 0, 0, 0, 0);
	return HI_RET_SUCC;
}
