/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2017-2019. All rights reserved.
 * Description: kdf��Կ����ģ��
 * Author: hsan
 * Create: 2017-4-11
 * History: 2017-4-11�������
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
	 * ��ȡKDF_BUSY״̬�Ĵ�����ƫ�Ƶ�ַ0x00��
	 * ���KDF_BUSYΪ0x1����ȴ��������õȴ���ʱ��������Ϊ1s
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
	 * ����KDF_ALARM��ƫ�Ƶ�ַ0x0C������ж�����ź�
	 * ������ʷ���ж�״̬�Ա��β�������Ӱ��
	 */
	int_st.resv_0 = 0;
	int_st.kdf_int = 1;           /* д1���� */
	int_st.kdf_busy_wr_alarm = 1; /* д1���� */
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

/* kdf�豸��Կ���� */
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

	/* ���ò���PSK��ƫ�Ƶ�ַ0x20~0x3C����PSK��256bit����Ҫ��8������ */
	hi_kdf_config_key(HI_SDK_L0_REG_KDF_HISC_KDF_PSK0_BASE,
		(hi_uint32 *)para->passwd, 8);

	/* ���ò���SN��ƫ�Ƶ�ַ0x60~06C����SN��128bit����Ҫ��4������ */
	hi_kdf_config_key(HI_SDK_L0_REG_KDF_HISC_KDF_SN0_BASE,
		(hi_uint32 *)para->salt, 4);

	/* ����ģʽKDF_MODE��ƫ�Ƶ�ַ0x04��������ѡ���豸��Կ����ģʽ */
	value = 0;
	hi_sdk_l0_write_reg(HI_SDK_L0_REG_KDF_HISC_KDF_MODE_BASE, &value);

	/* ����HMAC��������KDF_ITERATION��ƫ�Ƶ�ַ0x08������С����ֵΪ0x1 */
	value = para->iter;
	hi_sdk_l0_write_reg(HI_SDK_L0_REG_KDF_HISC_KDF_ITERATION_BASE, &value);

    __asm__ volatile("isb");
    __asm__ volatile("dsb sy");

	/*
	 * ����KDF_BUSYΪ0x1��ƫ�Ƶ�ַ0x00��
	 * ������KDF��ʼ����ͬʱ�����ʷ�ж����KDF_INT��
	 * KDF������ɺ󣬻ὫKDF_BUSY���ͣ�
	 */
	kdf_busy.kdf_busy = 1;
	hi_sdk_l0_write_reg(HI_SDK_L0_REG_KDF_HISC_KDF_BUSY_BASE,
		(hi_uint32 *)&kdf_busy);

	/*
	 * �ȴ�KDFģ����ж��ź�KDF_INT���ȡKDFģ���KDF_BUSY״̬�Ĵ�����
	 * ���KDF_INT�ж����߻�KDF_BUSY��0x1����Ϊ0x0�������һ�²��裻
	 * ����ȴ��������õȴ���ʱ������ʱ��Ϊ1s����
	 */
	if (hi_kdf_is_busy())
		return HI_RET_TIMEOUT;

	/*
	 * �ж�KDF�Ƿ���KDF_ALARM�쳣�жϣ�����У�
	 * ����Ҫ��ȡKDF_ALARM_STATE״̬��ƫ�Ƶ�ַ0x0C������ȡ�쳣�ж���Ϣ��
	 */
	hi_sdk_l0_read_reg(HI_SDK_L0_REG_KDF_HISC_KDF_INT_ST_BASE,
		(hi_uint32 *)&int_st);
	if (int_st.kdf_busy_wr_alarm) {
		hi_kdf_systrace(HI_RET_FAIL, 0, 0, 0, 0);
		return HI_RET_FAIL;
	}

	/*
	 * ��ȡKDF_RSLT��Կ���������ƫ�Ƶ�ַ0x70~0x8C��
	 * KDF_RSLT��256bit����8�ζ�ȡ��
	 */
	hi_kdf_get_key(HI_SDK_L0_REG_KDF_HISC_KDF_RSLT0_BASE,
		(hi_uint32 *)para->dk, 8);

	hi_kdf_systrace(HI_RET_SUCC, 0, 0, 0, 0);

	return HI_RET_SUCC;
}

/* kdf�洢��Կ���� */
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

	/* ���ò���CPU_KEY��ƫ�Ƶ�ַ0x40~0x5C����CPU_KEY��256bit����8������ */
	hi_kdf_config_key(HI_SDK_L0_REG_KDF_HISC_KDF_CPU_KEY0_BASE,
		(hi_uint32 *)para->key, 8);

	/* ����ģʽKDF_MODE��ƫ�Ƶ�ַ0x04��������ѡ��洢��Կ����ģʽ�� */
	value = 1;
	hi_sdk_l0_write_reg(HI_SDK_L0_REG_KDF_HISC_KDF_MODE_BASE, &value);

	/* ����HMAC��������KDF_ITERATION��ƫ�Ƶ�ַ0x08������С����ֵΪ0x1 */
	value = para->iter;
	hi_sdk_l0_write_reg(HI_SDK_L0_REG_KDF_HISC_KDF_ITERATION_BASE, &value);

    __asm__ volatile("isb");
    __asm__ volatile("dsb sy");

	/*
	 * ����KDF_BUSYΪ0x1��ƫ�Ƶ�ַ0x00��
	 * ������KDF��ʼ����ͬʱ�����ʷ�ж����KDF_INT��
	 * KDF������ɺ󣬻ὫKDF_BUSY����
	 */
	kdf_busy.kdf_busy = 1;
	hi_sdk_l0_write_reg(HI_SDK_L0_REG_KDF_HISC_KDF_BUSY_BASE,
		(hi_uint32 *)&kdf_busy);

	/*
	 * �ȴ�KDFģ����ж��ź�KDF_INT���ȡKDFģ���KDF_BUSY״̬�Ĵ�����
	 * ���KDF_INT�ж����߻�KDF_BUSY��0x1����Ϊ0x0�������һ�²��裻
	 * ����ȴ��������õȴ���ʱ������ʱ��Ϊ1s��
	 */
	if (hi_kdf_is_busy())
		return HI_RET_TIMEOUT;

	/*
	 * �ж�KDF�Ƿ���KDF_ALARM�쳣�жϣ�����У�
	 * ����Ҫ��ȡKDF_ALARM_STATE״̬��ƫ�Ƶ�ַ0x0C������ȡ�쳣�ж���Ϣ
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
