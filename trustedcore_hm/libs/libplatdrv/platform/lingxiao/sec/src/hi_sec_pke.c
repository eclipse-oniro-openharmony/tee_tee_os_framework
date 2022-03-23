/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2017-2019. All rights reserved.
 * Description: pke计算模块
 * Author: hsan
 * Create: 2017-4-11
 * History: 2017-4-11初稿完成
 *          2019-1-31 hsan code restyle
 */

#include <hisilicon/chip/level_2/hi_sdk_l2.h>
#include <linux/types.h>
#include <linux/module.h>
#include <linux/crc16.h>

#include "hi_sec_reg_crg_dio.h"
#include "hi_sec_reg_pke_top.h"
#include "hi_sec_tab_pke_top.h"
#include "hi_sec_api.h"
#include "hi_sec_pke.h"

/* 以下的len为数据长度，单位为8B；
 * 在点乘、点加工作模式下，len的取值范围为[4,12]；
 * 其他模式下，len的取值范围为[4,64]； */
#define HI_SEC_PKE_NLEN_MIN      (32)  //bytes
#define HI_SEC_PKE_NLEN_PM_512   (64)  //bytes 512bit point multi max length
#define HI_SEC_PKE_NLEN_PM_MAX   (72)  //bytes point multi max length
#define HI_SEC_PKE_NLEN_MAX      (512) //bytes
#define HI_SEC_PKE_NLEN_MOD       8    //bytes

#define HI_SEC_PKE_POINT_BLOCKLEN  0x60 //点运算坐标的表项长度
#define HI_SEC_PKE_POINT_BUFLEN    (HI_SEC_PKE_POINT_BLOCKLEN * 2) //点运算的表项长度

#define HI_SEC_PKE_PADING_NUM     11

#define HI_SEC_PKE_PARA_TYPE_ODD              0x01 //奇数
#define HI_SEC_PKE_PARA_TYPE_GREATER_THAN_1   0x02 //参数大于1

enum hi_sec_pke_rslt_e {
    HI_SEC_PKE_RSLT_RUNNING_E = 0,
    HI_SEC_PKE_RSLT_SUCC_E = 0x5,
    HI_SEC_PKE_RSLT_FAIL_E = 0xa,
};

enum hi_sec_pke_fail_e {
    HI_SEC_PKE_FAIL_RUNNING_E = 0,
    HI_SEC_PKE_FAIL_MODINV_E,
    HI_SEC_PKE_FAIL_RANDOM_E,
    HI_SEC_PKE_FAIL_DFA_E,
    HI_SEC_PKE_FAIL_UNLIMITP_E,
};

enum hi_pke_base_opera_e {
	HI_PKE_OP_MOD_EXP = 0,
	HI_PKE_OP_KEYE_EXTERN = 1,
	HI_PKE_OP_KEYE_INNER = 2,
	HI_PKE_OP_MOD_ADD = 3,
	HI_PKE_OP_MOD_MINUS = 5,
	HI_PKE_OP_MOD_MULTI = 6,
	HI_PKE_OP_MOD_INVERS = 7,
	HI_PKE_OP_MOD_MOD = 8,    /**/
	HI_PKE_OP_BIG_MULTI = 9,  /* */
	HI_PKE_OP_ECC_PM = 12,    /* ecc 的点乘 R = k * p */
	HI_PKE_OP_POINT_ADD = 13, /* 点加 C = S + R */
};

struct hi_sec_pke_s
{
    volatile hi_uint32      rdy;
    struct hi_sec_pke_sta_s sta;
    //struct hi_sec_pke_dfx_s dfx;
};

static struct hi_sec_pke_s g_sec_pke;

static hi_uint32 hi_sec_pke_para_check(hi_uchar8 *v,
	hi_uint32 len, hi_uint32 type)
{
    hi_int32 offset = 0;

    if ((type & HI_SEC_PKE_PARA_TYPE_ODD) > 0)
        if ((v[len - 1] & 0x1) == 0)
            return HI_RET_INVALID_PARA;

    if ((type & HI_SEC_PKE_PARA_TYPE_GREATER_THAN_1) > 0) {
        if (v[len - 1] <= 1 ) {
            for (offset = len - 2; offset >= 0; offset--) {
                if (v[offset] > 0)
                    break;
            }
        }
        if (offset < 0)
            return HI_RET_INVALID_PARA;
    }
    return HI_RET_SUCC;
}

/* 大数比较,如果v1 > v2,返回1; 如果v1 < v2,返回-1; 如果v1 = v2,返回0 */
static hi_int32 hi_sec_pke_compare(hi_uchar8 *v1, hi_uchar8 *v2, hi_uint32 len)
{
    hi_uint32 index;

    for (index = 0; index < len; index++) {
        if (v1[index] > v2[index]) {
            return 1;
        } else if (v1[index] < v2[index]) {
            return -1;
        }
    }

    return 0;
}

/* 大数比较, 符合: min<=k<=n-1 */
hi_int32 hi_sec_pke_data_valid(hi_uchar8 *k,
	hi_uchar8 *n, hi_uint32 min, hi_uint32 len)
{
	hi_int32 cnt;
	hi_uint32 valid = HI_FALSE;

	/* 判断随机数大于0 */
	for (cnt = len - 1; cnt >= 0; cnt--) {
		if (k[cnt] >= min) {
			valid = HI_TRUE;
			break;
		}
	}

	if (valid == HI_FALSE) {
		k[len - 1 ] = min;
		return valid;
	}

	/* 再判断随机数小于n */
	for (cnt = 0; cnt < len; cnt++) {
		if (k[cnt] < n[cnt]) {
			valid = HI_TRUE;
			break;
		} else if (k[cnt] > n[cnt]) {
			if (n[cnt] != 0) {
				k[cnt] = n[cnt] - 1;
				valid = HI_TRUE;
				break;
			} else {
				k[cnt] = 0;
			}
		}
	}

	if (cnt >= len) {
		k[len - 1 ] -= 1;
		valid = HI_TRUE;
	}

	return valid;
}

hi_int32 hi_sec_pke_random_get(hi_uchar8 *n, hi_uint32 len, hi_uchar8 *data)
{
	struct hi_sec_trng rng;
	hi_uint32 index;
	hi_int32 ret;
	hi_uchar8 *rand = HI_NULL;
	hi_uchar8 *tmp = HI_NULL;

	rand = (hi_uchar8 *)hi_malloc(8 * len);
	if (rand == HI_NULL) {
		hi_pke_systrace(HI_RET_MALLOC_FAIL, 0, 0, 0, 0);
		return HI_RET_MALLOC_FAIL;
	}

	for (index = 0, tmp = rand; index < 8; index++, tmp += len) {
		do {
			ret = hi_sec_trng_get(&rng);
			if (ret != HI_RET_SUCC) {
				hi_free(rand);
				hi_pke_systrace(ret, 0, 0, 0, 0);
				return ret;
			}

			if (len > HI_RNG_DATALEN) {
				hi_memcpy(tmp, rng.rng, HI_RNG_DATALEN);

				ret = hi_sec_trng_get(&rng);
				if (ret != HI_RET_SUCC) {
					hi_free(rand);
					hi_pke_systrace(ret, 0, 0, 0, 0);
					return ret;
				}
				hi_memcpy((tmp + HI_RNG_DATALEN), rng.rng,
					(len - HI_RNG_DATALEN));
			} else {
				hi_memcpy(tmp, rng.rng, len);
			}
		} while (hi_sec_pke_data_valid(tmp, n, 1, len)  == HI_FALSE);
	}

	ret = hi_sec_trng_get(&rng);
	if (ret != HI_RET_SUCC) {
		hi_free(rand);
		hi_pke_systrace(ret, 0, 0, 0, 0);
		return ret;
	}

	index = rng.rng[0] & 0x7;
	tmp = rand + (index * len);
	hi_memcpy(data, tmp, len);
	hi_free(rand);
	rand = HI_NULL;
	hi_pke_systrace(HI_RET_SUCC, 0, 0, 0, 0);
	return HI_RET_SUCC;
}

static hi_void hi_pke_cfg_work_mode(enum hi_pke_base_opera_e op_type,
	hi_uint32 len)
{
	struct hi_sdk_l0_reg_pke_top_pke_work_mode_s work_mode;
	hi_uint32 mode;

	if (len < HI_SEC_PKE_NLEN_MIN)
		mode = HI_SEC_PKE_NLEN_MIN / HI_SEC_PKE_NLEN_MOD;
	else
		mode = len / HI_SEC_PKE_NLEN_MOD;

	if ((op_type == HI_PKE_OP_ECC_PM) && (len > HI_SEC_PKE_NLEN_PM_512))
		mode = HI_SEC_PKE_NLEN_PM_MAX / HI_SEC_PKE_NLEN_MOD;

	/* 2. 配置WORK_MODE模式寄存器0x0004={16'd0,8'dlen,8'd0} */
	work_mode.opcode = op_type;
	work_mode.mode = mode;
	hi_sdk_l0_write_reg(HI_SDK_L0_REG_PKE_TOP_PKE_WORK_MODE_BASE,
		(hi_uint32 *)&work_mode);
}

/* 获取MRAM缓存 */
static hi_void hi_sec_pke_mram_get(hi_uchar8 *data, hi_uint32 len)
{
	struct hi_sdk_l0_tab_pke_top_mram_item_s mram_item;
	hi_uint32 cnt;
	hi_uint32 index;
	hi_uint32 outlen;
	hi_uint32 *buf = (hi_uint32 *)data;

	cnt = len / sizeof(mram_item.mram);
	for (index = 0; index < cnt; index++) {
		mram_item.idx = index;
		hi_sdk_l0_tab_get_pke_top_mram(&mram_item, len, &outlen);
		buf[cnt - 1 - index] = hi_ntohl(mram_item.mram.mram);
	}

	return;
}

static hi_void hi_sec_pke_mram_set(hi_uchar8 *data, hi_uint32 len)
{
	struct hi_sdk_l0_tab_pke_top_mram_item_s mram_item;
	hi_uint32 cnt;
	hi_uint32 index;
	hi_uint32 outlen;
	hi_uint32 *buf = (hi_uint32 *)data;

	cnt = len / sizeof(mram_item.mram);
	for (index = 0; index < cnt; index++) {
		/* 注意:这些RAM要从低地址开始写 */
		mram_item.idx = index;
		mram_item.mram.mram = hi_ntohl(buf[cnt - 1 - index]);
		hi_sdk_l0_tab_set_pke_top_mram(&mram_item, len, &outlen);
	}
	return;
}

static hi_void hi_sec_pke_nram_get(hi_uchar8 *data, hi_uint32 len)
{
	struct hi_sdk_l0_tab_pke_top_nram_item_s nram_item;
	hi_uint32 cnt;
	hi_uint32 index;
	hi_uint32 outlen;
	hi_uint32 *buf = (hi_uint32 *)data;

	cnt = len / sizeof(nram_item.nram);
	for (index = 0; index < cnt; index++) {
		nram_item.idx = index;
		hi_sdk_l0_tab_get_pke_top_nram(&nram_item, len, &outlen);
		buf[cnt - 1 - index] = hi_ntohl(nram_item.nram.nram);
	}

	return;
}

static hi_void hi_sec_pke_nram_set(hi_uchar8 *data, hi_uint32 len)
{
	struct hi_sdk_l0_tab_pke_top_nram_item_s nram_item;
	hi_uint32 cnt;
	hi_uint32 index;
	hi_uint32 outlen;
	hi_uint32 *buf = (hi_uint32 *)data;

	cnt = len / sizeof(nram_item.nram);
	for (index = 0; index < cnt; index++) {
		/* 注意:这些RAM要从低地址开始写 */
		nram_item.idx = index;
		nram_item.nram.nram = hi_ntohl(buf[cnt - 1 - index]);
		hi_sdk_l0_tab_set_pke_top_nram(&nram_item, len, &outlen);
	}

	return;
}

static hi_void hi_sec_pke_kram_set(hi_uint32 offset,
	hi_uchar8 *data, hi_uint32 len)
{
	struct hi_sdk_l0_tab_pke_top_kram_item_s kram_item;
	hi_uint32 cnt;
	hi_uint32 index;
	hi_uint32 outlen;
	hi_uint32 *buf = (hi_uint32 *)data;

	cnt = len / sizeof(kram_item.kram);
	for (index = 0; index < cnt; index++) {
		/* 注意:这些RAM要从低地址开始写 */
		kram_item.idx = index + offset;
		kram_item.kram.kram = hi_ntohl(buf[cnt - 1 - index]);
		hi_sdk_l0_tab_set_pke_top_kram(&kram_item, len, &outlen);
	}

	return;
}

static hi_void hi_sec_pke_rram_get(hi_uchar8 *data, hi_uint32 len)
{
	struct hi_sdk_l0_tab_pke_top_rram_item_s rram_item;
	hi_uint32 cnt;
	hi_uint32 index;
	hi_uint32 outlen;
	hi_uint32 *buf = (hi_uint32 *)data;

	cnt = len / sizeof(rram_item.rram);
	for (index = 0; index < cnt; index++) {
		rram_item.idx = index;
		hi_sdk_l0_tab_get_pke_top_rram(&rram_item, len, &outlen);
		buf[cnt - 1 - index] = hi_ntohl(rram_item.rram.rram);
	}

	return;
}

static hi_int32 hi_sec_pke_rslt_get(hi_void)
{
	struct hi_sdk_l0_reg_pke_top_pke_result_flag_s result_flag;
	struct hi_sdk_l0_reg_pke_top_pke_failure_flag_s failure_flag;
	struct hi_sec_reg_crg_dio_sc_rst_protect_s sc_rst;

	hi_sdk_l0_read_reg(HI_SDK_L0_REG_PKE_TOP_PKE_RESULT_FLAG_BASE,
		(hi_uint32 *)&result_flag);

	if (result_flag.pke_result_flag == HI_SEC_PKE_RSLT_SUCC_E) {
		g_sec_pke.sta.succ++;
		return HI_RET_SUCC;
	}

	if(result_flag.pke_result_flag == HI_SEC_PKE_RSLT_FAIL_E) {
		g_sec_pke.sta.fail++;

		hi_sdk_l0_read_reg(
			HI_SDK_L0_REG_PKE_TOP_PKE_FAILURE_FLAG_BASE,
			(hi_uint32 *)&failure_flag);
		switch (failure_flag.pke_failure_flag) {
		case HI_SEC_PKE_FAIL_RUNNING_E:
			g_sec_pke.sta.fail_runing++;
			break;
		case HI_SEC_PKE_FAIL_MODINV_E:
			g_sec_pke.sta.fail_modinvers++;
			break;
		case HI_SEC_PKE_FAIL_RANDOM_E:
			g_sec_pke.sta.fail_random++;
			break;
		case HI_SEC_PKE_FAIL_DFA_E:
			g_sec_pke.sta.fail_dfa++;
			break;
		case HI_SEC_PKE_FAIL_UNLIMITP_E:
			g_sec_pke.sta.fail_unlimit_point++;
			return HI_SEC_PKE_FAIL_UNLIMITP_E;
		default:
			g_sec_pke.sta.fail_unknow++;
			break;
		}
	} else if (result_flag.pke_result_flag == HI_SEC_PKE_RSLT_RUNNING_E) {
		g_sec_pke.sta.running++;
	} else {
		g_sec_pke.sta.unknow++;
	}

	/* 复位PKE */
	hi_sdk_l0_read_reg(HI_SDK_L0_REG_CRG_DIO_SC_RST_PROTECT_BASE,
		(hi_uint32 *)&sc_rst);
	sc_rst.pke_srst_n = 0;
	hi_sdk_l0_write_reg(HI_SDK_L0_REG_CRG_DIO_SC_RST_PROTECT_BASE,
		(hi_uint32 *)&sc_rst);
	/* 撤销复位 */
	sc_rst.pke_srst_n = 1;
	hi_sdk_l0_write_reg(HI_SDK_L0_REG_CRG_DIO_SC_RST_PROTECT_BASE,
		(hi_uint32 *)&sc_rst);

	hi_udelay(1);
	g_sec_pke.rdy = HI_FALSE;

	hi_pke_systrace(HI_RET_FAIL, result_flag.pke_result_flag,
		failure_flag.pke_failure_flag, 0, 0);
	return HI_RET_FAIL;
}

/* 读取BUSY状态寄存器0x0000，判断是否为0； 如果为0则继续执行，否则返回错误 */
static hi_int32 hi_pke_is_busy(hi_void)
{
	hi_int32 ret = HI_RET_SUCC;
	hi_uint32 timeout = (1000 * 1000);
	struct hi_sdk_l0_reg_pke_top_pke_busy_s busy;

	while (--timeout) {
		hi_sdk_l0_read_reg(HI_SDK_L0_REG_PKE_TOP_PKE_BUSY_BASE,
			(hi_uint32 *)&busy);
		if (!busy.pke_busy)
			break;
		hi_udelay(10);
	}
	if (!timeout) {
		ret = HI_RET_TIMEOUT;
		hi_pke_systrace(ret, 0, 0, 0, 0);
	}
	return ret;
}

static hi_void hi_pke_cfg_start(hi_void)
{
	struct hi_sdk_l0_reg_pke_top_pke_start_s start = {0};

	/* 4.配置START开工寄存器0x0008=32'h5; */
	start.pke_start = 0x5;
	hi_sdk_l0_write_reg(HI_SDK_L0_REG_PKE_TOP_PKE_START_BASE,
		(hi_uint32 *)&start);
}

/* c = a opcode b mod p*/
static hi_int32 hi_sec_pke_mod_calc(enum hi_pke_base_opera_e op_code,
	struct hi_pke_mod_s *mod_calc)
{
	hi_int32 ret;
	hi_uint32 len = mod_calc->len;

	if (hi_pke_is_busy()) {
		hi_pke_systrace(HI_RET_TIMEOUT, 0, 0, 0, 0);
		return HI_RET_TIMEOUT;
	}

	/* 2. 配置WORK_MODE模式寄存器0x0004={16'd0,8'dlen,8'd op_code}；*/
	hi_pke_cfg_work_mode(op_code, len);

	/* 3. 配置数据a到寄存器0x200~0x200+4*（2len-1；*/
	if (mod_calc->a != HI_NULL)
		hi_sec_pke_mram_set(mod_calc->a, len);

	/* 4. 配置数据p到寄存器0x600~0x600+4*（2len-1）*/
	if (mod_calc->p != HI_NULL)
		hi_sec_pke_nram_set(mod_calc->p, len);

	/* 5. 配置数据b到寄存器0xa00~0xa00+4*（2len-1）*/
	if (mod_calc->b != HI_NULL)
		hi_sec_pke_kram_set(0, mod_calc->b, len);

	/* 6. 配置开工寄存器0x0008=32'h5;*/
	hi_pke_cfg_start();

	if (hi_pke_is_busy()) {
		hi_pke_systrace(HI_RET_TIMEOUT, 0, 0, 0, 0);
		return HI_RET_TIMEOUT;
	}

	/*
	 * 7. 读取结果标志寄存器0x0040，如果为0x5则继续执行；
	 * 如果为0xa则读取结果失败标志寄存器0x0044，告知用户后结束；
	 * 如果为其他值则向用户告警后结束 备注：模运算的结果标志寄存器肯定为0x5
	 */
	ret = hi_sec_pke_rslt_get();
	if (ret != HI_RET_SUCC) {
		hi_pke_systrace(ret, 0, 0, 0, 0);
		return ret;
	}

	/* 8. 读取数据c，从寄存器0xe00~0xe00+4*（2len-1）；*/
	hi_sec_pke_rram_get(mod_calc->c, len);

	return HI_RET_SUCC;
}

/* 模加运算  modular addition; c= a + b mod p */
hi_int32 hi_sec_pke_modadd(
	hi_uchar8 *a, hi_uchar8 *b, hi_uchar8 *p, hi_uint32 len, hi_uchar8 *c)
{
	struct hi_pke_mod_s mod_calc;

	mod_calc.a = a;
	mod_calc.b = b;

	mod_calc.p = p;
	mod_calc.len = len;
	mod_calc.c = c;

	return hi_sec_pke_mod_calc(HI_PKE_OP_MOD_ADD, &mod_calc);
}

/* 模减运算  modular minus; c= a - b mod p */
hi_int32 hi_sec_pke_modminus(
	hi_uchar8 *a, hi_uchar8 *b, hi_uchar8 *p, hi_uint32 len, hi_uchar8 *c)
{
	struct hi_pke_mod_s mod_calc;

	mod_calc.a = a;
	mod_calc.b = b;

	mod_calc.p = p;
	mod_calc.len = len;
	mod_calc.c = c;

	return hi_sec_pke_mod_calc(HI_PKE_OP_MOD_MINUS, &mod_calc);
}

/* 模乘运算  modular Multiplication; c= a * b mod p */
hi_int32 hi_sec_pke_modmulti(
	hi_uchar8 *a, hi_uchar8 *b, hi_uchar8 *p, hi_uint32 len, hi_uchar8 *c)
{
	struct hi_pke_mod_s mod_calc;

	mod_calc.a = a;
	mod_calc.b = b;

	mod_calc.p = p;
	mod_calc.len = len;
	mod_calc.c = c;

	return hi_sec_pke_mod_calc(HI_PKE_OP_MOD_MULTI, &mod_calc);
}

/* 模逆运算  modular inversion; c= a^-1 mod p */
hi_int32 hi_sec_pke_modinvers(
	hi_uchar8 *a, hi_uchar8 *p, hi_uint32 len, hi_uchar8 *c)
{
	struct hi_pke_mod_s mod_calc;

	mod_calc.a = a;
	mod_calc.b = HI_NULL;

	mod_calc.p = p;
	mod_calc.len = len;
	mod_calc.c = c;

	return hi_sec_pke_mod_calc(HI_PKE_OP_MOD_INVERS, &mod_calc);
}

/* 模运算  modular addition; c= a mod p */
hi_int32 hi_sec_pke_mod(
	hi_uchar8 *a, hi_uchar8 *p, hi_uint32 len, hi_uchar8 *c)
{
	struct hi_pke_mod_s mod_calc;

	mod_calc.a = a;
	mod_calc.b = HI_NULL;

	mod_calc.p = p;
	mod_calc.len = len;
	mod_calc.c = c;

	return hi_sec_pke_mod_calc(HI_PKE_OP_MOD_MOD, &mod_calc);
}

/* 大数乘法 c= a * b */
hi_int32 hi_sec_pke_bigmulti(
	hi_uchar8 *a, hi_uchar8 *b, hi_uint32 len, hi_uchar8 *c)
{
	struct hi_pke_mod_s mod_calc;

	mod_calc.a = a;
	mod_calc.b = b;

	mod_calc.p = HI_NULL;
	mod_calc.len = len;
	mod_calc.c = c;

	return hi_sec_pke_mod_calc(HI_PKE_OP_BIG_MULTI, &mod_calc);
}

static hi_int32 hi_pke_modeexp_chk_para(struct hi_pke_modexp_s modexp,
	enum hi_sec_aealg_e sec_aealg)
{
	if (modexp.m == HI_NULL || modexp.e == HI_NULL ||
		modexp.n == HI_NULL || modexp.c == HI_NULL)
		return HI_RET_INVALID_PARA;

	if ((modexp.len < HI_SEC_PKE_NLEN_MIN) ||
		(modexp.len > HI_SEC_PKE_NLEN_MAX))
		return HI_RET_INVALID_PARA;

	if (modexp.len % HI_SEC_PKE_NLEN_MOD)
		return HI_RET_INVALID_PARA;

	 /* n 参数校验, 大于1的奇数 */
	if (hi_sec_pke_para_check(modexp.n, modexp.len,
		HI_SEC_PKE_PARA_TYPE_ODD | HI_SEC_PKE_PARA_TYPE_GREATER_THAN_1))
		return HI_RET_INVALID_PARA;

	/* m 参数校验,m < n*/
	if (hi_sec_pke_compare(modexp.n, modexp.m, modexp.len) <= 0)
		return HI_RET_INVALID_PARA;

	if (sec_aealg == HI_SEC_AEALG_RSA) {
		/* RSA e 参数校验 , RSA 中e 是大于1的奇数*/
		if (hi_sec_pke_para_check(modexp.e, modexp.len,
			HI_SEC_PKE_PARA_TYPE_ODD |
			HI_SEC_PKE_PARA_TYPE_GREATER_THAN_1))
			return HI_RET_INVALID_PARA;
		/* e 参数校验,e < n*/
		if (hi_sec_pke_compare(modexp.n, modexp.e, modexp.len) <= 0)
			return HI_RET_INVALID_PARA;
	} else {
		/* DH e 参数校验 , DH 中e 大于1*/
		if (hi_sec_pke_para_check(modexp.e, modexp.len,
			HI_SEC_PKE_PARA_TYPE_GREATER_THAN_1))
			return HI_RET_INVALID_PARA;
	}

	return HI_RET_SUCC;
}

/* 模幂运算 modular exponentiation */
hi_int32 hi_sec_pke_modexp(struct hi_pke_modexp_s *modexp,
	enum hi_sec_aealg_e sec_aealg)
{
	struct hi_sdk_l0_reg_pke_top_pke_work_mode_s work_mode;
	hi_int32 ret;
	hi_uint32 len;

	/* RSA DH参数检查 */
	if (hi_pke_modeexp_chk_para(*modexp, sec_aealg))
		return HI_RET_INVALID_PARA;

	len = modexp->len;
	if (hi_pke_is_busy())
		return HI_RET_TIMEOUT;

	/* 2. 配置WORK_MODE模式寄存器0x0004={16'd0,8'dlen,8'd0}； */
	work_mode.opcode = HI_PKE_OP_MOD_EXP;
	work_mode.mode = len / HI_SEC_PKE_NLEN_MOD;
	hi_sdk_l0_write_reg(HI_SDK_L0_REG_PKE_TOP_PKE_WORK_MODE_BASE,
		(hi_uint32 *)&work_mode);

	/* 3. 配置数据m到寄存器0x200~0x200+4*（2len-1）； */
	hi_sec_pke_mram_set(modexp->m, len);

	/* 4. 配置数据n到寄存器0x600~0x600+4*（2len-1）； */
	hi_sec_pke_nram_set(modexp->n, len);

	/* 5. 配置数据e到寄存器0xa00~0xa00+4*（2len-1）； */
	hi_sec_pke_kram_set(0, modexp->e, len);

	/* 6. 配置开工寄存器0x0008=32'h5； */
	hi_pke_cfg_start();

	if (hi_pke_is_busy())
		return HI_RET_TIMEOUT;

	/*
	 * 9.读取结果标志寄存器0x0040, 如果为0x5则继续执行第10步；
	 * 如果为0xa则读取结果失败标志寄存器0x0044，返回错误；
	 * 0x0044的值为0x3表示计算过程中受到了DFA攻击；
	 */
	ret = hi_sec_pke_rslt_get();
	if(ret != HI_RET_SUCC)
		return ret;

	/* 10.从寄存器0xe00~0xe00+4*（2len-1）读取模幂结果； */
	hi_sec_pke_rram_get(modexp->c, len);

	return HI_RET_SUCC;
}

static hi_int32 hi_pke_read_rram_rslt(hi_uchar8 *rx, hi_uchar8 *ry, hi_uint32 len)
{
	hi_uchar8 *buf_ram = HI_NULL;
	hi_uchar8 *buf_tmp = HI_NULL;

	/* 14 从寄存器0xe00~0xe5c读取计算结果Rx */
	/* 15 从寄存器0xe60~0xebc读取计算结果Ry */
	buf_ram = hi_malloc(HI_SEC_PKE_POINT_BUFLEN);
	if (buf_ram == HI_NULL)
		return HI_RET_MALLOC_FAIL;
	hi_sec_pke_rram_get(buf_ram, HI_SEC_PKE_POINT_BUFLEN);

	buf_tmp = buf_ram;
	hi_memcpy(ry, (buf_tmp + HI_SEC_PKE_POINT_BLOCKLEN - len), len);

	buf_tmp += HI_SEC_PKE_POINT_BLOCKLEN;
	hi_memcpy(rx, (buf_tmp + HI_SEC_PKE_POINT_BLOCKLEN - len), len);

	hi_free(buf_ram);
	buf_ram = HI_NULL;

	return HI_RET_SUCC;
}

/* ECC 点乘 R = k * P 数据 */
hi_int32 hi_sec_pke_ecc_pointmulti(struct hi_pke_ecc_pointmulti_s *ecc_pm)
{
	hi_int32 ret;
	hi_uint32 len, buflen;
	hi_uchar8 *buf_ram = HI_NULL;
	hi_uchar8 *buf_tmp = HI_NULL;

	len = ecc_pm->len;
	if (hi_pke_is_busy())
		return HI_RET_TIMEOUT;

	hi_pke_cfg_work_mode(HI_PKE_OP_ECC_PM, len);

	buflen = HI_SEC_PKE_POINT_BLOCKLEN * 5;
	buf_ram = hi_malloc(buflen);
	if(buf_ram == HI_NULL)
		return HI_RET_MALLOC_FAIL;

	hi_memset(buf_ram, 0, buflen); /* 高位补0 */
	buf_tmp = buf_ram;
	hi_memcpy((buf_tmp + HI_SEC_PKE_POINT_BLOCKLEN - len), ecc_pm->b, len);
	buf_tmp += HI_SEC_PKE_POINT_BLOCKLEN;
	hi_memcpy((buf_tmp + HI_SEC_PKE_POINT_BLOCKLEN - len), ecc_pm->n, len);
	buf_tmp += HI_SEC_PKE_POINT_BLOCKLEN;
	hi_memcpy((buf_tmp + HI_SEC_PKE_POINT_BLOCKLEN - len), ecc_pm->py, len);
	buf_tmp += HI_SEC_PKE_POINT_BLOCKLEN;
	hi_memcpy((buf_tmp + HI_SEC_PKE_POINT_BLOCKLEN - len), ecc_pm->px, len);
	hi_sec_pke_mram_set(buf_ram, HI_SEC_PKE_POINT_BLOCKLEN * 4);

	hi_memset(buf_ram, 0, buflen);
	buf_tmp = buf_ram;
	hi_memcpy((buf_tmp + HI_SEC_PKE_POINT_BLOCKLEN - len), ecc_pm->gy, len);
	buf_tmp += HI_SEC_PKE_POINT_BLOCKLEN;
	hi_memcpy((buf_tmp + HI_SEC_PKE_POINT_BLOCKLEN - len), ecc_pm->gx, len);
	buf_tmp += HI_SEC_PKE_POINT_BLOCKLEN;
	hi_memcpy((buf_tmp + HI_SEC_PKE_POINT_BLOCKLEN - len), ecc_pm->a, len);
	buf_tmp += HI_SEC_PKE_POINT_BLOCKLEN;
	hi_memcpy((buf_tmp + HI_SEC_PKE_POINT_BLOCKLEN - len), ecc_pm->p, len);
	buf_tmp += HI_SEC_PKE_POINT_BLOCKLEN;
	hi_memcpy((buf_tmp + HI_SEC_PKE_POINT_BLOCKLEN - len), ecc_pm->k, len);
	hi_sec_pke_kram_set(0, buf_ram, buflen);

	hi_free(buf_ram);
	buf_ram = HI_NULL;

	/* 6. 配置开工寄存器0x0008=32'h5;*/
	hi_pke_cfg_start();

	if (hi_pke_is_busy())
		return HI_RET_TIMEOUT;

	/* 读取结果标志寄存器0x0040，如果为0x5则继续执行 */
	ret = hi_sec_pke_rslt_get();
	if (ret != HI_RET_SUCC)
		return ret;

	ret = hi_pke_read_rram_rslt(ecc_pm->rx, ecc_pm->ry, len);

	return ret;
}

/* 点加 C = S + R */
hi_int32 hi_sec_pke_pointadd(struct hi_pke_pointadd_s *padd)
{
	hi_int32 ret;
	hi_uint32 len, buflen;
	hi_uchar8 *buf_ram = HI_NULL;
	hi_uchar8 *buf_tmp = HI_NULL;

	len = padd->len;
	if (hi_pke_is_busy())
		return HI_RET_TIMEOUT;

	hi_pke_cfg_work_mode(HI_PKE_OP_POINT_ADD, len);

	buflen = HI_SEC_PKE_POINT_BLOCKLEN * 4;
	buf_ram = hi_malloc(buflen);
	if(buf_ram == HI_NULL)
		return HI_RET_MALLOC_FAIL;

	hi_memset(buf_ram, 0, buflen);
	buf_tmp = buf_ram;
	hi_memcpy((buf_tmp + HI_SEC_PKE_POINT_BLOCKLEN - len), padd->sy, len);
	buf_tmp += HI_SEC_PKE_POINT_BLOCKLEN;
	hi_memcpy((buf_tmp + HI_SEC_PKE_POINT_BLOCKLEN - len), padd->sx, len);
	hi_sec_pke_mram_set(buf_ram, HI_SEC_PKE_POINT_BLOCKLEN * 2);

	/* 5 配置数据p到寄存器0xa60~0xabc；位宽不足的部分补0 */
	/* 6 配置数据a到寄存器0xac0~0xb1c；位宽不足的部分补0 */
	/* 7 配置数据Rx到寄存器0xb20~0xb7c；位宽不足的部分补0 */
	/* 8 配置数据Ry到寄存器0xb80~0xbdc；位宽不足的部分补0 */
	hi_memset(buf_ram, 0, buflen);
	buf_tmp = buf_ram;
	hi_memcpy((buf_tmp + HI_SEC_PKE_POINT_BLOCKLEN - len), padd->ry, len);
	buf_tmp += HI_SEC_PKE_POINT_BLOCKLEN;
	hi_memcpy((buf_tmp + HI_SEC_PKE_POINT_BLOCKLEN - len), padd->rx, len);
	buf_tmp += HI_SEC_PKE_POINT_BLOCKLEN;
	hi_memcpy((buf_tmp + HI_SEC_PKE_POINT_BLOCKLEN - len), padd->a, len);
	buf_tmp += HI_SEC_PKE_POINT_BLOCKLEN;
	hi_memcpy((buf_tmp + HI_SEC_PKE_POINT_BLOCKLEN - len), padd->p, len);
	hi_sec_pke_kram_set(0x60 / sizeof(hi_uint32), buf_ram, buflen);

	hi_free(buf_ram);
	buf_ram = HI_NULL;

	/* 6. 配置开工寄存器0x0008=32'h5;*/
	hi_pke_cfg_start();

	if (hi_pke_is_busy())
		return HI_RET_TIMEOUT;

	/* 读取结果标志寄存器0x0040，如果为0x5则继续执行 */
	ret = hi_sec_pke_rslt_get();
	if (ret != HI_RET_SUCC)
		return ret;

	ret = hi_pke_read_rram_rslt(padd->cx, padd->cy, len);

	return ret;
}

static hi_int32 hi_pke_keygen_chk_para(struct hi_sec_rsa_req *kgen_req)
{
	hi_uint32 len = kgen_req->key_len;

	if (kgen_req == HI_NULL || kgen_req->e == HI_NULL ||
		kgen_req->d == HI_NULL || kgen_req->n == HI_NULL)
		return HI_RET_INVALID_PARA;

	if (len < HI_SEC_PKE_NLEN_MIN ||
		len > HI_SEC_PKE_NLEN_MAX) {
		hi_pke_systrace(HI_RET_INVALID_PARA, len, 0, 0, 0);
		return HI_RET_INVALID_PARA;
	}

	if (len % HI_SEC_PKE_NLEN_MOD != 0) {
		hi_pke_systrace(HI_RET_INVALID_PARA, len, 0, 0, 0);
		return HI_RET_INVALID_PARA;
	}

	if (kgen_req->einput != HI_DISABLE) {
		/* e 参数校验 */
		if (hi_sec_pke_para_check(kgen_req->e, len,
			HI_SEC_PKE_PARA_TYPE_ODD |
			HI_SEC_PKE_PARA_TYPE_GREATER_THAN_1)) {
			hi_pke_systrace(HI_RET_INVALID_PARA,
				kgen_req->e[len - 1], 0, 0, 0);
			return HI_RET_INVALID_PARA;
		}
	}
	return HI_RET_SUCC;
}

static hi_int32 hi_pke_read_ararm_int(hi_void)
{
	struct hi_sdk_l0_reg_pke_top_pke_int_status_s int_status;

	/* 读取ALARM状态寄存器0x24，如果不为0xA则直接任务失败 */
	hi_sdk_l0_read_reg(HI_SDK_L0_REG_PKE_TOP_PKE_INT_STATUS_BASE,
		(hi_uint32 *)&int_status);
	if (int_status.alarm_int_status != 0xA) {
		hi_pke_systrace(HI_RET_FAIL, int_status.alarm_int_status, 0, 0, 0);
		return HI_RET_FAIL;
	}
	return HI_RET_SUCC;
}

static hi_int32 hi_pke_keygen_read_e(struct hi_sec_rsa_req *kgen_req)
{
	hi_int32 ret;
	hi_uchar8 *gen_e = HI_NULL;
	hi_uint32 len = kgen_req->key_len;

	/* 8.读取数据E，从寄存器0x200~0x200+4*（2len-1） */
	if (kgen_req->einput != HI_ENABLE) {
		hi_sec_pke_mram_get(kgen_req->e, len);
		return HI_RET_SUCC;
	}

	gen_e = (hi_uchar8 *)hi_malloc(len);
	if (gen_e == HI_NULL) {
		hi_pke_systrace(HI_RET_MALLOC_FAIL, 0, 0, 0, 0);
		return HI_RET_MALLOC_FAIL;
	}
	hi_sec_pke_mram_get(gen_e, len);

	/*
	* 9.软件对E进行校验：若E为软件输入，则判断读取的E和输入的E是否一致，
	* 如果不一致，则结束；
	* 若E为逻辑内部产生，则判断E的有效位宽是否大于32bit且小于等于64bit
	* 如果不是则结束；
	*/
	ret = hi_memcmp(gen_e, kgen_req->e, len);
	hi_free(gen_e);

	if (ret) {
		hi_pke_systrace(HI_RET_FAIL, 0, 0, 0, 0);
		return HI_RET_FAIL;
	} else {
		hi_sec_pke_mram_get(kgen_req->e, len);
	}
	return HI_RET_SUCC;
}

hi_int32 hi_sec_pke_rsa_keygen(struct hi_sec_rsa_req *kgen_req)
{
	struct hi_sdk_l0_reg_pke_top_pke_work_mode_s work_mode;
	hi_int32 ret;
	hi_uint32 len;

	if (hi_pke_keygen_chk_para(kgen_req))
		return HI_RET_INVALID_PARA;
	if (hi_pke_is_busy())
		return HI_RET_TIMEOUT;

	len = kgen_req->key_len;
	/* 
	 * 2.配置WORK_MODE模式寄存器0x0004={16'd0,8'dlen,8'd1}，
	 * 或者{16'd0,8'dlen,8'd2}，
	 * 前者用于公钥E由外部软件输入时的密钥对产生，
	 * 后者用于公钥由内部生成时的密钥对产生；
	 * 若公钥为外部输入，则按照按照长度len进行配置
	 */
	work_mode.opcode = kgen_req->einput ? 
		HI_PKE_OP_KEYE_EXTERN : HI_PKE_OP_KEYE_INNER;
	work_mode.mode = len / HI_SEC_PKE_NLEN_MOD;
	hi_sdk_l0_write_reg(HI_SDK_L0_REG_PKE_TOP_PKE_WORK_MODE_BASE,
		(hi_uint32 *)&work_mode);

	/* 3如果是带公钥的秘钥生成则配置公钥E到寄存器0x200~0x200+4*（2len-1）*/
	if (kgen_req->einput == HI_ENABLE)
		hi_sec_pke_mram_set(kgen_req->e, len);

	/* 4开工 */
	hi_pke_cfg_start();

	/* 5读BUSY */
	if (hi_pke_is_busy())
		return HI_RET_TIMEOUT;

	/* 6读取ALARM状态寄存器 */
	if (hi_pke_read_ararm_int())
		return HI_RET_FAIL;

	ret = hi_sec_pke_rslt_get();
	if(ret != HI_RET_SUCC) {
		hi_pke_systrace(ret, 0, 0, 0, 0);
		return ret;
	}

	ret = hi_pke_keygen_read_e(kgen_req);
	if (ret)
		return ret;
		
	/* 10.读取数据N，从寄存器0x600~0x600+4*（2len-1）；*/
	hi_sec_pke_nram_get(kgen_req->n, len);

	/* 11.软件判断N的高2bit是否全零，若全零，则需要重新生成秘钥，并结束；*/
	if (!(kgen_req->n[0] >> 6)) {
		hi_pke_systrace(HI_RET_FAIL, 0, 0, 0, 0);
		return HI_RET_FAIL;
	}

	/* 12.读取数据D，从寄存器0xe00~0xe00+4*（2len-1）*/
	hi_sec_pke_rram_get(kgen_req->d, len);

	return HI_RET_SUCC;
}
