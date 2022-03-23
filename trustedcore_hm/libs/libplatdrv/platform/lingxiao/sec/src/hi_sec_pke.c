/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2017-2019. All rights reserved.
 * Description: pke����ģ��
 * Author: hsan
 * Create: 2017-4-11
 * History: 2017-4-11�������
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

/* ���µ�lenΪ���ݳ��ȣ���λΪ8B��
 * �ڵ�ˡ���ӹ���ģʽ�£�len��ȡֵ��ΧΪ[4,12]��
 * ����ģʽ�£�len��ȡֵ��ΧΪ[4,64]�� */
#define HI_SEC_PKE_NLEN_MIN      (32)  //bytes
#define HI_SEC_PKE_NLEN_PM_512   (64)  //bytes 512bit point multi max length
#define HI_SEC_PKE_NLEN_PM_MAX   (72)  //bytes point multi max length
#define HI_SEC_PKE_NLEN_MAX      (512) //bytes
#define HI_SEC_PKE_NLEN_MOD       8    //bytes

#define HI_SEC_PKE_POINT_BLOCKLEN  0x60 //����������ı����
#define HI_SEC_PKE_POINT_BUFLEN    (HI_SEC_PKE_POINT_BLOCKLEN * 2) //������ı����

#define HI_SEC_PKE_PADING_NUM     11

#define HI_SEC_PKE_PARA_TYPE_ODD              0x01 //����
#define HI_SEC_PKE_PARA_TYPE_GREATER_THAN_1   0x02 //��������1

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
	HI_PKE_OP_ECC_PM = 12,    /* ecc �ĵ�� R = k * p */
	HI_PKE_OP_POINT_ADD = 13, /* ��� C = S + R */
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

/* �����Ƚ�,���v1 > v2,����1; ���v1 < v2,����-1; ���v1 = v2,����0 */
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

/* �����Ƚ�, ����: min<=k<=n-1 */
hi_int32 hi_sec_pke_data_valid(hi_uchar8 *k,
	hi_uchar8 *n, hi_uint32 min, hi_uint32 len)
{
	hi_int32 cnt;
	hi_uint32 valid = HI_FALSE;

	/* �ж����������0 */
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

	/* ���ж������С��n */
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

	/* 2. ����WORK_MODEģʽ�Ĵ���0x0004={16'd0,8'dlen,8'd0} */
	work_mode.opcode = op_type;
	work_mode.mode = mode;
	hi_sdk_l0_write_reg(HI_SDK_L0_REG_PKE_TOP_PKE_WORK_MODE_BASE,
		(hi_uint32 *)&work_mode);
}

/* ��ȡMRAM���� */
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
		/* ע��:��ЩRAMҪ�ӵ͵�ַ��ʼд */
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
		/* ע��:��ЩRAMҪ�ӵ͵�ַ��ʼд */
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
		/* ע��:��ЩRAMҪ�ӵ͵�ַ��ʼд */
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

	/* ��λPKE */
	hi_sdk_l0_read_reg(HI_SDK_L0_REG_CRG_DIO_SC_RST_PROTECT_BASE,
		(hi_uint32 *)&sc_rst);
	sc_rst.pke_srst_n = 0;
	hi_sdk_l0_write_reg(HI_SDK_L0_REG_CRG_DIO_SC_RST_PROTECT_BASE,
		(hi_uint32 *)&sc_rst);
	/* ������λ */
	sc_rst.pke_srst_n = 1;
	hi_sdk_l0_write_reg(HI_SDK_L0_REG_CRG_DIO_SC_RST_PROTECT_BASE,
		(hi_uint32 *)&sc_rst);

	hi_udelay(1);
	g_sec_pke.rdy = HI_FALSE;

	hi_pke_systrace(HI_RET_FAIL, result_flag.pke_result_flag,
		failure_flag.pke_failure_flag, 0, 0);
	return HI_RET_FAIL;
}

/* ��ȡBUSY״̬�Ĵ���0x0000���ж��Ƿ�Ϊ0�� ���Ϊ0�����ִ�У����򷵻ش��� */
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

	/* 4.����START�����Ĵ���0x0008=32'h5; */
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

	/* 2. ����WORK_MODEģʽ�Ĵ���0x0004={16'd0,8'dlen,8'd op_code}��*/
	hi_pke_cfg_work_mode(op_code, len);

	/* 3. ��������a���Ĵ���0x200~0x200+4*��2len-1��*/
	if (mod_calc->a != HI_NULL)
		hi_sec_pke_mram_set(mod_calc->a, len);

	/* 4. ��������p���Ĵ���0x600~0x600+4*��2len-1��*/
	if (mod_calc->p != HI_NULL)
		hi_sec_pke_nram_set(mod_calc->p, len);

	/* 5. ��������b���Ĵ���0xa00~0xa00+4*��2len-1��*/
	if (mod_calc->b != HI_NULL)
		hi_sec_pke_kram_set(0, mod_calc->b, len);

	/* 6. ���ÿ����Ĵ���0x0008=32'h5;*/
	hi_pke_cfg_start();

	if (hi_pke_is_busy()) {
		hi_pke_systrace(HI_RET_TIMEOUT, 0, 0, 0, 0);
		return HI_RET_TIMEOUT;
	}

	/*
	 * 7. ��ȡ�����־�Ĵ���0x0040�����Ϊ0x5�����ִ�У�
	 * ���Ϊ0xa���ȡ���ʧ�ܱ�־�Ĵ���0x0044����֪�û��������
	 * ���Ϊ����ֵ�����û��澯����� ��ע��ģ����Ľ����־�Ĵ����϶�Ϊ0x5
	 */
	ret = hi_sec_pke_rslt_get();
	if (ret != HI_RET_SUCC) {
		hi_pke_systrace(ret, 0, 0, 0, 0);
		return ret;
	}

	/* 8. ��ȡ����c���ӼĴ���0xe00~0xe00+4*��2len-1����*/
	hi_sec_pke_rram_get(mod_calc->c, len);

	return HI_RET_SUCC;
}

/* ģ������  modular addition; c= a + b mod p */
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

/* ģ������  modular minus; c= a - b mod p */
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

/* ģ������  modular Multiplication; c= a * b mod p */
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

/* ģ������  modular inversion; c= a^-1 mod p */
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

/* ģ����  modular addition; c= a mod p */
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

/* �����˷� c= a * b */
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

	 /* n ����У��, ����1������ */
	if (hi_sec_pke_para_check(modexp.n, modexp.len,
		HI_SEC_PKE_PARA_TYPE_ODD | HI_SEC_PKE_PARA_TYPE_GREATER_THAN_1))
		return HI_RET_INVALID_PARA;

	/* m ����У��,m < n*/
	if (hi_sec_pke_compare(modexp.n, modexp.m, modexp.len) <= 0)
		return HI_RET_INVALID_PARA;

	if (sec_aealg == HI_SEC_AEALG_RSA) {
		/* RSA e ����У�� , RSA ��e �Ǵ���1������*/
		if (hi_sec_pke_para_check(modexp.e, modexp.len,
			HI_SEC_PKE_PARA_TYPE_ODD |
			HI_SEC_PKE_PARA_TYPE_GREATER_THAN_1))
			return HI_RET_INVALID_PARA;
		/* e ����У��,e < n*/
		if (hi_sec_pke_compare(modexp.n, modexp.e, modexp.len) <= 0)
			return HI_RET_INVALID_PARA;
	} else {
		/* DH e ����У�� , DH ��e ����1*/
		if (hi_sec_pke_para_check(modexp.e, modexp.len,
			HI_SEC_PKE_PARA_TYPE_GREATER_THAN_1))
			return HI_RET_INVALID_PARA;
	}

	return HI_RET_SUCC;
}

/* ģ������ modular exponentiation */
hi_int32 hi_sec_pke_modexp(struct hi_pke_modexp_s *modexp,
	enum hi_sec_aealg_e sec_aealg)
{
	struct hi_sdk_l0_reg_pke_top_pke_work_mode_s work_mode;
	hi_int32 ret;
	hi_uint32 len;

	/* RSA DH������� */
	if (hi_pke_modeexp_chk_para(*modexp, sec_aealg))
		return HI_RET_INVALID_PARA;

	len = modexp->len;
	if (hi_pke_is_busy())
		return HI_RET_TIMEOUT;

	/* 2. ����WORK_MODEģʽ�Ĵ���0x0004={16'd0,8'dlen,8'd0}�� */
	work_mode.opcode = HI_PKE_OP_MOD_EXP;
	work_mode.mode = len / HI_SEC_PKE_NLEN_MOD;
	hi_sdk_l0_write_reg(HI_SDK_L0_REG_PKE_TOP_PKE_WORK_MODE_BASE,
		(hi_uint32 *)&work_mode);

	/* 3. ��������m���Ĵ���0x200~0x200+4*��2len-1���� */
	hi_sec_pke_mram_set(modexp->m, len);

	/* 4. ��������n���Ĵ���0x600~0x600+4*��2len-1���� */
	hi_sec_pke_nram_set(modexp->n, len);

	/* 5. ��������e���Ĵ���0xa00~0xa00+4*��2len-1���� */
	hi_sec_pke_kram_set(0, modexp->e, len);

	/* 6. ���ÿ����Ĵ���0x0008=32'h5�� */
	hi_pke_cfg_start();

	if (hi_pke_is_busy())
		return HI_RET_TIMEOUT;

	/*
	 * 9.��ȡ�����־�Ĵ���0x0040, ���Ϊ0x5�����ִ�е�10����
	 * ���Ϊ0xa���ȡ���ʧ�ܱ�־�Ĵ���0x0044�����ش���
	 * 0x0044��ֵΪ0x3��ʾ����������ܵ���DFA������
	 */
	ret = hi_sec_pke_rslt_get();
	if(ret != HI_RET_SUCC)
		return ret;

	/* 10.�ӼĴ���0xe00~0xe00+4*��2len-1����ȡģ�ݽ���� */
	hi_sec_pke_rram_get(modexp->c, len);

	return HI_RET_SUCC;
}

static hi_int32 hi_pke_read_rram_rslt(hi_uchar8 *rx, hi_uchar8 *ry, hi_uint32 len)
{
	hi_uchar8 *buf_ram = HI_NULL;
	hi_uchar8 *buf_tmp = HI_NULL;

	/* 14 �ӼĴ���0xe00~0xe5c��ȡ������Rx */
	/* 15 �ӼĴ���0xe60~0xebc��ȡ������Ry */
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

/* ECC ��� R = k * P ���� */
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

	hi_memset(buf_ram, 0, buflen); /* ��λ��0 */
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

	/* 6. ���ÿ����Ĵ���0x0008=32'h5;*/
	hi_pke_cfg_start();

	if (hi_pke_is_busy())
		return HI_RET_TIMEOUT;

	/* ��ȡ�����־�Ĵ���0x0040�����Ϊ0x5�����ִ�� */
	ret = hi_sec_pke_rslt_get();
	if (ret != HI_RET_SUCC)
		return ret;

	ret = hi_pke_read_rram_rslt(ecc_pm->rx, ecc_pm->ry, len);

	return ret;
}

/* ��� C = S + R */
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

	/* 5 ��������p���Ĵ���0xa60~0xabc��λ����Ĳ��ֲ�0 */
	/* 6 ��������a���Ĵ���0xac0~0xb1c��λ����Ĳ��ֲ�0 */
	/* 7 ��������Rx���Ĵ���0xb20~0xb7c��λ����Ĳ��ֲ�0 */
	/* 8 ��������Ry���Ĵ���0xb80~0xbdc��λ����Ĳ��ֲ�0 */
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

	/* 6. ���ÿ����Ĵ���0x0008=32'h5;*/
	hi_pke_cfg_start();

	if (hi_pke_is_busy())
		return HI_RET_TIMEOUT;

	/* ��ȡ�����־�Ĵ���0x0040�����Ϊ0x5�����ִ�� */
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
		/* e ����У�� */
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

	/* ��ȡALARM״̬�Ĵ���0x24�������Ϊ0xA��ֱ������ʧ�� */
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

	/* 8.��ȡ����E���ӼĴ���0x200~0x200+4*��2len-1�� */
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
	* 9.�����E����У�飺��EΪ������룬���ж϶�ȡ��E�������E�Ƿ�һ�£�
	* �����һ�£��������
	* ��EΪ�߼��ڲ����������ж�E����Чλ���Ƿ����32bit��С�ڵ���64bit
	* ��������������
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
	 * 2.����WORK_MODEģʽ�Ĵ���0x0004={16'd0,8'dlen,8'd1}��
	 * ����{16'd0,8'dlen,8'd2}��
	 * ǰ�����ڹ�ԿE���ⲿ�������ʱ����Կ�Բ�����
	 * �������ڹ�Կ���ڲ�����ʱ����Կ�Բ�����
	 * ����ԿΪ�ⲿ���룬���հ��ճ���len��������
	 */
	work_mode.opcode = kgen_req->einput ? 
		HI_PKE_OP_KEYE_EXTERN : HI_PKE_OP_KEYE_INNER;
	work_mode.mode = len / HI_SEC_PKE_NLEN_MOD;
	hi_sdk_l0_write_reg(HI_SDK_L0_REG_PKE_TOP_PKE_WORK_MODE_BASE,
		(hi_uint32 *)&work_mode);

	/* 3����Ǵ���Կ����Կ���������ù�ԿE���Ĵ���0x200~0x200+4*��2len-1��*/
	if (kgen_req->einput == HI_ENABLE)
		hi_sec_pke_mram_set(kgen_req->e, len);

	/* 4���� */
	hi_pke_cfg_start();

	/* 5��BUSY */
	if (hi_pke_is_busy())
		return HI_RET_TIMEOUT;

	/* 6��ȡALARM״̬�Ĵ��� */
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
		
	/* 10.��ȡ����N���ӼĴ���0x600~0x600+4*��2len-1����*/
	hi_sec_pke_nram_get(kgen_req->n, len);

	/* 11.����ж�N�ĸ�2bit�Ƿ�ȫ�㣬��ȫ�㣬����Ҫ����������Կ����������*/
	if (!(kgen_req->n[0] >> 6)) {
		hi_pke_systrace(HI_RET_FAIL, 0, 0, 0, 0);
		return HI_RET_FAIL;
	}

	/* 12.��ȡ����D���ӼĴ���0xe00~0xe00+4*��2len-1��*/
	hi_sec_pke_rram_get(kgen_req->d, len);

	return HI_RET_SUCC;
}
