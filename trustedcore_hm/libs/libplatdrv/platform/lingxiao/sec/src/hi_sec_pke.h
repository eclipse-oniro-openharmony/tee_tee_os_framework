/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2017-2019. All rights reserved.
 * Description: PKE
 * Author: hsan
 * Create: 2017-4-11
 * History: 2017-4-11初稿完成
 *          2019-1-31 hsan code restyle
 */

#ifndef __HI_SEC_PKE_H__
#define __HI_SEC_PKE_H__

#ifdef __cplusplus
#if __cplusplus
extern "C"{
#endif
#endif /* __cplusplus */

#ifndef HI_VERSION_DEBUG
#define HI_VERSION_DEBUG
#endif

#ifdef HI_VERSION_DEBUG
#define hi_pke_printmemdes(ui_dbglevel,puc_src,ui_len,fmt,arg...) \
        hi_memdes(HI_KSOC_SDK_L2_SCRTY_PKE, ui_dbglevel, puc_src, ui_len, (hi_uchar8 *)fmt, ##arg)
#if 0
#define hi_pke_systrace(ui_ret, arg1, arg2, arg3, arg4) \
        hi_systrace(HI_KSOC_SDK_L2_SCRTY_PKE, ui_ret, arg1, arg2, arg3, arg4)
#endif
#define hi_pke_systrace(ret, arg1, arg2, arg3, arg4) \
	printk("ret:0x%08x arg1:0x%08x arg2:0x%08x F:%s L:%d\n", ret, arg1, arg2, __FUNCTION__, __LINE__)
#define hi_pke_debug(ui_level, fmt, arg...) \
        hi_debug(HI_KSOC_SDK_L2_SCRTY_PKE, ui_level, fmt, ##arg)
#define hi_pke_print(ui_level, fmt, arg...) \
        hi_print(HI_KSOC_SDK_L2_SCRTY_PKE, ui_level, fmt, ##arg)
#else
#define hi_pke_printmemdes(ui_dbglevel, puc_src, ui_len, fmt, arg...)
#define hi_pke_systrace(ret, arg1, arg2, arg3, arg4)
#define hi_pke_debug(ui_module, ui_level, fmt, arg...)
#define hi_pke_print(ui_module, ui_dbglevel, fmt, arg...)
#endif

#define HI_SEC_PKE_RSA_1024BIT  128
#define HI_SEC_PKE_RSA_2048BIT  256
#define HI_SEC_PKE_RSA_3072BIT  384
#define HI_SEC_PKE_RSA_4096BIT  512

#define HI_SEC_PKE_DH_768BIT   96
#define HI_SEC_PKE_DH_1024BIT  128
#define HI_SEC_PKE_DH_1536BIT  192
#define HI_SEC_PKE_DH_2048BIT  256
#define HI_SEC_PKE_DH_3072BIT  384
#define HI_SEC_PKE_DH_4096BIT  512

#define HI_SEC_PKE_ECDSA_192BIT   24 
#define HI_SEC_PKE_ECDSA_224BIT   28 
#define HI_SEC_PKE_ECDSA_256BIT   32 
#define HI_SEC_PKE_ECDSA_384BIT   48 
#define HI_SEC_PKE_ECDSA_521BIT   66 /* 补齐字节 */

#define HI_SEC_PKE_RSA_MAXLEN     512
#define HI_SEC_PKE_DH_MAXLEN      512
#define HI_SEC_PKE_ECDSA_MAXLEN   66
#define HI_SEC_PKE_SM2_MAXLEN     32

enum hi_sec_aealg_e {
	HI_SEC_AEALG_RSA = 0,
	HI_SEC_AEALG_DH,
	HI_SEC_AEALG_ECDSA,
	HI_SEC_AEALG_NUM,
};

enum hi_sec_aealg_func_e {
	HI_SEC_AEALG_FUNC_SIGN = 0,
	HI_SEC_AEALG_FUNC_VERIF,
	HI_SEC_AEALG_FUNC_PUBENC,
	HI_SEC_AEALG_FUNC_PUBDEC,
	HI_SEC_AEALG_FUNC_PRIENC,
	HI_SEC_AEALG_FUNC_PRIDEC,
	HI_SEC_AEALG_FUNC_KEYGEN,
	HI_SEC_AEALG_FUNC_KEYCHK,
	HI_SEC_AEALG_FUNC_NUM,
};

/* 模加、减、乘、逆、模运算数据 */
struct hi_pke_mod_s {
	hi_uchar8 *a;
	hi_uchar8 *b;
	hi_uchar8 *p;
	hi_uint32 len;
	hi_uchar8 *c; /* out 模计算结果*/
};

/*
 * 模幂 c=me mod n
 * n必须为奇数，密钥e也必须为奇数，数据位宽按照需求规定的长度
 * len表示n的长度，秘钥e的位宽不足len时高位需补零对齐，单位为64bit
 */
struct hi_pke_modexp_s {
	hi_uchar8 *m;
	hi_uchar8 *e;
	hi_uchar8 *n;
	hi_uint32 len;
	hi_uchar8 *c; /* out 模幂计算结果*/
};

/* ECC 点乘 R = k * P 数据 */
struct hi_pke_ecc_pointmulti_s {
	hi_uchar8 *k;
	hi_uchar8 *p;
	hi_uchar8 *n;
	hi_uchar8 *a;
	hi_uchar8 *b;
	hi_uchar8 *gx;
	hi_uchar8 *gy;
	hi_uchar8 *px;
	hi_uchar8 *py;
	hi_uint32 len; /* in 数据位宽bit */
	hi_uchar8 *rx; /* out */
	hi_uchar8 *ry; /* out */
};

/* 点加 C = S + R 数据 */
struct hi_pke_pointadd_s {
	hi_uchar8 *sx;
	hi_uchar8 *sy;
	hi_uchar8 *rx;
	hi_uchar8 *ry;
	hi_uchar8 *p;
	hi_uchar8 *a;
	hi_uint32 len; /* in 数据位宽bit */
	hi_uchar8 *cx; /* out */
	hi_uchar8 *cy; /* out */
};

struct hi_sec_ecdsa_oval_param_s {
	hi_ushort16 keylen;
	hi_uchar8 p[HI_SEC_PKE_ECDSA_521BIT];
	hi_uchar8 n[HI_SEC_PKE_ECDSA_521BIT];
	hi_uchar8 a[HI_SEC_PKE_ECDSA_521BIT];
	hi_uchar8 b[HI_SEC_PKE_ECDSA_521BIT];
	hi_uchar8 gx[HI_SEC_PKE_ECDSA_521BIT];
	hi_uchar8 gy[HI_SEC_PKE_ECDSA_521BIT];
};

struct hi_sec_aealg_oval_s {
    struct hi_sec_ecdsa_oval_param_s ecdsa;
};

struct hi_sec_pke_sta_s {
    hi_uint32 running;            /* 初始或运行状态，无结果 */
    hi_uint32 succ;               /* 处理成功 */
    hi_uint32 unknow;             /* 未知结果 */
    hi_uint32 fail;               /* 处理失败，无结果数据 */
    hi_uint32 fail_runing;        /* 初始或运行状态，无结果 */
    hi_uint32 fail_modinvers;     /* 模逆无结果 */
    hi_uint32 fail_random;        /* 随机数申请失败 */
    hi_uint32 fail_dfa;           /* 被DFA导致失败 */
    hi_uint32 fail_unlimit_point; /* 点乘或点加结果为无穷远点 */
    hi_uint32 fail_unknow;        /* 未知失败 */
};

hi_int32 hi_sec_pke_data_valid(hi_uchar8 *k,
	hi_uchar8 *n, hi_uint32 min, hi_uint32 len);

hi_int32 hi_sec_pke_random_get(hi_uchar8 *n, hi_uint32 len, hi_uchar8 *data);

hi_int32 hi_sec_pke_modadd(
	hi_uchar8 *a, hi_uchar8 *b, hi_uchar8 *p, hi_uint32 len, hi_uchar8 *c);

hi_int32 hi_sec_pke_modminus(
	hi_uchar8 *a, hi_uchar8 *b, hi_uchar8 *p, hi_uint32 len, hi_uchar8 *c);

hi_int32 hi_sec_pke_modmulti(
	hi_uchar8 *a, hi_uchar8 *b, hi_uchar8 *p, hi_uint32 len, hi_uchar8 *c);

hi_int32 hi_sec_pke_modinvers(
	hi_uchar8 *a, hi_uchar8 *p, hi_uint32 len, hi_uchar8 *c);

hi_int32 hi_sec_pke_mod(
	hi_uchar8 *a, hi_uchar8 *p, hi_uint32 len, hi_uchar8 *c);

hi_int32 hi_sec_pke_bigmulti(
	hi_uchar8 *a, hi_uchar8 *b, hi_uint32 len, hi_uchar8 *c);

hi_int32 hi_sec_pke_modexp(struct hi_pke_modexp_s *modexp,
	enum hi_sec_aealg_e sec_aealg);

hi_int32 hi_sec_pke_ecc_pointmulti(struct hi_pke_ecc_pointmulti_s *ecc_pm);

hi_int32 hi_sec_pke_pointadd(struct hi_pke_pointadd_s *padd);

hi_int32 hi_sec_pke_rsa_keygen(struct hi_sec_rsa_req *kgen_req);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */

#endif /* __HI_SEC_PKE_H__ */
