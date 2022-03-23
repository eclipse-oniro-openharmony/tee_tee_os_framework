/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2017-2019. All rights reserved.
 * Description: PKE
 * Author: hsan
 * Create: 2017-4-11
 * History: 2017-4-11�������
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
#define HI_SEC_PKE_ECDSA_521BIT   66 /* �����ֽ� */

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

/* ģ�ӡ������ˡ��桢ģ�������� */
struct hi_pke_mod_s {
	hi_uchar8 *a;
	hi_uchar8 *b;
	hi_uchar8 *p;
	hi_uint32 len;
	hi_uchar8 *c; /* out ģ������*/
};

/*
 * ģ�� c=me mod n
 * n����Ϊ��������ԿeҲ����Ϊ����������λ��������涨�ĳ���
 * len��ʾn�ĳ��ȣ���Կe��λ����lenʱ��λ�貹����룬��λΪ64bit
 */
struct hi_pke_modexp_s {
	hi_uchar8 *m;
	hi_uchar8 *e;
	hi_uchar8 *n;
	hi_uint32 len;
	hi_uchar8 *c; /* out ģ�ݼ�����*/
};

/* ECC ��� R = k * P ���� */
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
	hi_uint32 len; /* in ����λ��bit */
	hi_uchar8 *rx; /* out */
	hi_uchar8 *ry; /* out */
};

/* ��� C = S + R ���� */
struct hi_pke_pointadd_s {
	hi_uchar8 *sx;
	hi_uchar8 *sy;
	hi_uchar8 *rx;
	hi_uchar8 *ry;
	hi_uchar8 *p;
	hi_uchar8 *a;
	hi_uint32 len; /* in ����λ��bit */
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
    hi_uint32 running;            /* ��ʼ������״̬���޽�� */
    hi_uint32 succ;               /* ����ɹ� */
    hi_uint32 unknow;             /* δ֪��� */
    hi_uint32 fail;               /* ����ʧ�ܣ��޽������ */
    hi_uint32 fail_runing;        /* ��ʼ������״̬���޽�� */
    hi_uint32 fail_modinvers;     /* ģ���޽�� */
    hi_uint32 fail_random;        /* ���������ʧ�� */
    hi_uint32 fail_dfa;           /* ��DFA����ʧ�� */
    hi_uint32 fail_unlimit_point; /* ��˻��ӽ��Ϊ����Զ�� */
    hi_uint32 fail_unknow;        /* δ֪ʧ�� */
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
