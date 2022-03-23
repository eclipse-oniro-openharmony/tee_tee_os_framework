/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2014-2019. All rights reserved.
 * Description: �ӽ�����������ͷ�ļ�
 * Author: o00302765
 * Create: 2019-10-22
 */

#ifndef __HI_SEC_DRV_H__
#define __HI_SEC_DRV_H__

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif /* __cplusplus */

#ifdef HI_VERSION_DEBUG
#define hi_secdrv_printmemdes(dbglevel,src,len,fmt,arg...) \
	hi_memdes(HI_KSOC_SDK_L2_SCRTY_SEC, dbglevel, src, len, (hi_uchar8 *)fmt, ##arg)
#define hi_secdrv_systrace(ret, arg1, arg2, arg3, arg4) \
	printk("ret:0x%08x 0x%08x 0x%d 0x%d 0x%d F:%s L:%d\n", ret, arg1, arg2, arg3, arg4, __FUNCTION__, __LINE__)
#define hi_secdrv_debug(level, fmt, arg...) \
	hi_debug(HI_KSOC_SDK_L2_SCRTY_SEC, level, fmt, ##arg)
#define hi_secdrv_print(level, fmt, arg...) \
	hi_print(HI_KSOC_SDK_L2_SCRTY_SEC, level, fmt, ##arg)
#else
#define hi_secdrv_printmemdes(dbglevel, src, len, fmt, arg...)
#define hi_secdrv_systrace(ret, arg1, arg2, arg3, arg4)
#define hi_secdrv_debug(module, level, fmt, arg...)
#define hi_secdrv_print(module, dbglevel, fmt, arg...)
#endif

#define HI_SEC_BD_QNUM  8

/* BD�����ø澯��Ϣ������bit��ֵ��'1'��ʾ�и澯��'0'��ʾ�޸澯�� */
#define HI_SEC_DRV_BD_SM3_ALARM         0x1 /* bit[0]=1'b1: ��ʾSM3��efuse��Ч������������SM3�㷨��*/
#define HI_SEC_DRV_BD_SM4_ALARM         0x2 /* bit[1]=1'b1: ��ʾSM4��efuse��Ч������������SM4�㷨��*/
#define HI_SEC_DRV_BD_KEY_ALARM         0x4 /* bit[2]=1'b1: ��ʾBD����Կ��Ϣ�����쳣���ã�*/
#define HI_SEC_DRV_BD_DATA_ALARM        0x8 /* bit[3]=1'b1: ��ʾBD�б�����Ϣ�����쳣���ã� */

/* sec_flag[2]: ������ */
#define HI_SEC_DRV_SEC_FLAG_BIG_ENDIAN  0x8 /* sec_flag[3]: ��С�˱�ǣ�1��b1��ʾ��ˣ�1��b0��ʾС�ˡ� */
#define HI_SEC_DRV_SEC_FLAG_HASH_BODY   0x0
#define HI_SEC_DRV_SEC_FLAG_HASH_TAIL   0x4
#define HI_SEC_DRV_SEC_FLAG_CRYPTO_BODY 0x0
#define HI_SEC_DRV_SEC_FLAG_CRYPTO_TAIL 0x2
#define HI_SEC_DRV_SEC_FLAG_CH_ERR      0x2 /* sec_flag[1]: ͨ�����쳣��ǣ���1����ʾch_id����7�� */
#define HI_SEC_DRV_SEC_FLAG_NON_SECURE  0x1 /* sec_flag[0]: 1'b0��ʾ��Կ�ڰ�ȫ���� 1'b1��ʾ��Կ�ڷǰ�ȫ���� */

#define HI_SEC_DRV_BD_FLAG_DONE         0x8 /* bd_flag[3]�� BD������ɵı�ǣ�1'b1:��ʾ������ɣ�1'b0:��ʾδ������ɡ� */
#define HI_SEC_DRV_BD_FLAG_HASH_SUCC    0x4 /* bd_flag[2]�� hash��֤�����ǣ� 1'b1:��ʾ��֤�ɹ���1'b0:��ʾ��֤ʧ�ܡ��������Ҫ�߼�������ֵ֤�Ƚϣ���ñ����Ч�� */

/* bd_flag[1:0]��LINK_BD��ǣ� 2��b00����ʾ��LINK_BD��ע��ͬһͨ���ڵ�LINK_BD���������� */
#define HI_SEC_DRV_BD_FLAG_LINK_START   0x1 /* 2��b01����ʾLINK_BD������ʼ BD�� */
#define HI_SEC_DRV_BD_FLAG_LINK_END     0x2 /* 2��b10����ʾLINK_BD���Ľ��� BD�� */
#define HI_SEC_DRV_BD_FLAG_LINK_BODY    0x3 /* 2��b11����ʾLINK_BD�����м� BD�� */

/* task_flag[7]: AES_CCM/GCMģʽ����֤ʧ�ܱ�־������Ч�� */
#define HI_SEC_DRV_TASK_FLAG_AES_XCM_AUTH_FAIL  0x80

/*
 * task_flag[6:5]: AES_GCM/CCM����A�Ͳ���iv��Ԥ������λ��
 * ������������AES���㣻
 * ע�⣺��A��iv�ĳ��ȴ���128bit����Ҫ����Ԥ����
 */
#define HI_SEC_DRV_TASK_FLAG_AES_XCM_IV_PRE     0x40    /* 2��b10����ʾ��ǰAES�ǶԲ���iv��Ԥ����*/
#define HI_SEC_DRV_TASK_FLAG_AES_XCM_A_PRE      0x20    /* 2��b01����ʾ��ǰAES�ǶԲ���A��Ԥ���� */

/*
 * task_flag [4]: AES_GCM/CCM����A�ı�ǣ�
 *  1��b1����ʾYi��������AԤ�����Ľ����
 *  1��b0����ʾԭʼ�Ĳ���A��
 */
#define HI_SEC_DRV_TASK_FLAG_AES_XCM_A_RSLT     0x10

/*
 * task_flag [3]: AES_GCM����iv�ı�ǣ�
 *  1��b1����ʾJi��������ivԤ�����Ľ����
 *  1��b0����ʾԭʼ�Ĳ���iv��
 */
#define HI_SEC_DRV_TASK_FLAG_AES_XCM_IV_RSLT    0x08

/* task_flag[2]���ӽ��ܱ�ǣ�1'b1:��ʾ���ܣ�  1'b0:��ʾ���ܣ� */
#define HI_SEC_DRV_TASK_FLAG_ENCRYPTO           0x04
#define HI_SEC_DRV_TASK_FLAG_DECRYPTO           0x00

/* task_flag[1]��AES��֤�����Ԥ�����ǣ� */
/*
 * ��AES_CCM/GCM�Ĳ���A/iv�Լ� AES_XCBC��keyԤ����ʱ��ʾ����Ƿ��д��
 *   1'b1:��ʾ��дԤ����Ľ����
 *   1'b0:��ʾ����дԤ��������
 */
#define HI_SEC_DRV_TASK_FLAG_AES_XCM_XCBC_PRE_REWR  0x02

/*
 * AESCCM/GCM��������ʱTAG��д���
 *  1'b1:��ʾ��дTAG��
 *  1'b0:��ʾ��ȡTAG����У�顣
 */
#define HI_SEC_DRV_TASK_FLAG_AES_XCM_TAG_REWR       0x02

/*
 * task_flag[0]����֤��Ϣ�Ĵ����ǣ�
 *  1'b1:��ʾ��д��֤�����
 *  1'b0:��ʾУ����֤�����
 */
#define HI_SEC_DRV_TASK_FLAG_AUTH_REWR  0x01

#define HI_SEC_DRV_CALLBACK_DATALEN 128
#define HI_SEC_DRV_MAX_BD_DATALEN   2000
#define HI_SEC_BD_LEN               1024

enum hi_sec_drv_task_e {
	HI_SEC_DRV_TASK_AUTH_ENC_E = 0,  /* ��֤+���� */
	HI_SEC_DRV_TASK_AUTH_DEC_E,      /* ��֤+���� */
	HI_SEC_DRV_TASK_ENC_AUTH_E,      /* ����+��֤ */
	HI_SEC_DRV_TASK_DEC_AUTH_E,      /* ����+��֤ */
	HI_SEC_DRV_TASK_AUTH_E,          /* ��֤ */
	HI_SEC_DRV_TASK_ENC_E,           /* ���� */
	HI_SEC_DRV_TASK_DEC_E,           /* ���� */
	HI_SEC_DRV_TASK_RAND_E,          /* �������ȡ */
};

enum hi_sec_drv_k_source_e {
	HI_SEC_DRV_K_SRC_BD_E = 0,  /* ��Կ������BD��*/
	HI_SEC_DRV_K_SRC_KDF_E,     /* ��Կ������KDF��*/
	HI_SEC_DRV_K_SRC_EFUSE1_E,  /* ��Կ������efuse1 ����OS����*/
	HI_SEC_DRV_K_SRC_EFUSE2_E,  /* ��Կ������efuse2 ����flash�洢�Ĵ���*/
};

enum hi_sec_drv_hash_e {
	HI_SEC_DRV_HASH_MD5_E = 0,
	HI_SEC_DRV_HASH_SHA1_E,
	HI_SEC_DRV_HASH_SHA256_E,
	HI_SEC_DRV_HASH_SHA384_E,
	HI_SEC_DRV_HASH_SHA512_E,
	HI_SEC_DRV_HASH_HMAC_SM3_E,
	HI_SEC_DRV_HASH_HMAC_MD5_E,
	HI_SEC_DRV_HASH_HMAC_SHA1_E,
	HI_SEC_DRV_HASH_HMAC_SHA256_E,
	HI_SEC_DRV_HASH_HMAC_SHA384_E,
	HI_SEC_DRV_HASH_HMAC_SHA512_E,
	HI_SEC_DRV_HASH_SM3_E,
};

/*
 * ע�⣺��AES_XCBC����ԿKEY���ȴ���128bitʱ��
 * ��Ҫ��KEY����Ԥ�������õ��Ľ����Ϊ���յ�KEY��
 */
enum hi_sec_drv_cipher_e {
	HI_SEC_DRV_CIPHER_AES_ECB_E = 0,
	HI_SEC_DRV_CIPHER_AES_CBC_E,
	HI_SEC_DRV_CIPHER_AES_CCM_E,
	HI_SEC_DRV_CIPHER_AES_GCM_E,
	HI_SEC_DRV_CIPHER_AES_XTS_E,
	HI_SEC_DRV_CIPHER_AES_CTR_E,
	HI_SEC_DRV_CIPHER_DES_ECB_E,
	HI_SEC_DRV_CIPHER_DES_CBC_E,
	HI_SEC_DRV_CIPHER_TDES_ECB_E,
	HI_SEC_DRV_CIPHER_TDES_CBC_E,
	HI_SEC_DRV_CIPHER_SM4_CBC_E,
	HI_SEC_DRV_CIPHER_AES_XCBC_E,
	HI_SEC_DRV_CIPHER_AES_GHSAH_E,
};

struct hi_sec_bd_desc_s {
	struct {
		/*
		 * BD�����ø澯��Ϣ������bit��ֵ��'1'��ʾ�и澯��'0'��ʾ�޸澯��
		 * bit[0]=1'b1: ��ʾSM3��efuse��Ч������������SM3�㷨��
		 * bit[1]=1'b1: ��ʾSM4��efuse��Ч������������SM4�㷨��
		 * bit[2]=1'b1: ��ʾBD����Կ��Ϣ�����쳣���ã�
		 * bit[3]=1'b1: ��ʾBD�б�����Ϣ�����쳣���ã�
		 * bit[7:4]������������ֵΪ0��
		 */
		hi_ulong64 bd_alarm: 8;

		/*
		 * ��λ���ֽڣ� ��ʾ��ǰBD��дDDRʱ�ӽ��ܽ������Ч���ȣ�
		 * ע�⣺��LINK_BDģʽ�¼ӽ��ܽ�����ܲ����ڵ�ǰBD���ĵĳ��ȣ���������ܳ�������ȵġ�
		 */
		hi_ulong64 crslt_len: 12;

		hi_ulong64 encrypt: 8;
		hi_ulong64 k_source: 4;
		hi_ulong64 hash: 8;
		hi_ulong64 task: 4;
		hi_ulong64 task_flag: 8;
		hi_ulong64 ch_id: 4;
		hi_ulong64 bd_flag: 4;
		hi_ulong64 sec_flag: 4;

		/* ��λ���ֽڣ���ʾhash��֤����ĳ��ȣ�����ʾICVIN�ĳ��ȣ�Ҳ��ʾICVOUT�ĳ��ȣ���Ϊ���ǵĳ�����ȡ� */
		hi_ulong64 icv_len: 8;

		/* ��λ���ֽڣ���ʾAES_CCM��AES_GCMģʽ��TAG�ĳ��ȡ� */
		hi_ulong64 tag_len: 8;

		/*
		 * ��λ���ֽڣ� ���ֶ��Ǹ����ֶΣ���������ʾ������Ϣ��
		 * 1����AES_CCMģʽ�£���ʾ������N���ĳ��ȣ�
		 * 2����AES_XTSģʽ�£���ʾ������i���ĳ��ȣ�
		 * 3����AES_GCMģʽ�±�ʾԤ������iv�ĳ��ȣ�������ԭʼiv���Ȳ�����128bitʱ��ԭʼiv����ֵ��
		 * 4����������£���ʾ�����ӽ����㷨��IV���ȣ�
		 */
		hi_ulong64 civ_len: 8;

		/*
		 * ��λ���ֽڣ� ���ֶα�ʾ�ӽ�����Կ�ĳ��ȣ�AES��XTSģʽ��ʹ����������Կ�����ȶ���ͬ��
		 * TDES�㷨ʱ��ʾ������Կ���ܳ�����������Կ�ĳ�����ȣ���
		 * 8��d8����Կ����Ϊ 64bit��
		 * 8��d16����Կ����Ϊ128bit��
		 * 8��d24����Կ����Ϊ192bit��
		 * 8��d32����Կ����Ϊ256bit��
		 * ���� ��DES/TDESĬ��ȡ8��d8��AES/SM4Ĭ��ȡ8��d16��
		 */
		hi_ulong64 ckey_len: 8;

		/*
		 * ��λ���ֽڣ� ���ֶα�ʾ���ӽ������ݻ�����AEX_XCBC������ĳ��ȡ�
		 * ��AES_GCM/CCM�Ĳ���A�Ͳ���iv��Ԥ����ʱ����ʾ��ǰBD��A��iv�ĳ��ȣ�
		 * ��AES_XCBC����Կkey��Ԥ����ʱ����ʾ��ǰBD��key�ĳ��ȣ�
		 */
		hi_ulong64 cdata_len: 12;

		/* ��λ���ֽڣ� ���ֶα�ʾ��֤���ݵĳ��ȡ� */
		hi_ulong64 adata_len: 12;

		/* ��λ���ֽڣ� ���ֶα�ʾ��֤�㷨����Կ���ȡ� */
		hi_ulong64 akey_len: 8;
	} bits;

	hi_uint32 ta_len;            /* ��λ���ֽڣ���ʾAES_CCM/GCMģʽ�²���A���ܳ��ȡ�*/
	hi_uint32 tcdata_len;        /* ��λ���ֽڣ���ʾAES_CCM/GCMģʽ�±��ĵ��ܳ��ȡ� */
	hi_uint32 cipher_rslt_addr;  /* ��д�ӽ��ܽ��ʱ��DDR�׵�ַ�� */
	hi_uint32 tiv_len;           /* ��λ���ֽڣ���ʾAES_ GCMģʽ�²���iv���ܳ��ȡ�  */

	/*
	 * ���ӽ������ݵ��׵�ַ��AES_CCM/GCMԤ�����ǵĲ���A��iv��
	 * �Լ�AES_XCBC��Ԥ����keyʱ����ʹ�øõ�ַ�����á�
	 */
	hi_uint32 cipher_data_addr;

	hi_uint32 auth_data_addr;    /* ����֤���ݵ��׵�ַ�� */

	/*
	 * AES_CCM��AES_GCM����֤�����TAG����DDR�е��׵�ַ��
	 * ���SECΪԴ�ˣ���ʾTAG��д�׵�ַ��
	 * ���SECΪĿ�Ķˣ���ʾ��У��TAG���׵�ַ���߼��Ӹõ�ַȥ��TAG��
	 */
	hi_uint32 cipher_tag_addr;

	/*
	 * ���task������֤���񣬲�ͬ��task_flag[0]��ֵ�õ�ַ��ʾ��ͬ�����壺
	 * task_flag[0]=1'b1ʱ���õ�ַ��ʾ��֤����Ļ�д�׵�ַ��
	 * task_flag[0]=1'b0ʱ����ʾ��У�����ֵ֤���׵�ַ���߼��Ӹõ�ַ����ICV��Ȼ�����߼��ڲ��ļ����ICV�Ƚ�
	 */
	hi_uint32 auth_icv_addr;

	hi_uint32 cipher_key1_addr;  /* �ӽ����㷨����Կ�����DDR�е��׵�ַ�� */
	hi_uint32 auth_key_addr;     /* ��֤�㷨ʹ�õ���Կ���׵�ַ�� */

	union {

		/*
		 * ��ʾ�����ӽ����㷨��IV���׵�ַ��
		 * ע�⣺��AES_GCMģʽ�µ�iv������Ԥ������ivֵ��������ԭʼiv���Ȳ�����128bitʱ��ԭʼivֵ��
		 */
		hi_uint32 cipher_iv_addr;

		/* ��AES_CCMģʽ�£���ʾ������N�����׵�ַ��*/
		hi_uint32 cipher_n_addr;

		/* ��AES_XTSģʽ�£���ʾ������i�����׵�ַ�� */
		hi_uint32 cipher_i_addr;
	};

	union {

		/*
		 * AES_CCM��AES_GCM�Ĳ���A��DDR�е��׵�ַ��
		 * ע�⣺������A�ĳ���С�ڵ���128bitʱ�����ߴ�ʱ��AΪԤ������Aʱ����ʹ�øõ�ַ����ȡ����A��
		 * �Բ���A��Ԥ�������ʱ��ʹ��Cipher_data_addr��
		 */
		hi_uint32 cipher_a_addr;

		/* AES��XTSģʽ��ʹ�õ��ĵڶ���KEY�����DDR�е��׵�ַ�� */
		hi_uint32 cipher_key2_addr;
	};

};

struct hi_sec_drv_cb_data_s {
	hi_uint32 data;
	hi_uint32 err;
};

typedef void (*hi_sec_drv_callback)(hi_void *data);

struct hi_sec_drv_cblist_s {
	hi_sec_drv_callback cb;
	struct hi_sec_drv_cb_data_s cbdata;
};

enum hi_sec_drv_process_e {
	HI_SEC_DRV_OS = 8,
	HI_SEC_DRV_APP,
};

struct hi_sec_threshhold_s {
	hi_uint32 intr;
	hi_uint32 timeout;
};

struct hi_sec_attr_s {
	struct hi_sec_threshhold_s th[HI_SEC_BD_QNUM];
};

struct hi_sec_drv_intr_sta_s {
	hi_ulong64 qrx;      /* ���������ж� */
	hi_ulong64 timeout;  /* ��ʱ�����ж� */
};

struct hi_sec_drv_data_sta_s {
	hi_ulong64 input;    /* ��������BDͳ�� */
	hi_ulong64 output;   /* �������BDͳ�� */
	hi_ulong64 bdalarm_sm3err;
	hi_ulong64 bdalarm_sm4err;
	hi_ulong64 bdalarm_keyerr;
	hi_ulong64 bdalarm_pkterr;
	hi_ulong64 auth_fail;
};

struct hi_sec_cnt_s {
	struct hi_sec_drv_intr_sta_s intr_sta[HI_SEC_BD_QNUM];
	struct hi_sec_drv_data_sta_s data_sta[HI_SEC_BD_QNUM];
	hi_ulong64 alarm;
};

struct hi_sec_ptr_s {
	hi_uint32 sptr;
	hi_uint32 eptr;
	hi_uint32 curr;
};

struct hi_sec_sta_s {
	struct hi_sec_ptr_s ptr[HI_SEC_BD_QNUM];
};

/* DFX */
struct hi_sec_drv_qid_map_s {
	hi_uint32 qid;
	hi_uint32 qidmap;
};

hi_int32 hi_sec_bd_proc(struct hi_sec_bd_desc_s *desc, hi_uint32 num);
hi_int32 hi_sec_drv_init(hi_void);
hi_void hi_sec_drv_exit(hi_void);

//DFX
hi_int32 hi_sec_cnt_get(struct hi_sec_cnt_s *cnt);
hi_int32 hi_sec_sta_get(struct hi_sec_sta_s *sta);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */


#endif /* __HI_SEC_DRV_H__ */
