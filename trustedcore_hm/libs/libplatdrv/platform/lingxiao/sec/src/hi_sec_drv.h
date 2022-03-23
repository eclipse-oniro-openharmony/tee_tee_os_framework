/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2014-2019. All rights reserved.
 * Description: 加解密引擎驱动头文件
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

/* BD的配置告警信息，各个bit的值：'1'表示有告警，'0'表示无告警； */
#define HI_SEC_DRV_BD_SM3_ALARM         0x1 /* bit[0]=1'b1: 表示SM3的efuse有效，但是配置了SM3算法；*/
#define HI_SEC_DRV_BD_SM4_ALARM         0x2 /* bit[1]=1'b1: 表示SM4的efuse有效，但是配置了SM4算法；*/
#define HI_SEC_DRV_BD_KEY_ALARM         0x4 /* bit[2]=1'b1: 表示BD中秘钥信息域有异常配置；*/
#define HI_SEC_DRV_BD_DATA_ALARM        0x8 /* bit[3]=1'b1: 表示BD中报文信息域有异常配置； */

/* sec_flag[2]: 保留。 */
#define HI_SEC_DRV_SEC_FLAG_BIG_ENDIAN  0x8 /* sec_flag[3]: 大小端标记，1’b1表示大端，1‘b0表示小端。 */
#define HI_SEC_DRV_SEC_FLAG_HASH_BODY   0x0
#define HI_SEC_DRV_SEC_FLAG_HASH_TAIL   0x4
#define HI_SEC_DRV_SEC_FLAG_CRYPTO_BODY 0x0
#define HI_SEC_DRV_SEC_FLAG_CRYPTO_TAIL 0x2
#define HI_SEC_DRV_SEC_FLAG_CH_ERR      0x2 /* sec_flag[1]: 通道号异常标记，‘1’表示ch_id大于7。 */
#define HI_SEC_DRV_SEC_FLAG_NON_SECURE  0x1 /* sec_flag[0]: 1'b0表示秘钥在安全区； 1'b1表示秘钥在非安全区。 */

#define HI_SEC_DRV_BD_FLAG_DONE         0x8 /* bd_flag[3]： BD处理完成的标记；1'b1:表示处理完成；1'b0:表示未处理完成。 */
#define HI_SEC_DRV_BD_FLAG_HASH_SUCC    0x4 /* bd_flag[2]： hash认证结果标记； 1'b1:表示认证成功；1'b0:表示认证失败。如果不需要逻辑进行认证值比较，则该标记无效。 */

/* bd_flag[1:0]：LINK_BD标记； 2’b00：表示非LINK_BD；注：同一通道内的LINK_BD必须连续。 */
#define HI_SEC_DRV_BD_FLAG_LINK_START   0x1 /* 2’b01：表示LINK_BD链的起始 BD； */
#define HI_SEC_DRV_BD_FLAG_LINK_END     0x2 /* 2’b10：表示LINK_BD链的结束 BD； */
#define HI_SEC_DRV_BD_FLAG_LINK_BODY    0x3 /* 2’b11：表示LINK_BD链的中间 BD； */

/* task_flag[7]: AES_CCM/GCM模式的认证失败标志，高有效。 */
#define HI_SEC_DRV_TASK_FLAG_AES_XCM_AUTH_FAIL  0x80

/*
 * task_flag[6:5]: AES_GCM/CCM参数A和参数iv的预处理标记位；
 * 其他：正常的AES计算；
 * 注意：当A和iv的长度大于128bit是需要进行预处理。
 */
#define HI_SEC_DRV_TASK_FLAG_AES_XCM_IV_PRE     0x40    /* 2’b10：表示当前AES是对参数iv的预处理；*/
#define HI_SEC_DRV_TASK_FLAG_AES_XCM_A_PRE      0x20    /* 2’b01：表示当前AES是对参数A的预处理； */

/*
 * task_flag [4]: AES_GCM/CCM参数A的标记；
 *  1’b1：表示Yi，即参数A预处理后的结果；
 *  1’b0：表示原始的参数A；
 */
#define HI_SEC_DRV_TASK_FLAG_AES_XCM_A_RSLT     0x10

/*
 * task_flag [3]: AES_GCM参数iv的标记；
 *  1’b1：表示Ji，即参数iv预处理后的结果；
 *  1’b0：表示原始的参数iv；
 */
#define HI_SEC_DRV_TASK_FLAG_AES_XCM_IV_RSLT    0x08

/* task_flag[2]：加解密标记，1'b1:表示加密；  1'b0:表示解密； */
#define HI_SEC_DRV_TASK_FLAG_ENCRYPTO           0x04
#define HI_SEC_DRV_TASK_FLAG_DECRYPTO           0x00

/* task_flag[1]：AES认证结果和预处理标记； */
/*
 * 在AES_CCM/GCM的参数A/iv以及 AES_XCBC的key预处理时表示结果是否回写；
 *   1'b1:表示回写预处理的结果；
 *   1'b0:表示不回写预处理结果。
 */
#define HI_SEC_DRV_TASK_FLAG_AES_XCM_XCBC_PRE_REWR  0x02

/*
 * AESCCM/GCM正常计算时TAG回写标记
 *  1'b1:表示回写TAG；
 *  1'b0:表示读取TAG进行校验。
 */
#define HI_SEC_DRV_TASK_FLAG_AES_XCM_TAG_REWR       0x02

/*
 * task_flag[0]：认证信息的处理标记；
 *  1'b1:表示回写认证结果；
 *  1'b0:表示校验认证结果。
 */
#define HI_SEC_DRV_TASK_FLAG_AUTH_REWR  0x01

#define HI_SEC_DRV_CALLBACK_DATALEN 128
#define HI_SEC_DRV_MAX_BD_DATALEN   2000
#define HI_SEC_BD_LEN               1024

enum hi_sec_drv_task_e {
	HI_SEC_DRV_TASK_AUTH_ENC_E = 0,  /* 认证+加密 */
	HI_SEC_DRV_TASK_AUTH_DEC_E,      /* 认证+解密 */
	HI_SEC_DRV_TASK_ENC_AUTH_E,      /* 加密+认证 */
	HI_SEC_DRV_TASK_DEC_AUTH_E,      /* 解密+认证 */
	HI_SEC_DRV_TASK_AUTH_E,          /* 认证 */
	HI_SEC_DRV_TASK_ENC_E,           /* 加密 */
	HI_SEC_DRV_TASK_DEC_E,           /* 解密 */
	HI_SEC_DRV_TASK_RAND_E,          /* 随机数获取 */
};

enum hi_sec_drv_k_source_e {
	HI_SEC_DRV_K_SRC_BD_E = 0,  /* 秘钥来自于BD；*/
	HI_SEC_DRV_K_SRC_KDF_E,     /* 秘钥来自于KDF；*/
	HI_SEC_DRV_K_SRC_EFUSE1_E,  /* 秘钥来自于efuse1 用于OS处理；*/
	HI_SEC_DRV_K_SRC_EFUSE2_E,  /* 秘钥来自于efuse2 用于flash存储的处理；*/
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
 * 注意：当AES_XCBC的秘钥KEY长度大于128bit时，
 * 需要对KEY进行预处理，将得到的结果作为最终的KEY。
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
		 * BD的配置告警信息，各个bit的值：'1'表示有告警，'0'表示无告警；
		 * bit[0]=1'b1: 表示SM3的efuse有效，但是配置了SM3算法；
		 * bit[1]=1'b1: 表示SM4的efuse有效，但是配置了SM4算法；
		 * bit[2]=1'b1: 表示BD中秘钥信息域有异常配置；
		 * bit[3]=1'b1: 表示BD中报文信息域有异常配置；
		 * bit[7:4]：保留，保留值为0。
		 */
		hi_ulong64 bd_alarm: 8;

		/*
		 * 单位：字节； 表示当前BD回写DDR时加解密结果的有效长度；
		 * 注意：在LINK_BD模式下加解密结果可能不等于当前BD报文的长度，但结果的总长度是相等的。
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

		/* 单位：字节；表示hash认证结果的长度，即表示ICVIN的长度，也表示ICVOUT的长度，因为他们的长度相等。 */
		hi_ulong64 icv_len: 8;

		/* 单位：字节；表示AES_CCM和AES_GCM模式下TAG的长度。 */
		hi_ulong64 tag_len: 8;

		/*
		 * 单位：字节； 该字段是复合字段，各场景表示如下信息：
		 * 1、在AES_CCM模式下，表示参数“N”的长度；
		 * 2、在AES_XTS模式下，表示参数“i”的长度；
		 * 3、在AES_GCM模式下表示预处理后的iv的长度，或者在原始iv长度不超过128bit时的原始iv长度值；
		 * 4、其他情况下，表示各个加解密算法的IV长度，
		 */
		hi_ulong64 civ_len: 8;

		/*
		 * 单位：字节； 该字段表示加解密秘钥的长度（AES的XTS模式下使用了两个秘钥，长度都相同；
		 * TDES算法时表示三个秘钥的总长，且三个秘钥的长度相等）。
		 * 8’d8：秘钥长度为 64bit；
		 * 8’d16：秘钥长度为128bit；
		 * 8’d24：秘钥长度为192bit；
		 * 8’d32：秘钥长度为256bit；
		 * 其他 ：DES/TDES默认取8’d8，AES/SM4默认取8’d16。
		 */
		hi_ulong64 ckey_len: 8;

		/*
		 * 单位：字节； 该字段表示待加解密数据或申请AEX_XCBC随机数的长度。
		 * 在AES_GCM/CCM的参数A和参数iv的预处理时，表示当前BD的A或iv的长度；
		 * 在AES_XCBC的秘钥key的预处理时，表示当前BD的key的长度；
		 */
		hi_ulong64 cdata_len: 12;

		/* 单位：字节； 该字段表示认证数据的长度。 */
		hi_ulong64 adata_len: 12;

		/* 单位：字节； 该字段表示认证算法的秘钥长度。 */
		hi_ulong64 akey_len: 8;
	} bits;

	hi_uint32 ta_len;            /* 单位：字节；表示AES_CCM/GCM模式下参数A的总长度。*/
	hi_uint32 tcdata_len;        /* 单位：字节；表示AES_CCM/GCM模式下报文的总长度。 */
	hi_uint32 cipher_rslt_addr;  /* 回写加解密结果时的DDR首地址。 */
	hi_uint32 tiv_len;           /* 单位：字节；表示AES_ GCM模式下参数iv的总长度。  */

	/*
	 * 待加解密数据的首地址。AES_CCM/GCM预处理是的参数A和iv，
	 * 以及AES_XCBC在预处理key时，请使用该地址来配置。
	 */
	hi_uint32 cipher_data_addr;

	hi_uint32 auth_data_addr;    /* 待认证数据的首地址。 */

	/*
	 * AES_CCM或AES_GCM的认证结果“TAG”在DDR中的首地址。
	 * 如果SEC为源端：表示TAG回写首地址；
	 * 如果SEC为目的端：表示待校验TAG的首地址，逻辑从该地址去读TAG。
	 */
	hi_uint32 cipher_tag_addr;

	/*
	 * 如果task带有认证任务，不同的task_flag[0]的值该地址表示不同的意义：
	 * task_flag[0]=1'b1时，该地址表示认证结果的回写首地址；
	 * task_flag[0]=1'b0时，表示待校验的认证值的首地址，逻辑从该地址读回ICV，然后与逻辑内部的计算的ICV比较
	 */
	hi_uint32 auth_icv_addr;

	hi_uint32 cipher_key1_addr;  /* 加解密算法的秘钥存放在DDR中的首地址。 */
	hi_uint32 auth_key_addr;     /* 认证算法使用的秘钥的首地址。 */

	union {

		/*
		 * 表示各个加解密算法的IV的首地址；
		 * 注意：在AES_GCM模式下的iv可能是预处理后的iv值，或者在原始iv长度不大于128bit时的原始iv值。
		 */
		hi_uint32 cipher_iv_addr;

		/* 在AES_CCM模式下，表示参数“N”的首地址；*/
		hi_uint32 cipher_n_addr;

		/* 在AES_XTS模式下，表示参数“i”的首地址； */
		hi_uint32 cipher_i_addr;
	};

	union {

		/*
		 * AES_CCM或AES_GCM的参数A在DDR中的首地址。
		 * 注意：当参数A的长度小于等于128bit时，或者此时的A为预处理后的A时，才使用该地址来读取参数A；
		 * 对参数A的预处理操作时请使用Cipher_data_addr。
		 */
		hi_uint32 cipher_a_addr;

		/* AES的XTS模式下使用到的第二个KEY存放在DDR中的首地址。 */
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
	hi_ulong64 qrx;      /* 正常接收中断 */
	hi_ulong64 timeout;  /* 超时接收中断 */
};

struct hi_sec_drv_data_sta_s {
	hi_ulong64 input;    /* 输入数据BD统计 */
	hi_ulong64 output;   /* 输出数据BD统计 */
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
