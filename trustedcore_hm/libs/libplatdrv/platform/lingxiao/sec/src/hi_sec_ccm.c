/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2014-2019. All rights reserved.
 * Description: ASE CCM算法
 * Author: o00302765
 * Create: 2019-10-22
 */

#include <hisilicon/chip/level_2/hi_sdk_l2.h>

#include "hi_sec_common.h"
#include "hi_sec_drv.h"
#include "hi_sec_aes.h"
#include "hi_sec_hash.h"
#include "hi_sec_api.h"

//static hi_uchar8 g_xcm_a[HI_SEC_AES_BLOCK_SIZE];
//static hi_uchar8 g_xcm_pre_iv[HI_SEC_IV_SIZE];
//static hi_uchar8 g_xcm_tag[HI_SHA512_DIGEST_SIZE];
static hi_uchar8 *g_xcm_a = HI_NULL;
static hi_uchar8 *g_xcm_pre_iv = HI_NULL;
static hi_uchar8 *g_xcm_tag = HI_NULL;

static hi_int32 hi_sec_xcm_dma_malloc(hi_void)
{
	g_xcm_a = hi_sec_dma_malloc(HI_SEC_AES_BLOCK_SIZE);
	if (g_xcm_a == HI_NULL) {
		hi_secdrv_systrace(HI_RET_MALLOC_FAIL, 0, 0, 0, 0);
		return HI_RET_MALLOC_FAIL;
	}

	g_xcm_pre_iv = hi_sec_dma_malloc(HI_SEC_IV_SIZE);
	if (g_xcm_pre_iv == HI_NULL) {
		hi_sec_dma_free(g_xcm_a);
		hi_secdrv_systrace(HI_RET_MALLOC_FAIL, 0, 0, 0, 0);
		return HI_RET_MALLOC_FAIL;
	}

	g_xcm_tag = hi_sec_dma_malloc(HI_SHA512_DIGEST_SIZE);
	if (g_xcm_tag == HI_NULL) {
		hi_sec_dma_free(g_xcm_a);
		hi_sec_dma_free(g_xcm_pre_iv);
		hi_secdrv_systrace(HI_RET_MALLOC_FAIL, 0, 0, 0, 0);
		return HI_RET_MALLOC_FAIL;	
	}

	return HI_RET_SUCC;
}

static hi_void hi_sec_xcm_dma_free(hi_void)
{
	hi_sec_dma_free(g_xcm_a);
	hi_sec_dma_free(g_xcm_pre_iv);
	hi_sec_dma_free(g_xcm_tag);
	g_xcm_a = HI_NULL;
	g_xcm_pre_iv = HI_NULL;
	g_xcm_tag = HI_NULL;
}

/* 认证数据预处理 */
static hi_int32 hi_sec_auth_pre(struct hi_sec_aes_xcm_req *req,
				hi_uint32 pre_ivlen,
				hi_uint32 cipher,
				hi_uint32 encrypt)
{
	struct hi_sec_bd_desc_s desc;
	hi_uint32 datalen = req->src_len;
	hi_int32 ret;

	/* 认证数据长度超出最大处理能力 */
	if (req->auth_len > HI_SEC_DRV_MAX_BD_DATALEN * HI_SEC_BD_LEN) {
		hi_secdrv_systrace(HI_RET_INVALID_PARA, 0, 0, 0, 0);
		return HI_RET_INVALID_PARA;
	}
	/* 认证数据大于一个BLOCK的，要预处理 */
	if (req->auth_len <= HI_SEC_AES_BLOCK_SIZE) {
		hi_memcpy(g_xcm_a, req->auth, req->auth_len);
		hi_secdrv_systrace(HI_RET_SUCC, 0, 0, 0, 0);
		return HI_RET_SUCC;
	}

	if (encrypt == HI_SEC_DRV_TASK_FLAG_DECRYPTO)
		datalen -= req->auth_tag_size;

	hi_memset(&desc, 0, sizeof(desc));
	desc.bits.encrypt = cipher;
	desc.bits.task = (encrypt == HI_SEC_DRV_TASK_FLAG_ENCRYPTO ? HI_SEC_DRV_TASK_ENC_E : HI_SEC_DRV_TASK_DEC_E);
	desc.bits.task_flag = encrypt | HI_SEC_DRV_TASK_FLAG_AES_XCM_A_PRE | HI_SEC_DRV_TASK_FLAG_AES_XCM_XCBC_PRE_REWR;
	desc.bits.civ_len = pre_ivlen;
	desc.bits.sec_flag = HI_SEC_DRV_SEC_FLAG_BIG_ENDIAN;
	desc.bits.cdata_len = req->src_len;
	desc.bits.tag_len = req->auth_tag_size;
	desc.bits.ckey_len = req->key_len;
	desc.cipher_data_addr = hi_sec_get_phyaddr(req->auth, req->auth_len, HI_DMA_TO_DEVICE);
	desc.cipher_tag_addr = hi_sec_get_phyaddr(g_xcm_a, sizeof(g_xcm_a), HI_DMA_FROM_DEVICE);
	desc.cipher_n_addr = hi_sec_get_phyaddr(g_xcm_pre_iv, pre_ivlen, HI_DMA_TO_DEVICE);
	desc.ta_len = req->auth_tag_size;
	desc.tiv_len = pre_ivlen;
	desc.tcdata_len = datalen;

	if (cipher == HI_SEC_DRV_CIPHER_AES_GCM_E) {
		desc.bits.civ_len = 16;
		desc.cipher_n_addr = desc.cipher_tag_addr;
	}

	if (req->key_src == HI_SEC_KEY_SRC_KDF) {
		desc.bits.k_source = HI_SEC_DRV_K_SRC_KDF_E;
	} else if (req->key_src == HI_SEC_KEY_SRC_HUK) {
		desc.bits.k_source = HI_SEC_DRV_K_SRC_EFUSE2_E;
	} else {
		desc.bits.k_source = HI_SEC_DRV_K_SRC_BD_E;
		desc.cipher_key1_addr = hi_sec_get_phyaddr(req->key, req->key_len, HI_DMA_TO_DEVICE);
	}

	ret = hi_sec_aes_bd_fragment(&desc);

	hi_sec_release_phyaddr(desc.cipher_data_addr, req->auth_len, HI_DMA_TO_DEVICE);
	hi_sec_release_phyaddr(desc.cipher_tag_addr, sizeof(g_xcm_a), HI_DMA_FROM_DEVICE);
	hi_sec_release_phyaddr(desc.cipher_n_addr, pre_ivlen, HI_DMA_TO_DEVICE);

	if (req->key_src != HI_SEC_KEY_SRC_KDF && req->key_src != HI_SEC_KEY_SRC_HUK)
		hi_sec_release_phyaddr(desc.cipher_key1_addr, req->key_len, HI_DMA_TO_DEVICE);

	hi_secdrv_systrace(ret, 0, 0, 0, 0);
	return ret;
}

/* CCM/GCM 描述符填写 */
static hi_int32 hi_sec_xcm(struct hi_sec_aes_xcm_req *req,
			   hi_uint32 pre_ivlen,
			   hi_uint32 cipher,
			   hi_uint32 encrypt)
{
	struct hi_sec_bd_desc_s desc;
	hi_uint32 task;
	hi_uint32 taskflag = 0;
	hi_uint32 tag_dir;
	hi_int32 ret;

	if (encrypt == HI_SEC_DRV_TASK_FLAG_ENCRYPTO) {
		task = HI_SEC_DRV_TASK_ENC_E;
		taskflag = HI_SEC_DRV_TASK_FLAG_AES_XCM_XCBC_PRE_REWR;
		tag_dir = HI_DMA_FROM_DEVICE;
	} else {
		task = HI_SEC_DRV_TASK_DEC_E;
		tag_dir = HI_DMA_TO_DEVICE;

		/* 解密时, 认证数据在密文尾部 */
		hi_memcpy(g_xcm_tag, (req->src + req->src_len), req->auth_tag_size);
	}

	if (req->auth_len > HI_SEC_AES_BLOCK_SIZE)
		taskflag |= HI_SEC_DRV_TASK_FLAG_AES_XCM_A_RSLT;

	if (req->iv_len > HI_SEC_IV_SIZE)
		taskflag |= HI_SEC_DRV_TASK_FLAG_AES_XCM_IV_RSLT;

	hi_memset(&desc, 0, sizeof(desc));
	desc.bits.encrypt = cipher;
	desc.bits.task = task;
	desc.bits.task_flag = taskflag;
	desc.bits.task_flag |= encrypt;
	desc.bits.civ_len = pre_ivlen;
	desc.bits.tag_len = req->auth_tag_size;
	desc.bits.sec_flag = HI_SEC_DRV_SEC_FLAG_BIG_ENDIAN;
	desc.bits.cdata_len = req->src_len;
	desc.bits.ckey_len = req->key_len;
	desc.cipher_data_addr = hi_sec_get_phyaddr(req->src, req->src_len, HI_DMA_TO_DEVICE);
	desc.cipher_rslt_addr = hi_sec_get_phyaddr(req->dst, req->dst_len, HI_DMA_FROM_DEVICE);
	desc.cipher_iv_addr = hi_sec_get_phyaddr(g_xcm_pre_iv, pre_ivlen, HI_DMA_TO_DEVICE);
	desc.cipher_a_addr = hi_sec_get_phyaddr(g_xcm_a, sizeof(g_xcm_a), HI_DMA_TO_DEVICE);
	desc.cipher_tag_addr = hi_sec_get_phyaddr(g_xcm_tag, sizeof(g_xcm_tag), tag_dir);
	desc.ta_len = req->auth_len;
	desc.tiv_len = (req->iv_len > HI_SEC_IV_SIZE ? req->iv_len : pre_ivlen);
	desc.tcdata_len = req->src_len;

	if (req->key_src == HI_SEC_KEY_SRC_KDF) {
		desc.bits.k_source = HI_SEC_DRV_K_SRC_KDF_E;
	} else if (req->key_src == HI_SEC_KEY_SRC_HUK) {
		desc.bits.k_source = HI_SEC_DRV_K_SRC_EFUSE2_E;
	} else {
		desc.bits.k_source = HI_SEC_DRV_K_SRC_BD_E;
		desc.cipher_key1_addr = hi_sec_get_phyaddr(req->key, req->key_len, HI_DMA_TO_DEVICE);
	}

	ret = hi_sec_aes_bd_fragment(&desc);

	hi_sec_release_phyaddr(desc.cipher_data_addr, req->src_len, HI_DMA_TO_DEVICE);
	hi_sec_release_phyaddr(desc.cipher_rslt_addr, req->dst_len, HI_DMA_FROM_DEVICE);
	hi_sec_release_phyaddr(desc.cipher_iv_addr, pre_ivlen, HI_DMA_TO_DEVICE);
	hi_sec_release_phyaddr(desc.cipher_a_addr, sizeof(g_xcm_a), HI_DMA_TO_DEVICE);
	hi_sec_release_phyaddr(desc.cipher_tag_addr, sizeof(g_xcm_tag), tag_dir);

	if (req->key_src != HI_SEC_KEY_SRC_KDF && req->key_src != HI_SEC_KEY_SRC_HUK)
		hi_sec_release_phyaddr(desc.cipher_key1_addr, req->key_len, HI_DMA_TO_DEVICE);

	if (ret != HI_RET_SUCC) {
		hi_secdrv_systrace(ret, 0, 0, 0, 0);
		return ret;
	}
	/* 加密时, 要把认证数据放在密文末尾 */
	if (encrypt == HI_SEC_DRV_TASK_FLAG_ENCRYPTO)
		hi_memcpy((req->dst + req->dst_len), g_xcm_tag, req->auth_tag_size);

	hi_secdrv_systrace(ret, 0, 0, 0, 0);
	return HI_RET_SUCC;
}

static hi_int32 hi_sec_ccm(struct hi_sec_aes_xcm_req *req, hi_uint32 encrypt)
{
	hi_uint32 iv_len;
	hi_int32 ret;

	if (req == HI_NULL)
		return HI_RET_NULLPTR;

	iv_len = req->iv_len;

	if (iv_len < HI_SEC_AES_XCM_MIN_NONCE_LEN) {
		hi_secdrv_systrace(HI_RET_FAIL, iv_len, 0, 0, 0);
		return HI_RET_FAIL;
	}
	if (iv_len > HI_SEC_AES_XCM_MAX_NONCE_LEN)
		iv_len = HI_SEC_AES_XCM_MAX_NONCE_LEN;

	ret = hi_sec_xcm_dma_malloc();
	if (ret) {
		hi_secdrv_systrace(ret, 0, 0, 0, 0);
		return ret;
	}
	hi_memcpy(g_xcm_pre_iv, req->iv, iv_len);

	ret = hi_sec_auth_pre(req, iv_len, HI_SEC_DRV_CIPHER_AES_CCM_E, encrypt);
	if (ret != HI_RET_SUCC) {
		hi_sec_xcm_dma_free();
		hi_secdrv_systrace(ret, 0, 0, 0, 0);
		return ret;
	}

	ret = hi_sec_xcm(req, iv_len, HI_SEC_DRV_CIPHER_AES_CCM_E, encrypt);

	hi_sec_xcm_dma_free();
	hi_secdrv_systrace(ret, 0, 0, 0, 0);
	return ret;
}

hi_int32 hi_sec_ccm_encrypt(struct hi_sec_aes_xcm_req *req)
{
	return hi_sec_ccm(req, HI_SEC_DRV_TASK_FLAG_ENCRYPTO);
}

hi_int32 hi_sec_ccm_decrypt(struct hi_sec_aes_xcm_req *req)
{
	return hi_sec_ccm(req, HI_SEC_DRV_TASK_FLAG_DECRYPTO);
}

static hi_int32 hi_sec_gcm_iv_pre(struct hi_sec_aes_xcm_req *req, hi_uint32 encrypt, hi_uint32 *pre_ivlen)
{
	struct hi_sec_bd_desc_s desc;
	hi_uint32 iv_len = req->iv_len;
	hi_uint32 task;
	hi_int32 ret;

	if (iv_len <= HI_SEC_IV_SIZE) {
		if (iv_len > HI_SEC_AES_GCM_MAX_IV_LEN) {
			iv_len = HI_SEC_AES_GCM_MAX_IV_LEN;
			*pre_ivlen = HI_SEC_AES_GCM_MAX_IV_LEN;
		}

		hi_memcpy(g_xcm_pre_iv, req->iv, iv_len);
		return HI_RET_SUCC;
	}

	if (encrypt == HI_SEC_DRV_TASK_FLAG_ENCRYPTO)
		task = HI_SEC_DRV_TASK_ENC_E;
	else
		task = HI_SEC_DRV_TASK_DEC_E;

	hi_memset(&desc, 0, sizeof(desc));
	desc.bits.encrypt = HI_SEC_DRV_CIPHER_AES_GCM_E;
	desc.bits.task = task;
	desc.bits.task_flag = encrypt | HI_SEC_DRV_TASK_FLAG_AES_XCM_IV_PRE | HI_SEC_DRV_TASK_FLAG_AES_XCM_XCBC_PRE_REWR;
	desc.bits.sec_flag = HI_SEC_DRV_SEC_FLAG_BIG_ENDIAN;
	desc.bits.cdata_len = iv_len;
	desc.bits.ckey_len = req->key_len;
	desc.bits.bd_flag = 0;
	desc.bits.civ_len = HI_SEC_IV_SIZE;
	desc.bits.tag_len = req->auth_tag_size;
	desc.cipher_data_addr = hi_sec_get_phyaddr(req->iv, iv_len, HI_DMA_TO_DEVICE);
	desc.cipher_tag_addr = hi_sec_get_phyaddr(g_xcm_pre_iv, sizeof(g_xcm_pre_iv), HI_DMA_FROM_DEVICE);
	desc.cipher_iv_addr = desc.cipher_tag_addr;
	desc.ta_len = req->auth_len;
	desc.tiv_len = iv_len;
	desc.tcdata_len = req->src_len;

	if (req->key_src == HI_SEC_KEY_SRC_KDF) {
		desc.bits.k_source = HI_SEC_DRV_K_SRC_KDF_E;
	} else if (req->key_src == HI_SEC_KEY_SRC_HUK) {
		desc.bits.k_source = HI_SEC_DRV_K_SRC_EFUSE2_E;
	} else {
		desc.bits.k_source = HI_SEC_DRV_K_SRC_BD_E;
		desc.cipher_key1_addr = hi_sec_get_phyaddr(req->key, req->key_len, HI_DMA_TO_DEVICE);
	}

	ret = hi_sec_aes_bd_fragment(&desc);

	hi_sec_release_phyaddr(desc.cipher_data_addr, iv_len, HI_DMA_TO_DEVICE);
	hi_sec_release_phyaddr(desc.cipher_tag_addr, sizeof(g_xcm_pre_iv), HI_DMA_FROM_DEVICE);

	if (req->key_src != HI_SEC_KEY_SRC_KDF && req->key_src != HI_SEC_KEY_SRC_HUK)
		hi_sec_release_phyaddr(desc.cipher_key1_addr, req->key_len, HI_DMA_TO_DEVICE);

	*pre_ivlen = HI_SEC_IV_SIZE;
	hi_secdrv_systrace(ret, iv_len, 0, 0, 0);
	return ret;
}

static hi_int32 hi_sec_gcm(struct hi_sec_aes_xcm_req *req, hi_uint32 encrypt)
{
	hi_uint32 pre_ivlen;
	hi_int32 ret;

	if (req == HI_NULL)
		return HI_RET_NULLPTR;

	ret = hi_sec_xcm_dma_malloc();
	if (ret) {
		hi_secdrv_systrace(ret, 0, 0, 0, 0);
		return ret;
	}

	ret = hi_sec_gcm_iv_pre(req, HI_SEC_DRV_TASK_FLAG_ENCRYPTO, &pre_ivlen);
	if (ret != HI_RET_SUCC) {
		hi_sec_xcm_dma_free();
		hi_secdrv_systrace(ret, req->iv_len, 0, 0, 0);
		return ret;
	}
	ret = hi_sec_auth_pre(req, pre_ivlen, 
		HI_SEC_DRV_CIPHER_AES_GCM_E, HI_SEC_DRV_TASK_FLAG_ENCRYPTO);
	if (ret != HI_RET_SUCC) {
		hi_sec_xcm_dma_free();
		hi_secdrv_systrace(ret, req->iv_len, 0, 0, 0);
		return ret;
	}

	ret = hi_sec_xcm(req, pre_ivlen, HI_SEC_DRV_CIPHER_AES_GCM_E, encrypt);

	hi_sec_xcm_dma_free();
	hi_secdrv_systrace(ret, 0, 0, 0, 0);
	return ret;
}

hi_int32 hi_sec_gcm_encrypt(struct hi_sec_aes_xcm_req *req)
{
	return hi_sec_gcm(req, HI_SEC_DRV_TASK_FLAG_ENCRYPTO);
}

hi_int32 hi_sec_gcm_decrypt(struct hi_sec_aes_xcm_req *req)
{
	return hi_sec_gcm(req, HI_SEC_DRV_TASK_FLAG_DECRYPTO);
}