/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2014-2019. All rights reserved.
 * Description: ASE CBC/CTR/XTS算法
 * Author: o00302765
 * Create: 2019-10-22
 */

#include <hisilicon/chip/level_2/hi_sdk_l2.h>

#include "hi_sec_common.h"
#include "hi_sec_drv.h"
#include "hi_sec_aes.h"
#include "hi_sec_api.h"

/* BD分片 */
hi_int32 hi_sec_aes_bd_fragment(struct hi_sec_bd_desc_s *origin)
{
	struct hi_sec_bd_desc_s *desc;
	struct hi_sec_bd_desc_s *descs;
	hi_uint32 len = origin->bits.cdata_len;
	hi_uint32 addr_offset;
	hi_uint32 cnt;
	hi_uint32 size;
	hi_uint32 index;
	hi_int32 ret;

	if (len > HI_SEC_DRV_MAX_BD_DATALEN) {

		cnt = len / HI_SEC_DRV_MAX_BD_DATALEN;
		size = cnt;
		if (len % HI_SEC_DRV_MAX_BD_DATALEN > 0)
			size++;

		descs = hi_malloc(sizeof(*desc) * size);
		if (descs == HI_NULL) {
			hi_secdrv_systrace(HI_RET_MALLOC_FAIL, 0, 0, 0, 0);
			return HI_RET_MALLOC_FAIL;
		}

		/* 分片写入 */
		for (index = 0, addr_offset = 0, desc = descs;
		     index < cnt;
		     index++, desc++, addr_offset += HI_SEC_DRV_MAX_BD_DATALEN) {

			hi_memcpy(desc, origin, sizeof(*origin));
			desc->bits.cdata_len = HI_SEC_DRV_MAX_BD_DATALEN;
			desc->cipher_data_addr = origin->cipher_data_addr + addr_offset;
			desc->cipher_rslt_addr = origin->cipher_rslt_addr + addr_offset;

			if (index == 0) {
				desc->bits.bd_flag = HI_SEC_DRV_BD_FLAG_LINK_START;
				desc->bits.sec_flag = (desc->bits.sec_flag |
						       HI_SEC_DRV_SEC_FLAG_CRYPTO_BODY);
			} else if ((index == cnt - 1) && (len % HI_SEC_DRV_MAX_BD_DATALEN == 0)) {
				/* 尾片正好是2k */
				desc->bits.bd_flag = HI_SEC_DRV_BD_FLAG_LINK_END;
				desc->bits.sec_flag = (desc->bits.sec_flag |
						       HI_SEC_DRV_SEC_FLAG_CRYPTO_TAIL);
			} else {
				desc->bits.bd_flag = HI_SEC_DRV_BD_FLAG_LINK_BODY;
				desc->bits.sec_flag = (desc->bits.sec_flag |
						       HI_SEC_DRV_SEC_FLAG_CRYPTO_BODY);
			}
		}

		/* 尾片不足2k */
		if (len % HI_SEC_DRV_MAX_BD_DATALEN > 0) {
			desc->bits.cdata_len = len - (cnt * HI_SEC_DRV_MAX_BD_DATALEN);
			desc->bits.bd_flag = HI_SEC_DRV_BD_FLAG_LINK_END;
			desc->bits.sec_flag = (desc->bits.sec_flag |
					      HI_SEC_DRV_SEC_FLAG_CRYPTO_TAIL);
			desc->cipher_data_addr = origin->cipher_data_addr + addr_offset;
			desc->cipher_rslt_addr = origin->cipher_rslt_addr + addr_offset;
		}

		ret = hi_sec_bd_proc(descs, size);
		if (ret != HI_RET_SUCC)
			hi_secdrv_systrace(ret, 0, 0, 0, 0);

		hi_free(desc);
	} else {
		origin->bits.sec_flag = (origin->bits.sec_flag | HI_SEC_DRV_SEC_FLAG_CRYPTO_TAIL);
		ret = hi_sec_bd_proc(origin, 1);
		if (ret != HI_RET_SUCC)
			hi_secdrv_systrace(ret, 0, 0, 0, 0);
	}

	hi_secdrv_systrace(ret, 0, 0, 0, 0);
	return ret;
}

/* 填写AES BD */
static hi_int32 hi_sec_aes_bd(struct hi_sec_aes_cipher_req *req, hi_uint32 encrypt)
{
	struct hi_sec_bd_desc_s desc;
	hi_uint32 taskflag;
	hi_uint32 ckeylen = req->key_len;
	hi_int32 ret;

	if (encrypt == HI_SEC_DRV_TASK_ENC_E)
		taskflag = HI_SEC_DRV_TASK_FLAG_ENCRYPTO;
	else
		taskflag = HI_SEC_DRV_TASK_FLAG_DECRYPTO;

	if (req->cipher == HI_SEC_CIPHER_AES_XTS_E)
		ckeylen = req->key_len / 2;

	hi_memset(&desc, 0, sizeof(desc));
	desc.bits.encrypt = req->cipher;
	desc.bits.task = encrypt;
	desc.bits.task_flag = taskflag;
	desc.bits.civ_len = req->iv_len;
	desc.bits.sec_flag = HI_SEC_DRV_SEC_FLAG_BIG_ENDIAN;
	desc.bits.cdata_len = req->src_len;
	desc.bits.ckey_len = ckeylen;
	desc.cipher_data_addr = hi_sec_get_phyaddr(req->src, req->src_len, HI_DMA_TO_DEVICE);
	desc.cipher_rslt_addr = hi_sec_get_phyaddr(req->dst, req->dst_len, HI_DMA_FROM_DEVICE);
	desc.cipher_iv_addr = hi_sec_get_phyaddr(req->iv, req->iv_len, HI_DMA_TO_DEVICE);

	if (req->key_src == HI_SEC_KEY_SRC_KDF) {
		desc.bits.k_source = HI_SEC_DRV_K_SRC_KDF_E;
	} else if (req->key_src == HI_SEC_KEY_SRC_HUK) {
		desc.bits.k_source = HI_SEC_DRV_K_SRC_EFUSE2_E;
	} else {
		desc.bits.k_source = HI_SEC_DRV_K_SRC_BD_E;
		desc.cipher_key1_addr = hi_sec_get_phyaddr(req->key, req->key_len, HI_DMA_TO_DEVICE);
		desc.cipher_key2_addr = desc.cipher_key1_addr + ckeylen;
	}

	ret = hi_sec_aes_bd_fragment(&desc);

	hi_sec_release_phyaddr(desc.cipher_data_addr, req->src_len, HI_DMA_TO_DEVICE);
	hi_sec_release_phyaddr(desc.cipher_rslt_addr, req->dst_len, HI_DMA_FROM_DEVICE);
	hi_sec_release_phyaddr(desc.cipher_iv_addr, req->iv_len, HI_DMA_TO_DEVICE);

	if (req->key_src != HI_SEC_KEY_SRC_KDF && req->key_src != HI_SEC_KEY_SRC_HUK)
		hi_sec_release_phyaddr(desc.cipher_key1_addr, req->key_len, HI_DMA_TO_DEVICE);

	hi_secdrv_systrace(ret, 0, 0, 0, 0);
	return ret;
}

static hi_int32 hi_sec_aes(struct hi_sec_aes_cipher_req *req, hi_uint32 encrypt)
{
	if (req == HI_NULL)
		return HI_RET_NULLPTR;

	if (req->cipher != HI_SEC_CIPHER_AES_ECB_E &&
	    req->cipher != HI_SEC_CIPHER_AES_CBC_E &&
	    req->cipher != HI_SEC_CIPHER_AES_XTS_E &&
	    req->cipher != HI_SEC_CIPHER_AES_CTR_E) {
	    hi_secdrv_systrace(HI_RET_INVALID_PARA, req->cipher, 0, 0, 0);
	    return HI_RET_INVALID_PARA;
	}

	return hi_sec_aes_bd(req, encrypt);
}

hi_int32 hi_sec_aes_encrypt(struct hi_sec_aes_cipher_req *req)
{
	return hi_sec_aes(req, HI_SEC_DRV_TASK_ENC_E);
}

hi_int32 hi_sec_aes_decrypt(struct hi_sec_aes_cipher_req *req)
{
	return hi_sec_aes(req, HI_SEC_DRV_TASK_DEC_E);
}

