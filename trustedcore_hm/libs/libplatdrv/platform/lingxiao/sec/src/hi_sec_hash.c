/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2014-2019. All rights reserved.
 * Description: HSAH算法
 * Author: o00302765
 * Create: 2019-10-22
 */

#include <hisilicon/chip/level_2/hi_sdk_l2.h>

#include "hi_sec_common.h"
#include "hi_sec_drv.h"
#include "hi_sec_hash.h"
#include "hi_sec_api.h"

static hi_uchar8 *g_hmac_prekey = HI_NULL;

static hi_int32 hi_sec_hash_bd_fragment(struct hi_sec_bd_desc_s *origin)
{
	struct hi_sec_bd_desc_s *desc;
	struct hi_sec_bd_desc_s *descs;
	hi_uint32 len = origin->bits.adata_len;
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
			hi_secdrv_systrace(HI_RET_MALLOC_FAIL, size, 0, 0, 0);
			return HI_RET_MALLOC_FAIL;
		}

		/* 分片写入 */
		for (index = 0, addr_offset = 0, desc = descs;
		     index < cnt;
		     index++, desc++, addr_offset += HI_SEC_DRV_MAX_BD_DATALEN) {

			hi_memcpy(desc, origin, sizeof(*origin));
			desc->bits.adata_len = HI_SEC_DRV_MAX_BD_DATALEN;
			desc->auth_data_addr = origin->auth_data_addr + addr_offset;

			if (index == 0) {
				desc->bits.bd_flag = HI_SEC_DRV_BD_FLAG_LINK_START;
				desc->bits.sec_flag = (desc->bits.sec_flag |
						       HI_SEC_DRV_SEC_FLAG_HASH_BODY);
			} else if ((index == cnt - 1) && (len % HI_SEC_DRV_MAX_BD_DATALEN == 0)) {
				/* 尾片正好是2k */
				desc->bits.bd_flag = HI_SEC_DRV_BD_FLAG_LINK_END;
				desc->bits.sec_flag = (desc->bits.sec_flag |
						       HI_SEC_DRV_SEC_FLAG_HASH_TAIL);
			} else {
				desc->bits.bd_flag = HI_SEC_DRV_BD_FLAG_LINK_BODY;
				desc->bits.sec_flag = (desc->bits.sec_flag |
						       HI_SEC_DRV_SEC_FLAG_HASH_BODY);
			}
		}

		/* 尾片不足2k */
		if (len % HI_SEC_DRV_MAX_BD_DATALEN > 0) {
			desc->bits.adata_len = len - (cnt * HI_SEC_DRV_MAX_BD_DATALEN);
			desc->bits.bd_flag = HI_SEC_DRV_BD_FLAG_LINK_END;
			desc->bits.sec_flag = (desc->bits.sec_flag |
					      HI_SEC_DRV_SEC_FLAG_HASH_TAIL);
			desc->auth_data_addr = origin->auth_data_addr + addr_offset;
		}

		ret = hi_sec_bd_proc(descs, size);
		hi_free(desc);
	} else {
		origin->bits.sec_flag = (origin->bits.sec_flag | HI_SEC_DRV_SEC_FLAG_HASH_TAIL);
		ret = hi_sec_bd_proc(origin, 1);
	}

	hi_secdrv_systrace(ret, len, 0, 0, 0);
	return ret;
}

static hi_int32 hi_sec_hash_bd(struct hi_sec_hash_req *req)
{
	struct hi_sec_bd_desc_s desc;
	hi_int32 ret;

	hi_memset(&desc, 0, sizeof(desc));
	desc.bits.hash = req->hash;
	desc.bits.task = HI_SEC_DRV_TASK_AUTH_E;
	desc.bits.task_flag = HI_SEC_DRV_TASK_FLAG_AUTH_REWR;
	desc.bits.icv_len = req->auth_len;
	desc.bits.sec_flag = HI_SEC_DRV_SEC_FLAG_BIG_ENDIAN;
	desc.bits.adata_len = req->src_len;
	desc.auth_data_addr = hi_sec_get_phyaddr(req->src, req->src_len, HI_DMA_TO_DEVICE);
	desc.auth_icv_addr = hi_sec_get_phyaddr(req->auth, req->auth_len, HI_DMA_FROM_DEVICE);

	ret = hi_sec_hash_bd_fragment(&desc);

	hi_sec_release_phyaddr(desc.auth_data_addr, req->src_len, HI_DMA_TO_DEVICE);
	hi_sec_release_phyaddr(desc.auth_icv_addr, req->auth_len, HI_DMA_FROM_DEVICE);

	hi_secdrv_systrace(ret, req->hash, 0, 0, 0);
	return ret;
}

hi_int32 hi_sec_hash(struct hi_sec_hash_req *req)
{
	if (req == HI_NULL) {
		hi_secdrv_systrace(HI_RET_NULLPTR, 0, 0, 0, 0);
		return HI_RET_NULLPTR;
	}

	return hi_sec_hash_bd(req);
}

static hi_int32 hi_sec_hmac_keylen_get(hi_uint32 hmac)
{
	switch (hmac) {
	case HI_SEC_DRV_HASH_HMAC_SHA1_E:
		return HI_SHA1_HMAC_DIGEST_SIZE;
	case HI_SEC_DRV_HASH_HMAC_SHA256_E:
		return HI_SHA256_HMAC_DIGEST_SIZE;
	case HI_SEC_DRV_HASH_HMAC_SHA384_E:
		return HI_SHA384_HMAC_DIGEST_SIZE;
	case HI_SEC_DRV_HASH_HMAC_SHA512_E:
		return HI_SHA512_HMAC_DIGEST_SIZE;
	default:
		return HI_SHA1_HMAC_DIGEST_SIZE;
	}
}

static hi_int32 hi_sec_hmac_prekey(struct hi_sec_hmac_req *req)
{
	struct hi_sec_bd_desc_s desc;
	hi_int32 ret;

	if (req->key_len <= HI_SEC_AUTH_KEY_LEN_MAX) {
		hi_memcpy(g_hmac_prekey, req->key, req->key_len);
		return HI_RET_SUCC;
	}

	hi_memset(&desc, 0, sizeof(desc));
	desc.bits.hash = req->hmac;
	desc.bits.task = HI_SEC_DRV_TASK_AUTH_E;
	desc.bits.task_flag = HI_SEC_DRV_TASK_FLAG_AUTH_REWR;
	desc.bits.icv_len = hi_sec_hmac_keylen_get(req->hmac);
	desc.bits.sec_flag = HI_SEC_DRV_SEC_FLAG_BIG_ENDIAN;
	desc.bits.adata_len = req->key_len;
	desc.auth_data_addr = hi_sec_get_phyaddr(req->key, req->key_len, HI_DMA_TO_DEVICE);
	desc.auth_icv_addr = hi_sec_get_phyaddr(g_hmac_prekey, sizeof(g_hmac_prekey), HI_DMA_FROM_DEVICE);

	ret = hi_sec_hash_bd_fragment(&desc);

	hi_sec_release_phyaddr(desc.auth_data_addr, req->key_len, HI_DMA_TO_DEVICE);
	hi_sec_release_phyaddr(desc.auth_icv_addr, sizeof(g_hmac_prekey), HI_DMA_FROM_DEVICE);

	return ret;
}

static hi_int32 hi_sec_hmac_bd(struct hi_sec_hmac_req *req)
{
	struct hi_sec_bd_desc_s desc;
	hi_int32 ret;

	hi_secdrv_systrace(g_hmac_prekey, 0, 0, 0, 0);

	hi_memset(&desc, 0, sizeof(desc));
	desc.bits.hash = req->hmac;
	desc.bits.task = HI_SEC_DRV_TASK_AUTH_E;
	desc.bits.task_flag = HI_SEC_DRV_TASK_FLAG_AUTH_REWR;
	desc.bits.icv_len = req->auth_len;
	desc.bits.sec_flag = HI_SEC_DRV_SEC_FLAG_BIG_ENDIAN;
	desc.bits.adata_len = req->src_len;
	desc.bits.akey_len = (req->key_len > HI_SEC_AUTH_KEY_LEN_MAX ? hi_sec_hmac_keylen_get(req->hmac) : req->key_len);

	desc.auth_data_addr = hi_sec_get_phyaddr(req->src, req->src_len, HI_DMA_TO_DEVICE);
	hi_secdrv_systrace(desc.auth_data_addr, 0, 0, 0, 0);

	desc.auth_icv_addr = hi_sec_get_phyaddr(req->auth, req->auth_len, HI_DMA_FROM_DEVICE);
	hi_secdrv_systrace(desc.auth_icv_addr, 0, 0, 0, 0);

	desc.auth_key_addr = hi_sec_get_phyaddr(g_hmac_prekey, sizeof(g_hmac_prekey), HI_DMA_TO_DEVICE);
	hi_secdrv_systrace(desc.auth_key_addr, 0, 0, 0, 0);

	ret = hi_sec_hash_bd_fragment(&desc);
	hi_secdrv_systrace(ret, req->hmac, 0, 0, 0);

	hi_sec_release_phyaddr(desc.auth_data_addr, req->src_len, HI_DMA_TO_DEVICE);
	hi_sec_release_phyaddr(desc.auth_icv_addr, req->auth_len, HI_DMA_FROM_DEVICE);
	hi_sec_release_phyaddr(desc.auth_key_addr, sizeof(g_hmac_prekey), HI_DMA_TO_DEVICE);

	hi_secdrv_systrace(ret, req->hmac, 0, 0, 0);
	return ret;
}

hi_int32 hi_sec_hmac(struct hi_sec_hmac_req *req)
{
	hi_int32 ret;

	if (req == HI_NULL)
		return HI_RET_NULLPTR;

	g_hmac_prekey = hi_sec_dma_malloc(HI_SEC_AUTH_KEY_LEN_MAX);
	if (g_hmac_prekey == HI_NULL) {
		hi_secdrv_systrace(HI_RET_MALLOC_FAIL, 0, 0, 0, 0);
		return HI_RET_MALLOC_FAIL;
	}

	ret = hi_sec_hmac_prekey(req);
	if (ret != HI_RET_SUCC) {
		hi_sec_dma_free(g_hmac_prekey);
		hi_secdrv_systrace(ret, req->hmac, 0, 0, 0);
		return ret;
	}

	ret = hi_sec_hmac_bd(req);

	hi_sec_dma_free(g_hmac_prekey);
	g_hmac_prekey = HI_NULL;
	hi_secdrv_systrace(ret, req->hmac, 0, 0, 0);
	return ret;
}