/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: drive key for FBE3
 * Create: 2020/01/11
 */

#include "sec_fbe3_derive_key.h"
#include "sec_fbe3_interface.h"
#include "sec_fbe3_drv.h"

#include "crys_ecpki_types.h"
#include "crys_error.h"
#include "ccmgr_ops_ext.h"
#include "sre_task.h"
#include "sre_syscall.h"
#include <dx_cc_defs.h>
#include <sre_syscalls_ext.h>
#include "securec.h"
#include "tee_log.h"
#include "tee_mem_mgmt_api.h"
#include "tee_crypto_api.h"
#include "tee_trusted_storage_api.h"

/* the field name is decided by TEE_UUID_TSK */
static struct tee_uuid g_file_encry_uuid = {
	.timeLow = 0x54ff868f,
	.timeMid = 0x0d8d,
	.timeHiAndVersion = 0x4495,
	.clockSeqAndNode = { 0x9d, 0x95, 0x8e, 0x24, 0xb2, 0xa0, 0x82, 0x74 }
};

static uint32_t file_encry_derive_key(uint8_t *secret, uint32_t secret_len,
				      uint8_t *key, uint32_t key_len)
{
	uint32_t i;
	CRYSError_t ret;

	/* split the key to 16 byte each for 128-bit key length */
	for (i = 0; i < key_len / 16; i++) {
		secret[secret_len - 1] = (uint8_t)i;
		ret = __CC_DX_UTIL_CmacDeriveKey(DX_ROOT_KEY,
						 secret, secret_len,
						 key + 16 * i);
		if (ret != CRYS_OK) {
			tloge("%s, derive key[0x%x] failed, ret=0x%x\n",
			      __func__, i, ret);
			return ret;
		}
	}
	return FILE_ENCRY_OK;
}

uint32_t file_encry_calc_hash(const uint8_t *src, uint32_t src_len,
			      uint8_t *dest, uint32_t dest_len)
{
	TEE_Result ret;
	TEE_OperationHandle cryptoops = NULL;
	uint8_t hash[HASH_LEN];
	size_t hash_len = HASH_LEN;

	if (!src || !dest || src_len > BLOCK_SIZE_MAX) {
		tloge("%s, input params is wrong 0x%x\n", __func__, src_len);
		return FILE_ENCRY_ERROR_BUFFER_FROMTA;
	}
	ret = TEE_AllocateOperation(&cryptoops, TEE_ALG_SHA256, TEE_MODE_DIGEST, 0);
	if (ret != TEE_SUCCESS) {
		tloge("%s, allocation opera fail 0x%x\n", __func__, ret);
		goto finish;
	}
	ret = TEE_DigestDoFinal(cryptoops, src, src_len, hash, &hash_len);
	if (ret != TEE_SUCCESS) {
		tloge("%s, hash do final fail 0x%x\n", __func__, ret);
		goto finish;
	}
	ret = memcpy_s(dest, dest_len, hash, hash_len);
	if (ret != EOK) {
		tloge("%s, memcpy fail 0x%x\n", __func__, ret);
		ret = FILE_ENCRY_ERROR_MEMCPY_FAIL;
		goto finish;
	}
	ret = FILE_ENCRY_OK;
finish:
	(void)memset_s(hash, sizeof(hash), 0, sizeof(hash));
	TEE_FreeOperation(cryptoops);
	return ret;
}

void file_encry_gen_random(uint32_t len, uint8_t *buf)
{
	if (!buf || len == 0) {
		tloge("%s, input params is wrong\n", __func__);
		return;
	}
	TEE_GenerateRandom(buf, len);
}

static TEE_ObjectHandle import_key(uint8_t *key, uint32_t len, uint32_t *ret)
{
	TEE_Attribute attribute;
	TEE_Result result = TEE_SUCCESS;
	TEE_ObjectHandle genkey = NULL;

	result = TEE_AllocateTransientObject(TEE_TYPE_AES, MAX_KEY_SIZE, &genkey);
	if (result != TEE_SUCCESS) {
		tloge("%s, allocate object fail 0x%x\n", __func__, result);
		*ret = result;
		return NULL;
	}
	TEE_InitRefAttribute(&attribute, TEE_ATTR_SECRET_VALUE, (void *)(key), len);

	result = TEE_PopulateTransientObject(genkey, &attribute, 1);
	if(result != TEE_SUCCESS) {
		tloge("%s, populate object fail 0x%x\n", __func__, result);
		TEE_FreeTransientObject(genkey);
		*ret = result;
		return NULL;
	}
	*ret = TEE_SUCCESS;
	return genkey;
}

/* AES-CBC-256 */
uint32_t file_encry_do_aes_cbc(uint32_t mode, struct aes_info input)
{
	uint8_t output[KEY_LEN] = {0};
	uint32_t out_len = KEY_LEN;
	TEE_Result result = TEE_SUCCESS;
	TEE_ObjectHandle keyobject = NULL;
	TEE_OperationHandle cryptops = NULL;

	/* key: 32 byte */
	keyobject = import_key(input.magic, input.magic_len, &result);
        if(!keyobject || result != TEE_SUCCESS) {
		tloge("%s, import key fail\n", __func__);
		return result;
        }
	result = TEE_AllocateOperation(&cryptops, TEE_ALG_AES_CBC_NOPAD, mode,
				       input.magic_len);
	if (result != TEE_SUCCESS) {
		tloge("%s, allocate opera fail 0x%x\n", __func__, result);
		goto free_object;
        }
	result = TEE_SetOperationKey(cryptops, keyobject);
	if (result != TEE_SUCCESS) {
		tloge("%s, set operation key fail 0x%x\n", __func__, result);
		goto free_operation;
        }

	/* IV: 16 byte */
	TEE_CipherInit(cryptops, input.nonce, input.nonce_len);

	result = TEE_CipherDoFinal(cryptops, input.key, input.key_len, output, &out_len);
	if (result != TEE_SUCCESS) {
		tloge("%s, do final fail 0x%x\n", __func__, result);
		goto free_operation;
        }
	result = memcpy_s(input.key, input.key_len, output, input.key_len);
	if (result != EOK) {
		tloge("%s, memcpy fail 0x%x\n", __func__, result);
		result = FILE_ENCRY_ERROR_MEMCPY_FAIL;
		goto free_operation;
	}
	result = FILE_ENCRY_OK;

free_operation:
	TEE_FreeOperation(cryptops);
free_object:
	TEE_FreeTransientObject(keyobject);
	(void)memset_s(output, sizeof(output), 0, sizeof(output));

	return result;
}

uint32_t file_encry_do_aes_ccm(uint32_t mode, struct aes_info input)
{
	uint8_t output[KEY_LEN] = {0};
	uint32_t out_len = KEY_LEN;
	TEE_Result result = TEE_SUCCESS;
	TEE_ObjectHandle keyobject = NULL;
	TEE_OperationHandle cryptops = NULL;

	keyobject = import_key(input.magic, input.magic_len, &result);
        if(!keyobject || result != TEE_SUCCESS) {
		tloge("%s, import key fail\n", __func__);
		return result;
        }
	result = TEE_AllocateOperation(&cryptops, TEE_ALG_AES_CCM, mode,
				       input.magic_len);
	if (result != TEE_SUCCESS) {
		tloge("%s, allocate opera fail 0x%x\n", __func__, result);
		goto free_object;
        }
	result = TEE_SetOperationKey(cryptops, keyobject);
	if (result != TEE_SUCCESS) {
		tloge("%s, set operation key fail 0x%x\n", __func__, result);
		goto free_operation;
        }
	result = TEE_AEInit(cryptops, input.nonce, input.nonce_len,
			    input.tag_len, input.add_len, input.key_len);
	if (result != TEE_SUCCESS) {
		tloge("%s, aes AEInit 0x%x\n", __func__, result);
		goto free_operation;
        }
	TEE_AEUpdateAAD(cryptops, input.add, input.add_len);
	if (mode == TEE_MODE_ENCRYPT)
		result = TEE_AEEncryptFinal(cryptops, input.key, input.key_len,
					    output, &out_len, input.tag,
					    &input.tag_len);
	else
		result = TEE_AEDecryptFinal(cryptops, input.key, input.key_len,
					    output, &out_len, input.tag,
					    input.tag_len);
	if (result != TEE_SUCCESS) {
		tloge("%s, do final fail 0x%x\n", __func__, result);
		goto free_operation;
        }
	result = memcpy_s(input.key, input.key_len, output, out_len);
	if (result != EOK) {
		tloge("%s, memcpy fail 0x%x\n", __func__, result);
		result = FILE_ENCRY_ERROR_MEMCPY_FAIL;
		goto free_operation;
	}
	result = FILE_ENCRY_OK;
free_operation:
	TEE_FreeOperation(cryptops);
free_object:
	TEE_FreeTransientObject(keyobject);
	(void)memset_s(output, sizeof(output), 0, sizeof(output));
	return result;
}

static uint32_t file_encry_invalid_params(uint8_t *secret, uint8_t *key)
{
	if (!secret || !key) {
		tloge("%s, invalid parameters, buf is NULL\n", __func__);
		return FILE_ENCRY_ERROR_BUFFER_FROMTA;
	}
	return FILE_ENCRY_OK;
}

uint32_t file_encry_root_derive_key(uint8_t *secret, uint32_t secret_len,
				    uint8_t *key, uint32_t key_len)
{
	uint8_t *tmp_sec = NULL;
	uint32_t tmp_sec_len = secret_len + sizeof(struct tee_uuid) + 1;
	uint32_t ret;

	ret = file_encry_invalid_params(secret, key);
	if (ret != FILE_ENCRY_OK)
		return ret;

	/*
	 * the TEE_Malloc is defined in TEE OS, can NOT be modified
	 * the length increased by 1 is for storing the index.
	 */
	tmp_sec = (uint8_t *)TEE_Malloc(tmp_sec_len, 0);
	if (!tmp_sec) {
		tloge("%s, alloc tmp_sec failed\n", __func__);
		return FILE_ENCRY_ERROR_OUT_OF_MEM;
	}

	ret = memset_s(tmp_sec, tmp_sec_len, 0, tmp_sec_len);
	if (ret != EOK) {
		tloge("%s, memset_s failed, ret 0x%x\n", __func__, ret);
		ret = FILE_ENCRY_ERROR_MEMSET_FAIL;
		goto _exit;
	}

	ret = memcpy_s(tmp_sec, tmp_sec_len, secret, secret_len);
	if (ret != EOK) {
		tloge("memcpy_s secret failed, ret 0x%x\n", ret);
		ret = FILE_ENCRY_ERROR_MEMCPY_FAIL;
		goto _exit;
	}

	ret = memcpy_s(tmp_sec + secret_len, tmp_sec_len - secret_len,
		       &g_file_encry_uuid, sizeof(struct tee_uuid));
	if (ret != EOK) {
		tloge("memcpy_s uuid failed, ret 0x%x\n", ret);
		ret = FILE_ENCRY_ERROR_MEMCPY_FAIL;
		goto _exit;
	}

	ret = file_encry_derive_key(tmp_sec, tmp_sec_len, key, key_len);
	if (ret != FILE_ENCRY_OK) {
		tloge("%s, derive key fail 0x%x\n", __func__, ret);
		goto _exit;
	}

	ret = FILE_ENCRY_OK;

_exit:
	/* the TEE_Free is defined in TEE OS, can NOT be modified */
	TEE_Free(tmp_sec);
	return ret;
}

static void file_encry_convert_endianness(uint32_t *buf_ptr, uint32_t sizewords)
{
	uint32_t i;
	uint32_t tmp;

	/* If sizewords is odd revert middle(sizewords / 2) word */
#ifndef BIG__ENDIAN
	if (sizewords & 1UL)
		buf_ptr[sizewords / 2] = REVERSE32(buf_ptr[sizewords / 2]);
#endif
	/*
	 * Reverse order of words and order of bytes in each word.
	 * Note: Condition (sizeWords >= 2) inserted inside for() to
	 *       prevent wrong false positive warnings.
	 */
	for (i = 0; ((i < sizewords / 2) && (sizewords >= 2)); i++) {
#ifndef BIG__ENDIAN
		tmp = REVERSE32(buf_ptr[i]);
		buf_ptr[i] = REVERSE32(buf_ptr[sizewords - i - 1]);
#else
		tmp = buf_ptr[i];
		buf_ptr[i] = buf_ptr[sizewords - i - 1];
#endif
		buf_ptr[sizewords - i - 1] = tmp;
	}
}

static uint32_t file_encry_invalid_params2(uint8_t *pubkey, uint32_t publen,
					   uint8_t *privkey, uint32_t privlen)
{
	if (publen != PUB_KEY_LEN || privlen != PRIV_KEY_LEN) {
		tloge("%s, invalid input, len is 0x%x, 0x%x\n",
		       __func__, publen, privlen);
		return FILE_ENCRY_ERROR_LENGTH_FROMTA;
	}
	if (!pubkey || !privkey) {
		tloge("%s, invalid parameters, buffer is NULL\n", __func__);
		return FILE_ENCRY_ERROR_BUFFER_FROMTA;
	}
	return FILE_ENCRY_OK;
}

/* generate keypair by hardware */
uint32_t file_encry_keypair_using_hw(uint8_t *pubkey, uint32_t publen,
				     uint8_t *privkey, uint32_t privlen)
{
	CRYSError_t ret;
	CRYS_ECPKI_KG_TempData_t tempbuff = {0};
	CRYS_ECPKI_UserPublKey_t pubkey0 = {0};
	CRYS_ECPKI_UserPrivKey_t privkey0 = {0};
	CRYS_ECPKI_PrivKey_t *pprivkey = NULL;
	uint32_t pub_key_size = EC_PUB_KEY_SIZE;
	uint8_t ec_pub_key[EC_PUB_KEY_SIZE] = {0};

	ret = file_encry_invalid_params2(pubkey, publen, privkey, privlen);
	if (ret != FILE_ENCRY_OK) {
		tloge("%s, check params fail 0x%x\n", __func__, ret);
		return ret;
	}

	ret = __CC_CRYS_ECPKI_GenKeyPair(FILE_ECDH_DOMAIN,
					 &privkey0,
					 &pubkey0, &tempbuff);
	if (ret != CRYS_OK) {
		tloge("ECPKI_GenKeyPair fail, 0x%x\n", ret);
		return ret;
	}
	/* 4: CC_EC_PointUncompressed */
	ret = __CC_CRYS_ECPKI_ExportPublKey(&pubkey0, 4, ec_pub_key,
					    &pub_key_size);

	if (ret != CRYS_OK) {
		tloge("ECPKI_ExportPublKey fail, 0x%x\n", ret);
		return ret;
	}

	if (memcpy_s(pubkey, publen, ec_pub_key, pub_key_size) != EOK) {
		tloge("%s, memcpy pubkey fail\n", __func__);
		return FILE_ENCRY_ERROR_MEMCPY_FAIL;
	}

	pprivkey = (CRYS_ECPKI_PrivKey_t *)(&privkey0.PrivKeyDbBuff[0]);
	file_encry_convert_endianness(pprivkey->PrivKey,
				      PRIV_KEY_LEN / WORDS_LEN);
	if (memcpy_s(privkey, privlen, (uint8_t *)pprivkey->PrivKey,
		     PRIV_KEY_LEN) != EOK) {
		tloge("%s, memcpy privkey fail\n", __func__);
		return FILE_ENCRY_ERROR_MEMCPY_FAIL;
	}
	return FILE_ENCRY_OK;
}

static uint32_t file_encry_generate_keys(TEE_ObjectHandle *obj)
{
	TEE_Result ret = FILE_ENCRY_OK;

	ret = TEE_AllocateTransientObject(TEE_TYPE_ECDH_KEYPAIR, MAX_ECC_SIZE,
					  obj);
	if (ret != TEE_SUCCESS) {
		tloge("%s, alloc object failed 0x%x\n", __func__, ret);
		*obj = NULL;
		return ret;
	}
	ret = TEE_GenerateKey(*obj, MAX_ECC_SIZE, NULL, 0);
	if (ret != TEE_SUCCESS) {
		tloge("%s, generate key failed 0x%x\n", __func__, ret);
		goto out;
	}
	return FILE_ENCRY_OK;
out:
	TEE_FreeTransientObject(*obj);
	*obj = NULL;
	return ret;
}

/* generate keypair by software */
uint32_t file_encry_keypair_using_sw(uint8_t *pubkey, uint32_t publen,
				     uint8_t *privkey, uint32_t privlen)
{
	uint32_t len;
	uint8_t *buf = NULL;
	uint32_t index = 0;
	TEE_Result ret = TEE_FAIL;
	TEE_ObjectHandle tmp_keyobj = NULL;

	ret = file_encry_invalid_params2(pubkey, publen, privkey, privlen);
	if (ret != FILE_ENCRY_OK) {
		tloge("%s, check params fail 0x%x\n", __func__, ret);
		return ret;
	}
	ret = file_encry_generate_keys(&tmp_keyobj);
	if (ret != FILE_ENCRY_OK || !tmp_keyobj) {
		tloge("%s, get keyobj fail 0x%x\n", __func__, ret);
		return ret;
	}

	/* Check the length before pubkey copy */
	len = tmp_keyobj->Attribute[0].content.ref.length +
	      tmp_keyobj->Attribute[1].content.ref.length + 1;
	if (len != publen) {
		tloge("%s, Pubkey len is invalid 0x%x, 0x%x\n",
		      __func__, len, publen);
		ret = FILE_ENCRY_ERROR_PUBKEY_LEN;
		goto out;
	}
	/* Below codes are just copy pubkey & privkey out */
	pubkey[index++] = 4; /* 4: PointUncompressed, used in ECDH */
	/* Copy X value out TEE_ATTR_ECC_PUBLIC_VALUE_X */
	len = tmp_keyobj->Attribute[0].content.ref.length;
	buf = tmp_keyobj->Attribute[0].content.ref.buffer;
	ret = memcpy_s(&pubkey[index], publen - index, buf, len);
	if (ret != EOK) {
		tloge("memcpy_s X value failed, ret 0x%x\n", ret);
		ret = FILE_ENCRY_ERROR_MEMCPY_FAIL;
		goto out;
	}
	index += len;
	/* Copy Y value out TEE_ATTR_ECC_PUBLIC_VALUE_Y */
	len = tmp_keyobj->Attribute[1].content.ref.length;
	buf = tmp_keyobj->Attribute[1].content.ref.buffer;
	ret = memcpy_s(&pubkey[index], publen - index, buf, len);
	if (ret != EOK) {
		tloge("memcpy_s Y value failed, ret 0x%x\n", ret);
		ret = FILE_ENCRY_ERROR_MEMCPY_FAIL;
		goto out;
	}

	/* Copy PRIVATE value out TEE_ATTR_ECC_PRIVATE_VALUE */
	len = tmp_keyobj->Attribute[2].content.ref.length;
	buf = tmp_keyobj->Attribute[2].content.ref.buffer;
	ret = memcpy_s(privkey, privlen, buf, len);
	if (ret != EOK) {
		tloge("memcpy_s PRIVKEY value failed, ret 0x%x\n", ret);
		ret = FILE_ENCRY_ERROR_MEMCPY_FAIL;
		goto out;
	}
	ret = FILE_ENCRY_OK;
out:
	TEE_FreeTransientObject(tmp_keyobj);
	return ret;
}

uint32_t file_encry_gen_metadata(uint8_t *pubkey, uint32_t pub_len,
				 uint8_t *privkey, uint32_t priv_len,
				 uint8_t *metadata, uint32_t len)
{
	CRYSError_t ret;
	uint32_t size = ECDH_KEY_LEN;
	CRYS_ECPKI_UserPublKey_t userpubkey = {0};
	CRYS_ECPKI_UserPrivKey_t userprivkey = {0};
	CRYS_ECDH_TempData_t tempdata = {0};
	u8 data[ECDH_KEY_LEN] = {0};

	ret = file_encry_invalid_params2(pubkey, pub_len, privkey, priv_len);
	if (ret != FILE_ENCRY_OK) {
		tloge("%s, check params fail 0x%x\n", __func__, ret);
		return ret;
	}

	if (!metadata || len != MATA_LEN) {
		tloge("%s, out buffer error\n", __func__);
		return FILE_ENCRY_ERROR_BUFFER_FROMTA;
	}
	ret = __CC_CRYS_ECPKI_BuildPublKey(FILE_ECDH_DOMAIN, pubkey,
					   pub_len, &userpubkey);
	if (ret != CRYS_OK) {
		tloge("%s, build pubkey fail, 0x%x\n", __func__, ret);
		return ret;
	}

	ret = __CC_CRYS_ECPKI_BuildPrivKey(FILE_ECDH_DOMAIN, privkey,
					   priv_len, &userprivkey);
	if (ret != CRYS_OK) {
		tloge("%s, build privkey fail, 0x%x\n", __func__, ret);
		return ret;
	}

	ret = __CC_CRYS_ECDH_SVDP_DH(&userpubkey, &userprivkey, data,
				     &size, &tempdata);
	if (ret != CRYS_OK) {
		tloge("%s, ecdh fail 0x%x\n", __func__, ret);
		return ret;
	}

	size = min(size, len);
	if (memcpy_s(metadata, len, data, size) != EOK) {
		tloge("%s, memcpy metadata fail\n", __func__);
		return FILE_ENCRY_ERROR_MEMCPY_FAIL;
	}
	return FILE_ENCRY_OK;
}

uint32_t file_encry_config_driver(uint32_t slot, uint8_t *key, uint32_t length)
{
	return __file_encry_interface(slot, key, length);
}
