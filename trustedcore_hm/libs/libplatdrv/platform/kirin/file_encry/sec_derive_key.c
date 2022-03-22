/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * Description: Library for FBE2
 * Author: security-ap
 * Create: 2018-06-11
 */

#include "sec_derive_key.h"
#include <legacy_mem_ext.h> // SRE_MemAlloc
#include <mem_ops.h>
#include "sec_ufs_km.h"

#include "securec.h"
#include "tee_defines.h"
#include "cc_lib.h"
#include "cc_des.h"
#include "cc_hmac.h"
#include "cc_aesccm.h"
#include "cc_util_oem_asset.h"
#include "cc_ecpki_types.h"
#include "cc_dh.h"
#include "cc_rsa_schemes.h"
#include "cc_rsa_build.h"
#include "cc_ecpki_build.h"
#include "cc_ecpki_domain.h"
#include "cc_ecpki_kg.h"
#include "cc_ecpki_ecdsa.h"
#include "cc_rsa_kg.h"
#include "cc_ecpki_dh.h"
#include "cc_rsa_prim.h"
#include "cc_adapt.h"
#include "tee_log.h"

/* the field name is decided by TEE_UUID_TSK */
static struct tee_uuid g_file_encry_uuid = {
	.timeLow = 0x54ff868f,
	.timeMid = 0x0d8d,
	.timeHiAndVersion = 0x4495,
	.clockSeqAndNode = { 0x9d, 0x95, 0x8e, 0x24, 0xb2, 0xa0, 0x82, 0x74 }
};

#define KEY_STRING { 0x51, 0x5C, 0x4f, 0x56, 0x4E, 0x53, 0x4A, 0x8F, 0x4E, \
		0x20, 0x4B, 0x45, 0x50, 0x68, 0x9A, 0x0C }

static int file_encry_user_derive_key(uint8_t *pUserKey, uint32_t keylen)
{
	uint8_t key_string[] = KEY_STRING;
	CCUtilAesCmacResult_t cmac_result = { 0 };
	CCUtilError_t ret;
	errno_t rc;

	if (!pUserKey || keylen != CC_UTIL_AES_CMAC_RESULT_SIZE_IN_BYTES) {
		tloge("%s: invalid input parameters\n", __func__);
		return FILE_ENCRY_ERROR_INPUT_ERROR;
	}

	ret = DX_UTIL_CmacDeriveKey(UTIL_ROOT_KEY, key_string,
				    sizeof(key_string), cmac_result);
	if (ret) {
		tloge("%s: derive key failed, ret = 0x%x\n", __func__, ret);
		return FILE_ENCRY_ERROR_DERIVE_KEY;
	}

	rc = memcpy_s(pUserKey, CC_UTIL_AES_CMAC_RESULT_SIZE_IN_BYTES,
		      cmac_result, sizeof(cmac_result));
	if (rc) {
		tloge("%s: memcpy_s failed, rc = 0x%x\n", __func__, rc);
		(void)memset_s(cmac_result, sizeof(cmac_result), 0,
			       sizeof(cmac_result));
		return FILE_ENCRY_ERROR_DER_MEMCPY_KEY;
	}

	(void)memset_s(cmac_result, sizeof(cmac_result), 0,
		       sizeof(cmac_result));
	return FILE_ENCRY_OK;
}

static int file_encry_derive_key(uint8_t *secret, uint32_t secret_len,
				 uint8_t *key, uint32_t key_len)
{
	uint8_t user_key[USER_KEY_LENGTH] = {0};
	CCAesUserKeyData_t UserKey;
	uint32_t i;
	CCUtilError_t ret;
	uint8_t fbe2_flag = FILE_ENCRY_KEY_ENHANCED;

	ret = secboot_get_fbe2_flag(&fbe2_flag);
	if (ret) {
		tloge("%s: get fbe2_flag failed!\n", __func__);
		return FILE_ENCRY_ERROR_GET_MAGIC;
	}

	tlogi("%s: fbe2_flag is 0x%x!\n", __func__, fbe2_flag);
	if (fbe2_flag != FILE_ENCRY_KEY_NORMAL) {
		tlogi("%s: enhanced method used!\n", __func__);

		ret = file_encry_user_derive_key(user_key, sizeof(user_key));
		if (ret != FILE_ENCRY_OK) {
			tloge("%s: derive key fail! key1\n", __func__);
			goto clean_buffer;
		}
		UserKey.pKey = user_key;
		UserKey.keySize = sizeof(user_key);

		/* split the key to 16 byte each for 128-bit key length */
		for (i = 0; i < key_len / 16; i++) {
			secret[secret_len - 1] = (uint8_t)i;
			ret = DX_UTIL_UserDeriveKey(UTIL_USER_KEY, &UserKey,
						    secret, secret_len,
						    key + 16 * i);
			if (ret) {
				tloge("derive key[%d] failed, ret=0x%x\n",
				      i, ret);
				goto err_proc;
			}
		}
	} else {
		tlogi("%s: normal method used!\n", __func__);

		/* split the key to 16 byte each for 128-bit key length */
		for (i = 0; i < key_len / 16; i++) {
			secret[secret_len - 1] = (uint8_t)i;
			ret = DX_UTIL_CmacDeriveKey(UTIL_ROOT_KEY,
						    secret, secret_len,
						    key + 16 * i);
			if (ret) {
				tloge("derive key[%d] failed, ret=0x%x\n",
				      i, ret);
				goto err_proc;
			}
		}
	}

	ret = FILE_ENCRY_OK;
	goto clean_buffer;
err_proc:
	ret = FILE_ENCRY_ERROR_DERIVE_KEY;
clean_buffer:
	if (memset_s(user_key, sizeof(user_key), 0, sizeof(user_key)) != EOK) {
		tloge("memset_s failed\n");
		ret = FILE_ENCRY_ERROR_MEMSET_FAIL;
	}
	return ret;
}

int file_encry_root_derive_key(uint8_t *secret, uint32_t secret_len,
			       uint8_t *key, uint32_t key_len)
{
	uint8_t *tmp_sec = NULL;
	uint32_t tmp_sec_len = secret_len + sizeof(struct tee_uuid);
	int ret;
	errno_t rc;

	if (secret_len != IV_LENGTH || key_len != IV_LENGTH) {
		tloge("invalid input parameters, len is wrong\n");
		return FILE_ENCRY_ERROR_INPUT_ERROR;
	}
	if (!secret || !key) {
		tloge("invalid input parameters, input is NULL\n");
		return FILE_ENCRY_ERROR_INPUT_ERROR;
	}
	/*
	 * the SRE_MemAlloc is defined in TEE OS, can NOT be modified
	 * the length increased by 1 is for storing the index.
	 */
	tmp_sec = (uint8_t *)SRE_MemAlloc(OS_MID_TSK, OS_MEM_DEFAULT_FSC_PT,
					   tmp_sec_len + 1);
	if (!tmp_sec) {
		tloge("alloc tmp_sec failed\n");
		return FILE_ENCRY_ERROR_DER_OUT_OF_MEM;
	}

	rc = memset_s(tmp_sec, tmp_sec_len + 1, 0, tmp_sec_len + 1);
	if (rc) {
		tloge("memset_s failed, rc %x\n", rc);
		ret = FILE_ENCRY_ERROR_DER_SETMEM;
		goto _exit;
	}

	rc = memcpy_s(tmp_sec, tmp_sec_len + 1, secret, secret_len);
	if (rc) {
		tloge("memcpy_s failed, rc %x\n", rc);
		ret = FILE_ENCRY_ERROR_DER_MEMCPY_KEY;
		goto _exit;
	}
	rc = memcpy_s(tmp_sec + secret_len, tmp_sec_len + 1 - secret_len,
		&g_file_encry_uuid, sizeof(g_file_encry_uuid));
	if (rc) {
		tloge("memcpy_s failed, rc %x\n", rc);
		ret = FILE_ENCRY_ERROR_DER_MEMORY_UUID;
		goto _exit;
	}

	ret = file_encry_derive_key(tmp_sec, tmp_sec_len + 1, key, key_len);
	if (ret != FILE_ENCRY_OK)
		goto _exit;

	ret = FILE_ENCRY_OK;

_exit:
	/* the SRE_MemFree is defined in TEE OS, can NOT be modified */
	SRE_MemFree(OS_MID_TSK, tmp_sec);
	return ret;
}
