/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: Library for FBE3
 * Create: 2020/01/07
 */

#include "sec_fbe3_drv.h"
#include "sec_fbe3_interface.h"
#include "sec_fbe3_derive_key.h"
#include "sec_fbe3_rpmb.h"
#include "mspc_ext_api.h"
#include "msp_fbe.h"

#include "crys_error.h"
#include "ccmgr_ops_ext.h"
#include <sre_syscall.h>
#include "securec.h"
#include "sre_typedef.h"
#include "tee_defines.h"
#include "tee_log.h"
#include "tee_trusted_storage_api.h"
#include "tee_mem_mgmt_api.h"
#include "sec_flash_ext_api.h"

static const char g_fbe3_sece_info[] = "sec_storage_data/fbe3/sece_status.txt";
static struct ufs_info g_ufs_info[MAX_KEY_NUM_SUPPORT];
static struct sece_info g_sece_info[MAX_SECE_NUM];
static uint32_t g_sece_ready_flag;
static uint8_t g_chip_id;
static bool g_msp_status = true;
static uint32_t g_msp_status_check;
static uint16_t g_fetch_rpmb = 0;
static uint16_t g_read_switch = 0;

static uint32_t file_encry_fetch_sfskey(const char *name, void *buf,
					uint32_t len, uint32_t offset)
{
	TEE_Result ret;
	uint32_t readed_size = 0;
	TEE_ObjectHandle handle = {0};
	uint32_t flag = TEE_DATA_FLAG_ACCESS_READ;

	ret = TEE_OpenPersistentObject(TEE_OBJECT_STORAGE_PRIVATE, (void *)name,
				       strlen(name), flag, &handle);
	if (ret == TEE_ERROR_ITEM_NOT_FOUND) {
		flag |= (TEE_DATA_FLAG_CREATE | TEE_DATA_FLAG_ACCESS_WRITE);
		ret = TEE_CreatePersistentObject(TEE_OBJECT_STORAGE_PRIVATE,
					 name, strlen(name), flag,
					 TEE_HANDLE_NULL, buf, len,
					 &handle);
	}
	if (ret != TEE_SUCCESS) {
		tloge("%s, open %s failed, 0x%x\n", __func__, name, ret);
		return ret;
	}

	ret = TEE_SeekObjectData(handle, offset * len, TEE_DATA_SEEK_CUR);
	if (ret != TEE_SUCCESS) {
		tloge("%s, seek %s failed, 0x%x\n", __func__, name, ret);
		goto out;
	}

	ret = (int)TEE_ReadObjectData(handle, buf, len, &readed_size);
	if (ret != TEE_SUCCESS) {
		tloge("%s, read %s failed, 0x%x, size 0x%x\n",
		      __func__, name, ret, readed_size);
		goto out;
	}
	ret = FILE_ENCRY_OK;
out:
	TEE_CloseObject(handle);
	return ret;
}

/* write one key at a time */
static uint32_t file_encry_store_sfs(const char *name, const void *buf,
				     uint32_t len, uint32_t offset)
{
	TEE_Result ret;
	TEE_ObjectHandle handle;
	uint32_t flag = TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_ACCESS_WRITE;

	ret = TEE_OpenPersistentObject(TEE_OBJECT_STORAGE_PRIVATE, (void *)name,
				       strlen(name), flag, &handle);
	if (ret == TEE_ERROR_ITEM_NOT_FOUND) {
		flag |= TEE_DATA_FLAG_CREATE;
		ret = TEE_CreatePersistentObject(TEE_OBJECT_STORAGE_PRIVATE,
					 name, strlen(name), flag,
					 TEE_HANDLE_NULL, buf, len,
					 &handle);
	}
	if (ret != TEE_SUCCESS) {
		tloge("%s, open %s failed, 0x%x\n", __func__, name, ret);
		return ret;
	}

	ret = TEE_SeekObjectData(handle, offset * len, TEE_DATA_SEEK_CUR);
	if (ret != TEE_SUCCESS) {
		tloge("%s, seek %s failed, 0x%x\n", __func__, name, ret);
		goto out;
	}

	ret = (int)TEE_WriteObjectData(handle, buf, len);
	if (ret != TEE_SUCCESS) {
		tloge("%s, write %s failed, 0x%x\n", __func__, name, ret);
		goto out;
	}

	TEE_SyncPersistentObject(handle);
	ret = FILE_ENCRY_OK;
out:
	TEE_CloseObject(handle);
	return ret;
}

#ifdef FILE_ENCRY_KEY_HASH_ENABLE
static uint32_t file_encry_hash_value(uint8_t *buf_in, uint32_t len_in,
				      uint8_t *buf_out, uint32_t len_out)
{
	uint32_t ret;

	ret = file_encry_calc_hash(buf_in, len_in, buf_out, len_out);
	if (ret != FILE_ENCRY_OK) {
		tloge("%s, crypto hash fail 0x%x\n", __func__, ret);
		return ret;
	}

	return FILE_ENCRY_OK;
}

static uint32_t file_encry_verify_hash(uint8_t *key, uint32_t key_len,
				       uint8_t *magic, uint32_t magic_len)
{
	uint32_t ret;
	uint8_t hash[HASH_LEN] = {0};

	ret = file_encry_hash_value(key, key_len, hash, sizeof(hash));
	if (ret != FILE_ENCRY_OK) {
		tloge("%s, get hash fail 0x%x\n", __func__, ret);
		return ret;
	}

	if (memcmp(hash, magic, magic_len)) {
		tloge("%s, hash verify fail\n", __func__);
		return FILE_ENCRY_ERROR_HASH_VERIFY;
	}
	tlogd("%s, hash verify succ\n", __func__);
	return FILE_ENCRY_OK;
}
#endif

/*
 * Function: is_invalid_file_type
 * Description: this is for install/uninstall key
 *     Valid file type is 0, 1, 2, 3
 *     Global DE key is defined as 4
 *     So valid key type must < FILE_GLOBAL_DE
 */
static uint32_t is_invalid_file_type(uint32_t file)
{
	if (file < FILE_GLOBAL_DE)
		return FILE_ENCRY_OK;

	tloge("unsupported file type 0x%x\n", file);
	return FILE_ENCRY_ERROR_FILE_TYPE;
}

static uint32_t find_available_ufs_slot(void)
{
	uint32_t slot;

	for (slot = 0; slot < MAX_KEY_NUM_SUPPORT; slot++) {
		if (g_ufs_info[slot].status == UFS_KEY_NONE ||
			g_ufs_info[slot].status == UFS_KEY_LOGOUT)
			break;
	}
	return slot;
}

static uint32_t find_available_sece_stat(void)
{
	uint32_t idx;

	for (idx = 0; idx < MAX_SECE_NUM; idx++) {
		if (g_sece_info[idx].avail == SECE_KEY_NONE)
			break;
	}
	return idx;
}

static uint32_t is_keypair_check(uint32_t user)
{
	uint32_t slot;

	for (slot = 0; slot < MAX_SECE_NUM; slot++) {
		if (g_sece_info[slot].user != user)
			continue;
		if (g_sece_info[slot].avail == SECE_KEY_NONE)
			continue;
		break;
	}
	return slot;
}

bool file_encry_msp_available(void)
{
	uint32_t ret;
	uint32_t status = MSPC_NOT_AVAILABLE_MAGIC;

	if (g_msp_status_check == MSP_CHECKED)
		return g_msp_status;

	(void)TEE_EXT_MSPIsAvailable(&status);
	if (status != MSPC_EXIST_MAGIC) {
		tloge("%s, mspc not ready, using sfs\n", __func__);
		g_msp_status = false;
		goto out;
	}

	status = SECFLASH_IS_ABSENCE_MAGIC;
	ret = (int)TEE_EXT_SecFlashIsAvailable(&status);
	if (ret != TEE_SUCCESS) {
		g_msp_status = false;
		tloge("%s, SecFlashIsAvailable is err status 0x%x, using sfs\n",
		      __func__, status);
		goto out;
	}
	if (status == SECFLASH_IS_ABSENCE_MAGIC) {
		g_msp_status = false;
		tloge("%s, secflash is invalid, using sfs\n", __func__);
		goto out;
	}
	tloge("%s, secflash status 0x%x, using msp\n", __func__, status);
	g_msp_status = true;
out:
	g_msp_status_check = MSP_CHECKED;
	return g_msp_status;
}

static uint32_t file_encry_get_file_ready(void)
{
	uint32_t ret;

	/* init sfs files only once during one boot */
	if (g_sece_ready_flag == SECE_READY)
		return FILE_ENCRY_OK;

	/* If MSP is exist, do not init sfs files */
	if (file_encry_msp_available())
		return FILE_ENCRY_OK;

	(void)memset_s(g_sece_info, sizeof(g_sece_info),
		       0, sizeof(g_sece_info));
	ret = file_encry_fetch_sfskey(g_fbe3_sece_info, g_sece_info,
				      sizeof(g_sece_info), 0);
	if (ret != FILE_ENCRY_OK) {
		tloge("%s, fetch keypair fail, 0x%x\n", __func__, ret);
		return ret;
	}

	g_sece_ready_flag = SECE_READY;
	return ret;
}

static uint32_t file_encry_first_ivadd(uint32_t user, uint32_t file,
				       uint8_t *iv, uint32_t iv_len,
				       uint32_t *ufs_slot)
{
	uint32_t slot;

	for (slot = 0; slot < MAX_KEY_NUM_SUPPORT; slot++) {
		if (g_ufs_info[slot].user != user ||
			g_ufs_info[slot].file != file)
			continue;
		/* user = 0 & file = 0 is an legal setting */
		if (g_ufs_info[slot].status == UFS_KEY_NONE)
			continue;
		if (memcmp(iv, g_ufs_info[slot].iv_value, iv_len)) {
			tloge("cannot update key user 0x%x, file 0x%x\n",
			      user, file);
			return FILE_ENCRY_ERROR_IV_VALUE;
		}
		break;
	}

	*ufs_slot = slot;
	return FILE_ENCRY_OK;
}

/*
 * Function: file_encry_update_msp
 * Input parameters:
 *     user file_type magic magic_len  key  key_len
 *     x    0/1/2     u8*   MAGIC_LEN  u8*  KEY_LEN
 *     x    3         u8*   MAGIC_LEN  u8*  KEY_LEN + PUB_LEN + PRIV_LEN
 */
static uint32_t file_encry_update_msp(uint32_t ufs_slot, uint32_t file_type,
				      uint8_t *key, uint32_t key_len)
{
	uint32_t ret;
	uint8_t magic[MAGIC_LEN] = {0};
	struct key_info_t key_info = {0};

	ret = file_encry_root_derive_key(g_ufs_info[ufs_slot].iv_value, KEY_LEN,
					 magic, sizeof(magic));
	if (ret != FILE_ENCRY_OK) {
		tloge("%s: derive magic fail 0x%x\n", __func__, ret);
		return ret;
	}

	key_info.user_id = g_ufs_info[ufs_slot].user;
	key_info.file_type = file_type;
	key_info.magic_buf = magic;
	key_info.magic_len = sizeof(magic);
	key_info.key_buf = key;
	key_info.key_len = key_len;

	ret = msp_fbe_fetch_key_enhance(&key_info);
	if (ret != MSP_SUCCESS) {
		tloge("%s: fetch to msp fail(0x%x)\n", __func__, ret);
		return ret;
	}

	ret = file_encry_rpmb_write(&key_info);
	if (ret != FILE_ENCRY_OK) /* ignore the error */
		tloge("%s, save keys to rpmb fail 0x%x\n", __func__, ret);
	return FILE_ENCRY_OK;
}

/*
 * Function: file_encry_fetch_msp
 * Input parameters:
 *     user key_flag  magic magic_len  key  key_len
 *     x    0/1/2     u8*   MAGIC_LEN  u8*  KEY_LEN
 *     x    3         u8*   MAGIC_LEN  u8*  KEY_LEN + PUB_LEN
 *     x    5         u8*   MAGIC_LEN  u8*  PRIV_LEN
 */
static uint32_t file_encry_fetch_msp(uint32_t ufs_slot, uint8_t *key,
				     uint32_t key_len, uint32_t key_flag)
{
	uint32_t ret;
	uint8_t magic[MAGIC_LEN] = {0};
	struct key_info_t key_info = {0};

	ret = file_encry_root_derive_key(g_ufs_info[ufs_slot].iv_value, KEY_LEN,
					 magic, sizeof(magic));
	if (ret != FILE_ENCRY_OK) {
		tloge("%s: derive magic fail 0x%x\n", __func__, ret);
		return ret;
	}

	key_info.user_id = g_ufs_info[ufs_slot].user;
	key_info.file_type = key_flag; /* using file type as default */
	key_info.magic_buf = magic;
	key_info.magic_len = sizeof(magic);
	key_info.key_buf = key;
	key_info.key_len = key_len;

	tloge("%s, into msp, file_type 0x%x\n", __func__, key_flag);
	ret = msp_fbe_fetch_key(&key_info);
	if (ret != MSP_SUCCESS) {
		g_fetch_rpmb += 1;
		/* if g_read_switch is even, add 1, means read keys from RPMB */
		if (!(g_read_switch & 0x1))
			g_read_switch += 1;
		tloge("%s: fetch msp fail, try rpmb 0x%hx\n", __func__, g_fetch_rpmb);
		ret = file_encry_rpmb_read(&key_info);
	} else {
		/* if g_read_switch is odd, add 1, means read keys from MSP again */
		if (g_read_switch & 0x1)
			g_read_switch += 1;
	}
	tloge("%s, out msp, file_type 0x%x\n", __func__, key_flag);

	uint32_t result;
	result = file_encry_rpmb_ensure_enc(g_ufs_info[ufs_slot].user, key_flag);
	if (result != FILE_ENCRY_OK)
		tloge("%s, rpmb enc failed, 0x%x\n", __func__, result);

	return ret;
}
#ifdef FILE_ENCRY_USING_RPMB
uint32_t file_encry_derive_rpmb_kek(uint32_t user_id, uint32_t file, uint8_t *kek,
				    uint32_t kek_len, struct aes_info *info)
{
	uint32_t ret;
	uint32_t slot;
	u8 iv[KEY_LEN] = {0};

	if (!kek || !info || kek_len < AES_KEK_LEN) {
		tloge("%s, user 0x%x, RPMB kek invalid input\n",
			__func__, user_id);
		return FILE_ENCRY_ERROR_RPMB_ENC_NULL;
	}

	if (file == FILE_PRIV)
		file = FILE_SECE;

	for (slot = 0; slot < MAX_KEY_NUM_SUPPORT; slot++) {
		if (g_ufs_info[slot].user == user_id &&
			g_ufs_info[slot].file == file) {
			break;
		}
	}
	if (slot >= MAX_KEY_NUM_SUPPORT) {
		tloge("%s, user 0x%x, file 0x%x IV not found\n",
			__func__, user_id, file);
		return FILE_ENCRY_ERROR_RPMB_ENC_NO_IV;
	}

	ret = file_encry_root_derive_key(g_ufs_info[slot].iv_value, KEY_LEN,
					 iv, KEY_LEN);
	if (ret != FILE_ENCRY_OK) {
		tloge("%s: derive temp IV fail 0x%x\n", __func__, ret);
		return ret;
	}

	ret = file_encry_root_derive_key(iv, KEY_LEN, kek, kek_len);
	if (ret != FILE_ENCRY_OK) {
		tloge("%s: derive KEK fail 0x%x\n", __func__, ret);
		return ret;
	}

	/*
	 * AES CBC 256 kek len = 48, used as:
	 * 0 - 31: key, len = 32
	 * 32 - 47: IV, len = 16
	 */
	info->magic = kek;
	info->magic_len = AES_KEY_LEN;
	info->nonce = &kek[AES_KEY_LEN];
	info->nonce_len = AES_NONCE_LEN + AES_ADD_LEN;
	return FILE_ENCRY_OK;
}
#endif
/*
 * Function: file_encry_delete_msp
 * Input parameters:
 *     user key_flag  magic magic_len  key   key_len
 *     x    0/1/2     u8*   MAGIC_LEN  NULL  KEY_LEN
 *     x    3         u8*   MAGIC_LEN  NULL  KEY_LEN + PUB_LEN + PRIV_LEN
 */
static uint32_t file_encry_delete_msp(uint32_t user, uint32_t key_flag)
{
	uint32_t ret;
	uint32_t len = KEY_LEN;
	uint8_t magic[MAGIC_LEN] = {0};
	struct key_info_t key_info = {0};

	if (key_flag == FILE_SECE)
		len = len + PUB_KEY_LEN + PRIV_KEY_LEN;

	key_info.user_id = user;
	key_info.file_type = key_flag;
	key_info.magic_buf = magic;
	key_info.magic_len = sizeof(magic);
	key_info.key_buf = NULL;
	key_info.key_len = len;

	ret = msp_fbe_delete_key(&key_info);
	if (ret != MSP_SUCCESS) {
		tloge("%s: delete_key fail, 0x%x!\n", __func__, ret);
		return ret;
	}
	(void)file_encry_rpmb_delete(&key_info);
	return FILE_ENCRY_OK;
}

static uint32_t file_encry_split_pubkey(uint32_t file, uint32_t ufs_slot,
					uint8_t *key, uint32_t len,
					uint32_t *index)
{
	uint32_t ret;
	uint32_t idx;

	if (file != FILE_SECE)
		return FILE_ENCRY_OK;

	ret = file_encry_get_file_ready();
	if (ret != FILE_ENCRY_OK) {
		tloge("%s, init sfs fail 0x%x\n", __func__, ret);
		return ret;
	}

	idx = is_keypair_check(g_ufs_info[ufs_slot].user);
	/* not the first install, return */
	if (idx < MAX_SECE_NUM) {
		*index = idx;
		goto out;
	}

	/* If MSP is off line, we need to re-allocate the sece slot */
	idx = find_available_sece_stat();
	if (idx >= MAX_SECE_NUM) {
		tloge("%s, sece is full, ufs_slot 0x%x\n", __func__, ufs_slot);
		return FILE_ENCRY_ERROR_SECE_IS_FULL;
	}
	if (!file_encry_msp_available()) {
		/*
		 * If MSP offline, sece info had be restored in
		 * file_encry_get_file_ready, should not be here
		 */
		tloge("%s, error, should not be here\n", __func__);
		return FILE_ENCRY_ERROR_INPUT_FLAG;
	}
out:
	if (file_encry_msp_available()) {
		ret = memcpy_s(g_sece_info[idx].pubkey,
			       sizeof(g_sece_info[idx].pubkey),
			       key + KEY_LEN, len - KEY_LEN);
		if (ret != EOK) {
			tloge("%s, Memcpy pubkey fail\n", __func__);
			return FILE_ENCRY_ERROR_MEMCPY_FAIL;
		}
	} else {
		ret = file_encry_fetch_sfskey(g_fbe3_sece_info, &g_sece_info[idx],
					      sizeof(g_sece_info[idx]), idx);
		if (ret != FILE_ENCRY_OK) {
			tloge("%s, fetch keypair fail 0x%x\n", __func__, ret);
			return ret;
		}
	}
	*index = idx;
	g_sece_info[idx].user = g_ufs_info[ufs_slot].user;
	g_sece_info[idx].ufs_slot = ufs_slot;
	g_sece_info[idx].avail = SECE_KEY_AVAILABLE;
	return FILE_ENCRY_OK;
}

static uint32_t file_encry_fetch_ufskey(uint8_t *buf, uint32_t len,
					uint32_t ufs_slot, uint32_t *idx)
{
	uint32_t ret;
	uint32_t file = g_ufs_info[ufs_slot].file;

	if (file == FILE_DE || file == FILE_GLOBAL_DE)
		return file_encry_root_derive_key(g_ufs_info[ufs_slot].iv_value,
						  KEY_LEN, buf, len);

	if (!file_encry_msp_available())
		ret = file_encry_root_derive_key(g_ufs_info[ufs_slot].iv_value,
						 KEY_LEN, buf, len);
	else
		ret = file_encry_fetch_msp(ufs_slot, buf, len, file);

	if (ret != FILE_ENCRY_OK) {
		tloge("%s, fetch keys fail 0x%x\n", __func__, ret);
		return ret;
	}
	ret = file_encry_split_pubkey(file, ufs_slot, buf, len, idx);
	if (ret != FILE_ENCRY_OK) {
		tloge("%s, spilt pubkey fail\n", __func__);
		return ret;
	}
	return FILE_ENCRY_OK;
}

static uint32_t file_encry_encrypt_keys(uint8_t *buf, uint32_t len,
					struct aes_ccm *info)
{
	uint32_t ret;
	uint8_t kek[AES_KEK_LEN] = {0};
	struct aes_info input = {0};

	file_encry_gen_random(sizeof(info->iv), info->iv);
	ret = file_encry_root_derive_key(info->iv, sizeof(info->iv),
					 kek, sizeof(kek));
	if (ret != FILE_ENCRY_OK) {
		tloge("%s: derive KEK fail 0x%x\n", __func__, ret);
		return ret;
	}
	/*
	 * AES kek len = 48, used as:
	 * 0 - 31: key, len = AES_KEY_LEN
	 * 32 - 39: nonce, len = AES_NONCE_LEN
	 * 40 - 47: addition, len = AES_ADD_LEN
	 */
	input.magic = kek;
	input.magic_len = AES_KEY_LEN;
	input.nonce = &kek[AES_KEY_LEN];
	input.nonce_len = AES_NONCE_LEN;
	input.add = &kek[AES_KEY_LEN + AES_NONCE_LEN];
	input.add_len = AES_ADD_LEN;
	input.key = buf;
	input.key_len = len;
	input.tag = info->tag;
	input.tag_len = sizeof(info->tag);
	ret = file_encry_do_aes_ccm(TEE_MODE_ENCRYPT, input);
	if (ret != FILE_ENCRY_OK)
		tloge("%s: encrypt key fail 0x%x\n", __func__, ret);

	(void)memset_s(kek, sizeof(kek), 0, sizeof(kek));
	(void)memset_s(&input, sizeof(input), 0, sizeof(input));
	return ret;
}

static uint32_t file_encry_decrypt_keys(uint8_t *buf, uint32_t len,
					struct aes_ccm *info)
{
	uint32_t ret;
	uint8_t kek[AES_KEK_LEN] = {0};
	struct aes_info input = {0};

	ret = file_encry_root_derive_key(info->iv, sizeof(info->iv),
					 kek, sizeof(kek));
	if (ret != FILE_ENCRY_OK) {
		tloge("%s: derive KEK fail 0x%x\n", __func__, ret);
		return ret;
	}
	/*
	 * AES kek len = 48, used as:
	 * 0 - 31: key, len = AES_KEY_LEN
	 * 32 - 39: nonce, len = AES_NONCE_LEN
	 * 40 - 47: addition, len = AES_ADD_LEN
	 */
	input.magic = kek;
	input.magic_len = AES_KEY_LEN;
	input.nonce = &kek[AES_KEY_LEN];
	input.nonce_len = AES_NONCE_LEN;
	input.add = &kek[AES_KEY_LEN + AES_NONCE_LEN];
	input.add_len = AES_ADD_LEN;
	input.key = buf;
	input.key_len = len;
	input.tag = info->tag;
	input.tag_len = sizeof(info->tag);
	ret = file_encry_do_aes_ccm(TEE_MODE_DECRYPT, input);
	if (ret != FILE_ENCRY_OK)
		tloge("%s: decrypt key fail 0x%x\n", __func__, ret);

	(void)memset_s(kek, sizeof(kek), 0, sizeof(kek));
	(void)memset_s(&input, sizeof(input), 0, sizeof(input));
	return ret;
}

/* After AES-CCM, the output length is 64B even the input value is only 32B */
struct privkey_info {
	uint8_t privkey[KEY_LEN];
	struct aes_ccm tag_iv;
};

static uint32_t file_encry_encrypt_privkey(uint32_t index, uint8_t *buf,
					   uint32_t len)
{
	uint32_t ret;
	struct privkey_info info = {{0}, {{0}, {0}}};

	ret = memcpy_s(info.privkey, sizeof(info.privkey), buf, len);
	if (ret != EOK) {
		tloge("%s: copy privkey in fail 0x%x\n", __func__, ret);
		return FILE_ENCRY_ERROR_MEMCPY_FAIL;
	}
	ret = file_encry_encrypt_keys(info.privkey, sizeof(info.privkey),
				      &(info.tag_iv));
	if (ret != FILE_ENCRY_OK) {
		tloge("%s: derive KEK fail 0x%x\n", __func__, ret);
		return ret;
	}

	ret = file_encry_config_driver(idx_to_priv_write(index),
				       (uint8_t *)&info,
				       sizeof(info));
	if (ret != FILE_ENCRY_OK)
		tloge("%s: save IV fail 0x%x\n", __func__, ret);

	(void)memset_s(&info, sizeof(info), 0, sizeof(info));
	return ret;
}

static uint32_t file_encry_decrypt_privkey(uint32_t index, uint8_t *buf,
					   uint32_t len)
{
	uint32_t ret;
	uint32_t size;
	struct privkey_info info = {{0}, {{0}, {0}}};

	tlogd("%s, do decrypt\n", __func__);
	ret = file_encry_config_driver(idx_to_priv_read(index),
				       (uint8_t *)&info,
				       sizeof(info));
	if (ret != FILE_ENCRY_OK) {
		tloge("%s: read IV fail 0x%x\n", __func__, ret);
		return ret;
	}

	ret = file_encry_decrypt_keys(info.privkey, sizeof(info.privkey),
				      &(info.tag_iv));
	if (ret != FILE_ENCRY_OK) {
		tloge("%s, decrypt privkey fail 0x%x\n", __func__, ret);
		goto finish;
	}
	size = min(len, sizeof(info.privkey));
	ret = memcpy_s(buf, len, info.privkey, size);
	if (ret != EOK) {
		tloge("%s: copy privkey out fail 0x%x\n", __func__, ret);
		ret = FILE_ENCRY_ERROR_MEMCPY_FAIL;
		goto finish;
	}

	ret = FILE_ENCRY_OK;
finish:
	(void)memset_s(&info, sizeof(info), 0, sizeof(info));
	return ret;
}

static uint32_t file_encry_update_sfs(uint32_t file, uint32_t idx)
{
	uint32_t ret;

	if (file != FILE_SECE || idx >= MAX_SECE_NUM)
		return FILE_ENCRY_OK;

	tloge("%s, using sfs\n", __func__);
	ret = file_encry_store_sfs(g_fbe3_sece_info, &g_sece_info[idx],
				   sizeof(struct sece_info), idx);
	if (ret != FILE_ENCRY_OK) {
		tloge("%s, store sece to sfs fail 0x%x\n", __func__, ret);
		return ret;
	}
	/* IN PERFORMANCE: encrypt privkey in TA */
	ret = file_encry_encrypt_privkey(idx, g_sece_info[idx].privkey,
					 sizeof(g_sece_info[idx].privkey));
	/* Clear Privkey after using */
	(void)memset_s(g_sece_info[idx].privkey,
		       sizeof(g_sece_info[idx].privkey),
		       0, PRIV_KEY_LEN);
	return ret;
}

static uint32_t file_encry_get_sece_index(uint32_t user, uint32_t avail,
					  uint32_t *index)
{
	uint32_t idx;

	/* static function, ignore input check */
	for (idx = 0; idx < MAX_SECE_NUM; idx++) {
		if (g_sece_info[idx].user != user)
			continue;
		/*
		 * user 0 can be here without install SECE key,
		 * So, we need to double check the status
		 */
		if (g_sece_info[idx].avail == SECE_KEY_NONE)
			continue;
		break;
	}
	if (idx >= MAX_SECE_NUM) {
		tloge("%s, cannot find sece key, 0x%x\n", __func__, user);
		return FILE_ENCRY_ERROR_NO_SECE_KEY;
	}
	/* invalid request, the status is not the one we wanted */
	if (!(g_sece_info[idx].avail & avail)) {
		tloge("%s, sece key status is wrong 0x%x, 0x%x\n", __func__,
		      avail, g_sece_info[idx].avail);
		return FILE_ENCRY_ERROR_SECE_STATUS;
	}
	*index = idx;
	return FILE_ENCRY_OK;
}

static uint32_t file_encry_delete_sfs(uint32_t file, uint32_t idx)
{
	uint32_t ret;

	if (file != FILE_SECE || idx >= MAX_SECE_NUM)
		return FILE_ENCRY_OK;

	ret = file_encry_store_sfs(g_fbe3_sece_info, &g_sece_info[idx],
				   sizeof(struct sece_info), idx);
	if (ret != FILE_ENCRY_OK) {
		tloge("%s, delete sece in sfs fail 0x%x\n", __func__, ret);
		return ret;
	}

	return FILE_ENCRY_OK;
}

static uint32_t file_encry_clear_sece(uint32_t file, uint32_t user,
				      uint32_t ufs_slot, uint32_t *idx)
{
	uint32_t ret;
	uint32_t avail;
	uint32_t index = MAX_SECE_NUM;

	if (file != FILE_SECE)
		return FILE_ENCRY_OK;

	avail = SECE_KEY_SUSPEND | SECE_KEY_AVAILABLE | SECE_KEY_LOGOUT;
	/*
	 * if sece key is not installed && msp is offline
	 * sece info will be set by file_encry_get_file_ready
	 * or if sece key is installed
	 * we need to clean g_sece_info
	 */
	ret = file_encry_get_sece_index(user, avail, &index);
	/* No sece info, return success */
	if (ret == FILE_ENCRY_ERROR_NO_SECE_KEY) {
		tloge("%s, 0x%x sece is not installed\n", __func__, user);
		return FILE_ENCRY_OK;
	}
	if (ret != FILE_ENCRY_OK) {
		tloge("%s, get sece info fail 0x%x\n",
		      __func__, ret);
		return ret;
	}

	if (ufs_slot < MAX_KEY_NUM_SUPPORT &&
		g_sece_info[index].ufs_slot != ufs_slot) {
		tloge("%s, delete user 0x%x incorrect slot 0x%x VS 0x%x\n",
		      __func__, user, ufs_slot, g_sece_info[index].ufs_slot);
		return FILE_ENCRY_ERROR_INPUT_USER;
	}
	*idx = index;
	(void)memset_s(&g_sece_info[index], sizeof(g_sece_info[index]),
		       0, sizeof(g_sece_info[index]));
	tlogd("%s, clear sece info success 0x%x\n", __func__, index);
	return FILE_ENCRY_OK;
}

static uint32_t file_encry_delete_keys(uint32_t user, uint32_t file,
				       uint32_t ufs_slot)
{
	uint32_t ret;
	uint32_t idx = MAX_SECE_NUM;

	if (file == FILE_DE)
		return FILE_ENCRY_OK;

	ret = file_encry_clear_sece(file, user, ufs_slot, &idx);
	if (ret != FILE_ENCRY_OK) {
		tloge("%s, clear sece fail 0x%x\n", __func__, ret);
		return ret;
	}

	if (!file_encry_msp_available())
		ret = file_encry_delete_sfs(file, idx);
	else
		ret = file_encry_delete_msp(user, file);

	if (ret != FILE_ENCRY_OK) {
		tloge("%s, delete sece keys fail 0x%x\n", __func__, ret);
		return ret;
	}
	return FILE_ENCRY_OK;
}

static uint32_t file_encry_drive_ckey(uint32_t file, uint8_t *buf,
				      uint32_t len, uint8_t *iv)
{
	if (file == FILE_DE || file == FILE_GLOBAL_DE)
		return file_encry_root_derive_key(iv, len, buf, len);

	if (!file_encry_msp_available())
		return file_encry_root_derive_key(iv, len, buf, len);

	file_encry_gen_random(len, buf);
	return FILE_ENCRY_OK;
}

static uint32_t file_encry_drive_key2(uint32_t ufs_slot, uint8_t *iv_buf,
				      uint32_t length)
{
	uint32_t ret;
	uint8_t mk[KEY_LEN] = {0};

	ret = file_encry_root_derive_key(g_ufs_info[ufs_slot].iv_value, KEY_LEN,
					 mk, sizeof(mk));
	if (ret != FILE_ENCRY_OK) {
		tloge("%s: for key2, driver mk fail 0x%x\n", __func__, ret);
		return ret;
	}
	/* using the second drive as key2 */
	ret = file_encry_root_derive_key(mk, sizeof(mk), iv_buf, length);
	if (ret != FILE_ENCRY_OK) {
		tloge("%s: driver key2 fail 0x%x\n", __func__, ret);
		return ret;
	}
	iv_buf[length - 1] = (uint8_t)ufs_slot;
	return FILE_ENCRY_OK;
}

static uint32_t file_encry_drive_keypair(uint32_t user, uint32_t file,
					 uint32_t ufs_slot, uint32_t *index)
{
	uint32_t ret;
	uint32_t idx;

	if (file != FILE_SECE)
		return FILE_ENCRY_OK;

	ret = file_encry_get_file_ready();
	if (ret != FILE_ENCRY_OK)
		return ret;

	idx = is_keypair_check(user);
	if (idx < MAX_SECE_NUM) {
		/* not the first install, the input params is wrong */
		tloge("%s, input flag is wrong idx 0x%x\n", __func__, idx);
		return FILE_ENCRY_ERROR_INPUT_FLAG;
	}
	idx = find_available_sece_stat();
	if (idx >= MAX_SECE_NUM) {
		tloge("%s, sece is full, user 0x%x\n", __func__, user);
		return FILE_ENCRY_ERROR_SECE_IS_FULL;
	}
	/* Device keypair using HW to generate */
	ret = file_encry_keypair_using_hw(g_sece_info[idx].pubkey, PUB_KEY_LEN,
					  g_sece_info[idx].privkey, PRIV_KEY_LEN);
	if (ret != FILE_ENCRY_OK) {
		tloge("%s, ufs_slot 0x%x, gen_keypair\n", __func__, ret);
		return ret;
	}
#ifdef FILE_ENCRY_KEY_HASH_ENABLE
	ret = file_encry_hash_value(g_sece_info[idx].privkey, PRIV_KEY_LEN,
				    g_sece_info[idx].privkey_hash,
				    sizeof(g_sece_info[idx].privkey_hash));
	if (ret != FILE_ENCRY_OK) {
		tloge("%s, genetate hash fail 0x%x\n", __func__, ret);
		return ret;
	}
#endif
	*index = idx;
	g_sece_info[idx].user = user;
	g_sece_info[idx].avail = SECE_KEY_AVAILABLE;
	g_sece_info[idx].ufs_slot = ufs_slot;
	return ret;
}

static uint32_t file_encry_ufskey_slot(uint32_t user, uint32_t file,
				       uint32_t status)
{
	uint32_t slot;

	for (slot = 0; slot < MAX_KEY_NUM_SUPPORT; slot++) {
		if (g_ufs_info[slot].user == user &&
			g_ufs_info[slot].file == file &&
			(g_ufs_info[slot].status & status)) {
			break;
		}
	}
	return slot;
}

static void file_encry_clear_ufsc(uint32_t slot)
{
	uint8_t random[KEY_LEN] = {0};

	file_encry_gen_random(sizeof(random), random);
	/* clean ufsc */
	(void)file_encry_config_driver(slot, random, sizeof(random));
}

static uint32_t file_encry_restore_ckey(uint32_t ufs_slot, uint32_t *idx,
					uint32_t flag __unused)
{
	uint32_t ret;
	uint32_t file = g_ufs_info[ufs_slot].file;
	uint32_t len = KEY_LEN;
	uint8_t *key = NULL;

	/* if file type == SECE, fetch pubkey with ckey in msp */
	if (file == FILE_SECE && file_encry_msp_available())
		len = len + PUB_KEY_LEN;
	key = (uint8_t *)TEE_Malloc(len, 0);
	if (!key) {
		tloge("%s, alloc key buffer failed\n", __func__);
		return FILE_ENCRY_ERROR_OUT_OF_MEM;
	}

	ret = file_encry_fetch_ufskey(key, len, ufs_slot, idx);
	if (ret != FILE_ENCRY_OK) {
		tloge("%s: fetch ckey fail\n", __func__);
		goto out;
	}
#ifdef FILE_ENCRY_KEY_HASH_ENABLE
	if (flag == HASH_VERIFY)
		ret = file_encry_verify_hash(key, KEY_LEN,
					     g_ufs_info[ufs_slot].ckey_hash,
					     sizeof(g_ufs_info[ufs_slot].ckey_hash));
	else
		ret = file_encry_hash_value(key, KEY_LEN,
					    g_ufs_info[ufs_slot].ckey_hash,
					    sizeof(g_ufs_info[ufs_slot].ckey_hash));
       if (ret != FILE_ENCRY_OK) {
               tloge("%s, do hash fail 0x%x\n", __func__, ret);
               goto out;
       }
#endif
	ret = file_encry_config_driver(ufs_slot, key, KEY_LEN);
	if (ret != FILE_ENCRY_OK) {
		tloge("%s, config slot 0x%x fail 0x%x\n", __func__, ufs_slot, ret);
		goto out;
	}
	ret = memcpy_s(g_ufs_info[ufs_slot].ckey,
		       sizeof(g_ufs_info[ufs_slot].ckey),
		       key, KEY_LEN);
	if (ret != EOK) {
		tloge("%s, copy ckey fail 0x%x\n", __func__, ret);
		ret = FILE_ENCRY_ERROR_MEMCPY_FAIL;
		goto out;
	}
	ret = FILE_ENCRY_OK;
out:
	(void)memset_s(key, len, 0, len);
	TEE_Free(key);
	return ret;
}

#ifdef FILE_ENCRY_LOCK_ECE
static uint32_t file_encry_suspend_ece(uint32_t user)
{
	uint32_t ret;
	uint32_t slot;
	uint32_t status = UFS_KEY_USING | UFS_KEY_SUSPEND;
	uint8_t random[KEY_LEN] = {0};

	slot = file_encry_ufskey_slot(user, FILE_ECE, status);
	if (slot >= MAX_KEY_NUM_SUPPORT) {
		tloge("%s, user 0x%x, ece key not installed\n", __func__, user);
		return FILE_ENCRY_OK;
	}

	file_encry_gen_random(sizeof(random), random);

	/* clear ece key */
	ret = file_encry_config_driver(slot, random, sizeof(random));
	if (ret != FILE_ENCRY_OK) {
		tloge("%s, clear ece ckey fail 0x%x\n", __func__, ret);
		return ret;
	}
	g_ufs_info[slot].status = UFS_KEY_SUSPEND;
	ret = file_encry_config_driver(idx_to_ufs_slot(slot),
				       (uint8_t *)&g_ufs_info[slot],
				       sizeof(g_ufs_info[slot]));
	if (ret != FILE_ENCRY_OK)
		tloge("%s, update keyinfo fail 0x%x\n", __func__, ret);

	return ret;
}
#else
static uint32_t file_encry_suspend_ece(uint32_t user __unused)
{
	return FILE_ENCRY_OK;
}
#endif

static uint32_t file_encry_suspend_keypair(uint32_t request, uint32_t user,
					   uint32_t avail)
{
	uint32_t ret;
	uint32_t ufs_slot;
	uint32_t index = MAX_SECE_NUM;
	uint32_t status = UFS_KEY_USING | UFS_KEY_SUSPEND;

	ufs_slot = file_encry_ufskey_slot(user, FILE_SECE, status);
	if (ufs_slot >= MAX_KEY_NUM_SUPPORT) {
		tloge("%s, user 0x%x sece key is not installed\n",
		      __func__, user);
		return FILE_ENCRY_OK;
	}
	ret = file_encry_get_sece_index(user, avail, &index);
	if (ret != FILE_ENCRY_OK || index >= MAX_SECE_NUM) {
		tloge("%s, cannot find sece info 0x%x\n", __func__, ret);
		return ret;
	}

	g_sece_info[index].avail = SECE_KEY_SUSPEND;
	/* do not clean SECE in driver if user is lock */
	if (request == USER_LOCK)
		return FILE_ENCRY_OK;

	/*
	 * clean SECE Privkey in driver if user is logout
	 * Note: DO NOT clean g_sece_info[index] to 0!!
	 */
	g_sece_info[index].avail = SECE_KEY_LOGOUT;
	(void)memset_s(g_sece_info[index].privkey,
		       sizeof(g_sece_info[index].privkey),
		       0, sizeof(g_sece_info[index].privkey));
	tlogd("%s, user 0x%x logout, clean sece in driver 0x%x\n",
	      __func__, user, index);
	(void)file_encry_config_driver(idx_to_priv_clean(index),
				       (uint8_t *)&g_sece_info[index],
				       sizeof(g_sece_info[index]));
	return FILE_ENCRY_OK;
}

static uint32_t file_encry_resume_keypair(uint32_t user)
{
	uint32_t ret;
	uint32_t ufs_slot;
	uint32_t status = UFS_KEY_USING | UFS_KEY_SUSPEND;
	uint32_t index = MAX_SECE_NUM;

	ufs_slot = file_encry_ufskey_slot(user, FILE_SECE, status);
	if (ufs_slot >= MAX_KEY_NUM_SUPPORT) {
		tloge("%s, user 0x%x sece key is not installed\n",
		      __func__, user);
		return FILE_ENCRY_OK;
	}
	status = SECE_KEY_SUSPEND | SECE_KEY_AVAILABLE;
	ret = file_encry_get_sece_index(user, status, &index);
	if (ret != FILE_ENCRY_OK || index >= MAX_SECE_NUM) {
		tloge("%s, cannot find sece info 0x%x\n", __func__, ret);
		return ret;
	}

	g_sece_info[index].avail = SECE_KEY_AVAILABLE;
	return FILE_ENCRY_OK;
}

static uint32_t file_encry_pack_keys(uint32_t file, uint32_t ufs_slot,
				     uint32_t idx, uint8_t *buf)
{
	errno_t rc;

	rc = memcpy_s(buf, KEY_LEN, g_ufs_info[ufs_slot].ckey,
		      sizeof(g_ufs_info[ufs_slot].ckey));
	if (rc != EOK) {
		tloge("copy ckey failed, rc 0x%x\n", rc);
		return FILE_ENCRY_ERROR_MEMCPY_FAIL;
	}
	if (file != FILE_SECE)
		return FILE_ENCRY_OK;

	/*
	 * if file == SECE, we need to repack the key buffer
	 * key[KEY_LEN] + pubkey[PUB_KEY_LEN] + prikey[PRIV_KEY_LEN]
	 */
	if (idx >= MAX_SECE_NUM) {
		tloge("%s, invalid sece index input 0x%x\n", __func__, idx);
		return FILE_ENCRY_ERROR_SECE_INDEX;
	}

	rc = memcpy_s(buf + KEY_LEN, PUB_KEY_LEN,
		      g_sece_info[idx].pubkey,
		      sizeof(g_sece_info[idx].pubkey));
	if (rc != EOK) {
		tloge("copy pubkey failed, rc 0x%x\n", rc);
		return FILE_ENCRY_ERROR_MEMCPY_FAIL;
	}
	rc = memcpy_s(buf + KEY_LEN + PUB_KEY_LEN, PRIV_KEY_LEN,
		      g_sece_info[idx].privkey,
		      sizeof(g_sece_info[idx].privkey));
	if (rc != EOK) {
		tloge("copy privkey failed, rc 0x%x\n", rc);
		return FILE_ENCRY_ERROR_MEMCPY_FAIL;
	}

	return FILE_ENCRY_OK;
}

static uint32_t file_encry_split_keypair(uint32_t file, uint8_t *key,
					 uint32_t index)
{
	uint32_t ret;

	if (file != FILE_SECE || index >= MAX_SECE_NUM)
		return FILE_ENCRY_OK;

	ret = memcpy_s(g_sece_info[index].pubkey,
		       sizeof(g_sece_info[index].pubkey),
		       key + KEY_LEN, PUB_KEY_LEN);
	if (ret != EOK) {
		tloge("%s, Memcpy pubkey fail\n", __func__);
		return FILE_ENCRY_ERROR_MEMCPY_FAIL;
	}
	/* Encrypt Privkey directly */
	ret = file_encry_encrypt_privkey(index, &key[KEY_LEN + PUB_KEY_LEN],
					 PRIV_KEY_LEN);
	if (ret != FILE_ENCRY_OK) {
		tloge("%s, encrypt privkey fail 0x%x", __func__, ret);
		return ret;
	}

	/* Clear Privkey after using */
	(void)memset_s(g_sece_info[index].privkey,
		       sizeof(g_sece_info[index].privkey),
		       0, PRIV_KEY_LEN);
	return FILE_ENCRY_OK;
}

/* keys could be update in file_encry_update_keys */
static uint32_t file_encry_update_keys(uint32_t file, uint32_t ufs_slot,
				       uint32_t idx)
{
	uint32_t ret;
	uint32_t len = KEY_LEN;
	uint8_t *buf = NULL;

	if (file == FILE_SECE)
		len += PUB_KEY_LEN + PRIV_KEY_LEN;
	buf = (uint8_t *)TEE_Malloc(len, 0);
	if (!buf) {
		tloge("alloc buf for sece keys failed\n");
		return FILE_ENCRY_ERROR_OUT_OF_MEM;
	}

	ret = file_encry_pack_keys(file, ufs_slot, idx, buf);
	if (ret != FILE_ENCRY_OK) {
		tloge("%s, pack keys fail 0x%x\n", __func__, ret);
		goto out;
	}

	ret = file_encry_update_msp(ufs_slot, file, buf, len);
	if (ret != FILE_ENCRY_OK) {
		tloge("%s, save to msp fail 0x%x\n", __func__, ret);
		goto out;
	}
	ret = file_encry_split_keypair(file, buf, idx);
	if (ret != FILE_ENCRY_OK) {
		tloge("%s, split keypair fail 0x%x\n", __func__, ret);
		goto out;
	}
	ret = file_encry_config_driver(ufs_slot, buf, KEY_LEN);
	if (ret != FILE_ENCRY_OK) {
		tloge("%s, config ufsc fail 0x%x\n", __func__, ret);
		goto out;
	}
	ret = memcpy_s(g_ufs_info[ufs_slot].ckey,
		       sizeof(g_ufs_info[ufs_slot].ckey),
		       buf, KEY_LEN);
	if (ret != EOK) {
		tloge("%s, copy original ckey fail 0x%x\n", __func__, ret);
		ret = FILE_ENCRY_ERROR_MEMCPY_FAIL;
		goto out;
	}
	ret = FILE_ENCRY_OK;
out:
	(void)memset_s(buf, len, 0, len);
	TEE_Free(buf);
	return ret;
}
static uint32_t file_encry_config_keys(uint32_t file, uint32_t ufs_slot,
				       uint32_t idx)
{
	uint32_t ret;

	if (file == FILE_DE || file == FILE_GLOBAL_DE)
		return file_encry_config_driver(ufs_slot, g_ufs_info[ufs_slot].ckey,
						KEY_LEN);

	if (file_encry_msp_available())
		return file_encry_update_keys(file, ufs_slot, idx);

	/* if msp is invalid, using sfs */
	ret = file_encry_config_driver(ufs_slot, g_ufs_info[ufs_slot].ckey,
				       KEY_LEN);
	if (ret != FILE_ENCRY_OK) {
		tloge("%s, config ckey fail 0x%x\n", __func__, ret);
		return ret;
	}
	ret = file_encry_update_sfs(file, idx);
	if (ret != FILE_ENCRY_OK) {
		tloge("%s, update sfs fail 0x%x\n", __func__, ret);
		return ret;
	}

	return FILE_ENCRY_OK;
}

static uint32_t file_encry_config_slot(uint32_t user, uint32_t file,
				       uint8_t *iv_buf, uint32_t iv_len,
				       uint32_t *slot)
{
	uint32_t ret;
	uint32_t new_slot;

	new_slot = find_available_ufs_slot();
	if (new_slot >= MAX_KEY_NUM_SUPPORT) {
		/* no empty new_slot, ufs key full */
		tloge("%s: ufs_key is full!\n", __func__);
		return FILE_ENCRY_ERROR_CKEY_IS_FULL;
	}
	/* find the empty one */
	g_ufs_info[new_slot].user = user;
	g_ufs_info[new_slot].file = file;
	ret = memcpy_s(g_ufs_info[new_slot].iv_value, KEY_LEN, iv_buf, iv_len);
	if (ret != EOK) {
		tloge("%s: memcpy fail, 0x%x!\n", __func__, ret);
		return FILE_ENCRY_ERROR_MEMCPY_FAIL;
	}
	*slot = new_slot;
	return FILE_ENCRY_OK;
}

static uint32_t file_encry_restore_privkey(uint32_t file, uint32_t ufs_slot,
					   uint32_t idx)
{
	uint32_t ret = FILE_ENCRY_OK;

	if (file != FILE_SECE || idx >= MAX_SECE_NUM)
		return ret;
	/*
	 * MSP invalid: privkey had been restored in file_encry_split_pubkey
	 * MSP valid: fetch privkey from MSP
	 * and encrypt privkey
	 */
	if (file_encry_msp_available())
		ret = file_encry_fetch_msp(ufs_slot, g_sece_info[idx].privkey,
					   sizeof(g_sece_info[idx].privkey),
					   FILE_PRIV);
	if (ret != FILE_ENCRY_OK) {
		tloge("%s, fetch privkey in MSP fail 0x%s\n", __func__, ret);
		return ret;
	}
	ret = file_encry_encrypt_privkey(idx, g_sece_info[idx].privkey,
					 sizeof(g_sece_info[idx].privkey));
	/* Clear privkey in TA after using */
	(void)memset_s(g_sece_info[idx].privkey,
		       sizeof(g_sece_info[idx].privkey),
		       0, PRIV_KEY_LEN);
	return ret;
}
/*
 * This is for install class key(Rebooting)
 * 1. driver key2 for output to vold
 * 2. restore class key
 */
static uint32_t file_encry_rebooting_add(uint32_t user, uint32_t file,
					 uint8_t *iv_buf, uint32_t iv_len,
					 uint32_t *slot)
{
	uint32_t ret;
	uint32_t idx = MAX_SECE_NUM;
	uint32_t ufs_slot = MAX_KEY_NUM_SUPPORT;
	uint32_t hash_tag = HASH_VERIFY;

	/* the params had been checked */
	ret = file_encry_first_ivadd(user, file, iv_buf, iv_len, &ufs_slot);
	if (ret != FILE_ENCRY_OK) {
		tloge("%s, iv check fail 0x%x\n", __func__, ret);
		return ret;
	}

	if (ufs_slot >= MAX_KEY_NUM_SUPPORT) {
		tlogd("%s, first unlock user 0x%x, file 0x%x\n",
		      __func__, user, file);
		/* return value can make sure slot < MAX_KEY_NUM_SUPPORT */
		ret = file_encry_config_slot(user, file, iv_buf,
					     iv_len, &ufs_slot);
		if (ret != FILE_ENCRY_OK) {
			tloge("%s, alloc new slot fail 0x%x\n", __func__, ret);
			return ret;
		}
		hash_tag = 0;
	}
	ret = file_encry_restore_ckey(ufs_slot, &idx, hash_tag);
	if (ret != FILE_ENCRY_OK) {
		tloge("%s: config ckey fail 0x%x, file 0x%x.\n",
		      __func__, ret, file);
		goto error;
	}
	ret = file_encry_drive_key2(ufs_slot, iv_buf, iv_len);
	if (ret != FILE_ENCRY_OK) {
		tloge("%s: config key2 fail 0x%x, file 0x%x\n",
		      __func__, ret, file);
		goto error;
	}
	ret = file_encry_restore_privkey(file, ufs_slot, idx);
	if (ret != FILE_ENCRY_OK) {
		tloge("%s: restore privkey fail 0x%x, idx 0x%x\n",
		      __func__, ret, idx);
		goto error;
	}
	*slot = ufs_slot;
	return FILE_ENCRY_OK;
error:
	file_encry_clear_ufsc(ufs_slot);
	(void)memset_s(&g_ufs_info[ufs_slot], sizeof(g_ufs_info[ufs_slot]),
		       0, sizeof(g_ufs_info[ufs_slot]));
	return ret;
}

/*
 * This is for install class key(New user)
 * 1. drive and config class key to ufs
 * 2. driver key2 for output to vold
 * 3. if file == SECE, drive key pair
 */
static uint32_t file_encry_booting_add(uint32_t user, uint32_t file,
				       uint8_t *iv_buf, uint32_t len,
				       uint32_t *slot)
{
	uint32_t ret;
	uint32_t new_slot = MAX_KEY_NUM_SUPPORT;
	uint32_t index = MAX_SECE_NUM;

	/* the params had been checked */
	ret = file_encry_first_ivadd(user, file, iv_buf, len, &new_slot);
	if (ret != FILE_ENCRY_OK) {
		tloge("%s, iv check error, ret 0x%x\n", __func__, ret);
		return ret;
	}
	if (new_slot != MAX_KEY_NUM_SUPPORT) {
		tloge("%s, flag is error, slot 0x%x\n", __func__, new_slot);
		return FILE_ENCRY_ERROR_INPUT_FLAG;
	}
	/* The return value can make sure new_slot < MAX_KEY_NUM_SUPPORT */
	ret = file_encry_config_slot(user, file, iv_buf, len, &new_slot);
	if (ret != FILE_ENCRY_OK) {
		tloge("%s, alloc new slot fail 0x%x\n", __func__, ret);
		return ret;
	}
	ret = file_encry_drive_keypair(user, file, new_slot, &index);
	/* The return value can make sure index < MAX_SECE_NUM */
	if (ret != FILE_ENCRY_OK) {
		tloge("%s: drive keypair fail 0x%x\n", __func__, ret);
		goto error1;
	}
	ret = file_encry_drive_ckey(file, g_ufs_info[new_slot].ckey,
				    KEY_LEN, iv_buf);
	if (ret != FILE_ENCRY_OK) {
		tloge("%s: derive ckey fail 0x%x.\n", __func__, ret);
		goto error2;
	}
	ret = file_encry_drive_key2(new_slot, iv_buf, len);
	if (ret != FILE_ENCRY_OK) {
		tloge("%s: config key2 fail\n", __func__);
		goto error2;
	}
	ret = file_encry_config_keys(file, new_slot, index);
	if (ret != FILE_ENCRY_OK) {
		tloge("%s: save keys fail 0x%x\n", __func__, ret);
		goto error2;
	}
	*slot = new_slot;
	return ret;
error2:
	if (index < MAX_SECE_NUM)
		(void)memset_s(&g_sece_info[index], sizeof(g_sece_info[index]),
			       0, sizeof(g_sece_info[index]));
error1:
	file_encry_clear_ufsc(new_slot);
	(void)memset_s(&g_ufs_info[new_slot], sizeof(g_ufs_info[new_slot]),
		       0, sizeof(g_ufs_info[new_slot]));
	return ret;
}

static uint32_t file_encry_encrypt_ckey(uint32_t file, uint32_t slot)
{
	uint32_t ret;
	struct aes_ccm ccm_info = {{0}, {0}};

	/* DE and global DE key and no msp do not need to be encrypted in TA */
	if (file == FILE_DE || file == FILE_GLOBAL_DE ||
		!file_encry_msp_available()) {
		/* Clear CKEY in TEEOS */
		(void)memset_s(g_ufs_info[slot].ckey,
			       sizeof(g_ufs_info[slot].ckey),
			       0, KEY_LEN);
		return FILE_ENCRY_OK;
	}
	/* MSP is on line, and keys stored in MSP */
	ret = file_encry_encrypt_keys(g_ufs_info[slot].ckey,
				      sizeof(g_ufs_info[slot].ckey),
				      &ccm_info);
	if (ret != FILE_ENCRY_OK) {
		tloge("%s: encrypt key fail 0x%x\n", __func__, ret);
		goto finish;
	}
	ret = file_encry_config_driver(idx_to_iv_write(slot),
				       (uint8_t *)&ccm_info,
				       sizeof(ccm_info));
	if (ret != FILE_ENCRY_OK)
		tloge("%s: save IV fail 0x%x\n", __func__, ret);

finish:
	(void)memset_s(&ccm_info, sizeof(ccm_info), 0, sizeof(ccm_info));
	return ret;
}

static uint32_t file_encry_decrypt_ckey(uint32_t slot)
{
	uint32_t ret;
	uint32_t file = g_ufs_info[slot].file;
	struct aes_ccm ccm_info = {{0}, {0}};

	/* DE and global DE key do not need to be decrypted in TA */
	if (file == FILE_DE || file == FILE_GLOBAL_DE)
		return file_encry_root_derive_key(g_ufs_info[slot].iv_value,
						  sizeof(g_ufs_info[slot].iv_value),
						  g_ufs_info[slot].ckey,
						  sizeof(g_ufs_info[slot].ckey));
	/* if MSP is invalid, do not need to decrypt keys */
	if (!file_encry_msp_available())
		return file_encry_root_derive_key(g_ufs_info[slot].iv_value,
						  sizeof(g_ufs_info[slot].iv_value),
						  g_ufs_info[slot].ckey,
						  sizeof(g_ufs_info[slot].ckey));
	/* MSP is on line, and keys stored in MSP */
	tlogd("%s, do decrypt\n", __func__);
	ret = file_encry_config_driver(idx_to_iv_read(slot),
				       (uint8_t *)&ccm_info,
				       sizeof(ccm_info));
	if (ret != FILE_ENCRY_OK) {
		tloge("%s: read IV fail 0x%x\n", __func__, ret);
		return ret;
	}
	ret = file_encry_config_driver(idx_to_ckey_read(slot),
				       g_ufs_info[slot].ckey,
				       sizeof(g_ufs_info[slot].ckey));
	if (ret != FILE_ENCRY_OK) {
		tloge("%s: read encrypt ckey 0x%x\n", __func__, ret);
		goto finish;
	}

	ret = file_encry_decrypt_keys(g_ufs_info[slot].ckey,
				      sizeof(g_ufs_info[slot].ckey),
				      &ccm_info);
	if (ret != FILE_ENCRY_OK)
		tloge("%s: decrypt ckey fail 0x%x\n", __func__, ret);
finish:
	(void)memset_s(&ccm_info, sizeof(ccm_info), 0, sizeof(ccm_info));
	return ret;
}

#ifdef FILE_ENCRY_LOCK_ECE
static uint32_t file_encry_resume_ece(uint32_t user, uint8_t *iv_buf,
				      uint32_t length)
{
	uint32_t ret;
	uint32_t ufs_slot;
	uint32_t idx;
	uint32_t status = UFS_KEY_USING | UFS_KEY_SUSPEND;

	ufs_slot = file_encry_ufskey_slot(user, FILE_ECE, status);
	if (ufs_slot >= MAX_KEY_NUM_SUPPORT) {
		tloge("%s, user 0x%x, ece key not installed\n", __func__, user);
		return FILE_ENCRY_OK;
	}

	ret = file_encry_restore_ckey(ufs_slot, &idx, HASH_VERIFY);
	if (ret != FILE_ENCRY_OK) {
		tloge("%s, resume ece fail, ret 0x%x\n", __func__, ret);
		goto out;
	}

	ret = file_encry_drive_key2(ufs_slot, iv_buf, length);
	if (ret != FILE_ENCRY_OK) {
		tloge("%s, drive key2 fail ret 0x%x\n", __func__, ret);
		goto out;
	}
	ret = file_encry_encrypt_ckey(FILE_ECE, ufs_slot);
	if (ret != FILE_ENCRY_OK) {
		tloge("%s, encrypt ckey fail 0x%x\n", __func__, ret);
		goto out;
	}
	g_ufs_info[ufs_slot].status = UFS_KEY_USING;
	ret = file_encry_config_driver(idx_to_ufs_slot(ufs_slot),
				       (uint8_t *)&g_ufs_info[ufs_slot],
				       sizeof(g_ufs_info[ufs_slot]));
	if (ret != FILE_ENCRY_OK) {
		tloge("%s, update keyinfo fail 0x%x\n", __func__, ret);
		goto out;
	}
	return FILE_ENCRY_OK;
out:
	file_encry_clear_ufsc(ufs_slot);
	return ret;
}
#else
static uint32_t file_encry_resume_ece(uint32_t user, uint8_t *iv_buf,
				      uint32_t length)
{
	uint32_t ret;
	uint32_t ufs_slot;
	uint32_t status = UFS_KEY_USING;

	ufs_slot = file_encry_ufskey_slot(user, FILE_ECE, status);
	if (ufs_slot >= MAX_KEY_NUM_SUPPORT) {
		tloge("%s, user 0x%x, ece key not installed\n", __func__, user);
		return FILE_ENCRY_OK;
	}

	ret = file_encry_drive_key2(ufs_slot, iv_buf, length);
	if (ret != FILE_ENCRY_OK) {
		tloge("%s, drive key2 fail ret 0x%x\n", __func__, ret);
		return ret;
	}

	return FILE_ENCRY_OK;
}
#endif

static uint32_t file_encry_params_check(uint32_t file, uint8_t *iv_buf,
					uint32_t length)
{
	if (!iv_buf || length != KEY_LEN) {
		tloge("%s: input error, len 0x%x, file 0x%x\n",
		      __func__, length, file);
		return FILE_ENCRY_ERROR_INPUT_BUFFER;
	}

	return is_invalid_file_type(file);
}

static uint32_t file_encry_params_check_del(uint32_t user, uint32_t file,
					    uint8_t *iv_buf, uint32_t length)
{
	if (user == MAIN_USER_ID) {
		tloge("%s, cannot delete user 0\n", __func__);
		return FILE_ENCRY_ERROR_DELETE_MAINID;
	}

	return file_encry_params_check(file, iv_buf, length);
}

static uint32_t file_encry_addkey_check(uint32_t user, uint32_t file,
					uint8_t *iv_buf, uint32_t length)
{
	if (!iv_buf || length != KEY_LEN) {
		tloge("%s: input error, len 0x%x, file 0x%x\n",
		      __func__, length, file);
		return FILE_ENCRY_ERROR_INPUT_BUFFER;
	}
	if (user == 0 && file == FILE_GLOBAL_DE) {
		tlogd("This is global de key\n");
		return FILE_ENCRY_OK;
	}

	return is_invalid_file_type(file);
}

static uint32_t file_encry_params_check2(uint32_t slot, uint8_t *pubkey,
					 uint32_t key_len, uint8_t *metadata,
					 uint32_t iv_len)
{
	if (slot >= MAX_KEY_NUM_SUPPORT) {
		tloge("%s, ufs slot is wrong 0x%x.\n", __func__, slot);
		return FILE_ENCRY_ERROR_INPUT_SLOT;
	}
	if (!pubkey || !metadata) {
		tloge("%s, input buff is null.\n", __func__);
		return FILE_ENCRY_ERROR_BUFFER_FROMCA;
	}
	if (key_len != PUB_KEY_LEN || iv_len != MATA_LEN) {
		tloge("%s, input keylen 0x%x, ivlen 0x%x.\n",
		      __func__, key_len, iv_len);
		return FILE_ENCRY_ERROR_LENGTH_FROMCA;
	}
	return FILE_ENCRY_OK;
}

static uint32_t file_encry_check_iv_value(uint8_t *iv_buf, uint32_t len,
					  uint32_t slot)
{
	if (memcmp(iv_buf, g_ufs_info[slot].iv_value, len)) {
		tloge("%s, iv error, cannot logout slot 0x%x\n",
		      __func__, slot);
		return FILE_ENCRY_ERROR_IV_VALUE;
	}
	return FILE_ENCRY_OK;
}

/*
 * if you want to logout ECE or SECE key, CE key must be logout first
 * This function is called by logout only
 */
static uint32_t file_encry_check_status(uint32_t user, uint32_t file)
{
	uint32_t avail;
	uint32_t slot;

	/* user CE key must logout first */
	slot = file_encry_ufskey_slot(user, FILE_CE, UFS_KEY_LOGOUT);
	if (slot >= MAX_KEY_NUM_SUPPORT) {
		tloge("%s, user 0x%x cekey is not logout\n", __func__, user);
		return FILE_ENCRY_ERROR_CKEY_STATUS;
	}
	avail = SECE_KEY_AVAILABLE | SECE_KEY_SUSPEND;
	/* if file is SECE, need to clean privkey info in Driver too */
	if (file == FILE_SECE)
		return file_encry_suspend_keypair(USER_LOGOUT, user, avail);

	return FILE_ENCRY_OK;
}

static uint32_t file_encry_check_magic(uint8_t *iv_buf, uint32_t len,
				       uint32_t slot)
{
	uint32_t ret;

	ret = file_encry_check_iv_value(iv_buf, len, slot);
	if (ret == FILE_ENCRY_OK) {
		tloge("%s, iv check success, delete slot 0x%x\n",
		      __func__, slot);
		return ret;
	}

	/* If IV check fail, check the magic number */
	if (iv_buf[0] != IV_MAGIC0 || iv_buf[1] != IV_MAGIC1) {
		tloge("%s, user magic fail\n", __func__);
		return FILE_ENCRY_ERROR_MAGIC_NUM;
	}
	tloge("%s, check magic success\n", __func__);
	return FILE_ENCRY_OK;
}

uint32_t file_encry_rpmb_times(void)
{
	/*
	 * u32 ret = ((u16 << U16_SHIFT) | u16) is:
	 * upper 16 bits indicate the number of storage switching times
	 * lower 16 bits indicate the number of rpmb reading times
	 */
	uint32_t ret = (g_read_switch << U16_SHIFT) | g_fetch_rpmb;

	g_fetch_rpmb = 0;
	/* clean g_read_switch, but keep it as "from RPMB" or "from MSP" */
	g_read_switch &= 0x1;
	return ret;
}

uint32_t file_encry_enable_kdf_ta(void)
{
	uint8_t magic = IV_MAGIC0;

	return file_encry_config_driver(FILE_ENCRY_ENABLE_KDF, &magic,
					sizeof(magic));
}

uint32_t file_encry_prefetch_key(uint32_t user)
{
	uint32_t ret;

	if (!file_encry_msp_available()) {
		tloge("%s, msp is offline\n", __func__);
		return FILE_ENCRY_OK;
	}

	ret = msp_fbe_prefetch_key(user);
	if (ret != MSP_SUCCESS) {
		tloge("%s, prefetch 0x%x fail 0x%x\n", __func__, user, ret);
		return ret;
	}
	tloge("%s, prefetch 0x%x status 0x%x\n", __func__, user, ret);
	return FILE_ENCRY_OK;
}

uint32_t file_encry_restore_iv(void)
{
	uint32_t ret;
	uint32_t ufs_slot;
	uint32_t count = 0;

	for (ufs_slot = 0; ufs_slot < MAX_KEY_NUM_SUPPORT; ufs_slot++) {
		if (g_ufs_info[ufs_slot].status != UFS_KEY_USING)
			continue;
		ret = file_encry_decrypt_ckey(ufs_slot);
		if (ret != FILE_ENCRY_OK) {
			tloge("%s: decrypt ckey fail 0x%x.\n", __func__, ret);
			return ret;
		}
		ret = file_encry_config_driver(ufs_slot, g_ufs_info[ufs_slot].ckey,
					       sizeof(g_ufs_info[ufs_slot].ckey));
		(void)memset_s(g_ufs_info[ufs_slot].ckey,
			       sizeof(g_ufs_info[ufs_slot].ckey),
			       0, sizeof(g_ufs_info[ufs_slot].ckey));
		if (ret != FILE_ENCRY_OK) {
			tloge("%s: config ckey to ufsc 0x%x\n", __func__, ret);
			return ret;
		}
		count += 1;
	}
	tlogd("restore key finish, 0x%x\n", count);
	return FILE_ENCRY_OK;
}

uint32_t file_encry_lock_screen(uint32_t user, uint32_t file)
{
	uint32_t avail = SECE_KEY_AVAILABLE | SECE_KEY_SUSPEND;

	tlogd("%s user 0x%x, file 0x%x\n", __func__, user, file);
	/* invalid sece privkey */
	if (file == FILE_SECE)
		return file_encry_suspend_keypair(USER_LOCK, user, avail);

	if (file == FILE_ECE)
		return file_encry_suspend_ece(user);
	tloge("%s, unsupported file type 0x%x\n", __func__, file);
	return FILE_ENCRY_ERROR_FILE_TYPE;
}

uint32_t file_encry_unlock_screen(uint32_t user, uint32_t file,
				  uint8_t *iv_buf, uint32_t length)
{
	uint32_t ret;

	tlogd("%s user 0x%x, file 0x%x\n", __func__, user, file);
	ret = file_encry_params_check(file, iv_buf, length);
	if (ret != FILE_ENCRY_OK) {
		tloge("%s, check params fail 0x%x\n", __func__, ret);
		return ret;
	}

	if (file != FILE_ECE) {
		tloge("%s, unsupported file type 0x%x\n", __func__, file);
		return FILE_ENCRY_ERROR_FILE_TYPE;
	}

	ret = file_encry_resume_keypair(user);
	if (ret != FILE_ENCRY_OK) {
		tloge("%s, resume keypair fail 0x%x\n", __func__, ret);
		return ret;
	}

	ret = file_encry_resume_ece(user, iv_buf, length);
	if (ret != FILE_ENCRY_OK) {
		tloge("%s, resume ece fail 0x%x\n", __func__, ret);
		return ret;
	}

	return FILE_ENCRY_OK;
}

uint32_t file_encry_user_logout(uint32_t user, uint32_t file,
				uint8_t *iv_buf, uint32_t length)
{
	uint32_t ret;
	uint32_t ufs_slot = MAX_KEY_NUM_SUPPORT;
	uint8_t ckey[KEY_LEN] = {0};
	uint32_t status = UFS_KEY_USING | UFS_KEY_SUSPEND;

	ret = file_encry_params_check(file, iv_buf, length);
	if (ret != FILE_ENCRY_OK) {
		tloge("%s, check params fail 0x%x\n", __func__, ret);
		return ret;
	}

	if (file == FILE_DE) {
		tloge("%s, de key cannot be logout, 0x%x\n", __func__, user);
		return FILE_ENCRY_ERROR_INVALID_LOGOUT;
	}

	ufs_slot = file_encry_ufskey_slot(user, file, status);
	if (ufs_slot >= MAX_KEY_NUM_SUPPORT) {
		tloge("%s, user 0x%x key 0x%x not found\n",
		      __func__, user, file);
		return FILE_ENCRY_OK;
	}
	/*
	 * for CE key, we need to check the IV input
	 * for ECE and SECE, we only need to check the CE status
	 * if file == SECE, logout keypair in file_encry_check_status
	 */
	if (file == FILE_CE)
		ret = file_encry_check_iv_value(iv_buf, length, ufs_slot);
	else
		ret = file_encry_check_status(user, file);

	if (ret != FILE_ENCRY_OK) {
		tloge("%s fail, ret 0x%x, slot 0x%x\n", __func__,
		      ret, ufs_slot);
		return ret;
	}

	/* just get random data, ignore the result */
	file_encry_gen_random(sizeof(ckey), ckey);
	/* Do I need to check the result */
	ret = file_encry_config_driver(ufs_slot, ckey, sizeof(ckey));
	if (ret != FILE_ENCRY_OK) {
		tloge("%s, write random fail 0x%x\n", __func__, ret);
		return ret;
	}

	g_ufs_info[ufs_slot].status = UFS_KEY_LOGOUT;
	/* We are OK with "config driver = fail" here */
	ret = file_encry_config_driver(idx_to_ufs_slot(ufs_slot),
				       (uint8_t *)&g_ufs_info[ufs_slot],
				       sizeof(g_ufs_info[ufs_slot]));
	if (ret != FILE_ENCRY_OK)
		tloge("%s, update keyinfo fail 0x%x\n", __func__, ret);

	return FILE_ENCRY_OK;
}

/*
 * This is for install class key
 * input:
 *    user: user id
 *    file: file type
 *    iv_buf: input/output, iv from vold & key2 to vold
 *    len: buf length
 * 1. check input file type & buf, buf length
 * 2. different process for rebooting(restore key) or new user(new key add)
 * 3. save ufs staus to sfs/msp.
 */
uint32_t file_encry_add_key(uint32_t user, uint32_t file,
			    uint8_t *iv_buf, uint32_t len)
{
	uint32_t ret;
	uint32_t ufs_slot = MAX_KEY_NUM_SUPPORT;
	uint8_t flag = (file >> FBEX_FILE_LEN) & FBEX_FILE_MASK;

	file = file & FBEX_FILE_MASK;
	ret = file_encry_addkey_check(user, file, iv_buf, len);
	if (ret != FILE_ENCRY_OK) {
		tloge("%s, check params fail 0x%x\n", __func__, ret);
		return ret;
	}

	tloge("%s in, user 0x%x, file 0x%x\n", __func__, user, file);
	if (flag == FBEX_IV_UPDATE)
		ret = file_encry_booting_add(user, file, iv_buf, len,
					     &ufs_slot);
	else
		ret = file_encry_rebooting_add(user, file, iv_buf, len,
					       &ufs_slot);
	if (ret != FILE_ENCRY_OK || ufs_slot >= MAX_KEY_NUM_SUPPORT) {
		tloge("%s: config key fail 0x%x\n", __func__, ret);
		return ret;
	}

	ret = file_encry_encrypt_ckey(file, ufs_slot);
	if (ret != FILE_ENCRY_OK) {
		tloge("%s, encrypt ckey fail 0x%x\n", __func__, ret);
		goto error;
	}
	g_ufs_info[ufs_slot].status = UFS_KEY_USING;
	ret = file_encry_config_driver(idx_to_ufs_slot(ufs_slot),
				       (uint8_t *)&g_ufs_info[ufs_slot],
				       sizeof(g_ufs_info[ufs_slot]));
	if (ret != FILE_ENCRY_OK) {
		tloge("%s, update keyinfo fail 0x%x\n", __func__, ret);
		goto error;
	}
	tloge("%s out, user 0x%x, file 0x%x\n", __func__, user, file);
	/* Clear CKEY in TEEOS */
	(void)memset_s(g_ufs_info[ufs_slot].ckey,
		       sizeof(g_ufs_info[ufs_slot].ckey),
		       0, KEY_LEN);
	return FILE_ENCRY_OK;
error:
	file_encry_clear_ufsc(ufs_slot);
	(void)memset_s(&g_ufs_info[ufs_slot], sizeof(g_ufs_info[ufs_slot]),
                       0, sizeof(g_ufs_info[ufs_slot]));
	return ret;
}

uint32_t file_encry_delete_key(uint32_t user, uint32_t file,
			       uint8_t *iv_buf, uint32_t length)
{
	uint32_t ret;
	uint32_t ufs_slot = MAX_KEY_NUM_SUPPORT;
	uint8_t ckey[KEY_LEN] = {0};
	uint32_t status = UFS_KEY_USING | UFS_KEY_SUSPEND | UFS_KEY_LOGOUT;

	file = file & FBEX_FILE_MASK;
	ret = file_encry_params_check_del(user, file, iv_buf, length);
	if (ret != FILE_ENCRY_OK) {
		tloge("%s, check params fail 0x%x\n", __func__, ret);
		return ret;
	}
	/*
	 * 1. if ufs_slot >= MAX_KEY_NUM_SUPPORT: user is not logged in
	 *    --> delete keys in MSP or SFS any way
	 * 2. else user had been logged in
	 *    --> 1. check the iv and magic input
	 *    --> 2. erase ufsc slot
	 *    --> 3. delete keys in MSP or SFS
	 *    --> 4. erase ufs info in TA
	 */
	ufs_slot = file_encry_ufskey_slot(user, file, status);
	if (ufs_slot >= MAX_KEY_NUM_SUPPORT) {
		tloge("%s, user 0x%x file 0x%x is not logged in\n",
		      __func__, user, file);
		return file_encry_delete_keys(user, file, MAX_KEY_NUM_SUPPORT);
	}

	tloge("%s, user 0x%x, file 0x%x is logged in ufs 0x%x\n",
	      __func__, user, file, ufs_slot);
	ret = file_encry_check_magic(iv_buf, length, ufs_slot);
	if (ret != FILE_ENCRY_OK) {
		tloge("%s, check iv buffer error 0x%x\n", __func__, ret);
		return ret;
	}
	/* just get random data, ignore the result */
	file_encry_gen_random(sizeof(ckey), ckey);
	/* Don't need to check the result */
	ret = file_encry_config_driver(ufs_slot, ckey, sizeof(ckey));
	if (ret != FILE_ENCRY_OK)
		tloge("%s, write random fail 0x%x\n", __func__, ret);

	ret = file_encry_delete_keys(user, file, ufs_slot);
	if (ret != FILE_ENCRY_OK)
		tloge("%s: delete ckey fail 0x%x\n", __func__, ret);

	(void)memset_s(&g_ufs_info[ufs_slot], sizeof(g_ufs_info[ufs_slot]),
		       0, sizeof(g_ufs_info[ufs_slot]));
	/* We are OK with "config driver = fail" here */
	ret = file_encry_config_driver(idx_to_ufs_slot(ufs_slot),
				       (uint8_t *)&g_ufs_info[ufs_slot],
				       sizeof(g_ufs_info[ufs_slot]));
	if (ret != FILE_ENCRY_OK)
		tloge("%s, update keyinfo fail 0x%x\n", __func__, ret);

	return FILE_ENCRY_OK;
}

uint32_t file_encry_new_sece(uint32_t ufs_slot, uint8_t *pubkey, uint32_t key_len,
			     uint8_t *metadata, uint32_t iv_len)
{
	uint32_t ret;
	uint32_t user;
	uint32_t idx = MAX_SECE_NUM;
	uint32_t avail = SECE_KEY_AVAILABLE | SECE_KEY_SUSPEND;
	uint8_t privkey[PRIV_KEY_LEN] = {0};

	ret = file_encry_params_check2(ufs_slot, pubkey, key_len,
				       metadata, iv_len);
	if (ret != FILE_ENCRY_OK) {
		tloge("%s, check params fail 0x%x\n", __func__, ret);
		return ret;
	}

	if (g_ufs_info[ufs_slot].file != FILE_SECE) {
		tloge("%s, input invalid file 0x%x\n", __func__,
		      g_ufs_info[ufs_slot].file);
		return FILE_ENCRY_ERROR_INVALID_NEW;
	}
	user = g_ufs_info[ufs_slot].user;
	ret = file_encry_get_sece_index(user, avail, &idx);
	if (ret != FILE_ENCRY_OK) {
		tloge("%s, cannot find sece index 0x%x\n", __func__, ret);
		return ret;
	}

	ret = file_encry_keypair_using_sw(pubkey, key_len, privkey, sizeof(privkey));
	if (ret != FILE_ENCRY_OK) {
		tloge("%s, 0x%x gen key pair fail\n", __func__, ret);
		return ret;
	}

	ret = file_encry_gen_metadata(g_sece_info[idx].pubkey, key_len, privkey,
				      sizeof(privkey), metadata, iv_len);
	if (ret != FILE_ENCRY_OK)
		tloge("%s, ecdh fail, ret 0x%x\n", __func__, ret);

	(void)memset_s(privkey, sizeof(privkey), 0, sizeof(privkey));
	return ret;
}

uint32_t file_encry_open_sece(uint32_t ufs_slot, uint8_t *pubkey, uint32_t key_len,
			      uint8_t *metadata, uint32_t iv_len)
{
	uint32_t ret;
	uint32_t user;
	uint32_t index = MAX_SECE_NUM;
	uint8_t privkey[PRIV_KEY_LEN] = {0};

	ret = file_encry_params_check2(ufs_slot, pubkey, key_len,
				       metadata, iv_len);
	if (ret != FILE_ENCRY_OK) {
		tloge("%s, check params fail 0x%x\n", __func__, ret);
		return ret;
	}

	if (g_ufs_info[ufs_slot].file != FILE_SECE) {
		tloge("%s, input invalid file 0x%x\n", __func__,
		      g_ufs_info[ufs_slot].file);
		return FILE_ENCRY_ERROR_INVALID_OPEN;
	}
	user = g_ufs_info[ufs_slot].user;
	ret = file_encry_get_sece_index(user, SECE_KEY_AVAILABLE, &index);
	if (ret != FILE_ENCRY_OK) {
		tloge("%s, cannot find sece index 0x%x\n", __func__, ret);
		return ret;
	}

	ret = file_encry_decrypt_privkey(index, privkey, sizeof(privkey));
	if (ret != FILE_ENCRY_OK) {
		tloge("%s, fetch mspkey fail 0x%x\n", __func__, ret);
		return ret;
	}
#ifdef FILE_ENCRY_KEY_HASH_ENABLE
	ret = file_encry_verify_hash(privkey, sizeof(privkey),
				     g_sece_info[index].privkey_hash,
				     sizeof(g_sece_info[index].privkey_hash));
	if (ret != FILE_ENCRY_OK) {
		tloge("%s, verify hash fail 0x%x\n", __func__, ret);
		return ret;
	}
#endif
	ret = file_encry_gen_metadata(pubkey, key_len, privkey, sizeof(privkey),
				      metadata, iv_len);
	if (ret != FILE_ENCRY_OK)
		tloge("%s, open sece get metadata, 0x%x\n", __func__, ret);

	(void)memset_s(privkey, sizeof(privkey), 0, sizeof(privkey));
	return ret;
}

uint32_t file_encry_prepare_ckey(void)
{
	uint32_t ret;

	ret = file_encry_config_driver(FILE_ENCRY_UFS_READ,
				       (uint8_t *)&g_ufs_info,
				       sizeof(g_ufs_info));
	if (ret != FILE_ENCRY_OK) {
		tloge("read from ufs info driver fail\n");
		return ret;
	}
	ret = file_encry_config_driver(FILE_ENCRY_CHIPID_READ,
				       &g_chip_id, sizeof(g_chip_id));
	if (ret != FILE_ENCRY_OK) {
		tloge("%s, read chip id fail\n", __func__);
		return ret;
	}

	return FILE_ENCRY_OK;
}
