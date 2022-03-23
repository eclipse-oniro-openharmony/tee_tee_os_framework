/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: Library for RPMB files
 * Create: 2020/06/17
 */

#include "sec_fbe3_rpmb.h"
#include "sec_fbe3_drv.h"
#include "sec_fbe3_derive_key.h"
#include <rpmb_fcntl.h>

#include "securec.h"
#include "tee_log.h"

#define MAX_FILE_TYPE          4
#define MAX_PUBKEY_SIZE        112
#define MAX_PRIVKEY_SIZE       64
#define RPMB_STATUS_INIT       0x5A6C
#define RPMB_FILE_NAME         "fbe3_rpmb_xxxxxxxx.dat"
#define RPMB_ENC_MASK          0xD1U
#define ENC_STATUS_VALID       0x5A

#define RPMB_FREE_FILE(name)   \
do { \
	if (name) \
		TEE_Free(name); \
}while(0);

struct key_info {
	uint8_t magic[MAGIC_LEN];
	uint8_t ckey[KEY_LEN];
	uint8_t hash[HASH_LEN];
};

struct user_key {
	uint8_t file;
	struct key_info ckeys[MAX_FILE_TYPE]; /* only support 4 ckeys */
	uint8_t pubkey[MAX_PUBKEY_SIZE];
	uint8_t privkey[MAX_PRIVKEY_SIZE];
};

struct enc_status {
	uint32_t user;
	uint8_t file;
	uint8_t flag;
};

static uint32_t g_rpmb_status_init;
static bool g_rpmb_is_avaiable = true;
#define INVALID_BIT 8
/* 1(CE) - 0, 2(ECE) - 4, 3(SECE) - 6, 5(PRIV) - 7 */
#define RPMB_MAP_SIZE 6
static uint8_t g_rpmb_enc_map[RPMB_MAP_SIZE] = {INVALID_BIT, 0, 4, 6, INVALID_BIT, 7};
struct enc_status g_enc_status[MAX_USER_NUM];

static bool file_encry_rpmb_avaiable(void)
{
	uint32_t ret;

	if (g_rpmb_status_init == RPMB_STATUS_INIT)
		return g_rpmb_is_avaiable;

	ret = TEE_RPMB_KEY_Status();
	if (ret != TEE_RPMB_KEY_SUCCESS) {
		tloge("%s, rpmb status check error 0x%x\n", __func__, ret);
		g_rpmb_is_avaiable = false;
		goto out;
	}
	g_rpmb_is_avaiable = true;
out:
	g_rpmb_status_init = RPMB_STATUS_INIT;
	return g_rpmb_is_avaiable;
}

static char *create_file_name(uint32_t user)
{
	int ret;
	uint32_t len = strlen(RPMB_FILE_NAME);

	char *buf = (char *)TEE_Malloc(len, 0);

	if (!buf) {
		tloge("%s, alloc buf error\n", __func__);
		return NULL;
	}
	ret = snprintf_s(buf, len, len - 1, "fbe3_rpmb_%x.dat", user);
	if (ret < 0) {
		tloge("%s, snprintf_s fail 0x%x\n", __func__, ret);
		TEE_Free(buf);
		return NULL;
	}
	return buf;
}

static uint32_t rpmb_file_read(char *filename, uint8_t *buf, uint32_t len)
{
	uint32_t ret;
	uint32_t read_size = 0;

	if (!filename) {
		tloge("%s, create file name fail\n", __func__);
		return FILE_ENCRY_ERROR_RPMB_FILENAME;
	}
	ret = TEE_RPMB_FS_Read(filename, buf, len, &read_size);
	if (ret != TEE_SUCCESS || len != read_size)
		tloge("%s, ret 0x%x, buf_len 0x%x, read_size 0x%x, file %s\n",
		      __func__, ret, len, read_size, filename);
	return ret;
}

static uint32_t rpmb_file_write(char *filename, const uint8_t *buf, uint32_t len)
{
	uint32_t ret;

	if (!filename) {
		tloge("%s, create file name fail\n", __func__);
		return FILE_ENCRY_ERROR_RPMB_FILENAME;
	}
	ret = TEE_RPMB_FS_Write(filename, buf, len);
	if (ret != TEE_SUCCESS) {
		tloge("%s, write fail, ret 0x%x, file %s\n", __func__, ret, filename);
		return ret;
	}

	return ret;
}

static uint32_t rpmb_file_remove(char *filename)
{
	uint32_t ret;

	if (!filename) {
		tloge("%s, create file name fail\n", __func__);
		return FILE_ENCRY_ERROR_RPMB_FILENAME;
	}
	ret = TEE_RPMB_FS_Rm(filename);
	if (ret != TEE_SUCCESS)
		tloge("%s failed, ret 0x%x, filename %s\n",
		      __func__, ret, filename);
	return ret;
}

static bool rpmb_get_enc_status(uint32_t user, uint8_t *file)
{
	int i;

	for (i = 0; i < MAX_USER_NUM; i++) {
		if (g_enc_status[i].flag != ENC_STATUS_VALID)
			continue;

		if (g_enc_status[i].user == user) {
			*file = g_enc_status[i].file;
			return true;
		}
	}

	return false;
}

static void rpmb_update_enc_status(uint32_t user, uint8_t file)
{
	int i;
	int idx = MAX_USER_NUM;

	for (i = 0; i < MAX_USER_NUM; i++) {
		if (g_enc_status[i].flag != ENC_STATUS_VALID) {
			if (idx == MAX_USER_NUM)
				idx = i;
			continue;
		}
		if (g_enc_status[i].user == user) {
			if ((file & (~RPMB_ENC_MASK)) == 0)
				g_enc_status[i].flag = 0;
			else
				g_enc_status[i].file = file;
			return;
		}
	}
	if (idx < MAX_USER_NUM && (file & (~RPMB_ENC_MASK)) != 0) {
		g_enc_status[idx].flag = ENC_STATUS_VALID;
		g_enc_status[idx].file = file;
		g_enc_status[idx].user = user;
		return;
	}
	tloge("%s, there is no struct to record enc status\n", __func__);
}

static bool file_encry_rpmb_if_enc(uint8_t flag, uint8_t file)
{
	uint8_t bit;
	uint8_t mask;

	bit = g_rpmb_enc_map[file];
	mask = 1u << bit;
	return ((flag & mask) == mask) ? true : false;
}

static uint32_t file_encry_rpmb_enc_process_magic(uint32_t file, struct user_key *keys)
{
	uint32_t ret;
	uint8_t magic_hash[HASH_LEN] = {0};

	if (file == FILE_PRIV)
		file = FILE_SECE;

	if (file > FILE_SECE)
		return FILE_ENCRY_OK;

	ret = file_encry_calc_hash(keys->ckeys[file].magic,
		sizeof(keys->ckeys[file].magic),
		magic_hash, sizeof(magic_hash));
	if (ret != FILE_ENCRY_OK) {
		tloge("%s magic hash failed, ret 0x%x\n", __func__, ret);
		return ret;;
	}

	ret = memcpy_s(keys->ckeys[file].magic, sizeof(keys->ckeys[file].magic),
		       magic_hash, sizeof(keys->ckeys[file].magic));
	if (ret != EOK) {
		tloge("%s, change magic to hash fail 0x%x\n", __func__, ret);
		ret = FILE_ENCRY_ERROR_MEMCPY_FAIL;
		return ret;
	}
	return FILE_ENCRY_OK;
}

static uint32_t file_encry_rpmb_encrypt(uint32_t user, uint32_t file, struct user_key *keys)
{
	uint32_t ret;
	uint8_t kek[AES_KEK_LEN] = {0};
	struct aes_info info = {0};

	ret = file_encry_derive_rpmb_kek(user, file, kek, AES_KEK_LEN, &info);
	if (ret != FILE_ENCRY_OK) {
		tloge("%s derive rpmb kek failed, ret 0x%x\n", __func__, ret);
		return ret;
	}

	ret = file_encry_rpmb_enc_process_magic(file, keys);
	if (ret != FILE_ENCRY_OK)
		goto finish;

	if (file < FILE_SECE) {
		info.key = (uint8_t *)keys->ckeys[file].ckey;
		info.key_len = sizeof(keys->ckeys[file].ckey);
		ret = file_encry_do_aes_cbc(TEE_MODE_ENCRYPT, info);
		if (ret != FILE_ENCRY_OK) {
			tloge("%s: encrypt key fail 0x%x\n", __func__, ret);
			goto finish;
		}
	}

	if (file == FILE_SECE || file == FILE_PRIV) {
		if ((keys->file & (1u << FILE_SECE))) {
			info.key = (uint8_t *)keys->ckeys[FILE_SECE].ckey;
			info.key_len = sizeof(keys->ckeys[FILE_SECE].ckey);
			ret = file_encry_do_aes_cbc(TEE_MODE_ENCRYPT, info);
			if (ret != FILE_ENCRY_OK) {
				tloge("%s: encrypt key fail 0x%x\n", __func__, ret);
				goto finish;
			}
		}

		if ((keys->file & (1u << FILE_PRIV))) {
			info.key = (uint8_t *)keys->privkey;
			info.key_len = sizeof(keys->privkey);
			ret = file_encry_do_aes_cbc(TEE_MODE_ENCRYPT, info);
			if (ret != FILE_ENCRY_OK) {
				tloge("%s: encrypt key fail 0x%x\n", __func__, ret);
				goto finish;
			}
		}
	}

	if (!file_encry_rpmb_if_enc(keys->file, file)) {
		keys->file |= (1U << g_rpmb_enc_map[file]);
		if (file == FILE_SECE || file == FILE_PRIV) {
			if ((keys->file & (1u << FILE_SECE)))
				keys->file |= (1U << g_rpmb_enc_map[FILE_SECE]);

			if ((keys->file & (1u << FILE_PRIV)))
				keys->file |= (1U << g_rpmb_enc_map[FILE_PRIV]);
		}
	}

finish:
	(void)memset_s(kek, sizeof(kek), 0, sizeof(kek));
	(void)memset_s(&info, sizeof(info), 0, sizeof(info));
	return ret;
}

static uint32_t file_encry_rpmb_decrypt(uint32_t user, uint32_t file, struct user_key *keys)
{
	uint32_t ret;
	uint8_t kek[AES_KEK_LEN] = {0};
	struct aes_info info = {0};

	if (!file_encry_rpmb_if_enc(keys->file, file))
		return FILE_ENCRY_OK;

	ret = file_encry_derive_rpmb_kek(user, file, kek, AES_KEK_LEN, &info);
	if (ret != FILE_ENCRY_OK) {
		tloge("%s derive rpmb kek failed, ret 0x%x\n", __func__, ret);
		return ret;
	}

	if (file < FILE_SECE) {
		info.key = (uint8_t *)keys->ckeys[file].ckey;
		info.key_len = sizeof(keys->ckeys[file].ckey);
		ret = file_encry_do_aes_cbc(TEE_MODE_DECRYPT, info);
		if (ret != FILE_ENCRY_OK) {
			tloge("%s: decrypt key fail 0x%x\n", __func__, ret);
			goto finish;
		}
	}

	if (file == FILE_SECE || file == FILE_PRIV) {
		if ((keys->file & (1u << FILE_SECE))) {
			info.key = (uint8_t *)keys->ckeys[FILE_SECE].ckey;
			info.key_len = sizeof(keys->ckeys[FILE_SECE].ckey);
			ret = file_encry_do_aes_cbc(TEE_MODE_DECRYPT, info);
			if (ret != FILE_ENCRY_OK) {
				tloge("%s: decrypt key fail 0x%x\n", __func__, ret);
				goto finish;
			}
		}

		if ((keys->file & (1u << FILE_PRIV))) {
			info.key = (uint8_t *)keys->privkey;
			info.key_len = sizeof(keys->privkey);
			ret = file_encry_do_aes_cbc(TEE_MODE_DECRYPT, info);
			if (ret != FILE_ENCRY_OK)
				tloge("%s: decrypt key fail 0x%x\n", __func__, ret);
		}
	}

finish:
	(void)memset_s(kek, sizeof(kek), 0, sizeof(kek));
	(void)memset_s(&info, sizeof(info), 0, sizeof(info));
	return ret;
}

/**
 * API for actively calling to encrypt the user key info in RPMB.
 */
uint32_t file_encry_rpmb_ensure_enc(uint32_t user, uint32_t file)
{
	uint32_t ret;
	char *file_name = NULL;
	struct user_key keys = {0};
	uint8_t tmp = 0;

	if (rpmb_get_enc_status(user, &tmp)) {
		if (!(tmp & (1u << file))) {
			tloge("%s, user 0x%x, file 0x%x is not installed\n",
			      __func__, user, file);
			return FILE_ENCRY_OK;
		}

		if (file_encry_rpmb_if_enc(tmp, file)) {
			tloge("%s, already encrypted\n", __func__);
			return FILE_ENCRY_OK;
		}
	}

	if (!file_encry_rpmb_avaiable()) {
		tloge("%s, rpmb is not supported\n", __func__);
		return FILE_ENCRY_OK;
	}

	file_name = create_file_name(user);
	ret = rpmb_file_read(file_name, (uint8_t *)&keys, sizeof(keys));
	if (ret == TEE_ERROR_RPMB_FILE_NOT_FOUND) {
		tloge("%s, rpmb not stored\n", __func__);
		ret = FILE_ENCRY_OK;
		goto finish;
	}
	if (ret != TEE_SUCCESS) {
		tloge("%s, read rpmb fail ret 0x%x\n", __func__, ret);
		goto finish;
	}

	if (!(keys.file & (1u << file))) {
		tloge("%s, user 0x%x, file 0x%x is not installed\n",
		      __func__, user, file);
		ret = FILE_ENCRY_OK;
		goto record;
	}

	if (file_encry_rpmb_if_enc(keys.file, file)) {
		ret = FILE_ENCRY_OK;
		tloge("%s, already encrypted\n", __func__);
		goto record;
	}

	ret = file_encry_rpmb_encrypt(user, file, &keys);
	if (ret != FILE_ENCRY_OK) {
		tloge("%s, rpmb encrypted fail ret 0x%x\n", __func__, ret);
		goto record;
	}

	ret = rpmb_file_write(file_name, (uint8_t *)&keys, sizeof(keys));
	if (ret != TEE_SUCCESS) {
		tloge("%s, write rpmb ckeys fail ret 0x%x\n", __func__, ret);
		goto record;
	}

record:
	rpmb_update_enc_status(user, keys.file);

finish:
	RPMB_FREE_FILE(file_name);
	(void)memset_s(&keys, sizeof(keys), 0, sizeof(keys));
	return ret;

}

static uint32_t file_encry_write_ckeys(const struct key_info_t *info,
				       struct user_key *ckeys_info)
{
	uint32_t ret;
	uint32_t file = info->file_type;

	ret = memcpy_s(ckeys_info->ckeys[file].magic, sizeof(ckeys_info->ckeys[file].magic),
		       info->magic_buf, info->magic_len);
	if (ret != EOK) {
		tloge("%s, copy magic fail 0x%x\n", __func__, ret);
		return FILE_ENCRY_ERROR_MEMCPY_FAIL;
	}
	ret = memcpy_s(ckeys_info->ckeys[file].ckey, sizeof(ckeys_info->ckeys[file].ckey),
		       info->key_buf, KEY_LEN);
	if (ret != EOK) {
		tloge("%s, copy ckey fail 0x%x\n", __func__, ret);
		return FILE_ENCRY_ERROR_MEMCPY_FAIL;
	}
	/* for DE, CE, ECE keys, we only need to copy ckey and magic */
	if (file != FILE_SECE)
		return FILE_ENCRY_OK;

	ret = memcpy_s(ckeys_info->pubkey, sizeof(ckeys_info->pubkey),
		       info->key_buf + KEY_LEN, PUB_KEY_LEN);
	if (ret != EOK) {
		tloge("%s, copy pubkey fail 0x%x\n", __func__, ret);
		return FILE_ENCRY_ERROR_MEMCPY_FAIL;
	}
	ret = memcpy_s(ckeys_info->privkey, sizeof(ckeys_info->privkey),
		       info->key_buf + KEY_LEN + PUB_KEY_LEN, PRIV_KEY_LEN);
	if (ret != EOK) {
		tloge("%s, copy privkey fail 0x%x\n", __func__, ret);
		return FILE_ENCRY_ERROR_MEMCPY_FAIL;
	}
	return FILE_ENCRY_OK;
}

static uint32_t file_encry_verify_rpmb(uint8_t *key, uint32_t key_len,
				       uint8_t *magic, uint32_t magic_len)
{
	uint32_t ret;
	uint8_t hash[HASH_LEN] = {0};

	ret = file_encry_calc_hash(key, key_len, hash, sizeof(hash));
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

static uint32_t file_encry_cmp_magic(const struct user_key *keys,
				     struct key_info_t *info)
{
	uint32_t ret;
	uint32_t file = info->file_type;
	uint8_t *real_magic = info->magic_buf;
	uint8_t magic_hash[HASH_LEN] = {0};

	if (file_encry_rpmb_if_enc(keys->file, file)) {
		ret = file_encry_calc_hash(info->magic_buf, info->magic_len,
			magic_hash, sizeof(magic_hash));
		if (ret != FILE_ENCRY_OK) {
			tloge("%s magic hash failed, ret 0x%x\n", __func__, ret);
			return ret;
		}
		real_magic = magic_hash;
	}

	if (file == FILE_PRIV)
		file = FILE_SECE;

	ret = memcmp(keys->ckeys[file].magic, real_magic, info->magic_len);
	if (ret != 0) {
		tloge("%s, verify magic fail 0x%x\n", __func__, ret);
		return FILE_ENCRY_ERROR_RPMB_VERIFY_MAGIC;
	}
	return FILE_ENCRY_OK;
}

static uint32_t file_encry_read_ckeys(struct user_key *ckeys_info,
				      struct key_info_t *info)
{
	uint32_t ret;
	uint32_t file = info->file_type;

	ret = file_encry_cmp_magic(ckeys_info, info);
	if (ret != 0)
		return ret;

	ret = memcpy_s(info->key_buf, info->key_len, ckeys_info->ckeys[file].ckey,
		       sizeof(ckeys_info->ckeys[file].ckey));
	if (ret != EOK) {
		tloge("%s, read ckey fail 0x%x\n", __func__, ret);
		return FILE_ENCRY_ERROR_MEMCPY_FAIL;
	}
	ret = file_encry_verify_rpmb(info->key_buf, info->key_len,
				     ckeys_info->ckeys[file].hash,
				     sizeof(ckeys_info->ckeys[file].hash));
	if (ret != FILE_ENCRY_OK) {
		tloge("%s, verify hash fail 0x%x\n", __func__, ret);
		return ret;
	}
	return FILE_ENCRY_OK;
}

static uint32_t file_encry_read_pubkey(struct user_key *ckeys_info,
				       struct key_info_t *info)
{
	uint32_t ret;
	uint32_t file = info->file_type;

	ret = file_encry_cmp_magic(ckeys_info, info);
	if (ret != 0)
		return ret;

	ret = memcpy_s(info->key_buf, info->key_len, ckeys_info->ckeys[file].ckey,
		       sizeof(ckeys_info->ckeys[file].ckey));
	if (ret != EOK) {
		tloge("%s, read ckey fail 0x%x\n", __func__, ret);
		return FILE_ENCRY_ERROR_MEMCPY_FAIL;
	}
	ret = file_encry_verify_rpmb(info->key_buf, KEY_LEN,
				     ckeys_info->ckeys[file].hash,
				     sizeof(ckeys_info->ckeys[file].hash));
	if (ret != FILE_ENCRY_OK) {
		tloge("%s, verify hash fail 0x%x\n", __func__, ret);
		return ret;
	}
	ret = memcpy_s(info->key_buf + KEY_LEN, PUB_KEY_LEN, ckeys_info->pubkey,
		       PUB_KEY_LEN);
	if (ret != EOK) {
		tloge("%s, read pubkey fail 0x%x\n", __func__, ret);
		return FILE_ENCRY_ERROR_MEMCPY_FAIL;
	}
	return FILE_ENCRY_OK;
}

static uint32_t file_encry_read_privkey(const struct user_key *ckeys_info,
					struct key_info_t *info)
{
	uint32_t ret;

	/* privkey, verify the magic from SECE */
	ret = file_encry_cmp_magic(ckeys_info, info);
	if (ret != 0)
		return ret;

	ret = memcpy_s(info->key_buf, info->key_len, ckeys_info->privkey,
		       PRIV_KEY_LEN);
	if (ret != EOK) {
		tloge("%s, read privkey fail 0x%x\n", __func__, ret);
		return FILE_ENCRY_ERROR_MEMCPY_FAIL;
	}
	return FILE_ENCRY_OK;
}

static uint32_t file_encry_clean_ckeys(uint32_t user, uint32_t file,
				       struct user_key *ckeys)
{
	uint32_t ret;
	char *file_name = NULL;

	ret = memset_s(ckeys->ckeys[file].magic, sizeof(ckeys->ckeys[file].magic),
		       0, sizeof(ckeys->ckeys[file].magic));
	if (ret != EOK)
		tloge("%s, clean magic fail 0x%x\n", __func__, ret);

	ret = memset_s(ckeys->ckeys[file].ckey, sizeof(ckeys->ckeys[file].ckey),
		       0, sizeof(ckeys->ckeys[file].ckey));
	if (ret != EOK)
		tloge("%s, clean ckey fail 0x%x\n", __func__, ret);
	/* for DE, CE, ECE keys, we only need to copy ckey and magic */
	ckeys->file &= ~(1u << file);
	if (file != FILE_SECE)
		goto finish;

	ret = memset_s(ckeys->pubkey, sizeof(ckeys->pubkey),
		      0, sizeof(ckeys->pubkey));
	if (ret != EOK)
		tloge("%s, clean pubkey fail 0x%x\n", __func__, ret);

	ret = memset_s(ckeys->privkey, sizeof(ckeys->privkey),
		      0, sizeof(ckeys->privkey));
	if (ret != EOK)
		tloge("%s, clean privkey fail 0x%x\n", __func__, ret);
	ckeys->file &= ~(1u << FILE_PRIV);
finish:
	file_name = create_file_name(user);
	if ((ckeys->file & (~RPMB_ENC_MASK)) == 0) /* the last one, remove files */
		ret = rpmb_file_remove(file_name);
	else
		ret = rpmb_file_write(file_name, (uint8_t *)ckeys, sizeof(struct user_key));
	RPMB_FREE_FILE(file_name);
	if (ret != TEE_SUCCESS) {
		tloge("%s, clean ckey in rpmb fail ret 0x%x\n", __func__, ret);
		return ret;
	}
	return FILE_ENCRY_OK;
}

static uint32_t file_encry_params_check(const struct key_info_t *info)
{
	uint32_t user = info->user_id;
	uint32_t file = info->file_type;
	uint32_t len = KEY_LEN + PUB_KEY_LEN + PRIV_KEY_LEN;

	if (!info->magic_buf || info->magic_len != MAGIC_LEN) {
		tloge("%s, invalid magic buf input\n", __func__);
		return FILE_ENCRY_ERROR_RPMB_VERIFY_BUF;
	}
	if (file < FILE_SECE && info->key_len == KEY_LEN)
		return FILE_ENCRY_OK;
	if (file == FILE_SECE && info->key_len == len)
		return FILE_ENCRY_OK;
	tloge("%s, invalid input user 0x%x, file 0x%x\n", __func__, user, file);
	return FILE_ENCRY_ERROR_RPMB_INVALID_PARAM;
}

static uint32_t file_encry_write_check(const struct key_info_t *info)
{
	if (!info->key_buf) {
		tloge("%s, key buf is NULL\n", __func__);
		return FILE_ENCRY_ERROR_RPMB_VERIFY_BUF;
	}

	return file_encry_params_check(info);
}

static uint32_t file_encry_read_check(const struct key_info_t *info)
{
	uint32_t user = info->user_id;
	uint32_t file = info->file_type;

	if (!info->magic_buf || info->magic_len != MAGIC_LEN || !info->key_buf) {
		tloge("%s, invalid magic buf input\n", __func__);
		return FILE_ENCRY_ERROR_RPMB_VERIFY_BUF;
	}
	if (file < FILE_SECE && info->key_len == KEY_LEN)
		return FILE_ENCRY_OK;
	if (file == FILE_SECE && info->key_len == (KEY_LEN + PUB_KEY_LEN))
		return FILE_ENCRY_OK;
	if (file == FILE_PRIV && info->key_len == PRIV_KEY_LEN)
		return FILE_ENCRY_OK;
	tloge("%s, invalid input user 0x%x, file 0x%x\n", __func__, user, file);
	return FILE_ENCRY_ERROR_RPMB_INVALID_PARAM;
}

static uint32_t file_encry_delete_check(const struct key_info_t *info)
{
	uint32_t user = info->user_id;

	if (user == MAIN_USER_ID)
		return FILE_ENCRY_ERROR_DELETE_MAINID;

	return file_encry_params_check(info);
}

/*
 * Function: file_encry_rpmb_write
 * Input parameters info->:
 *  user_id file_type magic magic_len  key  key_len
 *     x    0/1/2     u8*   MAGIC_LEN  u8*  KEY_LEN
 *     x    3         u8*   MAGIC_LEN  u8*  KEY_LEN + PUB_LEN + PRIV_LEN
 */
uint32_t file_encry_rpmb_write(const struct key_info_t *info)
{
	uint32_t ret;
	char *file_name = NULL;
	uint32_t user = info->user_id;
	uint32_t file = info->file_type;
	struct user_key ckeys = {0};

	if (!file_encry_rpmb_avaiable()) {
		tloge("%s, rpmb is not supported\n", __func__);
		return FILE_ENCRY_OK;
	}
	ret = file_encry_write_check(info);
	if (ret != FILE_ENCRY_OK) {
		tloge("%s, input params error 0x%x\n", __func__, ret);
		return ret;
	}
	file_name = create_file_name(user);
	ret = rpmb_file_read(file_name, (uint8_t *)&ckeys, sizeof(ckeys));
	RPMB_FREE_FILE(file_name);
	if (ret != TEE_SUCCESS && ret != TEE_ERROR_RPMB_FILE_NOT_FOUND) {
		tloge("%s, read rpmb keys fail ret 0x%x\n", __func__, ret);
		goto finish;
	}

	/* config ckeys first */
	ret = file_encry_write_ckeys(info, &ckeys);
	if (ret != FILE_ENCRY_OK) {
		tloge("%s, copy user 0x%x, file 0x%x fail\n", __func__, user, file);
		ret = FILE_ENCRY_ERROR_RPMB_COPY_CKEY;
		goto finish;
	}
	ret = file_encry_calc_hash(ckeys.ckeys[file].ckey, sizeof(ckeys.ckeys[file].ckey),
				   ckeys.ckeys[file].hash, sizeof(ckeys.ckeys[file].hash));
	if (ret != FILE_ENCRY_OK) {
		tloge("%s, calc hash fail 0x%x\n", __func__, ret);
		return ret;
	}
	ckeys.file |= (1u << file);
	if (file == FILE_SECE)
		ckeys.file |= (1u << FILE_PRIV);
	file_name = create_file_name(user);

	ret = file_encry_rpmb_encrypt(user, file, &ckeys);
	if (ret != FILE_ENCRY_OK) {
		tloge("%s, rpmb encrypted fail ret 0x%x\n", __func__, ret);
		goto finish;
	}

	ret = rpmb_file_write(file_name, (uint8_t *)&ckeys, sizeof(ckeys));
	RPMB_FREE_FILE(file_name);
	if (ret != TEE_SUCCESS) {
		tloge("%s, write rpmb ckeys fail ret 0x%x\n", __func__, ret);
		goto finish;
	}
	rpmb_update_enc_status(user, ckeys.file);

finish:
	(void)memset_s(&ckeys, sizeof(ckeys), 0, sizeof(ckeys));
	return ret;
}

/*
 * Function: file_encry_rpmb_read
 * Input parameters info->:
 *  user_id file_type magic magic_len  key  key_len
 *     x    0/1/2     u8*   MAGIC_LEN  u8*  KEY_LEN
 *     x    3         u8*   MAGIC_LEN  u8*  KEY_LEN + PUB_LEN
 *     x    5         u8*   MAGIC_LEN  u8*  PRIV_LEN
 */
uint32_t file_encry_rpmb_read(struct key_info_t *info)
{
	uint32_t ret;
	char *file_name = NULL;
	uint32_t user = info->user_id;
	uint32_t file = info->file_type;
	struct user_key ckeys = {0};

	if (!file_encry_rpmb_avaiable()) {
		tloge("%s, rpmb is not supported\n", __func__);
		return FILE_ENCRY_ERROR_RPMB_NOT_SUPPORT;
	}
	ret = file_encry_read_check(info);
	if (ret != FILE_ENCRY_OK) {
		tloge("%s, input params error 0x%x\n", __func__, ret);
		return ret;
	}
	file_name = create_file_name(user);
	ret = rpmb_file_read(file_name, (uint8_t *)&ckeys, sizeof(ckeys));
	RPMB_FREE_FILE(file_name);
	if (ret != TEE_SUCCESS) {
		tloge("%s, read ckey fail ret 0x%x\n", __func__, ret);
		goto finish;
	}
	if (!(ckeys.file & (1u << file))) {
		tloge("%s, user 0x%x, file 0x%x is not installed\n",
		      __func__, user, file);
		ret = FILE_ENCRY_ERROR_RPMB_NO_CKEY;
		goto finish;
	}

	ret = file_encry_rpmb_decrypt(user, file, &ckeys);
	if (ret != FILE_ENCRY_OK) {
		tloge("%s, rpmb decrypted fail ret 0x%x\n", __func__, ret);
		goto finish;
	}

	rpmb_update_enc_status(user, ckeys.file);

	if (file < FILE_SECE)
		ret = file_encry_read_ckeys(&ckeys, info);
	else if (file == FILE_SECE)
		ret = file_encry_read_pubkey(&ckeys, info);
	else if (file == FILE_PRIV)
		ret = file_encry_read_privkey(&ckeys, info);
	else
		ret = FILE_ENCRY_ERROR_RPMB_FILE_TYPE;
finish:
	(void)memset_s(&ckeys, sizeof(ckeys), 0, sizeof(ckeys));
	return ret;
}

/*
 * Function: file_encry_rpmb_delete
 * Input parameters info->:
 *  user_id key_flag  magic magic_len  key   key_len
 *     x    0/1/2     u8*   MAGIC_LEN  NULL  KEY_LEN
 *     x    3         u8*   MAGIC_LEN  NULL  KEY_LEN + PUB_LEN + PRIV_LEN
 */
uint32_t file_encry_rpmb_delete(const struct key_info_t *info)
{
	uint32_t ret;
	char *file_name = NULL;
	uint32_t user = info->user_id;
	uint32_t file = info->file_type;
	struct user_key ckeys = {0};

	if (!file_encry_rpmb_avaiable()) {
		tloge("%s, rpmb is not supported\n", __func__);
		return FILE_ENCRY_OK;
	}
	ret = file_encry_delete_check(info);
	if (ret != FILE_ENCRY_OK) {
		tloge("%s, input params error 0x%x\n", __func__, ret);
		return ret;
	}

	file_name = create_file_name(user);
	ret = rpmb_file_read(file_name, (uint8_t *)&ckeys, sizeof(ckeys));
	RPMB_FREE_FILE(file_name);

	if (ret != TEE_SUCCESS && ret != TEE_ERROR_RPMB_FILE_NOT_FOUND) {
		/* read rpmb files fail */
		tloge("%s, read keys info fail ret 0x%x\n", __func__, ret);
		goto out;
	}
	/* user is not installed, return OK */
	if (ret == TEE_ERROR_RPMB_FILE_NOT_FOUND) {
		tloge("%s, user 0x%x is not installed\n", __func__, user);
		ret = FILE_ENCRY_OK;
		goto out;
	}
	/* file is not installed, return OK */
	if (!(ckeys.file & (1u << file))) {
		tloge("%s, user 0x%x file 0x%x is not installed\n",
		      __func__, user, file);
		ret = FILE_ENCRY_OK;
		goto out;
	}
	ret = file_encry_clean_ckeys(user, file, &ckeys);
	if (ret != FILE_ENCRY_OK) {
		tloge("%s, clean ckeys fail ret 0x%x\n", __func__, ret);
		goto out;
	}
	rpmb_update_enc_status(user, ckeys.file);

out:
	(void)memset_s(&ckeys, sizeof(ckeys), 0, sizeof(ckeys));
	return ret;
}
