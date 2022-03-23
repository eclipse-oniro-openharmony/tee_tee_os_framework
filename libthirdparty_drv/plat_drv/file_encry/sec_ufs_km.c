/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * Description: Library for FBE2
 * Create: 2018-06-11
 */

#include "sec_ufs_km.h"

#include <drv_module.h>
#include <sre_typedef.h>
#include <tee_log.h>
#include "sre_task.h"
#include "securec.h"
#include "pthread.h"

#include "sre_access_control.h"
#include "sre_syscalls_id_ext.h"
#include "drv_pal.h"
#include <hmdrv_stub.h>
#include "drv_param_type.h"

static struct ufs_iv g_ufs_iv_store[UFS_KEY_MAX_NUM];
static pthread_mutex_t g_file_encry_lock;

/*
 * 1. set key1
 * 2. output key2
 */
static int set_key1_get_key2(int index, uint8_t *iv_buf, uint8_t *key2_buf,
			     uint32_t length)
{
	int ret;
	uint8_t key1_buf[IV_LENGTH] = {0};
	uint8_t iv_tmp[IV_LENGTH] = {0};
	uint8_t *secret = NULL;
	uint8_t fbe2_flag = FILE_ENCRY_KEY_ENHANCED;
	int i;

	if (!iv_buf || length != IV_LENGTH ||
	    index >= UFS_KEY_MAX_NUM ||
	    index < 0 || !key2_buf) {
		tloge("%s: input error!\n", __func__);
		return FILE_ENCRY_ERROR_INPUT_ERROR;
	}

	if (memcpy_s(iv_tmp, IV_LENGTH, iv_buf, length) != EOK) {
		tloge("%s: memcpy fail!\n", __func__);
		ret = FILE_ENCRY_ERROR_OUT_OF_MEM;
		goto clean_buffer;
	}

	ret = file_encry_root_derive_key(iv_tmp, IV_LENGTH, key1_buf,
					 IV_LENGTH);
	if (ret != FILE_ENCRY_OK) {
		tloge("%s: derive key fail! key1\n", __func__);
		goto clean_buffer;
	}

	ret = ufs_kirin_uie_key_config(index, key1_buf, IV_LENGTH);
	if (ret != 0) {
		tloge("%s: set ufs key fail!\n", __func__);
		ret = FILE_ENCRY_ERROR_WRITE_KEY;
		goto clean_buffer;
	}

	ret = secboot_get_fbe2_flag(&fbe2_flag);
	if (ret) {
		tloge("%s: get fbe2_flag failed!\n", __func__);
		ret = FILE_ENCRY_ERROR_INPUT_ERROR;
		goto clean_buffer;
	}

	if (fbe2_flag == FILE_ENCRY_KEY_NORMAL) {
		for (i = 0; i < IV_LENGTH; i++)
			iv_tmp[i] = ~iv_tmp[i];
		secret = iv_tmp;
	} else {
		/* default select ENHANCE mode, using the key1_buf */
		secret = key1_buf;
	}

	ret = file_encry_root_derive_key(secret, IV_LENGTH, key2_buf,
					 IV_LENGTH);
	if (ret != FILE_ENCRY_OK) {
		tloge("%s: derive key fail! key2\n", __func__);
		goto clean_buffer;
	}

	ret = FILE_ENCRY_OK;

clean_buffer:
	if (memset_s(iv_tmp, IV_LENGTH, 0, IV_LENGTH) != EOK) {
		tloge("memset_s iv_tmp failed, ret=0x%x\n", ret);
		ret = FILE_ENCRY_ERROR_MEMSET_FAIL;
	}
	if (memset_s(key1_buf, IV_LENGTH, 0, IV_LENGTH) != EOK) {
		tloge("memset_s key1_buf failed, ret=0x%x\n", ret);
		ret = FILE_ENCRY_ERROR_MEMSET_FAIL;
	}
	return ret;
}

/*
 * 1. get empty index
 * 2. return empty index or UFS_KEY_MAX_NUM(full).
 */
static int get_empty_index(void)
{
	int index;

	for (index = 0; index < UFS_KEY_MAX_NUM; index++) {
		/* recycle key slot */
		if (g_ufs_iv_store[index].iv_status == UFS_KEY_TO_DELETE) {
			g_ufs_iv_store[index].iv_status = UFS_KEY_NOT_USED;
			continue;
		}

		if (g_ufs_iv_store[index].iv_status != UFS_KEY_USED)
			break;
	}

	return index;
}

/*
 * find iv in g_ufs_iv_store
 */
static int find_iv_index(uint8_t *iv_buf, uint32_t length)
{
	int index;

	if (!iv_buf || length != IV_LENGTH) {
		tloge("%s: input error!\n", __func__);
		return FILE_ENCRY_ERROR_INPUT_ERROR;
	}

	for (index = 0; index < UFS_KEY_MAX_NUM; index++) {
		if (g_ufs_iv_store[index].iv_status != UFS_KEY_USED)
			continue;

		if (memcmp(iv_buf, g_ufs_iv_store[index].iv_value, IV_LENGTH))
			continue;

		break;
	}

	return index;
}

/*
 * add iv.
 * 1. find_iv_index to get index.
 * 2. if iv is new, get a new index.
 * 3. use add_key() to write key1, and get key2.
 * 4. output the key2 and index to buf.
 */
static int file_encry_add_iv(uint8_t *iv_buf, uint32_t length)
{
	int index;
	uint8_t iv_tmp[IV_LENGTH];
	uint8_t key2_buf[IV_LENGTH] = {0};
	int ret;

	if (!iv_buf || length != IV_LENGTH) {
		tloge("%s: input error!\n", __func__);
		return FILE_ENCRY_ERROR_INPUT_ERROR;
	}

	if (memcpy_s(iv_tmp, IV_LENGTH, iv_buf, length) != EOK) {
		tloge("%s: memcpy fail!\n", __func__);
		ret = FILE_ENCRY_ERROR_OUT_OF_MEM;
		goto clean_buffer;
	}

	index = find_iv_index(iv_tmp, IV_LENGTH);
	if (index >= UFS_KEY_MAX_NUM) {
		/* the iv isn't existed, get a empty index to store */
		index = get_empty_index();
		if (index >= UFS_KEY_MAX_NUM) {
			/* no empty index, ufs key full */
			tloge("%s: ufs_key is full!\n", __func__);
			ret = FILE_ENCRY_ERROR_KEY_IS_FULL;
			goto clean_buffer;
		}
	}

	/* set key1; get key2 */
	ret = set_key1_get_key2(index, iv_tmp, key2_buf, IV_LENGTH);
	if (ret != FILE_ENCRY_OK) {
		tloge("%s: set_key1_get_key2!\n", __func__);
		goto clean_buffer;
	}

	/* key2, [512:8]; index[7,0] */
	if (memcpy_s(g_ufs_iv_store[index].iv_value, IV_LENGTH, iv_buf, length)
		     != EOK) {
		tloge("%s: memcpy fail!\n", __func__);
		ret = FILE_ENCRY_ERROR_OUT_OF_MEM;
		goto clean_buffer;
	}
	key2_buf[IV_LENGTH - 1] = (uint8_t)index;

	/* write key2 to iv_buf */
	if (memcpy_s(iv_buf, length, key2_buf, IV_LENGTH) != EOK) {
		tloge("%s: memcpy fail!\n", __func__);
		ret = FILE_ENCRY_ERROR_OUT_OF_MEM;
		goto clean_buffer;
	}

	g_ufs_iv_store[index].iv_status = UFS_KEY_USED;
	ret = FILE_ENCRY_OK;

clean_buffer:
	if (memset_s(iv_tmp, IV_LENGTH, 0, IV_LENGTH) != EOK) {
		tloge("memset_s iv_tmp failed, ret=0x%x\n", ret);
		ret = FILE_ENCRY_ERROR_MEMSET_FAIL;
	}
	if (memset_s(key2_buf, IV_LENGTH, 0, IV_LENGTH) != EOK) {
		tloge("memset_s key2_buf failed, ret=0x%x\n", ret);
		ret = FILE_ENCRY_ERROR_MEMSET_FAIL;
	}
	return ret;
}

/*
 * delete iv if the iv is stored.
 */
static int file_encry_delete_iv(uint8_t *iv_buf, uint32_t length)
{
	int index;

	if (!iv_buf || length != IV_LENGTH) {
		tloge("%s: input error!\n", __func__);
		return FILE_ENCRY_ERROR_INPUT_ERROR;
	}

	index = find_iv_index(iv_buf, IV_LENGTH);
	if (index >= UFS_KEY_MAX_NUM) {
		tloge("%s: no the key!\n", __func__);
		return FILE_ENCRY_ERROR_NO_THE_KEY;
	}

	g_ufs_iv_store[index].iv_status = UFS_KEY_TO_DELETE;
	return FILE_ENCRY_OK;
}

/*
 * restore all stored iv.
 */
static int file_encry_restore_iv(void)
{
	int index;
	uint8_t key2_buf[IV_LENGTH] = {0};
	int ret = FILE_ENCRY_OK;

	for (index = 0; index < UFS_KEY_MAX_NUM; index++) {
		/* skip unused key */
		if (g_ufs_iv_store[index].iv_status == UFS_KEY_USED ||
		    g_ufs_iv_store[index].iv_status == UFS_KEY_TO_DELETE) {
			/* restore key */
			ret = set_key1_get_key2(index,
						g_ufs_iv_store[index].iv_value,
						key2_buf, IV_LENGTH);
			if (ret != FILE_ENCRY_OK) {
				tloge("%s: set_key1_get_key2 fail! ret = %d.\n",
				      __func__, ret);
				goto clean_buffer;
			}

			tloge("%s: %d restored, status = 0x%x!\n", __func__,
			      index, g_ufs_iv_store[index].iv_status);
		}
	}

clean_buffer:
	if (memset_s(key2_buf, IV_LENGTH, 0, IV_LENGTH) != EOK) {
		tloge("memset_s failed, ret=0x%x\n", ret);
		ret = FILE_ENCRY_ERROR_MEMSET_FAIL;
	}
	return ret;
}

/*
 * cmd_id come from task_file_encry(TA)
 * add_iv:     write key1, output key2, save iv.
 * delete_iv:  delete iv.
 * restore_iv: add all stored iv.
 */
int __file_encry_interface(uint32_t cmd_id, uint8_t *iv_buf, uint32_t length)
{
	int ret = FILE_ENCRY_ERROR_INPUT_ERROR;
	/* lock */
	if (pthread_mutex_lock(&g_file_encry_lock)) {
		tloge("%s: lock fail!\n", __func__);
		return FILE_ENCRY_ERROR_LOCK_FAIL;
	}

	switch (cmd_id) {
	case SEC_FILE_ENCRY_CMD_ID_VOLD_ADD_IV:
		ret = file_encry_add_iv(iv_buf, length);
		break;

	case SEC_FILE_ENCRY_CMD_ID_VOLD_DELETE_IV:
		ret = file_encry_delete_iv(iv_buf, length);
		break;

	case SEC_FILE_ENCRY_CMD_ID_UFS_RESTORE_IV:
		if (*iv_buf == 0 && length == sizeof(uint8_t))
			ret = file_encry_restore_iv();
		else
			ret = FILE_ENCRY_ERROR_INPUT_ERROR;
		break;

	default:
		ret = FILE_ENCRY_ERROR_INPUT_ERROR;
		break;
	}

	/* unlock */
	pthread_mutex_unlock(&g_file_encry_lock);
	return ret;
}

/*
 * init Sem and init local buff
 */
static int file_encry_init(void)
{
	if (pthread_mutex_init(&g_file_encry_lock, NULL)) {
		tloge("%s: file_encry_sem init fail!\n", __func__);
		return FILE_ENCRY_ERROR_LOCK_FAIL;
	}
	if (memset_s(g_ufs_iv_store, sizeof(g_ufs_iv_store),
		     0, sizeof(g_ufs_iv_store)) != EOK) {
		tloge("%s: memset fail!\n", __func__);
		return FILE_ENCRY_ERROR_DER_OUT_OF_MEM;
	}
	tlogd("file encry init succ!\n");
	return 0;
}

int file_encry_syscall(int swi_id, struct drv_param *params, uint64_t permissions)
{
	uint32_t ret;
	if (!params || !params->args) {
		tloge("%s: input param is null!\n", __func__);
		return -1;
	}
	uint64_t *args = (uint64_t *)(uintptr_t)(params->args);

	HANDLE_SYSCALL(swi_id) {
		SYSCALL_PERMISSION(SW_SYSCALL_FILE_ENCRY_INTERFACE, permissions,
				   FILE_ENCRY_GROUP_PERMISSION)
		ACCESS_CHECK_A64(args[1], (size_t)(args[2]));
		ACCESS_READ_RIGHT_CHECK(args[1], (size_t)(args[2]));
		ACCESS_WRITE_RIGHT_CHECK(args[1], (size_t)(args[2]));

		ret = __file_encry_interface((uint32_t)args[0],
					     (uint8_t *)(uintptr_t)args[1],
					     (uint32_t)args[2]);
		args[0] = ret;
		SYSCALL_END
		default:
			return -EINVAL;
	}
	return 0;
}

#if (TRUSTEDCORE_CHIP_CHOOSE != WITH_CHIP_BALTIMORE)
DECLARE_TC_DRV(
		file_encry_driver,
		0,
		0,
		0,
		TC_DRV_MODULE_INIT,
		file_encry_init,
		NULL,
		file_encry_syscall,
		NULL,
		NULL
		);
#endif
