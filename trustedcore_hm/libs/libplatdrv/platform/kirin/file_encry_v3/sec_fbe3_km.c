/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: FBE3 driver code
 * Author: security-ap
 * Create: 2020/02/27
 */

#include "sec_fbe3_km.h"
#include "sec_fbe3_ufsc.h"

#include <sre_typedef.h>
#include "securec.h"
#include "pthread.h"
#include <drv_module.h>

#include "hisi_boot.h"
#include "sys_generic.h"

#include "sre_access_control.h"
#include "sre_syscalls_id_ext.h"
#include <hmdrv_stub.h>
#include "drv_param_type.h"

static struct aes_ccm g_aes_info[MAX_KEY_NUM];
static struct ufs_info g_ufs_info[MAX_KEY_NUM];
/* privkey info is supported to 16 */
static struct privkey_info g_privkey_info[MAX_PRIVKEY_NUM];

static pthread_mutex_t g_file_encry_lock;

static uint32_t file_encry_ufs_config(uint32_t id, uint8_t *buf,
				      uint32_t len)
{
	int ret;
	uint32_t slot = id - MAX_KEY_NUM;

	tlogd("%s, ufs config slot 0x%x, len 0x%x\n",
	      __func__, slot, len);
	if (!buf || len != sizeof(g_ufs_info[slot]) ||
		slot >= MAX_KEY_NUM) {
		tloge("%s, input is wrong 0x%x\n", __func__, len);
		return (FILE_ENCRY_BUFF_INVALID | id_to_err_num(id));
	}
	ret = memcpy_s(&g_ufs_info[slot], sizeof(g_ufs_info[slot]),
		       buf, len);
	if (ret != EOK) {
		tloge("%s, store key(0x%x) info fail\n", __func__, ret);
		return (FILE_ENCRY_MEMCPY_FAIL | id_to_err_num(id));
	}
	return 0;
}

static uint32_t file_encry_info_read(uint8_t *buf, uint32_t len)
{
	int ret;

	tlogd("%s, info read\n", __func__);
	if (!buf || len != sizeof(g_ufs_info)) {
		tloge("%s, input is wrong 0x%x\n", __func__, len);
		return FILE_ENCRY_BUFF_INVALID;
	}
	ret = memcpy_s(buf, len, g_ufs_info, sizeof(g_ufs_info));
	if (ret != EOK) {
		tloge("%s, copy keyinfo fail 0x%x\n", __func__, ret);
		return FILE_ENCRY_MEMCPY_FAIL;
	}
	return 0;
}

static uint32_t file_encry_ckey_read(uint32_t id, uint8_t *buf, uint32_t len)
{
	int ret;
	uint32_t slot = id - MAX_KEY_IDX;

	tlogd("%s, ckey read\n", __func__);
	if (!buf || len != KEY_LEN || slot >= MAX_KEY_NUM) {
		tloge("%s, input is wrong 0x%x, 0x%x\n", __func__, len, slot);
		return (FILE_ENCRY_BUFF_INVALID | id_to_err_num(id));
	}
	ret = memcpy_s(buf, len, g_ufs_info[slot].ckey,
		       sizeof(g_ufs_info[slot].ckey));
	if (ret != EOK) {
		tloge("%s, copy ckey fail 0x%x\n", __func__, ret);
		return (FILE_ENCRY_MEMCPY_FAIL | id_to_err_num(id));
	}
	return 0;
}

static uint32_t file_encry_iv_read(uint32_t id, uint8_t *buf, uint32_t len)
{
	int ret;
	uint32_t slot = id - MAX_CKEY_IDX;

	tlogd("%s, IV read\n", __func__);
	if (!buf || len != sizeof(g_aes_info[slot]) || slot >= MAX_KEY_NUM) {
		tloge("%s, input is wrong 0x%x, 0x%x\n", __func__, len, slot);
		return (FILE_ENCRY_BUFF_INVALID | id_to_err_num(id));
	}
	ret = memcpy_s(buf, len, &g_aes_info[slot], sizeof(g_aes_info[slot]));
	if (ret != EOK) {
		tloge("%s, read IV fail 0x%x\n", __func__, ret);
		return (FILE_ENCRY_MEMCPY_FAIL | id_to_err_num(id));
	}
	return 0;
}

static uint32_t file_encry_iv_write(uint32_t id, uint8_t *buf, uint32_t len)
{
	int ret;
	uint32_t slot = id - MAX_IV_READ;

	tlogd("%s, IV write\n", __func__);
	if (!buf || len != sizeof(g_aes_info[slot]) || slot >= MAX_KEY_NUM) {
		tloge("%s, input is wrong 0x%x, 0x%x\n", __func__, len, slot);
		return (FILE_ENCRY_BUFF_INVALID | id_to_err_num(id));
	}
	ret = memcpy_s(&g_aes_info[slot], sizeof(g_aes_info[slot]), buf, len);
	if (ret != EOK) {
		tloge("%s, write IV fail\n", __func__);
		return (FILE_ENCRY_MEMCPY_FAIL | id_to_err_num(id));
	}
	return 0;
}

static uint32_t file_encry_privkey_handle(uint32_t id, uint8_t *buf, uint32_t len)
{
	int ret = EOK;
	uint32_t index = id - MAX_IV_WRITE;

	tlogd("%s, privkey handle\n", __func__);
	if (!buf || len != sizeof(struct privkey_info) || index >= MAX_KEY_NUM) {
		tloge("%s, input is wrong 0x%x, 0x%x\n", __func__, len, index);
		return (FILE_ENCRY_BUFF_INVALID | id_to_err_num(id));
	}

	/* if (index < MAX_PRIVKEY_NUM), this is write request */
	if (index < MAX_PRIVKEY_NUM)
		ret = memcpy_s(&g_privkey_info[index], sizeof(g_privkey_info[index]),
			       buf, len);
	/*
	 * if (index >= MAX_PRIVKEY_NUM && index < MAX_KEY_NUM)
	 * this is read request
	 */
	else
		ret = memcpy_s(buf, len, &g_privkey_info[index - MAX_PRIVKEY_NUM],
			       sizeof(g_privkey_info[index - MAX_PRIVKEY_NUM]));

	if (ret != EOK) {
		tloge("%s, privkey handle fail\n", __func__);
		return (FILE_ENCRY_MEMCPY_FAIL | id_to_err_num(id));
	}
	return 0;
}

static uint32_t file_encry_privkey_clean(uint32_t id, uint8_t *buf, uint32_t len)
{
	uint32_t idx = id - MAX_SECE_READ;

	tlogd("%s, logout, clean prikey 0x%x\n", __func__, idx);
	if (idx >= MAX_PRIVKEY_NUM) {
		tloge("%s, input idx 0x%x\n", __func__, idx);
		return  FILE_ENCRY_CLEAN_PRIVKEY;
	}
	(void)memset_s(&g_privkey_info[idx], sizeof(g_privkey_info[idx]), 0,
		       sizeof(g_privkey_info[idx]));
	(void)buf;
	(void)len;
	return 0;
}

static uint32_t file_encry_undefined(uint32_t id, uint8_t *buf __unused,
				     uint32_t len __unused)
{
	tloge("%s, undefined index 0x%x\n", __func__, id);
	return (FILE_ENCRY_INDEX_INVALID | id_to_err_num(id));
}

static uint32_t file_encry_chip_id(uint8_t *buf, uint32_t len)
{
	uint8_t chipid = 0;

	tlogd("%s, chipid read\n", __func__);
	if (!buf || len != sizeof(uint8_t)) {
		tloge("%s, input is wrong 0x%x\n", __func__, len);
		return FILE_ENCRY_BUFF_INVALID;
	}
	chipid = ((hisi_readl(SCSOCID0) & CHIPID_MASK) >> CHIPID_SHIFT);
	*buf = chipid;
	tlogd("%s, get chipid read 0x%x\n", __func__, chipid);
	return 0;
}

static uint32_t file_encry_write_dispatch(uint32_t id, uint8_t *buf,
				     uint32_t len)
{
	uint32_t idx = id_to_index(id);

	static const file_encry_cb dispatch[] = {
		FILE_ENCRY_CB_LIST
	};
	if (idx > FILE_ENXRY_DRIVER_MAX_ID) {
		tloge("%s, unsupported index, 0x%x\n", __func__, idx);
		return FILE_ENCRY_INDEX_INVALID;
	}
	return dispatch[idx](id, buf, len);
}

static int file_encry_init(void)
{
	uint32_t ret;
	if (pthread_mutex_init(&g_file_encry_lock, NULL)) {
		tloge("%s: file_encry_sem init fail!\n", __func__);
		return FILE_ENCRY_INIT_FAIL;
	}
	ret = memset_s(g_ufs_info, sizeof(g_ufs_info),
		       0, sizeof(g_ufs_info));
	if (ret != EOK) {
		tloge("%s: memset fail 0x%x\n", __func__, ret);
		return FILE_ENCRY_MEMSET_FAIL;
	}
	tlogd("file encry init succ!\n");
	return 0;
}

static uint32_t __file_encry_interface(uint32_t id, uint8_t *buf, uint32_t len)
{
	uint32_t ret;

	if (pthread_mutex_lock(&g_file_encry_lock)) {
		tloge("%s: lock fail!\n", __func__);
		return FILE_ENCRY_LOCK_FAIL;
	}
	switch (id) {
	case FILE_ENCRY_UFS_READ:
		ret = file_encry_info_read(buf, len);
		break;
	case FILE_ENCRY_ENABLE_KDF:
		ret = file_encry_enable_kdf();
		break;
	case FILE_ENCRY_CHIPID_READ:
		ret = file_encry_chip_id(buf, len);
		break;
	default:
		ret = file_encry_write_dispatch(id, buf, len);
		break;
	}
	pthread_mutex_unlock(&g_file_encry_lock);
	return ret;
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
		ACCESS_READ_RIGHT_CHECK(args[1], (size_t)args[2]);
		ACCESS_WRITE_RIGHT_CHECK(args[1], (size_t)args[2]);

		ret = __file_encry_interface((uint32_t)args[0],
					     (uint8_t *)(uintptr_t)args[1],
					     (uint32_t)args[2]);
		args[0] = (uint64_t)ret;
		SYSCALL_END
		default:
			return -EINVAL;
	}
	return 0;
}

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

