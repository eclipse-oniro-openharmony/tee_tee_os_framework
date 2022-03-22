/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * Description: ukey ta source file
 * Author: hanxuanwei 00353015
 * Create: 2019-05-26
 * History: 2019-04-08 hanyefei h00497291 CSEC rectification
 */
#include "ukey_ta_data.h"

#include "string.h"

#include "tee_ext_api.h"
#include "tee_ext_se_api.h"
#include "tee_log.h"

#include "TA_BasicLibs.h"
#include "TA_FileOperator.h"
#include "TA_Parcel.h"
#include "TA_SFSFileOperator.h"

#define FILE_NAME "ukey_switch_config"
#define FILE_PATH "sec_storage_data/UKEY/"
#define MIN_SELECT_CMD_LEN 5
#define UKEY_SELECT_CMD_CODE 0xA4
#define SE_TADEACTIVE 1
#define DEFAULT_AID_LIST_LEN 1
#define STAR_FLAG_FOR_PARTIAL "*"
#define SIZE_OF_STAR_FLAG 1
#define TEE_SERVICE_PANAPY \
{\
	0x54ad737b, \
	0xd84a, \
	0x46bd, \
	{ \
		0xb9, 0x93, 0x1a, 0x90, 0x88, 0x3f, 0x66, 0xf7 \
	} \
}

IMPLEMENT_TA_VECTOR(ukey_switch_vec, ukey_apk_switch_info, 1)

static ukey_switch_vec g_switch_vec;
static int g_init_flag = 0;
static int g_se_deactive_flag = 0;
/* when reset factory, the sem ta was disabled. */
/* current filter white list is null. */
const TEE_UUID array_se_deactive_white_table[] = {
};

#pragma pack(1)
typedef struct {
	char cls;
	char ins;
	char p1;
	char p2;
	char p3;
} ukey_select_cmd_head;
#pragma pack()

static ukey_apk_switch_info create_ukey_apk_switch_info()
{
	ukey_apk_switch_info switch_info;
	TEE_MemFill(&switch_info, 0, sizeof(switch_info));
	switch_info.aid_info.aid = create_parcel(PARCEL_DEFAULT_LENGTH,
		PARCEL_DEFAULT_ALLOC_UNIT);
	return switch_info;
}

static void destroy_ukey_apk_switch_info(ukey_apk_switch_info *switch_info)
{
	if (switch_info == NULL)
		return;
	delete_parcel(&switch_info->aid_info.aid);
	TEE_MemFill(switch_info, 0, sizeof(ukey_apk_switch_info));
}

/* check if p1 include p2 */
static bool is_aid_include(const ta_parcel_t *p1, const ta_parcel_t *p2)
{
	if ((p1 == NULL) || (p2 == NULL))
		return false;

	uint32_t len1 = get_parcel_data_size(p1);
	uint32_t len2 = get_parcel_data_size(p2);
	if ((len1 < len2) || (len1 == 0))
		return false;

	const char *c1 = get_parcel_data(p1);
	const char *c2 = get_parcel_data(p2);
	if ((c1 == NULL) || (c2 == NULL))
		return false;

	return (memcmp(c1, c2, len2) == 0);
}

/* check if p2 equal p1 */
static bool is_aid_equal(const ta_parcel_t *p1, const ta_parcel_t *p2)
{
	if ((p1 == NULL) || (p2 == NULL))
		return false;

	uint32_t len1 = get_parcel_data_size(p1);
	uint32_t len2 = get_parcel_data_size(p2);
	if ((len1 != len2) || (len1 == 0))
		return false;

	const char *c1 = get_parcel_data(p1);
	const char *c2 = get_parcel_data(p2);
	if ((c1 == NULL) || (c2 == NULL))
		return false;

	return (memcmp(c1, c2, len2) == 0);
}

static bool is_aid_in_switch_range(const ukey_aid_info *target_aid,
	const ukey_aid_info *switch_aid)
{
	if ((target_aid == NULL) || (switch_aid == NULL))
		return false;

	if (target_aid->is_partial == true) {
		if (switch_aid->is_partial == false)
			return false;
		else
			return is_aid_include(&target_aid->aid,
				&switch_aid->aid);
	} else {
		if (switch_aid->is_partial == false)
			return is_aid_equal(&switch_aid->aid,
				&target_aid->aid);
		else
			return is_aid_include(&target_aid->aid,
				&switch_aid->aid);
	}
}

static bool get_aid_switch_status(const ukey_aid_info *info)
{
	if (info == NULL)
		return false;
	uint32_t index = 0;
	ukey_apk_switch_info *index_item = NULL;

	FOR_EACH_TA_VECTOR(g_switch_vec, index, index_item) {
		if (is_aid_in_switch_range(info, &index_item->aid_info)) {
			tlogd("Switch_status %d.\n", index_item->switch_status);
			return index_item->switch_status;
		}
	}
	tlogd("AID not in range.\n");
	return true;
}

static TEE_Result get_aid_from_select_cmd(ta_parcel_t *cmd,
	ukey_aid_info *info)
{
	if (cmd == NULL || info == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	if (get_parcel_data_size(cmd) < MIN_SELECT_CMD_LEN)
		return TEE_ERROR_BAD_PARAMETERS;

	ukey_select_cmd_head head;
	if (!parcel_read(cmd, &head, sizeof(head)))
		return TEE_ERROR_WRITE_DATA;

	if (head.ins != (char)UKEY_SELECT_CMD_CODE)
		return TEE_ERROR_BAD_PARAMETERS;

	if (head.p3 != (char)get_parcel_data_size(cmd))
		return TEE_ERROR_BAD_PARAMETERS;

	if (!parcel_copy(cmd, &info->aid))
		return TEE_ERROR_WRITE_DATA;

	switch (head.p2) {
	/* case 0x00: SELECT control parameter P2, first or only occurrence */
	case 0x00:
		info->is_partial = false;
		return TEE_SUCCESS;
	/* case 0x02: SELECT control parameter P2, next occurrence */
	case 0x02:
		info->is_partial = true;
		return TEE_SUCCESS;
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}

bool check_applet_accessibility(TEE_UUID uuid, const uint8_t *select_cmd,
	uint32_t select_cmd_len)
{
	if (select_cmd == NULL || select_cmd_len == 0) {
		tloge("CMD len %d.\n", select_cmd_len);
		return false;
	}
	/* if SE deactive flag has been set, */
	/* just allow white list uuid to access SE */
	if (g_se_deactive_flag == SE_TADEACTIVE) {
		int32_t ret = 1;
		uint32_t index;
		uint32_t white_table_size =
			sizeof(array_se_deactive_white_table) /
			sizeof(TEE_UUID);
		for (index = 0; index < white_table_size; index++) {
			ret = TEE_MemCompare((void *)&uuid,
				(void *)&array_se_deactive_white_table[index],
				sizeof(TEE_UUID));
			if (ret == 0)
				break;
		}
		if (ret != 0) {
			tloge("SE is deactive status, your ta uuid is not in \
				the white list to access SE, uuid:0x%x.\n",
				uuid.timeLow);
			return false;
		}
	}

	ta_parcel_t cmd = create_parcel(PARCEL_DEFAULT_LENGTH,
		PARCEL_DEFAULT_ALLOC_UNIT);
	if (!parcel_write(&cmd, select_cmd, select_cmd_len)) {
		tloge("Parcel write error.\n");
		delete_parcel(&cmd);
		return false;
	}
	ukey_aid_info info;
	TEE_MemFill(&info, 0, sizeof(ukey_aid_info));
	info.aid = create_parcel(PARCEL_DEFAULT_LENGTH,
		PARCEL_DEFAULT_ALLOC_UNIT);

	if (get_aid_from_select_cmd(&cmd, &info) != TEE_SUCCESS) {
		tloge("Get_aid_from_select_cmd error.\n");
		delete_parcel(&cmd);
		delete_parcel(&info.aid);
		return false;
	}
	delete_parcel(&cmd);

	bool result = get_aid_switch_status(&info);
	delete_parcel(&info.aid);
	return result;
}

static bool write_struct_to_parcel(ta_parcel_t *dst,
	const ukey_apk_switch_info *index_item)
{
	if ((dst == NULL) || (index_item == NULL))
		return false;

	do {
		if (!parcel_write(dst, index_item->package_name,
			sizeof(index_item->package_name)))
			break;
		if (!parcel_write_uint32(dst, index_item->reserve))
			break;
		if (!parcel_write_uint8(dst, index_item->switch_status))
			break;
		if (!parcel_write_uint32(dst,
			get_parcel_data_size(&index_item->aid_info.aid)))
			break;
		if (!parcel_write(dst,
			get_parcel_data(&index_item->aid_info.aid),
			get_parcel_data_size(&index_item->aid_info.aid)))
			break;
		if (!parcel_write_uint8(dst, index_item->aid_info.is_partial))
			break;
		return true;
	} while (0);
	return false;
}

static void set_aidstatus_to_seservice (const char *aid, uint32_t aid_len,
	bool is_closed, bool range_status)
{
	if (aid == NULL || aid_len > ID_MAX_LENGTH || aid_len <= 0) {
		tloge("Param invalid.");
		return;
	}
	struct seaid_switch_info *seaid =
		(struct seaid_switch_info *)malloc(sizeof(struct seaid_switch_info));
	if (seaid == NULL) {
		tloge("Malloc failed.");
		goto EXIT;
	}
	errno_t rc = memset_s(seaid, sizeof(struct seaid_switch_info), 0,
		sizeof(struct seaid_switch_info));
	if (rc != EOK) {
		tloge("Memset_s failed.");
		goto EXIT;
	}
	rc = memcpy_s(seaid->aid, ID_MAX_LENGTH, aid, aid_len);
	if (rc != EOK) {
		tloge("Memcpy_s failed.");
		goto EXIT;
	}
	if (range_status == true && aid_len < ID_MAX_LENGTH) {
		rc = memcpy_s(seaid->aid + aid_len, ID_MAX_LENGTH - aid_len,
			STAR_FLAG_FOR_PARTIAL, SIZE_OF_STAR_FLAG);
		if (rc != EOK) {
			tloge("Memcpy_s failed.");
			goto EXIT;
		}
		aid_len += SIZE_OF_STAR_FLAG;
	}
	seaid->aid_len = aid_len;
	seaid->closed = is_closed;
	tee_se_set_aid(seaid, DEFAULT_AID_LIST_LEN);
EXIT:
	if (seaid != NULL) {
		free(seaid);
		seaid = NULL;
	}
}

static bool read_struct_from_parcel(ta_parcel_t *src,
	ukey_apk_switch_info *index_item)
{
	if ((src == NULL) || (index_item == NULL))
		return false;

	do {
		if (!parcel_read(src, index_item->package_name,
			sizeof(index_item->package_name)))
			break;
		if (!parcel_read_uint32(src, &index_item->reserve))
			break;
		if (!parcel_read_uint8(src,
			(uint8_t*)&index_item->switch_status))
			break;

		uint32_t aid_size = 0;
		if (!parcel_read_uint32(src, &aid_size))
			break;
		if (!parcel_read_parcel(src, &index_item->aid_info.aid,
			aid_size, TA_FALSE))
			break;
		if (!parcel_read_uint8(src,
			(uint8_t*)&index_item->aid_info.is_partial))
			break;

		uint32_t aid_len = get_parcel_data_size(&(index_item->aid_info.aid));
		bool is_closed = (index_item->switch_status == 1) ? false : true;
		bool range_status = index_item->aid_info.is_partial;
		set_aidstatus_to_seservice(get_parcel_data(&(index_item->aid_info.aid)),
			aid_len, is_closed, range_status);

		return true;
	} while (0);

	return false;
}

static TEE_Result write_config(void)
{
	if (g_init_flag == 0)
		return TEE_ERROR_BAD_STATE;

	TEE_Result ret = TEE_SUCCESS;
	ta_parcel_t switch_parcel = create_parcel(PARCEL_DEFAULT_LENGTH,
		PARCEL_DEFAULT_ALLOC_UNIT);
	uint32_t index = 0;
	ukey_apk_switch_info *index_item = NULL;

	FOR_EACH_TA_VECTOR(g_switch_vec, index, index_item) {
		if (!write_struct_to_parcel(&switch_parcel, index_item)) {
			tloge("Vector write error.\n");
			delete_parcel(&switch_parcel);
			return TEE_ERROR_OUT_OF_MEMORY;
		}
	}

	if (!write_parcel_into_file(FILE_NAME, &switch_parcel,
		get_security_file_ops())) {
		tloge("File operation error.\n");
		ret =  TEE_ERROR_WRITE_DATA;
	}
	delete_parcel(&switch_parcel);

	return ret;
}

static TEE_Result renew_switch(int32_t index, uint32_t status)
{
	ukey_apk_switch_info *switch_info = g_switch_vec.getp(&g_switch_vec,
		(uint32_t)index);
	if (switch_info == NULL) {
		tloge("Bad params.\n");
		return TEE_ERROR_BAD_PARAMETERS;
	}
	switch_info->switch_status = status;
	return write_config();
}

static TEE_Result add_switch(const char *package_name, uint32_t pkg_len,
	const char *aid, uint32_t aid_len, int status, uint32_t range_status)
{
	errno_t rc = EOK;
	TEE_Result ret = TEE_SUCCESS;

	if ((package_name == NULL) || (aid == NULL)) {
		tloge("Bad params.\n");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	ukey_apk_switch_info switch_info = create_ukey_apk_switch_info();
	ukey_apk_switch_info *element = NULL;
	switch_info.switch_status = status;

	do {
		rc = memcpy_s(switch_info.package_name, PKG_MAX_LENGTH,
			package_name, pkg_len);
		if (rc != EOK) {
			ret = TEE_ERROR_WRITE_DATA;
			destroy_ukey_apk_switch_info(&switch_info);
			break;
		}
		switch_info.aid_info.is_partial = range_status;
		element = g_switch_vec.push_back(&g_switch_vec, &switch_info);

		if (element == NULL) {
			tloge("Vector ops error.\n");
			ret = TEE_ERROR_WRITE_DATA;
			destroy_ukey_apk_switch_info(&switch_info);
			break;
		}

		if (!parcel_write(&element->aid_info.aid, aid, aid_len)) {
			if (!g_switch_vec.erase_element(&g_switch_vec,
				&switch_info,
				(uint32_t)(g_switch_vec.size(&g_switch_vec)-1)))
				tloge("Erase element error.\n");
			ret = TEE_ERROR_WRITE_DATA;
			destroy_ukey_apk_switch_info(&switch_info);
			break;
		}
		destroy_ukey_apk_switch_info(&switch_info);
		ret = write_config();
	} while (0);

	tlogd("Add rule result:%x.\n", ret);
	return (TEE_Result)ret;
}

static int32_t get_vec_index_by_pkg(const char *package_name, uint32_t pkg_len)
{
	if ((g_init_flag == 0) || (package_name == NULL)) {
		tloge("Param invalid.");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	uint32_t index = 0;
	ukey_apk_switch_info *index_item = NULL;

	FOR_EACH_TA_VECTOR(g_switch_vec, index, index_item) {
		uint32_t index_pkg_len = TA_Strlen(index_item->package_name);
		if ((index_pkg_len == pkg_len) &&
			(!TEE_MemCompare(index_item->package_name,
				package_name, index_pkg_len))) {
			tlogd("Got the switch.");
			return (int32_t)index;
		}
	}
	/* if not find, return -1 */
	return UKEY_ERROR_NO_INDEX;
}

static TEE_Result get_switch(const char *package_name, uint32_t pkg_len,
	uint32_t *switch_status)
{
	tlogd("Come get_switch.");
	if (g_init_flag == 0) {
		tloge("init not ok.");
		return TEE_ERROR_BAD_STATE;
	}
	caller_info caller_data_buf;
	TEE_Result ret = TEE_EXT_GetCallerInfo(&caller_data_buf,
		sizeof(caller_info));
	if (ret != TEE_SUCCESS) {
		tloge("Failed to get caller info ret is 0x%x.\n", ret);
		return ret;
	}
	if (caller_data_buf.session_type != SESSION_FROM_CA) {
		tloge("Get session_type error.");
		return TEE_ERROR_BAD_STATE;
	}
	if ((package_name == NULL) || (pkg_len > PKG_MAX_LENGTH) ||
		(switch_status == NULL)) {
		tloge("Param invalid.");
		return TEE_ERROR_BAD_PARAMETERS;
	}
	int32_t index = get_vec_index_by_pkg(package_name, pkg_len);
	if (index < 0) {
		tloge("Not add config yet, true default.");
		*switch_status = true;
		return TEE_SUCCESS; /* not find in vec,return true */
	}

	ukey_apk_switch_info *switch_info = g_switch_vec.getp(&g_switch_vec,
		(uint32_t)index);
	if (switch_info == NULL) {
		tloge("Switch_info is null.");
		return TEE_ERROR_GENERIC;
	}

	*switch_status = switch_info->switch_status;
	tlogd("Get status:%d.", *switch_status);
	/* renew the file */
	return TEE_SUCCESS;
}

TEE_Result set_switch(const char *package_name, uint32_t pkg_len,
	const char *aid, uint32_t aid_len,
	uint32_t status, uint32_t range_status)
{
	if (g_init_flag == 0) {
		tloge("Init not ok.");
		return TEE_ERROR_BAD_STATE;
	}
	caller_info caller_data_buf;
	TEE_Result ret = TEE_EXT_GetCallerInfo(&caller_data_buf,
		sizeof(caller_info));
	if (ret != TEE_SUCCESS) {
		tloge("Failed to get caller info ret is 0x%x.\n", ret);
		return ret;
	}
	if (caller_data_buf.session_type != SESSION_FROM_CA) {
		tloge("Set session_type error.");
		return TEE_ERROR_BAD_STATE;
	}
	if ((package_name == NULL) || (aid == NULL) ||
		(status > MAX_STATUS_VALUE) || (pkg_len > PKG_MAX_LENGTH) ||
		(aid_len > ID_MAX_LENGTH) || (range_status > MAX_STATUS_VALUE)) {
		tloge("Param invalid.");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	bool is_closed = (status == 1) ? false : true;

	int32_t index = get_vec_index_by_pkg(package_name, pkg_len);
	if (index < 0) {
		tlogi("Found no index in vec.");
		set_aidstatus_to_seservice(aid, aid_len, is_closed, range_status);
		return add_switch(package_name, pkg_len, aid, aid_len,
			status, range_status);
	} else {
		ukey_apk_switch_info *info = g_switch_vec.getp(&g_switch_vec,
			(uint32_t)index);
		if (info != NULL) {
			range_status = info->aid_info.is_partial;
			aid_len = get_parcel_data_size(&(info->aid_info.aid));
			set_aidstatus_to_seservice(get_parcel_data(&(info->aid_info.aid)),
				aid_len, is_closed, range_status);
		}

		tlogi("Information found, renew info.\n");
		return renew_switch(index, status);
	}
}

static TEE_Result fill_vec(ta_parcel_t *data_parcel)
{
	if (data_parcel == NULL) {
		tloge("Read rule error.");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	TEE_Result ret = TEE_SUCCESS;

	ukey_apk_switch_info switch_info = create_ukey_apk_switch_info();
	ukey_apk_switch_info *element = NULL;

	while (get_parcel_data_size(data_parcel) > 0) {
		element = g_switch_vec.push_back(&g_switch_vec, &switch_info);
		if (element == NULL) {
			tloge("Vector ops error.");
			ret = TEE_ERROR_READ_DATA;
			break;
		}
		if (!read_struct_from_parcel(data_parcel, element)) {
			tloge("Before erase element vector size:%d.",
				g_switch_vec.size(&g_switch_vec));
			if (!g_switch_vec.erase_element(&g_switch_vec,
				&switch_info,
				(uint32_t)(g_switch_vec.size(&g_switch_vec)-1)))
				tloge("erase element error.");
			ret = TEE_ERROR_READ_DATA;
			break;
		}
	}
	destroy_ukey_apk_switch_info(&switch_info);
	tlogd("Read rule result :%x.", ret);
	return ret;
}

static TEE_Result read_config()
{
	TEE_Result ret = TEE_SUCCESS;
	ta_parcel_t switch_parcel = create_parcel(PARCEL_DEFAULT_LENGTH,
		PARCEL_DEFAULT_ALLOC_UNIT);

	do {
		if (!read_parcel_from_file(FILE_NAME, get_security_file_ops(),
			&switch_parcel)) {
			tloge("Read rule error and begin to write file.");
			ret = TEE_ERROR_READ_DATA;
			char temp[] = "0";
			if (!parcel_write(&switch_parcel, temp, sizeof(temp))) {
				ret = TEE_ERROR_GENERIC;
				break;
			}
			if (!write_parcel_into_file(FILE_NAME, &switch_parcel,
				get_security_file_ops())) {
				tloge("Write parcel failed.");
				ret = TEE_ERROR_GENERIC;
			}
			break;
		}
		ret = fill_vec(&switch_parcel);
	} while (0);

	delete_parcel(&switch_parcel);
	return ret;
}

TEE_Result set_switch_impl(uint32_t param_types,
	TEE_Param params[TA_DEFAULT_PARAM])
{
	if ((TEE_PARAM_TYPE_GET(param_types, 0) !=
			TEE_PARAM_TYPE_MEMREF_INPUT) ||
		(TEE_PARAM_TYPE_GET(param_types, 1) !=
			TEE_PARAM_TYPE_MEMREF_INPUT) ||
		(TEE_PARAM_TYPE_GET(param_types, 2) !=
			TEE_PARAM_TYPE_VALUE_INPUT) ||
		(TEE_PARAM_TYPE_GET(param_types, 3) !=
			TEE_PARAM_TYPE_NONE) ||
		params[0].memref.buffer == NULL ||
		params[1].memref.buffer == NULL) {
		tloge("Bad expected parameter types.\n");
		return TEE_ERROR_BAD_PARAMETERS;
	}
	return set_switch(params[0].memref.buffer, params[0].memref.size,
		params[1].memref.buffer, params[1].memref.size,
		params[2].value.a, params[2].value.b);
}

TEE_Result get_switch_impl(uint32_t param_types,
	TEE_Param params[TA_DEFAULT_PARAM])
{
	if ((TEE_PARAM_TYPE_GET(param_types, 0) !=
			TEE_PARAM_TYPE_MEMREF_INPUT) ||
		(TEE_PARAM_TYPE_GET(param_types, 1) !=
			TEE_PARAM_TYPE_VALUE_OUTPUT) ||
		(TEE_PARAM_TYPE_GET(param_types, 2) !=
			TEE_PARAM_TYPE_NONE) ||
		(TEE_PARAM_TYPE_GET(param_types, 3) !=
			TEE_PARAM_TYPE_NONE) ||
		params[0].memref.buffer == NULL) {
		tloge("Bad expected parameter types.\n");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	return get_switch(params[0].memref.buffer,
		params[0].memref.size, &params[1].value.a);
}

static void destroy_parcel_in_vec()
{
	uint32_t index = 0;
	ukey_apk_switch_info *index_item = NULL;
	FOR_EACH_TA_VECTOR(g_switch_vec, index, index_item) {
		delete_parcel(&index_item->aid_info.aid);
	}
}

void data_destroy(void)
{
	if (g_init_flag == 1) {
		destroy_parcel_in_vec();
		DESTROY_TA_VECTOR(ukey_switch_vec, &g_switch_vec);
		g_init_flag = 0;
		tlogd("Data destroy end success.\n");
	}
}

TEE_Result data_init(void)
{
	if (g_init_flag == 1)
		return TEE_SUCCESS;

	if (!init_sec_storage_dir(FILE_PATH)) {
		tloge("Secure storage init error.");
		return TEE_ERROR_GENERIC;
	}

	g_switch_vec = CREATE_TA_VECTOR(ukey_switch_vec);
	TEE_Result ret = read_config();
	if (ret != TEE_SUCCESS && ret != TEE_ERROR_READ_DATA) {
		tloge("Read switch error.\n");
		destroy_parcel_in_vec();
		DESTROY_TA_VECTOR(ukey_switch_vec, &g_switch_vec);
		return TEE_ERROR_GENERIC;
	}
	/* set init flag */
	g_init_flag = 1;
	tlogi("Data init end success.\n");
	return TEE_SUCCESS;
}

TEE_Result set_se_deactive_flag(int value)
{
	caller_info caller_info_data;
	TEE_UUID panpay_uuid = TEE_SERVICE_PANAPY;

	if ((value != 0) && (value != 1)) {
		tloge("Set value error, value: %d.\n", value);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (TEE_EXT_GetCallerInfo(&caller_info_data,
		sizeof(caller_info_data)) == TEE_SUCCESS) {
		tlogd("Succeed to get caller info.\n");
		if (caller_info_data.session_type == SESSION_FROM_TA) {
			if (TEE_MemCompare(
				&(caller_info_data.caller_identity.caller_uuid),
				&panpay_uuid, sizeof(TEE_UUID)) == 0) {
				g_se_deactive_flag = value;
				tlogd("Current recover factory \
					flag value is %d.\n",
					g_se_deactive_flag);
				return TEE_SUCCESS;
			}
		}
	}
	tloge("Only panpay ta can set flag value.\n");
	return TEE_ERROR_ACCESS_DENIED;
}
