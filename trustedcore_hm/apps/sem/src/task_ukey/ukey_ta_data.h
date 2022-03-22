/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * Description: ukey ta header file
 * Author: hanxuanwei 00353015
 * Create: 2019-05-26
 * History: 2019-04-08 hanyefei h00497291 CSEC rectification
 */
#ifndef UKEY_TA_DATA_H
#define UKEY_TA_DATA_H
#include "TA_Parcel.h"
#include "TA_Vector.h"
#include "libhwsecurec/securec.h"
#include "tee_internal_api.h"

#define PKG_MAX_LENGTH 256
#define ID_MAX_LENGTH 16
#define MAX_TYPE_VALUE 1
#define MAX_STATUS_VALUE 1
#define MAX_ALLOW_AID_COUNT 6
#define TA_DEFAULT_PARAM 4

enum ukey_error {
	UKEY_SUCCESS = 0x00000000,
	UKEY_ERROR_FILE = 0x3333ff00, /* file not found */
	UKEY_ERROR_INIT,
	UKEY_ERROR_BAD_PARAMS,
	UKEY_ERROR_NO_MEM,
	UKEY_ERROR_GENERIC,
	UKEY_ERROR_PARCEL,
	UKEY_ERROR_VECTOR,
	UKEY_ERROR_BAD_CMD,
	UKEY_ERROR_NO_INDEX = 0xffffffff,
};

typedef struct {
	ta_parcel_t aid;
	bool is_partial;
} ukey_aid_info;

typedef struct {
	int ta_type;
	int ta_owner;
	int aid_count;
	ukey_aid_info allow_aids[MAX_ALLOW_AID_COUNT];
} ukey_ta_permission_info;

typedef struct {
	char package_name[PKG_MAX_LENGTH + 1];
	ukey_aid_info aid_info;
	uint32_t reserve;
	bool switch_status;
} ukey_apk_switch_info;

TEE_Result set_se_deactive_flag(int value);
TEE_Result data_init(void);
TEE_Result set_switch_impl(uint32_t param_types,
	TEE_Param params[TA_DEFAULT_PARAM]);
TEE_Result get_switch_impl(uint32_t param_types,
	TEE_Param params[TA_DEFAULT_PARAM]);
bool check_applet_accessibility(TEE_UUID uuid,
	const uint8_t *select_cmd, uint32_t select_cmd_len);
void data_destroy(void);
/* vector of switch */
DECLARE_TA_VECTOR(ukey_switch_vec, ukey_apk_switch_info)
#endif
