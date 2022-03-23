/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: system call interface for FBE3
 * Create: 2020/01/07
 */

#include "sec_fbe3_interface.h"
#include "sec_fbe3_ta.h"
#include "sec_fbe3_drv.h"

#include "sre_typedef.h"
#include "tee_internal_api.h"
#include "tee_log.h"

uint32_t file_encry_restore_interface(uint32_t paramTypes,
				      TEE_Param params[PARAM_NUM] __unused)
{
	if (!check_param_type(paramTypes, TEE_PARAM_TYPE_NONE,
			      TEE_PARAM_TYPE_NONE,
			      TEE_PARAM_TYPE_NONE,
			      TEE_PARAM_TYPE_NONE)) {
		tloge("%s, check_params_type fail!\n", __func__);
		return FILE_ENCRY_ERROR_INPUT_PARAM;
	}
	return file_encry_restore_iv();
}

uint32_t file_encry_lock_interface(uint32_t paramTypes, TEE_Param params[PARAM_NUM])
{
	if (!check_param_type(paramTypes, TEE_PARAM_TYPE_VALUE_INPUT,
			      TEE_PARAM_TYPE_NONE,
			      TEE_PARAM_TYPE_NONE,
			      TEE_PARAM_TYPE_NONE)) {
		tloge("%s, check_params_type fail!\n", __func__);
		return FILE_ENCRY_ERROR_INPUT_PARAM;
	}
	return file_encry_lock_screen(params[0].value.a, params[0].value.b);
}

uint32_t file_encry_unlock_interface(uint32_t paramTypes, TEE_Param params[PARAM_NUM])
{
	if (!check_param_type(paramTypes, TEE_PARAM_TYPE_MEMREF_INOUT,
			      TEE_PARAM_TYPE_VALUE_INPUT,
			      TEE_PARAM_TYPE_NONE,
			      TEE_PARAM_TYPE_NONE)) {
		tloge("%s, check_params_type fail!\n", __func__);
		return FILE_ENCRY_ERROR_INPUT_PARAM;
	}
	return file_encry_unlock_screen(params[1].value.a, params[1].value.b,
					params[0].memref.buffer,
					params[0].memref.size);
}

uint32_t file_encry_logout_interface(uint32_t paramTypes, TEE_Param params[PARAM_NUM])
{
	if (!check_param_type(paramTypes, TEE_PARAM_TYPE_MEMREF_INPUT,
			      TEE_PARAM_TYPE_VALUE_INPUT,
			      TEE_PARAM_TYPE_NONE,
			      TEE_PARAM_TYPE_NONE)) {
		tloge("%s, check_params_type fail!\n", __func__);
		return FILE_ENCRY_ERROR_INPUT_PARAM;
	}
	return file_encry_user_logout(params[1].value.a, params[1].value.b,
				      params[0].memref.buffer,
				      params[0].memref.size);
}

uint32_t file_encry_add_interface(uint32_t paramTypes, TEE_Param params[PARAM_NUM])
{
	if (!check_param_type(paramTypes, TEE_PARAM_TYPE_MEMREF_INOUT,
			      TEE_PARAM_TYPE_VALUE_INPUT,
			      TEE_PARAM_TYPE_NONE,
			      TEE_PARAM_TYPE_NONE)) {
		tloge("%s, check_params_type fail!\n", __func__);
		return FILE_ENCRY_ERROR_INPUT_PARAM;
	}

	return file_encry_add_key(params[1].value.a, params[1].value.b,
				  params[0].memref.buffer,
				  params[0].memref.size);
}

uint32_t file_encry_delete_interface(uint32_t paramTypes, TEE_Param params[PARAM_NUM])
{
	if (!check_param_type(paramTypes, TEE_PARAM_TYPE_MEMREF_INPUT,
			      TEE_PARAM_TYPE_VALUE_INPUT,
			      TEE_PARAM_TYPE_NONE,
			      TEE_PARAM_TYPE_NONE)) {
		tloge("%s, check_params_type fail!\n", __func__);
		return FILE_ENCRY_ERROR_INPUT_PARAM;
	}
	return file_encry_delete_key(params[1].value.a, params[1].value.b,
				     params[0].memref.buffer,
				     params[0].memref.size);
}

uint32_t file_encry_new_interface(uint32_t paramTypes, TEE_Param params[PARAM_NUM])
{
	if (!check_param_type(paramTypes, TEE_PARAM_TYPE_VALUE_INPUT,
			      TEE_PARAM_TYPE_MEMREF_OUTPUT,
			      TEE_PARAM_TYPE_MEMREF_OUTPUT,
			      TEE_PARAM_TYPE_NONE)) {
		tloge("%s, check_params_type fail!\n", __func__);
		return FILE_ENCRY_ERROR_INPUT_PARAM;
	}
	return file_encry_new_sece(params[0].value.a,
				   params[1].memref.buffer,
				   params[1].memref.size,
				   params[2].memref.buffer,
				   params[2].memref.size);
}

uint32_t file_encry_open_interface(uint32_t paramTypes, TEE_Param params[PARAM_NUM])
{
	if (!check_param_type(paramTypes, TEE_PARAM_TYPE_VALUE_INPUT,
			      TEE_PARAM_TYPE_MEMREF_INPUT,
			      TEE_PARAM_TYPE_MEMREF_OUTPUT,
			      TEE_PARAM_TYPE_NONE)) {
		tloge("%s, check_params_type fail!\n", __func__);
		return FILE_ENCRY_ERROR_INPUT_PARAM;
	}
	return file_encry_open_sece(params[0].value.a,
				    params[1].memref.buffer,
				    params[1].memref.size,
				    params[2].memref.buffer,
				    params[2].memref.size);
}

uint32_t file_encry_enable_kdf_interface(uint32_t paramTypes,
					 TEE_Param params[PARAM_NUM] __unused)
{
	if (!check_param_type(paramTypes, TEE_PARAM_TYPE_NONE,
			      TEE_PARAM_TYPE_NONE,
			      TEE_PARAM_TYPE_NONE,
			      TEE_PARAM_TYPE_NONE)) {
		tloge("%s, check_params_type fail!\n", __func__);
		return FILE_ENCRY_ERROR_INPUT_PARAM;
	}
	return file_encry_enable_kdf_ta();
}

uint32_t file_encry_preload_key(uint32_t paramTypes, TEE_Param params[PARAM_NUM])
{
	if (!check_param_type(paramTypes, TEE_PARAM_TYPE_VALUE_INPUT,
			      TEE_PARAM_TYPE_NONE,
			      TEE_PARAM_TYPE_NONE,
			      TEE_PARAM_TYPE_NONE)) {
		tloge("%s, check_params_type fail!\n", __func__);
		return FILE_ENCRY_ERROR_INPUT_PARAM;
	}
	return file_encry_prefetch_key(params[0].value.a);
}

uint32_t file_encry_msp_status(uint32_t paramTypes, TEE_Param params[PARAM_NUM])
{
	bool status = false;
	if (!check_param_type(paramTypes, TEE_PARAM_TYPE_VALUE_OUTPUT,
			      TEE_PARAM_TYPE_NONE,
			      TEE_PARAM_TYPE_NONE,
			      TEE_PARAM_TYPE_NONE)) {
		tloge("%s, check_params_type fail!\n", __func__);
		return FILE_ENCRY_ERROR_INPUT_PARAM;
	}
	status = file_encry_msp_available();
	params[0].value.a = status ? MSP_ONLINE : MSP_OFFLINE;
	return 0;
}

uint32_t file_encry_status_report(uint32_t paramTypes,
				  TEE_Param params[PARAM_NUM] __unused)
{
	if (!check_param_type(paramTypes, TEE_PARAM_TYPE_NONE,
			      TEE_PARAM_TYPE_NONE,
			      TEE_PARAM_TYPE_NONE,
			      TEE_PARAM_TYPE_NONE)) {
		tloge("%s, check_params_type fail!\n", __func__);
		return FILE_ENCRY_ERROR_INPUT_PARAM;
	}
	return file_encry_rpmb_times();
}

uint32_t file_encry_undefined(uint32_t paramTypes __unused,
			      TEE_Param params[PARAM_NUM] __unused)
{
	tloge("%s, unsupport cmd!\n", __func__);
	return FILE_ENCRY_ERROR_CMD_UNDEFINED;
}
