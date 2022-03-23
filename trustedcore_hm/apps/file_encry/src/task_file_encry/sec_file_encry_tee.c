/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * Description: TA for FBE2
 * Create: 2018-06-11
 */

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma GCC diagnostic ignored "-Wimplicit-function-declaration"

#include "sec_file_encry_tee.h"

#include "sre_typedef.h"
#include "tee_internal_api.h"
#include "tee_log.h"

/*
 *  Trusted Application Entry Points
 *  Description:
 *    The function TA_CreateEntryPoint is the Trusted Application's constructor,
 *    which the Framework calls when it creates a new instance of
 *    the Trusted Application.
 */
__attribute__((visibility ("default"))) TEE_Result TA_CreateEntryPoint(void)
{
	tlogd("----- %s -----\n", __func__);
	TEE_Result ret;

	ret = (TEE_Result)AddCaller_CA_exec(SEC_FE_VOLD_NAME, SEC_FE_VOLD_UID);
	if (ret != TEE_SUCCESS) {
		tloge("----- %s failed = 0x%lx-----\n", __func__, ret);
		return ret;
	}

	ret = (TEE_Result)AddCaller_CA_exec(SEC_FE_UFS_NAME, SEC_FE_UFS_UID);
	if (ret != TEE_SUCCESS)
		tloge("----- %s failed = 0x%lx-----\n", __func__, ret);

	return ret;
}

/*
 *  Function TA_OpenSessionEntryPoint
 *  Description:
 *    The Framework calls the function TA_OpenSessionEntryPoint
 *    when a client requests to open a session with the Trusted Application.
 *    The open session request may result in a new Trusted Application instance
 *    being created.
 *    The number of params[] is 4, according to the GPTEE SPEC
 */
__attribute__((visibility ("default"))) TEE_Result TA_OpenSessionEntryPoint(uint32_t paramTypes,
				    TEE_Param params[4], void **sessionContext)
{
	TEE_Result ret = TEE_SUCCESS;

	tlogd("---- %s --------\n", __func__);

	return ret;
}

static int file_encry_drv(uint32_t cmd_id, uint8_t *iv_buf, uint32_t length)
{
	return __file_encry_interface(cmd_id, iv_buf, length);
}

/*
 *  Function TA_InvokeCommandEntryPoint:
 *  Description:
 *    The Framework calls this function when the client invokes a command
 *    within the given session.
 *    The number of params[] is 4, according to the GPTEE SPEC
 */
__attribute__((visibility ("default"))) TEE_Result TA_InvokeCommandEntryPoint(void *session_context, uint32_t cmd_id,
				      uint32_t paramTypes, TEE_Param params[4])
{
	uint8_t dummy_buf = 0;
	int ret;

	switch (cmd_id) {
	case SEC_FILE_ENCRY_CMD_ID_VOLD_ADD_IV:
	case SEC_FILE_ENCRY_CMD_ID_VOLD_DELETE_IV:
		if (!check_param_type(paramTypes,
				      TEE_PARAM_TYPE_MEMREF_INOUT,
				      TEE_PARAM_TYPE_NONE,
				      TEE_PARAM_TYPE_NONE,
				      TEE_PARAM_TYPE_NONE)) {
			tloge("file encry check_params_type fail!\n");
			return TEE_FAIL;
		}

		ret = file_encry_drv(cmd_id, params[0].memref.buffer,
				     params[0].memref.size);
		if (ret != FILE_ENCRY_OK) {
			tloge("file_encry_drv fail!, %d\n", ret);
			return TEE_FAIL;
		}

		return TEE_SUCCESS;

	case SEC_FILE_ENCRY_CMD_ID_UFS_RESTORE_IV:
		if (!check_param_type(paramTypes, TEE_PARAM_TYPE_NONE,
				      TEE_PARAM_TYPE_NONE,
				      TEE_PARAM_TYPE_NONE,
				      TEE_PARAM_TYPE_NONE)) {
			tloge("file encry check_params_type fail!\n");
			return TEE_FAIL;
		}

		ret = file_encry_drv(cmd_id, &dummy_buf, sizeof(dummy_buf));
		if (ret != FILE_ENCRY_OK) {
			tloge("file_encry_drv fail!, %d\n", ret);
			return TEE_FAIL;
		}

		return TEE_SUCCESS;

	default:
		tlogd("invalid command.\n");
		return TEE_ERROR_INVALID_CMD;
	}
}

/*
 *  Function TA_CloseSessionEntryPoint:
 *  Description:
 *    The Framework calls this function to close a client session.
 *    During the call to this function the implementation can use
 *    any session functions.
 */
__attribute__((visibility ("default"))) void TA_CloseSessionEntryPoint(void *session_context)
{
	tlogd("---- %s -----\n", __func__);
}

/*
 *  Function TA_DestroyEntryPoint
 *  Description:
 *    The function TA_DestroyEntryPoint is the Trusted Application's destructor,
 *    which the Framework calls when the instance is being destroyed.
 */
__attribute__((visibility ("default"))) void TA_DestroyEntryPoint(void)
{
	tlogd("---- %s -----\n", __func__);
}

#pragma GCC diagnostic pop
