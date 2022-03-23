/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2020. All rights reserved.
 * Description: Eima TA which process message from rootscan CA
 * Create: 2018-06-11
 */

#ifdef DEF_ENG
#define LOG_ON
#endif

#include "antiroot_task.h"
#include "ccmgr_ops_ext.h"
#include "eima_task.h"
#include "root_status_ops.h"
#include "tee_ext_api.h"
#include "tee_log.h"

#define ROOTSCAN_PKGN  "antiroot-ca"
#define ROOTSCAN_UID   0

static antiroot_access antiroot_access_check(void)
{
	TEE_Result ret;
	antiroot_access ret_tmp;
	caller_info caller_info_data = { 0 };

	ret = TEE_EXT_GetCallerInfo(&caller_info_data, sizeof(caller_info));
	if (ret) {
		tloge("TEE_EXT_GetCallerInfo failed, ret %x\n", ret);
		return ANTIROOT_BAD_ACCESS;
	}

	switch (caller_info_data.session_type) {
	case SESSION_FROM_CA:
		ret_tmp = ANTIROOT_CA_ACCESS;
		break;
	case SESSION_FROM_TA:
		ret_tmp = ANTIROOT_TA_ACCESS;
		break;
	default:
		ret_tmp = ANTIROOT_BAD_ACCESS;
		break;
	}

	return ret_tmp;
}

/*
 *  Function TA_CreateEntryPoint
 *  Description:
 *    The function TA_CreateEntryPoint is the Trusted Application's
 *    constructor, which the Framework calls when it creates a new
 *    instance of the Trusted Application.
 */
__attribute__((visibility ("default"))) TEE_Result TA_CreateEntryPoint(void)
{
	TEE_Result ret = TEE_FAIL;

	tlogd("Hello EIMA and ROOTSCAN TA!\n");
	if (AddCaller_TA_all() == TEE_SUCCESS) {
		tlogd("TA CreateEntryPoint: AddCaller_TA_all success\n");
	} else {
		tloge("TA CreateEntryPoint: AddCaller_TA_all failed\n");
		return ret;
	}
	ret = AddCaller_CA_exec(ROOTSCAN_PKGN, ROOTSCAN_UID);

	return ret;
}

/*
 *  Function TA_OpenSessionEntryPoint
 *  Description:
 *    The Framework calls the function TA_OpenSessionEntryPoint
 *    when a client requests to open a session with the Trusted Application.
 *    The open session request may result in a new Trusted Application instance
 *    being created.
 */
__attribute__((visibility ("default"))) TEE_Result TA_OpenSessionEntryPoint(
				uint32_t param_types __UNUSED__,
				TEE_Param params[TEE_MAX_PARAM_NUM] __UNUSED__,
				void **session_context __UNUSED__)
{
	TEE_Result ret = TEE_SUCCESS;
	antiroot_access access_ret = antiroot_access_check();

	if (access_ret == ANTIROOT_CA_ACCESS) {
		ret = antiroot_open_session();
		if (ret != TEE_SUCCESS) {
			tloge("EIMA init root check error, ret = %x!\n", ret);
			return ret;
		}
		ret = eima_init();
		if (ret != TEE_SUCCESS) {
			tloge("EIMA init ima check error, ret = %x!\n", ret);
			return ret;
		}
	} else if (access_ret == ANTIROOT_BAD_ACCESS) {
		tloge("ANTIROOT_BAD_ACCESS!");
		return TEE_ERROR_GENERIC;
	}
	tlogd("----TA OpenSessionEntryPoint successed!\n");
	return ret;
}

static TEE_Result check_ca_command_param(uint32_t param_types,
					TEE_Param params[TEE_MAX_PARAM_NUM])
{
	if (params == NULL) {
		tloge("EIMA: Bad params\n");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (!check_param_type(param_types,
			TEE_PARAM_TYPE_MEMREF_INOUT,
			TEE_PARAM_TYPE_VALUE_OUTPUT,
			TEE_PARAM_TYPE_NONE,
			TEE_PARAM_TYPE_NONE)) {
		tloge("EIMA: Bad expected parameter types\n");
		return TEE_ERROR_BAD_PARAMETERS;
	}
	return TEE_SUCCESS;
}

static bool check_ca_cmd(uint32_t cmd_id,
					TEE_Param params[TEE_MAX_PARAM_NUM])
{
	uint32_t root_status;

	root_status = __SRE_ReadRootStatus();
	tlogd("EIMA: __SRE_ReadRootStatus 0x%x\n", root_status);

	/* add process for user version system. */
	if (root_status & (0x1 << ROOTSTATE_BIT)) {
		tloge("EIMA: phone is root, read status 0x%x\n", root_status);

		/* If is user version and root, TA not process CA messages. */
		if (get_eng_status() != ENG_VERSION) {
			params[1].value.a = REV_ROOTED;
			params[1].value.b = __SRE_ReadRootStatus();

			/*
			 * Only challenge and response need process
			 * TA cannot be stopped when the phone is root
			 * All detection items need to be checked in timer
			 */
			if ((cmd_id != CMD_SEND_CHALLENGE) &&
				(cmd_id != CMD_GET_RESPONSE)) {
				return false;
			}
		}
	}

	return true;
}

static TEE_Result handle_ca_command(
			uint32_t cmd_id,
			uint32_t param_types,
			TEE_Param params[TEE_MAX_PARAM_NUM])
{
	TEE_Result ret = TEE_FAIL;
	bool is_continue_whenroot = true;

	if (check_ca_command_param(param_types, params) != TEE_SUCCESS)
		return TEE_ERROR_BAD_PARAMETERS;

	params[1].value.a = REV_NOT_ROOT;

	is_continue_whenroot = check_ca_cmd(cmd_id, params);
	if (is_continue_whenroot == false) {
		return TEE_SUCCESS;
	}

	tlogd("EIMA: input the cmd is 0x%x\n", cmd_id);
	switch (cmd_id) {
	case CMD_SET_WHITELIST:
	case CMD_SEND_CHALLENGE:
	case CMD_GET_RESPONSE:

#ifdef TEE_KERNEL_MEASUREMENT
	case CMD_GET_REE_KERNEL_PHYSICAL_ADDR:
	case CMD_PAUSE_MEASURE:
	case CMD_RESUME_MEASURE:

#ifdef DEF_ENG
	case CMD_TEE_STATUS_TEST:
#endif
#endif
		ret = antiroot_hand_cmd(params, cmd_id);
		params[1].value.b = __SRE_ReadRootStatus();
		break;
	case CMD_EIMA_CHALLENGE:
	case CMD_EIMA_RESPONSE:
		ret = eima_handle_cmd(params, cmd_id);
		params[1].value.b = __SRE_ReadRootStatus();
		break;
	default:
		tloge("invalid cmd id!cmd = %u\n", cmd_id);
		ret = AR_ERR_INVOKE_ERROR;
		break;
	}
	return  ret;
}

static TEE_Result handle_ta_command(uint32_t cmd_id, uint32_t param_types,
			TEE_Param params[TEE_MAX_PARAM_NUM])
{
	TEE_Result ret = TEE_SUCCESS;

	if (params == NULL) {
		tloge("EIMA: Bad params\n");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (!check_param_type(param_types,
			TEE_PARAM_TYPE_VALUE_OUTPUT,
			TEE_PARAM_TYPE_NONE,
			TEE_PARAM_TYPE_NONE,
			TEE_PARAM_TYPE_NONE)) {
		tloge("EIMA: Bad expected parameter types\n");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	switch (cmd_id) {
	case CMD_GET_DEVICE_ROOT_STATUS:
		params[0].value.a = antiroot_get_root_status();
		tlogd("EIMA: handle ta command is %u **** %u\n",
			params[0].value.a, __SRE_ReadRootStatus());
		break;
	case CMD_GET_DEVICE_ROOT_STATUS_DETAIL:
		params[0].value.a = antiroot_get_root_status_detail();
		tlogd("EIMA: handle ta root detail is %u **** %u\n",
			params[0].value.a, __SRE_ReadRootStatus());
		break;
	default:
		tloge("invalid cmd id!cmd = %u\n", cmd_id);
		ret = AR_ERR_INVOKE_ERROR;
		break;
	}
	return ret;
}

/*
 *  Function TA_InvokeCommandEntryPoint:
 *  Description:
 *    The Framework calls this function when the client invokes a command
 *    within the given session.
 */
__attribute__((visibility ("default"))) TEE_Result TA_InvokeCommandEntryPoint(
				void *session_context __UNUSED__,
				uint32_t cmd_id,
				uint32_t param_types,
				TEE_Param params[TEE_MAX_PARAM_NUM])
{
	TEE_Result ret = TEE_SUCCESS;
	antiroot_access access_ret;
	CRYSError_t crys_ret;

	if (params == NULL) {
		tloge("EIMA: Bad params\n");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	crys_ret = __CC_DX_power_on();
	if (crys_ret != 0) {
		tloge("CC DX power on failed\n");
		return TEE_ERROR_GENERIC;
	}

	access_ret = antiroot_access_check();
	if (access_ret == ANTIROOT_CA_ACCESS) {
		ret = handle_ca_command(cmd_id, param_types, params);
	} else if (access_ret == ANTIROOT_TA_ACCESS) {
		ret = handle_ta_command(cmd_id, param_types, params);
	} else {
		tlogd("EIMA: ta has no right to access 0x%x\n", access_ret);
		ret = TEE_ERROR_ACCESS_DENIED;
	}

	crys_ret = __CC_DX_power_down();
	if (crys_ret != 0) {
		tloge("CC DX power down failed\n");
		return TEE_ERROR_GENERIC;
	}

	tlogd("EIMA: TA InvokeCommandEntryPoint ret is %x\n", ret);
	return  ret;
}

/*
 *  Function TA_CloseSessionEntryPoint:
 *  Description:
 *    The Framework calls this function to close a client session.
 *    During the call to this function the implementation can use
 *    any session functions.
 */
__attribute__((visibility ("default"))) void TA_CloseSessionEntryPoint(const void *session_context __UNUSED__)
{
	tlogi("---- EIMA TA Close Session! -----\n");
	antiroot_access access_ret = antiroot_access_check();

	if (access_ret == ANTIROOT_CA_ACCESS) {
		antiroot_close_session();
		eima_deinit();
	}
}

/*
 *  Function TA_DestroyEntryPoint
 *  Description:
 *    The function TA_DestroyEntryPoint is the Trusted Application's destructor,
 *    which the Framework calls when the instance is being destroyed.
 */
__attribute__((visibility ("default"))) void TA_DestroyEntryPoint(void)
{
	tlogd("---- EIMA TA destroyed points! -----\n");
}
