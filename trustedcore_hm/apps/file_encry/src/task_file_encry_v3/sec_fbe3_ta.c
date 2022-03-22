/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: TA for FBE3
 * Create: 2020/01/09
 */

#include "sec_fbe3_ta.h"
#include "sec_fbe3_interface.h"

#include "sre_typedef.h"
#include "tee_internal_api.h"
#include "tee_log.h"
#include "tee_common.h"
#include "tee_time_api.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wimplicit-function-declaration"

#define S_TO_MS 1000
#define TIME_2S 2000
/*
 *  Trusted Application Entry Points
 *  Description:
 *    The function TA_CreateEntryPoint is the Trusted Application's constructor,
 *    which the Framework calls when it creates a new instance of
 *    the Trusted Application.
 */

__default TEE_Result TA_CreateEntryPoint(void)
{
	tlogd("---- %s --------\n", __func__);
	TEE_Result ret;

	ret = AddCaller_CA_exec(SEC_FE_UFS_NAME, SEC_FE_UFS_UID);
	if (ret != TEE_SUCCESS) {
		tloge("%s, add CA exec fail 0x%x\n", __func__, ret);
		return ret;
	}
	ret = file_encry_prepare_ckey();
	if (ret != FILE_ENCRY_OK) {
		tloge("%s, get ckeyinfo fail 0x%x\n", __func__, ret);
		return ret;
	}

	return TEE_SUCCESS;
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
__default TEE_Result TA_OpenSessionEntryPoint(uint32_t paramTypes __unused,
					      TEE_Param params[4] __unused,
					      void **sessionContext __unused)
{
	TEE_Result ret = TEE_SUCCESS;

	tlogd("---- %s --------\n", __func__);

	return ret;
}

/*
 *  Function TA_InvokeCommandEntryPoint:
 *  Description:
 *    The Framework calls this function when the client invokes a command
 *    within the given session.
 *    The number of params[] is 4, according to the GPTEE SPEC
 */
__default TEE_Result TA_InvokeCommandEntryPoint(void *session_context __unused,
						uint32_t cmd_id,
						uint32_t paramTypes,
						TEE_Param params[4])
{
	uint32_t ret;
	uint8_t cmd_idx;
	uint32_t start;
	uint32_t end;
	uint32_t diff;
	TEE_Time time = {0};

	static const file_encry_cb dispatch[] = {
		FILE_ENCRY_LIST
	};
	TEE_GetSystemTime(&time);
	start = time.seconds * S_TO_MS + time.millis;
	if (cmd_id >= ARRAY_SIZE(dispatch)) {
		tloge("%s, unsupported cmd id, 0x%x\n", __func__, cmd_id);
		return FILE_ENCRY_ERROR_CMD_INVALID;
	}
	cmd_idx = (cmd_id & SEC_FILE_ENCRY_CMD_ID_MASK);

	if (!dispatch[cmd_idx]) {
		tloge("%s, unregistter call back\n", __func__);
		return FILE_ENCRY_ERROR_CMD_UNSUPPORT;
	}
	ret = dispatch[cmd_idx](paramTypes, params);

	TEE_GetSystemTime(&time);
	end = time.seconds * S_TO_MS + time.millis;
	diff = end - start;
	if (diff > TIME_2S)
		tloge("FBE works %lums, cmd id 0x%x\n", diff, cmd_idx);
	if (ret != FILE_ENCRY_OK) {
		tloge("fbe3 0x%x request fail, 0x%x\n", cmd_id, ret);
		return ret;
	}

	return TEE_SUCCESS;
}

/*
 *  Function TA_CloseSessionEntryPoint:
 *  Description:
 *    The Framework calls this function to close a client session.
 *    During the call to this function the implementation can use
 *    any session functions.
 */
__default void TA_CloseSessionEntryPoint(void *session_context __unused)
{
	tlogd("---- %s -----\n", __func__);
}

/*
 *  Function TA_DestroyEntryPoint
 *  Description:
 *    The function TA_DestroyEntryPoint is the Trusted Application's destructor,
 *    which the Framework calls when the instance is being destroyed.
 */
__default void TA_DestroyEntryPoint(void)
{
	tlogd("---- %s -----\n", __func__);
}

#pragma GCC diagnostic pop
