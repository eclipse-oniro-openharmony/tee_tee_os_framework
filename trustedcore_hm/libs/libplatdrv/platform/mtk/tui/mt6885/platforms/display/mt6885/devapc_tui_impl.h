/*
 * Copyright (c) 2016 - 2020 MediaTek Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files
 * (the "Software"), to deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge,
 * publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include "tlApisec.h"
#include "drStd.h"
#include "tlSecDriverApi.h"
#include "devapc_hal_impl.h"
#include "drv_fwk.h"

static inline uint32_t tui_set_devapc_protect(
		enum DEVAPC_MODULE_REQ_TYPE module,
		enum DEVAPC_PROTECT_ON_OFF onoff, uint32_t param)
{
	uint32_t api_ret, smc_ret;

	api_ret = msee_smc_call(MTK_SIP_TEE_HAL_APC_SET_AARCH32, module,
			onoff, param, &smc_ret);

	if (api_ret) {
		tloge("%s: SMC API failed, ret=0x%x\n", __func__,
				api_ret);
		return DEVAPC_ERROR_SMC_CALL_API_FAIL;

	} else if (smc_ret) {
		tloge("%s: SMC Set failed, ret=0x%x\n", __func__,
				smc_ret);
		return DEVAPC_ERROR_SMC_CALL_RESULT_FAIL;
	}

	tlogd("SMC passed!\n");
	return DEVAPC_API_OK;
}
