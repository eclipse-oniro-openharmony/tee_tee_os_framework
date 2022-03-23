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

#ifndef __TL_M_SEC_DRIVER_API_H__
#define __TL_M_SEC_DRIVER_API_H__

#include "tlApisec.h"

/*
 * Error code for Device APC
 */
#define DEVAPC_API_OK                       0x00000000
#define DEVAPC_ERROR_SMC_CALL_API_FAIL      0x10000000
#define DEVAPC_ERROR_SMC_CALL_RESULT_FAIL   0x20000000
#define DEVAPC_ERROR_BOUNDARY_CHECK_FAIL    0x30000000

int32_t tlset_devapc_protect(enum DEVAPC_MODULE_REQ_TYPE module,
		enum DEVAPC_PROTECT_ON_OFF onoff, uint32_t param);
int32_t tlset_devapc_master_trans(enum DEVAPC_MASTER_REQ_TYPE module,
		enum DEVAPC_PROTECT_ON_OFF onoff, uint32_t param);

#endif // __TL_M_SEC_DRIVER_API_H__
