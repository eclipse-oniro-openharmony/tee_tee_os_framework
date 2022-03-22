/*
* Copyright (c) Huawei Technologies Co., Ltd. 2015-2018. All rights reserved.
 * Description: Signature Verify CBB Library
 * Author: t00307193
 * Create: 2015
 * History: 2018/11/23 y00309840 UK rule fixes
 */
#ifndef H_CMSCBB_COMMON_H
#define H_CMSCBB_COMMON_H
#include "../cmscbb_common/cmscbb_buf.h"
#include "cmscbb_sdk.h"

#if CMSCBB_WITHOUT_SECUREC == 0
#include "securec.h"
#endif

#define CMSCBB_LOG_NAME "cmscbb_log.log"

#if CMSCBB_ENABLE_LOG
CVB_VOID CmscbbLogCallback(CMSCBB_LOG_TYPE log_level, const CVB_CHAR* filename, CVB_INT line, const CVB_CHAR* function, CMSCBB_ERROR_CODE rc, const CVB_CHAR* log, ...);

#ifndef CMSCBB_LOG_LEVEL
#define CMSCBB_LOG_LEVEL 1
#endif

#if CMSCBB_LOG_LEVEL >= 0
#define CVB_LOG_ERROR(rc, msg) CmscbbLogCallback(CMSCBB_LOG_TYPE_ERROR, (const CVB_CHAR*)CMSCBB_LOG_NAME, __LINE__, (const CVB_CHAR*)__FUNCTION__, rc, (const CVB_CHAR*)msg)
#define CVB_LOG_ERROR1(rc, msg, arg1) CmscbbLogCallback(CMSCBB_LOG_TYPE_ERROR, (const CVB_CHAR*)CMSCBB_LOG_NAME, __LINE__, (const CVB_CHAR*)__FUNCTION__, rc, (const CVB_CHAR*)msg, arg1)
#endif
#if CMSCBB_LOG_LEVEL >= 1
#define CVB_LOG_WARNING(rc, msg) CmscbbLogCallback(CMSCBB_LOG_TYPE_WARNING, (const CVB_CHAR*)CMSCBB_LOG_NAME, __LINE__, (const CVB_CHAR*)__FUNCTION__, rc, (const CVB_CHAR*)msg)
#define CVB_LOG_WARNING1(rc, msg, arg1) CmscbbLogCallback(CMSCBB_LOG_TYPE_WARNING, (const CVB_CHAR*)CMSCBB_LOG_NAME, __LINE__, (const CVB_CHAR*)__FUNCTION__, rc, (const CVB_CHAR*)msg, arg1)
#endif
#if CMSCBB_LOG_LEVEL >= 2
#define CVB_LOG_INFO(rc, msg) CmscbbLogCallback(CMSCBB_LOG_TYPE_INFO, (const CVB_CHAR*)CMSCBB_LOG_NAME, __LINE__, (const CVB_CHAR*)__FUNCTION__, rc, (const CVB_CHAR*)msg)
#define CVB_LOG_INFO1(rc, msg, arg1) CmscbbLogCallback(CMSCBB_LOG_TYPE_INFO, (const CVB_CHAR*)CMSCBB_LOG_NAME, __LINE__, (const CVB_CHAR*)__FUNCTION__, rc, (const CVB_CHAR*)msg, arg1)
#endif
#if CMSCBB_LOG_LEVEL >= 3
#define CVB_LOG_DEBUG(rc, msg) CmscbbLogCallback(CMSCBB_LOG_TYPE_DEBUG, (const CVB_CHAR*)CMSCBB_LOG_NAME, __LINE__, (const CVB_CHAR*)__FUNCTION__, rc, (const CVB_CHAR*)msg)
#define CVB_LOG_DEBUG1(rc, msg, arg1) CmscbbLogCallback(CMSCBB_LOG_TYPE_DEBUG, (const CVB_CHAR*)CMSCBB_LOG_NAME, __LINE__, (const CVB_CHAR*)__FUNCTION__, rc, (const CVB_CHAR*)msg, arg1)
#endif
#endif

#ifndef CVB_LOG_ERROR
#define CVB_LOG_ERROR(rc, msg)
#endif
#ifndef CVB_LOG_ERROR1
#define CVB_LOG_ERROR1(rc, msg, arg1)
#endif
#ifndef CVB_LOG_WARNING
#define CVB_LOG_WARNING(rc, msg)
#endif
#ifndef CVB_LOG_WARNING1
#define CVB_LOG_WARNING1(rc, msg, arg1)
#endif
#ifndef CVB_LOG_INFO
#define CVB_LOG_INFO(rc, msg)
#endif
#ifndef CVB_LOG_INFO1
#define CVB_LOG_INFO1(rc, msg, arg1)
#endif
#ifndef CVB_LOG_DEBUG
#define CVB_LOG_DEBUG(rc, msg)
#endif
#ifndef CVB_LOG_DEBUG1
#define CVB_LOG_DEBUG1(rc, msg, arg1)
#endif

#define CVB_FAILED(ret) ((ret) != CVB_SUCCESS)

#define CVB_GOTO_ERR_IF_FAIL(ret) if (CVB_FAILED(ret)) { CVB_LOG_DEBUG(ret, CVB_NULL); goto CVB_ERR; }
#define CVB_GOTO_ERR_IF_FAIL_LOG(ret) if (CVB_FAILED(ret)) { CVB_LOG_ERROR(ret, CVB_NULL); goto CVB_ERR; }

#define CVB_GOTO_ERR_IF(cond, err_code) if (cond) { CVB_LOG_DEBUG(err_code, CVB_NULL); ret = err_code; goto CVB_ERR; }
#define CVB_GOTO_ERR_WITH_LOG_IF(cond, err_code) if (cond) { CVB_LOG_ERROR(err_code, CVB_NULL); ret = err_code; goto CVB_ERR; }

/*
 * Prototype    : CmscbbMktime
 * Description  : <TODO>
 * Params
 *   [IN] datetime: datetime struct
 * Return Value : CVB_TIME_T
 *   Date              Author     Modification
 *   2015/08/14 17:43  t00307193  Create
 */
CVB_TIME_T CmscbbMktime(const CmscbbDatetime* datetime);

/*
 * Prototype    : CmscbbMallocWith0
 * Description  : implement
 * Params
 *   [IN] ppByte: bytes
 *   [IN] size:  size of bytes
 * Return Value : CMSCBB_ERROR_CODE
 *   Date              Author     Modification
 *   2015/08/11 12:17  t00307193  Create
 */
CMSCBB_ERROR_CODE CmscbbMallocWith0(CVB_VOID** ppByte, CVB_SIZE_T size);

#endif /* H_CMSCBB_COMMON_H */
