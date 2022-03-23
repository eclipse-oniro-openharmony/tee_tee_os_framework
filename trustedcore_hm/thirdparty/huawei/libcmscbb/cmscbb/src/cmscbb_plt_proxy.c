/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2015-2018. All rights reserved.
 * Description: Signature Verify CBB Library
 * Author: t00307193
 * Create: 2015
 * History: 2018/11/23 y00309840 UK rule fixes
 */
#include "../cmscbb_common/cmscbb_plt_proxy.h"
#include "cmscbb_config.h"
#include "../cmscbb_common/cmscbb_common.h"

#if CMSCBB_ENABLE_LOG
#ifndef MAX_LOG_STR_LEN
#define MAX_LOG_STR_LEN 2048
#endif
#ifndef CMSCBB_LOG_LEVEL
#define CMSCBB_LOG_LEVEL CMSCBB_LOG_TYPE_ERROR
#endif

CVB_VOID CmscbbLogCallback(CMSCBB_LOG_TYPE log_level, const CVB_CHAR* filename, CVB_INT line, const CVB_CHAR* function,
    CMSCBB_ERROR_CODE rc, const CVB_CHAR* msg, ...)
{
    if (filename == CVB_NULL || function == CVB_NULL) {
        return;
    }

    if (CMSCBB_LOG_LEVEL >= (CVB_UINT)log_level) {
        CVB_CHAR* log = CVB_NULL;
        CMSCBB_ERROR_CODE ret;

        ret = CmscbbMallocWith0((CVB_VOID**)&log, MAX_LOG_STR_LEN);
        if (CVB_FAILED(ret)) {
            CmscbbLogPrint(CMSCBB_LOG_TYPE_ERROR, (const CVB_CHAR*)CMSCBB_LOG_NAME, __LINE__, (const CVB_CHAR*)__FUNCTION__,
                           CMSCBB_ERR_SYS_MEM_ALLOC, (const CVB_CHAR*)"Allocate memory for log message failed.");
            CmscbbLogPrint(log_level, filename, line, function, rc, msg);
            return;
        }

        if (msg != CVB_NULL) {
            cvb_va_list vargs;
            CVB_INT nPrinted;

            cmscbb_va_start(vargs, msg);
            nPrinted = vsnprintf_s(log, MAX_LOG_STR_LEN, MAX_LOG_STR_LEN - 1, msg, vargs);
            cmscbb_va_end(vargs);
            (CVB_VOID)vargs;

            if (nPrinted <= 0) {
                CmscbbLogPrint(CMSCBB_LOG_TYPE_ERROR, (const CVB_CHAR*)CMSCBB_LOG_NAME, __LINE__, (const CVB_CHAR*)__FUNCTION__,
                               (CMSCBB_ERROR_CODE)ret, (const CVB_CHAR*)"format log message failed.");
                CmscbbLogPrint(log_level, filename, line, function, rc, msg);
                CmscbbFree(log);
                return;
            }
        }

        CmscbbLogPrint(log_level, filename, line, function, rc, log);
        CmscbbFree(log);
    }
}
#endif

CMSCBB_ERROR_CODE CmscbbMallocWith0(CVB_VOID** ppByte, CVB_SIZE_T size)
{
    CMSCBB_ERROR_CODE ret;
    if (ppByte == CVB_NULL) {
        return CMSCBB_ERR_CONTEXT_INVALID_PARAM;
    }

    ret = CmscbbMalloc(ppByte, size);
    if (ret != 0 || *ppByte == CVB_NULL) {
        return ret;
    }

    ret = (CMSCBB_ERROR_CODE)memset_s(*ppByte, size, 0, size);
    if (ret != 0) {
        CmscbbFree(*ppByte);
        return ret;
    }

    return ret;
}

CVB_TIME_T CmscbbMktime(const CmscbbDatetime* datetime)
{
    unsigned int year;
    unsigned int mon;
    unsigned int day;
    unsigned int hour;
    unsigned int minute;
    unsigned int sec;

    CVB_TIME_T vYear;
    CVB_TIME_T vMonth;
    CVB_TIME_T vDay;

    if (datetime == CVB_NULL) {
        return 0;
    }

    year = (CVB_UINT16)(datetime->uYear > START_TIME_YEAR ? datetime->uYear : datetime->uYear + START_TIME_YEAR);
    mon = datetime->uMonth;
    day = datetime->uDay;
    hour = datetime->uHour;
    minute = datetime->uMinute;
    sec = datetime->uSecond;

    mon -= MOV_FEB_TO_END;
    if (0 >= (int)mon) { /* 1..12 -> 11,12,1..10 */
        mon += MONTH_NUM_IN_ONE_YEAR; /* Puts Feb last since it has leap day */
        year -= ONE_YEAR;
    }

    vYear = (CVB_TIME_T)year / LEAP_YEAR + ((CVB_TIME_T)year / LEAP_YEAR_EX) - ((CVB_TIME_T)year / LEAP_YEAR_EX_EX);
    vMonth = (DAY_NUM_IN_ONE_LEAP_YEAR * (CVB_TIME_T)mon / MONTH_NUM_IN_ONE_YEAR);
    vDay = (CVB_TIME_T)day + (CVB_TIME_T)year * DAY_NUM_IN_ONE_YEAR - DAYS_BEFOR_1970;

    return (((vYear + vMonth + vDay) * HOUR_NUM_IN_ONE_DAY + (CVB_TIME_T)hour) * /* now have hours */
        SECOND_NUM_IN_ONE_MINUTE + (CVB_TIME_T)minute) * /* now have minutes */
        SECOND_NUM_IN_ONE_MINUTE + (CVB_TIME_T)sec; /* finally seconds */
}

