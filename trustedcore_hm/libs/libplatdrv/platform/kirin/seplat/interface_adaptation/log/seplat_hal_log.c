/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: Adapt for external log.
 * Create: 2021/02/20
 */

#include <seplat_hal_log.h>
#include <securec.h>
#include <seplat_common.h>
#include <stdint.h>

#define SEPLAT_TRACE_HEX_MAX_LEN  1024
#define BYTE_NUM_PER_HEX          2

void seplat_trace_hex(const uint8_t *buf, const uint32_t buflen)
{
#ifdef HAL_PRINT_DEBUG_ENABLE
    uint32_t i;
    char temp[SEPLAT_TRACE_HEX_MAX_LEN] = {0};
    int32_t count = 0;

    hal_print_trace("DL:TRACE len = %u\n", buflen);

    /* check buffer len in uplayer */
    for (i = 0; i < buflen; i++)
        count += snprintf_s(temp + count, SEPLAT_TRACE_HEX_MAX_LEN, BYTE_NUM_PER_HEX, "%02x", buf[i]);
    hal_print_trace("%s\n", temp);
#else
    UNUSED(buf);
    UNUSED(buflen);
#endif
}
