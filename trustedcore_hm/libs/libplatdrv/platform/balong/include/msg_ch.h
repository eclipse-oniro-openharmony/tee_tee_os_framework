/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: msg
 * Author:
 * Created: 2020-10-10
 * Last Modified:
 * History:
 * Modification: Create file
 */

#ifndef __MSG_CH_H__
#define __MSG_CH_H__
#ifndef __MSG_ID_H__
#error "please include msg_id.h instead"
#endif
#ifdef __cplusplus
extern "C"
{
#endif

enum msg_chnid {
    MSG_CHN_LOOP0,
    MSG_CHN_LOOP1,
    MSG_CHN_MDM_RST,
    MSG_CHN_MLOADER,
    MSG_CHN_EFUSE,
    MSG_CHN_ADC_CONF,
    MSG_CHN_ADC_DATA,
    MSG_CHN_WARMUP,
    MSG_CHN_THERMAL,
    MSG_CHN_TSENSOR,
    MSG_CHN_DDR_TMON,
    MSG_CHN_HIDSLOG,
    MSG_CHN_PM_PRESS,
    MSG_CHN_VCOM,
    MSG_CHN_CNT_MAX
};

#ifdef __cplusplus
}
#endif
#endif
