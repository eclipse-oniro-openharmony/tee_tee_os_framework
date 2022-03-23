/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2020. All rights reserved.
 */
#include "msg_plat.h"

static msg_chn_t g_msglite_test_hdl;
static int msg_lite_proc(const struct msg_addr *src_info, void *buf, u32 len)
{
    msg_always("get msg from chnid[%d]  len = %d succcess\n", (int)src_info->chnid, (int)len);
    return bsp_msg_lite_sendto(g_msglite_test_hdl, src_info, buf, len);
}

int msg_mntn_init(void)
{
    struct msgchn_attr lite_attr = { 0 };
    bsp_msgchn_attr_init(&lite_attr);
    lite_attr.chnid = MSG_CHN_LOOP0;
    lite_attr.coremask = MSG_CORE_MASK(MSG_CORE_TSP) | MSG_CORE_MASK(MSG_CORE_APP) | MSG_CORE_MASK(MSG_CORE_LPM);
    lite_attr.lite_notify = msg_lite_proc;
    if (bsp_msg_lite_open(&g_msglite_test_hdl, &lite_attr) == 0) {
        msg_always("bsp_msg_lite_open %d succcess\n", MSG_CHN_LOOP0);
    } else {
        msg_always("bsp_msg_lite_open %d fail\n", MSG_CHN_LOOP0);
    }

    return 0;
}
