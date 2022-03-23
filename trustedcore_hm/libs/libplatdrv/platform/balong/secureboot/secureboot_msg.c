/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2020. All rights reserved.
 */
/*
 * File Name       : adc_msg_msg.c
 * Description     : recv and send msg to mcore,run in ccore
 * History         :
 */
#include <drv_module.h>
#ifdef CONFIG_MLOADER_NO_SHARE_MEM
#include <msg_id.h>
#include <bsp_msg.h>
#include <securec.h>
#include "tee_log.h"
#include "bsp_param_cfg.h"

static msg_chn_t g_secboot_chn;
static struct hisi_secboot_msg_s g_modem_secboot_msg = {0};
volatile unsigned int g_modem_msg_rcv_flag = 0;
struct hisi_secboot_msg_s *hisi_secboot_get_msg_st(void)
{
    return &g_modem_secboot_msg;
}

int hisi_secboot_send_msg_to_cp(struct verify_result_info *verify_result)
{
    int ret;
    struct msg_addr dst;

    dst.core = MSG_CORE_TSP;
    dst.chnid = MSG_CHN_MLOADER;

    ret = bsp_msg_lite_sendto(g_secboot_chn, &dst, (void *)verify_result, sizeof(struct verify_result_info));
    if (ret != 0) {
        tloge("hisi_secboot_send_msg_to_cp send data err,ret=0x%x.\n", ret);
        return ret;
    }

    tloge("hisi_secboot_send_msg_to_cp imag_id = 0x%x.\n", verify_result->image_id);
    return ret;
}

int hisi_secboot_msg_handler(const struct msg_addr *src, void *buf, u32 len)
{
    struct verify_param_info *verify_info = NULL;

    if (buf == NULL || len != sizeof(struct verify_param_info)) {
        tloge("hisi_secboot_msg_handler arg err, msg_len:0x%x err\n", len);
        return -1;
    }
    verify_info = (struct verify_param_info *)buf;
    tloge("hisi_secboot_msg_handler msg receved.\n");
    memcpy_s((void *)&(g_modem_secboot_msg.verify_info), sizeof(struct verify_param_info), (void *)verify_info,
             sizeof(struct verify_param_info));
    g_modem_msg_rcv_flag = 1;
    return 0;
}

int hisi_secboot_msg_init(void)
{
    int ret;
    struct msgchn_attr lite_attr = {0};
    bsp_msgchn_attr_init(&lite_attr);
    lite_attr.chnid = MSG_CHN_MLOADER;
    lite_attr.coremask = MSG_CORE_MASK(MSG_CORE_TSP) | MSG_CORE_MASK(MSG_CORE_APP);
    lite_attr.lite_notify = hisi_secboot_msg_handler;

    ret = bsp_msg_lite_open(&g_secboot_chn, &lite_attr);
    if (ret != 0) {
        tloge("hisi_secboot_msg_init conf_mid_reg err,ret=%d\n", ret);
    }
    return ret;
}

#else
int hisi_secboot_msg_init(void)
{
    return 0;
}
#endif
DECLARE_TC_DRV(secboot_msg, 0, 0, 0, TC_DRV_MODULE_INIT, NULL, NULL, hisi_secboot_msg_init, NULL, NULL);
