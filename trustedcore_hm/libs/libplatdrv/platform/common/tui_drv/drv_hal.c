/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: tui driver hal interface to invoke the hardware platform
 * Author: DuJie dujie7@huawei.com
 * Create: 2020-03-04
 */
#include "drv_hal.h"

#include <drv_mem.h>
#ifndef TEE_SUPPORT_TUI_MTK_DRIVER
#include <gpio.h>
#include <hisi_tui_touchscreen.h>
#include <platform_touchscreen.h>
#endif
#include <libhwsecurec/securec.h>
#include <msg_ops.h>
#include <sre_hwi.h>

#include <tee_log.h>

#include "mem_cfg.h"
#include "tui_drv_types.h"
#ifdef TEE_SUPPORT_M_DRIVER
#include <secmem_core_api.h>
#endif
#ifdef TEE_SUPPORT_TUI_MTK_DRIVER
#include "tui_touchscreen.h"
#endif

#ifndef TEE_SUPPORT_TUI_MTK_DRIVER
static struct mxt_tui_data g_mxt_data;
static bool init_mxt_data(uint64_t tp_info_phy)
{
    uint64_t phy_addr = tp_info_phy;
    uint32_t phy_len  = sizeof(g_mxt_data);
    uint32_t vm_addr;
    int32_t ret;
    errno_t rc;

    ret = check_secureos_addr(phy_addr, sizeof(g_mxt_data));
    if (ret != 0) {
        tloge("check sos addr error 0x%x\n", ret);
        return false;
    }

    ret = sre_mmap(phy_addr, phy_len, &vm_addr, non_secure, cache);
    if (ret != 0) {
        tloge("map from ns page failed 0x%x\n", ret);
        return false;
    }

    rc = memcpy_s(&g_mxt_data, sizeof(g_mxt_data), (const void *)(uintptr_t)vm_addr, phy_len);
    (void)sre_unmap(vm_addr, phy_len);
    if (rc != EOK) {
        tloge("copy error 0x%0x\n", rc);
        return false;
    }

    if (!hisi_tui_set_mxt_data(&g_mxt_data)) {
        tloge("set hisi tui mxt data failed");
        return false;
    }

    return true;
}

static enum sec_mode g_tp_mode;
static int32_t g_chip_type;

static int32_t g_caller_pid;
static const int32_t g_irq_wanted[] = { TYPE_TOUCH, TYPE_RELEASE };
static bool g_irq_wanted_touch      = true;
#endif

static bool g_tp_slide              = false;
#define THP_MAX_FRAME_NUM 10

void set_tp_slide_mode(bool slide)
{
    g_tp_slide = slide;
}
#ifndef TEE_SUPPORT_TUI_MTK_DRIVER
static void tp_irq(const void *arg)
{
    (void)arg;

    struct ts_tui_finger event;
    struct ts_tui_fingers report;
    static struct event_node last_node;

    (void)memset_s(&event, sizeof(event), 0, sizeof(event));
    (void)memset_s(&report, sizeof(report), 0, sizeof(report));
    if (g_tp_mode != SECURE_ENABLE)
        return;

    if (hisi_tui_get_tpdata_read(&event, &report) != 0) {
        tloge("get tp data error\n");
        return;
    }
    struct event_node node = {
        .x      = event.x,
        .y      = event.y,
        .status = event.status,
    };
    if (memcmp(&last_node, &node, sizeof(node)) == 0)
        return;
    last_node = node;

    if (!g_tp_slide) {
        if (event.status != g_irq_wanted[g_irq_wanted_touch ? 0 : 1])
            return;
        g_irq_wanted_touch = !g_irq_wanted_touch;
    }
    tlogd("send tp event to 0x%x 0x%x:0x%x @ 0x%x", g_caller_pid, node.x, node.y, node.status);
    (void)ipc_msg_snd(TUI_DRV_MSG_TP_EVENT, g_caller_pid, &node, sizeof(node));
}

static bool g_tui_start = false;

void set_thp_start_flag(bool mode)
{
    g_tui_start = mode;
    /* need clear the count */
    if (mode) {
        hisi_tui_set_frame_count(0);
        gpio_irq_ctrl((uint32_t)TS_GPIO_IRQ, 1);
    }
}

#define THP_IRQ_QUEUE_MAX 5
static void tp_irq_thp(const void *arg)
{
    (void)arg;

    hisi_tui_thp_irq_ack();

    if (!g_tui_start)
        return;

    int32_t fr_cnt = hisi_tui_get_frame_count();
    if (g_tp_mode != SECURE_ENABLE || fr_cnt > THP_IRQ_QUEUE_MAX) {
        tloge("tp mode 0x%x, frame cnt %d", g_tp_mode, fr_cnt);
        return;
    }

    struct event_node node = { 0 };
    (void)ipc_msg_snd(TUI_DRV_MSG_TP_EVENT, g_caller_pid, &node, sizeof(node));

    /* incremented in hisi driver */
    hisi_tui_set_frame_count(hisi_tui_get_frame_count() + 1);
}

static bool set_tp_irq(const struct tp_cfg *cfg)
{
    g_chip_type = cfg->type;
    int32_t ret;

    tui_logt("tp init type 0x%x", g_chip_type);
    hisi_tui_set_frame_count(0);

#ifdef CONFIG_HISI_MAILBOX /* defined in kirin990.mk */
    if (g_chip_type == THP_SHB_DEVICE) {
        tui_logt("hisi shb tp init");
        ret = hisi_tui_shb_tp_init((void *)tp_irq, (uint32_t *)&cfg->caller_pid);
        if (ret != 0)
            return false;

        return true;
    }
#endif

    if (g_chip_type >= THP_JDI_DEVICE_VICTORIA && g_chip_type < MAX_THP_DEVICE_NUM)
        ret = hisi_tui_tp_init(g_chip_type, (void *)tp_irq_thp, NULL);
    else
        ret = hisi_tui_tp_init(g_chip_type, (void *)tp_irq, NULL);
    if (ret != 0) {
        tloge("hisi tp init error, ret is 0x%x\n", ret);
        return false;
    }

    return true;
}
#endif
#ifdef TEE_SUPPORT_TUI_MTK_DRIVER
int32_t tui_get_disp_info(struct panel_info *info)
#else
int32_t tui_get_disp_info(struct hisi_panel_info *info)
#endif
{
    if (info == NULL)
        return -1;
#ifdef TEE_SUPPORT_TUI_MTK_DRIVER
    return get_disp_info(info);
#else
    return hisi_get_disp_info(info);
#endif
}

bool set_fb_mem_mode(struct mem_cfg *fb_cfg, enum sec_mode mode)
{
    if (fb_cfg == NULL)
        return false;

    if (fb_cfg->mode == mode)
        return true;

    if (mode == SECURE_ENABLE) {
        set_secure_mem(fb_cfg, T_MPU_REQ_ORIGIN_TEE_ZONE_TUI_EXT1);
        tlogd("set fb mode to secure");
    } else {
        unset_secure_mem(fb_cfg, T_MPU_REQ_ORIGIN_TEE_ZONE_TUI_EXT1);
        tloge("set fb mode to no secure");
    }

    fb_cfg->mode = mode;

    return true;
}

bool set_fb_drv_mode(struct fb_cfg *cfg, enum sec_mode mode)
{
    int32_t ret;

    tlogd("set_fb_drv_mode entry");
    if (cfg == NULL) {
        tloge("set_fb_drv_mode fail cfg");
        return false;
    }

    if (mode == cfg->drv_mode) {
        tloge("set_fb_drv_mode fail mode 0x%x 0x%x", mode, cfg->drv_mode);
        return true;
    }
#ifdef TEE_SUPPORT_TUI_MTK_DRIVER
    ret = fb_cfg_sec(mode);
#else
    ret = hisi_fb_cfg_sec(mode);
#endif
    if (ret != 0) {
        tloge("set fb drv to mode 0x%x fail, res 0x%x\n", mode, ret);
        return false;
    }
    cfg->drv_mode = mode;

    return true;
}

bool set_tp_drv_mode(struct tp_cfg *cfg, enum sec_mode mode)
{
    if (cfg == NULL) {
        tloge("cfg is null");
        return false;
    }

    if (mode == cfg->drv_mode) {
        tloge("set_tp_drv_mode fail mode is 0x%x 0x%x", mode, cfg->drv_mode);
        return true;
    }

    if (mode == SECURE_ENABLE) {
#ifdef TEE_SUPPORT_TUI_MTK_DRIVER
        tloge("enter tui tp init\n");
        if (!tui_tp_driver_init((void*)cfg)) {
            tloge("init tp data fail");
            return false;
        }
#else
        if (!init_mxt_data(cfg->tp_info_phy))
            return false;

        cfg->type = hisi_tui_get_chip_type();
        if (cfg->type < 0) {
            tloge("other tp device, not support 0x%x\n", cfg->type);
            return false;
        }

        if (!set_tp_irq(cfg))
            return false;

        g_tp_mode    = mode;
        g_caller_pid = cfg->caller_pid;
#endif
    } else {
#ifdef TEE_SUPPORT_TUI_MTK_DRIVER
        tui_tp_exit();
        tui_logt("mtk tui tp exit");
#else
        tui_logt("hisi tui tp exit");
        g_tp_mode = mode;
        (void)hisi_tui_tp_exit();
        hisi_tui_set_frame_count(0);
        g_chip_type = 0;
#endif
    }

    cfg->drv_mode = mode;

    tloge("%s end", __func__);
    return true;
}

bool set_ttf_mode(struct ttf_cfg *ttf, enum sec_mode mode)
{
    if (ttf == NULL)
        return false;

    if (ttf->set == DATA_UNSET)
        return true;

    if (mode == SECURE_ENABLE) {
        if (!set_secure_mem(&ttf->cfg, T_MPU_REQ_ORIGIN_TEE_ZONE_TUI_EXT2))
            return false;
    } else {
        if (!unset_secure_mem(&ttf->cfg, T_MPU_REQ_ORIGIN_TEE_ZONE_TUI_EXT2))
            return false;
    }
    return true;
}
