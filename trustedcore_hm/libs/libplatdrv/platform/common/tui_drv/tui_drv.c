/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: syscall main message procedure for tui driver
 * Author: DuJie dujie7@huawei.com
 * Create: 2020-2-29
 */
#include "tui_drv.h"

#include <api/mm_common.h>
#include <drv_module.h>
#include <drv_pal.h>
#include <hm_getpid.h>
#include <libhwsecurec/securec.h>
#include <malloc.h>
#include <mem_drv_map.h>
#include <mem_ops_ext.h>
#include <platdrv.h>
#include <procmgr_ext.h>
#include <sre_access_control.h>
#include <sre_dev_relcb.h>
#include <sre_syscalls_id_ext.h>
#include <tee_log.h>
#ifdef SRE_AUDIT
#include <hmdrv_stub_timer.h>
#endif
#ifdef TEE_SUPPORT_TUI_MTK_DRIVER
#include <sre_audit_drv.h>
#include <tui_touchscreen.h>
#else
#include <hmdrv_stub.h>
#include <hisi_tui_touchscreen.h>
#include <platform_touchscreen.h>
#include <hisi_disp.h>
#endif
#include "drv_hal.h"
#include "mem_cfg.h"
#include "tui_drv_types.h"
#include "tui_timer.h"

#define COLOR_TYPE         4 /* ARGB */
#define BUFFER_NUM         2
#define FB_SIZE_ALIGN      (1U << 21)

static struct drv_state g_drv_state;

static void uninit_process(void);

struct buffer_map {
    uintptr_t ori_addr;
    uintptr_t vm_addr;
    uintptr_t lo_addr;
    uint32_t len;
    bool need_lo;
    int32_t prot;
    int32_t swi_id;
};

enum ttf_hash_type {
    TTF_NORMAL_TYPE      = 0,
    TTF_CONVERGENCE_TYPE = 1,
    TTF_MAX_TYPE,
};

static void audit_fail_syscall(void)
{
#ifdef SRE_AUDIT
    uint32_t pid = 0;
    (void)task_caller(&pid);
    kill_audit_task(pid, get_teesmc_hdlr());
#endif
}

#define TTF_HASH_SIZE  32

uint8_t g_nomal_ttf_sha[TTF_HASH_SIZE];
uint8_t g_reserve_ttf_sha[TTF_HASH_SIZE];

static void access_check_prepare(struct buffer_map *buf_map, int32_t swi_id)
{
    buf_map->swi_id = swi_id;
}

static void access_check_end(struct buffer_map *buf_map)
{
    pid_t drv_pid = hm_getpid();

    if (buf_map->lo_addr != 0 && buf_map->need_lo && ((uint32_t)buf_map->prot & PROT_WRITE) != 0) {
        if (memcpy_s((void *)buf_map->vm_addr, buf_map->len, (void *)buf_map->lo_addr, buf_map->len) != EOK)
            tloge("cmd %x: memcpy back size 0x%x failed", buf_map->swi_id, buf_map->len);
        free((void *)buf_map->lo_addr);
        buf_map->lo_addr = 0;
    }

    if (buf_map->vm_addr != 0)
        (void)task_unmap((uint32_t)drv_pid, (uintptr_t)buf_map->vm_addr, (uint32_t)buf_map->len);
}

static bool access_write_right_check(const struct buffer_map *buf_map, uint32_t size)
{
    if (((uint32_t)buf_map->prot & PROT_WRITE) != PROT_WRITE) {
        tloge("swi_id %x, do not have write permission\n", buf_map->swi_id);
        audit_fail_syscall();
        return false;
    }
    if (size != buf_map->len) {
        tloge("read and write length don't match, swi_id is 0x%x\n", buf_map->swi_id);
        return false;
    }

    return true;
}

static uintptr_t access_check(struct buffer_map *buf_map, uintptr_t addr, uint32_t size, struct drv_param *params,
                              bool need_local)
{
    int32_t ret;
    uint32_t caller_pid = 0;
    pid_t drv_pid       = hm_getpid();
    uint64_t *args      = (uint64_t *)(uintptr_t)params->args;

    if (addr == 0 || size == 0) {
        tlogd("input is zero");
        return 0;
    }

    (void)task_caller(&caller_pid);

    buf_map->need_lo  = need_local;
    buf_map->ori_addr = addr;
    buf_map->len      = size;

    ret = drv_map_from_task_under_tbac_handle(caller_pid, (uint64_t)addr, size, (uint32_t)drv_pid,
                                              (uint64_t *)&(buf_map->vm_addr), &buf_map->prot, params->job_handler);
    if (ret != 0) {
        tloge("cmd %x: ACCESS_READ_CHECK failed: 0x%x", buf_map->swi_id, ret);
        args[0] = OS_ERROR;
        audit_fail_syscall();
        return 0;
    }

    if (buf_map->need_lo) {
        buf_map->lo_addr = (uintptr_t)malloc(buf_map->len);
        if (buf_map->lo_addr == 0) {
            tloge("cmd %x: malloc size 0x%x failed", buf_map->swi_id, buf_map->len);
            args[0] = OS_ERROR;
            return 0;
        }
        if (memcpy_s((void *)buf_map->lo_addr, buf_map->len, (void *)(buf_map->vm_addr), size) != EOK) {
            tloge("cmd %x: memcpy size 0x%x failed", buf_map->swi_id, buf_map->len);
            args[0] = OS_ERROR;
            return 0;
        }
    } else {
        buf_map->lo_addr = buf_map->vm_addr;
    }

    return buf_map->lo_addr;
}

static void set_init_step(enum init_step step)
{
    g_drv_state.step = step;
}

static enum init_step get_init_step(void)
{
    return g_drv_state.step;
}

typedef int32_t (*helper_t)(struct drv_param *params, struct buffer_map *buf_map);

enum rel_cb_mode {
    REL_CB_UNREG,
    REG_CB_REG,
};

static int32_t tui_drv_relcb(void *data)
{
    (void)data;

    uninit_process();

    return 0;
}

void set_release_callback(enum rel_cb_mode mode)
{
    uint32_t ret;

    if (mode == REG_CB_REG) {
        ret = SRE_TaskRegister_DevRelCb(tui_drv_relcb, &g_drv_state);
        if (ret != 0)
            tloge("reg rel cb error:0x%x\n", ret);
    } else {
        SRE_TaskUnRegister_DevRelCb(tui_drv_relcb, &g_drv_state);
    }
}

static void uninit_process(void)
{
    tui_logt("drv un init process");
    switch (get_init_step()) {
    case INIT_OVER:
    case INIT_RELCB:
        set_release_callback(REL_CB_UNREG);
        /* fall through */
    case INIT_TIMER:
        tui_timer_release();
        /* fall through */
    case INIT_TTF_MEM:
        (void)set_ttf_mode(&g_drv_state.ttf, SECURE_DISABLE);
        /* fall through */
    case INIT_TP_DRV:
        (void)set_tp_drv_mode(&g_drv_state.tp_cfg, SECURE_DISABLE);
        /* fall through */
    case INIT_FB_DRV:
        (void)set_fb_drv_mode(&g_drv_state.fb_cfg, SECURE_DISABLE);
        /* fall through */
    case INIT_FB_MEM:
        (void)set_fb_mem_mode(&g_drv_state.fb_cfg.cfg, SECURE_DISABLE);
        /* fall through */
    case INIT_NONE:
        break;
    }

    set_init_step(INIT_NONE);
}

static bool init_process(void)
{
    tui_logt("drv init process");
    if (!set_fb_mem_mode(&g_drv_state.fb_cfg.cfg, SECURE_ENABLE))
        return false;
    set_init_step(INIT_FB_MEM);

    if (!set_fb_drv_mode(&g_drv_state.fb_cfg, SECURE_ENABLE))
        return false;
    set_init_step(INIT_FB_DRV);

    if (!set_tp_drv_mode(&g_drv_state.tp_cfg, SECURE_ENABLE))
        return false;
    set_init_step(INIT_TP_DRV);

    if (!set_ttf_mode(&g_drv_state.ttf, SECURE_ENABLE))
        return false;
    set_init_step(INIT_TTF_MEM);

    tui_timer_init();
    set_init_step(INIT_TIMER);

    set_release_callback(REG_CB_REG);
    set_init_step(INIT_RELCB);

    return true;
}

static void reset_drv_state(void)
{
    int32_t drv_pid     = hm_getpid();
    uint32_t caller_pid = 0;
    (void)task_caller(&caller_pid);

    g_drv_state.tp_cfg.drv_pid        = (uint32_t)drv_pid;
    g_drv_state.tp_cfg.caller_pid     = caller_pid;
    g_drv_state.fb_cfg.cfg.drv_pid    = drv_pid;
    g_drv_state.fb_cfg.cfg.caller_pid = caller_pid;
    g_drv_state.ttf.cfg.drv_pid       = drv_pid;
    g_drv_state.ttf.cfg.caller_pid    = caller_pid;
}

static bool check_fb_size(const struct tui_config *cfg)
{
    uint64_t fb_size  = (uint64_t)g_drv_state.panel.bpp * g_drv_state.panel.fps *
        COLOR_TYPE * BUFFER_NUM;

    uint32_t low_size = (uint32_t)fb_size;

    fb_size = ((low_size + FB_SIZE_ALIGN - 1) / FB_SIZE_ALIGN * FB_SIZE_ALIGN);

    if ((uint32_t)fb_size != cfg->phy_size) {
        tloge("check fb size fail 0x%x 0x%x\n", (uint32_t)fb_size, cfg->phy_size);
        return false;
    }

    return true;
}

static int32_t set_config(struct drv_param *params, struct buffer_map *buf_map)
{
    if (get_init_step() == INIT_OVER)
        return -1;

    if (params == NULL || buf_map == NULL)
        return -1;

    uint64_t *args = (uint64_t *)(uintptr_t)params->args;
    if (args == NULL) {
        tloge("input is invalid");
        return -1;
    }

    struct tui_config *cfg = (void *)access_check(buf_map, (uintptr_t)args[0],
        sizeof(*cfg), params, true);
    if (cfg == NULL) {
        tloge("input is invalid");
        return -1;
    }
    if (!access_write_right_check(buf_map, sizeof(*cfg))) {
        tloge("access write check img vir error");
        return -1;
    }

    if (!check_fb_size(cfg))
        return -1;

    reset_drv_state();
    init_mem_cfg(&g_drv_state.fb_cfg.cfg, cfg, true);
    g_drv_state.tp_cfg.tp_info_phy = cfg->tp_info_phy;

    if (!init_process()) {
        uninit_process();
        return -1;
    }

    set_init_step(INIT_OVER);

    cfg->vm_addr = g_drv_state.fb_cfg.cfg.vm_addr;
    cfg->vm_size = g_drv_state.fb_cfg.cfg.size;

    return 0;
}

static int32_t unset_config(struct drv_param *params, struct buffer_map *buf_map)
{
    (void)params;
    (void)buf_map;

    if (get_init_step() == INIT_NONE)
        return 0;

    uninit_process();

    return 0;
}

/* set the ttf physical memory from global task */
static int32_t init_ttf_mem_info(struct drv_param *params, struct buffer_map *buf_map)
{
    tlogd("init ttf for type");

    if (params == NULL || buf_map == NULL)
        return -1;

    uint64_t *args = (uint64_t *)(uintptr_t)params->args;
    if (args == NULL) {
        tloge("input is invalid");
        return -1;
    }
    uint32_t size = sizeof(struct tui_ion_sglist_k) + sizeof(struct tui_page_info_k);

    struct tui_ion_sglist_k *ttf_sglist = (void *)access_check(buf_map, (uintptr_t)args[0],
        size, params, true);
    if (ttf_sglist == NULL) {
        tloge("input is invalid");
        return -1;
    }

    struct ttf_cfg *ttf = &g_drv_state.ttf;

    if (ttf->cfg.mode == SECURE_ENABLE) {
        tlogd("ttf is secure , then new addres set by gtask");
        if (!set_ttf_mode(ttf, SECURE_DISABLE))
            tloge("unmap unusual font mem failed");
    }

    ttf->cfg.file_size   = LOW32(ttf_sglist->ion_id);
    ttf->cfg.phy_addr    = ttf_sglist->page_info[0].phys_addr;
    ttf->cfg.size        = LOW32(ttf_sglist->ion_size);
    ttf->cfg.npages      = ttf_sglist->page_info[0].npages;
    ttf->cfg.info_length = ttf_sglist->info_length;
    ttf->cfg.need_clear  = false;
    ttf->set             = DATA_SET;

    return 0;
}

/*
 * unset the ttf physical memory from global task
 * because the map operation should invoke by tui-service
 * so this operation only copy the physical address, not do map operation
 */
static int32_t uninit_ttf_mem_info(struct drv_param *params, struct buffer_map *buf_map)
{
    (void)params;
    (void)buf_map;
    struct ttf_cfg *ttf = NULL;

    tlogd("uninit ttf ");

    ttf = &g_drv_state.ttf;

    if (!set_ttf_mode(ttf, SECURE_DISABLE))
        tloge("unmap unusual font mem failed");

    ttf->set = DATA_UNSET;

    return 0;
}

/*
 * if the ttf memory is not mapped, do map first.
 */
static int32_t map_ttf_mem(struct drv_param *params, struct buffer_map *buf_map)
{
    if (params == NULL || buf_map == NULL)
        return -1;

    uint64_t *args = (uint64_t *)(uintptr_t)params->args;
    if (args == NULL) {
        tloge("input is invalid");
        return -1;
    }

    struct map_node *ttf = (void *)access_check(buf_map, (uintptr_t)args[0],
        sizeof(*ttf), params, true);
    if (ttf == NULL) {
        tloge("input is invalid");
        return -1;
    }
    if (!access_write_right_check(buf_map, sizeof(*ttf))) {
        tloge("access write check img vir error");
        return -1;
    }

    /* if the mem is not mapped, should map it first */
    if (!set_ttf_mode(&g_drv_state.ttf, SECURE_ENABLE)) {
        tloge("init usual font mem failed");
        return -1;
    }

    ttf->vm_addr = 0;
    if (g_drv_state.ttf.cfg.mode == SECURE_ENABLE) {
        ttf->vm_addr   = g_drv_state.ttf.cfg.vm_addr;
        ttf->file_size = (int32_t)g_drv_state.ttf.cfg.file_size;
    }

    tlogi("map font mem success");
    return 0;
}

static int32_t unmap_ttf_mem(struct drv_param *params, struct buffer_map *buf_map)
{
    (void)params;
    (void)buf_map;
    tlogd("unmap ttf mem");

    /* if the mem is not mapped, should map it first */
    if (!set_ttf_mode(&g_drv_state.ttf, SECURE_DISABLE))
        tloge("unmap usual font mem failed");

    return 0;
}

static int32_t get_hisi_panel_info(struct drv_param *params, struct buffer_map *buf_map)
{
    if (params == NULL || buf_map == NULL)
        return -1;

    uint64_t *args = (uint64_t *)(uintptr_t)params->args;
    if (args == NULL) {
        tloge("input is invalid");
        return -1;
    }
#ifdef TEE_SUPPORT_TUI_MTK_DRIVER
    struct panel_info *panel = (void *)access_check(buf_map, (uintptr_t)args[0],
        sizeof(*panel), params, true);
#else
    struct hisi_panel_info *panel = (void *)access_check(buf_map, (uintptr_t)args[0],
        sizeof(*panel), params, true);
#endif
    if (panel == NULL) {
        tloge("input is invalid");
        return -1;
    }
    if (!access_write_right_check(buf_map, sizeof(*panel))) {
        tloge("access write check img vir error");
        return -1;
    }

    panel->xres = g_drv_state.panel.bpp;
    panel->yres = g_drv_state.panel.fps;

    int32_t ret = tui_get_disp_info(panel);

    if (g_drv_state.panel.bpp != 0 && g_drv_state.panel.fps != 0) {
        /*
         * bpp fps is from tzdriver, and the ion buffer is malloc on them.
         * the screen size get from tzdriver and tee sometimes is not the same.
         */
        panel->xres = g_drv_state.panel.bpp;
        panel->yres = g_drv_state.panel.fps;
    }

    return ret;
}

static void switch_x_y_res(uint32_t *x, uint32_t *y, uint32_t *w, uint32_t *h)
{
    uint32_t temp;

    if (x == NULL || y == NULL || w == NULL || h == NULL)
        return;

    if (*x > *y) {
        temp = *x;
        *x = *y;
        *y = temp;
    }
    if (*w > *h) {
        temp = *w;
        *w = *h;
        *h = temp;
    }
}

static int32_t set_fold_screen(struct drv_param *params, struct buffer_map *buf_map)
{
    if (params == NULL || buf_map == NULL)
        return -1;

    uint64_t *args = (uint64_t *)(uintptr_t)params->args;
    if (args == NULL) {
        tloge("input is invalid");
        return -1;
    }

    if (get_init_step() == INIT_OVER)
        return -1;

    struct tui_panel_info_k *panel = (void *)access_check(buf_map, (uintptr_t)args[0],
        sizeof(*panel), params, true);
    if (panel == NULL) {
        tloge("input is invalid");
        return -1;
    }

    if (panel->fold_state == 0)
        switch_x_y_res(&panel->xres, &panel->yres, &panel->width, &panel->height);

    if (panel->bpp == 0 || panel->fps == 0) {
        panel->bpp = panel->xres;
        panel->fps = panel->yres;
    }
    g_drv_state.panel = *panel;
    tui_logt("fold: type %u, xres %u, yres %u, width %u, height %u, notch %u, bpp %u, fps %u, ori %u, fold %u, dis %u",
             panel->type, panel->xres, panel->yres, panel->width, panel->height, panel->notch, panel->bpp, panel->fps,
             panel->orientation, panel->fold_state, panel->display_state);
    return 0;
}

/* for touchscreen/panel/tui_st_new.c */
int32_t get_fold_screen(struct tui_panel_info_k *panel)
{
    if (panel == NULL)
        return -1;
    if (memcpy_s(panel, sizeof(*panel), &g_drv_state.panel, sizeof(g_drv_state.panel)) != EOK)
        return -1;

    return 0;
}

static int32_t get_cur_panel(struct drv_param *params, struct buffer_map *buf_map)
{
    if (params == NULL || buf_map == NULL)
        return -1;

    uint64_t *args = (uint64_t *)(uintptr_t)params->args;
    if (args == NULL) {
        tloge("input is invalid");
        return -1;
    }

    struct tui_panel_info_k *panel = (void *)access_check(buf_map, (uintptr_t)args[0],
        sizeof(*panel), params, true);
    if (panel == NULL) {
        tloge("input is invalid");
        return -1;
    }
    if (!access_write_right_check(buf_map, sizeof(*panel))) {
        tloge("access write check img vir error");
        return -1;
    }

    *panel = g_drv_state.panel;
    return 0;
}

static int32_t tui_display_check(struct drv_param *params, struct buffer_map *buf_map)
{
    if (get_init_step() != INIT_OVER) {
        tloge("current fb is not init");
        return -1;
    }

    if (params == NULL || buf_map == NULL) {
        tloge("invalid input\n");
        return -1;
    }

    return 0;
}

static int32_t tui_pan_display_sec(struct drv_param *params, struct buffer_map *buf_map)
{
    if (tui_display_check(params, buf_map) != 0)
        return -1;

    uint64_t *args = (uint64_t *)(uintptr_t)params->args;
    if (args == NULL) {
        tloge("input is invalid");
        return -1;
    }

    struct dss_layer *layer = (void *)access_check(buf_map, (uintptr_t)args[0],
        sizeof(*layer), params, true);
    if (layer == NULL) {
        tloge("input is invalid");
        return -1;
    }
    if (!access_write_right_check(buf_map, sizeof(*layer))) {
        tloge("access write check img vir error");
        return -1;
    }

    struct buffer_map buf_map_fb = { 0 };
    access_check_prepare(&buf_map_fb, buf_map->swi_id);
    layer->img.vir_addr = access_check(&buf_map_fb, (uintptr_t)layer->img.vir_addr,
        layer->img.buf_size, params, false);
    if (layer->img.vir_addr == 0) {
        tloge("access check img vir error");
        return -1;
    }

    if (!access_write_right_check(&buf_map_fb, layer->img.buf_size)) {
        tloge("access write check img vir error");
        access_check_end(&buf_map_fb);
        return -1;
    }

#ifdef TEE_SUPPORT_TUI_MTK_DRIVER
    int32_t ret = wait_vactive_flag();
#else
    int32_t ret = hisi_wait_vactive_flag();
#endif
    if (ret != 0) {
        tloge("wait vactive flag failed 0x%x", ret);
        access_check_end(&buf_map_fb);
        return -1;
    }
#ifdef TEE_SUPPORT_TUI_MTK_DRIVER
    ret = pan_display_sec(layer);
#else
    ret = hisi_pan_display_sec(layer);
#endif

    layer->img.phy_addr = 0;

    access_check_end(&buf_map_fb);

    return ret;
}

static int32_t thp_ioctl(struct drv_param *params, struct buffer_map *buf_map)
{
    if (params == NULL || buf_map == NULL)
        return -1;

    uint64_t *args = (uint64_t *)(uintptr_t)params->args;
    if (args == NULL) {
        tloge("input is invalid");
        return -1;
    }

    uint32_t cmd = (uint32_t)args[0];
    void *arg    = (void *)access_check(buf_map, (uintptr_t)args[1], sizeof(struct ts_info), params, true);
    if (arg == NULL && args[1] != 0) {
        tloge("input is invalid");
        return -1;
    }

    return ts_ioctl(cmd, arg); /* Not support 64bit TA now */
}

static int32_t wait_release_flag_tui(struct drv_param *params, struct buffer_map *buf_map)
{
    (void)params;
    (void)buf_map;
    if (get_init_step() != INIT_OVER) {
        tloge("current fb is not init");
        return 0;
    }

#ifdef TEE_SUPPORT_TUI_MTK_DRIVER
    return wait_release_flag();
#else
    return hisi_wait_release_flag();
#endif
}

static int32_t tui_timer_create(struct drv_param *params, struct buffer_map *buf_map)
{
    if (params == NULL || buf_map == NULL)
        return -1;

    uint64_t *args = (uint64_t *)(uintptr_t)params->args;
    if (args == NULL) {
        tloge("input is invalid");
        return -1;
    }
    if (args[1] <= TUI_DRV_MSG_BASE || args[1] >= TUI_DRV_MSG_MAX) {
        tloge("input is invalid");
        return -1;
    }

    timeval_t *interval = (void *)access_check(buf_map, (uintptr_t)args[0], sizeof(*interval), params, true);
    if (interval == NULL) {
        tloge("input is invalid");
        return -1;
    }

    uint32_t caller_pid = 0;
    (void)task_caller(&caller_pid);
    return (int32_t)timer_node_create(*interval, (enum tui_drv_msg)args[1], caller_pid);
}

static int32_t tui_timer_delete(struct drv_param *params, struct buffer_map *buf_map)
{
    if (params == NULL || buf_map == NULL)
        return -1;

    (void)buf_map;
    uint64_t *args = (uint64_t *)(uintptr_t)params->args;
    if (args == NULL) {
        tloge("input is invalid");
        return -1;
    }

    if (args[0] <= TUI_DRV_MSG_BASE || args[0] >= TUI_DRV_MSG_MAX) {
        tloge("msg id error 0x%x", args[0]);
        return -1;
    }

    timer_node_destroy((enum tui_drv_msg)args[0]);
    return 0;
}

static int32_t tui_timer_start(struct drv_param *params, struct buffer_map *buf_map)
{
    if (params == NULL || buf_map == NULL)
        return -1;

    (void)buf_map;
    uint64_t *args = (uint64_t *)(uintptr_t)params->args;
    if (args == NULL) {
        tloge("input is invalid");
        return -1;
    }

    if (args[0] <= TUI_DRV_MSG_BASE || args[0] >= TUI_DRV_MSG_MAX) {
        tloge("msg id error 0x%x", args[0]);
        return -1;
    }

    timer_node_start((enum tui_drv_msg)args[0]);
    return 0;
}

static int32_t tui_timer_stop(struct drv_param *params, struct buffer_map *buf_map)
{
    if (params == NULL || buf_map == NULL)
        return -1;

    (void)buf_map;
    uint64_t *args = (uint64_t *)(uintptr_t)params->args;

    if (args[0] <= TUI_DRV_MSG_BASE || args[0] >= TUI_DRV_MSG_MAX) {
        tloge("msg id error 0x%x", args[0]);
        return -1;
    }

    timer_node_stop((enum tui_drv_msg)args[0]);
    return 0;
}

static int32_t tui_timer_enable(struct drv_param *params, struct buffer_map *buf_map)
{
    if (params == NULL || buf_map == NULL)
        return -1;

    (void)buf_map;
    uint64_t *args = (uint64_t *)(uintptr_t)params->args;
    if (args == NULL) {
        tloge("input is invalid");
        return -1;
    }

    set_timer_enabled(args[0] != 0);
    return 0;
}

static int32_t tui_tp_slide_mode(struct drv_param *params, struct buffer_map *buf_map)
{
    if (params == NULL || buf_map == NULL)
        return -1;

    (void)buf_map;
    uint64_t *args = (uint64_t *)(uintptr_t)params->args;
    if (args == NULL) {
        tloge("input is invalid");
        return -1;
    }

    set_tp_slide_mode(args[0] != 0);
    return 0;
}

static int32_t set_kb_rect(struct drv_param *params, struct buffer_map *buf_map)
{
    if (params == NULL || buf_map == NULL)
        return -1;

    (void)buf_map;
    bool mode = false;
    uint64_t *args = (uint64_t *)(uintptr_t)params->args;

    mode = args[0];
#ifdef TEE_SUPPORT_TUI_MTK_DRIVER
    display_state_notify(mode);
#else
    set_thp_start_flag(mode);
#endif
    return 0;
}
static int32_t push_hash_info(struct drv_param *params, struct buffer_map *buf_map)
{
    if (params == NULL || buf_map == NULL)
        return -1;

    uint64_t *args = (uint64_t *)(uintptr_t)params->args;
    if (args == NULL) {
        tloge("input is invalid");
        return -1;
    }

    if (args[1] != TTF_HASH_SIZE) {
        tloge("bad size %d", args[1]);
        return -1;
    }

    if (args[BUFFER_NUM] == TTF_NORMAL_TYPE) {
        char *nomal_ttf = (void *)access_check(buf_map, (uintptr_t)args[0], sizeof(g_nomal_ttf_sha), params, true);
        if (nomal_ttf == NULL) {
            tloge("input is invalid");
            return -1;
        }
        if (memcpy_s(g_nomal_ttf_sha, sizeof(g_nomal_ttf_sha), nomal_ttf, (size_t)args[1]) != EOK) {
            tloge("tui font hash failed");
            return -1;
        }
    } else if (args[BUFFER_NUM] == TTF_CONVERGENCE_TYPE) {
        char *revert_ttf = (void *)access_check(buf_map, (uintptr_t)args[0], sizeof(g_reserve_ttf_sha), params, true);
        if (revert_ttf == NULL) {
            tloge("input is invalid");
            return -1;
        }
        if (memcpy_s(g_reserve_ttf_sha, sizeof(g_reserve_ttf_sha), revert_ttf, (size_t)args[1]) != EOK) {
            tloge("tui font hash failed");
            return -1;
        }
    } else {
        tloge("bad ttf hash type");
    }

    return 0;
}

static int32_t get_hash_info(struct drv_param *params, struct buffer_map *buf_map)
{
    if (params == NULL || buf_map == NULL)
        return -1;

    uint64_t *args = (uint64_t *)(uintptr_t)params->args;

    if (args == NULL) {
        tloge("input is invalid");
        return -1;
    }

    if (args[1] != TTF_HASH_SIZE) {
        tloge("bad size %d", args[1]);
        return -1;
    }

    if (args[BUFFER_NUM] == TTF_NORMAL_TYPE) {
        char *nomal_ttf = (void *)access_check(buf_map, (uintptr_t)args[0],
                                               sizeof(g_nomal_ttf_sha), params, true);
        if (nomal_ttf == NULL) {
            tloge("input is invalid");
            return -1;
        }

        if (!access_write_right_check(buf_map, sizeof(g_nomal_ttf_sha))) {
            tloge("access write check img vir error");
            return -1;
        }

        if (memcpy_s(nomal_ttf, sizeof(g_nomal_ttf_sha), g_nomal_ttf_sha, sizeof(g_nomal_ttf_sha)) != EOK) {
            tloge("tui font hash failed");
            return -1;
        }
    } else if (args[BUFFER_NUM] == TTF_CONVERGENCE_TYPE) {
        char *revert_ttf = (void *)access_check(buf_map, (uintptr_t)args[0],
                                                sizeof(g_reserve_ttf_sha), params, true);
        if (revert_ttf == NULL) {
            tloge("input is invalid");
            return -1;
        }

        if (!access_write_right_check(buf_map, sizeof(g_nomal_ttf_sha))) {
            tloge("access write check img vir error");
            return -1;
        }

        if (memcpy_s(revert_ttf, sizeof(g_reserve_ttf_sha),
                     g_reserve_ttf_sha, (size_t)args[1]) != EOK) {
            tloge("tui font hash failed");
            return -1;
        }
    } else {
        tloge("bad ttf hash type");
    }

    return 0;
}

static bool check_permission(int32_t sw_id, uint64_t permissions, uint64_t expect)
{
    if ((expect & permissions) != expect) {
        tloge("permission denied to access swi_id 0x%x\n", sw_id);
        audit_fail_syscall();
        return false;
    }
    return true;
}

static int32_t syscall_common(int32_t swi_id, struct drv_param *params, uint64_t permissions, uint64_t expect_perm,
                              const helper_t func)
{
    struct buffer_map buf_map = { 0 };
    uint64_t *args = NULL;

    if (params == NULL || func == NULL) {
        tloge("invalid input param\n");
        return -1;
    }
    args = (uint64_t *)(uintptr_t)params->args;
    if (!check_permission(swi_id, permissions, expect_perm))
        return -1;

    access_check_prepare(&buf_map, swi_id);

    args[0] = (uint32_t)func(params, &buf_map);
    if (args[0])
        params->rdata_len = 0;

    access_check_end(&buf_map);

    return 0;
}

struct syscall_node {
    enum tui_sw_syscall_id swi_id;
    uint64_t expect_perm;
    helper_t func;
};

#define TBIDX(si) ((si) - SW_SYSCALL_TUI_BASE)
static const struct syscall_node g_syscall_tbl[] = {
    [TBIDX(SW_SYSCALL_TUI_CONFIG)]        = { SW_SYSCALL_TUI_CONFIG, TUI_GROUP_PERMISSION, set_config },
    [TBIDX(SW_SYSCALL_TUI_DECONFIG)]      = { SW_SYSCALL_TUI_DECONFIG, TUI_GROUP_PERMISSION, unset_config },
    [TBIDX(SW_SYSCALL_TUI_FB_GETINFO)]    = { SW_SYSCALL_TUI_FB_GETINFO, TUI_GROUP_PERMISSION, get_hisi_panel_info },
    [TBIDX(SW_SYSCALL_SET_FOLD_SCREEN)]   = { SW_SYSCALL_SET_FOLD_SCREEN, TUI_GROUP_PERMISSION, set_fold_screen },
    [TBIDX(SW_SYSCALL_GET_CUR_PANEL)]     = { SW_SYSCALL_GET_CUR_PANEL, TUI_GROUP_PERMISSION, get_cur_panel },
    [TBIDX(SW_SYSCALL_INIT_TTF_MEM)]      = { SW_SYSCALL_INIT_TTF_MEM, TUI_GROUP_PERMISSION, init_ttf_mem_info },
    [TBIDX(SW_SYSCALL_UNINIT_TTF_MEM)]    = { SW_SYSCALL_UNINIT_TTF_MEM, TUI_GROUP_PERMISSION, uninit_ttf_mem_info },
    [TBIDX(SW_SYSCALL_MAP_TTF_MEM)]       = { SW_SYSCALL_MAP_TTF_MEM, TUI_GROUP_PERMISSION, map_ttf_mem },
    [TBIDX(SW_SYSCALL_UNMAP_TTF_MEM)]     = { SW_SYSCALL_UNMAP_TTF_MEM, TUI_GROUP_PERMISSION, unmap_ttf_mem },
    [TBIDX(SW_SYSCALL_TUI_FB_DISPLAY)]    = { SW_SYSCALL_TUI_FB_DISPLAY, TUI_GROUP_PERMISSION, tui_pan_display_sec },
    [TBIDX(SW_SYSCALL_TS_IOCTL)]          = { SW_SYSCALL_TS_IOCTL, TUI_GROUP_PERMISSION, thp_ioctl },
    [TBIDX(SW_SYSCALL_TUI_FB_RELEASE)]    = { SW_SYSCALL_TUI_FB_RELEASE, TUI_GROUP_PERMISSION, wait_release_flag_tui },
    [TBIDX(SW_SYSCALL_TUI_TIMER_CREATE)]  = { SW_SYSCALL_TUI_TIMER_CREATE, TUI_GROUP_PERMISSION, tui_timer_create },
    [TBIDX(SW_SYSCALL_TUI_TIMER_STOP)]    = { SW_SYSCALL_TUI_TIMER_STOP, TUI_GROUP_PERMISSION, tui_timer_stop },
    [TBIDX(SW_SYSCALL_TUI_TIMER_DELETE)]  = { SW_SYSCALL_TUI_TIMER_DELETE, TUI_GROUP_PERMISSION, tui_timer_delete },
    [TBIDX(SW_SYSCALL_TUI_TIMER_ENABLE)]  = { SW_SYSCALL_TUI_TIMER_ENABLE, TUI_GROUP_PERMISSION, tui_timer_enable },
    [TBIDX(SW_SYSCALL_TUI_TIMER_START)]   = { SW_SYSCALL_TUI_TIMER_START, TUI_GROUP_PERMISSION, tui_timer_start },
    [TBIDX(SW_SYSCALL_TUI_TP_SLIDE_MODE)] = { SW_SYSCALL_TUI_TP_SLIDE_MODE, TUI_GROUP_PERMISSION, tui_tp_slide_mode },
    [TBIDX(SW_SYSCALL_TP_SET_KB_RECT)]    = { SW_SYSCALL_TP_SET_KB_RECT, TUI_GROUP_PERMISSION, set_kb_rect },
    [TBIDX(SW_SYSCALL_PUSH_HASH_INFO)]    = { SW_SYSCALL_PUSH_HASH_INFO, TUI_GROUP_PERMISSION, push_hash_info },
    [TBIDX(SW_SYSCALL_GET_HASH_INFO)]     = { SW_SYSCALL_GET_HASH_INFO, TUI_GROUP_PERMISSION, get_hash_info },
    /* TUI_MAX is the last one , insert new before this line */
    [TBIDX(SW_SYSCALL_TUI_MAX)] = { SW_SYSCALL_TUI_MAX, 0, NULL },
};

/* compatible for invoke hm_drv_call_ex syscall interface */
int32_t tui_hal_syscall(int32_t swi_id, struct drv_param *params, uint64_t permissions)
{
    int32_t ret;
    if (params == NULL) {
        tloge("invalid input param\n");
        return -1;
    }

    int32_t idx = TBIDX(swi_id);
    if (swi_id >= SW_SYSCALL_TUI_MAX || swi_id <= SW_SYSCALL_TUI_BASE || g_syscall_tbl[idx].func == NULL)
        return -1;
    tlogd("tui hal syscall id 0x%x begin", swi_id);

    ret = syscall_common(swi_id, params, permissions, g_syscall_tbl[idx].expect_perm, g_syscall_tbl[idx].func);

    tlogd("tui hal syscall id 0x%x, ret 0x%x", swi_id, ret);

    return ret;
}

DECLARE_TC_DRV(tui_hal, 0, 0, 0, TC_DRV_MODULE_INIT, NULL, NULL, tui_hal_syscall, NULL, NULL);
