/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: TUI secure display interfaces with secure_os
 * Author: Hisilicon DSS
 * Create: 2019-06-19
 */
#include <mem_ops.h> // virt_mem_to_phys
#include <drv_module.h>
#include "hisi_disp.h"
#include "sre_task.h"
#include "sre_syscalls_id_ext.h"
#include "sre_syscalls_id.h"
#include "mem_page_ops.h"
#include "tee_mutex.h"
#include "sre_access_control.h"
#include "hisi_fb_sec.h"
/* redefine several macros */
#include "drv_pal.h"
#include <hmdrv_stub.h>
#include "sre_dev_relcb.h"


/* for debug */
#define HISI_FB_DISPLAY_DEBUG (0)
unsigned int g_hisi_fb_msg_level = 3;

/* global data */
struct hisifb_data_type g_hisifb_data;


int display_release(void *data);

/* dss secure mode init
 * input: sec_value,
 *        if true, enter into secure pay mode
 *        if false, exit secure pay mode
 * return: 0, success
 *        -1, failed
 */
int hisi_fb_cfg_sec(int sec_value)
{
	int ret = 0;
	struct hisifb_data_type *hisifd = &g_hisifb_data;

	if (tee_mutex_lock_wait(hisifd->disp_lock)) {
		HISI_FB_INFO("wait lock failed!\n");
		return -1;
	}

	if ((hisifd->panel_power_on != NULL) && hisifd->panel_power_on(hisifd)) {
		tee_mutex_unlock(hisifd->disp_lock);
		return -1;
	}

	if (hisifd->fb_cfg_sec != NULL) {
		ret = hisifd->fb_cfg_sec(hisifd, sec_value);
	}

	tee_mutex_unlock(hisifd->disp_lock);
	if (ret != 0)
		return ret;

	if (sec_value)
		ret = (int)task_register_devrelcb((DEV_RELEASE_CALLBACK)display_release, NULL);
	else
		(void)task_unregister_devrelcb((DEV_RELEASE_CALLBACK)display_release, NULL);

	if (ret)
		HISI_FB_ERR("sec_value=%d, register tui dss release callback failed:%d\n", sec_value, ret);
	else
		HISI_FB_INFO("sec_value=%d, register/unregister tui dss release callback success\n", sec_value);

	return ret;
}

/* dss secure alpha enable set
 * input: sec_value,
 *        if true, enable
 *        if false, disable
 * return: 0, success
 *       -1, failed
 */
int hisi_fb_alpha_set(int value)
{
	int ret = 0;
	struct hisifb_data_type *hisifd = &g_hisifb_data;

	if (hisifd->alpha_enable) {
		HISI_FB_INFO("hisifd->alpha_enable = %d\n", hisifd->alpha_enable);
		return ret;
	}
	if (tee_mutex_lock_wait(hisifd->disp_lock)) {
		HISI_FB_INFO("wait lock failed!\n");
		return -1;
	}
	if ((hisifd->panel_power_on != NULL) && hisifd->panel_power_on(hisifd)) {
		tee_mutex_unlock(hisifd->disp_lock);
		return -1;
	}

	hisifd->alpha_enable = value;
	if (hisifd->alpha_enable && (hisifd->pan_display_sec != NULL)) {
		ret = hisifd->pan_display_sec(hisifd, &(hisifd->layer_prev));
		if (ret != 0) {
			HISI_FB_ERR("hisi pan display sec failed.\n");
			tee_mutex_unlock(hisifd->disp_lock);
			return -1;
		}
	}
	tee_mutex_unlock(hisifd->disp_lock);
	return ret;
}

static int hisi_wait_vactive_start_flag(void)
{
	int ret = 0;
	struct hisifb_data_type *hisifd = &g_hisifb_data;

	if ((hisifd->panel_power_on != NULL) && hisifd->panel_power_on(hisifd))
		return -1;

	if (hisifd->wait_vactive_flag != NULL)
		ret = hisifd->wait_vactive_flag(hisifd);

	return ret;
}

/*
 * receive one frame data information
 *
 * input: rect, display region and data format(bpp)
 *       display_addr, display buffer base address
 *
 * return: 0, success
 *       -1, failed
 */
int hisi_pan_display_sec(dss_layer_t *layer)
{
	int ret;
	errno_t err;
	struct hisifb_data_type *hisifd = &g_hisifb_data;
	dss_layer_t *player = NULL;

	HISI_ERR_CHECK_RETURN((layer == NULL), -1, "layer is NULL\n");

	HISI_FB_DEBUG("enter!\n");
	if (tee_mutex_lock_wait(hisifd->disp_lock)) {
		HISI_FB_INFO("wait lock failed!\n");
		return -1;
	}
	if ((hisifd->panel_power_on != NULL) && hisifd->panel_power_on(hisifd)) {
		tee_mutex_unlock(hisifd->disp_lock);
		return -1;
	}

	layer->img.phy_addr = (uint32_t)virt_mem_to_phys(layer->img.vir_addr);
	hisifd->xres = layer->src_rect.w;
	hisifd->yres = layer->src_rect.h;

	HISI_FB_INFO("layer[%u]: img.bpp = %u\n", hisifd->frame_count, layer->img.bpp);
	HISI_FB_PRINTF("\timg.width = %u, img.height = %u\n", layer->img.width, layer->img.height);
	HISI_FB_PRINTF("\tsrc_rect: [%u, %u, %u, %u], dst_rect: [%u, %u, %u, %u]\n",
		layer->src_rect.x, layer->src_rect.y,
		layer->src_rect.w, layer->src_rect.h,
		layer->dst_rect.x, layer->dst_rect.y,
		layer->dst_rect.w, layer->dst_rect.h);

	ret = hisi_wait_vactive_start_flag();
	if (ret) {
		HISI_FB_ERR("hisi wait vactive flag failed\n");
		tee_mutex_unlock(hisifd->disp_lock);
		return -1;
	}

	if (hisifd->pan_display_sec != NULL) {
		player = &(hisifd->layer);
		err = memcpy_s(player, sizeof(dss_layer_t), layer, sizeof(dss_layer_t));
		if (err != EOK)
			HISI_FB_ERR("memcpy_s error: ret=[%d]\n", err);

		ret = hisifd->pan_display_sec(hisifd, player);
		if (ret) {
			HISI_FB_ERR("hisi pan display sec failed.\n");
			tee_mutex_unlock(hisifd->disp_lock);
			return -1;
		}
		// save last frame data
		hisifd->frame_count++;
		err = memcpy_s(&(hisifd->layer_prev), sizeof(dss_layer_t), player, sizeof(dss_layer_t));
		if (err != EOK)
			HISI_FB_ERR("memcpy_s error: ret=[%d]\n", err);
	}

	tee_mutex_unlock(hisifd->disp_lock);
	HISI_FB_DEBUG("exit!\n");
	return ret;
}

int hisi_wait_vactive_flag(void)
{
	/* this function will be deleted with secure os later */
	return 0;
}

int hisi_wait_release_flag(void)
{
	int ret = 0;
	struct hisifb_data_type *hisifd = &g_hisifb_data;

	if (hisifd->panel_power_on && hisifd->panel_power_on(hisifd))
		return -1;

	if (hisifd->wait_release_flag != NULL)
		ret = hisifd->wait_release_flag(hisifd);

	return ret;
}

int hisi_get_disp_info(struct hisi_panel_info *pinfo)
{
	int ret = 0;
	struct hisifb_data_type *hisifd = &g_hisifb_data;

	HISI_ERR_CHECK_RETURN((pinfo == NULL), -1, "pinfo is NULL!\n");

	if (hisifd->get_disp_info != NULL) {
		ret = hisifd->get_disp_info(hisifd, pinfo);
		if (ret)
			HISI_FB_ERR("failed to get disp info!!!\n");
	}

	return ret;
}

int display_release(void *data)
{
	(void)data;
	int ret = hisi_fb_cfg_sec(0);

	if (ret != 0)
		HISI_FB_ERR("config dss to 0 error %d\n", ret);
	else
		HISI_FB_INFO("config dss to 0 success\n");

	return ret;
}

static int display_init(void)
{
	int ret;
	errno_t err;
	struct hisifb_data_type *hisifd = &g_hisifb_data;

	err = memset_s(hisifd, sizeof(struct hisifb_data_type), 0,
			sizeof(struct hisifb_data_type));
	if (err != EOK)
		HISI_FB_ERR("memset_s error: ret=[%d]\n", err);

	ret = device_probe(hisifd);
	if (ret) {
		HISI_FB_ERR("display initialize error\n");
		return ret;
	}
	return ret;
}

int display_syscall(int swi_id, struct drv_param *params, UINT64 permissions)
{
	uint64_t *args = NULL;
	char *data = NULL;
	char *rdata = NULL;
	size_t rdata_len;

	UINT32 uwRet;
	/* According to ARM AAPCS arguments from 5-> in a function call
	 * are stored on the stack, which in this case is pointer by
	 * user sp. Our own TrustedCore also push FP and LR on the stack
	 * just before SWI, so skip them */
	if (params == NULL || params->args == 0) {
		HISI_FB_ERR("regs is NULL! \n");
		return -1;
	}

	args = (uint64_t *)(uintptr_t)params->args;
	data = (char *)(uintptr_t)params->data;
	rdata = (char *)(uintptr_t)params->rdata;
	rdata_len = (size_t)params->rdata_len;

	HANDLE_SYSCALL(swi_id) {
		SYSCALL_PERMISSION(SW_SYSCALL_FB_SEC_CFG, permissions, TUI_GROUP_PERMISSION)
		uwRet = (UINT32)hisi_fb_cfg_sec((int)args[0]);
		args[0] = uwRet;
		SYSCALL_END

		SYSCALL_PERMISSION(SW_SYSCALL_FB_SEC_DISPLAY, permissions, TUI_GROUP_PERMISSION)
		/* args[0] is dss_layer_t, a small data structure, store in message buffer */
		/* args[0] is input arg, and it is modified in hisi_pan_display_sec, so it is also output arg */
		if (args[0] != 0) {
			tloge("cmd %s: invalid parameter\n", "SW_SYSCALL_FB_SEC_DISPLAY");
			args[0] = OS_ERROR;
			goto out;
		}
		args[0] = (uintptr_t)data + args[0];
		/* for the pointer in args[0], ACCESS_CHECK with drv_map_from_task for read/write with the pointer */
		if (args[0]) {
			ACCESS_CHECK_NOCPY_A64(((dss_layer_t *)(uintptr_t)args[0])->img.vir_addr, ((dss_layer_t *)(uintptr_t)args[0])->img.buf_size);
			ACCESS_READ_RIGHT_CHECK(((dss_layer_t *)(uintptr_t)args[0])->img.vir_addr, ((dss_layer_t *)(uintptr_t)args[0])->img.buf_size);
			ACCESS_WRITE_RIGHT_CHECK(((dss_layer_t *)(uintptr_t)args[0])->img.vir_addr, ((dss_layer_t *)(uintptr_t)args[0])->img.buf_size);
		}
		uwRet = (UINT32)hisi_pan_display_sec((dss_layer_t *)(uintptr_t)args[0]);
		if (memcpy_s(rdata, rdata_len, (char *)(uintptr_t)args[0], sizeof(dss_layer_t))) {
			params->rdata_len = 0;
			args[0] = OS_ERROR;
		} else {
			params->rdata_len = sizeof(dss_layer_t);
			args[0] = uwRet;
		}
		SYSCALL_END

		SYSCALL_PERMISSION(SW_SYSCALL_FB_ACTIVE_FLAG, permissions, TUI_GROUP_PERMISSION)
		uwRet = (UINT32)hisi_wait_vactive_start_flag();
		args[0] = uwRet;
		SYSCALL_END

		SYSCALL_PERMISSION(SW_SYSCALL_FB_RELEASE_FLAG, permissions, TUI_GROUP_PERMISSION)
		uwRet = (UINT32)hisi_wait_release_flag();
		args[0] = uwRet;
		SYSCALL_END

		SYSCALL_PERMISSION(SW_SYSCALL_FB_GETINFO, permissions, TUI_GROUP_PERMISSION)
		/* args[0] is struct hisi_panel_info, a small data structure, store in message buffer */
		/* args[0] is both input and output argument */
		if (args[0] != 0) {
			tloge("cmd %s: invalid parameter\n", "SW_SYSCALL_FB_GETINFO");
			args[0] = OS_ERROR;
			goto out;
		}
		args[0] = (uintptr_t)data + args[0];
		uwRet = (UINT32)hisi_get_disp_info((struct hisi_panel_info *)(uintptr_t)args[0]);
		if (memcpy_s(rdata, rdata_len, (char *)(uintptr_t)args[0], sizeof(struct hisi_panel_info))) {
			params->rdata_len = 0;
			args[0] = OS_ERROR;
		} else {
			params->rdata_len = sizeof(struct hisi_panel_info);
			args[0] = uwRet;
		}
		SYSCALL_END

		SYSCALL_PERMISSION(SW_SYSCALL_FB_SEC_SET, permissions, TUI_GROUP_PERMISSION)
		uwRet = (UINT32)hisi_fb_alpha_set((int)args[0]);
		args[0] = uwRet;
		SYSCALL_END

	default:
		return -1;
	}

	return 0;
}

DECLARE_TC_DRV(
	display_driver,
	0,
	0,
	0,
	TC_DRV_MODULE_INIT,
	display_init,
	NULL,
	display_syscall,
	NULL,
	NULL
);

