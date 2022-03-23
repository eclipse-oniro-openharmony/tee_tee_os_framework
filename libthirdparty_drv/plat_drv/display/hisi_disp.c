/* Copyright (c) 2014-2015, Hisilicon Tech. Co., Ltd. All rights reserved.
 *
 */
#include "sre_task.h"
#include "sre_syscalls_id_ext.h"
#include "sre_syscalls_id.h"
#include "mem_ops.h"
#include "mem_page_ops.h"
#include "tee_mutex.h"
#include "sre_access_control.h"
#include "hisi_disp.h"
#include "hisi_fb_sec.h"
#include "sre_dev_relcb.h"
#include "drv_module.h"
#include "drv_pal.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wint-conversion"
/* for debug */
#define HISI_FB_DISPLAY_DEBUG  (0)
unsigned int hisi_fb_msg_level = 3;

/* global data */
struct hisifb_data_type hisifb_data;
int display_release(void *data);

/* dss secure mode init
 ** input: sec_value,
 **        if true, enter into secure pay mode
 **        if false, exit secure pay mode
 **return: 0, success
 **       -1, failed
 */
int hisi_fb_cfg_sec(int sec_value)
{
	int ret = 0;
	struct hisifb_data_type *hisifd = &hisifb_data;

	if (!hisifd) {
		HISI_FB_ERR("hisifd is NULL! \n");
		return -1;
	}

	if (tee_mutex_lock_wait(hisifd->disp_lock)){
		HISI_FB_INFO("wait lock failed!\n");
		return -1;
	}

	if (hisifd->panel_power_on && hisifd->panel_power_on(hisifd)) {
		HISI_FB_INFO("hisi fb is already power off!\n");
		tee_mutex_unlock(hisifd->disp_lock);
		return -1;
	}

	if (hisifd->fb_cfg_sec) {
		ret = hisifd->fb_cfg_sec(hisifd, sec_value);
	}
	tee_mutex_unlock(hisifd->disp_lock);

	if(!ret){
		if (sec_value) {
			ret = (int)task_register_devrelcb((DEV_RELEASE_CALLBACK)display_release, NULL);
			if (ret) {
				HISI_FB_ERR("register tui dss release callback failed:%d\n", ret);
			} else {
				HISI_FB_INFO("register tui dss release callback success\n");
			}
		} else {
			(void)task_unregister_devrelcb((DEV_RELEASE_CALLBACK)display_release, NULL);//lint !e792
			HISI_FB_INFO("unregister tui dss release callback success\n");
		}
	}
	return ret;
}

/* dss secure alpha enable set
 ** input: sec_value,
 **        if true, enable
 **        if false, disable
 **return: 0, success
 **       -1, failed
 */
int hisi_fb_alpha_set(int value)
{
	int ret = 0;
	struct hisifb_data_type *hisifd = &hisifb_data;
	dss_layer_t *layer = NULL;

	if (!hisifd) {
		HISI_FB_ERR("hisifd is NULL! \n");
		return -1;
	}

	if (hisifd->alpha_enable) {
		HISI_FB_INFO("hisifd->alpha_enable = %d \n", hisifd->alpha_enable);
		return ret;
	}

	if (tee_mutex_lock_wait(hisifd->disp_lock)) {
		HISI_FB_INFO("wait lock failed!\n");
		return -1;
	}
	if (hisifd->panel_power_on && hisifd->panel_power_on(hisifd)) {
		HISI_FB_INFO("hisi fb is already power off!\n");
		tee_mutex_unlock(hisifd->disp_lock);
		return -1;
	}

	hisifd->alpha_enable = value;
	if (hisifd->alpha_enable && hisifd->pan_display_sec) {
		layer = &(hisifd->layer_prev);
		ret = hisifd->pan_display_sec(hisifd, layer);
		if (ret) {
			HISI_FB_ERR("hisi pan display sec failed.\n");
			tee_mutex_unlock(hisifd->disp_lock);
			return -1;
		}
	}

	tee_mutex_unlock(hisifd->disp_lock);
	return ret;
}

/*
 **receive one frame data information
 **
 **input: rect, display region and data format(bpp)
 **       display_addr, display buffer base address
 **
 **return: 0, success
 **       -1, failed
 */
int hisi_pan_display_sec(dss_layer_t *layer)
{
	int ret = 0;
	struct hisifb_data_type *hisifd = &hisifb_data;
	dss_layer_t *player = NULL;

	if (!hisifd) {
		HISI_FB_ERR("hisifd is NULL! \n");
		return -1;
	}

	HISI_FB_DEBUG("enter! \n");
	if (layer == NULL) {
		HISI_FB_ERR("pdisp_info is NULL! \n");
		return -1;
	}

	if (tee_mutex_lock_wait(hisifd->disp_lock)){
		HISI_FB_INFO("wait lock failed!\n");
		return -1;
	}
	if (hisifd->panel_power_on && hisifd->panel_power_on(hisifd)) {
		HISI_FB_INFO("hisi fb is already power off!\n");
		tee_mutex_unlock(hisifd->disp_lock);
		return -1;
	}

	layer->img.phy_addr = (uint32_t)virt_mem_to_phys(layer->img.vir_addr);

	HISI_FB_INFO("layer[%d]: img.bpp = %d\n",hisifd->frame_count, layer->img.bpp);
	/*HISI_FB_PRINTF("\timg.vir_addr = 0x%x, img.phy_addr = 0x%x\n",
			layer->img.vir_addr, layer->img.phy_addr);*/
	HISI_FB_PRINTF("\timg.width = %d, img.height = %d\n",layer->img.width, layer->img.height);
	HISI_FB_PRINTF("\tsrc_rect: [%d, %d, %d, %d], dst_rect: [%d, %d, %d, %d]\n",
			layer->src_rect.x, layer->src_rect.y,
			layer->src_rect.w, layer->src_rect.h,
			layer->dst_rect.x, layer->dst_rect.y,
			layer->dst_rect.w, layer->dst_rect.h);

	if (hisifd->pan_display_sec) {
		player = &(hisifd->layer);
		if (!player) {
			HISI_FB_ERR("player is NULL! \n");
			return -1;
		}

		ret = memcpy_s(player, sizeof(dss_layer_t), layer, sizeof(dss_layer_t));
		if (ret) {
			HISI_FB_ERR("memcpy_s error: ret=[%d]\n", ret);
		}
		ret = hisifd->pan_display_sec(hisifd, player);
		if (ret) {
			HISI_FB_ERR("hisi pan display sec failed.\n");
			tee_mutex_unlock(hisifd->disp_lock);
			return -1;
		}
		// save last frame data
		hisifd->frame_count++;
		ret = memcpy_s(&(hisifd->layer_prev), sizeof(dss_layer_t), player, sizeof(dss_layer_t));
		if (ret) {
			HISI_FB_ERR("memcpy_s error: ret=[%d]\n", ret);
		}
	}

	tee_mutex_unlock(hisifd->disp_lock);
	HISI_FB_DEBUG("exit! \n");

	return ret;
}

int hisi_wait_vactive_flag(void)
{
	int ret = 0;
	struct hisifb_data_type *hisifd = &hisifb_data;

	if (!hisifd) {
		HISI_FB_ERR("hisifd is NULL! \n");
		return -1;
	}

	if (hisifd->panel_power_on && hisifd->panel_power_on(hisifd)) {
		HISI_FB_INFO("hisi fb is already power off!\n");
		return -1;
	}

	if (hisifd->wait_vactive_flag) {
		ret = hisifd->wait_vactive_flag(hisifd);
	}
	return ret;
}

int hisi_wait_release_flag(void)
{
	int ret = 0;
	struct hisifb_data_type *hisifd = &hisifb_data;

	if (!hisifd) {
		HISI_FB_ERR("hisifd is NULL! \n");
		return -1;
	}

	if (hisifd->panel_power_on && hisifd->panel_power_on(hisifd)) {
		HISI_FB_INFO("hisi fb is already power off!\n");
		return -1;
	}

	if (hisifd->wait_release_flag) {
		ret = hisifd->wait_release_flag(hisifd);
	}
	return ret;
}

int hisi_get_disp_info(struct hisi_panel_info *pinfo)
{
	int ret = 0;
	struct hisifb_data_type *hisifd = &hisifb_data;

	if (!hisifd) {
		HISI_FB_ERR("hisifd is NULL! \n");
		return -1;
	}

	if (!pinfo) {
		HISI_FB_ERR("pinfo is NULL! \n");
		return -1;
	}

	if (hisifd->get_disp_info) {
		ret = hisifd->get_disp_info(hisifd, pinfo);
		if (ret) {
			HISI_FB_ERR("failed to get disp info!!!\n");
		}
	}
	return ret;
}

int display_release(void *data)
{
	(void)data;
	int ret = hisi_fb_cfg_sec(0);
	if (ret) {
		HISI_FB_ERR("config dss to 0 error %d\n", ret);
	} else {
		HISI_FB_INFO("config dss to 0 success.\n");
	}
	return ret;
}//lint !e715

static int display_init(void)
{
	int ret;
	struct hisifb_data_type *hisifd = &hisifb_data;

	if (!hisifd) {
		HISI_FB_ERR("hisifd is NULL! \n");
		return -1;
	}

	ret = memset_s(hisifd, sizeof(struct hisifb_data_type), 0, \
			sizeof(struct hisifb_data_type)); //lint !e838
	if (ret) {
		HISI_FB_ERR("memset_s error: ret=[%d]\n", ret);
	}

	ret = device_probe(hisifd);
	if (ret) {
		HISI_FB_ERR("display_init error\n");
		return ret;
	}
	return ret;
}

#if HISI_FB_DISPLAY_DEBUG
#define WHITE_COLOR		(0x00FFFFFF)
#define RED_COLOR		(0x00FF0000)
#define GREEN_COLOR		(0x0000FF00)
#define BLUE_COLOR		(0x000000FF)
static void fill_color(char *buff, unsigned int size, int32_t color)
{
	if (!buff) {
		HISI_FB_ERR("The input parameter is NULL\n");
		return;
	}
	while (size) {
		*buff ++ = (char)(color&0x000000ff);
		*buff ++ = (char)((color&0x0000ff00) >> 8);
		*buff ++ = (char)((color&0x00ff0000) >> 16);
		*buff ++ = (char)((color&0xff000000) >> 24);
		size -= 4;
	}
}
static void test_buffer_set(uint32_t test_buffer_base, uint32_t size , int32_t color)
{
	fill_color((char *)(unsigned long)test_buffer_base, size, color);
}

unsigned char temp[64 * 64 * 4];
int display_test(void)
{
	uint32_t disp_phys_addr = 0;
	dss_layer_t *layer = NULL;
	static int func_switch = 1;
	struct hisifb_data_type *hisifd = &hisifb_data;
	int ret = 0;

	if (!hisifd) {
		HISI_FB_ERR("hisifd is NULL! \n");
		return -1;
	}

	HISI_FB_INFO("+++!\n");
	if (!disp_phys_addr) {
		disp_phys_addr = (uint32_t)temp;
		HISI_FB_INFO("display_addr = 0x%x\n", disp_phys_addr);
	}

	test_buffer_set(disp_phys_addr, 64*16*4, RED_COLOR);
	test_buffer_set(disp_phys_addr + 64*16*4, 64*16*4, WHITE_COLOR);
	test_buffer_set(disp_phys_addr + 64*32*4, 64*16*4, GREEN_COLOR);
	test_buffer_set(disp_phys_addr + 64*48*4, 64*16*4, BLUE_COLOR);

	layer = &(hisifd->layer);

	if (!layer) {
		HISI_FB_ERR("layer is NULL! \n");
		return -1;
	}

	ret = memset_s(layer, sizeof(dss_layer_t), 0, sizeof(dss_layer_t));
	if (ret) {
		HISI_FB_ERR("memset_s error: ret=[%d]\n", ret);
	}

	layer->img.format = HISI_FB_PIXEL_FORMAT_RGBA_8888;
	layer->img.width  = 64;
	layer->img.height = 64;
	layer->img.bpp    = 4;
	layer->img.stride = ALIGN_UP(layer->img.width * layer->img.bpp, DMA_STRIDE_ALIGN);
	layer->img.phy_addr = virt_mem_to_phys(disp_phys_addr);
	layer->img.vir_addr = disp_phys_addr;
	layer->img.mmu_enable = 0;
	layer->img.secure_mode = 1;

	layer->src_rect.x = 0;
	layer->src_rect.y = 0;
	layer->src_rect.w = 64;
	layer->src_rect.h = 64;

	layer->dst_rect.x = 500;
	layer->dst_rect.y = 500;
	layer->dst_rect.w = 64;
	layer->dst_rect.h = 64;
	layer->transform = HISI_FB_TRANSFORM_NOP;
	layer->blending  = HISI_FB_BLENDING_NONE;
	layer->glb_alpha = 0xFF;
	layer->color     = 0x0;
	layer->layer_idx = 0x0;
	layer->chn_idx   = hisifd->sec_rch_idx;

	if (func_switch) {
		hisi_fb_cfg_sec(func_switch);
		hisi_pan_display_sec(layer);
	} else {
		hisi_fb_cfg_sec(func_switch);
	}
	func_switch = !func_switch;
	HISI_FB_INFO("---!\n");

	return 0;
}
#endif

/* redefine several macros */
#include <hmdrv_stub.h>
int display_syscall(int swi_id, struct drv_param *params, UINT64 permissions)
{
	uint64_t *args = NULL;
	char *data = NULL;
	char *rdata = NULL;
	size_t rdata_len = 0;
	UINT32 uwRet = 0;
	/* According to ARM AAPCS arguments from 5-> in a function call
	 * are stored on the stack, which in this case is pointer by
	 * user sp. Our own TrustedCore also push FP and LR on the stack
	 * just before SWI, so skip them */
	if (params == NULL || params->args == 0) {
		HISI_FB_ERR("regs is NULL! \n");
		return -1;
	}

	args = (uint64_t *)(uintptr_t)params->args;
	data = (char *)params->data;
	rdata = (char *)params->rdata;
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
		args[0] = data + args[0];
		/* for the pointer in args[0], ACCESS_CHECK with drv_map_from_task for read/write with the pointer */
		if (args[0]) {
			ACCESS_CHECK_NOCPY_A64(((dss_layer_t *)args[0])->img.vir_addr, ((dss_layer_t *)args[0])->img.buf_size);
			ACCESS_READ_RIGHT_CHECK(((dss_layer_t *)args[0])->img.vir_addr, ((dss_layer_t *)args[0])->img.buf_size);
			ACCESS_WRITE_RIGHT_CHECK(((dss_layer_t *)args[0])->img.vir_addr, ((dss_layer_t *)args[0])->img.buf_size);
		}
		uwRet = (UINT32)hisi_pan_display_sec((dss_layer_t *)args[0]);
		if (memcpy_s(rdata, rdata_len, args[0], sizeof(dss_layer_t))) {
			params->rdata_len = 0;
			args[0] = OS_ERROR;
		} else {
			params->rdata_len = sizeof(dss_layer_t);
			args[0] = uwRet;
		}
		SYSCALL_END

		SYSCALL_PERMISSION(SW_SYSCALL_FB_ACTIVE_FLAG, permissions, TUI_GROUP_PERMISSION)
		uwRet = (UINT32)hisi_wait_vactive_flag();
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
		args[0] = data + args[0];
		uwRet = (UINT32)hisi_get_disp_info((struct hisi_panel_info *)args[0]);
		if (memcpy_s(rdata, rdata_len, (const void *)(uintptr_t)args[0], sizeof(struct hisi_panel_info))) {
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
/*lint -e528 -esym(528,*)*/
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
/*lint +e528 -esym(528,*)*/
#pragma GCC diagnostic pop
