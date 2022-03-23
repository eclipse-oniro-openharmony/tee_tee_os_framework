/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: TUI secure display test functions
 * Author: Hisilicon DSS
 * Create: 2019-06-19
 */
#include "mem_ops.h" // virt_mem_to_phys
#include "hisi_disp_test.h"
#include "hisi_fb_sec.h"


#define WHITE_COLOR (0x00FFFFFF)
#define RED_COLOR   (0x00FF0000)
#define GREEN_COLOR (0x0000FF00)
#define BLUE_COLOR  (0x000000FF)

unsigned char g_test_buf[64 * 64 * 4]; /* w=64,h=64,each pixel=4 bytes */

static void fill_color(char *buff, unsigned int size, int32_t color)
{
	HISI_ERR_CHECK_NO_RETVAL((buff == NULL), "buff is NULL\n");

	while (size) {
		*buff++ = (char)(color & 0x000000ff);
		*buff++ = (char)((color & 0x0000ff00) >> 8);
		*buff++ = (char)((color & 0x00ff0000) >> 16);
		*buff++ = (char)((color & 0xff000000) >> 24);
		size -= 4;
	}
}
static void set_test_buffer(uint32_t test_buffer_base, uint32_t size, int32_t color)
{
	fill_color((char *)(unsigned long)test_buffer_base, size, color);
}

static void set_test_layer_data(struct hisifb_data_type *hisifd, uint32_t disp_phys_addr)
{
	dss_layer_t *layer = &(hisifd->layer);
	errno_t err;

	err = memset_s(layer, sizeof(dss_layer_t), 0, sizeof(dss_layer_t));
	if (err != EOK)
		HISI_FB_ERR("memset_s error: ret=[%d]\n", err);

	/* display test buffer is w=64,h=64,bpp=4 bytes */
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
}

int display_test(struct hisifb_data_type *hisifd)
{
	uint32_t disp_phys_addr = 0;
	dss_layer_t *layer = NULL;
	static int func_switch = 1;

	HISI_ERR_CHECK_RETURN((hisifd == NULL), -1, "hisifd is NULL\n");

	HISI_FB_INFO("+++!\n");
	if (!disp_phys_addr) {
		disp_phys_addr = (uint32_t)g_test_buf;
		HISI_FB_INFO("display_addr = 0x%x\n", disp_phys_addr);
	}
	/* fill test buffer with test color data */
	set_test_buffer(disp_phys_addr, 64 * 16 * 4, RED_COLOR);
	set_test_buffer(disp_phys_addr + 64 * 16 * 4, 64 * 16 * 4, WHITE_COLOR);
	set_test_buffer(disp_phys_addr + 64 * 32 * 4, 64 * 16 * 4, GREEN_COLOR);
	set_test_buffer(disp_phys_addr + 64 * 48 * 4, 64 * 16 * 4, BLUE_COLOR);

	set_test_layer_data(hisifd, disp_phys_addr);

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



