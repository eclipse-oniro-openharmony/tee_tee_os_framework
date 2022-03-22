/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * Description: process load hifi
 * Author: liwanpeng l00319081
 * Create: 2018-5-21
 */

#include "hisi_reload_hifi.h"

#include <stdint.h>
#include "securec.h"
#include "mem_page_ops.h"
#include "mem_ops.h"
#include "register_ops.h"
#include "sre_debug.h"
#include "drv_mem.h"
#include "hisi_secureboot.h"
#include <hisi_hifi.h>

#define IMG_TIME_STAMP_MAX_SIZE 24

enum image_section_type {
	IMAGE_SECTION_CODE = 0,
	IMAGE_SECTION_DATA,
	IMAGE_SECTION_BSS,
	IMAGE_SECTION_BUTT,
};

enum image_section_load_attribute {
	LOAD_ATTRIBUTE_STATIC = 0,
	LOAD_ATTRIBUTE_DYNAMIC,
	LOAD_ATTRIBUTE_SHARE_MEM,
	LOAD_ATTRIBUTE_UNINIT,
	LOAD_ATTRIBUTE_UNLOAD,
	LOAD_ATTRIBUTE_BUTT,
};

struct image_section {
	unsigned short sn;
	unsigned char type;
	unsigned char load_attib;
	unsigned int src_offset;
	unsigned int des_addr;
	unsigned int size;
};

struct image_head {
	char time_stamp[IMG_TIME_STAMP_MAX_SIZE];
	unsigned int image_size;
	unsigned int sections_num;
	struct image_section sections[HIFI_SEC_MAX_NUM];
};

extern void v7_dma_clean_range(unsigned long start, unsigned long end);
extern void irq_lock();
extern void irq_unlock();

static bool is_hifi_power_on(void)
{
	unsigned int ret;
	unsigned int val;
	unsigned int map_addr;

	ret = sre_mmap((paddr_t)(HIFI_POWER_STATUS_ADDR), sizeof(int),
		&map_addr, non_secure, cache);
	if (ret != 0) {
		aloge("map power status addr error");
		return false;
	}

	val = *(unsigned int *)(uintptr_t)(map_addr);

	(void)sre_unmap(map_addr, sizeof(int));

	if (val == HIFI_POWER_ON)
		return true;

	return false;
}

#if (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_KIRIN990 || TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_BALTIMORE)
static void ddr_remap_dump(void)
{
	alogi("ddr remap register 1: remap_en = 0x%x, src = 0x%x, des = 0x%x",
		readl(HIFI_CFG_DDR_REMAP_EN_1), readl(HIFI_CFG_DDR_REMAP_SRC_1), readl(HIFI_CFG_DDR_REMAP_DES_1));
	alogi("ddr remap register 2: remap_en = 0x%x, src = 0x%x, des = 0x%x",
		readl(HIFI_CFG_DDR_REMAP_EN_2), readl(HIFI_CFG_DDR_REMAP_SRC_2), readl(HIFI_CFG_DDR_REMAP_DES_2));
	alogi("ddr remap register 3: remap_en = 0x%x, src = 0x%x, des = 0x%x",
		readl(HIFI_CFG_DDR_REMAP_EN_3), readl(HIFI_CFG_DDR_REMAP_SRC_3), readl(HIFI_CFG_DDR_REMAP_DES_3));
}

static void dmmu_unremap(void)
{
	alogi("before unremap: begin = 0x%x, end = 0x%x, gid = 0x%x",
		readl(HIFI_DMMU_REMAP_BEGIN_ADDR), readl(HIFI_DMMU_REMAP_END_ADDR), readl(HIFI_DMMU_REMAP_GID_ADDR));

	writel(0x0, HIFI_DMMU_REMAP_BEGIN_ADDR);
	writel(0xfffff, HIFI_DMMU_REMAP_END_ADDR);
	writel(0x0, HIFI_DMMU_REMAP_GID_ADDR);

	alogi("after unremap: begin = 0x%x, end = 0x%x, gid = 0x%x",
		readl(HIFI_DMMU_REMAP_BEGIN_ADDR), readl(HIFI_DMMU_REMAP_END_ADDR), readl(HIFI_DMMU_REMAP_GID_ADDR));
}
#endif

static unsigned int pause_hifi(void)
{
	if (!is_hifi_power_on()) {
		aloge("hifi is not power on, do not reload hifi");
		return SECBOOT_RET_HIFI_NOT_POWER_ON;
	}

	writel(0x1, HIFI_CFG_R_DSP_RUNSTALL);

	/*
	 * On the 990 or baltimore platform, HIFI do dmmu remap when power up,
	 * and unremap has to be done when HIFI reset.
	 */
#if (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_KIRIN990 || TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_BALTIMORE)
	ddr_remap_dump();
	dmmu_unremap();
#endif

	return 0;
}

static unsigned int get_noclear_size(unsigned int *size)
{
	int ret;
	unsigned int i;
	unsigned int head_addr;
	unsigned int uninit_size;
	unsigned long uninit_addr;
	unsigned long noclear_size;
	struct image_head *head = NULL;

	ret = sre_mmap((paddr_t)HIFI_SEC_HEAD_LOCATION, HIFI_SEC_HEAD_SIZE,
		&head_addr, secure, cache);
	if (ret != 0) {
		aloge("map section head error");
		return SECBOOT_RET_HIFI_MAP_FAIL;
	}

	head = (struct image_head *)(uintptr_t)head_addr;
	if (head->sections_num > HIFI_SEC_MAX_NUM) {
		aloge("sections num error: %u", head->sections_num);
		(void)sre_unmap(head_addr, HIFI_SEC_HEAD_SIZE);
		return SECBOOT_RET_HIFI_PRE_CHECK_FAIL;
	}

	for (i = 0; i < head->sections_num; i++) {
		if (head->sections[i].load_attib ==
			(unsigned char)LOAD_ATTRIBUTE_UNINIT) {
			uninit_size = head->sections[i].size;
			uninit_addr = head->sections[i].des_addr;
			break;
		}
	}

	if (i == head->sections_num) {
		aloge("get uninit size error");
		(void)sre_unmap(head_addr, HIFI_SEC_HEAD_SIZE);
		return SECBOOT_RET_HIFI_PRE_CHECK_FAIL;
	}

	(void)sre_unmap(head_addr, HIFI_SEC_HEAD_SIZE);

	noclear_size = uninit_addr + uninit_size - HIFI_DDR_MAP_BEGIN_ADDR;
	if (noclear_size >= HIFI_RUN_SIZE) {
		aloge("section head is dirty");
		return SECBOOT_RET_HIFI_SEC_HEAD_DIRTY;
	}

	*size = noclear_size;

	return 0;
}

static unsigned int clear_load_region(unsigned int size)
{
	int ret;
	unsigned int hifi_addr;
	unsigned int load_addr;

	ret = sre_mmap((paddr_t)HIFI_RUN_LOCATION, HIFI_RUN_SIZE,
		&hifi_addr, secure, cache);
	if (ret != 0) {
		aloge("map run location addr error");
		return SECBOOT_RET_HIFI_ADDR_MAP_FAIL;
	}

	load_addr = size + hifi_addr;
	ret = memset_s((char *)(uintptr_t)load_addr, HIFI_RUN_SIZE - size,
		0, HIFI_RUN_SIZE - size);
	if (ret != EOK) {
		aloge("memset_s fail ret:%d", ret);
		(void)sre_unmap(hifi_addr, HIFI_RUN_SIZE);
		return SECBOOT_INVALID_VALUE;
	}

	(void)sre_unmap(hifi_addr, HIFI_RUN_SIZE);

	return 0;
}

static unsigned int check_section(const struct image_head *img_head,
	const struct image_section *img_sec)
{
	/* BSS section excluded, it only record the address and length */
	if (img_sec->type == IMAGE_SECTION_BSS &&
		(img_sec->sn < img_head->sections_num) &&
		(img_sec->load_attib < (unsigned char)LOAD_ATTRIBUTE_BUTT)) {
		return 0;
	}

	if ((img_sec->sn >= img_head->sections_num) ||
		(img_sec->src_offset + img_sec->size > img_head->image_size) ||
		(img_sec->type >= (unsigned char)IMAGE_SECTION_BUTT) ||
		(img_sec->load_attib >= (unsigned char)LOAD_ATTRIBUTE_BUTT)) {
		return SECBOOT_RET_FAILURE;
	}

	return 0;
}

unsigned int get_hifi_cma_size(void)
{
	return HIFI_CMA_IMAGE_SIZE;
}

unsigned int get_hifi_image_size(unsigned int *image_size)
{
	int ret;
	unsigned int size;
	unsigned int head_addr;
	struct image_head *head = NULL;

	if (image_size == NULL) {
		aloge("para null");
		return SECBOOT_RET_PARAM_ERROR;
	}

	ret = sre_mmap((paddr_t)HIFI_SEC_HEAD_LOCATION, HIFI_SEC_HEAD_SIZE,
		&head_addr, secure, cache);
	if (ret != 0) {
		aloge("map data buffer error");
		return SECBOOT_RET_HIFI_MAP_FAIL;
	}

	head = (struct image_head *)(uintptr_t)head_addr;
	size = head->image_size;
	(void)sre_unmap(head_addr, HIFI_SEC_HEAD_SIZE);

	if (size == 0 || size > HIFI_CMA_IMAGE_SIZE) {
		aloge("image size error: %u", size);
		return SECBOOT_RET_FAILURE;
	}

	*image_size = size;

	alogi("image size: %u", *image_size);

	return 0;
}

unsigned int prepare_reload_hifi(void)
{
	unsigned int ret;
	unsigned int size;

	ret = pause_hifi();
	if (ret != 0)
		return ret;

	ret = get_noclear_size(&size);
	if (ret != 0)
		return ret;

	ret = clear_load_region(size);
	if (ret != 0)
		return ret;

	return 0;
}

static unsigned int load_img_sections(const struct image_head *head,
	unsigned int hifi_addr)
{
	int ret;
	unsigned int i;
	unsigned int uint_ret;
	unsigned long offset;
	unsigned long load_addr;

	for (i = 0; i < head->sections_num; i++) {
		uint_ret = check_section(head, &(head->sections[i]));
		if (uint_ret == SECBOOT_RET_FAILURE) {
			aloge("hifi section %u is error", i);
			return SECBOOT_RET_HIFI_LOAD_CHECK_FAIL;
		}

		if (head->sections[i].size == 0 ||
			(head->sections[i].load_attib !=
			(unsigned char)LOAD_ATTRIBUTE_STATIC) ||
			(head->sections[i].type == IMAGE_SECTION_BSS))
			continue;

		offset = (unsigned long)head->sections[i].des_addr - HIFI_DDR_MAP_BEGIN_ADDR;
		load_addr = hifi_addr + offset;

		ret = memcpy_s((void *)(uintptr_t)(load_addr), HIFI_RUN_SIZE,
			(void *)((char *)head + head->sections[i].src_offset),
			head->sections[i].size);
		if (ret != EOK) {
			aloge("memcpy_s fail ret:%d", ret);
			return SECBOOT_INVALID_VALUE;
		}

		__asm__ volatile ("isb");
		__asm__ volatile ("dsb sy");
	}

	return 0;
}

unsigned int load_hifi_image(const void *img_buf)
{
	int ret;
	unsigned int uint_ret;
	unsigned int hifi_addr;
	const struct image_head *head = NULL;

	if (img_buf == NULL) {
		aloge("img buf is null");
		return SECBOOT_RET_FAILURE;
	}

	ret = sre_mmap((paddr_t)HIFI_RUN_LOCATION, HIFI_RUN_SIZE, &hifi_addr, secure, cache);
	if (ret != 0) {
		aloge("map hifi run loaction addr err");
		return SECBOOT_RET_HIFI_MAP_FAIL;
	}

	head = (struct image_head *)img_buf;
	if (head->sections_num > HIFI_SEC_MAX_NUM) {
		aloge("sections num error: %u", head->sections_num);
		(void)sre_unmap(hifi_addr, HIFI_RUN_SIZE);
		return SECBOOT_RET_HIFI_LOAD_CHECK_FAIL;
	}

	irq_lock();

	uint_ret = load_img_sections(head, hifi_addr);
	if (uint_ret != 0) {
		irq_unlock();
		aloge("load img section err, ret: %u", uint_ret);
		(void)sre_unmap(hifi_addr, HIFI_RUN_SIZE);
		return uint_ret;
	}

	v7_dma_clean_range(hifi_addr, hifi_addr + HIFI_RUN_SIZE);
	irq_unlock();
	(void)sre_unmap(hifi_addr, HIFI_RUN_SIZE);

	return 0;
}

unsigned int dump_cma_text(const void *img_buf)
{
	int ret;
	unsigned int remap_addr;
	unsigned long dump_addr;

	if (img_buf == NULL) {
		aloge("img buf is null");
		return SECBOOT_RET_FAILURE;
	}

	dump_addr = HIFI_IMAGE_OCRAMBAK_LOCATION - HIFI_CMA_IMAGE_SIZE;
	ret = sre_mmap((paddr_t)dump_addr, HIFI_CMA_IMAGE_SIZE, &remap_addr,
		secure, cache);
	if (ret != 0) {
		aloge("map hifi cma image addr err");
		return SECBOOT_RET_HIFI_MAP_FAIL;
	}

	(void)memcpy_s((void *)(uintptr_t)(remap_addr), HIFI_CMA_IMAGE_SIZE,
		img_buf, HIFI_CMA_IMAGE_SIZE);

	__asm__ volatile ("isb");
	__asm__ volatile ("dsb sy");

	v7_dma_clean_range(remap_addr, remap_addr + HIFI_CMA_IMAGE_SIZE);

	(void)sre_unmap(remap_addr, HIFI_CMA_IMAGE_SIZE);

	return 0;
}

