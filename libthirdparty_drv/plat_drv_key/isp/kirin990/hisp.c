/*
* Copyright (c) Huawei Technologies Co., Ltd. 2012-2019. All rights reserved.
* Description: isp interface
* Author: z00367550
* Create: 2019-9-26
*/

#include "hisp.h"
#include "register_ops.h"
#include "dynion.h"
#include "tee_log.h"
#include "mem_page_ops.h"
#include "ccmgr_ops_ext.h"

static int is_media1_reset(void)
{
	unsigned int reg;

	reg = readl(CRG_0A4_PERRSTSTAT5) & IP_RST_MEDIA;
	return (reg == 0) ? 0 : -1;
}

static int is_isp_reset(void)
{
	unsigned int reg;

	reg = readl(MEDIA_CRG_808_PERRSTSTAT_ISP_SEC) & IP_RST_ISP;
	return (reg == 0) ? 0 : -1;
}

int hisi_isp_reset(void)
{
	tloge("[%s] +\n", __func__);

	if (is_media1_reset() < 0) {
		tloge("[%s] : Media1 is Reset.-1\n", __func__);
		return -1;
	}

	writel(0x00000010, MEDIA_CRG_800_PERRSTEN_ISP_SEC);
	tloge("[%s] -\n", __func__);
	return 0;
}

/*lint -e438 -e529 -esym(438,*) -esym(529,*)*/
int hisi_isp_disreset(unsigned int remapaddr)
{
	unsigned int canary;
	unsigned int err;

	tloge("[%s] +\n", __func__);
	if (is_media1_reset() < 0) {
		tloge("[%s] : Media1 is Reset.-1\n", __func__);
		return -1;
	}

	if (is_isp_reset() < 0) {
		tloge("[%s] : Isp is Reset.-1\n", __func__);
		return -1;
	}

	err = CRYS_RND_GenerateVector(sizeof(canary), (unsigned char *)(&canary));
	if (err != 0) {
		tloge("[%s] : CRYS_RND_GenerateVector fail.%u\n", __func__, err);
		canary = 0;
	}

	writel(canary, ISP_SUBCTRL_CANARY_ADDR);
#if (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_KIRIN990 || \
	TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_DENVER \
)
	writel(ISP_CPU_MID, ISP_SUBCTRL_ISP_CPU_MID);
#endif
	writel(0x00000008, MEDIA_CRG_804_PERRSTDIS_ISP_SEC);
	writel(ISPA7_REMAP_ENABLE | (remapaddr >> ISPA7_REMAP_OFFSET), ISP_SUBCTRL_ISP_A7_CTRL_0); /* lint !e648  */
	writel(FAMA_REMAP_DISABLE, ISP_SUBCTRL_ISP_A7_CTRL_1);
	writel(((readl(MEDIA_CRG_810_ISPCPU_CTRL0_SEC))) & 0xFFFFFFE0, MEDIA_CRG_810_ISPCPU_CTRL0_SEC);
	writel(0x00000010, MEDIA_CRG_804_PERRSTDIS_ISP_SEC);
#if ((TRUSTEDCORE_CHIP_CHOOSE != WITH_CHIP_HI6260) && \
    (TRUSTEDCORE_CHIP_CHOOSE != WITH_CHIP_HI3670))
	writel(0x00000800, (MEDIA_CRG_BASE_ADDR + 0x034));
#endif
	tloge("[%s] -\n", __func__);
	return 0;
}

unsigned int get_isp_img_size(void)
{
	return SEC_ISP_BIN_SIZE;
}

unsigned int get_isp_cma_size(void)
{
	return SEC_CMA_IMAGE_SIZE;
}

unsigned int get_isp_baseaddr(void)
{
	return SEC_ISP_IMG_BASE_ADDR;
}

