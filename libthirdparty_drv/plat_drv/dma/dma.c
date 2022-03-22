#include "dma.h"
#include "./../seccfg/hwspinlock.h"
#include <mem_page_ops.h>
#include "soc_acpu_baseaddr_interface.h"

#include <hisi_boot.h>
#include <stdlib.h>
#include <securec.h>
#include <drv_cache_flush.h> /* v7_dma_flush_range */
#include <drv_mem.h> /* sre_mmap */
#include <mem_ops.h> /* SRE_MemAllocAlign */

#ifdef CONFIG_SUPPORT_DMA_STATIC_ADDR
#include "global_ddr_map.h"
#define HISI_DMA_TX_STATIC_ADDR_OFFSET (310 * 1024)
#define HISI_DMA_RX_STATIC_ADDR_OFFSET (315 * 1024)
#define HISI_DMA_MAX_STATIC_ADDR_SIZE (5 * 1024)
#endif

#ifdef CONFIG_SUPPORT_DMA_MOD_QOS_LEVEL
#include <soc_iomcu_interface.h>
#define HIGHEST_QOS_LEVEL_RW  (0x3 | (0x3 << 2))
#endif

#define DMA_CHAN_TX_RX (BIT(DMA_TX_CHANNEL) | BIT(DMA_RX_CHANNEL))
#define REG_BASE_IOMCU_DMAC SOC_ACPU_IOMCU_DMAC_BASE_ADDR
#define DMA_LIST_MAX_SIZE 0x1FFF
#define DMA_BLOCK_MAX_SIZE 0xFFFF
#define DMA_LIST_32_ALIGN 0x1F

#define INVALID_HW_RES_LOCK_ID 0xFFFFFFFF

#if ((TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_KIRIN990) || \
	(TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_ORLANDO) \
	|| (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI6260) \
	|| (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI3680) \
	|| (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_BALTIMORE) \
	|| (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_DENVER) \
	|| (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_LAGUNA))
#define DMA_HW_RES_LOCK_ID 38
#else
#define DMA_HW_RES_LOCK_ID INVALID_HW_RES_LOCK_ID
#endif

#define INT_STAT 0x00
#define INT_TC1 0x04
#define INT_ERR1 0x0c
#define INT_ERR2 0x10
#define INT_ERR3 0x14
#define INT_TC1_MASK 0x18
#define INT_ERR1_MASK 0x20
#define INT_ERR2_MASK 0x24
#define INT_ERR3_MASK 0x28
#define INT_TC1_RAW 0x600
#define INT_TC2_RAW 0x608
#define INT_ERR1_RAW 0x610
#define INT_ERR2_RAW 0x618
#define INT_ERR3_RAW 0x620
#define CH_PRI 0x688
#define CH_STAT 0x690
#define CX_CUR_CNT1 0x700
#define CX_CUR_CNT0 0x704
#define CX_CURR_SRC_ADDR 0x708
#define CX_CURR_DES_ADDR 0x70C
#define CX_LLI 0x800
#define CX_CNT1 0x80C
#define CX_CNT0 0x810
#define CX_SRC 0x814
#define CX_DST 0x818
#define CX_CONFIG 0x81C
#define AXI_CONFIG 0x820

#define DEF_AXI_CONFIG_TX 0x206206
#define DEF_AXI_CONFIG_RX 0x207207

#define CX_LLI_CHAIN_EN 0x2
#define CCFG_EN 0x1
#define CCFG_SRCINCR (0x1 << 31)
#define CCFG_DSTINCR (0x1 << 30)

#define CHAN_OFFSET 0x40
#define CUR_CHAN_OFFSET 0x10
#define DMA_CHAN_MAX 8
#define DMA_TX_CHANNEL 0x06
#define DMA_RX_CHANNEL 0x07

#define SOC_DMAC_CX_CONFIG_ch_en_START 0
#define SOC_DMAC_CX_CONFIG_ch_en_END 0
#define SOC_DMAC_CX_CONFIG_itc_en_START 1
#define SOC_DMAC_CX_CONFIG_itc_en_END 1
#define SOC_DMAC_CX_CONFIG_flow_ctrl_START 2
#define SOC_DMAC_CX_CONFIG_flow_ctrl_END 3
#define SOC_DMAC_CX_CONFIG_peri_START 4
#define SOC_DMAC_CX_CONFIG_peri_END 9
#define SOC_DMAC_CX_CONFIG_dw_START 12
#define SOC_DMAC_CX_CONFIG_dw_END 14
#define SOC_DMAC_CX_CONFIG_sw_START 16
#define SOC_DMAC_CX_CONFIG_sw_END 18
#define SOC_DMAC_CX_CONFIG_dl_START 20
#define SOC_DMAC_CX_CONFIG_dl_END 23
#define SOC_DMAC_CX_CONFIG_sl_START 24
#define SOC_DMAC_CX_CONFIG_sl_END 27
#define SOC_DMAC_CX_CONFIG_dmode_START 28
#define SOC_DMAC_CX_CONFIG_dmode_END 28
#define SOC_DMAC_CX_CONFIG_smode_START 29
#define SOC_DMAC_CX_CONFIG_smode_END 29
#define SOC_DMAC_CX_CONFIG_di_START 30
#define SOC_DMAC_CX_CONFIG_di_END 30
#define SOC_DMAC_CX_CONFIG_si_START 31
#define SOC_DMAC_CX_CONFIG_si_END 31

#define SI ((1) << SOC_DMAC_CX_CONFIG_si_START)
#define SIN ((0) << SOC_DMAC_CX_CONFIG_si_START)
#define DI ((1) << SOC_DMAC_CX_CONFIG_di_START)
#define DIN ((0) << SOC_DMAC_CX_CONFIG_di_START)
#define SMODE ((0) << SOC_DMAC_CX_CONFIG_smode_START)
#define DMODE ((0) << SOC_DMAC_CX_CONFIG_dmode_START)
#define SL ((0x0F) << SOC_DMAC_CX_CONFIG_sl_START)
#define SLN ((0x0) << SOC_DMAC_CX_CONFIG_sl_START)
#define DL ((0x0F) << SOC_DMAC_CX_CONFIG_dl_START)
#define SL3 ((0x03) << SOC_DMAC_CX_CONFIG_sl_START)
#define DL1 ((0x01) << SOC_DMAC_CX_CONFIG_dl_START)
#define SL1 ((0x01) << SOC_DMAC_CX_CONFIG_sl_START)
#define DLN ((0x0) << SOC_DMAC_CX_CONFIG_dl_START)
#define DL8 ((0x07) << SOC_DMAC_CX_CONFIG_dl_START)
#define SL8 ((0x07) << SOC_DMAC_CX_CONFIG_sl_START)
#define SW ((0x02) << SOC_DMAC_CX_CONFIG_sw_START)
#define DW ((0x02) << SOC_DMAC_CX_CONFIG_dw_START)
#define SW1 ((0x01) << SOC_DMAC_CX_CONFIG_sw_START)
#define DW1 ((0x01) << SOC_DMAC_CX_CONFIG_dw_START)
#define SW0 ((0x0) << SOC_DMAC_CX_CONFIG_sw_START)
#define DW0 ((0x0) << SOC_DMAC_CX_CONFIG_dw_START)
#define PERI_NUM ((0) << SOC_DMAC_CX_CONFIG_peri_START)
#define FLOW_CTRL ((0) << SOC_DMAC_CX_CONFIG_flow_ctrl_START)
#define FLOW_CTRLR ((1) << SOC_DMAC_CX_CONFIG_flow_ctrl_START)
#define FLOW_CTRLN ((2) << SOC_DMAC_CX_CONFIG_flow_ctrl_START)
#define ITC_EN ((0) << SOC_DMAC_CX_CONFIG_itc_en_START)
#define ITC_ENR ((1) << SOC_DMAC_CX_CONFIG_itc_en_START)
#define CH_EN_BIT BIT(SOC_DMAC_CX_CONFIG_ch_en_START)
#define CH_DISABLE 0

struct hisi_desc_hw {
	u32 lli;
	u32 reserved[3];
	u32 count;
	u32 saddr;
	u32 daddr;
	u32 config;
};

struct hisi_dma_desc_sw {
	u32 reserved[5];
	u32 desc_hw_lli;
	u32 desc_num;
	u32 size;
	struct hisi_desc_hw desc_hw[0];
};

struct hisi_dma_cfg_info {
	u32 channel;
	u32 src;
	u32 dst;
	u32 ccfg;
};

#define writel(val, addr)  \
	((*(volatile unsigned int *)((uintptr_t)(addr))) = (val))
#define readl(addr) (*(volatile unsigned int *)((uintptr_t)(addr)))

struct hisi_dma_list_info {
	void *tx_addr;
	void *rx_addr;
};

struct hisi_dma_list_info dma_list_info;

#define HISI_PRINT_FLAG 1

#if (HISI_PRINT_FLAG)
#define HISI_PRINT_ERROR uart_printf_func
#else
#define HISI_PRINT_ERROR(exp, ...)
#endif

int hisi_dma_config_check(void)
{
	u32 val;

	val = readl(REG_BASE_IOMCU_DMAC + INT_ERR1_RAW);
	if (val & DMA_CHAN_TX_RX) {
		HISI_PRINT_ERROR("hisi dma config error.\n");
		return -1;
	}
	return 0;
}

static void show_dma_chan_register(void)
{
	u32 val;
	u32 dma_chan_num;

	for (dma_chan_num = 0; dma_chan_num < DMA_CHAN_MAX; dma_chan_num++) {
		val = readl(REG_BASE_IOMCU_DMAC + dma_chan_num *
			CUR_CHAN_OFFSET + CX_CUR_CNT0);
		HISI_PRINT_ERROR("dma:chan%d CX_CUR_CNT0 = 0x%x\n",
			dma_chan_num, val);
		val = readl(REG_BASE_IOMCU_DMAC + dma_chan_num *
			CUR_CHAN_OFFSET + CX_CUR_CNT1);
		HISI_PRINT_ERROR("dma:chan%d CX_CUR_CNT1 = 0x%x\n",
			dma_chan_num, val);
		val = readl(REG_BASE_IOMCU_DMAC + dma_chan_num *
			CUR_CHAN_OFFSET + CX_CURR_SRC_ADDR);
		HISI_PRINT_ERROR("dma:chan%d CX_CURR_SRC_ADDR = 0x%x\n",
			dma_chan_num, val);
		val = readl(REG_BASE_IOMCU_DMAC + dma_chan_num *
			CUR_CHAN_OFFSET + CX_CURR_DES_ADDR);
		HISI_PRINT_ERROR("dma:chan%d CX_CURR_DES_ADDR = 0x%x\n",
			dma_chan_num, val);
		val = readl(REG_BASE_IOMCU_DMAC + dma_chan_num * CHAN_OFFSET +
			CX_SRC);
		HISI_PRINT_ERROR("dma:chan%d CX_SRC = 0x%x\n",
			dma_chan_num, val);
		val = readl(REG_BASE_IOMCU_DMAC + dma_chan_num * CHAN_OFFSET +
			CX_DST);
		HISI_PRINT_ERROR("dma:chan%d CX_DST = 0x%x\n",
			dma_chan_num, val);
		val = readl(REG_BASE_IOMCU_DMAC + dma_chan_num * CHAN_OFFSET +
			CX_CNT0);
		HISI_PRINT_ERROR("dma:chan%d CX_CNT0 = 0x%x\n",
			dma_chan_num, val);
		val = readl(REG_BASE_IOMCU_DMAC + dma_chan_num * CHAN_OFFSET +
			CX_CNT1);
		HISI_PRINT_ERROR("dma:chan%d CX_CNT1 = 0x%x\n",
			dma_chan_num, val);
		val = readl(REG_BASE_IOMCU_DMAC + dma_chan_num * CHAN_OFFSET +
			CX_CONFIG);
		HISI_PRINT_ERROR("dma:chan%d CX_CONFIG = 0x%x\n",
			dma_chan_num, val);
		val = readl(REG_BASE_IOMCU_DMAC + dma_chan_num * CHAN_OFFSET +
			CX_LLI);
		HISI_PRINT_ERROR("dma:chan%d CX_LLI = 0x%x\n",
			dma_chan_num, val);
	}
}

static void show_dma_common_register(void)
{
	u32 val;

	val = readl(REG_BASE_IOMCU_DMAC + INT_STAT);
	HISI_PRINT_ERROR("dma: INT_STAT = 0x%x\n", val);
	val = readl(REG_BASE_IOMCU_DMAC + INT_TC1_RAW);
	HISI_PRINT_ERROR("dma: INT_TC1_RAW = 0x%x\n", val);
	val = readl(REG_BASE_IOMCU_DMAC + INT_TC2_RAW);
	HISI_PRINT_ERROR("dma: INT_TC2_RAW = 0x%x\n", val);
	val = readl(REG_BASE_IOMCU_DMAC + INT_ERR1_RAW);
	HISI_PRINT_ERROR("dma: INT_ERR1_RAW = 0x%x\n", val);
	val = readl(REG_BASE_IOMCU_DMAC + INT_ERR2_RAW);
	HISI_PRINT_ERROR("dma: INT_ERR2_RAW = 0x%x\n", val);
	val = readl(REG_BASE_IOMCU_DMAC + INT_ERR3_RAW);
	HISI_PRINT_ERROR("dma: INT_ERR3_RAW = 0x%x\n", val);
	val = readl(REG_BASE_IOMCU_DMAC + CH_PRI);
	HISI_PRINT_ERROR("dma: CH_PRI = 0x%x\n", val);
	val = readl(REG_BASE_IOMCU_DMAC + CH_STAT);
	HISI_PRINT_ERROR("dma: CH_STAT = 0x%x\n", val);
}

static void show_dma_register(void)
{
	HISI_PRINT_ERROR("Show teeos dma register\n");
	show_dma_common_register();
	show_dma_chan_register();
}

int hisi_dma_process_status(void)
{
	u32 val1;
	u32 val2;
	u32 retry = 500000; /* 500ms */

	u32 stat = 0;

	while (!(stat & BIT(DMA_RX_CHANNEL)) && retry) {
		stat = readl(REG_BASE_IOMCU_DMAC + INT_TC1_RAW);
		stat |= readl(REG_BASE_IOMCU_DMAC + INT_ERR1_RAW);
		stat |= readl(REG_BASE_IOMCU_DMAC + INT_ERR2_RAW);
		stat |= readl(REG_BASE_IOMCU_DMAC + INT_ERR3_RAW);

		hisi_udelay(1);
		retry--;
	}

	if (retry == 0)
		HISI_PRINT_ERROR("hisi dma stat error.\n");

	val1 = readl(
		REG_BASE_IOMCU_DMAC + CX_CONFIG + CHAN_OFFSET * DMA_TX_CHANNEL);
	val2 = readl(
		REG_BASE_IOMCU_DMAC + CX_CONFIG + CHAN_OFFSET * DMA_RX_CHANNEL);
	if ((val1 & CH_EN_BIT) || (val2 & CH_EN_BIT)) {
		HISI_PRINT_ERROR("hisi dma transfer error.\n");
		show_dma_register();
		return -1;
	}
	return 0;
}

static void hisi_dma_enable_dma(u32 chip_addr, s32 on)
{
	u32 val;

	__asm__ volatile("isb");
	__asm__ volatile("dsb sy");
	if (on) {
		val = readl(
			chip_addr + DMA_RX_CHANNEL * CHAN_OFFSET + CX_CONFIG);
		val |= CH_EN_BIT;
		writel(val,
			chip_addr + DMA_RX_CHANNEL * CHAN_OFFSET + CX_CONFIG);
		val = readl(
			chip_addr + DMA_TX_CHANNEL * CHAN_OFFSET + CX_CONFIG);
		val |= CH_EN_BIT;
		writel(val,
			chip_addr + DMA_TX_CHANNEL * CHAN_OFFSET + CX_CONFIG);
	} else {
		writel(DMA_CHAN_TX_RX, chip_addr + INT_TC1_RAW);
		writel(DMA_CHAN_TX_RX, chip_addr + INT_ERR1_RAW);
		writel(DMA_CHAN_TX_RX, chip_addr + INT_ERR2_RAW);
		writel(DMA_CHAN_TX_RX, chip_addr + INT_ERR3_RAW);
		writel(CH_DISABLE,
			chip_addr + DMA_RX_CHANNEL * CHAN_OFFSET + CX_CONFIG);
		writel(CH_DISABLE,
			chip_addr + DMA_TX_CHANNEL * CHAN_OFFSET + CX_CONFIG);
	}
}

static void hisi_dma_set_desc(u32 chip_addr, u32 idx, struct hisi_desc_hw *hw)
{
	__asm__ volatile("isb");
	__asm__ volatile("dsb sy");
	if (idx == DMA_TX_CHANNEL)
		writel(DEF_AXI_CONFIG_TX,
			chip_addr + idx * CHAN_OFFSET + AXI_CONFIG);
	if (idx == DMA_RX_CHANNEL)
		writel(DEF_AXI_CONFIG_RX, chip_addr + idx * CHAN_OFFSET +
						  AXI_CONFIG);
	writel(hw->lli, chip_addr + idx * CHAN_OFFSET + CX_LLI);
	writel(hw->count, chip_addr + idx * CHAN_OFFSET + CX_CNT0);
	writel(hw->saddr, chip_addr + idx * CHAN_OFFSET + CX_SRC);
	writel(hw->daddr, chip_addr + idx * CHAN_OFFSET + CX_DST);
	writel(hw->config, chip_addr + idx * CHAN_OFFSET + CX_CONFIG);
}

static void hisi_dma_fill_desc(struct hisi_dma_desc_sw *ds, u32 dst, u32 src,
	u32 len, u32 num, u32 ccfg)
{
	if ((num + 1) < ds->desc_num)
		ds->desc_hw[num].lli = ds->desc_hw_lli +
			(num + 1) * sizeof(struct hisi_desc_hw);
	ds->desc_hw[num].lli |= CX_LLI_CHAIN_EN;
	ds->desc_hw[num].count = len;
	ds->desc_hw[num].reserved[0] = 0;
	ds->desc_hw[num].reserved[1] = 0;
	ds->desc_hw[num].reserved[2] = 0;
	ds->desc_hw[num].saddr = src;
	ds->desc_hw[num].daddr = dst;
	ds->desc_hw[num].config = ccfg;
}

static int hisi_dma_get_transfer_cfg(struct hisi_dma_des *dma_des,
	struct hisi_dma_cfg_info *dma_cfg_info)
{
	if (dma_des->dir == HISI_DMA_TX) {
		dma_cfg_info->channel = DMA_TX_CHANNEL;
		dma_cfg_info->src = (u32)virt_mem_to_phys((uintptr_t)dma_des->src);
		dma_cfg_info->dst = (uintptr_t)dma_des->dst;
		dma_cfg_info->ccfg = SI | DIN | SMODE | DMODE | SL | DL | SW0 |
			DW0 | (dma_des->req_no << 4) | FLOW_CTRLR | ITC_EN;
	} else if (dma_des->dir == HISI_DMA_RX) {
		dma_cfg_info->channel = DMA_RX_CHANNEL;
		dma_cfg_info->src = (uintptr_t)dma_des->src;
		dma_cfg_info->dst = (u32)virt_mem_to_phys((uintptr_t)dma_des->dst);
		dma_cfg_info->ccfg = SIN | DI | SMODE | DMODE | SL | DL | SW0 |
			DW0 | (dma_des->req_no << 4) | FLOW_CTRLR | ITC_EN;
	} else {
		HISI_PRINT_ERROR("%s dma_des->dir error!\n", __func__);
		return -1;
	}

	return 0;
}

static int hisi_dma_cfg_block_trans(struct hisi_dma_des *dma_des)
{
	int ret ;
	struct hisi_dma_desc_sw *ds = NULL;
	struct hisi_dma_cfg_info dma_cfg_info;

	ret = memset_s(&dma_cfg_info, sizeof(struct hisi_dma_cfg_info), 0x00,
			sizeof(struct hisi_dma_cfg_info));
	if (ret)
		HISI_PRINT_ERROR("%s memset_s failed\n", __func__);

	ret = hisi_dma_get_transfer_cfg(dma_des, &dma_cfg_info);
	if (ret) {
		HISI_PRINT_ERROR("%s get transfer cfg failed!\n", __func__);
		return -1;
	}

	ds = (struct hisi_dma_desc_sw *)SRE_MemAllocAlign(0,
		OS_MEM_DEFAULT_PTNUM,
		sizeof(*ds) + sizeof(struct hisi_desc_hw), 32);
	if (ds == NULL) {
		HISI_PRINT_ERROR(
			"%s fail to alloc buf for struct ds\n", __func__);
		return -1;
	}
	ds->desc_num = 1;
	hisi_dma_fill_desc(ds, dma_cfg_info.dst, dma_cfg_info.src,
		dma_des->len, 0, dma_cfg_info.ccfg);
	ds->desc_hw[0].lli = 0;
	hisi_dma_set_desc(REG_BASE_IOMCU_DMAC, dma_cfg_info.channel,
		&ds->desc_hw[0]);
	SRE_MemFree(OS_MID_MSG, ds);

	return 0;
}

static int hisi_dma_cfg_list_trans(struct hisi_dma_des *dma_des)
{
	int ret;
	u32 num, mem_len;
	u32 copy, src, dst, len;
	void *list_addr = NULL;
	struct hisi_dma_desc_sw *ds = NULL;
	struct hisi_dma_cfg_info dma_cfg_info;

	ret = memset_s(&dma_cfg_info, sizeof(struct hisi_dma_cfg_info), 0x00,
			sizeof(struct hisi_dma_cfg_info));
	if (ret)
		HISI_PRINT_ERROR("%s memset_s failed\n", __func__);

	ret = hisi_dma_get_transfer_cfg(dma_des, &dma_cfg_info);
	if (ret) {
		HISI_PRINT_ERROR("%s get transfer cfg failed!\n", __func__);
		return -1;
	}

	dst = dma_cfg_info.dst;
	src = dma_cfg_info.src;
	num = dma_des->len / DMA_LIST_MAX_SIZE + 1;
	len = dma_des->len;
	mem_len = sizeof(*ds) + (num + 1) * sizeof(struct hisi_desc_hw);
#ifdef CONFIG_SUPPORT_DMA_STATIC_ADDR
	if (mem_len >= HISI_DMA_MAX_STATIC_ADDR_SIZE - DMA_LIST_32_ALIGN) {
		HISI_PRINT_ERROR("%s static reserved memory is not enough!\n", __func__);
		return -1;
	}

	if (dma_des->dir == HISI_DMA_TX)
		ret = sre_mmap(HISI_RESERVED_FINGERPRINT_BASE +
			HISI_DMA_TX_STATIC_ADDR_OFFSET,
			HISI_DMA_MAX_STATIC_ADDR_SIZE,
			(unsigned int *)(&list_addr), secure, non_cache);
	else
		ret = sre_mmap(HISI_RESERVED_FINGERPRINT_BASE +
			HISI_DMA_RX_STATIC_ADDR_OFFSET,
			HISI_DMA_MAX_STATIC_ADDR_SIZE,
			(unsigned int *)(&list_addr), secure, non_cache);
	if (ret) {
		HISI_PRINT_ERROR("%s phy memory mmap failed!\n", __func__);
		return -1;
	}

	ds = (struct hisi_dma_desc_sw *)(((uintptr_t)list_addr + DMA_LIST_32_ALIGN)
		& (~DMA_LIST_32_ALIGN));
#else
	list_addr =  malloc_coherent(mem_len);

	if (list_addr == NULL) {
		HISI_PRINT_ERROR("%s fail to alloc buf!\n", __func__);
		return -1;
	}

	ds = (struct hisi_dma_desc_sw *)(((uintptr_t)list_addr + DMA_LIST_32_ALIGN)
		& (~DMA_LIST_32_ALIGN));
#endif
	if (dma_des->dir == HISI_DMA_TX)
		dma_list_info.tx_addr = list_addr;
	else
		dma_list_info.rx_addr = list_addr;

	ds->desc_hw_lli = virt_mem_to_phys((u32)(uintptr_t)&ds->desc_hw[0]);
	ds->size = dma_des->len;
	ds->desc_num = num;
	num = 0;

	do {
		copy = (len < (u32)DMA_LIST_MAX_SIZE ? len : (u32)DMA_LIST_MAX_SIZE);
		hisi_dma_fill_desc(ds, dst, src, copy, num, dma_cfg_info.ccfg);
		if (dma_des->dir == HISI_DMA_TX)
			src += copy;
		else
			dst += copy;
		len -= copy;
		num++;
	} while (len);

	ds->desc_hw[num - 1].lli = 0; /* end of link */
	hisi_dma_set_desc(REG_BASE_IOMCU_DMAC, dma_cfg_info.channel, &ds->desc_hw[0]);

	v7_dma_flush_range((uintptr_t)list_addr,
		(uintptr_t)(list_addr + mem_len));

	return 0;
}

int hisi_dma_config(struct hisi_dma_des *dma_des)
{
	int ret;

	if (dma_des == NULL) {
		HISI_PRINT_ERROR("%s hisi_dma_des is NULL!\n", __func__);
		return -1;
	}

	if (dma_des->len == 0) {
		HISI_PRINT_ERROR("%s len is zero!\n", __func__);
		return 0;
	}

	if (dma_des->len < DMA_BLOCK_MAX_SIZE) {
		ret = hisi_dma_cfg_block_trans(dma_des);
		return ret;
	}

	ret = hisi_dma_cfg_list_trans(dma_des);
	return ret;
}

#ifdef CONFIG_SUPPORT_DMA_MOD_QOS_LEVEL
static void hisi_mod_dma_rw_qos(unsigned int qos_level)
{
	unsigned int val;

	val = readl(SOC_IOMCU_NOC_CTRL_ADDR(SOC_ACPU_IOMCU_CONFIG_BASE_ADDR));
	if ((val & qos_level) != qos_level) {
		val |= qos_level;
		writel(val, SOC_IOMCU_NOC_CTRL_ADDR(SOC_ACPU_IOMCU_CONFIG_BASE_ADDR));
	}
}
#endif

int hisi_dma_init(void)
{
	if (DMA_HW_RES_LOCK_ID != INVALID_HW_RES_LOCK_ID) {
		if (hwspin_lock_timeout(DMA_HW_RES_LOCK_ID, WAITTIME_MAX)) {
			HISI_PRINT_ERROR("dma get hardware res lock failed!\n");
			return -1;
		}
	}

#ifdef CONFIG_SUPPORT_DMA_MOD_QOS_LEVEL
	hisi_mod_dma_rw_qos(HIGHEST_QOS_LEVEL_RW);
#endif
	return 0;
}

void hisi_dma_start(void)
{
	hisi_dma_enable_dma(REG_BASE_IOMCU_DMAC, TRUE);
}

void hisi_dma_exit(void)
{
	hisi_dma_enable_dma(REG_BASE_IOMCU_DMAC, FALSE);

	if (dma_list_info.tx_addr) {
#ifdef CONFIG_SUPPORT_DMA_STATIC_ADDR
		(void)sre_unmap((u32)(uintptr_t)dma_list_info.tx_addr,
			HISI_DMA_MAX_STATIC_ADDR_SIZE);
#else
		free(dma_list_info.tx_addr);
#endif
		dma_list_info.tx_addr = NULL;
	}

	if (dma_list_info.rx_addr) {
#ifdef CONFIG_SUPPORT_DMA_STATIC_ADDR
		(void)sre_unmap((u32)(uintptr_t)dma_list_info.rx_addr,
			HISI_DMA_MAX_STATIC_ADDR_SIZE);
#else
		free(dma_list_info.rx_addr);
#endif
		dma_list_info.rx_addr = NULL;
	}

	if (DMA_HW_RES_LOCK_ID != INVALID_HW_RES_LOCK_ID) {
		if (hwspin_unlock(DMA_HW_RES_LOCK_ID)) {
			HISI_PRINT_ERROR("%s release lock failed!\n", __func__);
		}
	}
}
