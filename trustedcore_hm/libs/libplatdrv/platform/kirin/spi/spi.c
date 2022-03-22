/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2020. All rights reserved.
 * Description: SPI core code
 * Create: 2018-5-21
 */

#include "spi.h"
#include "lib_timer.h"
#include "./../dma/dma.h"
#include "./../seccfg/hwspinlock.h"
#include "libhwsecurec/securec.h"
#include "sre_access_control.h"
#include "sre_syscalls_id_ext.h"
#include "lib_timer.h"
#include <gpio.h>
#include <hisi_debug.h>
#include <mem_page_ops.h>
#include <drv_cache_flush.h>
#include <drv_module.h>
#include <sre_sys.h>
#include <tzpc.h>

#if (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI3670)
#include "spi_config_kirin970.h"
#elif (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI6260)
#include "spi_config_kirin710.h"
#elif (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_MIAMICW)
#include "spi_config_kirin710.h"
#elif (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI3680)
#include "spi_config_kirin980.h"
#elif (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_KIRIN990)
#include "spi_config_kirin990.h"
#elif (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_ORLANDO)
#include "spi_config_orlando.h"
#elif (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_BALTIMORE)
#include "spi_config_baltimore.h"
#elif (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_DENVER)
#include "spi_config_denver.h"
#elif (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_LAGUNA)
#include "spi_config_laguna.h"
#elif (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_BURBANK)
#include "spi_config_burbank.h"
#else
#endif

#define SSP_WRITE_BITS(reg, val, mask, sb)                                     \
	((reg) = (((reg) & ~(mask)) | (((val) << (sb)) & (mask))))

#define GEN_MASK_BITS(val, mask, sb) (((val) << (sb)) & (mask))

#ifndef BIT
#define BIT(x) (1 << (x))
#endif

#define ERROR (-1)
#define OK 0

#define SPI_TZPC_ENABLE 1
#define SPI_TZPC_DISABLE 0

#define DRIVE_TX 0
#define DO_NOT_DRIVE_TX 1

#define SPI_POLLING_TIMEOUT 1000
#define SPI_CLK_RATE 96000000

// SSP DMA State - Whether DMA Enabled or Disabled
#define SSP_DMA_DISABLED 0
#define SSP_DMA_ENABLED 1

// SSP Clock Defaults
#define SSP_DEFAULT_CLKRATE 0x2
#define SSP_DEFAULT_PRESCALE 0x40

// SSP Interrupt related Macros
#define DEFAULT_SSP_REG_IMSC 0x0UL
#define DISABLE_ALL_INTERRUPTS DEFAULT_SSP_REG_IMSC

#define CLEAR_ALL_INTERRUPTS 0x3

#define GT_CLK_SPI0 (1 << 8)
#define GT_CLK_SPI1 (1 << 9)

#define SSP_SR_MASK_TFE (0x1UL << 0)
#define SSP_SR_MASK_BSY (0x1UL << 4) /* Busy Flag */

#define REG_IOMG53 (REG_BASE_AO_IOC + 0x0D4)
#define REG_IOMG54 (REG_BASE_AO_IOC + 0x0D8)
#define REG_IOMG55 (REG_BASE_AO_IOC + 0x0DC)
#define REG_IOMG56 (REG_BASE_AO_IOC + 0x0E0)
#define REG_IOMG57 (REG_BASE_AO_IOC + 0x0E4)

#define REG_IOMG98 (REG_BASE_AO_IOC + 0x184)
#define REG_IOMG58 (REG_BASE_AO_IOC + 0x0E8)
#define REG_IOMG95 (REG_BASE_AO_IOC + 0x0EC)

// Macros to access SSP Registers with their offsets
#define SSP_CR0(r) (r + 0x000)
#define SSP_CR1(r) (r + 0x004)
#define SSP_DR(r) (r + 0x008)
#define SSP_SR(r) (r + 0x00C)
#define SSP_CPSR(r) (r + 0x010)
#define SSP_IMSC(r) (r + 0x014)
#define SSP_RIS(r) (r + 0x018)
#define SSP_MIS(r) (r + 0x01C)
#define SSP_ICR(r) (r + 0x020)
#define SSP_DMACR(r) (r + 0x024)
#define SSP_TXFIFOCR(r) (r + 0x028)
#define SSP_RXFIFOCR(r) (r + 0x02C)
// SSP State - Whether Enabled or Disabled
#define SSP_DISABLED 0
#define SSP_ENABLED 1

// SSP Clock Parameter ranges
#define CPSDVR_MIN 0x02
#define CPSDVR_MAX 0xFE
#define SCR_MIN 0x00
#define SCR_MAX 0xFF

// SSP Control Register 0  - SSP_CR0
#define SSP_CR0_MASK_DSS (0x0FUL << 0)
#define SSP_CR0_MASK_FRF (0x3UL << 4)
#define SSP_CR0_MASK_SPO (0x1UL << 6)
#define SSP_CR0_MASK_SPH (0x1UL << 7)
#define SSP_CR0_MASK_SCR (0xFFUL << 8)

// SSP Control Register 0  - SSP_CR1
#define SSP_CR1_MASK_LBM (0x1UL << 0)
#define SSP_CR1_MASK_SSE (0x1UL << 1)
#define SSP_CR1_MASK_MS (0x1UL << 2)
#define SSP_CR1_MASK_SOD (0x1UL << 3)

#define SSP_SR_MASK_RNE (0x1UL << 2) /* Receive FIFO not empty */
#define SSP_SR_MASK_BSY (0x1UL << 4) /* Busy Flag */

// SSP Clock Prescale Register  - SSP_CPSR
#define SSP_CPSR_MASK_CPSDVSR (0xFFUL << 0)

// SSP DMA Control Register - SSP_DMACR
#define SSP_DMACR_MASK_RXDMAE (0x1UL << 0) /* Receive DMA Enable bit */
#define SSP_DMACR_MASK_TXDMAE (0x1UL << 1) /* Transmit DMA Enable bit */

// SSP TX FIFO Register - SSP_TXFIFOCR
#define SSP_TXFIFOCR_MASK_DMA (0x07UL << 0)
#define SSP_TXFIFOCR_MASK_INT (0x3UL << 3)

// SSP RX FIFO Register - SSP_TXFIFOCR
#define SSP_RXFIFOCR_MASK_DMA (0x07UL << 0)
#define SSP_RXFIFOCR_MASK_INT (0x3UL << 3)

#define FIFO_DEPTH 256
#define SEC_SPI 0
#define UNSEC_SPI 1

#define CLK_GATE_HIGH_BIT_MASK(sb)    (0x1UL << ((sb) + 16))

#define SPI_CLK_ENABLE 1
#define SPI_CLK_DISABLE 0

#define SPI_CLK_TIMEOUT 10
#define SPI_RESET_CONTROLLER_TIMEOUT 10

#define SPI_RX_FIFO_CONFIG (BIT(1) | BIT(0))
#define SPI_TX_FIFO_CONFIG (BIT(1) | BIT(0))
#define SPI_DMA_ENABLE_TRANSFER (BIT(1) | BIT(0))

#define SPI_DMA_ENABLE 1
#define SPI_DMA_DISABLE 0

#define SPI_RETRY_TIMES 500000
#define FLUSH_LIMIT 10000

enum ssp_interface {
	SSP_INTERFACE_MOTOROLA_SPI,
	SSP_INTERFACE_TI_SYNC_SERIAL,
	SSP_INTERFACE_NATIONAL_MICROWIRE,
	SSP_INTERFACE_UNIDIRECTIONAL
};

// Default SSP Register Values
#define DEFAULT_SSP_REG_CR0                                                    \
	(GEN_MASK_BITS(SSP_DATA_BITS_12, SSP_CR0_MASK_DSS, 0) |                \
		GEN_MASK_BITS(                                                 \
			SSP_INTERFACE_MOTOROLA_SPI, SSP_CR0_MASK_FRF, 4) |     \
		GEN_MASK_BITS(SSP_CLK_POL_IDLE_LOW, SSP_CR0_MASK_SPO, 6) |     \
		GEN_MASK_BITS(SSP_CLK_SECOND_EDGE, SSP_CR0_MASK_SPH, 7) |      \
		GEN_MASK_BITS(SSP_DEFAULT_CLKRATE, SSP_CR0_MASK_SCR, 8))
#define DEFAULT_SSP_REG_CR1                                                    \
	(GEN_MASK_BITS(LOOPBACK_DISABLED, SSP_CR1_MASK_LBM, 0) |               \
		GEN_MASK_BITS(SSP_DISABLED, SSP_CR1_MASK_SSE, 1) |             \
		GEN_MASK_BITS(SSP_MASTER, SSP_CR1_MASK_MS, 2) |                \
		GEN_MASK_BITS(DO_NOT_DRIVE_TX, SSP_CR1_MASK_SOD, 3))
#define DEFAULT_SSP_REG_DMACR                                                  \
	(GEN_MASK_BITS(SSP_DMA_DISABLED, SSP_DMACR_MASK_RXDMAE, 0) |           \
		GEN_MASK_BITS(SSP_DMA_DISABLED, SSP_DMACR_MASK_TXDMAE, 1))
#define DEFAULT_SSP_REG_CPSR                                                   \
	(GEN_MASK_BITS(SSP_DEFAULT_PRESCALE, SSP_CPSR_MASK_CPSDVSR, 0))

#define DEFAULT_SSP_REG_TXFIFOCR                                               \
	(GEN_MASK_BITS(                                                        \
		 SSP_TX_16_OR_MORE_EMPTY_LOC, SSP_TXFIFOCR_MASK_DMA, 0) |      \
		GEN_MASK_BITS(SSP_TX_16_OR_MORE_EMPTY_LOC,                     \
			SSP_TXFIFOCR_MASK_INT, 3))

#define DEFAULT_SSP_REG_RXFIFOCR                                               \
	(GEN_MASK_BITS(SSP_RX_16_OR_MORE_ELEM, SSP_RXFIFOCR_MASK_DMA, 0) |     \
		GEN_MASK_BITS(                                                 \
			SSP_RX_16_OR_MORE_ELEM, SSP_RXFIFOCR_MASK_INT, 3))

#define BUFFER_LEN 512

#define UNUSED(a) (a = a)


#define MAX_SPEED_HZ	5000000

#define BITS_PER_WORD_3		3
#define BITS_PER_WORD_8		8
#define BITS_PER_WORD_16	16

enum ssp_bytes {
	BYTE_NULL,
	BYTE_1,
	BYTE_2,
};

// The type of reading going on on this chip
enum ssp_reading {
	READING_NULL,
	READING_U8,
	READING_U16,
};

// The type of writing going on on this chip
enum ssp_writing { WRITING_NULL, WRITING_U8, WRITING_U16 };

struct crc_data {
	u32 cr0;
	u16 cr1;
	u16 dmacr;
	u16 cpsr;
	u8 n_bytes;
};

struct chip_data {
	struct crc_data crc;
	enum ssp_reading read;
	enum ssp_writing write;
	void (*cs_control)(u32 command);
};

struct pl022_data {
	void *tx;
	void *tx_end;
	void *rx;
	void *rx_end;
};

struct pl022 {
	struct spi_transfer *cur_transfer;
	struct chip_data *cur_chip;
	struct pl022_data data;
	enum ssp_reading read;
	enum ssp_writing write;
	u32 exp_fifo_level;
};

#define CHIP_ARRAY_SIZE 5
struct chip_data cur_chip[CHIP_ARRAY_SIZE];

static int get_chip_array_id(const u32 chip_addr)
{
	u32 i, max;

	max = sizeof(spi_res) / sizeof(struct spi_resource);

	for (i = 0; i < max; i++) {
		if (spi_res[i].base == chip_addr)
			return i;
	}

	HISI_PRINT_ERROR("spi chip addr is error: 0x%x.\n", chip_addr);
	return -SPI_ERR;
}

void null_cs_control(unsigned int value)
{
	UNUSED(value);
}

static const struct spi_config_chip pl022_default_chip_info = {
	.hierarchy = SSP_SLAVE,
	.slave_tx_disable = DO_NOT_DRIVE_TX,
	.cs_control = null_cs_control,
};

static struct spi_resource *get_resource_info(const u32 chip_addr)
{
	u32 max, i;

	max = sizeof(spi_res) / sizeof(struct spi_resource);

	for (i = 0; i < max; i++) {
		if (spi_res[i].base == chip_addr) {
			HISI_PRINT_DEBUG(
				"spi bus-id is %d.\n", spi_res[i].bus_id);
			return &spi_res[i];
		}
	}

	HISI_PRINT_ERROR("no spi resource, base is 0x%x\n", chip_addr);
	return NULL;
}

static int set_tzpc_iomcu_domain(struct spi_resource *sr, u32 value)
{
	u32 data;

	data = hisi_readl(
		sr->tzpc_data.tzpc_info.addr + sr->tzpc_data.tzpc_info.offset);
	data &= ~(1 << sr->tzpc_data.tzpc_info.mask_bit);
	data |= value << sr->tzpc_data.tzpc_info.mask_bit;

	hisi_writel(
		data, sr->tzpc_data.tzpc_info.addr +
			      sr->tzpc_data.tzpc_info.offset);

	HISI_PRINT_DEBUG("spi bus[%d] set tzpc succ\n", sr->bus_id);

	return SPI_OK;
}

static inline int set_tzpc_ap_domain(struct spi_resource *sr, u32 value)
{
	return tzpc_cfg(sr->tzpc_data.tzpc_map.tzpc_idx, value);
}

static int spi_tzpc_cfg(const u32 chip_addr, s32 value)
{
	struct spi_resource *sr = NULL;
	int ret;

	sr = get_resource_info(chip_addr);
	if (sr == NULL)
		return -SPI_ERR;

	if (sr->tzpc_flag == NO_NEED_SWITCH_SEC_FLAG) {
		HISI_PRINT_DEBUG("spi bus-%d, no need to set sec property\n",
			sr->bus_id);
		return SPI_OK;
	}

	switch (sr->domain) {
	case SPI_AP_DOMAIN:
		ret = set_tzpc_ap_domain(sr, (u32)value);
		break;
	case SPI_IOMCU_DOMAIN:
		ret = set_tzpc_iomcu_domain(sr, (u32)value);
		break;
	default:
		HISI_PRINT_ERROR("spi bus[%d], pelse check domain[%d]\n",
			sr->bus_id, sr->domain);
		ret = -SPI_ERR;
		break;
	}

	return ret;
}

static void spi_open_clk(struct spi_resource *sr)
{
	u32 timeout = 0;

	/* If clk div gate cfg exist, then enable clk div gate */
	if (sr->reg_clk_gate_enable)
		hisi_writel(BIT(sr->spi_clk_gate_bit) |
			CLK_GATE_HIGH_BIT_MASK(sr->spi_clk_gate_bit),
			sr->reg_clk_gate_enable);

	/* If clk cfg exist, then enable spi controller clk */
	if (sr->reg_clk_enable) {
		hisi_writel(BIT(sr->spi_clk_bit), sr->reg_clk_enable);
		while (!(BIT(sr->spi_clk_bit) &
			hisi_readl(sr->reg_clk_status)) &&
			(timeout < SPI_CLK_TIMEOUT))
			timeout++;

		if (timeout == SPI_CLK_TIMEOUT)
			HISI_PRINT_ERROR("spi bus[%d] : enable clk time out!\n",
				sr->bus_id);
	}
}

static void spi_close_clk(struct spi_resource *sr)
{
	/* If clk cfg exist, then disable spi controller clk */
	if (sr->reg_clk_disable)
		hisi_writel(BIT(sr->spi_clk_bit), sr->reg_clk_disable);

	/* If clk div gate cfg exist, then disable clk div gate */
	if (sr->reg_clk_gate_enable)
		hisi_writel(
			CLK_GATE_HIGH_BIT_MASK(sr->spi_clk_gate_bit),
			sr->reg_clk_gate_enable);
}

static void spi_clk_enable(const u32 chip_addr, u32 enable)
{
	struct spi_resource *sr = NULL;

	sr = get_resource_info(chip_addr);
	if (sr == NULL) {
		HISI_PRINT_ERROR(
			"get spi resource fail,in func:%s\n", __func__);
		return;
	}

	if (enable)
		spi_open_clk(sr);
	else
		spi_close_clk(sr);
}

static void spi_reset_controller(const u32 chip_addr)
{
	u32 timeout = SPI_RESET_CONTROLLER_TIMEOUT;
	u32 stat;
	struct spi_resource *sr = NULL;

	sr = get_resource_info(chip_addr);
	if (sr == NULL) {
		HISI_PRINT_ERROR(
			"get spi resource fail,in func:%s\n", __func__);
		return;
	}

	hisi_writel(
		BIT(sr->spi_reset_bit), sr->reg_reset_enable);
	stat = hisi_readl(sr->reg_reset_status) &
	       BIT(sr->spi_reset_bit);

	while (!stat && timeout) {
		hisi_udelay(1);
		stat = hisi_readl(sr->reg_reset_status) &
		       BIT(sr->spi_reset_bit);
		timeout--;
	}
	if (!stat && !timeout) {
		HISI_PRINT_ERROR(
			"spi bus[%d]  reset: enable failed(s=%d, t=%d).\n",
			sr->bus_id, stat, timeout);
	}

	hisi_udelay(1);

	timeout = SPI_RESET_CONTROLLER_TIMEOUT;
	hisi_writel(
		BIT(sr->spi_reset_bit), sr->reg_reset_disable);
	stat = hisi_readl(sr->reg_reset_status) &
	       BIT(sr->spi_reset_bit);
	while (stat && timeout) {
		hisi_udelay(1);
		stat = hisi_readl(sr->reg_reset_status) &
		       BIT(sr->spi_reset_bit);
		timeout--;
	}
	if (stat && !timeout) {
		HISI_PRINT_ERROR(
			"spi bus[%d] reset: disable failed(s=%d, t=%d).\n",
			sr->bus_id, stat, timeout);
	}
}

static s32 get_clk_rate(const u32 chip_addr)
{
	struct spi_resource *sr = NULL;

	sr = get_resource_info(chip_addr);
	if (sr == NULL)
		return -SPI_ERR;

	HISI_PRINT_DEBUG(
		"spi bus[%d] clk rate is %d Hz\n", sr->bus_id, sr->clk_rate);

	return (s32)sr->clk_rate;
}

static inline void set_spi_gpio_status(
	struct gpio_spi_cfg_status *gscs, u8 status)
{
	int i;

	for (i = 0; i < SPI_GPIO_MAX_NUM; i++)
		gpio_set_mode(gscs[i].gpio, gscs[i].function[status]);
}

static s32 spi_cfg_gpio(u32 chip_addr, s32 value)
{
	struct spi_resource *sr = NULL;

	sr = get_resource_info(chip_addr);
	if (sr == NULL)
		return -SPI_ERR;

	if (value == SPI_TRUE)
		set_spi_gpio_status(sr->gpios, SPI_GPIO_CFG_DEFAULT);
	else
		set_spi_gpio_status(sr->gpios, SPI_GPIO_CFG_IDLE);

	HISI_PRINT_DEBUG("spi bus[%d] set gpio succ\n", sr->bus_id);

	return SPI_OK;
}

static int get_hdres_lock(const u32 chip_addr)
{
	int val = 0;
	struct spi_resource *sr = NULL;
	u32 timeout = TIMEOUT_LOCAL;

	sr = get_resource_info(chip_addr);
	if (sr == NULL)
		return -SPI_ERR;

	if (!sr->spi_hw.hw_valid)
		return SPI_OK;

	do {
		hisi_udelay(10);

		val = hwspin_lock_timeout(sr->spi_hw.lock_id, 0);

	} while ((val != 0) && (--timeout));

	if (!timeout) {
		HISI_PRINT_ERROR("TEE get source 0x%x timeout\n",
				sr->spi_hw.lock_id);
		return -SPI_ERR;
	}
	HISI_PRINT_DEBUG("TEE get spi hardware source 0x%x\n",
			sr->spi_hw.lock_id);

	return SPI_OK;
}

static void put_hdres_lock(const u32 chip_addr)
{
	struct spi_resource *sr = NULL;

	sr = get_resource_info(chip_addr);
	if (sr == NULL)
		return;

	if (!sr->spi_hw.hw_valid)
		return;

	if (hwspin_unlock(sr->spi_hw.lock_id)) {
		HISI_PRINT_ERROR("TEE put spi hardware source 0x%x error\n",
				sr->spi_hw.lock_id);
		return;
	}
}

static void load_ssp_default_config(const u32 chip_addr)
{
	hisi_writel(
		DEFAULT_SSP_REG_CR0, SSP_CR0(chip_addr));
	hisi_writel(
		DEFAULT_SSP_REG_CR1, SSP_CR1(chip_addr));
	hisi_writel(DEFAULT_SSP_REG_DMACR,
		SSP_DMACR(chip_addr));
	hisi_writel(DEFAULT_SSP_REG_CPSR, SSP_CPSR(chip_addr));
	hisi_writel(DISABLE_ALL_INTERRUPTS, SSP_IMSC(chip_addr));
	hisi_writel(CLEAR_ALL_INTERRUPTS, SSP_ICR(chip_addr));
}

static int calculate_effective_freq(
	u32 freq, struct ssp_clock_params *clk_freq, const u32 chip_addr)
{
	/* Lets calculate the frequency parameters */
	u32 rate, max_tclk, min_tclk;
	u16 cpsdvsr = 2;
	u16 scr = SCR_MIN;
	u8 freq_found = 0;

	rate = (u32)get_clk_rate(chip_addr);
	HISI_PRINT_DEBUG("rate:[%u]\n", rate);
	/* cpsdvscr = 2 & scr 0 */
	max_tclk = (rate / (CPSDVR_MIN * (1 + SCR_MIN)));
	/* cpsdvsr = 254 & scr = 255 */
	min_tclk = (rate / (CPSDVR_MAX * (1 + SCR_MAX)));

	if ((freq > max_tclk) || (freq < min_tclk)) {
		HISI_PRINT_ERROR(
			"controller data is incorrect, rate:%u max:%u min:%u\n",
			rate, max_tclk, min_tclk);
		return -SPI_ERR;
	}

	while (cpsdvsr <= CPSDVR_MAX && !freq_found) {
		while (scr <= SCR_MAX && !freq_found) {
			if ((rate / (cpsdvsr * (1 + scr))) > freq)
				scr += 1;
			else {
				/*
				 * This bool is made true when
				 * effective frequency >=
				 * target frequency is found
				 */
				freq_found = 1;
				if (((rate / (cpsdvsr * (1 + scr))) != freq) &&
					(scr == SCR_MIN)) {
					cpsdvsr -= 2;
					scr = SCR_MAX;
				}
			}
		}

		if (!freq_found) {
			cpsdvsr += 2;
			scr = SCR_MIN;
		}
	}

	if (cpsdvsr != 0) {
		clk_freq->cpsdvsr = (u8)(cpsdvsr & 0xFF);
		clk_freq->scr = (u8)(scr & 0xFF);
	}

	return SPI_OK;
}

static int verify_controller_parameters(struct spi_config_chip const *chip_info)
{
	if ((chip_info->hierarchy != SSP_MASTER) &&
		(chip_info->hierarchy != SSP_SLAVE)) {
		HISI_PRINT_ERROR("%s hierarchy err\n", __func__);
		return -SPI_ERR;
	}

	return SPI_OK;
}

static int hisi_spi_config(struct chip_data *chip, struct spi_device *spi,
	struct spi_config_chip const *chip_info,
	struct ssp_clock_params *clk_freq)
{
	unsigned int bits = spi->bits_per_word;
	u32 tmp;

	if (!chip_info->cs_control)
		chip->cs_control = null_cs_control;
	else
		chip->cs_control = chip_info->cs_control;

	if (bits <= BITS_PER_WORD_3) {
		/* PL022 doesn't support less than 4-bits */
		return -SPI_ERR;
	} else if (bits <= BITS_PER_WORD_8) {
		chip->crc.n_bytes = BYTE_1;
		chip->read = READING_U8;
		chip->write = WRITING_U8;
	} else if (bits <= BITS_PER_WORD_16) {
		chip->crc.n_bytes = BYTE_2;
		chip->read = READING_U16;
		chip->write = WRITING_U16;
	} else {
		HISI_PRINT_DEBUG(" n >= 16 bits per word\n");
		return -SPI_ERR;
	}

	chip->crc.cr0 = 0;
	chip->crc.cr1 = 0;
	chip->crc.dmacr = 0;
	chip->crc.cpsr = 0;
	SSP_WRITE_BITS(chip->crc.dmacr, SSP_DMA_DISABLED, SSP_DMACR_MASK_RXDMAE,
		0);
	SSP_WRITE_BITS(chip->crc.dmacr, SSP_DMA_DISABLED, SSP_DMACR_MASK_TXDMAE,
		1);
	chip->crc.cpsr = clk_freq->cpsdvsr;
	SSP_WRITE_BITS(chip->crc.cr0, bits - 1, SSP_CR0_MASK_DSS, 0);
	SSP_WRITE_BITS(chip->crc.cr0, SSP_INTERFACE_MOTOROLA_SPI,
		SSP_CR0_MASK_FRF, 4);

	if (spi->mode & SPI_CPOL)
		tmp = SSP_CLK_POL_IDLE_HIGH;
	else
		tmp = SSP_CLK_POL_IDLE_LOW;
	SSP_WRITE_BITS(chip->crc.cr0, tmp, SSP_CR0_MASK_SPO, 6);

	if (spi->mode & SPI_CPHA)
		tmp = SSP_CLK_SECOND_EDGE;
	else
		tmp = SSP_CLK_FIRST_EDGE;
	SSP_WRITE_BITS(chip->crc.cr0, tmp, SSP_CR0_MASK_SPH, 7);
	SSP_WRITE_BITS(chip->crc.cr0, clk_freq->scr, SSP_CR0_MASK_SCR, 8);

	if (spi->mode & SPI_LOOP)
		tmp = LOOPBACK_ENABLED;
	else
		tmp = LOOPBACK_DISABLED;
	SSP_WRITE_BITS(chip->crc.cr1, tmp, SSP_CR1_MASK_LBM, 0);
	SSP_WRITE_BITS(chip->crc.cr1, SSP_DISABLED, SSP_CR1_MASK_SSE, 1);
	SSP_WRITE_BITS(chip->crc.cr1,
		(unsigned int)chip_info->hierarchy, SSP_CR1_MASK_MS, 2);
	SSP_WRITE_BITS(chip->crc.cr1, (unsigned int)chip_info->slave_tx_disable,
		SSP_CR1_MASK_SOD, 3);

	return SPI_OK;
}

static int hisi_spi_setup(
	struct spi_device *spi, struct chip_data *chip, const u32 chip_addr)
{
	struct spi_config_chip const *chip_info = NULL;
	struct ssp_clock_params clk_freq;
	int status;
	int ret;

	if (!spi->max_speed_hz) {
		HISI_PRINT_ERROR(
			"%s MAX SPEED HZ is zero\n", __func__);
		return -SPI_ERR;
	}

	chip_info = spi->controller_data;
	if (chip_info == NULL)
		chip_info = &pl022_default_chip_info;

	if ((chip_info->clk_freq.cpsdvsr == 0) &&
		(chip_info->clk_freq.scr == 0)) {
		status = calculate_effective_freq(
			spi->max_speed_hz, &clk_freq, chip_addr);
		if (status < 0)
			return -SPI_ERR;
	} else {
		ret = memcpy_s(&clk_freq, sizeof(clk_freq),
			&chip_info->clk_freq, sizeof(chip_info->clk_freq));
		if (ret) {
			HISI_PRINT_ERROR("memcpy_s error: ret=[%d]\n", ret);
			return -SPI_ERR;
		}
		if ((clk_freq.cpsdvsr % CPSDVR_MIN) != 0)
			clk_freq.cpsdvsr = clk_freq.cpsdvsr - 1;
	}
	if ((clk_freq.cpsdvsr < CPSDVR_MIN) ||
			(clk_freq.cpsdvsr > CPSDVR_MAX)) {
		HISI_PRINT_ERROR("cpsdvsr is configured incorrectly\n");
		return -SPI_ERR;
	}

	status = verify_controller_parameters(chip_info);
	if (status) {
		HISI_PRINT_ERROR("verity controller param fail\n");
		return -SPI_ERR;
	}

	status = hisi_spi_config(chip, spi, chip_info, &clk_freq);
	if (status) {
		HISI_PRINT_ERROR("spi config err\n");
		return -SPI_ERR;
	}

	return SPI_OK;
}

static void spi_chip_config(const u32 chip_addr, struct chip_data *chip)
{
	hisi_writel(chip->crc.cr0, SSP_CR0(chip_addr));
	hisi_writel(chip->crc.cr1, SSP_CR1(chip_addr));
	hisi_writel(chip->crc.dmacr, SSP_DMACR(chip_addr));
	hisi_writel(chip->crc.cpsr, SSP_CPSR(chip_addr));
	hisi_writel(DISABLE_ALL_INTERRUPTS, SSP_IMSC(chip_addr));
	hisi_writel(CLEAR_ALL_INTERRUPTS, SSP_ICR(chip_addr));
	hisi_writel(DEFAULT_SSP_REG_TXFIFOCR,
		SSP_TXFIFOCR(chip_addr));
	hisi_writel(DEFAULT_SSP_REG_RXFIFOCR,
		SSP_RXFIFOCR(chip_addr));
}

static void flush(const u32 chip_addr, struct pl022 *pl022)
{
	u32 limit = FLUSH_LIMIT;
	u32 retry = SPI_RETRY_TIMES; /* 500ms */

	do {
		while ((hisi_readl(SSP_SR(chip_addr)) & SSP_SR_MASK_RNE) &&
			(retry)) {
			hisi_readl(SSP_DR(chip_addr));

			retry--;
		}
		if (!retry)
			HISI_PRINT_ERROR("RNE!\n");

	} while ((hisi_readl(SSP_SR(chip_addr)) & SSP_SR_MASK_BSY) &&
		(--limit));

	if (!limit)
		HISI_PRINT_ERROR("BSY!\n");

	pl022->exp_fifo_level = 0;
}

static int set_up_next_transfer(
	struct pl022 *pl022, struct spi_transfer *transfer)
{
	int residue;

	/* Sanity check the message for this bus width */
	residue = pl022->cur_transfer->len % pl022->cur_chip->crc.n_bytes;
	if (residue != 0) {
		HISI_PRINT_ERROR("%s len [%d], n_bytes[%d]\n", __func__,
			pl022->cur_transfer->len,
			pl022->cur_chip->crc.n_bytes);
		return -SPI_ERR;
	}

	pl022->data.tx = (void *)transfer->tx_buf;
	pl022->data.tx_end = pl022->data.tx + pl022->cur_transfer->len;
	pl022->data.rx = (void *)transfer->rx_buf;
	pl022->data.rx_end = pl022->data.rx + pl022->cur_transfer->len;
	pl022->write = pl022->data.tx ? pl022->cur_chip->write : WRITING_NULL;
	pl022->read = pl022->data.rx ? pl022->cur_chip->read : READING_NULL;
	return SPI_OK;
}

static int hisi_spi_read_rx(const u32 chip_addr,
	struct pl022 *pl022)
{
	u32 retry = SPI_RETRY_TIMES;

	while (((hisi_readl(SSP_SR(chip_addr)) & SSP_SR_MASK_RNE) &&
		(pl022->data.rx < pl022->data.rx_end)) && retry) {
		switch (pl022->read) {
		case READING_NULL:
			hisi_readl(SSP_DR(chip_addr));
			break;
		case READING_U8:
			*(u8 *)(pl022->data.rx) =
				(u8)hisi_readl(SSP_DR(chip_addr));
			break;
		case READING_U16:
			*(u16 *)(pl022->data.rx) =
				(u16)hisi_readl(SSP_DR(chip_addr));
			break;
		default:
			HISI_PRINT_ERROR("mask rne default err\n");
			break;
		}
		pl022->data.rx += (pl022->cur_chip->crc.n_bytes);
		pl022->exp_fifo_level--;

		retry--;
	}

	if (!retry) {
		HISI_PRINT_ERROR("spi hisi_spi_read_rx err\n");
		return -SPI_ERR;
	}

	return SPI_OK;
}
static int hisi_spi_write_rx(const u32 chip_addr, struct pl022 *pl022)
{
	u32 retry;
	int ret;

	retry = SPI_RETRY_TIMES;
	while (((pl022->exp_fifo_level < FIFO_DEPTH) &&
		(pl022->data.tx < pl022->data.tx_end)) && retry) {
		switch (pl022->write) {
		case WRITING_NULL:
			hisi_writel(0x0, SSP_DR(chip_addr));
			break;
		case WRITING_U8:
			hisi_writel(*(u8 *)(pl022->data.tx), SSP_DR(chip_addr));
			break;
		case WRITING_U16:
			hisi_writel((*(u16 *)(pl022->data.tx)),
				SSP_DR(chip_addr));
			break;
		default:
			HISI_PRINT_ERROR("depth default err\n");
			break;
		}
		pl022->data.tx += (pl022->cur_chip->crc.n_bytes);
		pl022->exp_fifo_level++;
		/*
		 * This inner reader takes care of things appearing in the RX
		 * FIFO as we're transmitting. This will happen a lot since the
		 * clock starts running when you put things into the TX FIFO,
		 * and then things are continuously clocked into the RX FIFO.
		 */
		ret = hisi_spi_read_rx(chip_addr, pl022);
		if (ret)
			HISI_PRINT_ERROR("spi mask rne err\n");

		retry--;
	}

	if (!retry) {
		HISI_PRINT_ERROR("spi fifo depth err\n");
		return -SPI_ERR;
	}
	return SPI_OK;
}

static int readwriter(const u32 chip_addr, struct pl022 *pl022)
{
	u32 retry;
	int ret;

	retry = SPI_RETRY_TIMES;
	/* wait until spi is free */
	while (((hisi_readl(SSP_SR(chip_addr))) & SSP_SR_MASK_BSY) && retry) {
		hisi_udelay(1);
		retry--;
	}
	if (!retry) {
		HISI_PRINT_ERROR("spi mask bsy err\n");
		return -SPI_ERR;
	}

	ret = hisi_spi_read_rx(chip_addr, pl022);
	if (ret) {
		HISI_PRINT_ERROR("spi mask rne err\n");
		return -SPI_ERR;
	}

	if (hisi_spi_write_rx(chip_addr, pl022) == -SPI_ERR) {
		HISI_PRINT_ERROR("spi hisi_spi_write_rx err\n");
		return -SPI_ERR;
	}

	return SPI_OK;
}

static int hisi_spi_dma_parse_des(const u32 chip_addr, struct pl022 *pl022,
	struct hisi_dma_des *dma_rx_des, struct hisi_dma_des *dma_tx_des)
{
	struct spi_resource *sr = NULL;

	sr = get_resource_info(chip_addr);
	if (sr == NULL) {
		HISI_PRINT_ERROR("spi can't get resource.\n");
		return -SPI_ERR;
	}

	if (pl022->cur_transfer->rx_buf) {
		dma_rx_des->dir = HISI_DMA_RX;
		dma_rx_des->src = (void *)(uintptr_t)SSP_DR(chip_addr);
		dma_rx_des->dst = pl022->cur_transfer->rx_buf;
		dma_rx_des->len = pl022->cur_transfer->len;
		dma_rx_des->req_no = sr->spi_req_no.rx_req_no;
		v7_dma_flush_range((uintptr_t)dma_rx_des->dst,
			(uintptr_t)(dma_rx_des->dst + dma_rx_des->len));
	}
	if (pl022->cur_transfer->tx_buf) {
		dma_tx_des->dir = HISI_DMA_TX;
		dma_tx_des->src = (void *)(pl022->cur_transfer->tx_buf);
		dma_tx_des->dst = (void *)(uintptr_t)SSP_DR(chip_addr);
		dma_tx_des->len = pl022->cur_transfer->len;
		dma_tx_des->req_no = sr->spi_req_no.tx_req_no;
		v7_dma_flush_range((uintptr_t)dma_tx_des->src,
			(uintptr_t)(dma_tx_des->src + dma_tx_des->len));
	}

	return SPI_OK;
}

static void hisi_spi_dma_start(const u32 chip_addr)
{
	/* config spi dma fifo */
	hisi_writel(SPI_TX_FIFO_CONFIG, SSP_TXFIFOCR(chip_addr));
	hisi_writel(SPI_RX_FIFO_CONFIG, SSP_RXFIFOCR(chip_addr));

	/* enable spi dma */
	hisi_writel(SPI_DMA_ENABLE_TRANSFER, SSP_DMACR(chip_addr));

	/* enable spi */
	hisi_writel((hisi_readl(SSP_CR1(chip_addr)) | SSP_CR1_MASK_SSE),
		SSP_CR1(chip_addr));
}

static void hisi_spi_dma_stop(const u32 chip_addr)
{
	/* disable spi dma */
	hisi_writel(0x0, SSP_DMACR(chip_addr));

	/* disable spi */
	hisi_writel((hisi_readl(SSP_CR1(chip_addr)) & (~SSP_CR1_MASK_SSE)),
		SSP_CR1(chip_addr));
}

static int hisi_spi_dma_transfer_message(
	const u32 chip_addr, struct spi_message *msg)
{
	struct hisi_dma_des dma_rx_des, dma_tx_des;
	unsigned int i;
	unsigned int val;
	int ret;
	int has_err = SPI_OK;
	int id;
	struct pl022 pl022;
	struct spi_transfer *previous = NULL;

	ret = memset_s(&pl022, sizeof(struct pl022), 0, sizeof(struct pl022));
	if (ret) {
		HISI_PRINT_ERROR(
			"memset_s error: ret=[%d]\n", ret);
	}

	id = get_chip_array_id(chip_addr);
	if ((id < 0) || (id >= CHIP_ARRAY_SIZE)) {
		HISI_PRINT_ERROR("spi chip addr is invalid\n");
		return -SPI_ERR;
	}

	spi_chip_config(chip_addr, &cur_chip[id]);
	pl022.cur_chip = &cur_chip[id];

	flush(chip_addr, &pl022);

	for (i = 0; i < msg->transfer_num; i++) {
		pl022.cur_transfer = msg->transfers + i;
		if ((pl022.cur_transfer->rx_buf == NULL) &&
			(pl022.cur_transfer->tx_buf == NULL))
			continue;

		if (previous) {
			if (previous->delay_usecs)
				SRE_DelayUs(previous->delay_usecs);
			if (previous->cs_change)
				pl022.cur_chip->cs_control(SSP_CHIP_SELECT);
			previous = pl022.cur_transfer;
		} else {
			/* STATE_START */
			previous = pl022.cur_transfer;
			pl022.cur_chip->cs_control(SSP_CHIP_SELECT);
		}
		v7_dma_map_area(pl022.cur_transfer->tx_buf,
			pl022.cur_transfer->len, DMA_TO_DEVICE);

		ret = hisi_spi_dma_parse_des(chip_addr, &pl022,
				&dma_rx_des, &dma_tx_des);
		if (ret) {
			HISI_PRINT_ERROR("spi parse_des error\n");
			return -SPI_ERR;
		}

		ret = hisi_dma_init();
		if (ret) {
			HISI_PRINT_ERROR("dma init error\n");
			return -SPI_ERR;
		}
		ret = hisi_dma_config(&dma_rx_des);
		if (ret) {
			hisi_dma_exit();
			HISI_PRINT_ERROR("rx dma cfg error\n");
			return -SPI_ERR;
		}
		ret = hisi_dma_config(&dma_tx_des);
		if (ret) {
			hisi_dma_exit();
			HISI_PRINT_ERROR("tx dma cfg error\n");
			return -SPI_ERR;
		}

		hisi_dma_start();

		ret = hisi_dma_config_check();
		if (ret) {
			hisi_dma_exit();
			HISI_PRINT_ERROR("dma cfg check error\n");
			return -SPI_ERR;
		}

		hisi_spi_dma_start(chip_addr);

		v7_dma_map_area(pl022.cur_transfer->rx_buf,
			pl022.cur_transfer->len, DMA_FROM_DEVICE);

		ret = hisi_dma_process_status();
		if (ret) {
			HISI_PRINT_ERROR("hisi_dma_process_status error\n");
			has_err = -SPI_ERR;
			val = hisi_readl(SSP_RIS(chip_addr));
			HISI_PRINT_ERROR("SSP_RIS: 0x%x\n", val);
		}

		hisi_dma_exit();

		v7_dma_unmap_area(pl022.cur_transfer->tx_buf,
			pl022.cur_transfer->len, DMA_TO_DEVICE);
		v7_dma_unmap_area(pl022.cur_transfer->rx_buf,
			pl022.cur_transfer->len, DMA_FROM_DEVICE);

		hisi_spi_dma_stop(chip_addr);

		if (pl022.cur_transfer->cs_change)
			pl022.cur_chip->cs_control(SSP_CHIP_DESELECT);

		if (has_err == -SPI_ERR)
			return -SPI_ERR;
	}

	return SPI_OK;
}

int hisi_spi_polling_transfer(const u32 chip_addr, struct spi_message *msg)
{
	struct pl022 pl022;
	struct spi_transfer *previous = NULL;
	unsigned int i;
	int ret;
	int id;
	u32 retry = SPI_RETRY_TIMES; /* 500ms */

	if (msg == NULL) {
		HISI_PRINT_ERROR("msg is NULL err\n");
		return -SPI_ERR;
	}

	ret = memset_s(&pl022, sizeof(struct pl022), 0, sizeof(struct pl022));
	if (ret) {
		HISI_PRINT_ERROR(
			"memset_s error: ret=[%d]\n", ret);
	}

	id = get_chip_array_id(chip_addr);
	if ((id < 0) || (id >= CHIP_ARRAY_SIZE)) {
		HISI_PRINT_ERROR("spi chip addr is invalid\n");
		return -SPI_ERR;
	}

	spi_chip_config(chip_addr, &cur_chip[id]);
	pl022.cur_chip = &cur_chip[id];
	for (i = 0; i < msg->transfer_num; i++) {
		pl022.cur_transfer = msg->transfers + i;
		if (previous) {
			if (previous->delay_usecs)
				SRE_DelayUs(previous->delay_usecs);
			if (previous->cs_change)
				pl022.cur_chip->cs_control(SSP_CHIP_SELECT);
			previous = pl022.cur_transfer;
		} else {
			/* STATE_START */
			previous = pl022.cur_transfer;
			pl022.cur_chip->cs_control(SSP_CHIP_SELECT);
		}

		if (set_up_next_transfer(&pl022, pl022.cur_transfer)) {
			/* Error path */
			HISI_PRINT_ERROR("set_up_next_transfer is error\n");
			msg->status = -SPI_ERR;
			return -SPI_ERR;
		}

		flush(chip_addr, &pl022);

		/* enable spi */
		hisi_writel((hisi_readl(SSP_CR1(chip_addr)) | SSP_CR1_MASK_SSE),
			SSP_CR1(chip_addr));

		while ((pl022.data.tx < pl022.data.tx_end ||
				pl022.data.rx < pl022.data.rx_end) &&
			retry) {
			/* read or write spi fifo */
			if (readwriter(chip_addr, &pl022) == -SPI_ERR)
				HISI_PRINT_ERROR("spi readwriter err\n");

			retry--;
		}

		if (retry == 0)
			HISI_PRINT_ERROR("spi readwriter err\n");

		/* disable spi */
		hisi_writel((hisi_readl(SSP_CR1(chip_addr)) &
			(~SSP_CR1_MASK_SSE)), SSP_CR1(chip_addr));
		/* Update total byte transferred */
		msg->actual_length += pl022.cur_transfer->len;
		if (pl022.cur_transfer->cs_change)
			pl022.cur_chip->cs_control(SSP_CHIP_DESELECT);
	}

	msg->status = SPI_OK;
	return SPI_OK;
}

static int hisi_spi_dma_enable(const u32 chip_addr)
{
	struct spi_resource *sr = NULL;

	sr = get_resource_info(chip_addr);
	if (sr == NULL) {
		HISI_PRINT_ERROR("spi can't get resource.\n");
		return SPI_DMA_DISABLE;
	}

	if (sr->spi_req_no.is_valid == SPI_DMA_REQ_NO_VALID)
		return SPI_DMA_ENABLE;
	else
		return SPI_DMA_DISABLE;
}

int hisi_spi_dma_transfer(const u32 chip_addr, struct spi_message *msg)
{
	int ret;

	if (msg == NULL) {
		HISI_PRINT_ERROR("msg is null err\n");
		return -SPI_ERR;
	}

	/**
	 *if config req no of dma that will call hisi_spi_dma_transfer_message,
	 *otherwise call hisi_spi_polling_transfer
	 */
	if (hisi_spi_dma_enable(chip_addr) == SPI_DMA_ENABLE) {
		ret = hisi_spi_dma_transfer_message(chip_addr, msg);
		if (ret == -SPI_ERR) {
			HISI_PRINT_ERROR(
				"spi dma transfer error\n");
			return -SPI_ERR;
		}
	} else {
		ret = hisi_spi_polling_transfer(chip_addr, msg);
		if (ret == -SPI_ERR) {
			HISI_PRINT_ERROR(
				"spi poll transfer error\n");
			return -SPI_ERR;
		}
	}

	return SPI_OK;
}

int hisi_spi_init(const u32 chip_addr, struct spi_device *spi)
{
	int ret;
	int id;

	if (spi == NULL) {
		HISI_PRINT_ERROR("spi is null err\n");
		return -SPI_ERR;
	}

	if (get_hdres_lock(chip_addr))
		return -SPI_ERR;

	id = get_chip_array_id(chip_addr);
	if ((id < 0) || (id >= CHIP_ARRAY_SIZE)) {
		HISI_PRINT_ERROR("spi chip addr is invalid\n");
		put_hdres_lock(chip_addr);
		return -SPI_ERR;
	}

	ret = memset_s((void *)&cur_chip[id], sizeof(struct chip_data),
			0, sizeof(struct chip_data));
	if (ret)
		HISI_PRINT_ERROR("memset_s error: ret=[%d]\n", ret);

	spi_clk_enable(chip_addr, SPI_CLK_ENABLE);
	spi_reset_controller(chip_addr);

	ret = spi_tzpc_cfg(chip_addr, SEC_SPI);
	if (ret != SPI_OK) {
		HISI_PRINT_ERROR("spi_tzpc_cfg is failed\n");
		put_hdres_lock(chip_addr);
		return -SPI_ERR;
	}
	ret = spi_cfg_gpio(chip_addr, SPI_TRUE);
	if (ret != SPI_OK) {
		HISI_PRINT_ERROR("spi_cfg_gpio for SPI_TRUE failed\n");
		spi_tzpc_cfg(chip_addr, UNSEC_SPI);
		spi_clk_enable(chip_addr, SPI_CLK_DISABLE);
		put_hdres_lock(chip_addr);

		return -SPI_ERR;
	}
	load_ssp_default_config(chip_addr);
	hisi_writel((hisi_readl(SSP_CR1(chip_addr)) & (~SSP_CR1_MASK_SSE)),
		SSP_CR1(chip_addr));

	ret = hisi_spi_setup(spi, &cur_chip[id], chip_addr);
	if (ret < 0) {
		HISI_PRINT_ERROR("hisi_spi_setup failed\n");
		spi_tzpc_cfg(chip_addr, UNSEC_SPI);
		spi_cfg_gpio(chip_addr, SPI_FALSE);
		spi_clk_enable(chip_addr, SPI_CLK_DISABLE);
		put_hdres_lock(chip_addr);

		return -SPI_ERR;
	}
	return SPI_OK;
}

void hisi_spi_exit(const u32 chip_addr)
{
	load_ssp_default_config(chip_addr);
	spi_tzpc_cfg(chip_addr, UNSEC_SPI);
	spi_cfg_gpio(chip_addr, SPI_FALSE);
	spi_clk_enable(chip_addr, SPI_CLK_DISABLE);
	put_hdres_lock(chip_addr);
}

int spi_read(struct spi_device *spi, void *buf, unsigned int len,
	const u32 chip_addr)
{
	int ret;
	struct spi_transfer t;
	struct spi_message m;

	if (spi == NULL) {
		HISI_PRINT_ERROR("spi is null err\n");
		return -SPI_ERR;
	}

	if (buf == NULL) {
		HISI_PRINT_ERROR("buf is null err\n");
		return -SPI_ERR;
	}

	t.rx_buf = buf;
	t.len = len;
	t.delay_usecs = 0;
	t.cs_change = 1;

	m.transfers = &t;
	m.transfer_num = 1;
	m.actual_length = 0;
	m.status = 0;

	ret = hisi_spi_init(chip_addr, spi);
	if (ret)
		return -SPI_ERR;

	ret = hisi_spi_polling_transfer(chip_addr, &m);
	if (ret) {
		HISI_PRINT_ERROR("polling transfer error: ret=[%d]\n", ret);
		hisi_spi_exit(chip_addr);
		return -SPI_ERR;
	}

	hisi_spi_exit(chip_addr);
	return m.status;
}

int spi_write(struct spi_device *spi, const void *buf, unsigned int len,
	const u32 chip_addr)
{
	int ret;
	struct spi_transfer t;
	struct spi_message m;

	if (spi == NULL) {
		HISI_PRINT_ERROR("spi is null err\n");
		return -SPI_ERR;
	}

	if (buf == NULL) {
		HISI_PRINT_ERROR("buf is null err\n");
		return -SPI_ERR;
	}

	t.tx_buf = buf;
	t.len = len;
	t.delay_usecs = 0;
	t.cs_change = 1;

	m.transfers = &t;
	m.transfer_num = 1;
	m.actual_length = 0;
	m.status = 0;

	ret = hisi_spi_init(chip_addr, spi);
	if (ret)
		return -SPI_ERR;

	ret = hisi_spi_polling_transfer(chip_addr, &m);
	if (ret) {
		HISI_PRINT_ERROR("polling transfer error: ret=[%d]\n", ret);
		hisi_spi_exit(chip_addr);
		return -SPI_ERR;
	}

	hisi_spi_exit(chip_addr);
	return m.status;
}

int spi_dev_read(struct spi_seq *seq, const u32 chip_addr)
{
	struct spi_transfer t;
	struct spi_message m;
	int ret;

	if (seq == NULL) {
		HISI_PRINT_ERROR("seq is null err\n");
		return -SPI_ERR;
	}

	ret = hisi_spi_init(chip_addr, &seq->spi);
	if (ret)
		return -SPI_ERR;

	t.tx_buf = NULL;
	t.rx_buf = seq->rx;
	t.len = (unsigned int)seq->rx_len;
	t.delay_usecs = 0;

	ret = memset_s((void *)&m, sizeof(struct spi_message), 0xff,
		sizeof(struct spi_message));
	if (ret) {
		HISI_PRINT_ERROR(
			"memset_s error: ret=[%d]\n", ret);
	}

	m.transfers = &t;
	m.transfer_num = 1;
	m.actual_length = 0;
	m.status = 0;

	ret = hisi_spi_polling_transfer(chip_addr, &m);
	if (ret) {
		HISI_PRINT_ERROR("polling transfer error: ret=[%d]\n", ret);
		hisi_spi_exit(chip_addr);
		return -SPI_ERR;
	}

	hisi_spi_exit(chip_addr);
	return m.status;
}

int spi_dev_write(struct spi_seq *seq, const u32 chip_addr)
{
	struct spi_transfer spi_tf;
	struct spi_message spi_msg;
	int ret;

	if (seq == NULL) {
		HISI_PRINT_ERROR("seq is null err\n");
		return -SPI_ERR;
	}

	ret = hisi_spi_init(chip_addr, &seq->spi);
	if (ret)
		return -SPI_ERR;

	spi_tf.tx_buf = seq->tx;
	spi_tf.rx_buf = NULL;
	spi_tf.len = (unsigned int)seq->tx_len;
	spi_tf.delay_usecs = 0;

	ret = memset_s(&spi_msg, sizeof(struct spi_message), 0xff,
		sizeof(struct spi_message));
	if (ret)
		HISI_PRINT_ERROR("memset_s error: ret=[%d]\n", ret);

	spi_msg.transfers = &spi_tf;
	spi_msg.transfer_num = 1;
	spi_msg.actual_length = 0;
	spi_msg.status = 0;

	ret = hisi_spi_polling_transfer(chip_addr, &spi_msg);
	if (ret) {
		HISI_PRINT_ERROR("polling transfer error: ret=[%d]\n", ret);
		hisi_spi_exit(chip_addr);
		return -SPI_ERR;
	}

	hisi_spi_exit(chip_addr);
	return spi_msg.status;
}

static inline void spi_message_init(struct spi_message *m)
{
	int ret;

	ret = memset_s(m, sizeof(*m), 0, sizeof(*m));
	if (ret)
		HISI_PRINT_ERROR("memset_s error: ret=[%d]\n", ret);

	INIT_LIST_HEAD(&m->transfer);
}

static inline void spi_message_add_tail(
	struct spi_transfer *t, struct spi_message *m)
{
	list_add_tail(&t->transfer_list, &m->transfer);
}

int spi_write_then_read(struct spi_device *spi, const void *txbuf,
	unsigned int n_tx, void *rxbuf, unsigned int n_rx, const u32 chip_addr)
{
	struct spi_message message;
	struct spi_transfer x[2];
	u8 *local_buf = NULL;
	int ret;
	u8 buf[BUFFER_LEN];

	local_buf = buf;

	if ((spi == NULL) || (rxbuf == NULL) || (txbuf == NULL))
		return -SPI_ERR;

	if ((n_tx + n_rx) > BUFFER_LEN) {
		HISI_PRINT_ERROR("n_tx+n_rx  is too long %d %d\n", n_tx,
			n_rx);
		return -SPI_ERR;
	}

	spi_message_init(&message);

	ret = memset_s((void *)x, sizeof(x), 0, sizeof(x));
	if (ret) {
		HISI_PRINT_ERROR(
			"memset_s error: ret=[%d]\n", ret);
	}
	if (n_tx) {
		ret = memcpy_s(
			(void *)local_buf, BUFFER_LEN, txbuf, n_tx);
		if (ret) {
			HISI_PRINT_ERROR("memcpy_s error: ret=[%d]\n", ret);
			return -SPI_ERR;
		}
		x[0].tx_buf = local_buf;
		x[0].cs_change = 0;
		x[0].delay_usecs = 0;
		x[0].len = n_tx;
		spi_message_add_tail(&x[0], &message);
		message.transfer_num++;
	}
	if (n_rx) {
		x[1].rx_buf = local_buf + n_tx;
		x[1].cs_change = 1;
		x[1].delay_usecs = 0;
		x[1].len = n_rx;
		spi_message_add_tail(&x[1], &message);
		message.transfer_num++;
	}

	ret = hisi_spi_init(chip_addr, spi);
	if (ret)
		return -SPI_ERR;

	ret = hisi_spi_polling_transfer(chip_addr, &message);
	if (ret) {
		HISI_PRINT_ERROR("polling transfer error: ret=[%d]\n", ret);
		hisi_spi_exit(chip_addr);
		return -SPI_ERR;
	}

	ret = memcpy_s((void *)rxbuf, BUFFER_LEN-n_tx,
			x[1].rx_buf + n_tx, n_rx);
	if (ret)
		HISI_PRINT_ERROR("memcpy_s error: ret=[%d]\n", ret);

	hisi_spi_exit(chip_addr);
	return message.status;
}
